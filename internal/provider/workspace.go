package provider

// WorkspaceBroker provides controller-owned, path-contained file operations
// for structured provider tool calls. It never executes repository commands.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	workspaceBrokerSchema = "ntm.provider-workspace.v2"
	maxWorkspaceFile      = 1 << 20
	maxWorkspaceListing   = 4096
)

type WorkspaceOperationReceipt struct {
	SchemaVersion  string    `json:"schema_version"`
	Action         string    `json:"action"`
	WorktreeSHA256 string    `json:"worktree_sha256"`
	RevisionSHA256 string    `json:"revision_sha256"`
	PathSHA256     string    `json:"path_sha256,omitempty"`
	BeforeSHA256   string    `json:"before_sha256,omitempty"`
	AfterSHA256    string    `json:"after_sha256,omitempty"`
	ResultSHA256   string    `json:"result_sha256,omitempty"`
	Bytes          int64     `json:"bytes"`
	Mutated        bool      `json:"mutated"`
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at"`
	ErrorSHA256    string    `json:"error_sha256,omitempty"`
}

type WorkspaceBroker struct {
	root         string
	revision     string
	now          func() time.Time
	writeMu      sync.Mutex
	beforeCommit func()
}

func NewWorkspaceBroker(ctx context.Context, worktree, revision string) (*WorkspaceBroker, error) {
	if ctx == nil || !gitRevision.MatchString(revision) {
		return nil, errors.New("workspace broker requires context and an exact Git revision")
	}
	inspectCtx, cancel := context.WithTimeout(ctx, worktreeInspectTimeout)
	resolved, actual, disposable, err := (gitWorktreeInspector{}).Inspect(inspectCtx, worktree)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("inspect provider workspace: %w", err)
	}
	if !disposable || actual != revision {
		return nil, errors.New("workspace broker requires the exact current revision of a linked disposable worktree")
	}
	return &WorkspaceBroker{root: resolved, revision: revision, now: time.Now}, nil
}

func (b *WorkspaceBroker) ReadFile(ctx context.Context, relative string) ([]byte, WorkspaceOperationReceipt, error) {
	receipt := b.newReceipt("read", relative)
	if err := validateWorkspaceBroker(b, ctx); err != nil {
		return nil, b.failReceipt(receipt, err), err
	}
	path, normalized, err := b.resolve(relative, false)
	if err != nil {
		return nil, b.failReceipt(receipt, err), err
	}
	receipt.PathSHA256 = verifierHash(normalized)
	file, err := os.Open(path)
	if err != nil {
		return nil, b.failReceipt(receipt, err), errors.New("workspace file could not be opened")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxWorkspaceFile {
		err = errors.New("workspace read requires a bounded regular file")
		return nil, b.failReceipt(receipt, err), err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxWorkspaceFile+1))
	if err != nil || len(data) > maxWorkspaceFile || !utf8.Valid(data) {
		err = errors.New("workspace read requires bounded UTF-8 content")
		return nil, b.failReceipt(receipt, err), err
	}
	receipt.ResultSHA256, receipt.Bytes, receipt.CompletedAt = verifierHash(string(data)), int64(len(data)), b.now().UTC()
	return data, receipt, nil
}

// WriteFile serializes writes made through this broker and uses optimistic
// concurrency. expectedSHA256 must match the current file, or SHA-256 of empty
// bytes for a new file. The target and its resolved parent are checked again
// immediately before commit. This protects cooperating controller operations;
// it is not an OS-wide lock against unrelated host processes.
func (b *WorkspaceBroker) WriteFile(ctx context.Context, relative, expectedSHA256 string, content []byte) (WorkspaceOperationReceipt, error) {
	receipt := b.newReceipt("write", relative)
	if err := validateWorkspaceBroker(b, ctx); err != nil {
		return b.failReceipt(receipt, err), err
	}
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	if err := validateWorkspaceBroker(b, ctx); err != nil {
		return b.failReceipt(receipt, err), err
	}
	if len(content) > maxWorkspaceFile || !utf8.Valid(content) || !isWorkspaceSHA256(expectedSHA256) {
		err := errors.New("workspace write requires bounded UTF-8 content and an expected SHA-256")
		return b.failReceipt(receipt, err), err
	}
	path, normalized, err := b.resolve(relative, true)
	if err != nil {
		return b.failReceipt(receipt, err), err
	}
	receipt.PathSHA256 = verifierHash(normalized)
	current, existed, err := readWorkspaceWriteTarget(path)
	if err != nil {
		return b.failReceipt(receipt, err), err
	}
	receipt.BeforeSHA256 = verifierHash(string(current))
	if receipt.BeforeSHA256 != expectedSHA256 {
		err = errors.New("workspace write optimistic-concurrency digest mismatch")
		return b.failReceipt(receipt, err), err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return b.failReceipt(receipt, err), errors.New("workspace write parent could not be prepared")
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".ntm-provider-write-*")
	if err != nil {
		return b.failReceipt(receipt, err), errors.New("workspace atomic write could not start")
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return b.failReceipt(receipt, err), errors.New("workspace atomic write permissions failed")
	}
	if _, err := temporary.Write(content); err != nil {
		return b.failReceipt(receipt, err), errors.New("workspace atomic write failed")
	}
	if err := temporary.Sync(); err != nil {
		return b.failReceipt(receipt, err), errors.New("workspace atomic write sync failed")
	}
	if err := temporary.Close(); err != nil {
		return b.failReceipt(receipt, err), errors.New("workspace atomic write close failed")
	}
	if b.beforeCommit != nil {
		b.beforeCommit()
	}
	commitPath, commitNormalized, err := b.resolve(relative, true)
	if err != nil || commitPath != path || commitNormalized != normalized {
		err = errors.New("workspace write target or resolved parent changed before commit")
		return b.failReceipt(receipt, err), err
	}
	commitCurrent, commitExisted, err := readWorkspaceWriteTarget(commitPath)
	if err != nil {
		return b.failReceipt(receipt, err), err
	}
	if commitExisted != existed || verifierHash(string(commitCurrent)) != expectedSHA256 {
		err = errors.New("workspace write target changed before commit")
		return b.failReceipt(receipt, err), err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return b.failReceipt(receipt, err), errors.New("workspace atomic write commit failed")
	}
	committed = true
	receipt.AfterSHA256, receipt.ResultSHA256 = verifierHash(string(content)), verifierHash(string(content))
	receipt.Bytes, receipt.Mutated, receipt.CompletedAt = int64(len(content)), true, b.now().UTC()
	return receipt, nil
}

func readWorkspaceWriteTarget(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return []byte{}, false, nil
	}
	if err != nil {
		return nil, false, errors.New("workspace write target could not be inspected")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxWorkspaceFile {
		return nil, false, errors.New("workspace write target must be a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, errors.New("workspace write target could not be opened safely")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, false, errors.New("workspace write target changed while being opened")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxWorkspaceFile+1))
	if err != nil || len(data) > maxWorkspaceFile || !utf8.Valid(data) {
		return nil, false, errors.New("workspace write target requires bounded UTF-8 content")
	}
	return data, true, nil
}

func (b *WorkspaceBroker) ListFiles(ctx context.Context, relative string) ([]string, WorkspaceOperationReceipt, error) {
	receipt := b.newReceipt("list", relative)
	if err := validateWorkspaceBroker(b, ctx); err != nil {
		return nil, b.failReceipt(receipt, err), err
	}
	path, normalized, err := b.resolveDirectory(relative)
	if err != nil {
		return nil, b.failReceipt(receipt, err), err
	}
	receipt.PathSHA256 = verifierHash(normalized)
	files := make([]string, 0)
	err = filepath.WalkDir(path, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(b.root, current)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			if rel != "." && (workspacePathDenied(rel) || workspaceGeneratedDirectory(entry.Name())) {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || workspacePathDenied(rel) {
			return nil
		}
		if len(files) >= maxWorkspaceListing {
			return errors.New("workspace listing exceeded its bounded file limit")
		}
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return nil, b.failReceipt(receipt, err), errors.New("workspace listing failed")
	}
	sort.Strings(files)
	receipt.ResultSHA256 = verifierHash(strings.Join(files, "\x00"))
	receipt.Bytes, receipt.CompletedAt = int64(len(files)), b.now().UTC()
	return files, receipt, nil
}

func validateWorkspaceBroker(b *WorkspaceBroker, ctx context.Context) error {
	if b == nil || b.now == nil || b.root == "" || !gitRevision.MatchString(b.revision) || ctx == nil {
		return errors.New("workspace broker is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (b *WorkspaceBroker) resolve(relative string, allowMissing bool) (string, string, error) {
	normalized, err := normalizeWorkspaceRelative(relative)
	if err != nil || workspacePathDenied(normalized) {
		return "", "", errors.New("workspace path is invalid or protected")
	}
	target := filepath.Join(b.root, filepath.FromSlash(normalized))
	parent := filepath.Dir(target)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		if allowMissing && errors.Is(err, fs.ErrNotExist) {
			return "", "", errors.New("workspace write parent must already exist")
		}
		return "", "", errors.New("workspace path parent could not be resolved")
	}
	if !pathWithin(b.root, resolvedParent) {
		return "", "", errors.New("workspace path escaped through a parent link")
	}
	target = filepath.Join(resolvedParent, filepath.Base(target))
	if info, statErr := os.Lstat(target); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", "", errors.New("workspace path may not be a symbolic link")
	} else if statErr != nil && !allowMissing {
		return "", "", errors.New("workspace path does not exist")
	}
	return target, normalized, nil
}

func (b *WorkspaceBroker) resolveDirectory(relative string) (string, string, error) {
	if strings.TrimSpace(relative) == "" || strings.TrimSpace(relative) == "." {
		return b.root, ".", nil
	}
	target, normalized, err := b.resolve(relative, false)
	if err != nil {
		return "", "", err
	}
	info, err := os.Stat(target)
	if err != nil || !info.IsDir() {
		return "", "", errors.New("workspace listing target must be a directory")
	}
	return target, normalized, nil
}

func normalizeWorkspaceRelative(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n") || filepath.IsAbs(value) {
		return "", errors.New("workspace path must be a bounded relative path")
	}
	clean := filepath.ToSlash(filepath.Clean(value))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "", errors.New("workspace path escapes its root")
	}
	return clean, nil
}

func workspacePathDenied(value string) bool {
	lower := strings.ToLower(filepath.ToSlash(value))
	segments := strings.Split(lower, "/")
	for _, segment := range segments {
		if segment == ".git" || segment == ".ssh" || segment == ".aws" || segment == ".gnupg" || segment == ".kube" || segment == "credentials" || segment == "id_rsa" || segment == "id_ed25519" || segment == ".netrc" || segment == ".npmrc" || segment == ".pypirc" || segment == "secrets" || strings.HasPrefix(segment, ".env") {
			return true
		}
	}
	return false
}

func workspaceGeneratedDirectory(value string) bool {
	switch strings.ToLower(value) {
	case "node_modules", "vendor", "dist", "build", "coverage", ".next", ".turbo", "target":
		return true
	default:
		return false
	}
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func (b *WorkspaceBroker) newReceipt(action, relative string) WorkspaceOperationReceipt {
	now := time.Now
	if b != nil && b.now != nil {
		now = b.now
	}
	receipt := WorkspaceOperationReceipt{SchemaVersion: workspaceBrokerSchema, Action: action, StartedAt: now().UTC()}
	if b != nil {
		receipt.WorktreeSHA256, receipt.RevisionSHA256 = verifierHash(b.root), verifierHash(b.revision)
		if relative != "" {
			receipt.PathSHA256 = verifierHash(relative)
		}
	}
	return receipt
}

func (b *WorkspaceBroker) failReceipt(receipt WorkspaceOperationReceipt, err error) WorkspaceOperationReceipt {
	if err != nil {
		receipt.ErrorSHA256 = verifierHash(err.Error())
	}
	if b != nil && b.now != nil {
		receipt.CompletedAt = b.now().UTC()
	} else {
		receipt.CompletedAt = time.Now().UTC()
	}
	return receipt
}

func isWorkspaceSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
