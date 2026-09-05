package provider

// This file contains the controller-owned verification boundary used after an
// agent edits a disposable worktree.  The agent supplies only command IDs; the
// controller owns the catalog, the worktree/revision binding, and the bwrap
// invocation.  In particular, this is not a general command runner.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

const (
	verifierSchemaVersion  = "ntm.disposable-verifier.v2"
	defaultVerifyTimeout   = 5 * time.Minute
	worktreeInspectTimeout = 10 * time.Second
	maxVerifyCommands      = 8
	maxVerifierOutput      = 8 << 20
)

var verifierID = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
var gitRevision = regexp.MustCompile(`^[0-9a-f]{40,64}$`)

// Release builds using -trimpath omit runtime.GOROOT. The build may bind the
// exact controller toolchain with -X; it is never supplied by a provider.
var verifierBuildGoRoot string

func verifierGoRoot(runtimeRoot, buildRoot string) (string, error) {
	root := buildRoot
	if root == "" {
		root = runtimeRoot
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) == string(filepath.Separator) {
		return "", errors.New("isolated verifier requires a build-bound Go toolchain root; trimpath builds must set provider.verifierBuildGoRoot")
	}
	for _, relative := range []string{"bin/go", "src/runtime", "pkg/tool"} {
		if _, err := os.Stat(filepath.Join(root, relative)); err != nil {
			return "", errors.New("isolated verifier Go toolchain root is incomplete")
		}
	}
	return filepath.Clean(root), nil
}

// ApprovedCommand is controller-authored, immutable command metadata.  A
// catalog must never be assembled from provider output or repository content.
type ApprovedCommand struct {
	ID      string
	Program string
	Args    []string
	Timeout time.Duration
}

// CommandCatalog maps opaque manifest IDs to controller-approved commands.
// Its map is intentionally private so a caller cannot mutate it after
// validation.
type CommandCatalog struct{ commands map[string]ApprovedCommand }

// NewCommandCatalog validates and copies a controller-maintained command list.
func NewCommandCatalog(commands []ApprovedCommand) (CommandCatalog, error) {
	if len(commands) == 0 || len(commands) > maxVerifyCommands {
		return CommandCatalog{}, errors.New("verification catalog must contain 1 to 8 commands")
	}
	catalog := CommandCatalog{commands: make(map[string]ApprovedCommand, len(commands))}
	for _, command := range commands {
		if !verifierID.MatchString(command.ID) || !bareProgram(command.Program) || command.Timeout <= 0 || command.Timeout > defaultVerifyTimeout || !safeArguments(command.Args) {
			return CommandCatalog{}, fmt.Errorf("invalid approved verification command %q", command.ID)
		}
		if _, exists := catalog.commands[command.ID]; exists {
			return CommandCatalog{}, fmt.Errorf("duplicate approved verification command %q", command.ID)
		}
		command.Args = append([]string(nil), command.Args...)
		catalog.commands[command.ID] = command
	}
	return catalog, nil
}

// DefaultDisposableCommandCatalog is deliberately small.  Callers may add a
// reviewed project-specific catalog, but should not accept command data from
// an agent, prompt, or repository configuration as catalog input.
func DefaultDisposableCommandCatalog() (CommandCatalog, error) {
	return NewCommandCatalog([]ApprovedCommand{
		{ID: "go-test", Program: "go", Args: []string{"test", "./..."}, Timeout: defaultVerifyTimeout},
		{ID: "go-vet", Program: "go", Args: []string{"vet", "./..."}, Timeout: defaultVerifyTimeout},
		{ID: "cargo-test", Program: "cargo", Args: []string{"test", "--locked"}, Timeout: defaultVerifyTimeout},
	})
}

// VerificationManifest is the untrusted-to-trusted handoff.  CommandIDs are
// resolved only against a catalog already held by the controller.
type VerificationManifest struct {
	Worktree   string
	Revision   string
	CommandIDs []string
}

// CommandVerification is redacted evidence for one command.  It never retains
// stdout, stderr, command arguments, credentials, or repository paths.
type CommandVerification struct {
	ID              string    `json:"id"`
	CommandSHA256   string    `json:"command_sha256"`
	OutputSHA256    string    `json:"output_sha256"`
	OutputBytes     int64     `json:"output_bytes"`
	ExitCode        int       `json:"exit_code"`
	TimedOut        bool      `json:"timed_out"`
	ProcessWaited   bool      `json:"process_waited"`
	CleanupVerified bool      `json:"cleanup_verified"`
	StartedAt       time.Time `json:"started_at"`
	CompletedAt     time.Time `json:"completed_at"`
	ErrorSHA256     string    `json:"error_sha256,omitempty"`
}

// VerificationReceipt binds results to the resolved disposable worktree and
// exact Git revision.  Hashing paths keeps machine layout out of durable logs.
type VerificationReceipt struct {
	SchemaVersion        string                `json:"schema_version"`
	ManifestSHA256       string                `json:"manifest_sha256"`
	WorktreeSHA256       string                `json:"worktree_sha256"`
	RevisionSHA256       string                `json:"revision_sha256"`
	NetworkIsolated      bool                  `json:"network_isolated"`
	CredentialsCleared   bool                  `json:"credentials_cleared"`
	PIDNamespaceIsolated bool                  `json:"pid_namespace_isolated"`
	CleanupVerified      bool                  `json:"cleanup_verified"`
	DisposableWorktree   bool                  `json:"disposable_worktree"`
	Commands             []CommandVerification `json:"commands"`
	StartedAt            time.Time             `json:"started_at"`
	CompletedAt          time.Time             `json:"completed_at"`
}

type verificationPlan struct {
	Program string
	Args    []string
	Dir     string
	Env     []string
}

type verificationOutcome struct {
	Output          []byte
	OutputSHA256    string
	OutputBytes     int64
	ExitCode        int
	ProcessWaited   bool
	CleanupVerified bool
}

type verificationRunner interface {
	Run(context.Context, verificationPlan) (verificationOutcome, error)
}

type worktreeInspector interface {
	Inspect(context.Context, string) (resolvedPath, revision string, disposable bool, err error)
}

// IsolatedVerifier runs only catalog commands inside Bubblewrap with a fresh
// empty environment and network namespace.  It fails closed when Bubblewrap
// or disposable-worktree evidence is unavailable.
type IsolatedVerifier struct {
	goRoot    string
	catalog   CommandCatalog
	runner    verificationRunner
	inspector worktreeInspector
	now       func() time.Time
}

func NewIsolatedVerifier(catalog CommandCatalog) (*IsolatedVerifier, error) {
	if len(catalog.commands) == 0 {
		return nil, errors.New("isolated verifier requires a non-empty approved command catalog")
	}
	if runtime.GOOS != "linux" {
		return nil, errors.New("isolated verifier requires Linux Bubblewrap")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		return nil, fmt.Errorf("isolated verifier requires Bubblewrap: %w", err)
	}
	var root string
	for _, command := range catalog.commands {
		if command.Program == "go" {
			var err error
			root, err = verifierGoRoot(runtime.GOROOT(), verifierBuildGoRoot)
			if err != nil {
				return nil, err
			}
			break
		}
	}
	return &IsolatedVerifier{catalog: catalog, runner: bwrapVerificationRunner{}, inspector: gitWorktreeInspector{}, now: time.Now, goRoot: root}, nil
}

// Verify rejects a non-disposable tree, a revision mismatch, duplicate or
// unknown command IDs, and any inability to start the isolated process.  It
// stops at the first failed command; a caller must make a new manifest to retry.
func (v *IsolatedVerifier) Verify(ctx context.Context, manifest VerificationManifest) (VerificationReceipt, error) {
	if v == nil || v.runner == nil || v.inspector == nil || v.now == nil || len(v.catalog.commands) == 0 {
		return VerificationReceipt{}, errors.New("isolated verifier is not initialized")
	}
	if ctx == nil {
		return VerificationReceipt{}, errors.New("verification requires a context")
	}
	if len(manifest.CommandIDs) == 0 || len(manifest.CommandIDs) > maxVerifyCommands || !gitRevision.MatchString(manifest.Revision) {
		return VerificationReceipt{}, errors.New("verification manifest is invalid")
	}
	inspectCtx, inspectCancel := context.WithTimeout(ctx, worktreeInspectTimeout)
	resolved, actualRevision, disposable, err := v.inspector.Inspect(inspectCtx, manifest.Worktree)
	inspectCancel()
	if err != nil {
		return VerificationReceipt{}, fmt.Errorf("inspect disposable worktree: %w", err)
	}
	if !disposable || actualRevision != manifest.Revision {
		return VerificationReceipt{}, errors.New("verification requires the exact current revision of a linked disposable worktree")
	}
	commands := make([]ApprovedCommand, 0, len(manifest.CommandIDs))
	seen := make(map[string]struct{}, len(manifest.CommandIDs))
	for _, id := range manifest.CommandIDs {
		command, ok := v.catalog.commands[id]
		if !ok || !verifierID.MatchString(id) {
			return VerificationReceipt{}, fmt.Errorf("verification command %q is not approved", id)
		}
		if _, exists := seen[id]; exists {
			return VerificationReceipt{}, fmt.Errorf("verification command %q is duplicated", id)
		}
		seen[id] = struct{}{}
		commands = append(commands, command)
	}

	started := v.now().UTC()
	receipt := VerificationReceipt{SchemaVersion: verifierSchemaVersion, ManifestSHA256: manifestDigest(resolved, manifest.Revision, manifest.CommandIDs), WorktreeSHA256: verifierHash(resolved), RevisionSHA256: verifierHash(manifest.Revision), NetworkIsolated: true, CredentialsCleared: true, PIDNamespaceIsolated: true, CleanupVerified: true, DisposableWorktree: true, StartedAt: started}
	for _, command := range commands {
		commandStarted := v.now().UTC()
		commandCtx, cancel := context.WithTimeout(ctx, command.Timeout)
		outcome, runErr := v.runner.Run(commandCtx, bwrapPlan(resolved, command, v.goRoot))
		timedOut := errors.Is(commandCtx.Err(), context.DeadlineExceeded)
		cancel()
		completed := v.now().UTC()
		outputHash := outcome.OutputSHA256
		if outputHash == "" {
			outputHash = verifierHash(string(outcome.Output))
		}
		entry := CommandVerification{ID: command.ID, CommandSHA256: commandDigest(command), OutputSHA256: outputHash, OutputBytes: outcome.OutputBytes, ExitCode: outcome.ExitCode, TimedOut: timedOut, ProcessWaited: outcome.ProcessWaited, CleanupVerified: outcome.CleanupVerified, StartedAt: commandStarted, CompletedAt: completed}
		if !outcome.CleanupVerified {
			receipt.CleanupVerified = false
		}
		if runErr != nil {
			entry.ErrorSHA256 = verifierHash(runErr.Error())
		}
		receipt.Commands = append(receipt.Commands, entry)
		if runErr != nil {
			receipt.CompletedAt = completed
			return receipt, fmt.Errorf("isolated verification command %s failed: %w", command.ID, runErr)
		}
	}
	receipt.CompletedAt = v.now().UTC()
	return receipt, nil
}

func bwrapPlan(worktree string, command ApprovedCommand, goRoot string) verificationPlan {
	// Start from an empty tmpfs root. Read-only system runtime directories are
	// mounted explicitly; the host home, root, configuration, credential, and
	// cache trees are never visible. The linked worktree is mounted at a fixed
	// path so a repository symlink cannot escape into an unmounted host path.
	// --unshare-all includes network, PID, IPC, UTS, cgroup, and user isolation.
	args := []string{
		"--die-with-parent", "--new-session", "--unshare-all", "--clearenv", "--cap-drop", "ALL",
		"--tmpfs", "/",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind-try", "/bin", "/bin",
		"--ro-bind-try", "/lib", "/lib",
		"--ro-bind-try", "/lib64", "/lib64",
		"--ro-bind-try", "/sbin", "/sbin",
	}
	pathValue := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	if command.Program == "go" {
		// Go's selected toolchain may live below GOPATH (for example after a
		// toolchain directive download). Mount only that immutable runtime, not
		// GOPATH or the surrounding home directory, and disable auto-downloads.
		args = append(args, "--dir", "/opt", "--dir", "/opt/ntm", "--ro-bind", goRoot, "/opt/ntm/go")
		pathValue = "/opt/ntm/go/bin:" + pathValue
	}
	args = append(args,
		"--dir", "/workspace", "--bind", worktree, "/workspace",
		"--tmpfs", "/tmp", "--dir", "/tmp/home", "--dir", "/tmp/go-cache", "--dir", "/tmp/go-mod", "--dir", "/tmp/cargo-home",
		"--proc", "/proc", "--dev", "/dev",
		"--setenv", "PATH", pathValue,
		"--setenv", "HOME", "/tmp/home", "--setenv", "TMPDIR", "/tmp", "--setenv", "GOCACHE", "/tmp/go-cache", "--setenv", "GOMODCACHE", "/tmp/go-mod", "--setenv", "CARGO_HOME", "/tmp/cargo-home", "--setenv", "LANG", "C",
	)
	if command.Program == "go" {
		args = append(args, "--setenv", "GOROOT", "/opt/ntm/go", "--setenv", "GOTOOLCHAIN", "local")
	}
	args = append(args, "--chdir", "/workspace", "--", command.Program)
	args = append(args, command.Args...)
	return verificationPlan{Program: "bwrap", Args: args, Dir: worktree, Env: []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/tmp/home", "TMPDIR=/tmp", "GOCACHE=/tmp/go-cache", "GOMODCACHE=/tmp/go-mod", "CARGO_HOME=/tmp/cargo-home", "LANG=C", "GOTOOLCHAIN=local"}}
}

type bwrapVerificationRunner struct{}

func (bwrapVerificationRunner) Run(ctx context.Context, plan verificationPlan) (verificationOutcome, error) {
	cmd := exec.CommandContext(ctx, plan.Program, plan.Args...)
	cmd.Dir, cmd.Env = plan.Dir, append([]string(nil), plan.Env...)
	var output cappedHashBuffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		return verificationOutcome{Output: output.snapshot(), OutputSHA256: output.digest(), OutputBytes: output.total}, err
	}
	pid := int32(cmd.Process.Pid)
	waitErr := cmd.Wait()
	exists, inspectErr := process.PidExists(pid)
	cleanupVerified := inspectErr == nil && !exists && cmd.ProcessState != nil && cmd.ProcessState.Exited()
	outcome := verificationOutcome{Output: output.snapshot(), OutputSHA256: output.digest(), OutputBytes: output.total, ProcessWaited: true, CleanupVerified: cleanupVerified}
	err := waitErr
	if !cleanupVerified {
		err = errors.Join(err, errors.New("isolated verifier could not prove sandbox process cleanup"))
	}
	if exitErr := new(exec.ExitError); errors.As(err, &exitErr) {
		outcome.ExitCode = exitErr.ExitCode()
	}
	return outcome, err
}

type gitWorktreeInspector struct{}

func (gitWorktreeInspector) Inspect(ctx context.Context, worktree string) (string, string, bool, error) {
	if strings.TrimSpace(worktree) == "" {
		return "", "", false, errors.New("worktree path is empty")
	}
	resolved, err := filepath.EvalSymlinks(worktree)
	if err != nil {
		return "", "", false, err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", "", false, err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", "", false, errors.New("worktree is not a directory")
	}
	revision, err := gitOutput(ctx, resolved, "rev-parse", "HEAD")
	if err != nil || !gitRevision.MatchString(revision) {
		return "", "", false, errors.New("worktree has no resolved Git revision")
	}
	listing, err := gitOutput(ctx, resolved, "worktree", "list", "--porcelain")
	if err != nil {
		return "", "", false, err
	}
	paths := make([]string, 0)
	for _, block := range strings.Split(listing, "\n\n") {
		for _, line := range strings.Split(block, "\n") {
			if value, ok := strings.CutPrefix(line, "worktree "); ok {
				paths = append(paths, filepath.Clean(value))
				break
			}
		}
	}
	if len(paths) < 2 || filepath.Clean(paths[0]) == filepath.Clean(resolved) {
		return resolved, revision, false, nil
	}
	for _, path := range paths[1:] {
		if filepath.Clean(path) == filepath.Clean(resolved) {
			return resolved, revision, true, nil
		}
	}
	return resolved, revision, false, nil
}

func gitOutput(ctx context.Context, dir string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "LANG=C"}
	output, err := command.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

type cappedHashBuffer struct {
	buffer bytes.Buffer
	hash   hash.Hash
	total  int64
}

func (b *cappedHashBuffer) Write(value []byte) (int, error) {
	if b.hash == nil {
		b.hash = sha256.New()
	}
	b.total += int64(len(value))
	_, _ = b.hash.Write(value)
	if b.buffer.Len() < maxVerifierOutput {
		remaining := maxVerifierOutput - b.buffer.Len()
		_, _ = b.buffer.Write(value[:min(remaining, len(value))])
	}
	return len(value), nil
}

func (b *cappedHashBuffer) snapshot() []byte {
	if b.hash == nil {
		return nil
	}
	return b.buffer.Bytes()
}

func (b *cappedHashBuffer) digest() string {
	if b.hash == nil {
		return verifierHash("")
	}
	return hex.EncodeToString(b.hash.Sum(nil))
}

func bareProgram(value string) bool {
	return verifierID.MatchString(value) && !strings.ContainsAny(value, `/\\`)
}
func safeArguments(values []string) bool {
	for _, value := range values {
		if value == "" || strings.ContainsAny(value, "\x00\r\n") || filepath.IsAbs(value) || value == ".." || strings.HasPrefix(value, "../") || strings.HasPrefix(value, `..\\`) {
			return false
		}
	}
	return true
}
func verifierHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func commandDigest(command ApprovedCommand) string {
	return verifierHash(command.ID + "\x00" + command.Program + "\x00" + strings.Join(command.Args, "\x00"))
}
func manifestDigest(worktree, revision string, ids []string) string {
	return verifierHash(worktree + "\x00" + revision + "\x00" + strings.Join(ids, "\x00"))
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
