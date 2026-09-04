package provider

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testWorkspaceBroker(t *testing.T) *WorkspaceBroker {
	t.Helper()
	root := t.TempDir()
	return &WorkspaceBroker{root: root, revision: strings.Repeat("a", 40), now: func() time.Time { return time.Unix(100, 0).UTC() }}
}

func TestWorkspaceBrokerReadWriteListAndReceiptsAreRedacted(t *testing.T) {
	broker := testWorkspaceBroker(t)
	if err := os.Mkdir(filepath.Join(broker.root, "pkg"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(broker.root, "pkg", "file.go")
	if err := os.WriteFile(path, []byte("package old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, readReceipt, err := broker.ReadFile(t.Context(), "pkg/file.go")
	if err != nil || string(data) != "package old\n" || readReceipt.ResultSHA256 != verifierHash(string(data)) {
		t.Fatalf("data=%q receipt=%+v err=%v", data, readReceipt, err)
	}
	writeReceipt, err := broker.WriteFile(t.Context(), "pkg/file.go", verifierHash(string(data)), []byte("package next\n"))
	if err != nil || !writeReceipt.Mutated || writeReceipt.BeforeSHA256 == writeReceipt.AfterSHA256 {
		t.Fatalf("receipt=%+v err=%v", writeReceipt, err)
	}
	files, listReceipt, err := broker.ListFiles(t.Context(), ".")
	if err != nil || len(files) != 1 || files[0] != "pkg/file.go" || listReceipt.Bytes != 1 {
		t.Fatalf("files=%v receipt=%+v err=%v", files, listReceipt, err)
	}
	encoded, _ := json.Marshal([]WorkspaceOperationReceipt{readReceipt, writeReceipt, listReceipt})
	for _, prohibited := range []string{broker.root, "pkg/file.go", "package next"} {
		if strings.Contains(string(encoded), prohibited) {
			t.Fatalf("receipt leaked %q: %s", prohibited, encoded)
		}
	}
}

func TestWorkspaceBrokerRejectsProtectedTraversalSymlinkAndStaleWrite(t *testing.T) {
	broker := testWorkspaceBroker(t)
	if err := os.Mkdir(filepath.Join(broker.root, "pkg"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broker.root, "pkg", "file.go"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../outside", ".git/config", ".env", "pkg/../../outside"} {
		if _, _, err := broker.ReadFile(t.Context(), path); err == nil {
			t.Fatalf("unsafe path %q was readable", path)
		}
	}
	if _, err := broker.WriteFile(t.Context(), "pkg/file.go", verifierHash("different"), []byte("new")); err == nil {
		t.Fatal("stale optimistic-concurrency write succeeded")
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(broker.root, "linked")); err == nil {
		if _, _, err := broker.ReadFile(t.Context(), "linked/secret"); err == nil {
			t.Fatal("parent symlink escaped workspace")
		}
	}
}

func TestWorkspaceBrokerDeniesCredentialFamiliesAcrossReadWriteAndList(t *testing.T) {
	broker := testWorkspaceBroker(t)
	protected := []string{
		".config/gh/hosts.yml", ".config/gcloud/application_default_credentials.json",
		"config/gh/hosts.yml", "config/gcloud/credentials.json",
		".azure/accessTokens.json", ".docker/config.json", ".grok/auth.json",
		"certs/client.pem", "certs/client.key", "certs/client.p12", "certs/client.pfx",
		"customer-secret.txt", "service-credentials.json", ".env.production",
	}
	for _, relative := range protected {
		path := filepath.Join(broker.root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("prepare %s: %v", relative, err)
		}
		if err := os.WriteFile(path, []byte("do-not-expose"), 0o600); err != nil {
			t.Fatalf("write %s: %v", relative, err)
		}
		if _, _, err := broker.ReadFile(t.Context(), relative); err == nil {
			t.Errorf("protected path %q was readable", relative)
		}
		if _, err := broker.WriteFile(t.Context(), relative, verifierHash("do-not-expose"), []byte("changed")); err == nil {
			t.Errorf("protected path %q was writable", relative)
		}
	}
	allowed := filepath.Join(broker.root, "pkg", "visible.go")
	if err := os.MkdirAll(filepath.Dir(allowed), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(allowed, []byte("package pkg\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, _, err := broker.ListFiles(t.Context(), ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != "pkg/visible.go" {
		t.Fatalf("protected paths leaked through listing: %v", files)
	}
}

func TestWorkspaceBrokerRejectsTargetChangedBeforeCommit(t *testing.T) {
	broker := testWorkspaceBroker(t)
	if err := os.Mkdir(filepath.Join(broker.root, "pkg"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(broker.root, "pkg", "file.go")
	if err := os.WriteFile(path, []byte("provider-read"), 0o600); err != nil {
		t.Fatal(err)
	}
	broker.beforeCommit = func() {
		if err := os.WriteFile(path, []byte("concurrent-owner-edit"), 0o600); err != nil {
			t.Errorf("concurrent write: %v", err)
		}
	}
	receipt, err := broker.WriteFile(t.Context(), "pkg/file.go", verifierHash("provider-read"), []byte("provider-write"))
	if err == nil || receipt.ErrorSHA256 == "" || receipt.Mutated {
		t.Fatalf("receipt=%+v err=%v, want a pre-commit concurrency rejection", receipt, err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || string(data) != "concurrent-owner-edit" {
		t.Fatalf("target=%q err=%v, concurrent edit was overwritten", data, readErr)
	}
}

func TestWorkspaceBrokerRejectsPrimaryWorktreeAtConstruction(t *testing.T) {
	root := t.TempDir()
	runWorkspaceGit(t, root, "init", "-b", "main")
	runWorkspaceGit(t, root, "config", "user.email", "test@example.invalid")
	runWorkspaceGit(t, root, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(root, "seed"), []byte("seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	runWorkspaceGit(t, root, "add", "seed")
	runWorkspaceGit(t, root, "commit", "-m", "seed")
	revision := runWorkspaceGit(t, root, "rev-parse", "HEAD")
	if _, err := NewWorkspaceBroker(context.Background(), root, revision); err == nil {
		t.Fatal("primary worktree was accepted")
	}
}

func runWorkspaceGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}
