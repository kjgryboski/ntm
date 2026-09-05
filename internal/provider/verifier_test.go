package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const verifierTestRevision = "0123456789abcdef0123456789abcdef01234567"

type fakeVerifierInspector struct {
	path       string
	revision   string
	disposable bool
	err        error
}

func (f fakeVerifierInspector) Inspect(context.Context, string) (string, string, bool, error) {
	return f.path, f.revision, f.disposable, f.err
}

type fakeVerifierRunner struct {
	plans   []verificationPlan
	outcome verificationOutcome
	err     error
	wait    bool
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (f *fakeVerifierRunner) Run(ctx context.Context, plan verificationPlan) (verificationOutcome, error) {
	f.plans = append(f.plans, plan)
	if f.wait {
		<-ctx.Done()
		return verificationOutcome{Output: []byte("timed out"), OutputBytes: 9, ProcessWaited: true, CleanupVerified: true}, ctx.Err()
	}
	return f.outcome, f.err
}

func testVerifier(t *testing.T, runner *fakeVerifierRunner, inspector fakeVerifierInspector) *IsolatedVerifier {
	t.Helper()
	catalog, err := NewCommandCatalog([]ApprovedCommand{
		{ID: "go-test", Program: "go", Args: []string{"test", "./..."}, Timeout: time.Second},
		{ID: "go-vet", Program: "go", Args: []string{"vet", "./..."}, Timeout: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &IsolatedVerifier{catalog: catalog, runner: runner, inspector: inspector, goRoot: runtime.GOROOT(), now: func() time.Time { return time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC) }}
}

func TestVerifierGoRootSurvivesTrimpathWithoutMountingAnUnboundRoot(t *testing.T) {
	root := runtime.GOROOT()
	if root == "" {
		t.Skip("test toolchain has no GOROOT")
	}
	if got, err := verifierGoRoot("", root); err != nil || got != filepath.Clean(root) {
		t.Fatalf("build-bound toolchain lost: %q %v", got, err)
	}
	for _, invalid := range []string{"", "/", t.TempDir()} {
		if _, err := verifierGoRoot("", invalid); err == nil {
			t.Fatalf("unbound toolchain root accepted: %q", invalid)
		}
	}
	if _, err := verifierGoRoot(root, t.TempDir()); err == nil {
		t.Fatal("broken build binding silently fell back to ambient toolchain")
	}
}

func TestIsolatedVerifierBindsManifestAndBuildsCredentialFreeNetworkSandbox(t *testing.T) {
	runner := &fakeVerifierRunner{outcome: verificationOutcome{Output: []byte("secret provider output"), OutputBytes: int64(len("secret provider output")), ExitCode: 0, ProcessWaited: true, CleanupVerified: true}}
	verifier := testVerifier(t, runner, fakeVerifierInspector{path: "/worktrees/disposable", revision: verifierTestRevision, disposable: true})
	receipt, err := verifier.Verify(t.Context(), VerificationManifest{Worktree: "/input/path", Revision: verifierTestRevision, CommandIDs: []string{"go-test", "go-vet"}})
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.NetworkIsolated || !receipt.CredentialsCleared || !receipt.PIDNamespaceIsolated || !receipt.CleanupVerified || !receipt.DisposableWorktree || receipt.SchemaVersion != verifierSchemaVersion || len(receipt.Commands) != 2 {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	if strings.Contains(string(mustJSON(t, receipt)), "/worktrees/disposable") || strings.Contains(string(mustJSON(t, receipt)), "secret provider output") {
		t.Fatalf("receipt retained path or output: %s", mustJSON(t, receipt))
	}
	if len(runner.plans) != 2 || runner.plans[0].Program != "bwrap" || runner.plans[0].Dir != "/worktrees/disposable" {
		t.Fatalf("plans = %#v", runner.plans)
	}
	joined := strings.Join(runner.plans[0].Args, "\n")
	for _, want := range []string{"--die-with-parent", "--new-session", "--unshare-all", "--clearenv", "--cap-drop", "--ro-bind", "--bind", "--tmpfs", "--proc", "--dev", "--chdir", "/workspace"} {
		if !strings.Contains(joined, want) {
			t.Errorf("sandbox args omit %q: %s", want, joined)
		}
	}
	if strings.Contains(joined, "--ro-bind\n/\n/") || strings.Contains(joined, "/home") && !strings.Contains(joined, "/tmp/home") {
		t.Fatalf("sandbox exposed a broad host root/home mount: %s", joined)
	}
	for _, forbidden := range []string{"XAI_API_KEY", "ZAI_API_KEY", "ZAI_NATIVE_API_KEY", "HTTPS_PROXY"} {
		if strings.Contains(strings.Join(runner.plans[0].Env, "\n"), forbidden) {
			t.Errorf("sandbox inherited credential-bearing environment %q", forbidden)
		}
	}
	if receipt.Commands[0].OutputSHA256 != verifierHash("secret provider output") || receipt.Commands[0].CommandSHA256 == "" || receipt.ManifestSHA256 == "" {
		t.Fatalf("missing hash-bound evidence: %+v", receipt.Commands[0])
	}
}

func TestIsolatedVerifierCannotExfiltrateHostCredentialFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Bubblewrap verifier is Linux-only")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("Bubblewrap is unavailable")
	}
	root := t.TempDir()
	primary := filepath.Join(root, "primary")
	linked := filepath.Join(root, "linked")
	secretPath := filepath.Join(root, "host-credential")
	if err := os.Mkdir(primary, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretPath, []byte("must-not-enter-sandbox"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, output)
		}
		return strings.TrimSpace(string(output))
	}
	run(primary, "init", "-b", "main")
	goMod := "module verifier-exfiltration\n\ngo 1.26\n"
	testSource := "package verifier_exfiltration\n\nimport (\"os\"; \"testing\")\n\nfunc TestHostCredentialIsInvisible(t *testing.T) {\n if data, err := os.ReadFile(" + fmt.Sprintf("%q", secretPath) + "); err == nil { _ = os.WriteFile(\"leaked-credential\", data, 0600); t.Fatal(\"host credential was visible\") }\n}\n"
	if err := os.WriteFile(filepath.Join(primary, "go.mod"), []byte(goMod), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(primary, "exfiltration_test.go"), []byte(testSource), 0o600); err != nil {
		t.Fatal(err)
	}
	run(primary, "add", "go.mod", "exfiltration_test.go")
	run(primary, "-c", "user.name=Verifier Test", "-c", "user.email=verifier@example.invalid", "commit", "-m", "seed")
	revision := run(primary, "rev-parse", "HEAD")
	run(primary, "worktree", "add", "--detach", linked, revision)
	catalog, err := NewCommandCatalog([]ApprovedCommand{{ID: "go-test", Program: "go", Args: []string{"test", "./..."}, Timeout: time.Minute}})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewIsolatedVerifier(catalog)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := verifier.Verify(t.Context(), VerificationManifest{Worktree: linked, Revision: revision, CommandIDs: []string{"go-test"}})
	if err != nil {
		t.Fatalf("isolated adversarial verification: %v (receipt=%+v)", err, receipt)
	}
	if _, err := os.Stat(filepath.Join(linked, "leaked-credential")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("host credential exfiltration artifact exists: %v", err)
	}
}

func TestIsolatedVerifierFailsClosedBeforeDispatch(t *testing.T) {
	cases := []struct {
		name      string
		manifest  VerificationManifest
		inspector fakeVerifierInspector
	}{
		{"revision mismatch", VerificationManifest{Worktree: "/x", Revision: verifierTestRevision, CommandIDs: []string{"go-test"}}, fakeVerifierInspector{path: "/worktrees/d", revision: "abcdefabcdefabcdefabcdefabcdefabcdefabcd", disposable: true}},
		{"primary worktree", VerificationManifest{Worktree: "/x", Revision: verifierTestRevision, CommandIDs: []string{"go-test"}}, fakeVerifierInspector{path: "/worktrees/d", revision: verifierTestRevision, disposable: false}},
		{"unknown command", VerificationManifest{Worktree: "/x", Revision: verifierTestRevision, CommandIDs: []string{"shell"}}, fakeVerifierInspector{path: "/worktrees/d", revision: verifierTestRevision, disposable: true}},
		{"duplicate command", VerificationManifest{Worktree: "/x", Revision: verifierTestRevision, CommandIDs: []string{"go-test", "go-test"}}, fakeVerifierInspector{path: "/worktrees/d", revision: verifierTestRevision, disposable: true}},
		{"bad revision", VerificationManifest{Worktree: "/x", Revision: "main", CommandIDs: []string{"go-test"}}, fakeVerifierInspector{path: "/worktrees/d", revision: verifierTestRevision, disposable: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeVerifierRunner{}
			_, err := testVerifier(t, runner, tc.inspector).Verify(t.Context(), tc.manifest)
			if err == nil || len(runner.plans) != 0 {
				t.Fatalf("err=%v plans=%d, want fail closed before dispatch", err, len(runner.plans))
			}
		})
	}
}

func TestIsolatedVerifierRecordsTimeoutAndWaitedCleanup(t *testing.T) {
	runner := &fakeVerifierRunner{wait: true}
	verifier := testVerifier(t, runner, fakeVerifierInspector{path: "/worktrees/d", revision: verifierTestRevision, disposable: true})
	verifier.catalog.commands["go-test"] = ApprovedCommand{ID: "go-test", Program: "go", Args: []string{"test", "./..."}, Timeout: time.Millisecond}
	receipt, err := verifier.Verify(t.Context(), VerificationManifest{Worktree: "/x", Revision: verifierTestRevision, CommandIDs: []string{"go-test"}})
	if !errors.Is(err, context.DeadlineExceeded) || len(receipt.Commands) != 1 {
		t.Fatalf("err=%v receipt=%+v", err, receipt)
	}
	entry := receipt.Commands[0]
	if !entry.TimedOut || !entry.ProcessWaited || entry.ErrorSHA256 == "" || entry.OutputSHA256 != verifierHash("timed out") {
		t.Fatalf("timeout cleanup evidence = %+v", entry)
	}
}

func TestCommandCatalogRejectsMutableOrUnsafeCommandForms(t *testing.T) {
	cases := [][]ApprovedCommand{
		{{ID: "go-test", Program: "/bin/sh", Args: []string{"-c", "echo bad"}, Timeout: time.Second}},
		{{ID: "go-test", Program: "go", Args: []string{"test", "../outside"}, Timeout: time.Second}},
		{{ID: "go-test", Program: "go", Args: []string{"test"}, Timeout: 0}},
		{{ID: "go-test", Program: "go", Args: []string{"test"}, Timeout: time.Second}, {ID: "go-test", Program: "go", Args: []string{"vet"}, Timeout: time.Second}},
	}
	for _, commands := range cases {
		if _, err := NewCommandCatalog(commands); err == nil {
			t.Fatalf("unsafe catalog accepted: %#v", commands)
		}
	}
	catalog, err := DefaultDisposableCommandCatalog()
	if err != nil || len(catalog.commands) != 3 {
		t.Fatalf("default catalog = %#v err=%v", catalog, err)
	}
}

func TestGitWorktreeInspectorRejectsPrimaryAndBindsLinkedWorktreeRevision(t *testing.T) {
	base := t.TempDir()
	runGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", base}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, output)
		}
		return strings.TrimSpace(string(output))
	}
	runGit("init")
	if err := os.WriteFile(filepath.Join(base, "seed.txt"), []byte("seed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit("add", "seed.txt")
	runGit("-c", "user.name=Verifier Test", "-c", "user.email=verifier@example.invalid", "commit", "-m", "seed")
	linked := filepath.Join(t.TempDir(), "linked")
	runGit("worktree", "add", "-b", "verifier-linked", linked, "HEAD")

	inspector := gitWorktreeInspector{}
	_, _, disposable, err := inspector.Inspect(t.Context(), base)
	if err != nil || disposable {
		t.Fatalf("primary inspection disposable=%v err=%v, want false nil", disposable, err)
	}
	resolved, revision, disposable, err := inspector.Inspect(t.Context(), linked)
	if err != nil || !disposable || !gitRevision.MatchString(revision) || filepath.Clean(resolved) != filepath.Clean(linked) {
		t.Fatalf("linked inspection resolved=%q revision=%q disposable=%v err=%v", resolved, revision, disposable, err)
	}
}
