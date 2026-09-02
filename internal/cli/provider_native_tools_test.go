package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

func TestProviderNativeControllerRequiresVerificationAfterLastWrite(t *testing.T) {
	primary := t.TempDir()
	runProviderToolsGit(t, primary, "init", "-b", "main")
	runProviderToolsGit(t, primary, "config", "user.email", "test@example.invalid")
	runProviderToolsGit(t, primary, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(primary, "source.go"), []byte("package source\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runProviderToolsGit(t, primary, "add", "source.go")
	runProviderToolsGit(t, primary, "commit", "-m", "seed")
	revision := runProviderToolsGit(t, primary, "rev-parse", "HEAD")
	linked := filepath.Join(t.TempDir(), "linked")
	runProviderToolsGit(t, primary, "worktree", "add", "--detach", linked, revision)
	workspace, err := provider.NewWorkspaceBroker(t.Context(), linked, revision)
	if err != nil {
		t.Fatal(err)
	}
	verifier := &providerVerifierFake{receipt: provider.VerificationReceipt{SchemaVersion: "ntm.disposable-verifier.v2", DisposableWorktree: true, NetworkIsolated: true, CredentialsCleared: true, PIDNamespaceIsolated: true, CleanupVerified: true, Commands: []provider.CommandVerification{{ID: "go-test", ExitCode: 0, ProcessWaited: true, CleanupVerified: true}}}}
	controller := &providerNativeController{workspace: workspace, verifier: verifier, manifest: provider.VerificationManifest{Worktree: linked, Revision: revision, CommandIDs: []string{"go-test"}}, receipt: providerNativeControllerReceipt{SchemaVersion: "ntm.provider-native-controller.v1", ManifestSHA256: providerTestHash("manifest"), WorkspaceOperations: []provider.WorkspaceOperationReceipt{}}}

	read, err := controller.ExecuteNativeTool(t.Context(), zai.NativeToolCall{ID: "read", Name: "read_file", Arguments: json.RawMessage(`{"path":"source.go"}`)})
	if err != nil || !strings.Contains(read.Content, "package source") || controller.CompletedVerification() {
		t.Fatalf("read=%+v err=%v receipt=%+v", read, err, controller.Receipt())
	}
	writeArgs, _ := json.Marshal(map[string]string{"path": "source.go", "expected_sha256": providerTestHash("package source\n"), "content": "package changed\n"})
	if _, err := controller.ExecuteNativeTool(t.Context(), zai.NativeToolCall{ID: "write", Name: "write_file", Arguments: writeArgs}); err != nil {
		t.Fatal(err)
	}
	if controller.CompletedVerification() || !controller.Receipt().Dirty {
		t.Fatalf("write did not invalidate verification: %+v", controller.Receipt())
	}
	if _, err := controller.ExecuteNativeTool(t.Context(), zai.NativeToolCall{ID: "verify", Name: "verify_worktree", Arguments: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if !controller.CompletedVerification() || controller.Receipt().Dirty || len(controller.Receipt().WorkspaceOperations) != 2 {
		t.Fatalf("verification state=%+v", controller.Receipt())
	}
	secondWrite, _ := json.Marshal(map[string]string{"path": "source.go", "expected_sha256": providerTestHash("package changed\n"), "content": "package changed_again\n"})
	if _, err := controller.ExecuteNativeTool(t.Context(), zai.NativeToolCall{ID: "write2", Name: "write_file", Arguments: secondWrite}); err != nil {
		t.Fatal(err)
	}
	if controller.CompletedVerification() {
		t.Fatal("write after verification retained a stale passing gate")
	}
}

func TestProviderNativeControllerRejectsUnknownArgumentsAndTools(t *testing.T) {
	controller := &providerNativeController{}
	if _, err := controller.ExecuteNativeTool(t.Context(), zai.NativeToolCall{Name: "shell", Arguments: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("uninitialized controller accepted tool")
	}
	var args struct {
		Path string `json:"path"`
	}
	if err := decodeProviderNativeToolArgs(json.RawMessage(`{"path":"x","extra":true}`), &args); err == nil {
		t.Fatal("unknown provider arguments were accepted")
	}
	definitions := providerNativeToolDefinitions()
	if len(definitions) != 4 {
		t.Fatalf("definitions=%+v", definitions)
	}
	for _, definition := range definitions {
		if definition.Name == "shell" || definition.Name == "bash" {
			t.Fatalf("unsafe tool advertised: %+v", definition)
		}
	}
}

type providerNativeToolControllerFake struct{ verified bool }

func (f *providerNativeToolControllerFake) ExecuteNativeTool(context.Context, zai.NativeToolCall) (zai.NativeToolResult, error) {
	return zai.NativeToolResult{}, nil
}
func (f *providerNativeToolControllerFake) Receipt() providerNativeControllerReceipt {
	return providerNativeControllerReceipt{SchemaVersion: "ntm.provider-native-controller.v1", Verified: f.verified}
}
func (f *providerNativeToolControllerFake) CompletedVerification() bool { return f.verified }

func TestProviderNativeRunToolsUsesSeparatePolicyAndControllerGate(t *testing.T) {
	profile := providerNativeProfile()
	profile.AutomationPolicy = provider.NativeZAIToolsPolicyName
	admission := &providerNativeAdmissionFake{decision: ratelimit.Decision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerNativeDeps(profile, admission)
	qualification := providerNativeToolsTestQualification(t, profile, time.Unix(1, 0).UTC())
	deps.qualificationStore = func(string, string) (providerqualification.Receipt, string, error) {
		return qualification, "/redacted/qualification.json", nil
	}
	controller := &providerNativeToolControllerFake{verified: true}
	deps.newController = func(context.Context, providerNativeRunOptions) (providerNativeToolController, error) {
		return controller, nil
	}
	deps.runTools = func(_ context.Context, _ zai.NativeHTTPClient, request zai.NativeToolRequest) (zai.NativeToolReceipt, error) {
		if !request.AllowTools || len(request.Tools) != 4 || request.Executor != controller {
			t.Fatalf("tool request=%+v", request)
		}
		return zai.NativeToolReceipt{NativeReceipt: zai.NativeReceipt{Model: profile.Model, NonceVerified: true, FinishReason: "stop", OutputSHA256: providerTestHash("output")}, ControllerOwnedExecutor: true, Rounds: 2}, nil
	}
	opts := providerNativeRunOptions{profile: "zai-native", prompt: "make change", operationID: "native-tools", live: true, tools: true, worktree: "/redacted/linked", revision: strings.Repeat("a", 40), commands: []string{"go-test"}, qualificationAge: 24 * time.Hour}
	if err := runProviderNative(&cobra.Command{}, opts, deps); err != nil {
		t.Fatal(err)
	}
}

func TestProviderNativeRunToolsRejectsMissingStaleTamperedAndMismatchedQualification(t *testing.T) {
	profile := providerNativeProfile()
	profile.AutomationPolicy = provider.NativeZAIToolsPolicyName
	valid := providerNativeToolsTestQualification(t, profile, time.Unix(1, 0).UTC())
	stale := providerNativeToolsTestQualification(t, profile, time.Unix(1, 0).UTC().Add(-48*time.Hour))
	tampered := valid
	tampered.RuntimeVersion = "tampered-adapter"
	mismatched := valid
	mismatched.IdentitySHA256 = providerTestHash("different-identity")
	cases := []struct {
		name    string
		receipt providerqualification.Receipt
		err     error
	}{
		{name: "missing", err: errors.New("missing")},
		{name: "stale", receipt: stale},
		{name: "tampered", receipt: tampered},
		{name: "mismatched", receipt: mismatched},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			admission := &providerNativeAdmissionFake{decision: ratelimit.Decision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
			deps := providerNativeDeps(profile, admission)
			deps.qualificationStore = func(string, string) (providerqualification.Receipt, string, error) { return tc.receipt, "", tc.err }
			dispatched := false
			deps.runTools = func(context.Context, zai.NativeHTTPClient, zai.NativeToolRequest) (zai.NativeToolReceipt, error) {
				dispatched = true
				return zai.NativeToolReceipt{}, nil
			}
			opts := providerNativeRunOptions{profile: "zai-native", prompt: "bounded", operationID: "qualification-" + tc.name, live: true, tools: true, worktree: "/redacted/linked", revision: strings.Repeat("a", 40), commands: []string{"go-test"}, qualificationAge: 24 * time.Hour}
			if err := runProviderNative(&cobra.Command{}, opts, deps); err == nil || dispatched || admission.acquires != 0 {
				t.Fatalf("qualification gate err=%v dispatched=%t admission=%+v", err, dispatched, admission)
			}
		})
	}
}

func providerNativeToolsTestQualification(t *testing.T, profile config.ProviderProfileConfig, completedAt time.Time) providerqualification.Receipt {
	t.Helper()
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	checks := nativeQualificationChecks()
	for i := range checks {
		checks[i].Passed = true
		checks[i].Provenance = "live"
		checks[i].EvidenceSHA256 = providerTestHash(checks[i].Name)
	}
	receipt := providerqualification.Receipt{
		Provider: "zai", Transport: "zai_native_api", IdentitySHA256: identity.Hash(), PolicySHA256: providerNativeToolsPolicySHA256(), RuntimeVersion: providerNativeAdapterVersion,
		StartedAt: completedAt.Add(-time.Minute), CompletedAt: completedAt, DisposableRepoHash: providerTestHash("native-tools-repo"), Checks: checks,
	}
	if err := receipt.Finalize(); err != nil {
		t.Fatal(err)
	}
	payload, err := receipt.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := newProviderNativeTestSigner()(t.Context(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.AttachAttestation(signature); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func runProviderToolsGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}
