package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providercredential"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

func TestProviderNativeQualificationProducesCompleteLiveAndLocalMatrix(t *testing.T) {
	profile := providerNativeProfile()
	profile.AutomationPolicy = provider.NativeZAIToolsPolicyName
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	credential := &providerCredentialStoreFake{secret: []byte("native-qualification-key"), status: providercredential.Status{Backend: providercredential.BackendLinuxSecretTool, Available: true, Present: true, Evidence: providercredential.EvidenceOSProtectedProcessReadable}}
	admission := &providerNativeAdmissionFake{decision: ratelimit.Decision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	controller := &providerNativeToolControllerFake{verified: true}
	controllerReceipt := providerNativeControllerReceipt{SchemaVersion: "ntm.provider-native-controller.v1", Verified: true, VerificationSHA256: providerTestHash("verification"), Verification: &provider.VerificationReceipt{SchemaVersion: "ntm.disposable-verifier.v2", NetworkIsolated: true, CredentialsCleared: true, PIDNamespaceIsolated: true, CleanupVerified: true, DisposableWorktree: true, Commands: []provider.CommandVerification{{ID: "go-test", ExitCode: 0, ProcessWaited: true, CleanupVerified: true}}}}
	controllerWithReceipt := &providerNativeQualificationControllerFake{providerNativeToolControllerFake: *controller, receipt: controllerReceipt}
	var workspace providerNativeQualificationWorkspace
	nonceCalls := 0
	var stored providerqualification.Receipt
	deps := providerNativeQualificationDependencies{
		credential: credential,
		newNonce: func() (string, error) {
			nonceCalls++
			if nonceCalls == 1 {
				return "NTM_ACK_11111111111111111111111111111111", nil
			}
			return "NTM_ACK_22222222222222222222222222222222", nil
		},
		prepare: func(ctx context.Context, edit string) (providerNativeQualificationWorkspace, error) {
			var prepareErr error
			workspace, prepareErr = prepareProviderNativeQualificationWorkspace(ctx, edit)
			return workspace, prepareErr
		},
		newController: func(context.Context, providerNativeRunOptions) (providerNativeToolController, error) {
			return controllerWithReceipt, nil
		},
		runTools: func(_ context.Context, _ zai.NativeHTTPClient, request zai.NativeToolRequest) (zai.NativeToolReceipt, error) {
			if request.Model != identity.Model() || !request.AllowTools || len(request.Tools) != 4 || !strings.Contains(request.Prompt, workspace.ExpectedContent) {
				t.Fatalf("request=%+v", request)
			}
			if err := os.WriteFile(workspace.Worktree+string(os.PathSeparator)+"qualification.go", []byte(workspace.ExpectedContent), 0o600); err != nil {
				t.Fatal(err)
			}
			return zai.NativeToolReceipt{NativeReceipt: zai.NativeReceipt{Model: identity.Model(), ProviderRequestIDSHA256: providerTestHash("request"), NonceVerified: true, FinishReason: "stop", ToolCallCount: 1}, ControllerOwnedExecutor: true, Rounds: 2, ToolExecutions: []zai.NativeToolExecutionReceipt{{Round: 1, Name: "write_file", Succeeded: true}}}, nil
		},
		client: providerNativeHTTPClientFake{},
		store: func(_ string, receipt providerqualification.Receipt) (string, error) {
			stored = receipt
			return "/redacted/receipt.json", nil
		},
		sign:      func(context.Context, *providerqualification.Receipt) error { return nil },
		preflight: func(context.Context) error { return nil },
		admission: admission,
		now:       func() time.Time { return time.Unix(2_000_000_000, int64(nonceCalls)).UTC() },
	}
	cmd := &cobra.Command{}
	var output bytes.Buffer
	cmd.SetOut(&output)
	opts := providerQualificationOptions{profile: "zai-native", live: true, timeout: time.Second, suiteTimeout: time.Minute}
	if err := runProviderNativeQualification(cmd, opts, profile, identity, deps); err != nil {
		t.Fatal(err)
	}
	if !stored.Passed || len(stored.Checks) != 9 || countPassedQualificationChecks(stored) != 9 || admission.acquires != 1 || admission.releases != 1 || admission.successes != 1 {
		t.Fatalf("receipt=%+v admission=%+v", stored, admission)
	}
	if !strings.Contains(output.String(), "9/9") || strings.Contains(output.String(), "qualification-key") || credential.getID != providerCredentialID(identity) {
		t.Fatalf("output=%q credential=%q", output.String(), credential.getID)
	}
}

type providerNativeQualificationControllerFake struct {
	providerNativeToolControllerFake
	receipt providerNativeControllerReceipt
}

func (f *providerNativeQualificationControllerFake) Receipt() providerNativeControllerReceipt {
	return f.receipt
}
func (f *providerNativeQualificationControllerFake) CompletedVerification() bool { return true }

func TestProviderNativeQualificationRequiresBrokerCredentialBeforeWorkspaceMutation(t *testing.T) {
	profile := providerNativeProfile()
	profile.AutomationPolicy = provider.NativeZAIToolsPolicyName
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	prepared := false
	deps := providerNativeQualificationDependencies{
		credential: &providerCredentialStoreFake{}, newNonce: providerNativeNonce,
		runTools: zai.RunNativeTools, client: providerNativeHTTPClientFake{},
		newController: newProviderNativeController,
		prepare: func(context.Context, string) (providerNativeQualificationWorkspace, error) {
			prepared = true
			return providerNativeQualificationWorkspace{}, nil
		},
		store:     providerqualification.Store,
		sign:      func(context.Context, *providerqualification.Receipt) error { return nil },
		preflight: func(context.Context) error { return nil },
		admission: &providerNativeAdmissionFake{status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}},
		now:       time.Now,
	}
	if err := runProviderNativeQualification(&cobra.Command{}, providerQualificationOptions{profile: "zai-native", live: true, suiteTimeout: time.Second}, profile, identity, deps); err == nil || prepared {
		t.Fatalf("err=%v prepared=%t", err, prepared)
	}
}
