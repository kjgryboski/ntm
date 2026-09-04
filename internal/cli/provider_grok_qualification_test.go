package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/agent"
	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/grok"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
)

func grokQualificationDepsForTest(t *testing.T, profile config.ProviderProfileConfig, result grok.Result) (providerGrokQualificationDependencies, *providerSessionAdmissionFake, *providerqualification.Receipt, *grok.Request, *int) {
	t.Helper()
	admission := &providerSessionAdmissionFake{
		decision: ratelimit.Decision{Allowed: true, NoFailover: true},
		status:   ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared},
	}
	var stored providerqualification.Receipt
	var request grok.Request
	calls := 0
	now := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	deps := providerGrokQualificationDependencies{
		authority: func(context.Context, string, config.ProviderProfileConfig, provider.Identity) (string, error) {
			return "/usr/local/bin/grok", nil
		},
		version: func(context.Context, string) (string, error) { return profile.RuntimeVersion, nil },
		hashBinary: func(string) (string, error) {
			return strings.Repeat("b", 64), nil
		},
		run: func(_ context.Context, _ grok.Runner, got grok.Request) (grok.Result, error) {
			calls++
			request = got
			return result, nil
		},
		store: func(_ string, receipt providerqualification.Receipt) (string, error) {
			stored = receipt
			return "/redacted/grok-observe-only.json", nil
		},
		sign:      func(context.Context, *providerqualification.Receipt) error { return nil },
		preflight: func(context.Context) error { return nil },
		admission: admission,
		now:       func() time.Time { return now },
		getwd:     func() (string, error) { return "/qualification", nil },
		newNonce:  func() (string, error) { return "NTM_ACK_GROK_QUALIFICATION", nil },
	}
	return deps, admission, &stored, &request, &calls
}

func TestProviderGrokQualificationProducesHonestObserveOnlyNoGoReceipt(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	result := grok.Result{
		Success: true, AcknowledgementVerified: true, Authenticated: true,
		Model: identity.Model(), ModelEvidence: "completion_metadata",
		ResolvedModel: grok.ExpectedResolvedModel(profile.RuntimeVersion, identity.Model()), ResolvedModelEvidence: "completion_metadata.usage.model_usage_singleton",
		RuntimeEventContract: provider.EventContractReport{Passed: true},
		Cleanup:              grok.ProcessCleanupReceipt{ObservedAt: time.Date(2026, time.September, 3, 12, 0, 1, 0, time.UTC), Reaped: true, ResidualPIDs: []int32{}},
	}
	deps, admission, stored, request, calls := grokQualificationDepsForTest(t, profile, result)
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	var output bytes.Buffer
	cmd.SetOut(&output)
	err = runProviderGrokQualification(cmd, providerQualificationOptions{profile: "grok", live: true, timeout: time.Second, suiteTimeout: time.Second}, profile, identity, deps)
	var exit *providerQualificationExitError
	if !errors.As(err, &exit) {
		t.Fatalf("err=%v, want NO-GO exit", err)
	}
	if *calls != 1 || admission.acquires != 1 || admission.releases != 1 || admission.successes != 0 {
		t.Fatalf("calls=%d admission=%+v", *calls, admission)
	}
	if request.ExpectedNonce != "NTM_ACK_GROK_QUALIFICATION" || request.Model != identity.Model() || request.RuntimeVersion != profile.RuntimeVersion || request.CWD != "/qualification" || request.Binary != "/usr/local/bin/grok" || request.RuntimeHome != profile.RuntimeHome || len(request.AutomationPolicyArgs) == 0 {
		t.Fatalf("unsafe or incomplete observe request: %+v", *request)
	}
	if stored.Passed || stored.Transport != "xai_acp" || stored.Validate() != nil {
		t.Fatalf("receipt=%+v validate=%v", *stored, stored.Validate())
	}
	if stored.RuntimeSHA256 != strings.Repeat("b", 64) {
		t.Fatalf("observe receipt omitted exact runtime digest: %q", stored.RuntimeSHA256)
	}
	passed := make(map[string]bool, len(stored.Checks))
	for _, check := range stored.Checks {
		passed[check.Name] = check.Passed
	}
	if !passed[providerqualification.CheckIdentity] || !passed[providerqualification.CheckProcessCleanup] {
		t.Fatalf("observed checks were not retained: %+v", stored.Checks)
	}
	for _, name := range providerqualification.GrokRequiredChecks() {
		if name != providerqualification.CheckIdentity && name != providerqualification.CheckProcessCleanup && passed[name] {
			t.Fatalf("unexercised lifecycle check %q was fabricated as passed", name)
		}
	}
}

func TestProviderGrokHeadlessLineageQualificationProducesSignedPartialReceipt(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := grok.Result{
		Success: true, AcknowledgementVerified: true, Authenticated: true, ProviderSessionID: "raw-parent-session",
		Model: identity.Model(), ModelEvidence: "completion_metadata",
		ResolvedModel: grok.ExpectedResolvedModel(profile.RuntimeVersion, identity.Model()), ResolvedModelEvidence: "completion_metadata.usage.model_usage_singleton",
		RuntimeEventContract: provider.EventContractReport{Passed: true},
		Cleanup:              grok.ProcessCleanupReceipt{ObservedAt: time.Now().UTC(), Reaped: true, ResidualPIDs: []int32{}, LocalTermination: "observed_tree_terminated_verified"},
	}
	deps, admission, stored, _, calls := grokQualificationDepsForTest(t, profile, bootstrap)
	workspace := providerGrokLineageWorkspace{Root: "/tmp/ntm-grok-lineage-qualification-test", Primary: "/tmp/ntm-grok-lineage-qualification-test/primary", Worktree: "/tmp/ntm-grok-lineage-qualification-test/linked", RuntimeHome: "/tmp/ntm-grok-lineage-qualification-test/grok-home"}
	deps.prepareLineage = func(context.Context, string) (providerGrokLineageWorkspace, error) { return workspace, nil }
	cleanups := 0
	deps.cleanupLineage = func(context.Context, providerGrokLineageWorkspace) error { cleanups++; return nil }
	deps.sessionRunner = grok.HeadlessOSRunner{}
	sessionCalls := 0
	deps.runSession = func(_ context.Context, _ grok.LifecycleRunner, req grok.SessionRequest) (grok.SessionReceipt, error) {
		sessionCalls++
		parent := sha256StringCLI(req.SessionID)
		child := parent
		if req.Action == grok.SessionFork {
			child = sha256StringCLI("fork-child")
		}
		zero := 0
		return grok.SessionReceipt{
			Action: req.Action, Fork: req.Action == grok.SessionFork,
			ParentSessionSHA256: parent, ChildSessionSHA256: child,
			CWDSHA256: sha256StringCLI(req.CWD), WorktreeSHA256: sha256StringCLI(req.Worktree),
			PolicySHA256: req.PolicySHA256, ConfigSHA256: req.ConfigSHA256, BinarySHA256: req.BinarySHA256,
			NonceSHA256: sha256StringCLI(req.ExpectedNonce), LineageBound: true, ProviderAcknowledged: true,
			CompletionConfirmed: true, StopReason: "end_turn", RequestedModel: req.Model,
			ExpectedReceiptModel: grok.ExpectedResolvedModel(req.RuntimeVersion, req.Model), Model: grok.ExpectedResolvedModel(req.RuntimeVersion, req.Model), ModelEvidence: "end.modelUsage_singleton",
			ExitCode: &zero, Cancellation: grok.CancellationReceipt{LocalTermination: "not_required_process_exited", ResidualPIDs: []int32{}, ObservedAt: time.Now().UTC()},
		}, nil
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	var output bytes.Buffer
	cmd.SetOut(&output)
	err = runProviderGrokQualification(cmd, providerQualificationOptions{profile: "grok", live: true, grokHeadlessLineage: true, timeout: time.Second, suiteTimeout: time.Second}, profile, identity, deps)
	var exit *providerQualificationExitError
	if !errors.As(err, &exit) {
		t.Fatalf("err=%v, want partial qualification exit", err)
	}
	if *calls != 1 || sessionCalls != 2 || cleanups != 1 || admission.acquires != 1 || admission.releases != 1 || admission.successes != 0 {
		t.Fatalf("ACP=%d sessions=%d cleanups=%d admission=%+v", *calls, sessionCalls, cleanups, admission)
	}
	if stored.Transport != "xai_headless_session" || stored.Passed || stored.Validate() != nil {
		t.Fatalf("stored receipt=%+v validate=%v", *stored, stored.Validate())
	}
	if stored.RuntimeSHA256 != strings.Repeat("b", 64) {
		t.Fatalf("lineage receipt omitted exact runtime digest: %q", stored.RuntimeSHA256)
	}
	passed := make(map[string]bool, len(stored.Checks))
	for _, check := range stored.Checks {
		passed[check.Name] = check.Passed
	}
	for _, name := range []string{providerqualification.CheckIdentity, providerqualification.CheckResume, providerqualification.CheckProcessCleanup} {
		if !passed[name] {
			t.Fatalf("lineage receipt omitted proven check %q: %+v", name, stored.Checks)
		}
	}
	for _, name := range []string{providerqualification.CheckWorkspaceEdit, providerqualification.CheckTestCommand, providerqualification.CheckSecretDenied, providerqualification.CheckPushDenied, providerqualification.CheckCrashRecovery, providerqualification.CheckCancellation} {
		if passed[name] {
			t.Fatalf("lineage receipt fabricated unexercised check %q", name)
		}
	}
	if strings.Contains(output.String(), "raw-parent-session") {
		t.Fatal("lineage qualification output leaked the raw provider session id")
	}
}

func TestProviderGrokLineageWorkspaceIsDisposableAndCredentialIsolated(t *testing.T) {
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "auth.json"), []byte(`{"cached":"redacted-test-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace, err := prepareProviderGrokLineageWorkspace(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Root == source || workspace.RuntimeHome == source || filepath.Dir(workspace.Worktree) != workspace.Root {
		t.Fatalf("workspace was not isolated: %+v", workspace)
	}
	if body, err := os.ReadFile(filepath.Join(workspace.RuntimeHome, "auth.json")); err != nil || string(body) != `{"cached":"redacted-test-token"}` {
		t.Fatalf("isolated auth copy invalid: body=%q err=%v", body, err)
	}
	if linked, err := providerIsLinkedGitWorktree(t.Context(), workspace.Worktree); err != nil || !linked {
		t.Fatalf("qualification worktree is not linked: linked=%v err=%v", linked, err)
	}
	if err := cleanupProviderGrokLineageWorkspace(t.Context(), workspace); err != nil {
		t.Fatal(err)
	}
	if !providerGrokLineageWorkspaceRemoved(workspace) {
		t.Fatal("qualification workspace or isolated session home remained after cleanup")
	}
}

func TestProviderGrokQualificationFailsClosedForNonObservePolicy(t *testing.T) {
	profile := providerTestGrokProfile(agent.GrokWorkspaceWritePolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	deps, _, _, _, calls := grokQualificationDepsForTest(t, profile, grok.Result{})
	err = runProviderGrokQualification(&cobra.Command{}, providerQualificationOptions{profile: "grok", live: true, timeout: time.Second, suiteTimeout: time.Second}, profile, identity, deps)
	if err == nil || *calls != 0 {
		t.Fatalf("err=%v calls=%d; non-observe policy must not dispatch", err, *calls)
	}
}

func TestProviderQualificationRoutesGrokToObserveOnlyProducer(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	result := grok.Result{Success: true, AcknowledgementVerified: true, Authenticated: true, Model: identity.Model(), ModelEvidence: "completion_metadata", ResolvedModel: grok.ExpectedResolvedModel(profile.RuntimeVersion, identity.Model()), ResolvedModelEvidence: "completion_metadata.usage.model_usage_singleton", RuntimeEventContract: provider.EventContractReport{Passed: true}, Cleanup: grok.ProcessCleanupReceipt{ObservedAt: time.Now().UTC(), Reaped: true, ResidualPIDs: []int32{}}}
	grokDeps, _, _, _, calls := grokQualificationDepsForTest(t, profile, result)
	previous := providerGrokQualificationDeps
	providerGrokQualificationDeps = grokDeps
	t.Cleanup(func() { providerGrokQualificationDeps = previous })
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	err = runProviderQualification(cmd, providerQualificationOptions{profile: "grok", live: true, timeout: time.Second, suiteTimeout: time.Second}, providerQualificationDependencies{
		loadConfig: func() *config.Config {
			return &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"grok": profile}}
		},
	})
	var exit *providerQualificationExitError
	if !errors.As(err, &exit) || *calls != 1 {
		t.Fatalf("err=%v calls=%d; expected the dedicated Grok producer", err, *calls)
	}
}
