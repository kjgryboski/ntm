package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/agent"
	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/grok"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

func providerRouteTestDeps(t *testing.T, snapshot ratelimit.SubscriptionCapacitySnapshot) providerRouteDependencies {
	t.Helper()
	root := t.TempDir()
	zaiProfile := providerCodexProfile(root)
	grokProfile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	return providerRouteDependencies{
		loadConfig: func() *config.Config {
			return &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"zai-codex": zaiProfile, "grok-acp": grokProfile}}
		},
		now:              func() time.Time { return time.Date(2026, time.January, 5, 1, 0, 0, 0, time.UTC) },
		admission:        &providerCodexSubscriptionAdmissionFake{snapshot: snapshot},
		isLinkedWorktree: func(context.Context, string) (bool, error) { return true, nil },
		readFile:         os.ReadFile,
	}
}

func TestPlanZAISubscriptionRouteUsesExactModelAndSubscriptionCapacity(t *testing.T) {
	snapshot := ratelimit.SubscriptionCapacitySnapshot{Scope: provider.CapacityControlScopeLocalShared, FiveHourCreditsLimit: 2000, WeeklyCreditsLimit: 10000, AdmissionReservation: 1}
	plan, err := planZAISubscriptionRoute("zai-codex", "implementation", providerRouteTestDeps(t, snapshot))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Outcome != providerRouteOutcomeAdmitted || plan.RequestedModel != "glm-5.3" || plan.Workload != providerCodexWorkloadImplementation || !plan.NoFailover {
		t.Fatalf("route plan = %+v", plan)
	}
}

func TestPlanZAISubscriptionRouteUsesFlashOnlyForExplicitBulkReview(t *testing.T) {
	snapshot := ratelimit.SubscriptionCapacitySnapshot{Scope: provider.CapacityControlScopeLocalShared, FiveHourCreditsLimit: 2000, WeeklyCreditsLimit: 10000, AdmissionReservation: 1}
	deps := providerRouteTestDeps(t, snapshot)
	root := t.TempDir()
	flash := providerCodexProfile(root)
	flash.Model = "glm-5.3-flash"
	deps.loadConfig = func() *config.Config {
		return &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"zai-flash": flash}}
	}
	plan, err := planZAISubscriptionRoute("zai-flash", "bulk-review", deps)
	if err != nil || plan.Workload != "bulk-review" || plan.RequestedModel != "glm-5.3-flash" || plan.Outcome != providerRouteOutcomeAdmitted {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
}

func TestProviderRoutingCommandExposesPlanClassificationAndWorkflow(t *testing.T) {
	cmd := newProviderRoutingCmd()
	for _, want := range []string{"plan", "classify", "workflow"} {
		found := false
		for _, child := range cmd.Commands() {
			if child.Name() == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("route command does not expose %q", want)
		}
	}
}

func TestPlanZAISubscriptionRouteSeparatesFiveHourAndWeeklyExhaustion(t *testing.T) {
	cases := []struct {
		name, want string
		snapshot   ratelimit.SubscriptionCapacitySnapshot
	}{
		{name: "five hour", want: providerRouteOutcomeFiveHourExhausted, snapshot: ratelimit.SubscriptionCapacitySnapshot{Scope: provider.CapacityControlScopeLocalShared, FiveHourCreditsUsed: 2000, FiveHourCreditsLimit: 2000, WeeklyCreditsLimit: 10000, AdmissionReservation: 1}},
		{name: "weekly", want: providerRouteOutcomeWeeklyExhausted, snapshot: ratelimit.SubscriptionCapacitySnapshot{Scope: provider.CapacityControlScopeLocalShared, FiveHourCreditsLimit: 2000, WeeklyCreditsUsed: 10000, WeeklyCreditsLimit: 10000, AdmissionReservation: 1}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			plan, err := planZAISubscriptionRoute("zai-codex", "review", providerRouteTestDeps(t, test.snapshot))
			if err != nil || plan.Outcome != test.want || !plan.NoFailover {
				t.Fatalf("plan=%+v err=%v", plan, err)
			}
		})
	}
}

func TestClassifyZAIRouteOutcomeHasNoCrossProviderFallback(t *testing.T) {
	cases := []struct {
		code, want string
	}{
		{"1001", providerRouteOutcomeAuthentication},
		{"1305", providerRouteOutcomeOverloaded},
		{"1302", providerRouteOutcomeRateLimited},
		{"1311", providerRouteOutcomeUnsupportedModel},
		{"1301", providerRouteOutcomeUsageRestricted},
		{"1113", providerRouteOutcomeInsufficientBalance},
	}
	for _, test := range cases {
		plan := classifyZAIRouteOutcome(0, test.code)
		if plan.Outcome != test.want || !plan.NoFailover || !strings.Contains(plan.Fallback, "none") {
			t.Fatalf("code=%s plan=%+v", test.code, plan)
		}
	}
}

func TestPlanZAIGrokWorkflowUsesExactProfilesAndManualReconciliation(t *testing.T) {
	plan, err := planZAIGrokWorkflow(context.Background(), "zai-codex", "grok-acp", t.TempDir(), "workflow-zai-1", "grok-parent-1", true, providerRouteTestDeps(t, ratelimit.SubscriptionCapacitySnapshot{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Stages) != 3 || plan.Stages[0].AgentType != "zai" || plan.Stages[1].AgentType != "grok" || plan.Stages[1].Transport != "xai_headless_session" || plan.Stages[2].Name != providerWorkflowReconcileStage || !plan.NoAutomaticFailover || !strings.Contains(plan.ReconciliationPolicy, "manual") || !validProviderWorkflowPlan(plan) {
		t.Fatalf("workflow plan = %+v", plan)
	}
}

func TestPlanZAIGrokWorkflowFailsClosedWithoutDisposableConfirmation(t *testing.T) {
	_, err := planZAIGrokWorkflow(context.Background(), "zai-codex", "grok-acp", t.TempDir(), "workflow-zai-1", "grok-parent-1", false, providerRouteTestDeps(t, ratelimit.SubscriptionCapacitySnapshot{}))
	if err == nil || !strings.Contains(err.Error(), "disposable-worktree") {
		t.Fatalf("err=%v", err)
	}
}

func TestReconcileZAIGrokWorkflowVerifiesBothSignatures(t *testing.T) {
	dir := t.TempDir()
	worktree := t.TempDir()
	deps := providerRouteTestDeps(t, ratelimit.SubscriptionCapacitySnapshot{})
	signer := newProviderNativeTestSigner()
	preflight, err := signer(t.Context(), []byte(providerattestation.ProviderAttestationPreflight))
	if err != nil {
		t.Fatal(err)
	}
	deps.trustedSigner = func(context.Context) (providerattestation.KeyMetadata, error) {
		return preflight.KeyMetadata, nil
	}
	var signerProfiles []string
	deps.profileTrustedSigner = func(_ context.Context, profile config.ProviderProfileConfig) (providerattestation.KeyMetadata, error) {
		signerProfiles = append(signerProfiles, profile.Runtime)
		return preflight.KeyMetadata, nil
	}
	plan, err := planZAIGrokWorkflow(context.Background(), "zai-codex", "grok-acp", worktree, "workflow-zai-1", "grok-parent-1", true, deps)
	if err != nil {
		t.Fatal(err)
	}
	zaiProfile := deps.loadConfig().ProviderProfiles["zai-codex"]
	zaiSpec := zai.CodexRunSpec{
		RequestedModel: "glm-5.3", CWD: worktree, WorkspaceWrite: true,
		ConfigSHA256: zaiProfile.ConfigSHA256, BinarySHA256: zaiProfile.RuntimeSHA256,
		BrokerCommandSHA256: zaiProfile.BrokerCommandSHA256, CredentialBridgeCommandSHA256: zaiProfile.CredentialBridgeCommandSHA256,
		PolicySHA256: providerCodexPolicySHA256(), RuntimeVersion: zaiProfile.RuntimeVersion,
	}
	zaiReceipt := successfulProviderCodexReceipt(zaiSpec)
	zaiReceipt.ToolEventCount = 1
	zaiReceipt.PolicySHA256 = plan.Stages[0].PolicySHA256
	zaiReceipt.CWDSHA256 = plan.WorktreeSHA256
	refreshProviderCodexRuntimeContract(&zaiReceipt, zaiSpec)
	zaiOutput := providerCodexRunOutput{
		SchemaVersion: providerCodexRunSchema, Success: true, Profile: plan.Stages[0].ProviderProfile, Transport: "zai_codex_runtime",
		IdentitySHA256: plan.Stages[0].IdentitySHA256,
		ConfigSHA256:   zaiProfile.ConfigSHA256, BinarySHA256: zaiProfile.RuntimeSHA256,
		BrokerCommandSHA256: zaiProfile.BrokerCommandSHA256, CredentialBridgeSHA256: zaiProfile.CredentialBridgeCommandSHA256,
		RuntimeVersion: zaiProfile.RuntimeVersion, BrokerCredentialSHA256: providerTestHash("broker-credential"),
		QualificationSHA256: providerTestHash("zai-qualification"), OperationIDSHA256: plan.ZAIOperationIDSHA256,
		BindingSHA256: providerTestHash("binding"), ReceiptState: "completed", State: "completed",
		Admission: providerCodexSubscriptionAdmissionEvidence{Allowed: true, NoFailover: true, CapacityControlScope: provider.CapacityControlScopeLocalShared},
		Receipt:   zaiReceipt,
	}
	zaiPayload, err := canonicalProviderCodexOutput(zaiOutput)
	if err != nil {
		t.Fatal(err)
	}
	zaiSignature, err := signer(t.Context(), zaiPayload)
	if err != nil {
		t.Fatal(err)
	}
	zaiOutput.Attestation = &zaiSignature
	grokOutput := providerSessionOutput{
		SchemaVersion: providerSessionSchema, Success: true, Dispatched: true, Profile: plan.Stages[1].ProviderProfile, Transport: "xai_headless_session",
		IdentitySHA256: plan.Stages[1].IdentitySHA256, Policy: agent.DefaultGrokAutomationPolicyName,
		PolicySHA256: plan.Stages[1].PolicySHA256, ConfigSHA256: providerTestHash("config"), BinarySHA256: providerTestHash("binary"), QualificationSHA256: providerTestHash("grok-qualification"), CWD_SHA256: plan.WorktreeSHA256, WorktreeSHA256: plan.WorktreeSHA256,
		Admission: providerSessionAdmissionEvidence{Allowed: true, NoFailover: true, CapacityControlScope: provider.CapacityControlScopeLocalShared},
		Telemetry: providerTelemetryEvidence{State: providerTelemetryStateRecorded, ObservationID: "11111111111111111111111111111111", ObservationSHA256: providerTestHash("observation")},
		Receipt: grok.SessionReceipt{
			Action: grok.SessionResume, CompletionConfirmed: true, ProviderAcknowledged: true, LineageBound: true,
			ParentSessionSHA256: plan.GrokParentSHA256, ChildSessionSHA256: providerTestHash("child"), NonceSHA256: providerTestHash("nonce"),
			CWDSHA256: plan.WorktreeSHA256, WorktreeSHA256: plan.WorktreeSHA256, PolicySHA256: plan.Stages[1].PolicySHA256,
			ConfigSHA256: providerTestHash("config"), BinarySHA256: providerTestHash("binary"),
			Stderr: grok.StderrDigest{SHA256: sha256StringCLI("")},
			Cancellation: grok.CancellationReceipt{
				LocalTermination: "already_exited_verified", ResidualPIDs: []int32{},
				ObservedAt: time.Unix(1_800_000_000, 0).UTC(),
			},
		},
	}
	if err := sealProviderSessionOutput(t.Context(), &grokOutput, signer); err != nil {
		t.Fatal(err)
	}
	planPath, zaiPath, grokPath := filepath.Join(dir, "plan.json"), filepath.Join(dir, "zai.json"), filepath.Join(dir, "grok.json")
	for _, fixture := range []struct {
		path  string
		value any
	}{{planPath, plan}, {zaiPath, zaiOutput}, {grokPath, grokOutput}} {
		data, err := json.Marshal(fixture.value)
		if err != nil || os.WriteFile(fixture.path, data, 0o600) != nil {
			t.Fatalf("write fixture %s: %v", fixture.path, err)
		}
	}
	result, err := reconcileZAIGrokWorkflow(t.Context(), planPath, zaiPath, grokPath, deps)
	if err != nil || !result.BothReceiptsValid || result.Decision != "manual_review_required" || result.AutomaticDispatch || result.AutomaticFailover {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if len(signerProfiles) != 2 || signerProfiles[0] != "codex" || signerProfiles[1] != "grok" {
		t.Fatalf("workflow did not resolve exact per-stage profile signers: %v", signerProfiles)
	}
	forgedZAIOutput := zaiOutput
	forgedZAIOutput.Receipt.RuntimeEventContract.ReceiptSHA256 = providerTestHash("forged-runtime-contract")
	forgedZAIPayload, err := canonicalProviderCodexOutput(forgedZAIOutput)
	if err != nil {
		t.Fatal(err)
	}
	forgedZAISignature, err := signer(t.Context(), forgedZAIPayload)
	if err != nil {
		t.Fatal(err)
	}
	forgedZAIOutput.Attestation = &forgedZAISignature
	forgedZAIBytes, err := json.Marshal(forgedZAIOutput)
	if err != nil || os.WriteFile(zaiPath, forgedZAIBytes, 0o600) != nil {
		t.Fatalf("write forged Z.ai receipt: %v", err)
	}
	if _, err := reconcileZAIGrokWorkflow(t.Context(), planPath, zaiPath, grokPath, deps); err == nil {
		t.Fatal("signed but internally inconsistent runtime-event contract was accepted")
	}
	originalZAIBytes, err := json.Marshal(zaiOutput)
	if err != nil || os.WriteFile(zaiPath, originalZAIBytes, 0o600) != nil {
		t.Fatalf("restore Z.ai receipt: %v", err)
	}
	wrongSigner := newProviderNativeTestSigner()
	wrongSignature, err := wrongSigner(t.Context(), zaiPayload)
	if err != nil {
		t.Fatal(err)
	}
	wrongSignerOutput := zaiOutput
	wrongSignerOutput.Attestation = &wrongSignature
	wrongSignerBytes, _ := json.Marshal(wrongSignerOutput)
	if err := os.WriteFile(zaiPath, wrongSignerBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reconcileZAIGrokWorkflow(t.Context(), planPath, zaiPath, grokPath, deps); err == nil {
		t.Fatal("receipt signed by an untrusted local key was accepted")
	}
	wrongModelOutput := zaiOutput
	wrongModelOutput.Receipt.RequestedModel = "glm-5.3-flash"
	wrongModelOutput.Receipt.ResolvedModel = "glm-5.3-flash"
	wrongModelSpec := zaiSpec
	wrongModelSpec.RequestedModel = "glm-5.3-flash"
	refreshProviderCodexRuntimeContract(&wrongModelOutput.Receipt, wrongModelSpec)
	wrongModelPayload, err := canonicalProviderCodexOutput(wrongModelOutput)
	if err != nil {
		t.Fatal(err)
	}
	wrongModelSignature, err := signer(t.Context(), wrongModelPayload)
	if err != nil {
		t.Fatal(err)
	}
	wrongModelOutput.Attestation = &wrongModelSignature
	wrongModelBytes, _ := json.Marshal(wrongModelOutput)
	if err := os.WriteFile(zaiPath, wrongModelBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reconcileZAIGrokWorkflow(t.Context(), planPath, zaiPath, grokPath, deps); err == nil {
		t.Fatal("signed receipt for an unplanned but internally consistent Z.ai model was accepted")
	}
	if err := os.WriteFile(zaiPath, originalZAIBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	plan.WorktreeSHA256 = providerTestHash("other-worktree")
	plan.WorkflowSHA256 = providerWorkflowPlanDigest(plan)
	data, _ := json.Marshal(plan)
	if err := os.WriteFile(planPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reconcileZAIGrokWorkflow(t.Context(), planPath, zaiPath, grokPath, deps); err == nil {
		t.Fatal("valid receipts from a different worktree were accepted")
	}
}
