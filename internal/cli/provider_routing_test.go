package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/spf13/cobra"
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
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

func TestGrokOperationDiagnosticsPreflightAndCleanupBindVerifiedRuntime(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_STATE_HOME", root)
	identity, policy, runtimeHash := providerTestHash("identity"), providerTestHash("policy"), providerTestHash("executable")
	if sink, err := prepareGrokOperationDiagnosticSink(identity, policy, "", time.Now().UTC()); err == nil || sink != nil {
		t.Fatal("empty optional runtime digest survived preflight")
	}
	sink, err := prepareGrokOperationDiagnosticSink(identity, policy, runtimeHash, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := sink(provider.ProtocolObservation{}); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(filepath.Join(root, "ntm", "provider-diagnostics", identity))
	if err != nil || len(files) != 2 {
		t.Fatalf("expected both durable observations: %v %v", files, err)
	}
	phases := map[string]bool{}
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(root, "ntm", "provider-diagnostics", identity, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var record providerqualification.DiagnosticObservation
		if err := json.Unmarshal(data, &record); err != nil {
			t.Fatal(err)
		}
		if record.Trust != "unsigned_diagnostic_only" || record.RuntimeSHA256 != runtimeHash || record.IdentitySHA256 != identity {
			t.Fatalf("incorrect diagnostic authority: %+v", record)
		}
		phases[record.Phase] = true
	}
	if !phases["before_dispatch"] || !phases["before_cleanup"] {
		t.Fatal("missing lifecycle observation")
	}
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "unwritable-file"))
	if err := os.WriteFile(filepath.Join(root, "unwritable-file"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if sink, err := prepareGrokOperationDiagnosticSink(identity, policy, runtimeHash, time.Now().UTC()); err == nil || sink != nil {
		t.Fatal("unavailable store survived preflight")
	}
}

func TestAssignmentAndSendShareExactProviderDispatch(t *testing.T) {
	previous := dispatchProviderAssignment
	t.Cleanup(func() { dispatchProviderAssignment = previous })
	for _, surface := range []string{"assign", "send"} {
		for _, profile := range []string{"grok-workspace-write", "zai-codex-kevin-v21"} {
			t.Run(surface+"/"+profile, func(t *testing.T) {
				calls := 0
				dispatchProviderAssignment = func(_ *cobra.Command, got providerAssignmentRequest) error {
					calls++
					if got.Profile != profile || got.OperationID != "same-task" || got.Prompt != "edit and test" || got.CWD != "/isolated" || got.Timeout != time.Minute {
						t.Fatalf("assignment changed: %+v", got)
					}
					return nil
				}
				var cmd *cobra.Command
				args := []string{"--provider-profile", profile, "--operation-id", "same-task", "--timeout", "1m"}
				if surface == "assign" {
					cmd = newAssignCmd()
					args = append(args, "--auto", "--prompt", "edit and test", "--repo", "/isolated")
				} else {
					cmd = newSendCmd()
					args = append(args, "--cwd", "/isolated", "edit and test")
				}
				cmd.SetOut(&bytes.Buffer{})
				cmd.SetErr(&bytes.Buffer{})
				cmd.SetArgs(args)
				if err := cmd.Execute(); err != nil || calls != 1 {
					t.Fatalf("calls=%d err=%v", calls, err)
				}
			})
		}
	}
}

func TestProviderControlsRejectMixedTargetsBeforeDispatch(t *testing.T) {
	previous := dispatchProviderAssignment
	t.Cleanup(func() { dispatchProviderAssignment = previous })
	dispatchProviderAssignment = func(*cobra.Command, providerAssignmentRequest) error {
		t.Fatal("mixed targeting reached provider")
		return nil
	}
	for _, tc := range []struct {
		cmd  func() *cobra.Command
		args []string
	}{
		{newAssignCmd, []string{"--provider-profile", "exact", "--auto", "--beads", "unrelated"}},
		{newAssignCmd, []string{"--provider-profile", "exact", "--prompt", "work"}},
		{newSendCmd, []string{"--provider-profile", "exact", "--cc", "work"}},
		{newSendCmd, []string{"--provider-profile", "exact", "session", "work"}},
		{newSendCmd, []string{"--operation-id", "orphan", "session", "work"}},
	} {
		cmd := tc.cmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(tc.args)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("accepted ambiguous targeting: %v", tc.args)
		}
	}
}

func TestStatusAndHealthShareProviderReceiptInspection(t *testing.T) {
	previous := inspectProviderAssignment
	t.Cleanup(func() { inspectProviderAssignment = previous })
	for _, makeCommand := range []func() *cobra.Command{newStatusCmd, newHealthCmd} {
		calls := 0
		inspectProviderAssignment = func(_ *cobra.Command, profile, operation string) error {
			calls++
			if profile != "zai-codex" || operation != "same-task" {
				t.Fatal("inspection changed provider binding")
			}
			return nil
		}
		cmd := makeCommand()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"--provider-profile", "zai-codex", "--operation-id", "same-task"})
		if err := cmd.Execute(); err != nil || calls != 1 {
			t.Fatalf("inspection calls=%d err=%v", calls, err)
		}
	}
}

func TestProviderSpawnAndResumeUseBoundedAssignmentDispatcher(t *testing.T) {
	previous := dispatchProviderAssignment
	t.Cleanup(func() { dispatchProviderAssignment = previous })
	for _, resume := range []bool{false, true} {
		calls := 0
		dispatchProviderAssignment = func(_ *cobra.Command, request providerAssignmentRequest) error {
			calls++
			if request.Profile != "zai-codex" || request.OperationID != "new-turn" || request.Prompt != "work" || request.CWD != "/isolated" || request.Timeout != time.Minute {
				t.Fatalf("request=%+v", request)
			}
			if (request.ParentSession != "") != resume || (resume && request.ParentSession != "parent") {
				t.Fatal("resume lineage lost or invented")
			}
			return nil
		}
		args := []string{"--provider-profile", "zai-codex", "--prompt", "work", "--cwd", "/isolated", "--timeout", "1m"}
		var cmd *cobra.Command
		if resume {
			cmd = newResumeCmd()
			args = append(args, "--operation-id", "new-turn", "--parent-session", "parent")
		} else {
			cmd = newSpawnCmd()
			args = append(args, "new-turn")
		}
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil || calls != 1 {
			t.Fatalf("resume=%v calls=%d err=%v", resume, calls, err)
		}
	}
}

func TestProviderStatusRequiresSignedExactOperation(t *testing.T) {
	root := t.TempDir()
	profile := providerCodexProfile(root)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	ledger := &providerNativeLedgerFake{}
	admission := &providerCodexSubscriptionAdmissionFake{decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerCodexTestDeps(profile, admission, ledger)
	deps.run = func(_ context.Context, spec zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		return successfulProviderCodexReceipt(spec), nil
	}
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	if err := runProviderCodex(cmd, providerCodexRunOptions{profile: "zai-codex", prompt: "status fixture", cwd: root, operationID: "status-proof", live: true, timeout: time.Minute}, deps); err != nil {
		t.Fatal(err)
	}
	row := ledger.ops[providerCodexOperationScope+"\x00status-proof"]
	var receipt providerCodexRunOutput
	if row == nil || json.Unmarshal([]byte(row.OutcomeJSON), &receipt) != nil {
		t.Fatal("missing signed fixture")
	}
	trusted := receipt.Attestation.KeyMetadata
	if !validProviderCodexStatusReceipt(receipt, row, "zai-codex", identity, trusted) {
		t.Fatal("valid exact receipt rejected")
	}
	if validProviderCodexStatusReceipt(receipt, row, "other-account", identity, trusted) {
		t.Fatal("another profile accepted")
	}
	receipt.Receipt.ResolvedModel = "forged-model"
	if validProviderCodexStatusReceipt(receipt, row, "zai-codex", identity, trusted) {
		t.Fatal("tampered served model accepted")
	}
}

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
