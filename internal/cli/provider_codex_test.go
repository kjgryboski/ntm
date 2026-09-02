package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/state"
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

func providerCodexProfile(root string) config.ProviderProfileConfig {
	return config.ProviderProfileConfig{
		Provider: "zai", AccountAlias: "kevin", Model: "glm-5.3", Endpoint: zai.OfficialCodexEndpoint,
		Runtime: "codex", RuntimeVersion: "0.149.0", CredentialClass: provider.CredentialClassCodingPlan,
		BillingClass: provider.BillingClassCodingPlan, Entitlement: provider.EntitlementCodexResponses,
		ConfigSHA256: strings.Repeat("a", 64), Command: filepath.Join(root, "codex"), RuntimeSHA256: strings.Repeat("b", 64),
		BrokerCommand: filepath.Join(root, "caam"), BrokerCommandSHA256: strings.Repeat("c", 64),
		CredentialBridgeCommand: filepath.Join(root, "ntm-provider-bridge"), CredentialBridgeCommandSHA256: strings.Repeat("6", 64),
		RuntimeHome: filepath.Join(root, "profiles", "zai-kevin", ".codex"), BrokerCredentialID: "ntm.zai.coding_plan.kevin",
		AutomationPolicy: provider.DefaultZAICodexAutomationPolicyName, ExactTargetOnly: true, ProbeRequired: true,
	}
}

type providerCodexSubscriptionAdmissionFake struct {
	decision             ratelimit.SubscriptionDecision
	status               ratelimit.CapacityStatus
	snapshot             ratelimit.SubscriptionCapacitySnapshot
	acquires             int
	releases             int
	successes            int
	reconciliations      []providerCodexUsageReconciliation
	reconcileErr         error
	unknownReservations  []providerCodexUnknownUsageReservation
	unknownErr           error
	canceledReservations int
	cancelErr            error
}

type providerCodexUsageReconciliation struct {
	identity      provider.Identity
	decision      ratelimit.SubscriptionDecision
	resolvedModel string
	usage         ratelimit.TokenUsage
	observedAt    time.Time
}

type providerCodexUnknownUsageReservation struct {
	identity provider.Identity
	decision ratelimit.SubscriptionDecision
}

func (f *providerCodexSubscriptionAdmissionFake) Acquire(provider.Identity) ratelimit.SubscriptionDecision {
	f.acquires++
	return f.decision
}

func (f *providerCodexSubscriptionAdmissionFake) Release(provider.Identity, ratelimit.SubscriptionDecision) {
	f.releases++
}

func (f *providerCodexSubscriptionAdmissionFake) RecordUsage(identity provider.Identity, decision ratelimit.SubscriptionDecision, resolvedModel string, usage ratelimit.TokenUsage, observedAt time.Time) error {
	f.reconciliations = append(f.reconciliations, providerCodexUsageReconciliation{identity: identity, decision: decision, resolvedModel: resolvedModel, usage: usage, observedAt: observedAt})
	return f.reconcileErr
}

func (f *providerCodexSubscriptionAdmissionFake) RecordUnknownUsage(identity provider.Identity, decision ratelimit.SubscriptionDecision) error {
	f.unknownReservations = append(f.unknownReservations, providerCodexUnknownUsageReservation{identity: identity, decision: decision})
	return f.unknownErr
}

func (f *providerCodexSubscriptionAdmissionFake) CancelReservation(provider.Identity, ratelimit.SubscriptionDecision) error {
	f.canceledReservations++
	return f.cancelErr
}

func (f *providerCodexSubscriptionAdmissionFake) RecordSuccess(provider.Identity) { f.successes++ }

func (f *providerCodexSubscriptionAdmissionFake) CapacityStatus() ratelimit.CapacityStatus {
	return f.status
}
func (f *providerCodexSubscriptionAdmissionFake) Snapshot(provider.Identity) ratelimit.SubscriptionCapacitySnapshot {
	return f.snapshot
}

func providerCodexTestDeps(profile config.ProviderProfileConfig, admission *providerCodexSubscriptionAdmissionFake, ledger *providerNativeLedgerFake) providerCodexRunDependencies {
	return providerCodexRunDependencies{
		loadConfig: func() *config.Config {
			return &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"zai-codex": profile}}
		},
		attest: func(context.Context, zai.CodexManifestExpectation) (zai.CodexManifestAttestation, error) {
			return zai.CodexManifestAttestation{ConfigSHA256: profile.ConfigSHA256, BinarySHA256: profile.RuntimeSHA256, AuthHelperSHA256: profile.BrokerCommandSHA256, CredentialBridgeSHA256: profile.CredentialBridgeCommandSHA256, RuntimeVersion: profile.RuntimeVersion}, nil
		},
		newNonce:         func() (string, error) { return "NTM_ACK_0123456789abcdef0123456789abcdef", nil },
		isLinkedWorktree: func(context.Context, string) (bool, error) { return true, nil },
		sign:             newProviderNativeTestSigner(),
		admission:        admission,
		openLedger: func() (providerNativeOperationLedger, func() error, error) {
			return ledger, func() error { return nil }, nil
		},
		now: func() time.Time { return time.Unix(1, 0).UTC() },
	}
}

func successfulProviderCodexReceipt(spec zai.CodexRunSpec) zai.CodexRunReceipt {
	action := "start"
	parent := ""
	if spec.Resume {
		action = "resume"
		parent = sha256StringCLI(strings.TrimSpace(spec.ParentSession))
	}
	return zai.CodexRunReceipt{
		AdapterVersion: zai.CodexRuntimeAdapterVersion, Action: action, RequestedModel: spec.RequestedModel,
		ResolvedModel: spec.RequestedModel, ModelEvidence: "provider_response.model", ConfigSHA256: spec.ConfigSHA256,
		BinarySHA256: spec.BinarySHA256, BrokerCommandSHA256: spec.BrokerCommandSHA256, CredentialBridgeSHA256: spec.CredentialBridgeCommandSHA256,
		PolicySHA256: spec.PolicySHA256, RuntimeVersion: spec.RuntimeVersion,
		CWDSHA256: sha256StringCLI(filepath.Clean(spec.CWD)), PromptSHA256: sha256StringCLI(strings.TrimSpace(spec.Prompt)), SessionIDSHA256: strings.Repeat("f", 64), ParentSessionSHA256: parent,
		NonceSHA256: sha256StringCLI(spec.ExpectedNonce), OutputSHA256: strings.Repeat("2", 64), EventStreamSHA256: strings.Repeat("3", 64),
		StderrSHA256: strings.Repeat("4", 64), ToolEventsSHA256: strings.Repeat("5", 64), StopReason: "turn.completed", ProcessStarted: true,
		ProviderStarted: true, OutcomeKnown: true, CompletionConfirmed: true, NonceVerified: true, ModelVerified: true, LineageVerified: true,
		ZeroResiduals: true, Cancellation: zai.CodexCancellationReceipt{LocalTermination: "observed_no_residual_processes", ResidualProcessIDs: []int{}, ObservedAt: time.Unix(2, 0).UTC()},
		Usage:     zai.CodexUsage{InputTokens: 100, CachedInputTokens: 10, OutputTokens: 20},
		StartedAt: time.Unix(1, 0).UTC(), CompletedAt: time.Unix(2, 0).UTC(),
	}
}

func TestProviderCodexRunRequiresLiveOptIn(t *testing.T) {
	root := t.TempDir()
	admission := &providerCodexSubscriptionAdmissionFake{status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerCodexTestDeps(providerCodexProfile(root), admission, &providerNativeLedgerFake{})
	called := false
	deps.run = func(context.Context, zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		called = true
		return zai.CodexRunReceipt{}, nil
	}
	err := runProviderCodex(&cobra.Command{}, providerCodexRunOptions{profile: "zai-codex", prompt: "p", cwd: root, operationID: "codex-1"}, deps)
	if err == nil || called || admission.acquires != 0 {
		t.Fatalf("err=%v called=%t admission=%+v", err, called, admission)
	}
}

func TestProviderCodexRunAttestsAdmitsAndPersistsStructuredReceipt(t *testing.T) {
	root := t.TempDir()
	profile := providerCodexProfile(root)
	ledger := &providerNativeLedgerFake{}
	admission := &providerCodexSubscriptionAdmissionFake{decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerCodexTestDeps(profile, admission, ledger)
	var observed zai.CodexRunSpec
	deps.run = func(_ context.Context, spec zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		observed = spec
		return successfulProviderCodexReceipt(spec), nil
	}
	cmd := &cobra.Command{}
	var output bytes.Buffer
	cmd.SetOut(&output)
	err := runProviderCodex(cmd, providerCodexRunOptions{profile: "zai-codex", prompt: "bounded edit", cwd: root, operationID: "codex-success", live: true, timeout: time.Minute}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Binary != profile.Command || observed.BrokerCommand != profile.BrokerCommand || observed.BrokerCommandSHA256 != profile.BrokerCommandSHA256 || observed.CredentialBridgeCommand != profile.CredentialBridgeCommand || observed.CredentialBridgeCommandSHA256 != profile.CredentialBridgeCommandSHA256 || observed.RuntimeHome != profile.RuntimeHome || observed.RequestedModel != profile.Model || admission.acquires != 1 || admission.releases != 1 || admission.successes != 1 || len(admission.reconciliations) != 1 {
		t.Fatalf("spec=%+v admission=%+v", observed, admission)
	}
	reconciliation := admission.reconciliations[0]
	if reconciliation.resolvedModel != "glm-5.3" || reconciliation.usage != (ratelimit.TokenUsage{InputTokens: 100, CachedInputTokens: 10, OutputTokens: 20}) || !reconciliation.observedAt.Equal(time.Unix(2, 0).UTC()) {
		t.Fatalf("reconciliation=%+v", reconciliation)
	}
	op := ledger.ops[providerCodexOperationScope+"\x00codex-success"]
	if op == nil || op.Status != "completed" || strings.Contains(op.OutcomeJSON, "bounded edit") || strings.Contains(op.OutcomeJSON, `"operation_id":"`) || !strings.Contains(op.OutcomeJSON, `"operation_id_sha256"`) || !strings.Contains(op.OutcomeJSON, `"credential_bridge_sha256":"`+profile.CredentialBridgeCommandSHA256+`"`) || !strings.Contains(op.OutcomeJSON, `"state":"completed"`) {
		t.Fatalf("durable operation = %+v", op)
	}
}

func TestProviderCodexRunPersistsCompletedButUnqualifiedModelGap(t *testing.T) {
	root := t.TempDir()
	profile := providerCodexProfile(root)
	ledger := &providerNativeLedgerFake{}
	admission := &providerCodexSubscriptionAdmissionFake{decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerCodexTestDeps(profile, admission, ledger)
	deps.run = func(_ context.Context, spec zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		receipt := successfulProviderCodexReceipt(spec)
		receipt.ResolvedModel, receipt.ModelEvidence, receipt.ModelVerified = "", "", false
		return receipt, errors.New("provider-reported model identity unavailable")
	}
	err := runProviderCodex(&cobra.Command{}, providerCodexRunOptions{profile: "zai-codex", prompt: "p", cwd: root, operationID: "codex-model-gap", live: true, timeout: time.Minute}, deps)
	if err == nil {
		t.Fatal("unqualified model gap was promoted")
	}
	if len(admission.reconciliations) != 0 || len(admission.unknownReservations) != 1 || admission.unknownReservations[0].identity.Hash() == "" {
		t.Fatalf("model-gap receipt reconciled requested-model usage: %+v", admission.reconciliations)
	}
	op := ledger.ops[providerCodexOperationScope+"\x00codex-model-gap"]
	if op == nil || op.Status != "completed" || !strings.Contains(op.OutcomeJSON, `"state":"completed_unqualified"`) || strings.Contains(op.OutcomeJSON, `"success":true`) {
		t.Fatalf("durable unqualified receipt = %+v", op)
	}
}

func TestProviderCodexRunFailsClosedWhenSubscriptionUsageCannotReconcile(t *testing.T) {
	root := t.TempDir()
	ledger := &providerNativeLedgerFake{}
	admission := &providerCodexSubscriptionAdmissionFake{
		decision:     ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true},
		status:       ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared},
		reconcileErr: errors.New("shared state unavailable"),
	}
	deps := providerCodexTestDeps(providerCodexProfile(root), admission, ledger)
	deps.run = func(_ context.Context, spec zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		return successfulProviderCodexReceipt(spec), nil
	}
	err := runProviderCodex(&cobra.Command{}, providerCodexRunOptions{profile: "zai-codex", prompt: "p", cwd: root, operationID: "codex-reconcile-fail", live: true, timeout: time.Minute}, deps)
	if err == nil || admission.acquires != 1 || admission.releases != 1 || admission.successes != 0 || len(admission.reconciliations) != 1 || len(admission.unknownReservations) != 1 {
		t.Fatalf("err=%v admission=%+v", err, admission)
	}
	if op := ledger.ops[providerCodexOperationScope+"\x00codex-reconcile-fail"]; op == nil || op.Status != state.SendOperationInProgress {
		t.Fatalf("reconciliation failure must remain non-replayable: %+v", op)
	}
}

func TestProviderCodexRunCancelsCapacityReservationWhenProcessNeverStarts(t *testing.T) {
	root := t.TempDir()
	ledger := &providerNativeLedgerFake{}
	admission := &providerCodexSubscriptionAdmissionFake{decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerCodexTestDeps(providerCodexProfile(root), admission, ledger)
	deps.run = func(context.Context, zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		return zai.CodexRunReceipt{}, errors.New("manifest check failed before process start")
	}
	err := runProviderCodex(&cobra.Command{}, providerCodexRunOptions{profile: "zai-codex", prompt: "p", cwd: root, operationID: "codex-not-dispatched", live: true, timeout: time.Minute}, deps)
	if err == nil || admission.acquires != 1 || admission.releases != 1 || admission.canceledReservations != 1 || len(admission.reconciliations) != 0 || len(admission.unknownReservations) != 0 || len(ledger.ops) != 0 {
		t.Fatalf("err=%v admission=%+v ledger=%+v", err, admission, ledger.ops)
	}
}

func TestProviderCodexRunRejectsAdmissionThatPermitsFailover(t *testing.T) {
	root := t.TempDir()
	ledger := &providerNativeLedgerFake{}
	admission := &providerCodexSubscriptionAdmissionFake{decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: false}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerCodexTestDeps(providerCodexProfile(root), admission, ledger)
	deps.run = func(context.Context, zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		t.Fatal("cross-provider failover admission dispatched")
		return zai.CodexRunReceipt{}, nil
	}
	err := runProviderCodex(&cobra.Command{}, providerCodexRunOptions{profile: "zai-codex", prompt: "p", cwd: root, operationID: "codex-no-failover", live: true, timeout: time.Minute}, deps)
	if err == nil || admission.acquires != 1 || admission.releases != 1 || len(admission.reconciliations) != 0 || len(ledger.ops) != 0 {
		t.Fatalf("err=%v admission=%+v ledger=%+v", err, admission, ledger.ops)
	}
}

func TestProviderCodexWorkloadPolicyNeverSilentlyChangesModel(t *testing.T) {
	peak := time.Date(2026, 9, 7, 7, 0, 0, 0, time.UTC) // Monday 15:00 Singapore.
	offPeak := peak.Add(4 * time.Hour)
	for _, test := range []struct {
		name, model, workload string
		at                    time.Time
		want                  string
		wantErr               string
	}{
		{name: "implementation flagship", model: "glm-5.3", workload: "implementation", at: peak, want: "implementation"},
		{name: "review flagship", model: "glm-5.3", workload: "review", at: peak, want: "review"},
		{name: "bulk flash off peak", model: "glm-5.3-flash", workload: "bulk", at: offPeak, want: "bulk"},
		{name: "bulk held during peak", model: "glm-5.3-flash", workload: "bulk", at: peak, wantErr: "retry after 2026-09-07T10:00:00Z"},
		{name: "bulk never remaps flagship", model: "glm-5.3", workload: "bulk", at: offPeak, wantErr: "explicitly selected glm-5.3-flash"},
		{name: "hard work never remaps flash", model: "glm-5.3-flash", workload: "review", at: offPeak, wantErr: "exact glm-5.3 profile"},
		{name: "unknown class", model: "glm-5.3", workload: "cheap", at: offPeak, wantErr: "must be implementation, review, or bulk"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := validateProviderCodexWorkload(test.model, test.workload, test.at)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("got=%q err=%v", got, err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("got=%q err=%v", got, err)
			}
		})
	}
}
