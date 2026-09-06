package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/state"
	"github.com/spf13/cobra"
)

func TestEvidenceSurfaceExportsFailureWithoutReplayAndPreservesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.json")
	calls := 0
	inspect := func(_ *cobra.Command, profile, operation string, visit func(providerAssignmentStatus) error) error {
		calls++
		if profile != "exact" || operation != "uncertain" {
			t.Fatal("changed exact task selection")
		}
		return visit(providerAssignmentStatus{State: "outcome_unknown"})
	}
	cmd := providerEvidenceCommand(inspect)
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"--profile", "exact", "--operation", "uncertain", "--output", path})
	if err := cmd.Execute(); err == nil || calls != 1 {
		t.Fatal("unknown task passed or inspector replayed")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Passed          bool
		GenerationCalls int  `json:"generation_calls"`
		Dispatch        bool `json:"dispatch_authorized"`
	}
	if json.Unmarshal(data, &result) != nil || result.Passed || result.Dispatch || result.GenerationCalls != 0 {
		t.Fatal("failure export granted authority")
	}
	cmd = providerEvidenceCommand(inspect)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"--profile", "exact", "--operation", "uncertain", "--output", path})
	if err := cmd.Execute(); err == nil {
		t.Fatal("existing evidence overwritten")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, after) {
		t.Fatal("retained evidence changed")
	}
}

func TestEvidenceSurfaceBindsRestartParentAndRejectsIncompleteController(t *testing.T) {
	identity := strings.Repeat("a", 64)
	parent := providerAssignmentStatus{Provider: "anthropic", IdentitySHA256: identity, IdentityBindingVerified: true, OutcomeSHA256: strings.Repeat("b", 64), ControllerFinalized: true, State: "cancelled_local", LocalCleanupVerified: true, CancellationObserved: true, CapacityObservation: &provider.CapacityReleaseObservation{IdentitySHA256: identity, Scope: provider.CapacityControlScopeLocalShared, LocalSlotReleased: true, ObservedAt: time.Now()}}
	parent.OperationIDSHA256 = sha256StringCLI("parent")
	child := parent
	child.State, child.CompletionConfirmed, child.WorkspaceVerified = "completed", true, true
	child.RestartOfSHA256 = sha256StringCLI("parent")
	child.OperationIDSHA256 = sha256StringCLI("child")
	if !providerTaskRequirementPassed(parent, providerAssignmentStatus{}, "local-cancellation", "") {
		t.Fatal("verified cancellation rejected")
	}
	for _, scenario := range []string{"valid", "wrong-parent", "wrong-identity", "no-release", "incomplete-controller"} {
		t.Run(scenario, func(t *testing.T) {
			p, c := parent, child
			switch scenario {
			case "wrong-parent":
				c.RestartOfSHA256 = sha256StringCLI("another")
			case "wrong-identity":
				p.IdentitySHA256 = strings.Repeat("c", 64)
			case "no-release":
				p.CapacityObservation = nil
			case "incomplete-controller":
				c.ControllerFinalized = false
			}
			calls := 0
			cmd := providerEvidenceCommand(func(_ *cobra.Command, profile, operation string, visit func(providerAssignmentStatus) error) error {
				calls++
				if profile != "exact" {
					t.Fatal("profile drift")
				}
				if operation == "child" {
					return visit(c)
				}
				if operation == "parent" {
					return visit(p)
				}
				t.Fatal("unexpected operation")
				return nil
			})
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs([]string{"--profile", "exact", "--operation", "child", "--require", "guarded-restart", "--restart-of", "parent"})
			err := cmd.Execute()
			if (err == nil) != (scenario == "valid") || calls != 2 {
				t.Fatalf("unexpected verdict: %v calls=%d", err, calls)
			}
		})
	}
}

func TestEvidenceContractNeverInspectsOrAuthorizesWork(t *testing.T) {
	cmd := providerEvidenceCommand(func(*cobra.Command, string, string, func(providerAssignmentStatus) error) error {
		t.Fatal("contract inspected a task")
		return nil
	})
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--contract"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "quarantine uncertain ownership") || !strings.Contains(output.String(), `"dispatch_authorized": false`) {
		t.Fatal("missing lifecycle boundary")
	}
}

func TestRecoveryDispositionDistinguishesFailureFromUnknownOwnership(t *testing.T) {
	out := providerAssignmentStatus{State: "failed", IdentityBindingVerified: true, ControllerFinalized: true}
	if providerRecoveryDisposition(out) != "verified_terminal_result_requires_review" {
		t.Fatal("known failure labeled unknown")
	}
	out.ControllerFinalized = false
	if providerRecoveryDisposition(out) != "quarantined_controller_incomplete" {
		t.Fatal("missing controller hidden")
	}
	out.IdentityBindingVerified = false
	if providerRecoveryDisposition(out) != "quarantined_unknown_outcome" {
		t.Fatal("unknown owner promoted")
	}
}

func TestReadinessDiscoversOnlyExactIdentityWithBoundedHistory(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(); err != nil {
		t.Fatal(err)
	}
	identity, other := strings.Repeat("a", 64), strings.Repeat("b", 64)
	for i := 0; i < 67; i++ {
		payload := identity
		if i == 66 {
			payload = other
		}
		_, _, err := store.ClaimSendOperation(&state.SendOperation{OperationID: fmt.Sprintf("task-%03d", i), SessionName: providerControlScope, BindingHash: strings.Repeat("c", 64), PayloadSHA256: payload, CreatedAt: time.Unix(int64(1800000000+i), 0)})
		if err != nil {
			t.Fatal(err)
		}
	}
	ids, truncated, err := discoverProviderReadinessOperations(store, identity)
	if err != nil || !truncated || len(ids) != 64 || ids[0] != "task-065" {
		t.Fatalf("wrong discovery: %v %t %v", ids, truncated, err)
	}
	for _, id := range ids {
		if id == "task-066" {
			t.Fatal("cross identity evidence discovered")
		}
	}
	ids, truncated, err = discoverProviderReadinessOperations(store, other)
	if err != nil || truncated || len(ids) != 1 || ids[0] != "task-066" {
		t.Fatal("exact identity missing")
	}
}

func TestReadinessSummaryRetainsConflictingObservationsWithoutPromotingAdmission(t *testing.T) {
	checks := []providerReadinessEvidence{{Operation: "ordinary_task", State: "untested"}, {Operation: "ordinary_task", State: "passed"}, {Operation: "ordinary_task", State: "failed"}, {Operation: "resume", State: "unsupported"}}
	summary := summarizeProviderReadiness(checks)
	if len(summary) != 2 || summary[0].State != "passed" || len(summary[0].ObservationIndexes) != 3 || summary[1].State != "unsupported" {
		t.Fatalf("summary lost observations: %+v", summary)
	}
	if len(checks) != 4 || checks[2].State != "failed" {
		t.Fatal("summary erased failure")
	}
}

func TestReadinessUsesEarliestExpiryAndRequiresTaskToFit(t *testing.T) {
	now := time.Unix(1800000000, 0)
	qualification := now.Add(time.Hour)
	credential := now.Add(10 * time.Minute)
	lane := providerReadinessLane{QualificationExpiresAt: &qualification, Credential: map[string]any{"expires_at": credential}, AdmissionState: "ready_for_dispatch_checks"}
	applyProviderReadinessWindow(&lane, 5*time.Minute, now)
	if !lane.DurationFits || !lane.UsableUntil.Equal(credential) || lane.DispatchAuthorized {
		t.Fatal("earliest expiry not used")
	}
	applyProviderReadinessWindow(&lane, 10*time.Minute, now)
	if lane.DurationFits || lane.AdmissionState != "blocked" {
		t.Fatal("timeout extending to expiry admitted")
	}
	lane.Credential = nil
	qualification = now.Add(-time.Second)
	applyProviderReadinessWindow(&lane, time.Second, now)
	if lane.DurationFits {
		t.Fatal("expired qualification admitted")
	}
}

func TestReadinessShowsLatestFailureWithoutErasingHistoricalSuccess(t *testing.T) {
	old := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	recent := old.Add(time.Hour)
	for _, reversed := range []bool{false, true} {
		checks := []providerReadinessEvidence{
			{Operation: "ordinary_task", State: "passed", ObservedAt: &old},
			{Operation: "ordinary_task", State: "failed", ObservedAt: &recent},
		}
		if reversed {
			checks[0], checks[1] = checks[1], checks[0]
		}
		summary := summarizeProviderReadiness(checks)[0]
		if summary.State != "passed" || summary.FailedObservations != 1 || len(summary.LatestDatedStates) != 1 || summary.LatestDatedStates[0] != "failed" || !summary.LatestObservedAt.Equal(recent) {
			t.Fatalf("historical pass hid recent failure: %+v", summary)
		}
		text := providerReadinessCapabilityText(summary)
		if !strings.Contains(text, "passed historically (2 retained observations, 1 failed)") || !strings.Contains(text, "latest dated observation: failed at 2026-09-05T13:00:00Z") {
			t.Fatalf("human readiness hid failure: %s", text)
		}
		data, err := json.Marshal(summary)
		if err != nil || !bytes.Contains(data, []byte(`"latest_dated_states":["failed"]`)) || !bytes.Contains(data, []byte(`"failed_observations":1`)) {
			t.Fatalf("structured readiness hid failure: %s %v", data, err)
		}
	}
}

func TestReadinessLatestObservationPreservesTiesAndDoesNotInventDates(t *testing.T) {
	recent := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	zero := time.Time{}
	checks := []providerReadinessEvidence{
		{Operation: "ordinary_task", State: "passed", ObservedAt: &recent},
		{Operation: "ordinary_task", State: "failed", ObservedAt: &recent},
		{Operation: "ordinary_task", State: "passed", ObservedAt: &recent},
		{Operation: "ordinary_task", State: "untested"},
		{Operation: "ordinary_task", State: "untested", ObservedAt: &zero},
		{Operation: "resume", State: "unsupported"},
	}
	summary := summarizeProviderReadiness(checks)
	if len(summary[0].LatestDatedStates) != 2 || strings.Join(summary[0].LatestDatedStates, ",") != "failed,passed" || len(summary[0].ObservationIndexes) != 5 || summary[0].FailedObservations != 1 {
		t.Fatalf("same-time conflict or undated evidence lost: %+v", summary[0])
	}
	if summary[1].LatestObservedAt != nil || len(summary[1].LatestDatedStates) != 0 || !strings.Contains(providerReadinessCapabilityText(summary[1]), "latest dated observation: unknown") {
		t.Fatal("undated observation acquired a date")
	}
	// Summary timestamps must not alias the caller's retained evidence.
	*summary[0].LatestObservedAt = zero
	if recent.IsZero() {
		t.Fatal("summary mutation rewrote source evidence")
	}
}

func TestSharedReadinessKeepsQualifiedEvidenceSeparateFromCredentialsAndAdmission(t *testing.T) {
	for _, vendor := range []string{"openai", "anthropic", "xai", "zai"} {
		t.Run(vendor, func(t *testing.T) {
			report := providerDoctorReport{Profile: "exact", Identity: providerDoctorIdentity{Provider: vendor}, Runtime: providerDoctorRuntime{Drift: "none"}, Qualification: providerDoctorQualification{State: "current_partial", TrustedCurrent: true, ModelIdentityVerified: true, ReceiptSHA256: strings.Repeat("a", 64), CompletedAt: time.Now().UTC(), CheckStates: map[string]bool{}, CheckOutcomes: map[string]string{}}}
			for _, name := range []string{providerqualification.CheckIdentity, providerqualification.CheckWorkspaceEdit, providerqualification.CheckTestCommand, providerqualification.CheckSecretDenied, providerqualification.CheckPushDenied, providerqualification.CheckProcessCleanup} {
				report.Qualification.CheckStates[name] = true
				report.Qualification.CheckOutcomes[name] = "passed"
			}
			lane := providerReadinessFromReport(report, map[string]any{"state": "missing_or_expired"}, []string{"credential_snapshot_requires_refresh"})
			if lane.WorkspaceEvidence != "qualified" || lane.AdmissionState != "blocked" || lane.DispatchAuthorized || lane.QualificationExpiresAt == nil {
				t.Fatalf("evidence/admission conflated: %+v", lane)
			}
			report.Qualification.TrustedCurrent = false
			stale := providerReadinessFromReport(report, nil, nil)
			if stale.WorkspaceEvidence == "qualified" || stale.AdmissionState != "blocked" {
				t.Fatal("stale evidence promoted")
			}
			report.Qualification.TrustedCurrent = true
			report.Capabilities.Resume = provider.EvidenceUnavailable
			lane = providerReadinessFromReport(report, nil, nil)
			for _, check := range lane.Checks {
				if check.Operation == "resume" && check.State != "unsupported" {
					t.Fatal("unsupported resume obscured")
				}
			}
		})
	}
}

func TestTaskEvidenceDoesNotRenewQualificationEraseSuccessOrInventResume(t *testing.T) {
	observed := time.Now().Add(-48 * time.Hour)
	good := providerAssignmentStatus{IdentityBindingVerified: true, OutcomeSHA256: strings.Repeat("a", 64), CompletedAt: &observed, CompletionConfirmed: true, WorkspaceVerified: true, LocalCleanupVerified: true, RestartOfSHA256: strings.Repeat("b", 64), CapacityObservation: &provider.CapacityReleaseObservation{LocalSlotReleased: true}}
	good.Provider, good.IdentitySHA256, good.State, good.ControllerFinalized = "openai", strings.Repeat("c", 64), "completed", true
	good.CapacityObservation.IdentitySHA256, good.CapacityObservation.Scope, good.CapacityObservation.ObservedAt = good.IdentitySHA256, provider.CapacityControlScopeLocalShared, observed
	failed := providerAssignmentStatus{IdentityBindingVerified: true, OutcomeSHA256: strings.Repeat("c", 64), State: "failed"}
	checks := providerTaskEvidence([]providerAssignmentStatus{good, failed})
	successes, failures := 0, 0
	for _, check := range checks {
		if check.ExpiresAt != nil {
			t.Fatal("historical task renewed qualification")
		}
		if check.Operation == "ordinary_task" {
			if check.State == "passed" {
				successes++
			}
			if check.State == "failed" {
				failures++
			}
		}
		if (check.Operation == "resume" || check.Operation == "remote_generation_termination" || check.Operation == "billing_settlement") && check.State == "passed" {
			t.Fatal("local completion invented remote/lifecycle authority")
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatal("independent outcomes lost")
	}
	good.IdentityBindingVerified = false
	for _, check := range providerTaskEvidence([]providerAssignmentStatus{good}) {
		if check.State == "passed" {
			t.Fatal("untrusted task promoted")
		}
	}
}

func TestReadinessAccountingUnitsDoNotTurnSlotsOrAttemptsIntoBilling(t *testing.T) {
	campaign := state.ProviderCampaign{ID: "bounded", Limit: 4, Used: 4, AuthorizationSHA256: strings.Repeat("a", 64)}
	out := providerReadinessCapacity(providerDoctorCapacity{Scope: provider.CapacityControlScopeLocalShared, Running: 0, Subscription: &providerDoctorSubscriptionCapacity{UnknownUsageReserved: true, WeeklyCreditsUsed: 10000}}, &campaign)
	billing := out["billing_usage"].(map[string]any)
	attempts := out["experiment_attempts"].(map[string]any)
	if billing["unknown_usage_reserved"] != true || billing["settlement"] != "unverified" || attempts["billing_usage"] != false || attempts["remaining"] != 0 {
		t.Fatal("capacity dimensions conflated")
	}
}

func TestReadinessTaskSelectionRejectsAmbiguousBindings(t *testing.T) {
	for _, input := range []struct{ profiles, operations []string }{{[]string{"a", "a"}, nil}, {[]string{"a"}, []string{"b=task"}}, {[]string{"a"}, []string{"a=task", "a=task"}}, {[]string{"a"}, []string{"task"}}} {
		if _, err := providerReadinessOperationBindings(input.profiles, input.operations); err == nil {
			t.Fatal("ambiguous task accepted")
		}
	}
	if _, err := providerReadinessOperationBindings([]string{"a", "b"}, []string{"a=task-one", "b=task-two"}); err != nil {
		t.Fatal(err)
	}
	cmd := newProviderReadinessCmd()
	cmd.SetArgs([]string{"--profile", "a", "--operation", "b=task"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("CLI accepted unselected profile binding")
	}
}

func TestReconciliationTargetNeverInfersProviderBindingFromLocalRow(t *testing.T) {
	row := &state.SendOperation{OperationID: "unknown", BindingHash: strings.Repeat("a", 64), Status: state.SendOperationInProgress}
	out := providerReconciliationOperationTarget("unknown", row)
	if out["provider_request_binding"] != "not_established" || out["changes_admission"] != false || out["settlement"] != "unverified" || row.Status != state.SendOperationInProgress {
		t.Fatal("correlation reference became authority")
	}
	if providerReconciliationOperationTarget("missing", nil)["found_in_selected_ledger"] != false {
		t.Fatal("missing row fabricated")
	}
}
