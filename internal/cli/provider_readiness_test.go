package cli

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/state"
)

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
