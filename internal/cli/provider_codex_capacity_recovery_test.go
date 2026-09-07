package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/state"
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

func TestProviderUsageReviewRejectsAmbiguousNestedSignature(t *testing.T) {
	for _, data := range []string{`{"attestation":{"key_id":"a","key_id":"b"}}`, `{"attestation":{"Key_id":"a"}}`, `{"attestation":[]}`, `{} {}`, `null`} {
		if validateProviderUsageObject(json.NewDecoder(strings.NewReader(data)), 0) == nil {
			t.Fatalf("ambiguous review accepted: %s", data)
		}
	}
	if err := validateProviderUsageObject(json.NewDecoder(strings.NewReader(`{"attestation":{"key_id":"a"},"schema_version":"fixture"}`)), 0); err != nil {
		t.Fatal(err)
	}
}

func TestProviderLegacySettlementSurfacePreviewApplyAndRestart(t *testing.T) {
	id, row, e, source, now := providerUsageFixture(t)
	path := filepath.Join(t.TempDir(), "capacity.json")
	open := func() *ratelimit.SubscriptionAdmissionController {
		c, err := ratelimit.NewSubscriptionAdmissionController(ratelimit.DefaultSubscriptionAdmissionConfig(), path, func() time.Time { return now }, func() float64 { return .5 })
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := open()
	d := c.Acquire(id)
	if !d.Allowed {
		t.Fatal(d)
	}
	if err := c.RecordUnknownUsage(id, d); err != nil {
		t.Fatal(err)
	}
	c.Release(id, d)
	resolve := func(profile, operation string) (provider.Identity, *state.SendOperation, error) {
		if profile != "exact" || operation != row.OperationID {
			t.Fatal("target changed")
		}
		return id, row, nil
	}
	var key providerattestation.KeyMetadata
	run := func(args ...string) (string, error) {
		cmd := providerUsageSettlementCommand(resolve, open, func(*cobra.Command, string) (providerattestation.KeyMetadata, error) { return key, nil })
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(append([]string{"--profile", "exact", "--operation-id", row.OperationID}, args...))
		err := cmd.Execute()
		return out.String(), err
	}
	out, err := run("--inspect-legacy-reservations")
	if err != nil {
		t.Fatal(err)
	}
	var inspection struct {
		Reservations []string `json:"reservation_sha256"`
	}
	if json.Unmarshal([]byte(out), &inspection) != nil || len(inspection.Reservations) != 1 {
		t.Fatal(out)
	}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	imported := validateProviderUsageEvidence(data, source, id, row.OperationID, row, now)
	review := providerUsageSourceReview{Schema: "ntm.provider-usage-source-review.v2", EvidenceSHA256: imported.EvidenceSHA256, SourceSHA256: imported.SourceSHA256, IdentitySHA256: id.Hash(), OperationBinding: row.BindingHash, LegacyReservationSHA256: inspection.Reservations[0], LegacyAssociation: "exact_local_reservation_associated_with_authenticated_original_request", ProviderAccount: e.ProviderAccount, ProviderRequest: e.ProviderRequest, SourceAuthentication: "authenticated_support_reply_reviewed", RequestAssociation: "original_request_confirmed_by_provider_source", ReviewedAt: now}
	sign := newProviderNativeTestSigner()
	payload, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sign(t.Context(), payload)
	if err != nil {
		t.Fatal(err)
	}
	review.Attestation = &sig
	key = sig.KeyMetadata
	dir := t.TempDir()
	evidencePath, sourcePath, reviewPath := filepath.Join(dir, "evidence.json"), filepath.Join(dir, "source.txt"), filepath.Join(dir, "review.json")
	if err := os.WriteFile(evidencePath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, source, 0600); err != nil {
		t.Fatal(err)
	}
	writeReview := func(r providerUsageSourceReview) {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(reviewPath, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"--evidence-file", evidencePath, "--source-file", sourcePath, "--review-file", reviewPath}
	for _, mutate := range []func(*providerUsageSourceReview){
		func(r *providerUsageSourceReview) { r.Attestation = nil },
		func(r *providerUsageSourceReview) { r.LegacyAssociation = "timestamp_proximity" },
		func(r *providerUsageSourceReview) { r.LegacyReservationSHA256 = strings.Repeat("f", 64) },
		func(r *providerUsageSourceReview) { r.NonceSHA256 = strings.Repeat("f", 64) },
		func(r *providerUsageSourceReview) { r.SourceAuthentication = "unverified" },
	} {
		changed := review
		mutate(&changed)
		writeReview(changed)
		if _, err := run(append(args, "--apply")...); err == nil {
			t.Fatal("untrusted migration accepted")
		}
		if !open().Snapshot(id).UnknownUsageReserved {
			t.Fatal("rejected evidence released capacity")
		}
	}
	writeReview(review)
	if _, err := run(args...); err != nil {
		t.Fatal(err)
	}
	if !open().Snapshot(id).UnknownUsageReserved {
		t.Fatal("preview released capacity")
	}
	for i := 0; i < 2; i++ {
		out, err := run(append(args, "--apply")...)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "private-source-canary") || !strings.Contains(out, `"generation_calls": 0`) || !strings.Contains(out, `"admission_granted": false`) {
			t.Fatal(out)
		}
	}
	if snapshot := open().Snapshot(id); snapshot.UnknownUsageReserved || snapshot.WeeklyCreditsUsed != *e.FinalUsage {
		t.Fatal(snapshot)
	}
	if row.Status != state.SendOperationInProgress {
		t.Fatal("accounting settlement declared task completion")
	}
}

func providerUsageFixture(t *testing.T) (provider.Identity, *state.SendOperation, providerUsageEvidence, []byte, time.Time) {
	t.Helper()
	id, err := providerCodexProfile(t.TempDir()).Identity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Minute)
	row := &state.SendOperation{OperationID: "original-request", BindingHash: strings.Repeat("a", 64), CreatedAt: now.Add(-time.Hour), Status: state.SendOperationInProgress}
	usage, outstanding := 2.5, 0.0
	source := []byte("Synthetic provider source for offline testing; private-source-canary")
	e := providerUsageEvidence{SchemaVersion: "ntm.provider-usage-evidence.v1", IdentitySHA256: id.Hash(), AccountAliasSHA256: sha256StringCLI(id.AccountAlias()), OperationIDSHA256: sha256StringCLI(row.OperationID), OperationBinding: row.BindingHash, ProviderAccount: strings.Repeat("b", 64), ProviderRequest: strings.Repeat("c", 64), SourceKind: "provider_support_reply", SourceSHA256: sha256TextCLI(source), TerminalStatus: "completed", BillingUnits: "coding_plan_credit", FinalUsage: &usage, SettlementScope: "original_request_only", OutstandingUsage: &outstanding, RequestCompletedAt: now.Add(-30 * time.Minute), SettledThrough: now.Add(-time.Minute), ObservedAt: now}
	return id, row, e, source, now
}

func TestProviderUsageSettlementRequiresSignedExactSourceReview(t *testing.T) {
	id, row, e, source, now := providerUsageFixture(t)
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	imported := validateProviderUsageEvidence(data, source, id, row.OperationID, row, now)
	review := providerUsageSourceReview{Schema: "ntm.provider-usage-source-review.v1", EvidenceSHA256: imported.EvidenceSHA256, SourceSHA256: imported.SourceSHA256, IdentitySHA256: id.Hash(), OperationBinding: row.BindingHash, NonceSHA256: strings.Repeat("d", 64), ProviderAccount: e.ProviderAccount, ProviderRequest: e.ProviderRequest, SourceAuthentication: "authenticated_support_reply_reviewed", RequestAssociation: "original_request_confirmed_by_provider_source", ReviewedAt: now}
	sign := newProviderNativeTestSigner()
	payload, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sign(t.Context(), payload)
	if err != nil {
		t.Fatal(err)
	}
	review.Attestation = &sig
	if err := verifyProviderUsageSourceReview(review, imported, sig.KeyMetadata, now); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*providerUsageSourceReview){
		func(r *providerUsageSourceReview) { r.Attestation = nil },
		func(r *providerUsageSourceReview) { r.ProviderAccount = strings.Repeat("f", 64) },
		func(r *providerUsageSourceReview) { r.ProviderRequest = strings.Repeat("f", 64) },
		func(r *providerUsageSourceReview) { r.SourceSHA256 = strings.Repeat("f", 64) },
		func(r *providerUsageSourceReview) { r.SourceAuthentication = "unverified_source_claim" },
		func(r *providerUsageSourceReview) { r.NonceSHA256 = "" },
	} {
		changed := review
		mutate(&changed)
		if verifyProviderUsageSourceReview(changed, imported, sig.KeyMetadata, now) == nil {
			t.Fatal("altered source review accepted")
		}
	}
	cmd := newProviderUsageSettlementCmd()
	cmd.SetArgs([]string{"--profile", "zai", "--operation-id", "original-request", "--apply"})
	if cmd.Execute() == nil {
		t.Fatal("surface settled without evidence")
	}
}

func TestProviderUsageImporterRejectsMismatchedOrIncompleteSettlement(t *testing.T) {
	for _, scenario := range []string{"valid", "identity", "account", "operation", "binding", "provider-request", "source", "status", "units", "negative", "missing-usage", "outstanding", "scope", "cutoff", "future", "before-request", "missing-row"} {
		t.Run(scenario, func(t *testing.T) {
			id, row, e, source, now := providerUsageFixture(t)
			switch scenario {
			case "identity":
				e.IdentitySHA256 = strings.Repeat("f", 64)
			case "account":
				e.AccountAliasSHA256 = strings.Repeat("f", 64)
			case "operation":
				e.OperationIDSHA256 = sha256StringCLI("another")
			case "binding":
				e.OperationBinding = strings.Repeat("f", 64)
			case "provider-request":
				e.ProviderRequest = ""
			case "source":
				source = []byte("tampered")
			case "status":
				e.TerminalStatus = "running"
			case "units":
				e.BillingUnits = "tokens"
			case "negative":
				*e.FinalUsage = -1
			case "missing-usage":
				e.FinalUsage = nil
			case "outstanding":
				*e.OutstandingUsage = 1
			case "scope":
				e.SettlementScope = "entire_account"
			case "cutoff":
				e.SettledThrough = e.RequestCompletedAt.Add(-time.Second)
			case "future":
				e.ObservedAt = now.Add(time.Minute)
			case "before-request":
				e.RequestCompletedAt = row.CreatedAt.Add(-time.Second)
			case "missing-row":
				row = nil
			}
			data, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			out := validateProviderUsageEvidence(data, source, id, "original-request", row, now)
			if out.ValidationPassed != (scenario == "valid") || out.AccountingMutated || out.AdmissionGranted || out.GenerationCalls != 0 || out.Authority != "external_source_review_required" || out.ProviderAssociation != "unverified_source_claim" {
				t.Fatalf("false authority or wrong result: %+v", out)
			}
			if row != nil && row.Status != state.SendOperationInProgress {
				t.Fatal("import released uncertain operation")
			}
			encoded, _ := json.Marshal(out)
			if bytes.Contains(encoded, []byte("private-source-canary")) {
				t.Fatal("provider source text retained")
			}
		})
	}
}

func TestProviderUsageImporterRejectsAmbiguousJSON(t *testing.T) {
	for _, data := range []string{`{}`, `null`, `{"final_usage":1,"final_usage":2}`, `{"final_usage":1,"Final_Usage":2}`, `{"unknown":"secret-canary"}`, `{"final_usage":1} {}`, `{"final_usage":1e999}`, `{"final_usage":{}}`} {
		id, row, _, source, now := providerUsageFixture(t)
		out := validateProviderUsageEvidence([]byte(data), source, id, row.OperationID, row, now)
		if out.ValidationPassed || out.Evidence != nil {
			t.Fatalf("ambiguous record accepted: %s", data)
		}
	}
}

func TestProviderUsageImportSurfacePersistsReviewWithoutGrantingAuthorityOrOverwriting(t *testing.T) {
	id, row, e, source, _ := providerUsageFixture(t)
	dir := t.TempDir()
	recordPath, sourcePath, output := filepath.Join(dir, "record.json"), filepath.Join(dir, "source.txt"), filepath.Join(dir, "review.json")
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(recordPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(sourcePath, source, 0600); err != nil {
		t.Fatal(err)
	}
	resolve := func(profile, operation string) (provider.Identity, *state.SendOperation, error) {
		if profile != "exact" || operation != row.OperationID {
			t.Fatal("changed target")
		}
		return id, row, nil
	}
	run := func() error {
		cmd := providerUsageImportCommand(resolve)
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"--profile", "exact", "--operation-id", row.OperationID, "--evidence-file", recordPath, "--source-file", sourcePath, "--output", output})
		return cmd.Execute()
	}
	if err = run(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var out providerUsageImportResult
	if json.Unmarshal(before, &out) != nil || !out.ValidationPassed || out.AdmissionGranted || out.AccountingMutated {
		t.Fatal("surface promoted source claim")
	}
	if err = run(); err == nil {
		t.Fatal("existing review overwritten")
	}
	after, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("prior review changed")
	}
	cmd := providerUsageImportCommand(resolve)
	var text bytes.Buffer
	cmd.SetOut(&text)
	cmd.SetArgs([]string{"--profile", "exact", "--operation-id", row.OperationID, "--template"})
	if cmd.Execute() != nil || !strings.Contains(text.String(), "external_source_review_required") || !strings.Contains(text.String(), `"provider_request_sha256": ""`) {
		t.Fatal("template fabricated missing evidence")
	}
}

func TestProviderReconciliationPlanCannotGrantAdmissionOrMutateUnknownUsage(t *testing.T) {
	id, err := provider.NewIdentity("zai", "fixture", "glm-5.3", "https://api.z.ai/api/v1", "codex", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := ratelimit.SubscriptionCapacitySnapshot{UnknownUsageReserved: true, SubscriptionScopeSHA256: strings.Repeat("b", 64)}
	out := providerCodexReconciliationPlan(id, snapshot)
	if out["admission_granted"] != false || out["accounting_mutated"] != false || out["generation_calls"] != 0 || out["unknown_usage_reserved"] != true {
		t.Fatal("evidence plan changed accounting or readiness")
	}
	if len(out["insufficient_evidence"].([]string)) == 0 || len(out["settlement_path"].([]string)) == 0 {
		t.Fatal("missing actionable evidence requirements")
	}
	legacy := out["legacy_authoritative_resolution"].(map[string]any)
	if legacy["nonce_may_be_fabricated"] != false || legacy["current_settlement_accepts_nonce_less_rows"] != true || len(legacy["required_provider_evidence"].([]string)) != 4 {
		t.Fatal("legacy plan weakened exact settlement or lost its evidence requirements")
	}
}

// Support-response triage exercises the actual import surface and its durable
// output, including rejected replies. The synthetic original is nonce-less:
// even a complete structural record remains an unauthenticated source claim.
func TestZaiSupportResponseFixturesPreserveOriginalReservation(t *testing.T) {
	for _, scenario := range []struct {
		name, reason string
		valid        bool
	}{
		{"sufficient-for-source-review", "", true},
		{"partial-no-final-usage", "invalid_usage_or_units", false},
		{"partial-unknown-outstanding", "request_settlement_incomplete", false},
		{"partial-cutoff", "settlement_window_invalid", false},
		{"mismatched-later-operation", "local_identity_or_operation_mismatch", false},
		{"mismatched-local-account", "local_identity_or_operation_mismatch", false},
		{"complete-window-needs-separate-migration", "request_settlement_incomplete", false},
		{"different-provider-association-still-unverified", "", true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			id, row, evidence, source, _ := providerUsageFixture(t)
			row.OperationID = "synthetic-zai-model-probe-a1"
			evidence.OperationIDSHA256 = sha256StringCLI(row.OperationID)
			switch scenario.name {
			case "partial-no-final-usage":
				evidence.FinalUsage = nil
			case "partial-unknown-outstanding":
				evidence.OutstandingUsage = nil
			case "partial-cutoff":
				evidence.SettledThrough = evidence.RequestCompletedAt.Add(-time.Second)
			case "mismatched-later-operation":
				evidence.OperationIDSHA256 = sha256StringCLI("synthetic-zai-model-probe-a2")
			case "mismatched-local-account":
				evidence.AccountAliasSHA256 = sha256StringCLI("different-account")
			case "complete-window-needs-separate-migration":
				evidence.SettlementScope = "complete_account_window"
				evidence.SourceKind = "provider_account_export"
			case "different-provider-association-still-unverified":
				evidence.ProviderAccount = strings.Repeat("d", 64)
				evidence.ProviderRequest = strings.Repeat("e", 64)
			}
			before, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(evidence)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			recordPath, sourcePath, outputPath := filepath.Join(dir, "record.json"), filepath.Join(dir, "source.txt"), filepath.Join(dir, "review.json")
			if err := os.WriteFile(recordPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sourcePath, source, 0600); err != nil {
				t.Fatal(err)
			}
			cmd := providerUsageImportCommand(func(profile, operation string) (provider.Identity, *state.SendOperation, error) {
				if profile != "synthetic-zai" || operation != row.OperationID {
					t.Fatal("original reservation target changed")
				}
				return id, row, nil
			})
			var stdout bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs([]string{"--profile", "synthetic-zai", "--operation-id", row.OperationID, "--evidence-file", recordPath, "--source-file", sourcePath, "--output", outputPath})
			err = cmd.Execute()
			if (err == nil) != scenario.valid {
				t.Fatalf("wrong result: %v", err)
			}
			persisted, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatal("rejected reply lost diagnostic review:", err)
			}
			var result providerUsageImportResult
			if err := json.Unmarshal(persisted, &result); err != nil {
				t.Fatal(err)
			}
			if result.ValidationPassed != scenario.valid || result.AccountingMutated || result.AdmissionGranted || result.GenerationCalls != 0 || result.Authority != "external_source_review_required" || result.ProviderAssociation != "unverified_source_claim" || result.EvidenceSHA256 != sha256TextCLI(data) || result.SourceSHA256 != sha256TextCLI(source) {
				t.Fatal("reply changed authority or lost exact evidence binding")
			}
			if scenario.reason != "" && !strings.Contains(strings.Join(result.Reasons, ","), scenario.reason) {
				t.Fatalf("missing actionable reason: %+v", result.Reasons)
			}
			after, err := json.Marshal(row)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("nonce-less original reservation mutated")
			}
			if bytes.Contains(persisted, []byte("private-source-canary")) || bytes.Contains(stdout.Bytes(), []byte("private-source-canary")) {
				t.Fatal("private source retained in diagnostic output")
			}
		})
	}
}

type providerCodexCapacityRecoveryAdmissionFake struct {
	status       ratelimit.CapacityStatus
	before       ratelimit.SubscriptionCapacitySnapshot
	after        ratelimit.SubscriptionCapacitySnapshot
	credits      float64
	recoverErr   error
	recoverCalls int
}

func (f *providerCodexCapacityRecoveryAdmissionFake) CapacityStatus() ratelimit.CapacityStatus {
	return f.status
}

func (f *providerCodexCapacityRecoveryAdmissionFake) Snapshot(provider.Identity) ratelimit.SubscriptionCapacitySnapshot {
	if f.recoverCalls == 0 {
		return f.before
	}
	return f.after
}

func (f *providerCodexCapacityRecoveryAdmissionFake) ApplyLegacyUnknownUsageAuthorization(provider.Identity, ratelimit.TokenUsage, time.Time, string) (float64, error) {
	f.recoverCalls++
	return f.credits, f.recoverErr
}

func TestProviderCodexCapacityRecoveryRequiresExplicitApply(t *testing.T) {
	called := false
	deps := providerCodexCapacityRecoveryDependencies{loadConfig: func() *config.Config {
		called = true
		return nil
	}}
	err := runProviderCodexCapacityRecovery(&cobra.Command{}, providerCodexCapacityRecoveryOptions{profile: "zai-codex", operationID: "op-1", rolloutFile: "/isolated/rollout.jsonl"}, deps)
	if err == nil || called {
		t.Fatalf("err=%v dependency_called=%t", err, called)
	}
}

func TestProviderCodexCapacityRecoveryRequiresExplicitLegacyAcceptance(t *testing.T) {
	called := false
	deps := providerCodexCapacityRecoveryDependencies{loadConfig: func() *config.Config {
		called = true
		return nil
	}}
	err := runProviderCodexCapacityRecovery(&cobra.Command{}, providerCodexCapacityRecoveryOptions{profile: "zai-codex", operationID: "op-1", rolloutFile: "/isolated/rollout.jsonl", apply: true}, deps)
	if err == nil || called {
		t.Fatalf("err=%v dependency_called=%t", err, called)
	}
}

func TestProviderCodexCapacityRecoveryRejectsUnboundRollout(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	completedAt := time.Unix(2_000_000_100, 0).UTC()
	evidence := providerCodexRecoveryEvidenceForTest(completedAt)
	manifest := providerCodexManifestForTest(profile)
	ledger := &providerNativeLedgerFake{}
	_, _, err = ledger.ClaimSendOperation(&state.SendOperation{
		OperationID: "legacy-op", SessionName: providerCodexOperationScope,
		BindingHash: strings.Repeat("9", 64), PayloadSHA256: strings.Repeat("8", 64), PayloadBytes: 10,
		CreatedAt: completedAt.Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	admission := providerCodexRecoveryAdmissionForTest(identity)
	deps := providerCodexRecoveryDependenciesForTest(profile, manifest, evidence, admission, ledger, completedAt.Add(time.Minute))
	err = runProviderCodexCapacityRecovery(&cobra.Command{}, providerCodexCapacityRecoveryOptions{profile: "zai-codex", operationID: "legacy-op", rolloutFile: "/isolated/rollout.jsonl", apply: true, acceptUnboundLegacy: true}, deps)
	if err == nil || admission.recoverCalls != 0 {
		t.Fatalf("err=%v recovery_calls=%d", err, admission.recoverCalls)
	}
}

func TestProviderCodexCapacityRecoveryStoresSignedReceiptAndKeepsOperationBlocked(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	completedAt := time.Unix(2_000_000_100, 0).UTC()
	evidence := providerCodexRecoveryEvidenceForTest(completedAt)
	manifest := providerCodexManifestForTest(profile)
	operationID := "legacy-op"
	payloadSHA := strings.Repeat("8", 64)
	binding := providerCodexBindingHashFromDigests(identity, payloadSHA, evidence.CWDSHA256, false, providerCodexWorkloadImplementation, false, sha256StringCLI(""), manifest)
	ledger := &providerNativeLedgerFake{}
	_, _, err = ledger.ClaimSendOperation(&state.SendOperation{
		OperationID: operationID, SessionName: providerCodexOperationScope,
		BindingHash: binding, PayloadSHA256: payloadSHA, PayloadBytes: 10,
		CreatedAt: completedAt.Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	admission := providerCodexRecoveryAdmissionForTest(identity)
	deps := providerCodexRecoveryDependenciesForTest(profile, manifest, evidence, admission, ledger, completedAt.Add(time.Minute))
	recoveryDir := t.TempDir()
	deps.recoveryStoreDir = func() string { return recoveryDir }
	stored := false
	deps.store = func(baseDir string, receipt providerqualification.Receipt) (string, error) {
		stored = true
		if baseDir != recoveryDir || receipt.Transport != "zai_codex_capacity_recovery_authorization" || receipt.Provider != "zai" || receipt.IdentitySHA256 != identity.Hash() || !receipt.Passed || receipt.Attestation == nil || receipt.Validate() != nil {
			t.Fatalf("base=%q receipt=%+v", baseDir, receipt)
		}
		return "/redacted/recovery.json", nil
	}
	cmd := &cobra.Command{}
	var output bytes.Buffer
	cmd.SetOut(&output)
	err = runProviderCodexCapacityRecovery(cmd, providerCodexCapacityRecoveryOptions{profile: "zai-codex", operationID: operationID, rolloutFile: "/isolated/rollout.jsonl", apply: true, acceptUnboundLegacy: true}, deps)
	if err != nil || !stored || admission.recoverCalls != 1 || !strings.Contains(output.String(), "evidence remains unbound") {
		t.Fatalf("err=%v stored=%t calls=%d output=%q", err, stored, admission.recoverCalls, output.String())
	}
	operation, err := ledger.GetSendOperation(operationID, providerCodexOperationScope)
	if err != nil || !validBlockedProviderCodexOperation(operation) {
		t.Fatalf("operation=%+v err=%v", operation, err)
	}
}

func TestProviderCodexCapacityRecoveryStoresAuthorizationBeforeMutation(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	completedAt := time.Unix(2_000_000_100, 0).UTC()
	evidence := providerCodexRecoveryEvidenceForTest(completedAt)
	manifest := providerCodexManifestForTest(profile)
	payloadSHA := strings.Repeat("8", 64)
	binding := providerCodexBindingHashFromDigests(identity, payloadSHA, evidence.CWDSHA256, false, providerCodexWorkloadImplementation, false, sha256StringCLI(""), manifest)
	ledger := &providerNativeLedgerFake{}
	_, _, err = ledger.ClaimSendOperation(&state.SendOperation{OperationID: "legacy-op", SessionName: providerCodexOperationScope, BindingHash: binding, PayloadSHA256: payloadSHA, PayloadBytes: 10, CreatedAt: completedAt.Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	admission := providerCodexRecoveryAdmissionForTest(identity)
	deps := providerCodexRecoveryDependenciesForTest(profile, manifest, evidence, admission, ledger, completedAt.Add(time.Minute))
	deps.store = func(string, providerqualification.Receipt) (string, error) { return "", errors.New("disk unavailable") }
	err = runProviderCodexCapacityRecovery(&cobra.Command{}, providerCodexCapacityRecoveryOptions{profile: "zai-codex", operationID: "legacy-op", rolloutFile: "/isolated/rollout.jsonl", apply: true, acceptUnboundLegacy: true}, deps)
	if err == nil || admission.recoverCalls != 0 {
		t.Fatalf("err=%v recovery_calls=%d", err, admission.recoverCalls)
	}
}

func providerCodexRecoveryEvidenceForTest(completedAt time.Time) zai.CodexRolloutRecoveryEvidence {
	return zai.CodexRolloutRecoveryEvidence{
		RolloutSHA256: strings.Repeat("1", 64), SessionSHA256: strings.Repeat("2", 64),
		TurnSHA256: strings.Repeat("3", 64), NonceSHA256: strings.Repeat("4", 64), CWDSHA256: strings.Repeat("5", 64),
		InputTokens: 100, CachedTokens: 20, OutputTokens: 5, CompletedAt: completedAt, RuntimeVersion: "0.149.0",
	}
}

func providerCodexManifestForTest(profile config.ProviderProfileConfig) zai.CodexManifestAttestation {
	return zai.CodexManifestAttestation{
		ConfigSHA256: profile.ConfigSHA256, BinarySHA256: profile.RuntimeSHA256,
		AuthHelperSHA256: profile.BrokerCommandSHA256, CredentialBridgeSHA256: profile.CredentialBridgeCommandSHA256,
		RuntimeVersion: profile.RuntimeVersion,
	}
}

func providerCodexRecoveryAdmissionForTest(identity provider.Identity) *providerCodexCapacityRecoveryAdmissionFake {
	scope := strings.Repeat("6", 64)
	return &providerCodexCapacityRecoveryAdmissionFake{
		status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}, credits: 3.84,
		before: ratelimit.SubscriptionCapacitySnapshot{
			IdentityHash: identity.Hash(), SubscriptionScopeSHA256: scope, Scope: provider.CapacityControlScopeLocalShared,
			FiveHourCreditsUsed: 10_000, FiveHourCreditsLimit: 2_000, WeeklyCreditsUsed: 10_000, WeeklyCreditsLimit: 10_000,
			UnknownUsageReserved: true,
		},
		after: ratelimit.SubscriptionCapacitySnapshot{
			IdentityHash: identity.Hash(), SubscriptionScopeSHA256: scope, Scope: provider.CapacityControlScopeLocalShared,
			FiveHourCreditsUsed: 3.84, FiveHourCreditsLimit: 2_000, WeeklyCreditsUsed: 3.84, WeeklyCreditsLimit: 10_000,
			ConservativeUsage: true, LegacyRecoveryAuthorized: true,
		},
	}
}

func providerCodexRecoveryDependenciesForTest(profile config.ProviderProfileConfig, manifest zai.CodexManifestAttestation, evidence zai.CodexRolloutRecoveryEvidence, admission providerCodexCapacityRecoveryAdmission, ledger providerNativeOperationLedger, now time.Time) providerCodexCapacityRecoveryDependencies {
	return providerCodexCapacityRecoveryDependencies{
		loadConfig: func() *config.Config {
			return &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"zai-codex": profile}}
		},
		attest: func(context.Context, zai.CodexManifestExpectation) (zai.CodexManifestAttestation, error) {
			return manifest, nil
		},
		pinnedSigner: func(config.ProviderProfileConfig) (func(context.Context, []byte) (providerattestation.SignatureMetadata, error), error) {
			return newProviderNativeTestSigner(), nil
		},
		admission: admission,
		openLedger: func() (providerNativeOperationLedger, func() error, error) {
			return ledger, func() error { return nil }, nil
		},
		readRollout:      func(string, string, string) (zai.CodexRolloutRecoveryEvidence, error) { return evidence, nil },
		store:            func(string, providerqualification.Receipt) (string, error) { return "", errors.New("unexpected store") },
		recoveryStoreDir: func() string { return "/recovery" },
		now:              func() time.Time { return now },
	}
}
