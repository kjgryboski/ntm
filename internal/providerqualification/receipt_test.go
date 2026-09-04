package providerqualification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providercredential"
)

func testHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func passingReceipt(t *testing.T, completed time.Time) Receipt {
	t.Helper()
	checks := make([]Check, 0, len(requiredChecks))
	for _, name := range requiredChecks {
		checks = append(checks, Check{Name: name, Passed: true, Provenance: "live", EvidenceSHA256: testHash(name)})
	}
	r := Receipt{
		Mode: ModeLive, Provider: "zai", Transport: "zai_claude_runtime",
		IdentitySHA256: testHash("identity"), PolicySHA256: testHash("policy"), RuntimeVersion: "2.1.252",
		StartedAt: completed.Add(-time.Minute), CompletedAt: completed, DisposableRepoHash: testHash("repo"), Checks: checks,
	}
	if err := r.Finalize(); err != nil {
		t.Fatalf("Finalize() error: %v", err)
	}
	return r
}

func TestReceiptSealsOnlyBoundedFailureReasons(t *testing.T) {
	r := passingReceipt(t, time.Unix(1_800_000_000, 0).UTC())
	r.Checks[0].Passed = false
	r.Checks[0].FailureReason = provider.ProtocolMalformedEnvelope
	if err := r.Finalize(); err != nil {
		t.Fatal(err)
	}
	payload, err := r.CanonicalPayload()
	if err != nil || !strings.Contains(string(payload), `"failure_reason":"malformed_envelope"`) || r.Validate() != nil {
		t.Fatal("failure reason was not sealed in the canonical signed payload")
	}
	r.Checks[0].FailureReason = provider.ProtocolUnknownMethod
	if r.Validate() == nil {
		t.Fatal("tampering with failure reason did not invalidate receipt")
	}
	r.Checks[0].FailureReason = provider.ProtocolFailureReason("SENSITIVE_CANARY")
	if err := r.Finalize(); err == nil || strings.Contains(err.Error(), "SENSITIVE_CANARY") {
		t.Fatal("arbitrary diagnostic text accepted or exposed")
	}
	r.Checks[0].FailureReason = provider.ProtocolUnknownMethod
	r.Checks[0].Passed = true
	if r.Finalize() == nil {
		t.Fatal("passing check accepted a failure reason")
	}
}

func TestDiagnosticsAreRedactedDurableAndNeverReceipts(t *testing.T) {
	r := passingReceipt(t, time.Now().UTC())
	r.Provider = "SECRET_PROVIDER_CANARY"
	r.RuntimeVersion = "SECRET_RUNTIME_CANARY"
	r.Checks[0].Detail = "SECRET_PAYLOAD_CANARY"
	r.Checks[0].Passed = false
	r.Checks[0].FailureReason = provider.ProtocolSessionMismatch
	r.Checks = append(r.Checks, Check{Name: "SECRET_CHECK_CANARY", Provenance: "live"})
	if err := r.Finalize(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	r.Checks[0].Provenance = "SECRET_PROVENANCE_CANARY"
	r.Checks[0].EvidenceSHA256 = "SECRET_EVIDENCE_CANARY"
	r.ReceiptSHA256 = ""
	digest, err := digestReceipt(r)
	if err != nil {
		t.Fatal(err)
	}
	r.ReceiptSHA256 = digest
	path, err := StoreDiagnostics(dir, r)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "SECRET_") {
		t.Fatal("free-form data leaked")
	}
	var record DiagnosticObservation
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if record.Trust != "unsigned_diagnostic_only" || record.ReceiptSHA256 != r.ReceiptSHA256 || record.Observations[0].FailureReason != provider.ProtocolSessionMismatch {
		t.Fatal("lost diagnostic identity or structured reason")
	}
	var receipt Receipt
	if json.Unmarshal(data, &receipt) != nil || receipt.Validate() == nil {
		t.Fatal("diagnostics accepted as a receipt")
	}
	if _, _, err := LoadLatestForTransport(dir, r.IdentitySHA256, r.Transport); err == nil {
		t.Fatal("diagnostics loaded as qualification")
	}
	second, err := StoreDiagnostics(dir, r)
	if err != nil || second == path {
		t.Fatal("observation was overwritten")
	}
	bad := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(bad, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := StoreDiagnostics(bad, r); err == nil {
		t.Fatal("storage failure ignored")
	}
}

func TestReceiptFinalizeRequiresEveryLiveCheck(t *testing.T) {
	r := passingReceipt(t, time.Unix(1_800_000_000, 0).UTC())
	if !r.Passed || r.Validate() != nil {
		t.Fatalf("passing receipt = %#v, validate=%v", r, r.Validate())
	}
	r.Checks[3].Passed = false
	if err := r.Finalize(); err != nil {
		t.Fatalf("Finalize(failed check) error: %v", err)
	}
	if r.Passed {
		t.Fatal("receipt passed with a failed required check")
	}
}

func TestReceiptFinalizeRecognizesZaiCodexRuntimeMatrix(t *testing.T) {
	completed := time.Unix(1_800_000_000, 0).UTC()
	checks := make([]Check, 0, len(codexRequiredChecks))
	for _, name := range codexRequiredChecks {
		checks = append(checks, Check{Name: name, Passed: true, Provenance: "live", EvidenceSHA256: testHash("codex-" + name)})
	}
	receipt := Receipt{
		Mode: ModeLive, Provider: "zai", Transport: "zai_codex_runtime",
		IdentitySHA256: testHash("codex-identity"), PolicySHA256: testHash("codex-policy"), RuntimeVersion: "0.149.0",
		StartedAt: completed.Add(-time.Minute), CompletedAt: completed, DisposableRepoHash: testHash("codex-repo"), Checks: checks,
	}
	if err := receipt.Finalize(); err != nil {
		t.Fatalf("Finalize() error: %v", err)
	}
	if !receipt.Passed || receipt.Validate() != nil {
		t.Fatalf("Codex receipt = %#v, validate=%v", receipt, receipt.Validate())
	}
}

func TestReceiptFinalizeRecognizesDistinctCodexIdentityPreflightMatrix(t *testing.T) {
	completed := time.Unix(1_800_000_000, 0).UTC()
	checks := make([]Check, 0, len(codexIdentityPreflightRequiredChecks))
	for _, name := range codexIdentityPreflightRequiredChecks {
		checks = append(checks, Check{Name: name, Passed: true, Provenance: "live", EvidenceSHA256: testHash("preflight-" + name)})
	}
	receipt := Receipt{
		Mode: ModeLive, Provider: "zai", Transport: "zai_codex_identity_preflight",
		IdentitySHA256: testHash("preflight-identity"), PolicySHA256: testHash("preflight-policy"), RuntimeVersion: "0.149.0",
		StartedAt: completed.Add(-time.Minute), CompletedAt: completed, DisposableRepoHash: testHash("preflight-root"), Checks: checks,
	}
	if err := receipt.Finalize(); err != nil {
		t.Fatalf("Finalize() error: %v", err)
	}
	if !receipt.Passed || receipt.Validate() != nil {
		t.Fatalf("preflight receipt = %#v, validate=%v", receipt, receipt.Validate())
	}

	// A complete preflight has a smaller, distinct matrix and cannot validate
	// if relabeled as the full runtime qualification transport.
	relabeled := receipt
	relabeled.Transport = "zai_codex_runtime"
	if err := relabeled.Finalize(); err != nil || relabeled.Passed || relabeled.Validate() != nil {
		t.Fatalf("preflight matrix was accepted as a full runtime qualification: receipt=%#v finalize=%v validate=%v", relabeled, err, relabeled.Validate())
	}
}

func TestCodexIdentityPreflightStoreIsSeparateFromQualificationStore(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	qualificationDir := DefaultStoreDir()
	preflightDir := DefaultCodexIdentityPreflightStoreDir()
	if filepath.Dir(qualificationDir) != filepath.Dir(preflightDir) || qualificationDir == preflightDir {
		t.Fatalf("store dirs are not distinct siblings: qualification=%q preflight=%q", qualificationDir, preflightDir)
	}
	if filepath.Base(preflightDir) != "provider-codex-identity-preflights" {
		t.Fatalf("preflight directory = %q", preflightDir)
	}
}

func TestReceiptRejectsSyntheticProvenance(t *testing.T) {
	r := passingReceipt(t, time.Unix(1_800_000_000, 0).UTC())
	r.Checks[0].Provenance = "synthetic"
	if err := r.Finalize(); err == nil {
		t.Fatal("Finalize() accepted synthetic provenance")
	}
}

func TestReceiptAcceptsObservedLocalProcessTreeProvenance(t *testing.T) {
	r := passingReceipt(t, time.Unix(1_800_000_000, 0).UTC())
	for i := range r.Checks {
		if r.Checks[i].Name == "zero_residual_cleanup" {
			r.Checks[i].Provenance = "local_observed_process_tree"
		}
	}
	if err := r.Finalize(); err != nil {
		t.Fatalf("Finalize() rejected scoped authoritative provenance: %v", err)
	}
	if !r.Passed {
		t.Fatal("scoped authoritative cleanup evidence must remain eligible to pass")
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate() rejected scoped authoritative provenance: %v", err)
	}
}

type qualificationAttestationStore struct{ seed []byte }

func (s *qualificationAttestationStore) Get(context.Context, string) ([]byte, error) {
	if len(s.seed) == 0 {
		return nil, providercredential.ErrNotFound
	}
	return append([]byte(nil), s.seed...), nil
}
func (s *qualificationAttestationStore) Put(_ context.Context, _ string, value []byte) error {
	s.seed = append([]byte(nil), value...)
	return nil
}
func (s *qualificationAttestationStore) Status(context.Context, string) (providercredential.Status, error) {
	return providercredential.Status{Available: true, Present: len(s.seed) != 0, Evidence: providercredential.EvidenceOSProtectedProcessReadable}, nil
}

func TestReceiptValidateAcceptsItsAttachedAttestation(t *testing.T) {
	receipt := passingReceipt(t, time.Unix(1_800_000_000, 0).UTC())
	attestor, err := providerattestation.New(&qualificationAttestationStore{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attestor.EnsureKey(t.Context(), "qualification-test"); err != nil {
		t.Fatal(err)
	}
	payload, err := receipt.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := attestor.Sign(t.Context(), "qualification-test", payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.AttachAttestation(signature); err != nil {
		t.Fatal(err)
	}
	if err := receipt.Validate(); err != nil {
		t.Fatalf("attached qualification attestation failed validation: %v", err)
	}
}

func TestStoreIsCreateOnlyAndLoadLatestValid(t *testing.T) {
	dir := t.TempDir()
	older := passingReceipt(t, time.Unix(1_800_000_000, 0).UTC())
	newer := passingReceipt(t, older.CompletedAt.Add(time.Hour))
	if _, err := Store(dir, older); err != nil {
		t.Fatalf("Store(older) error: %v", err)
	}
	if _, err := Store(dir, newer); err != nil {
		t.Fatalf("Store(newer) error: %v", err)
	}
	got, path, err := LoadLatest(dir, newer.IdentitySHA256)
	if err != nil {
		t.Fatalf("LoadLatest() error: %v", err)
	}
	if got.ReceiptSHA256 != newer.ReceiptSHA256 || path == "" {
		t.Fatalf("LoadLatest() = %s %q, want %s", got.ReceiptSHA256, path, newer.ReceiptSHA256)
	}
	if _, err := Store(dir, newer); err == nil {
		t.Fatal("Store() overwrote a create-only receipt")
	}
}

func TestLoadLatestForTransportSkipsNewerDifferentLane(t *testing.T) {
	dir := t.TempDir()
	older := passingReceipt(t, time.Unix(1_800_000_000, 0).UTC())
	checks := make([]Check, 0, len(codexRequiredChecks))
	for _, name := range codexRequiredChecks {
		checks = append(checks, Check{Name: name, Passed: true, Provenance: "live", EvidenceSHA256: testHash("other-" + name)})
	}
	newerOtherLane := Receipt{
		Mode: ModeLive, Provider: "zai", Transport: "zai_codex_runtime",
		IdentitySHA256: older.IdentitySHA256, PolicySHA256: testHash("codex-policy"), RuntimeVersion: "0.149.0",
		StartedAt: older.CompletedAt.Add(59 * time.Minute), CompletedAt: older.CompletedAt.Add(time.Hour), DisposableRepoHash: testHash("codex-repo"), Checks: checks,
	}
	if err := newerOtherLane.Finalize(); err != nil {
		t.Fatal(err)
	}
	if _, err := Store(dir, older); err != nil {
		t.Fatal(err)
	}
	if _, err := Store(dir, newerOtherLane); err != nil {
		t.Fatal(err)
	}
	got, _, err := LoadLatestForTransport(dir, older.IdentitySHA256, older.Transport)
	if err != nil {
		t.Fatal(err)
	}
	if got.ReceiptSHA256 != older.ReceiptSHA256 {
		t.Fatalf("transport-filtered load = %s, want %s", got.ReceiptSHA256, older.ReceiptSHA256)
	}
}

func TestLoadLatestMissingIsNotExist(t *testing.T) {
	_, _, err := LoadLatest(t.TempDir(), testHash("missing"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadLatest() error = %v, want fs.ErrNotExist", err)
	}
}
