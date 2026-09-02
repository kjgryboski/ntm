package providerqualification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"testing"
	"time"

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

func TestReceiptRejectsSyntheticProvenance(t *testing.T) {
	r := passingReceipt(t, time.Unix(1_800_000_000, 0).UTC())
	r.Checks[0].Provenance = "synthetic"
	if err := r.Finalize(); err == nil {
		t.Fatal("Finalize() accepted synthetic provenance")
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

func TestLoadLatestMissingIsNotExist(t *testing.T) {
	_, _, err := LoadLatest(t.TempDir(), testHash("missing"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadLatest() error = %v, want fs.ErrNotExist", err)
	}
}
