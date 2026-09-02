package providerqualification

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"testing"
	"time"
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
