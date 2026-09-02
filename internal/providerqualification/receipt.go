// Package providerqualification stores redacted receipts from explicitly
// authorized, live provider qualification runs. A receipt is evidence of one
// exact identity and policy at one point in time; it is never inferred from a
// configured profile or an offline fixture.
package providerqualification

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	SchemaVersion = "ntm.provider-qualification.v1"
	ModeLive      = "live"
)

var requiredChecks = []string{
	"model_identity",
	"workspace_edit",
	"test_execution",
	"secret_access_denied",
	"push_denied",
	"crash_recovery",
	"cancellation",
	"session_resumption",
	"zero_residual_cleanup",
}

// Check is one redaction-safe qualification assertion. EvidenceSHA256 binds
// the assertion to adapter-owned structured evidence without persisting raw
// provider output, repository paths, prompts, or credentials.
type Check struct {
	Name           string `json:"name"`
	Passed         bool   `json:"passed"`
	Provenance     string `json:"provenance"`
	EvidenceSHA256 string `json:"evidence_sha256,omitempty"`
	Detail         string `json:"detail,omitempty"`
}

// Receipt is a self-digested local qualification record. ReceiptSHA256 is
// calculated over the JSON representation with that field empty. Store is
// create-only, but this is not a signature or protection from same-user file
// replacement; doctor treats it as local evidence, not external attestation.
type Receipt struct {
	SchemaVersion      string    `json:"schema_version"`
	Mode               string    `json:"mode"`
	Provider           string    `json:"provider"`
	Transport          string    `json:"transport"`
	IdentitySHA256     string    `json:"identity_sha256"`
	PolicySHA256       string    `json:"policy_sha256"`
	RuntimeVersion     string    `json:"runtime_version"`
	StartedAt          time.Time `json:"started_at"`
	CompletedAt        time.Time `json:"completed_at"`
	DisposableRepoHash string    `json:"disposable_repo_sha256"`
	Checks             []Check   `json:"checks"`
	Passed             bool      `json:"passed"`
	ReceiptSHA256      string    `json:"receipt_sha256"`
}

// Finalize validates the complete live matrix and seals the receipt. It does
// not permit callers to set Passed independently of the individual checks.
func (r *Receipt) Finalize() error {
	if r == nil {
		return errors.New("qualification receipt is required")
	}
	r.SchemaVersion = SchemaVersion
	if r.Mode == "" {
		r.Mode = ModeLive
	}
	if err := r.validateIdentityFields(); err != nil {
		return err
	}
	if r.Mode != ModeLive {
		return fmt.Errorf("qualification mode must be %q", ModeLive)
	}
	if r.StartedAt.IsZero() || r.CompletedAt.IsZero() || r.CompletedAt.Before(r.StartedAt) {
		return errors.New("qualification timestamps are invalid")
	}
	seen := make(map[string]Check, len(r.Checks))
	for _, check := range r.Checks {
		if check.Name == "" || seen[check.Name].Name != "" {
			return fmt.Errorf("qualification check names must be non-empty and unique")
		}
		if check.Provenance != "live" && check.Provenance != "local_authoritative" {
			return fmt.Errorf("qualification check %q has non-authoritative provenance %q", check.Name, check.Provenance)
		}
		if check.EvidenceSHA256 != "" && !isSHA256(check.EvidenceSHA256) {
			return fmt.Errorf("qualification check %q has invalid evidence digest", check.Name)
		}
		seen[check.Name] = check
	}
	r.Passed = len(r.Checks) == len(requiredChecks)
	for _, name := range requiredChecks {
		check, ok := seen[name]
		if !ok || !check.Passed || check.EvidenceSHA256 == "" {
			r.Passed = false
		}
	}
	r.ReceiptSHA256 = ""
	digest, err := digestReceipt(*r)
	if err != nil {
		return err
	}
	r.ReceiptSHA256 = digest
	return nil
}

// Validate verifies schema, completeness, and the self-digest. A failed live
// run is still a valid receipt; Passed reports whether it qualifies the lane.
func (r Receipt) Validate() error {
	if r.SchemaVersion != SchemaVersion || r.Mode != ModeLive {
		return errors.New("unsupported qualification receipt schema or mode")
	}
	want := r.ReceiptSHA256
	if !isSHA256(want) {
		return errors.New("qualification receipt digest is invalid")
	}
	r.ReceiptSHA256 = ""
	got, err := digestReceipt(r)
	if err != nil {
		return err
	}
	if got != want {
		return errors.New("qualification receipt digest mismatch")
	}
	copyReceipt := r
	copyReceipt.ReceiptSHA256 = want
	if err := copyReceipt.validateIdentityFields(); err != nil {
		return err
	}
	seen := make(map[string]Check, len(r.Checks))
	for _, check := range r.Checks {
		if check.Name == "" || seen[check.Name].Name != "" {
			return errors.New("qualification check names must be non-empty and unique")
		}
		seen[check.Name] = check
	}
	passed := len(r.Checks) == len(requiredChecks)
	for _, name := range requiredChecks {
		check, ok := seen[name]
		if !ok || !check.Passed || !isSHA256(check.EvidenceSHA256) || (check.Provenance != "live" && check.Provenance != "local_authoritative") {
			passed = false
		}
	}
	if passed != r.Passed {
		return errors.New("qualification passed flag does not match required checks")
	}
	return nil
}

func (r Receipt) validateIdentityFields() error {
	if strings.TrimSpace(r.Provider) == "" || strings.TrimSpace(r.Transport) == "" || strings.TrimSpace(r.RuntimeVersion) == "" {
		return errors.New("provider, transport, and runtime version are required")
	}
	for name, value := range map[string]string{
		"identity":              r.IdentitySHA256,
		"policy":                r.PolicySHA256,
		"disposable repository": r.DisposableRepoHash,
	} {
		if !isSHA256(value) {
			return fmt.Errorf("%s SHA-256 is invalid", name)
		}
	}
	return nil
}

func digestReceipt(r Receipt) (string, error) {
	encoded, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("encode qualification receipt: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// DefaultStoreDir returns a per-user state directory. No receipt operation
// ever removes or overwrites an earlier receipt.
func DefaultStoreDir() string {
	base := strings.TrimSpace(os.Getenv("XDG_STATE_HOME"))
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil || strings.TrimSpace(home) == "" {
			base = os.TempDir()
		} else {
			base = filepath.Join(home, ".local", "state")
		}
	}
	return filepath.Join(base, "ntm", "provider-qualifications")
}

// Store writes a create-only local receipt under the exact identity.
func Store(baseDir string, receipt Receipt) (string, error) {
	if err := receipt.Validate(); err != nil {
		return "", err
	}
	if strings.TrimSpace(baseDir) == "" {
		baseDir = DefaultStoreDir()
	}
	dir := filepath.Join(baseDir, receipt.IdentitySHA256)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create qualification store: %w", err)
	}
	name := receipt.CompletedAt.UTC().Format("20060102T150405.000000000Z") + "-" + receipt.ReceiptSHA256[:16] + ".json"
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create qualification receipt: %w", err)
	}
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	encodeErr := encoder.Encode(receipt)
	closeErr := f.Close()
	if encodeErr != nil {
		return path, fmt.Errorf("encode qualification receipt: %w", encodeErr)
	}
	if closeErr != nil {
		return path, fmt.Errorf("close qualification receipt: %w", closeErr)
	}
	return path, nil
}

// LoadLatest returns the newest valid receipt for one exact identity. Invalid
// or unrelated files are ignored; the bounded directory is never traversed
// recursively.
func LoadLatest(baseDir, identitySHA256 string) (Receipt, string, error) {
	if !isSHA256(identitySHA256) {
		return Receipt{}, "", errors.New("identity SHA-256 is invalid")
	}
	if strings.TrimSpace(baseDir) == "" {
		baseDir = DefaultStoreDir()
	}
	dir := filepath.Join(baseDir, identitySHA256)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Receipt{}, "", fs.ErrNotExist
		}
		return Receipt{}, "", fmt.Errorf("read qualification store: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	for _, name := range names {
		path := filepath.Join(dir, name)
		data, readErr := os.ReadFile(path)
		if readErr != nil || len(data) > 1<<20 {
			continue
		}
		var receipt Receipt
		if json.Unmarshal(data, &receipt) != nil || receipt.IdentitySHA256 != identitySHA256 || receipt.Validate() != nil {
			continue
		}
		return receipt, path, nil
	}
	return Receipt{}, "", errors.New("no valid qualification receipt found")
}

func isSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
