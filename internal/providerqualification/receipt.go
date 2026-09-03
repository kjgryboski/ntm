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

	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
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

// codexRequiredChecks is deliberately a distinct matrix even though the
// current Z.ai Codex qualification gate set matches the Claude-compatible
// Coding Plan lane. Keeping the transport-specific declaration prevents a
// future Codex adapter from silently inheriting a reduced or expanded set of
// checks when either lane evolves.
var codexRequiredChecks = []string{
	"model_identity",
	"workspace_edit",
	"test_execution",
	"secret_access_denied",
	"push_denied",
	"crash_recovery",
	"cancellation",
	"session_resumption",
	"capacity_accounting",
	"zero_residual_cleanup",
}

// codexCapacityRecoveryAuthorizationRequiredChecks is an authorization
// matrix, not a runtime qualification. It is stored in a separate tree and
// explicitly records the legacy evidence-link limitation before mutation.
var codexCapacityRecoveryAuthorizationRequiredChecks = []string{
	"profile_manifest",
	"operation_ledger",
	"isolated_rollout",
	"nonce_completion",
	"provider_usage",
	"unknown_reservation_observed",
	"owner_authorized_unbound_exception",
}

// codexIdentityPreflightRequiredChecks is a narrow, paid read-only probe
// matrix. It is deliberately not a runtime qualification: it proves only the
// exact identity and no-tool safety boundary before a disposable-worktree
// suite may begin. These receipts live outside the qualification store and
// must never be used as readiness evidence.
var codexIdentityPreflightRequiredChecks = []string{
	"profile_manifest",
	"credential_broker",
	"receipt_signer",
	"shared_capacity_admission",
	"provider_dispatch",
	"nonce_completion",
	"exact_model_identity",
	"no_tool_activity",
	"empty_workspace",
	"zero_residual_cleanup",
	"capacity_accounting",
}

var nativeRequiredChecks = []string{
	"exact_model_request_id",
	"controller_tool_loop",
	"workspace_edit",
	"isolated_verification",
	"protected_path_denial",
	"shell_and_push_absent",
	"local_inflight_http_cancellation",
	"outcome_unknown_no_replay",
	"local_sandbox_process_cleanup",
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
// create-only. Attestation, when present, provides public tamper evidence;
// readiness consumers must separately require it rather than treating an
// unsigned legacy receipt as qualified evidence.
type Receipt struct {
	SchemaVersion      string                                 `json:"schema_version"`
	Mode               string                                 `json:"mode"`
	Provider           string                                 `json:"provider"`
	Transport          string                                 `json:"transport"`
	IdentitySHA256     string                                 `json:"identity_sha256"`
	PolicySHA256       string                                 `json:"policy_sha256"`
	RuntimeVersion     string                                 `json:"runtime_version"`
	StartedAt          time.Time                              `json:"started_at"`
	CompletedAt        time.Time                              `json:"completed_at"`
	DisposableRepoHash string                                 `json:"disposable_repo_sha256"`
	Checks             []Check                                `json:"checks"`
	Passed             bool                                   `json:"passed"`
	ReceiptSHA256      string                                 `json:"receipt_sha256"`
	Attestation        *providerattestation.SignatureMetadata `json:"attestation,omitempty"`
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
		if !authoritativeProvenance(check.Provenance) {
			return fmt.Errorf("qualification check %q has non-authoritative provenance %q", check.Name, check.Provenance)
		}
		if check.EvidenceSHA256 != "" && !isSHA256(check.EvidenceSHA256) {
			return fmt.Errorf("qualification check %q has invalid evidence digest", check.Name)
		}
		seen[check.Name] = check
	}
	required, err := requiredChecksForTransport(r.Transport)
	if err != nil {
		return err
	}
	r.Passed = len(r.Checks) == len(required)
	for _, name := range required {
		check, ok := seen[name]
		if !ok || !check.Passed || check.EvidenceSHA256 == "" {
			r.Passed = false
		}
	}
	r.ReceiptSHA256 = ""
	r.Attestation = nil
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
	required, err := requiredChecksForTransport(r.Transport)
	if err != nil {
		return err
	}
	passed := len(r.Checks) == len(required)
	for _, name := range required {
		check, ok := seen[name]
		if !ok || !check.Passed || !isSHA256(check.EvidenceSHA256) || !authoritativeProvenance(check.Provenance) {
			passed = false
		}
	}
	if passed != r.Passed {
		return errors.New("qualification passed flag does not match required checks")
	}
	if r.Attestation != nil {
		attested := r
		attested.ReceiptSHA256 = want
		payload, err := attested.CanonicalPayload()
		if err != nil || providerattestation.Verify(payload, *r.Attestation) != nil {
			return errors.New("qualification receipt attestation is invalid")
		}
	}
	return nil
}

// authoritativeProvenance deliberately distinguishes provider evidence from
// controller-owned checks and from the narrower, continuously observed local
// process-tree cleanup claim. The latter is authoritative for processes NTM
// observed beneath the launched root only; it is not provider-side
// cancellation evidence and must never be described as such.
func authoritativeProvenance(provenance string) bool {
	switch provenance {
	case "live", "local_authoritative", "local_observed_process_tree":
		return true
	default:
		return false
	}
}

// CanonicalPayload returns the finalized receipt bytes covered by the public
// attestation. The signature envelope itself is excluded to avoid recursion;
// the self-digest remains included.
func (r Receipt) CanonicalPayload() ([]byte, error) {
	if !isSHA256(r.ReceiptSHA256) {
		return nil, errors.New("qualification receipt must be finalized before attestation")
	}
	r.Attestation = nil
	encoded, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("encode qualification attestation payload: %w", err)
	}
	return encoded, nil
}

func (r *Receipt) AttachAttestation(signature providerattestation.SignatureMetadata) error {
	if r == nil {
		return errors.New("qualification receipt is required")
	}
	payload, err := r.CanonicalPayload()
	if err != nil {
		return err
	}
	if err := providerattestation.Verify(payload, signature); err != nil {
		return errors.New("qualification receipt attestation is invalid")
	}
	r.Attestation = &signature
	return nil
}

func requiredChecksForTransport(transport string) ([]string, error) {
	switch transport {
	case "zai_claude_runtime":
		return requiredChecks, nil
	case "zai_codex_runtime":
		return codexRequiredChecks, nil
	case "zai_codex_capacity_recovery_authorization":
		return codexCapacityRecoveryAuthorizationRequiredChecks, nil
	case "zai_codex_identity_preflight":
		return codexIdentityPreflightRequiredChecks, nil
	case "zai_native_api":
		return nativeRequiredChecks, nil
	default:
		return nil, fmt.Errorf("unsupported qualification transport %q", transport)
	}
}

// NativeRequiredChecks returns a copy of the complete native qualification
// matrix so the live adapter cannot silently omit a gate.
func NativeRequiredChecks() []string { return append([]string(nil), nativeRequiredChecks...) }

// CodexRequiredChecks returns the complete transport-specific Coding Plan
// Codex matrix. Keeping this exported prevents the live CLI adapter from
// re-declaring a potentially incomplete gate list.
func CodexRequiredChecks() []string { return append([]string(nil), codexRequiredChecks...) }

// CodexCapacityRecoveryAuthorizationRequiredChecks returns the one-shot
// legacy authorization matrix. These records are stored separately and never
// qualify a runtime.
func CodexCapacityRecoveryAuthorizationRequiredChecks() []string {
	return append([]string(nil), codexCapacityRecoveryAuthorizationRequiredChecks...)
}

// CodexIdentityPreflightRequiredChecks returns the narrow, non-qualifying
// preflight matrix. A passed preflight never substitutes for the complete
// zai_codex_runtime qualification matrix.
func CodexIdentityPreflightRequiredChecks() []string {
	return append([]string(nil), codexIdentityPreflightRequiredChecks...)
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
	r.Attestation = nil
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

// DefaultCodexIdentityPreflightStoreDir is intentionally a sibling of the
// qualification store. This physical separation, together with the distinct
// transport matrix, prevents a paid identity probe from being mistaken for a
// full runtime qualification by callers that load readiness receipts.
func DefaultCodexIdentityPreflightStoreDir() string {
	return filepath.Join(filepath.Dir(DefaultStoreDir()), "provider-codex-identity-preflights")
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
