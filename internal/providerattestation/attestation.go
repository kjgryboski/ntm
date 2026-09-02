// Package providerattestation creates tamper-evident, redaction-safe
// signatures for provider receipts. Private signing seeds live only in the OS
// credential broker and are deliberately never fields of a receipt.
package providerattestation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/Dicklesworthstone/ntm/internal/providercredential"
)

const (
	AlgorithmEd25519        = "ed25519"
	ProtectionOSProcessRead = providercredential.EvidenceOSProtectedProcessReadable
	maxCanonicalPayload     = 4 << 20
)

var (
	ErrInvalidKeyName        = errors.New("provider attestation key name is invalid")
	ErrInvalidPayload        = errors.New("provider attestation payload is invalid")
	ErrKeyNotInitialized     = errors.New("provider attestation key is not initialized; call EnsureKey explicitly")
	ErrInvalidSignature      = errors.New("provider attestation signature is invalid")
	ErrProtectionUnavailable = errors.New("provider attestation requires os_protected_process_readable storage")
	keyNamePattern           = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
)

// CredentialStore is the small, testable surface needed from the OS-backed
// provider credential broker. Implementations must not provide plaintext-file
// or environment-variable fallback.
type CredentialStore interface {
	Get(context.Context, string) ([]byte, error)
	Put(context.Context, string, []byte) error
	Status(context.Context, string) (providercredential.Status, error)
}

// BrokerStore adapts the native provider credential broker for normal use.
// The broker retains no secret fields; neither does Attestor.
type BrokerStore struct{ Broker *providercredential.Broker }

func (s BrokerStore) Get(ctx context.Context, id string) ([]byte, error) {
	if s.Broker == nil {
		return nil, providercredential.ErrUnavailable
	}
	return s.Broker.Get(ctx, id)
}
func (s BrokerStore) Put(ctx context.Context, id string, value []byte) error {
	if s.Broker == nil {
		return providercredential.ErrUnavailable
	}
	return s.Broker.Put(ctx, id, value)
}
func (s BrokerStore) Status(ctx context.Context, id string) (providercredential.Status, error) {
	if s.Broker == nil {
		return providercredential.Status{}, providercredential.ErrUnavailable
	}
	return s.Broker.Status(ctx, id)
}

// Attestor uses a CredentialStore only while ensuring or signing.  It never
// retains a seed or private key after the method returns.
type Attestor struct {
	store  CredentialStore
	random io.Reader
}

func New(store CredentialStore) (*Attestor, error) {
	if store == nil {
		return nil, ErrProtectionUnavailable
	}
	return &Attestor{store: store, random: rand.Reader}, nil
}

// NewOSProtected constructs an attestor backed by providercredential's native
// OS store. It is intentionally not described as hardware-backed or
// non-exportable: a process running as the current user can read the seed.
func NewOSProtected() *Attestor {
	attestor, _ := New(BrokerStore{Broker: providercredential.New()})
	return attestor
}

// KeyMetadata is safe to persist with a receipt.  PublicKey is intentionally
// included so another process can verify without reading the OS store; it is a
// public Ed25519 key, never a seed or private key.
type KeyMetadata struct {
	Algorithm          string                           `json:"algorithm"`
	KeyID              string                           `json:"key_id"`
	PublicKey          string                           `json:"public_key"`
	PublicKeySHA256    string                           `json:"public_key_sha256"`
	ProtectionEvidence providercredential.EvidenceGrade `json:"protection_evidence"`
}

// SignatureMetadata is the complete public verification envelope for canonical
// payload bytes. It contains no credential-store identifier or private key.
type SignatureMetadata struct {
	KeyMetadata
	PayloadSHA256 string `json:"payload_sha256"`
	Signature     string `json:"signature"`
}

// EnsureKey is the only operation allowed to create a signing seed. It first
// verifies that the configured store is available and OS-protected, then
// obtains an existing seed or generates and stores a fresh Ed25519 seed.
func (a *Attestor) EnsureKey(ctx context.Context, name string) (KeyMetadata, error) {
	if err := validateInput(ctx, name, nil, false); err != nil {
		return KeyMetadata{}, err
	}
	id := storageID(name)
	if err := a.requireProtection(ctx, id); err != nil {
		return KeyMetadata{}, err
	}
	seed, err := a.store.Get(ctx, id)
	if errors.Is(err, providercredential.ErrNotFound) {
		seed = make([]byte, ed25519.SeedSize)
		if _, randomErr := io.ReadFull(a.random, seed); randomErr != nil {
			zero(seed)
			return KeyMetadata{}, errors.New("provider attestation key generation failed")
		}
		if putErr := a.store.Put(ctx, id, seed); putErr != nil {
			zero(seed)
			return KeyMetadata{}, safeStoreError(putErr)
		}
		// Read back after Put: this avoids returning metadata for a seed that a
		// racing or faulty store did not durably retain.
		zero(seed)
		seed, err = a.store.Get(ctx, id)
	}
	if err != nil {
		return KeyMetadata{}, safeStoreError(err)
	}
	defer zero(seed)
	if len(seed) != ed25519.SeedSize {
		return KeyMetadata{}, errors.New("provider attestation stored key is invalid")
	}
	return metadataForSeed(seed), nil
}

// Sign signs pre-canonicalized payload bytes with an explicitly initialized
// key. It never creates a key implicitly; callers must use EnsureKey during an
// explicit setup action rather than surprise-generating key material on a run.
func (a *Attestor) Sign(ctx context.Context, name string, canonicalPayload []byte) (SignatureMetadata, error) {
	if err := validateInput(ctx, name, canonicalPayload, true); err != nil {
		return SignatureMetadata{}, err
	}
	id := storageID(name)
	if err := a.requireProtection(ctx, id); err != nil {
		return SignatureMetadata{}, err
	}
	seed, err := a.store.Get(ctx, id)
	if errors.Is(err, providercredential.ErrNotFound) {
		return SignatureMetadata{}, ErrKeyNotInitialized
	}
	if err != nil {
		return SignatureMetadata{}, safeStoreError(err)
	}
	defer zero(seed)
	if len(seed) != ed25519.SeedSize {
		return SignatureMetadata{}, errors.New("provider attestation stored key is invalid")
	}
	private := ed25519.NewKeyFromSeed(seed)
	defer zero(private)
	metadata := metadataForSeed(seed)
	return SignatureMetadata{KeyMetadata: metadata, PayloadSHA256: digest(canonicalPayload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, canonicalPayload))}, nil
}

// Verify checks the canonical bytes against self-contained public metadata; it
// does not contact the credential store and therefore can run on a verifier
// host that has never had access to the signing seed.
func Verify(canonicalPayload []byte, signature SignatureMetadata) error {
	if len(canonicalPayload) == 0 || len(canonicalPayload) > maxCanonicalPayload || signature.Algorithm != AlgorithmEd25519 || signature.ProtectionEvidence != ProtectionOSProcessRead || signature.PayloadSHA256 != digest(canonicalPayload) {
		return ErrInvalidSignature
	}
	public, err := base64.RawURLEncoding.DecodeString(signature.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize || digest(public) != signature.PublicKeySHA256 || signature.KeyID != keyID(public) {
		return ErrInvalidSignature
	}
	encoded, err := base64.RawURLEncoding.DecodeString(signature.Signature)
	if err != nil || len(encoded) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(public), canonicalPayload, encoded) {
		return ErrInvalidSignature
	}
	return nil
}

func (a *Attestor) requireProtection(ctx context.Context, id string) error {
	if a == nil || a.store == nil {
		return ErrProtectionUnavailable
	}
	status, err := a.store.Status(ctx, id)
	if err != nil || !status.Available || status.Evidence != ProtectionOSProcessRead {
		return ErrProtectionUnavailable
	}
	return nil
}

func validateInput(ctx context.Context, name string, payload []byte, requirePayload bool) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrProtectionUnavailable
	}
	if !keyNamePattern.MatchString(name) {
		return ErrInvalidKeyName
	}
	if requirePayload && (len(payload) == 0 || len(payload) > maxCanonicalPayload) {
		return ErrInvalidPayload
	}
	return nil
}

func metadataForSeed(seed []byte) KeyMetadata {
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	defer zero(private)
	return KeyMetadata{Algorithm: AlgorithmEd25519, KeyID: keyID(public), PublicKey: base64.RawURLEncoding.EncodeToString(public), PublicKeySHA256: digest(public), ProtectionEvidence: ProtectionOSProcessRead}
}

func storageID(name string) string { return "provider-attestation:" + digest([]byte(name)) }
func keyID(public []byte) string   { return "ed25519:" + digest(public) }
func digest(value []byte) string   { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func safeStoreError(err error) error {
	if errors.Is(err, providercredential.ErrUnavailable) {
		return ErrProtectionUnavailable
	}
	return fmt.Errorf("provider attestation key store operation failed")
}
