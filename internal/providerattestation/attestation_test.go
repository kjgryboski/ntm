package providerattestation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Dicklesworthstone/ntm/internal/providercredential"
)

type memoryStore struct {
	values map[string][]byte
	status providercredential.Status
	getErr error
	putErr error
	gets   int
	puts   int
}

func (m *memoryStore) Get(_ context.Context, id string) ([]byte, error) {
	m.gets++
	if m.getErr != nil {
		return nil, m.getErr
	}
	value, ok := m.values[id]
	if !ok {
		return nil, providercredential.ErrNotFound
	}
	return append([]byte(nil), value...), nil
}
func (m *memoryStore) Put(_ context.Context, id string, value []byte) error {
	m.puts++
	if m.putErr != nil {
		return m.putErr
	}
	if m.values == nil {
		m.values = make(map[string][]byte)
	}
	m.values[id] = append([]byte(nil), value...)
	return nil
}
func (m *memoryStore) Status(context.Context, string) (providercredential.Status, error) {
	return m.status, nil
}

func protectedStore() *memoryStore {
	return &memoryStore{values: make(map[string][]byte), status: providercredential.Status{Backend: providercredential.BackendWindowsCredentialManager, Available: true, Evidence: providercredential.EvidenceOSProtectedProcessReadable}}
}

func newTestAttestor(t *testing.T, store CredentialStore) *Attestor {
	t.Helper()
	attestor, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	return attestor
}

func TestEnsureKeyCreatesOnceAndReturnsOnlyPublicMetadata(t *testing.T) {
	store := protectedStore()
	attestor := newTestAttestor(t, store)
	seedMaterial := bytes.Repeat([]byte("s"), 64)
	attestor.random = bytes.NewReader(seedMaterial)

	first, err := attestor.EnsureKey(t.Context(), "grok.primary")
	if err != nil {
		t.Fatal(err)
	}
	second, err := attestor.EnsureKey(t.Context(), "grok.primary")
	if err != nil {
		t.Fatal(err)
	}
	if first != second || store.puts != 1 || store.gets != 3 || first.Algorithm != AlgorithmEd25519 || first.ProtectionEvidence != ProtectionOSProcessRead || first.KeyID == "" || first.PublicKeySHA256 == "" || first.PublicKey == "" {
		t.Fatalf("unexpected ensure metadata=%+v puts=%d gets=%d", first, store.puts, store.gets)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, bytes.Repeat([]byte("s"), 8)) || bytes.Contains(encoded, []byte(storageID("grok.primary"))) {
		t.Fatalf("public metadata leaked seed or storage identifier: %s", encoded)
	}
}

func TestSignRequiresExplicitEnsureThenVerifiesTamperEvidently(t *testing.T) {
	store := protectedStore()
	attestor := newTestAttestor(t, store)
	payload := []byte(`{"identity_sha256":"abc","receipt":"completed"}`)
	if _, err := attestor.Sign(t.Context(), "zai.native", payload); !errors.Is(err, ErrKeyNotInitialized) {
		t.Fatalf("implicit sign creation error=%v", err)
	}
	if _, err := attestor.EnsureKey(t.Context(), "zai.native"); err != nil {
		t.Fatal(err)
	}
	signature, err := attestor.Sign(t.Context(), "zai.native", payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(payload, signature); err != nil {
		t.Fatalf("verify signed payload: %v", err)
	}
	if err := Verify([]byte(`{"identity_sha256":"changed","receipt":"completed"}`), signature); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("payload tamper verify error=%v", err)
	}
	tampered := signature
	first := "A"
	if strings.HasPrefix(tampered.Signature, first) {
		first = "B"
	}
	tampered.Signature = first + tampered.Signature[1:]
	if err := Verify(payload, tampered); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("signature tamper verify error=%v", err)
	}
	tampered = signature
	tampered.PublicKeySHA256 = "00" + tampered.PublicKeySHA256[2:]
	if err := Verify(payload, tampered); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("public digest tamper verify error=%v", err)
	}
}

func TestAttestorFailsClosedOnProtectionOrStoredKeyProblems(t *testing.T) {
	t.Run("unprotected store", func(t *testing.T) {
		store := protectedStore()
		store.status.Evidence = providercredential.EvidenceUnavailable
		if _, err := newTestAttestor(t, store).EnsureKey(t.Context(), "grok.primary"); !errors.Is(err, ErrProtectionUnavailable) || store.puts != 0 {
			t.Fatalf("error=%v puts=%d", err, store.puts)
		}
	})
	t.Run("invalid stored seed", func(t *testing.T) {
		store := protectedStore()
		store.values[storageID("grok.primary")] = []byte("not-a-seed")
		if _, err := newTestAttestor(t, store).EnsureKey(t.Context(), "grok.primary"); err == nil {
			t.Fatal("invalid seed accepted")
		}
	})
	t.Run("storage failure is redacted", func(t *testing.T) {
		store := protectedStore()
		store.getErr = errors.New("secret=do-not-leak")
		_, err := newTestAttestor(t, store).EnsureKey(t.Context(), "grok.primary")
		if err == nil || bytes.Contains([]byte(err.Error()), []byte("do-not-leak")) {
			t.Fatalf("store error leaked: %v", err)
		}
	})
	for _, name := range []string{"", "UPPER", "contains space", "newline\n"} {
		if _, err := newTestAttestor(t, protectedStore()).EnsureKey(t.Context(), name); !errors.Is(err, ErrInvalidKeyName) {
			t.Fatalf("EnsureKey(%q) error=%v", name, err)
		}
	}
}

func TestSignatureMetadataNeverSerializesPrivateSeedAndVerifyNeedsNoStore(t *testing.T) {
	store := protectedStore()
	attestor := newTestAttestor(t, store)
	seed := bytes.Repeat([]byte{0x7f}, 32)
	attestor.random = bytes.NewReader(seed)
	if _, err := attestor.EnsureKey(t.Context(), "grok.primary"); err != nil {
		t.Fatal(err)
	}
	payload := []byte("canonical-v1\x00receipt")
	signature, err := attestor.Sign(t.Context(), "grok.primary", payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(signature)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, seed) || bytes.Contains(encoded, []byte(storageID("grok.primary"))) || bytes.Contains(encoded, payload) {
		t.Fatalf("signature metadata leaked private or payload data: %s", encoded)
	}
	if err := Verify(payload, signature); err != nil {
		t.Fatalf("offline verify failed: %v", err)
	}
}

func TestEnsureKeyRandomFailureAndInputLimits(t *testing.T) {
	attestor := newTestAttestor(t, protectedStore())
	attestor.random = failingReader{}
	if _, err := attestor.EnsureKey(t.Context(), "grok.primary"); err == nil {
		t.Fatal("random failure accepted")
	}
	if _, err := attestor.Sign(t.Context(), "grok.primary", nil); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("empty payload error=%v", err)
	}
	tooLarge := make([]byte, maxCanonicalPayload+1)
	if _, err := attestor.Sign(t.Context(), "grok.primary", tooLarge); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("large payload error=%v", err)
	}
}

type fakeHardwareSigner struct {
	private *ecdsa.PrivateKey
	ensures int
	signs   int
}

func (s *fakeHardwareSigner) EnsureKey(_ context.Context, _ string) (KeyMetadata, error) {
	s.ensures++
	der, err := x509.MarshalPKIXPublicKey(&s.private.PublicKey)
	if err != nil {
		return KeyMetadata{}, err
	}
	return KeyMetadata{Algorithm: AlgorithmECDSAP256SHA256, KeyID: "ecdsa-p256:" + digest(der), PublicKey: base64.RawURLEncoding.EncodeToString(der), PublicKeySHA256: digest(der), ProtectionEvidence: ProtectionHardwareNoExportLocalController}, nil
}

func TestTPMKeyPropertiesRequireExactLocalControllerPolicy(t *testing.T) {
	valid := tpmKeyProperties{Algorithm: ncryptECDSAP256Algorithm, ExportPolicy: 0, KeyUsage: ncryptAllowSigning}
	if err := validateTPMKeyProperties(valid); err != nil {
		t.Fatalf("valid properties rejected: %v", err)
	}
	platformReported := valid
	platformReported.Algorithm = ncryptECDSAAlgorithm
	if err := validateTPMKeyProperties(platformReported); err != nil {
		t.Fatalf("platform-reported ECDSA family rejected: %v", err)
	}
	for name, altered := range map[string]tpmKeyProperties{
		"algorithm":     {Algorithm: "RSA", ExportPolicy: 0, KeyUsage: ncryptAllowSigning},
		"export policy": {Algorithm: ncryptECDSAP256Algorithm, ExportPolicy: 1, KeyUsage: ncryptAllowSigning},
		"key usage":     {Algorithm: ncryptECDSAP256Algorithm, ExportPolicy: 0, KeyUsage: ncryptAllowSigning | 4},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateTPMKeyProperties(altered); !errors.Is(err, ErrProtectionPolicy) {
				t.Fatalf("properties=%+v error=%v", altered, err)
			}
		})
	}
	if err := validateTPMProviderName(msPlatformCryptoProvider); err != nil {
		t.Fatalf("platform provider rejected: %v", err)
	}
	if err := validateTPMProviderName("Microsoft Software Key Storage Provider"); !errors.Is(err, ErrProtectionPolicy) {
		t.Fatalf("software provider accepted: %v", err)
	}
}

func (s *fakeHardwareSigner) Sign(_ context.Context, _ string, payload []byte) (SignatureMetadata, error) {
	s.signs++
	metadata, err := s.EnsureKey(context.Background(), "test")
	if err != nil {
		return SignatureMetadata{}, err
	}
	hash := sha256.Sum256(payload)
	r, ss, err := ecdsa.Sign(rand.Reader, s.private, hash[:])
	if err != nil {
		return SignatureMetadata{}, err
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	ss.FillBytes(raw[32:])
	return SignatureMetadata{KeyMetadata: metadata, PayloadSHA256: digest(payload), Signature: base64.RawURLEncoding.EncodeToString(raw)}, nil
}

func TestHardwareSignerUsesECDSAP256VerificationWithoutSeedStore(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hardware := &fakeHardwareSigner{private: private}
	attestor := &Attestor{hardware: hardware}
	if metadata, err := attestor.EnsureKey(t.Context(), "zai.native"); err != nil || metadata.ProtectionEvidence != ProtectionHardwareNoExportLocalController || metadata.Algorithm != AlgorithmECDSAP256SHA256 {
		t.Fatalf("EnsureKey metadata=%+v err=%v", metadata, err)
	}
	payload := []byte("canonical TPM-backed receipt")
	signature, err := attestor.Sign(t.Context(), "zai.native", payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(payload, signature); err != nil {
		t.Fatalf("hardware receipt verification failed: %v", err)
	}
	if hardware.ensures == 0 || hardware.signs != 1 {
		t.Fatalf("ensure=%d sign=%d", hardware.ensures, hardware.signs)
	}
	signature.ProtectionEvidence = ProtectionOSProcessRead
	if err := Verify(payload, signature); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("weaker protection evidence accepted: %v", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
