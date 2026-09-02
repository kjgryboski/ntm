package providerattestation

import (
	"bytes"
	"context"
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

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
