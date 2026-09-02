package providercredential

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Dicklesworthstone/ntm/internal/provider"
)

type backendFake struct {
	calls    int
	snapshot Status
	secret   []byte
}

func (b *backendFake) get(_ context.Context, _ string) ([]byte, error) {
	b.calls++
	return append([]byte(nil), b.secret...), nil
}
func (b *backendFake) put(_ context.Context, _ string, secret []byte) error {
	b.calls++
	if len(secret) == 0 {
		return ErrInvalidSecret
	}
	return nil
}
func (b *backendFake) delete(_ context.Context, _ string) error { b.calls++; return nil }
func (b *backendFake) status(_ context.Context, _ string) (Status, error) {
	b.calls++
	return b.snapshot, nil
}

func TestBrokerRejectsInvalidIdentifiersBeforeTouchingBackend(t *testing.T) {
	fake := &backendFake{}
	b := &Broker{backend: fake}
	for _, id := range []string{"", "UPPER", "contains space", "line\nbreak"} {
		if _, err := b.Get(t.Context(), id); !errors.Is(err, ErrInvalidID) {
			t.Fatalf("Get(%q) error = %v, want invalid ID", id, err)
		}
	}
	if err := b.Put(t.Context(), "provider:abc", nil); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("Put empty secret error = %v, want invalid secret", err)
	}
	if fake.calls != 0 {
		t.Fatalf("backend called for invalid input: %d", fake.calls)
	}
}

func TestBrokerStatusIsReceiptSafe(t *testing.T) {
	fake := &backendFake{snapshot: Status{
		Backend: BackendWindowsCredentialManager, Available: true, Present: true, Evidence: EvidenceOSProtectedProcessReadable,
	}}
	status, err := (&Broker{backend: fake}).Status(t.Context(), "provider:abc")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"backend":"windows_credential_manager","available":true,"present":true,"evidence":"os_protected_process_readable"}` {
		t.Fatalf("unexpected or non-redacted status JSON: %s", encoded)
	}
}

func TestBrokerReturnsUnavailableWithoutFallback(t *testing.T) {
	b := &Broker{backend: unavailableBackend{snapshot: unavailableStatus()}}
	if _, err := b.Get(t.Context(), "provider:abc"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Get error = %v, want unavailable", err)
	}
	if err := b.Put(t.Context(), "provider:abc", []byte("secret")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Put error = %v, want unavailable", err)
	}
	status, err := b.Status(t.Context(), "provider:abc")
	if err != nil || status != unavailableStatus() {
		t.Fatalf("status = %+v, %v", status, err)
	}
}

func TestCanonicalIDBindsTheCompleteProviderIdentity(t *testing.T) {
	identity, err := provider.NewIdentityWithAuthorization("zai", "account", "model", "https://api.z.ai/api/paas/v4/chat/completions", "zai-api", provider.CredentialClassAPIKey, provider.BillingClassAPIUsage, provider.EntitlementNativeAPI, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	want := "ntm.zai.native_api." + identity.Hash()
	if got := CanonicalID(identity); got != want {
		t.Fatalf("CanonicalID=%q want=%q", got, want)
	}
}
