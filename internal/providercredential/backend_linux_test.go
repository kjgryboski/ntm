//go:build linux

package providercredential

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
)

type fakeLinuxSecretService struct {
	collection linuxSecretCollection
	err        error
	closed     bool
}

func (s *fakeLinuxSecretService) DefaultCollection(context.Context) (linuxSecretCollection, error) {
	return s.collection, s.err
}
func (s *fakeLinuxSecretService) Close() error { s.closed = true; return nil }

type fakeLinuxSecretCollection struct {
	items     []linuxSecretItem
	searchErr error
	createErr error
	created   bool
}

func (c *fakeLinuxSecretCollection) Search(context.Context, string) ([]linuxSecretItem, error) {
	return c.items, c.searchErr
}
func (c *fakeLinuxSecretCollection) Create(context.Context, string, []byte) error {
	c.created = true
	return c.createErr
}

type fakeLinuxSecretItem struct {
	secret    []byte
	secretErr error
	deleteErr error
	deleted   bool
}

func (i *fakeLinuxSecretItem) Secret(context.Context) ([]byte, error) {
	return append([]byte(nil), i.secret...), i.secretErr
}
func (i *fakeLinuxSecretItem) Delete(context.Context) error { i.deleted = true; return i.deleteErr }

func TestPersistentCollectionPathRejectsRootAndSessionCollections(t *testing.T) {
	for _, path := range []string{"/", sessionCollection, sessionCollection + "/1", "/wrong/collection/login"} {
		if persistentCollectionPath(path) {
			t.Fatalf("persistentCollectionPath(%q) = true, want false", path)
		}
	}
	if !persistentCollectionPath("/org/freedesktop/secrets/collection/login") {
		t.Fatal("persistent login collection rejected")
	}
}

func TestLinuxBackendFailsClosedBeforeAnyCollectionOperation(t *testing.T) {
	backend := linuxSecretToolBackend{open: func(context.Context) (linuxSecretService, error) {
		return nil, errors.New("locked or session-only collection")
	}}
	if _, err := backend.get(t.Context(), "provider:abc"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("get error = %v, want unavailable", err)
	}
	if err := backend.put(t.Context(), "provider:abc", []byte("secret")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("put error = %v, want unavailable", err)
	}
	if err := backend.delete(t.Context(), "provider:abc"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("delete error = %v, want unavailable", err)
	}
	status, err := backend.status(t.Context(), "provider:abc")
	if err != nil || status != unavailableStatus() {
		t.Fatalf("status = %+v, %v; want unavailable", status, err)
	}
}

func TestLinuxBackendUsesOneValidatedCollectionAndRejectsAmbiguousItems(t *testing.T) {
	first := &fakeLinuxSecretItem{secret: []byte("one")}
	second := &fakeLinuxSecretItem{secret: []byte("two")}
	collection := &fakeLinuxSecretCollection{items: []linuxSecretItem{first, second}}
	service := &fakeLinuxSecretService{collection: collection}
	backend := linuxSecretToolBackend{open: func(context.Context) (linuxSecretService, error) { return service, nil }}
	if _, err := backend.get(t.Context(), "provider:abc"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ambiguous get error = %v, want unavailable", err)
	}
	if err := backend.delete(t.Context(), "provider:abc"); !errors.Is(err, ErrUnavailable) || first.deleted || second.deleted {
		t.Fatalf("ambiguous delete err=%v deleted=%t/%t", err, first.deleted, second.deleted)
	}
	status, err := backend.status(t.Context(), "provider:abc")
	if err != nil || status != unavailableStatus() {
		t.Fatalf("ambiguous status = %+v, %v", status, err)
	}
}

func TestLinuxBackendGetPutDeleteUseValidatedCollection(t *testing.T) {
	item := &fakeLinuxSecretItem{secret: []byte("secret")}
	collection := &fakeLinuxSecretCollection{items: []linuxSecretItem{item}}
	service := &fakeLinuxSecretService{collection: collection}
	backend := linuxSecretToolBackend{open: func(context.Context) (linuxSecretService, error) { return service, nil }}
	got, err := backend.get(t.Context(), "provider:abc")
	if err != nil || string(got) != "secret" {
		t.Fatalf("get = %q, %v", got, err)
	}
	if err := backend.put(t.Context(), "provider:abc", []byte("replacement")); err != nil || !collection.created {
		t.Fatalf("put err=%v created=%t", err, collection.created)
	}
	if err := backend.delete(t.Context(), "provider:abc"); err != nil || !item.deleted {
		t.Fatalf("delete err=%v deleted=%t", err, item.deleted)
	}
	if !service.closed {
		t.Fatal("service connection was not closed")
	}
}

func TestWSLWindowsBridgeFallbackIsReadOnlyAndNonceBound(t *testing.T) {
	calls := make([]windowsCredentialBridgeRequest, 0, 2)
	backend := newLinuxSecretToolBackend(func(context.Context) (linuxSecretService, error) {
		return nil, ErrUnavailable
	}, true, "/mnt/c/ntm-provider-bridge.exe", func(_ context.Context, _ string, request windowsCredentialBridgeRequest) (windowsCredentialBridgeResponse, error) {
		calls = append(calls, request)
		if !windowsBridgeNonce.MatchString(request.Nonce) || request.CredentialID != "provider:abc" {
			t.Fatalf("invalid bridge request: %+v", request)
		}
		switch request.Operation {
		case "credential_get":
			return windowsCredentialBridgeResponse{Nonce: request.Nonce, Credential: base64.RawURLEncoding.EncodeToString([]byte("secret"))}, nil
		case "credential_status":
			return windowsCredentialBridgeResponse{Nonce: request.Nonce, Status: &Status{Backend: BackendWindowsCredentialManager, Available: true, Present: true, Evidence: EvidenceOSProtectedProcessReadable}}, nil
		default:
			return windowsCredentialBridgeResponse{}, errors.New("unexpected operation")
		}
	})
	secret, err := backend.get(t.Context(), "provider:abc")
	if err != nil || string(secret) != "secret" {
		t.Fatalf("bridge get = %q, %v", secret, err)
	}
	status, err := backend.status(t.Context(), "provider:abc")
	if err != nil || !status.Available || !status.Present || status.Backend != BackendWindowsCredentialManager {
		t.Fatalf("bridge status = %+v, %v", status, err)
	}
	if err := backend.put(t.Context(), "provider:abc", []byte("new")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("bridge-backed put error = %v, want unavailable", err)
	}
	if err := backend.delete(t.Context(), "provider:abc"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("bridge-backed delete error = %v, want unavailable", err)
	}
	if len(calls) != 2 || calls[0].Operation != "credential_get" || calls[1].Operation != "credential_status" {
		t.Fatalf("bridge calls = %+v", calls)
	}
}

func TestWSLWindowsBridgeFallsBackAfterExactDirectMiss(t *testing.T) {
	collection := &fakeLinuxSecretCollection{}
	service := &fakeLinuxSecretService{collection: collection}
	calls := 0
	backend := newLinuxSecretToolBackend(func(context.Context) (linuxSecretService, error) {
		return service, nil
	}, true, "/mnt/c/ntm-provider-bridge.exe", func(_ context.Context, _ string, request windowsCredentialBridgeRequest) (windowsCredentialBridgeResponse, error) {
		calls++
		switch request.Operation {
		case "credential_get":
			return windowsCredentialBridgeResponse{Nonce: request.Nonce, Credential: base64.RawURLEncoding.EncodeToString([]byte("windows-secret"))}, nil
		case "credential_status":
			return windowsCredentialBridgeResponse{Nonce: request.Nonce, Status: &Status{Backend: BackendWindowsCredentialManager, Available: true, Present: true, Evidence: EvidenceOSProtectedProcessReadable}}, nil
		default:
			return windowsCredentialBridgeResponse{}, errors.New("unexpected operation")
		}
	})
	secret, err := backend.get(t.Context(), "provider:abc")
	if err != nil || string(secret) != "windows-secret" {
		t.Fatalf("secret=%q err=%v", secret, err)
	}
	status, err := backend.status(t.Context(), "provider:abc")
	if err != nil || status.Backend != BackendWindowsCredentialManager || !status.Present {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestWSLWindowsBridgeNeverMasksDirectAmbiguityOrReadFailure(t *testing.T) {
	for name, collection := range map[string]*fakeLinuxSecretCollection{
		"duplicate":    {items: []linuxSecretItem{&fakeLinuxSecretItem{secret: []byte("one")}, &fakeLinuxSecretItem{secret: []byte("two")}}},
		"search error": {searchErr: errors.New("Secret Service search failed")},
		"secret error": {items: []linuxSecretItem{&fakeLinuxSecretItem{secretErr: errors.New("Secret Service read failed")}}},
	} {
		t.Run(name, func(t *testing.T) {
			called := false
			backend := newLinuxSecretToolBackend(func(context.Context) (linuxSecretService, error) {
				return &fakeLinuxSecretService{collection: collection}, nil
			}, true, "/mnt/c/ntm-provider-bridge.exe", func(context.Context, string, windowsCredentialBridgeRequest) (windowsCredentialBridgeResponse, error) {
				called = true
				return windowsCredentialBridgeResponse{}, nil
			})
			if _, err := backend.get(t.Context(), "provider:abc"); !errors.Is(err, ErrUnavailable) || called {
				t.Fatalf("get err=%v bridge_called=%t", err, called)
			}
			if _, err := backend.status(t.Context(), "provider:abc"); err != nil || called {
				t.Fatalf("status err=%v bridge_called=%t", err, called)
			}
		})
	}
}

func TestWindowsBridgeRejectsMismatchedNonceAndIsNeverEnabledOffWSL(t *testing.T) {
	called := false
	backend := newLinuxSecretToolBackend(func(context.Context) (linuxSecretService, error) {
		return nil, ErrUnavailable
	}, true, "/mnt/c/ntm-provider-bridge.exe", func(_ context.Context, _ string, request windowsCredentialBridgeRequest) (windowsCredentialBridgeResponse, error) {
		called = true
		return windowsCredentialBridgeResponse{Nonce: request.Nonce + "x", Credential: base64.RawURLEncoding.EncodeToString([]byte("secret"))}, nil
	})
	if _, err := backend.get(t.Context(), "provider:abc"); !errors.Is(err, ErrUnavailable) || !called {
		t.Fatalf("mismatched nonce err=%v called=%t", err, called)
	}
	called = false
	notWSL := newLinuxSecretToolBackend(func(context.Context) (linuxSecretService, error) {
		return nil, ErrUnavailable
	}, false, "/mnt/c/ntm-provider-bridge.exe", func(context.Context, string, windowsCredentialBridgeRequest) (windowsCredentialBridgeResponse, error) {
		called = true
		return windowsCredentialBridgeResponse{}, nil
	})
	if _, err := notWSL.get(t.Context(), "provider:abc"); !errors.Is(err, ErrUnavailable) || called {
		t.Fatalf("non-WSL bridge err=%v called=%t", err, called)
	}
}
