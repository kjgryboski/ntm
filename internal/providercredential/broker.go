// Package providercredential brokers provider credentials through native OS
// secure storage. It deliberately has no environment-variable fallback.
package providercredential

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

var (
	// ErrUnavailable means the current platform has no safe, noninteractive
	// native credential store available. Callers must not fall back to an
	// environment variable or a plaintext file.
	ErrUnavailable = errors.New("provider credential broker is unavailable")
	// ErrNotFound means the native store was available but held no credential
	// for the requested identifier.
	ErrNotFound      = errors.New("provider credential was not found")
	ErrInvalidID     = errors.New("provider credential identifier is invalid")
	ErrInvalidSecret = errors.New("provider credential secret is invalid")
)

const maxSecretBytes = 64 << 10

var credentialIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)

// EvidenceGrade describes the security boundary of a successful native-store
// operation. OSProtectedProcessReadable is deliberately not described as
// hardware-backed or non-exportable: a process running as the user can obtain
// a credential through Get.
type EvidenceGrade string

const (
	EvidenceUnavailable                EvidenceGrade = "unavailable"
	EvidenceOSProtectedProcessReadable EvidenceGrade = "os_protected_process_readable"
)

// Backend identifies the native store, not a credential value or location.
type Backend string

const (
	BackendUnavailable              Backend = "unavailable"
	BackendWindowsCredentialManager Backend = "windows_credential_manager"
	BackendLinuxSecretTool          Backend = "linux_secret_tool"
	BackendMacOSKeychain            Backend = "macos_keychain"
)

// Status is intentionally secret-free and receipt-safe. Present is meaningful
// only when Available is true.
type Status struct {
	Backend   Backend       `json:"backend"`
	Available bool          `json:"available"`
	Present   bool          `json:"present"`
	Evidence  EvidenceGrade `json:"evidence"`
}

type backend interface {
	get(context.Context, string) ([]byte, error)
	put(context.Context, string, []byte) error
	delete(context.Context, string) error
	status(context.Context, string) (Status, error)
}

// Broker has no persistent secret fields. Get returns a credential only to the
// immediate caller; callers must avoid logging it or embedding it in receipts.
type Broker struct{ backend backend }

type unavailableBackend struct{ snapshot Status }

func (b unavailableBackend) get(_ context.Context, _ string) ([]byte, error) {
	return nil, ErrUnavailable
}
func (b unavailableBackend) put(_ context.Context, _ string, _ []byte) error { return ErrUnavailable }
func (b unavailableBackend) delete(_ context.Context, _ string) error        { return ErrUnavailable }
func (b unavailableBackend) status(_ context.Context, _ string) (Status, error) {
	return b.snapshot, nil
}

// New returns a broker for the current OS. It is always safe to construct; a
// missing native dependency is reported by operations as ErrUnavailable.
func New() *Broker { return &Broker{backend: newNativeBackend()} }

func (b *Broker) Get(ctx context.Context, id string) ([]byte, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}
	if b == nil || b.backend == nil {
		return nil, ErrUnavailable
	}
	secret, err := b.backend.get(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := validateSecret(secret); err != nil {
		return nil, fmt.Errorf("native store returned invalid credential: %w", err)
	}
	return secret, nil
}

func (b *Broker) Put(ctx context.Context, id string, secret []byte) error {
	if err := validateID(id); err != nil {
		return err
	}
	if err := validateSecret(secret); err != nil {
		return err
	}
	if b == nil || b.backend == nil {
		return ErrUnavailable
	}
	return b.backend.put(ctx, id, secret)
}

func (b *Broker) Delete(ctx context.Context, id string) error {
	if err := validateID(id); err != nil {
		return err
	}
	if b == nil || b.backend == nil {
		return ErrUnavailable
	}
	return b.backend.delete(ctx, id)
}

func (b *Broker) Status(ctx context.Context, id string) (Status, error) {
	if err := validateID(id); err != nil {
		return Status{}, err
	}
	if b == nil || b.backend == nil {
		return unavailableStatus(), nil
	}
	return b.backend.status(ctx, id)
}

func validateID(id string) error {
	if !credentialIDPattern.MatchString(id) {
		return ErrInvalidID
	}
	return nil
}

func validateSecret(secret []byte) error {
	if len(secret) == 0 || len(secret) > maxSecretBytes {
		return ErrInvalidSecret
	}
	return nil
}

func unavailableStatus() Status {
	return Status{Backend: BackendUnavailable, Available: false, Present: false, Evidence: EvidenceUnavailable}
}
