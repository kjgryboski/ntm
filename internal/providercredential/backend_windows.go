//go:build windows

package providercredential

import (
	"context"
	"errors"
	"syscall"
	"unsafe"
)

const credTypeGeneric = 1
const credPersistLocalMachine = 2

var advapi32 = syscall.NewLazyDLL("advapi32.dll")
var procCredReadW = advapi32.NewProc("CredReadW")
var procCredWriteW = advapi32.NewProc("CredWriteW")
var procCredDeleteW = advapi32.NewProc("CredDeleteW")
var procCredFree = advapi32.NewProc("CredFree")

// credentialW is the documented CREDENTIALW layout used by Credential
// Manager. CredentialBlob points only at the short-lived input/output buffer.
type credentialW struct {
	flags              uint32
	typ                uint32
	targetName         *uint16
	comment            *uint16
	lastWrittenLow     uint32
	lastWrittenHigh    uint32
	credentialBlobSize uint32
	credentialBlob     *byte
	persist            uint32
	attributeCount     uint32
	attributes         uintptr
	targetAlias        *uint16
	userName           *uint16
}

type windowsCredentialBackend struct{}

func newNativeBackend() backend { return windowsCredentialBackend{} }

func (windowsCredentialBackend) get(ctx context.Context, id string) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	target, err := syscall.UTF16PtrFromString(windowsTarget(id))
	if err != nil {
		return nil, ErrUnavailable
	}
	var credential *credentialW
	r1, _, callErr := procCredReadW.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0, uintptr(unsafe.Pointer(&credential)))
	if r1 == 0 {
		if errors.Is(callErr, syscall.ERROR_NOT_FOUND) {
			return nil, ErrNotFound
		}
		return nil, ErrUnavailable
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(credential)))
	if credential == nil || credential.credentialBlob == nil || credential.credentialBlobSize == 0 || credential.credentialBlobSize > maxSecretBytes {
		return nil, ErrUnavailable
	}
	secret := make([]byte, credential.credentialBlobSize)
	copy(secret, unsafe.Slice(credential.credentialBlob, credential.credentialBlobSize))
	return secret, nil
}

func (windowsCredentialBackend) put(ctx context.Context, id string, secret []byte) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	target, err := syscall.UTF16PtrFromString(windowsTarget(id))
	if err != nil {
		return ErrUnavailable
	}
	credential := credentialW{
		typ:                credTypeGeneric,
		targetName:         target,
		credentialBlobSize: uint32(len(secret)),
		credentialBlob:     &secret[0],
		persist:            credPersistLocalMachine,
	}
	r1, _, _ := procCredWriteW.Call(uintptr(unsafe.Pointer(&credential)), 0)
	if r1 == 0 {
		return ErrUnavailable
	}
	return nil
}

func (windowsCredentialBackend) delete(ctx context.Context, id string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	target, err := syscall.UTF16PtrFromString(windowsTarget(id))
	if err != nil {
		return ErrUnavailable
	}
	r1, _, callErr := procCredDeleteW.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0)
	if r1 == 0 {
		if errors.Is(callErr, syscall.ERROR_NOT_FOUND) {
			return ErrNotFound
		}
		return ErrUnavailable
	}
	return nil
}

func (b windowsCredentialBackend) status(ctx context.Context, id string) (Status, error) {
	secret, err := b.get(ctx, id)
	clearSecret(secret)
	status := Status{Backend: BackendWindowsCredentialManager, Available: true, Evidence: EvidenceOSProtectedProcessReadable}
	if err == nil {
		status.Present = true
		return status, nil
	}
	if errors.Is(err, ErrNotFound) {
		return status, nil
	}
	return unavailableStatus(), nil
}

func windowsTarget(id string) string { return "NTM/provider-credential/v1/" + id }

func contextError(ctx context.Context) error {
	if ctx == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func clearSecret(secret []byte) {
	for i := range secret {
		secret[i] = 0
	}
}
