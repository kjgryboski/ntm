//go:build windows

package providerattestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"github.com/Dicklesworthstone/ntm/internal/providercredential"
)

// CNG's Microsoft Platform Crypto Provider is the Windows TPM key storage
// provider. Unlike the credential-manager path, it never returns private key
// bytes to this package.
const (
	ncryptECCPublicBlob = "ECCPUBLICBLOB"
	ncryptExportPolicy  = "Export Policy"
	ncryptKeyUsage      = "Key Usage"
	ncryptAlgorithmName = "Algorithm Name"
	ncryptObjectName    = "Name"
	nteBadKeyset        = uintptr(0x80090016)
	eccPublicP256Magic  = uint32(0x31534345) // BCRYPT_ECDSA_PUBLIC_P256_MAGIC
)

var (
	ncryptDLL                     = syscall.NewLazyDLL("ncrypt.dll")
	procNCryptOpenStorageProvider = ncryptDLL.NewProc("NCryptOpenStorageProvider")
	procNCryptOpenKey             = ncryptDLL.NewProc("NCryptOpenKey")
	procNCryptCreatePersistedKey  = ncryptDLL.NewProc("NCryptCreatePersistedKey")
	procNCryptSetProperty         = ncryptDLL.NewProc("NCryptSetProperty")
	procNCryptGetProperty         = ncryptDLL.NewProc("NCryptGetProperty")
	procNCryptFinalizeKey         = ncryptDLL.NewProc("NCryptFinalizeKey")
	procNCryptSignHash            = ncryptDLL.NewProc("NCryptSignHash")
	procNCryptExportKey           = ncryptDLL.NewProc("NCryptExportKey")
	procNCryptFreeObject          = ncryptDLL.NewProc("NCryptFreeObject")
)

// Thin seams keep the CNG calls testable without creating a TPM key. They use
// syscall.NewLazyDLL on Windows only, through aliases below to avoid exposing
// the Windows API surface on other builds.
type cngDLL interface{ NewProc(string) cngProc }
type cngProc interface {
	Call(...uintptr) (uintptr, uintptr, error)
}

type nativeTPMSigner struct{}

func newNativeHardwareSigner() hardwareSigner { return nativeTPMSigner{} }

func (nativeTPMSigner) EnsureKey(ctx context.Context, name string) (KeyMetadata, error) {
	if ctx == nil || ctx.Err() != nil {
		return KeyMetadata{}, ErrProtectionUnavailable
	}
	provider, err := openPlatformProvider()
	if err != nil {
		return KeyMetadata{}, err
	}
	defer freeCNG(provider)
	key, found, err := openTPMKey(provider, name)
	if err != nil {
		return KeyMetadata{}, err
	}
	if !found {
		key, err = createTPMKey(provider, name)
		if err != nil {
			return KeyMetadata{}, err
		}
	}
	defer freeCNG(key)
	return cngKeyMetadata(key)
}

func (nativeTPMSigner) Sign(ctx context.Context, name string, payload []byte) (SignatureMetadata, error) {
	if ctx == nil || ctx.Err() != nil {
		return SignatureMetadata{}, ErrProtectionUnavailable
	}
	provider, err := openPlatformProvider()
	if err != nil {
		return SignatureMetadata{}, err
	}
	defer freeCNG(provider)
	key, found, err := openTPMKey(provider, name)
	if err != nil {
		return SignatureMetadata{}, err
	}
	if !found {
		return SignatureMetadata{}, ErrKeyNotInitialized
	}
	defer freeCNG(key)
	metadata, err := cngKeyMetadata(key)
	if err != nil {
		return SignatureMetadata{}, err
	}
	// Re-read the provider and key policy immediately before the signing call.
	// A handle being opened by the platform provider is not evidence that its
	// finalized algorithm, export policy, and usage are the required values.
	if err := validateTPMKey(key); err != nil {
		return SignatureMetadata{}, err
	}
	hash := sha256.Sum256(payload)
	var size uint32
	if status := callStatus(procNCryptSignHash, key, 0, uintptr(unsafe.Pointer(&hash[0])), uintptr(len(hash)), 0, 0, uintptr(unsafe.Pointer(&size)), 0); status != 0 || size != 64 {
		return SignatureMetadata{}, errors.New("TPM attestation signing failed")
	}
	signature := make([]byte, size)
	if status := callStatus(procNCryptSignHash, key, 0, uintptr(unsafe.Pointer(&hash[0])), uintptr(len(hash)), uintptr(unsafe.Pointer(&signature[0])), uintptr(len(signature)), uintptr(unsafe.Pointer(&size)), 0); status != 0 || size != uint32(len(signature)) {
		return SignatureMetadata{}, errors.New("TPM attestation signing failed")
	}
	return SignatureMetadata{KeyMetadata: metadata, PayloadSHA256: digest(payload), Signature: base64.RawURLEncoding.EncodeToString(signature)}, nil
}

func openPlatformProvider() (uintptr, error) {
	name, err := syscall.UTF16PtrFromString(msPlatformCryptoProvider)
	if err != nil {
		return 0, ErrProtectionUnavailable
	}
	var provider uintptr
	if status := callStatus(procNCryptOpenStorageProvider, uintptr(unsafe.Pointer(&provider)), uintptr(unsafe.Pointer(name)), 0); status != 0 || provider == 0 {
		return 0, ErrProtectionUnavailable
	}
	providerName, err := getCNGStringProperty(provider, ncryptObjectName)
	if err != nil || validateTPMProviderName(providerName) != nil {
		freeCNG(provider)
		return 0, fmt.Errorf("%w: provider handle name", ErrProtectionPolicy)
	}
	return provider, nil
}

func openTPMKey(provider uintptr, name string) (uintptr, bool, error) {
	keyName, err := syscall.UTF16PtrFromString(tpmKeyName(name))
	if err != nil {
		return 0, false, ErrInvalidKeyName
	}
	var key uintptr
	status := callStatus(procNCryptOpenKey, provider, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(keyName)), 0, 0)
	if status == 0 && key != 0 {
		return key, true, nil
	}
	if status == nteBadKeyset {
		return 0, false, nil
	}
	return 0, false, ErrProtectionUnavailable
}

func createTPMKey(provider uintptr, name string) (uintptr, error) {
	algorithm, err := syscall.UTF16PtrFromString(ncryptECDSAP256Algorithm)
	if err != nil {
		return 0, ErrProtectionUnavailable
	}
	keyName, err := syscall.UTF16PtrFromString(tpmKeyName(name))
	if err != nil {
		return 0, ErrInvalidKeyName
	}
	var key uintptr
	if status := callStatus(procNCryptCreatePersistedKey, provider, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(algorithm)), uintptr(unsafe.Pointer(keyName)), 0, 0); status != 0 || key == 0 {
		return 0, ErrProtectionUnavailable
	}
	keep := false
	defer func() {
		if !keep {
			freeCNG(key)
		}
	}()
	// Zero is the documented "never export" policy. Set it explicitly before
	// finalizing so a future provider default cannot weaken the invariant.
	if err := setCNGUint32(key, ncryptExportPolicy, 0); err != nil {
		return 0, err
	}
	if err := setCNGUint32(key, ncryptKeyUsage, ncryptAllowSigning); err != nil {
		return 0, err
	}
	if status := callStatus(procNCryptFinalizeKey, key, 0); status != 0 {
		return 0, ErrProtectionUnavailable
	}
	keep = true
	return key, nil
}

func setCNGUint32(key uintptr, property string, value uint32) error {
	name, err := syscall.UTF16PtrFromString(property)
	if err != nil {
		return ErrProtectionUnavailable
	}
	if status := callStatus(procNCryptSetProperty, key, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&value)), unsafe.Sizeof(value), 0); status != 0 {
		return ErrProtectionUnavailable
	}
	return nil
}

func cngKeyMetadata(key uintptr) (KeyMetadata, error) {
	if err := validateTPMKey(key); err != nil {
		return KeyMetadata{}, err
	}
	blobType, err := syscall.UTF16PtrFromString(ncryptECCPublicBlob)
	if err != nil {
		return KeyMetadata{}, ErrProtectionUnavailable
	}
	var size uint32
	if status := callStatus(procNCryptExportKey, key, 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0, uintptr(unsafe.Pointer(&size)), 0); status != 0 || size != 72 {
		return KeyMetadata{}, ErrProtectionUnavailable
	}
	blob := make([]byte, size)
	if status := callStatus(procNCryptExportKey, key, 0, uintptr(unsafe.Pointer(blobType)), 0, uintptr(unsafe.Pointer(&blob[0])), uintptr(len(blob)), uintptr(unsafe.Pointer(&size)), 0); status != 0 || size != uint32(len(blob)) {
		return KeyMetadata{}, ErrProtectionUnavailable
	}
	public, err := parseP256PublicBlob(blob)
	if err != nil {
		return KeyMetadata{}, err
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return KeyMetadata{}, ErrProtectionUnavailable
	}
	return KeyMetadata{Algorithm: AlgorithmECDSAP256SHA256, KeyID: "ecdsa-p256:" + digest(der), PublicKey: base64.RawURLEncoding.EncodeToString(der), PublicKeySHA256: digest(der), ProtectionEvidence: providercredential.EvidenceHardwareNonExportableLocalController}, nil
}

func validateTPMKey(key uintptr) error {
	algorithm, err := getCNGStringProperty(key, ncryptAlgorithmName)
	if err != nil {
		return fmt.Errorf("%w: read %s", ErrProtectionPolicy, ncryptAlgorithmName)
	}
	exportPolicy, err := getCNGUint32Property(key, ncryptExportPolicy)
	if err != nil {
		return fmt.Errorf("%w: read %s", ErrProtectionPolicy, ncryptExportPolicy)
	}
	keyUsage, err := getCNGUint32Property(key, ncryptKeyUsage)
	if err != nil {
		return fmt.Errorf("%w: read %s", ErrProtectionPolicy, ncryptKeyUsage)
	}
	properties := tpmKeyProperties{Algorithm: algorithm, ExportPolicy: exportPolicy, KeyUsage: keyUsage}
	if err := validateTPMKeyProperties(properties); err != nil {
		return fmt.Errorf("%w: algorithm=%q export_policy=0x%08x key_usage=0x%08x", err, algorithm, exportPolicy, keyUsage)
	}
	return nil
}

func getCNGUint32Property(key uintptr, property string) (uint32, error) {
	value, err := getCNGProperty(key, property)
	if err != nil || len(value) != 4 {
		return 0, ErrProtectionPolicy
	}
	return uint32(value[0]) | uint32(value[1])<<8 | uint32(value[2])<<16 | uint32(value[3])<<24, nil
}

func getCNGStringProperty(key uintptr, property string) (string, error) {
	value, err := getCNGProperty(key, property)
	if err != nil || len(value) == 0 || len(value)%2 != 0 {
		return "", ErrProtectionPolicy
	}
	words := unsafe.Slice((*uint16)(unsafe.Pointer(&value[0])), len(value)/2)
	decoded := strings.TrimRight(string(utf16.Decode(words)), "\x00")
	if decoded == "" || strings.ContainsRune(decoded, '\x00') {
		return "", ErrProtectionPolicy
	}
	return decoded, nil
}

func getCNGProperty(key uintptr, property string) ([]byte, error) {
	name, err := syscall.UTF16PtrFromString(property)
	if err != nil {
		return nil, ErrProtectionPolicy
	}
	var size uint32
	if status := callStatus(procNCryptGetProperty, key, uintptr(unsafe.Pointer(name)), 0, 0, uintptr(unsafe.Pointer(&size)), 0); status != 0 || size == 0 || size > 4096 {
		return nil, ErrProtectionPolicy
	}
	value := make([]byte, size)
	if status := callStatus(procNCryptGetProperty, key, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&value[0])), uintptr(len(value)), uintptr(unsafe.Pointer(&size)), 0); status != 0 || size != uint32(len(value)) {
		return nil, ErrProtectionPolicy
	}
	return value, nil
}

func parseP256PublicBlob(blob []byte) (*ecdsa.PublicKey, error) {
	if len(blob) != 72 || uint32(blob[0])|uint32(blob[1])<<8|uint32(blob[2])<<16|uint32(blob[3])<<24 != eccPublicP256Magic || uint32(blob[4])|uint32(blob[5])<<8|uint32(blob[6])<<16|uint32(blob[7])<<24 != 32 {
		return nil, ErrProtectionUnavailable
	}
	x := new(big.Int).SetBytes(blob[8:40])
	y := new(big.Int).SetBytes(blob[40:72])
	curve := elliptic.P256()
	if !curve.IsOnCurve(x, y) {
		return nil, ErrProtectionUnavailable
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func tpmKeyName(name string) string { return "ntm.provider.attestation." + digest([]byte(name)) }

func callStatus(proc cngProc, args ...uintptr) uintptr {
	status, _, _ := proc.Call(args...)
	return status
}

func freeCNG(handle uintptr) {
	if handle != 0 {
		_, _, _ = procNCryptFreeObject.Call(handle)
	}
}
