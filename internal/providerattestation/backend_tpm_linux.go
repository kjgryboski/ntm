//go:build linux

package providerattestation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const windowsBridgeEnvironment = "NTM_WINDOWS_PROVIDER_BRIDGE"

type windowsBridgeSigner struct {
	path           string
	expectedSHA256 string
	invoke         func(context.Context, string, BridgeRequest) (BridgeResponse, error)
	invokePinned   func(context.Context, string, string, BridgeRequest) (BridgeResponse, error)
}

func newNativeHardwareSigner() hardwareSigner {
	path := strings.TrimSpace(os.Getenv(windowsBridgeEnvironment))
	if !isWSLHost() || !validBridgePath(path) {
		return nil
	}
	return &windowsBridgeSigner{path: path, invoke: invokeWindowsBridge}
}

// NewPinnedWindowsBridge constructs a WSL attestor for one exact, immutable
// Windows bridge executable. Unlike the ambient compatibility path, the file
// is re-opened and re-hashed immediately before every ensure/sign invocation.
func NewPinnedWindowsBridge(path, expectedSHA256 string) (*Attestor, error) {
	signer := &windowsBridgeSigner{path: strings.TrimSpace(path), expectedSHA256: strings.TrimSpace(expectedSHA256), invoke: invokeWindowsBridge}
	if !isWSLHost() || !signer.pinnedPathValid() {
		return nil, ErrProtectionUnavailable
	}
	return &Attestor{hardware: signer}, nil
}

func (s *windowsBridgeSigner) EnsureKey(ctx context.Context, name string) (KeyMetadata, error) {
	if s == nil || name != WindowsBridgeKeyName || s.invoke == nil || !s.pathReady() {
		return KeyMetadata{}, ErrProtectionUnavailable
	}
	response, err := s.invokeRequest(ctx, BridgeRequest{Operation: BridgeOperationEnsure})
	if err != nil || response.Error != "" || response.Metadata == nil || response.Signature != nil || !validBridgeMetadata(*response.Metadata) {
		return KeyMetadata{}, ErrProtectionUnavailable
	}
	return *response.Metadata, nil
}

func (s *windowsBridgeSigner) Sign(ctx context.Context, name string, payload []byte) (SignatureMetadata, error) {
	if s == nil || name != WindowsBridgeKeyName || s.invoke == nil || !s.pathReady() || ValidateBridgePayload(payload) != nil {
		return SignatureMetadata{}, ErrProtectionUnavailable
	}
	response, err := s.invokeRequest(ctx, BridgeRequest{Operation: BridgeOperationSign, Payload: base64.RawURLEncoding.EncodeToString(payload)})
	if err != nil || response.Error != "" || response.Metadata != nil || response.Signature == nil || Verify(payload, *response.Signature) != nil {
		return SignatureMetadata{}, ErrProtectionUnavailable
	}
	return *response.Signature, nil
}

func (s *windowsBridgeSigner) pathReady() bool {
	if s == nil || !validBridgePath(s.path) {
		return false
	}
	if s.expectedSHA256 == "" {
		return true
	}
	return s.pinnedPathValid()
}

// invokeRequest keeps the historical ambient bridge strictly outside governed
// provider paths. A profile-pinned bridge is opened, checked, and executed by
// descriptor so the pathname cannot be swapped between the digest check and
// execve. Tests may inject invokePinned without weakening production callers.
func (s *windowsBridgeSigner) invokeRequest(ctx context.Context, request BridgeRequest) (BridgeResponse, error) {
	if s == nil || s.invoke == nil {
		return BridgeResponse{}, ErrProtectionUnavailable
	}
	if s.expectedSHA256 == "" {
		return s.invoke(ctx, s.path, request)
	}
	if s.invokePinned != nil {
		return s.invokePinned(ctx, s.path, s.expectedSHA256, request)
	}
	return invokePinnedWindowsBridge(ctx, s.path, s.expectedSHA256, request)
}

func (s *windowsBridgeSigner) pinnedPathValid() bool {
	if s == nil || !validBridgePath(s.path) || len(s.expectedSHA256) != 64 {
		return false
	}
	for _, r := range s.expectedSHA256 {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	file, err := openPinnedWindowsBridge(s.path, s.expectedSHA256)
	if err != nil {
		return false
	}
	return file.Close() == nil
}

// openPinnedWindowsBridge validates every path component from / through the
// executable. Governed provider receipt signers may not rely on a bridge under
// an operator-writable directory: ownership or mode changes make authority
// unavailable rather than silently falling back to NTM_WINDOWS_PROVIDER_BRIDGE.
func openPinnedWindowsBridge(path, expectedSHA256 string) (*os.File, error) {
	if !validBridgePath(path) || len(expectedSHA256) != sha256.Size*2 {
		return nil, ErrProtectionUnavailable
	}
	for _, r := range expectedSHA256 {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return nil, ErrProtectionUnavailable
		}
	}
	for component := filepath.Dir(filepath.Clean(path)); ; component = filepath.Dir(component) {
		info, err := os.Lstat(component)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !rootOwnedImmutable(info) {
			return nil, ErrProtectionUnavailable
		}
		if component == string(filepath.Separator) {
			break
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrProtectionUnavailable
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || !rootOwnedImmutable(info) {
		_ = file.Close()
		return nil, ErrProtectionUnavailable
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil || hex.EncodeToString(hasher.Sum(nil)) != expectedSHA256 {
		_ = file.Close()
		return nil, ErrProtectionUnavailable
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, ErrProtectionUnavailable
	}
	return file, nil
}

func rootOwnedImmutable(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && info.Mode().Perm()&0o022 == 0
}

func validBridgePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && !strings.ContainsRune(path, '\x00')
}

func isWSLHost() bool {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	return err == nil && strings.Contains(strings.ToLower(string(data)), "microsoft")
}

func invokeWindowsBridge(ctx context.Context, path string, request BridgeRequest) (BridgeResponse, error) {
	if ctx == nil || ctx.Err() != nil || !validBridgePath(path) {
		return BridgeResponse{}, ErrProtectionUnavailable
	}
	input, err := json.Marshal(request)
	if err != nil {
		return BridgeResponse{}, ErrProtectionUnavailable
	}
	command := exec.CommandContext(ctx, path)
	command.Stdin = bytes.NewReader(input)
	command.Stderr = io.Discard
	output := &limitedBridgeOutput{limit: maxCanonicalPayload}
	command.Stdout = output
	if err := command.Run(); err != nil || output.exceeded {
		return BridgeResponse{}, ErrProtectionUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	decoder.DisallowUnknownFields()
	var response BridgeResponse
	if err := decoder.Decode(&response); err != nil {
		return BridgeResponse{}, ErrProtectionUnavailable
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return BridgeResponse{}, ErrProtectionUnavailable
	}
	return response, nil
}

func invokePinnedWindowsBridge(ctx context.Context, path, expectedSHA256 string, request BridgeRequest) (BridgeResponse, error) {
	if ctx == nil || ctx.Err() != nil {
		return BridgeResponse{}, ErrProtectionUnavailable
	}
	file, err := openPinnedWindowsBridge(path, expectedSHA256)
	if err != nil {
		return BridgeResponse{}, ErrProtectionUnavailable
	}
	defer file.Close()
	input, err := json.Marshal(request)
	if err != nil {
		return BridgeResponse{}, ErrProtectionUnavailable
	}
	// ExtraFiles maps file to descriptor 3 in the child. /proc/self/fd/3 is the
	// verified opened object, not a second resolution of the mutable path.
	command := exec.CommandContext(ctx, "/proc/self/fd/3")
	command.ExtraFiles = []*os.File{file}
	command.Stdin = bytes.NewReader(input)
	command.Stderr = io.Discard
	output := &limitedBridgeOutput{limit: maxCanonicalPayload}
	command.Stdout = output
	if err := command.Run(); err != nil || output.exceeded {
		return BridgeResponse{}, ErrProtectionUnavailable
	}
	return decodeWindowsBridgeResponse(output.Bytes())
}

func decodeWindowsBridgeResponse(raw []byte) (BridgeResponse, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var response BridgeResponse
	if err := decoder.Decode(&response); err != nil {
		return BridgeResponse{}, ErrProtectionUnavailable
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return BridgeResponse{}, ErrProtectionUnavailable
	}
	return response, nil
}

type limitedBridgeOutput struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *limitedBridgeOutput) Write(value []byte) (int, error) {
	if b.Len()+len(value) > b.limit {
		b.exceeded = true
		return 0, errors.New("bridge output limit exceeded")
	}
	return b.Buffer.Write(value)
}

func validBridgeMetadata(metadata KeyMetadata) bool {
	if metadata.Algorithm != AlgorithmECDSAP256SHA256 || metadata.ProtectionEvidence != ProtectionHardwareNoExportLocalController || metadata.KeyID == "" {
		return false
	}
	der, err := base64.RawURLEncoding.DecodeString(metadata.PublicKey)
	if err != nil || digest(der) != metadata.PublicKeySHA256 || metadata.KeyID != "ecdsa-p256:"+digest(der) {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	public, ok := parsed.(*ecdsa.PublicKey)
	return err == nil && ok && public.Curve == elliptic.P256()
}
