//go:build linux

package providerattestation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const windowsBridgeEnvironment = "NTM_WINDOWS_PROVIDER_BRIDGE"

type windowsBridgeSigner struct {
	path   string
	invoke func(context.Context, string, BridgeRequest) (BridgeResponse, error)
}

func newNativeHardwareSigner() hardwareSigner {
	path := strings.TrimSpace(os.Getenv(windowsBridgeEnvironment))
	if !isWSLHost() || !validBridgePath(path) {
		return nil
	}
	return &windowsBridgeSigner{path: path, invoke: invokeWindowsBridge}
}

func (s *windowsBridgeSigner) EnsureKey(ctx context.Context, name string) (KeyMetadata, error) {
	if s == nil || name != WindowsBridgeKeyName || s.invoke == nil {
		return KeyMetadata{}, ErrProtectionUnavailable
	}
	response, err := s.invoke(ctx, s.path, BridgeRequest{Operation: BridgeOperationEnsure})
	if err != nil || response.Error != "" || response.Metadata == nil || response.Signature != nil || !validBridgeMetadata(*response.Metadata) {
		return KeyMetadata{}, ErrProtectionUnavailable
	}
	return *response.Metadata, nil
}

func (s *windowsBridgeSigner) Sign(ctx context.Context, name string, payload []byte) (SignatureMetadata, error) {
	if s == nil || name != WindowsBridgeKeyName || s.invoke == nil || ValidateBridgePayload(payload) != nil {
		return SignatureMetadata{}, ErrProtectionUnavailable
	}
	response, err := s.invoke(ctx, s.path, BridgeRequest{Operation: BridgeOperationSign, Payload: base64.RawURLEncoding.EncodeToString(payload)})
	if err != nil || response.Error != "" || response.Metadata != nil || response.Signature == nil || Verify(payload, *response.Signature) != nil {
		return SignatureMetadata{}, ErrProtectionUnavailable
	}
	return *response.Signature, nil
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
