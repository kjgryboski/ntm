//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providercredential"
)

func main() {
	request, err := decodeRequest(os.Stdin)
	if err != nil {
		writeError()
		return
	}
	attestor := providerattestation.NewOSProtected()
	var response providerattestation.BridgeResponse
	switch request.Operation {
	case providerattestation.BridgeOperationEnsure:
		if request.Payload != "" {
			writeError()
			return
		}
		metadata, err := attestor.EnsureKey(context.Background(), providerattestation.WindowsBridgeKeyName)
		if err != nil {
			writeError()
			return
		}
		response.Metadata = &metadata
	case providerattestation.BridgeOperationSign:
		payload, err := base64.RawURLEncoding.DecodeString(request.Payload)
		if err != nil || providerattestation.ValidateBridgePayload(payload) != nil {
			writeError()
			return
		}
		signature, err := attestor.Sign(context.Background(), providerattestation.WindowsBridgeKeyName, payload)
		if err != nil {
			writeError()
			return
		}
		response.Signature = &signature
	case providerattestation.BridgeOperationCredentialGet:
		if request.Payload != "" || request.CredentialID == "" || !providerattestation.ValidBridgeNonce(request.Nonce) || !windowsBridgeCredentialAllowed(request.CredentialID) {
			writeError()
			return
		}
		credential, err := providercredential.New().Get(context.Background(), request.CredentialID)
		if err != nil {
			writeErrorNonce(request.Nonce)
			return
		}
		response.Credential, response.Nonce = base64.RawURLEncoding.EncodeToString(credential), request.Nonce
		zero(credential)
	case providerattestation.BridgeOperationCredentialStatus:
		if request.Payload != "" || request.CredentialID == "" || !providerattestation.ValidBridgeNonce(request.Nonce) || !windowsBridgeCredentialAllowed(request.CredentialID) {
			writeError()
			return
		}
		status, err := providercredential.New().Status(context.Background(), request.CredentialID)
		if err != nil {
			writeErrorNonce(request.Nonce)
			return
		}
		response.Status, response.Nonce = &status, request.Nonce
	default:
		writeError()
		return
	}
	_ = json.NewEncoder(os.Stdout).Encode(response)
}

func decodeRequest(reader io.Reader) (providerattestation.BridgeRequest, error) {
	var request providerattestation.BridgeRequest
	data, err := io.ReadAll(io.LimitReader(reader, 4<<20+1))
	if err != nil || len(data) == 0 || len(data) > 4<<20 {
		return request, io.ErrUnexpectedEOF
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return providerattestation.BridgeRequest{}, io.ErrUnexpectedEOF
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return providerattestation.BridgeRequest{}, io.ErrUnexpectedEOF
	}
	return request, nil
}

func writeError() {
	_ = json.NewEncoder(os.Stdout).Encode(providerattestation.BridgeResponse{Error: "request failed"})
}

func writeErrorNonce(nonce string) {
	_ = json.NewEncoder(os.Stdout).Encode(providerattestation.BridgeResponse{Error: "request failed", Nonce: nonce})
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

// windowsBridgeCredentialAllowed is a narrowing allowlist, not caller
// authentication. The executable still runs under the current Windows user;
// it delegates either an exact configured native-API identity or a separately
// named Z.ai Coding Plan Codex broker credential, never one as the other.
func windowsBridgeCredentialAllowed(id string) bool {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return false
	}
	// This deliberately ignores NTM_CONFIG and XDG_CONFIG_HOME inherited from
	// WSL. The allowlist is read only from the Windows owner's fixed profile.
	configPath, err := resolvedWindowsBridgeConfigPath(home)
	if err != nil {
		return false
	}
	cfg, err := config.Load(configPath)
	if err != nil || cfg == nil {
		return false
	}
	for _, profile := range cfg.ProviderProfiles {
		if strings.TrimSpace(profile.Provider) != "zai" || !profile.ExactTargetOnly {
			continue
		}
		identity, err := profile.Identity()
		if err != nil {
			continue
		}
		if strings.TrimSpace(profile.Entitlement) == provider.EntitlementNativeAPI && strings.TrimSpace(profile.CredentialClass) == provider.CredentialClassAPIKey && strings.TrimSpace(profile.BillingClass) == provider.BillingClassAPIUsage && providercredential.CanonicalID(identity) == id {
			return true
		}
		if strings.TrimSpace(profile.Entitlement) == provider.EntitlementCodexResponses && strings.TrimSpace(profile.CredentialClass) == provider.CredentialClassCodingPlan && strings.TrimSpace(profile.BillingClass) == provider.BillingClassCodingPlan && strings.TrimSpace(profile.BrokerCredentialID) != "" && strings.TrimSpace(profile.BrokerCredentialID) == id {
			return true
		}
	}
	return false
}
