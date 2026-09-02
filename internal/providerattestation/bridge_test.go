//go:build linux

package providerattestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func TestValidateBridgePayloadAllowsOnlyNamedReceiptSchemas(t *testing.T) {
	for _, payload := range [][]byte{
		[]byte(ProviderAttestationPreflight),
		validBridgeNativePayload(),
		validBridgeQualificationPayload(),
		validBridgeSessionPayload(),
	} {
		if err := ValidateBridgePayload(payload); err != nil {
			t.Fatalf("payload %q rejected: %v", payload, err)
		}
	}
	for _, payload := range [][]byte{nil, []byte(`{"schema_version":"other"}`), []byte(`{"schema_version":"ntm.provider-session.v2"}`), []byte(`{"schema_version":"ntm.provider-session.v2"}{}`), []byte("not json")} {
		if err := ValidateBridgePayload(payload); !errors.Is(err, ErrBridgePayloadDenied) {
			t.Fatalf("payload %q error=%v", payload, err)
		}
	}
}

func TestValidBridgeNonceRejectsAmbiguousValues(t *testing.T) {
	for _, nonce := range []string{"0123456789abcdef", "valid_nonce-012345"} {
		if !ValidBridgeNonce(nonce) {
			t.Fatalf("nonce %q rejected", nonce)
		}
	}
	for _, nonce := range []string{"", "too-short", "contains space 012345", "0123456789abcdef!"} {
		if ValidBridgeNonce(nonce) {
			t.Fatalf("nonce %q accepted", nonce)
		}
	}
}

func TestWindowsBridgeSignerValidatesEnsureAndSignResponsesLocally(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeHardwareSigner{private: private}
	called := 0
	signer := &windowsBridgeSigner{path: "/mnt/c/ntm-provider-bridge.exe", invoke: func(_ context.Context, _ string, request BridgeRequest) (BridgeResponse, error) {
		called++
		switch request.Operation {
		case BridgeOperationEnsure:
			metadata, err := fake.EnsureKey(context.Background(), WindowsBridgeKeyName)
			return BridgeResponse{Metadata: &metadata}, err
		case BridgeOperationSign:
			payload, err := base64.RawURLEncoding.DecodeString(request.Payload)
			if err != nil {
				return BridgeResponse{}, err
			}
			signature, err := fake.Sign(context.Background(), WindowsBridgeKeyName, payload)
			return BridgeResponse{Signature: &signature}, err
		default:
			return BridgeResponse{}, errors.New("unexpected operation")
		}
	}}
	if _, err := signer.EnsureKey(t.Context(), WindowsBridgeKeyName); err != nil {
		t.Fatal(err)
	}
	payload := validBridgeSessionPayload()
	signature, err := signer.Sign(t.Context(), WindowsBridgeKeyName, payload)
	if err != nil || Verify(payload, signature) != nil {
		t.Fatalf("signature=%+v err=%v", signature, err)
	}
	if called != 2 {
		t.Fatalf("calls=%d", called)
	}
}

func TestValidateBridgePayloadRejectsUnknownAndRecursiveFields(t *testing.T) {
	for _, payload := range [][]byte{
		[]byte(`{"schema_version":"ntm.provider-qualification.v1","mode":"live","provider":"zai","transport":"zai_native_api","identity_sha256":"` + bridgeTestDigest + `","policy_sha256":"` + bridgeTestDigest + `","runtime_version":"zai-native-http-v1","started_at":"2026-09-02T12:00:00Z","completed_at":"2026-09-02T12:01:00Z","disposable_repo_sha256":"` + bridgeTestDigest + `","checks":[{"name":"gate","passed":true,"provenance":"live","evidence_sha256":"` + bridgeTestDigest + `","unexpected":true}],"passed":true,"receipt_sha256":"` + bridgeTestDigest + `"}`),
		[]byte(`{"schema_version":"ntm.provider-session.v2","schema_version":"ntm.provider-session.v2"}`),
		[]byte(`{"schema_version":"ntm.provider-qualification.v1","mode":"live","provider":"zai","transport":"zai_native_api","identity_sha256":"` + bridgeTestDigest + `","policy_sha256":"` + bridgeTestDigest + `","runtime_version":"zai-native-http-v1","started_at":"not-a-time","completed_at":"2026-09-02T12:01:00Z","disposable_repo_sha256":"` + bridgeTestDigest + `","checks":[{"name":"gate","passed":true,"provenance":"live","evidence_sha256":"` + bridgeTestDigest + `"}],"passed":true,"receipt_sha256":"` + bridgeTestDigest + `","attestation":null}`),
	} {
		if err := ValidateBridgePayload(payload); !errors.Is(err, ErrBridgePayloadDenied) {
			t.Fatalf("payload %q error=%v", payload, err)
		}
	}
}

const bridgeTestDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validBridgeQualificationPayload() []byte {
	return []byte(`{"schema_version":"ntm.provider-qualification.v1","mode":"live","provider":"zai","transport":"zai_native_api","identity_sha256":"` + bridgeTestDigest + `","policy_sha256":"` + bridgeTestDigest + `","runtime_version":"zai-native-http-v1","started_at":"2026-09-02T12:00:00Z","completed_at":"2026-09-02T12:01:00Z","disposable_repo_sha256":"` + bridgeTestDigest + `","checks":[{"name":"gate","passed":true,"provenance":"live","evidence_sha256":"` + bridgeTestDigest + `"}],"passed":true,"receipt_sha256":"` + bridgeTestDigest + `"}`)
}

func validBridgeNativePayload() []byte {
	return []byte(`{"schema_version":"ntm.provider-native-run.v2","success":false,"profile":"zai-native-no-tools","transport":"zai_native_api","identity_sha256":"` + bridgeTestDigest + `","adapter_version":"zai-native-http-v1","tools":false,"operation_id":"test","binding_sha256":"` + bridgeTestDigest + `","receipt_state":"completed","replayed":false,"state":"provider_failure","admission":{"allowed":true,"no_failover":true,"capacity_control_scope":"local_shared"},"receipt":{"usage":{},"tool_call_count":0,"tool_calls_sha256":"` + bridgeTestDigest + `","output_sha256":"` + bridgeTestDigest + `","nonce_verified":false,"http_status":429,"cancellation":{},"started_at":"2026-09-02T12:00:00Z","completed_at":"2026-09-02T12:01:00Z"},"telemetry":{"state":"failed","error_sha256":"` + bridgeTestDigest + `"}}`)
}

func validBridgeSessionPayload() []byte {
	return []byte(`{"schema_version":"ntm.provider-session.v2","success":false,"profile":"grok-observe","transport":"xai_headless_session","identity_sha256":"` + bridgeTestDigest + `","policy":"grok-readonly-ci","policy_sha256":"` + bridgeTestDigest + `","config_sha256":"` + bridgeTestDigest + `","binary_sha256":"` + bridgeTestDigest + `","cwd_sha256":"` + bridgeTestDigest + `","worktree_sha256":"` + bridgeTestDigest + `","dispatched":true,"admission":{"allowed":true,"no_failover":true,"capacity_control_scope":"local_shared"},"receipt":{"action":"resume","fork":false,"parent_session_sha256":"` + bridgeTestDigest + `","cwd_sha256":"` + bridgeTestDigest + `","worktree_sha256":"` + bridgeTestDigest + `","policy_sha256":"` + bridgeTestDigest + `","lineage_bound":false,"provider_acknowledged":false,"completion_confirmed":false,"stderr":{"bytes":0,"sha256":"` + bridgeTestDigest + `","truncated":false},"cancellation":{"provider_acknowledged":false,"local_termination":"not_started","residual_pids":[],"observed_at":"2026-09-02T12:00:00Z"}},"failure_code":"provider","error_sha256":"` + bridgeTestDigest + `","telemetry":{"state":"failed","error_sha256":"` + bridgeTestDigest + `"}}`)
}

func TestWindowsBridgeSignerRejectsUnallowlistedPayloadBeforeInvoke(t *testing.T) {
	called := false
	signer := &windowsBridgeSigner{path: "/mnt/c/ntm-provider-bridge.exe", invoke: func(context.Context, string, BridgeRequest) (BridgeResponse, error) {
		called = true
		return BridgeResponse{}, nil
	}}
	if _, err := signer.Sign(t.Context(), WindowsBridgeKeyName, []byte(`{"schema_version":"not-allowed"}`)); !errors.Is(err, ErrProtectionUnavailable) || called {
		t.Fatalf("err=%v called=%t", err, called)
	}
}
