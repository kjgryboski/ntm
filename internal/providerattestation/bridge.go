package providerattestation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/providercredential"
)

const (
	WindowsBridgeKeyName            = "ntm.provider.receipts.v1"
	BridgeOperationEnsure           = "ensure"
	BridgeOperationSign             = "sign"
	BridgeOperationCredentialGet    = "credential_get"
	BridgeOperationCredentialStatus = "credential_status"
	ProviderAttestationPreflight    = "ntm.provider-receipt-attestation-preflight.v1"
)

var ErrBridgePayloadDenied = errors.New("provider attestation bridge payload is not allowlisted")
var bridgeNoncePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
var bridgeSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// BridgeRequest and BridgeResponse are machine-only JSON exchanged over the
// explicit WSL-to-Windows helper. Payload is base64url canonical receipt bytes.
type BridgeRequest struct {
	Operation    string `json:"operation"`
	Payload      string `json:"payload,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
	Nonce        string `json:"nonce,omitempty"`
}

type BridgeResponse struct {
	Metadata   *KeyMetadata               `json:"metadata,omitempty"`
	Signature  *SignatureMetadata         `json:"signature,omitempty"`
	Credential string                     `json:"credential_base64,omitempty"`
	Status     *providercredential.Status `json:"credential_status,omitempty"`
	Nonce      string                     `json:"nonce,omitempty"`
	Error      string                     `json:"error,omitempty"`
}

// ValidBridgeNonce accepts an opaque caller-generated correlation value. It
// prevents a caller from accepting a crossed helper response; it is not an
// authentication mechanism.
func ValidBridgeNonce(nonce string) bool { return bridgeNoncePattern.MatchString(nonce) }

func ValidateBridgePayload(payload []byte) error {
	if bytes.Equal(payload, []byte(ProviderAttestationPreflight)) {
		return nil
	}
	object, err := bridgeJSONObject(payload)
	if err != nil {
		return ErrBridgePayloadDenied
	}
	schema, ok := bridgeString(object, "schema_version")
	if !ok {
		return ErrBridgePayloadDenied
	}
	switch schema {
	case "ntm.provider-native-run.v2":
		err = validateBridgeNativeRun(object)
	case "ntm.provider-qualification.v1":
		err = validateBridgeQualification(object)
	case "ntm.provider-session.v2":
		err = validateBridgeSession(object)
	default:
		err = ErrBridgePayloadDenied
	}
	if err != nil {
		return ErrBridgePayloadDenied
	}
	return nil
}

// bridgeJSONObject rejects malformed JSON, duplicate keys, and non-object
// roots before individual receipt validators inspect their schema.  A bridge
// is a signing oracle: permissive decoding here would let an untrusted WSL
// process obtain a signature over a shape NTM never emits.
func bridgeJSONObject(payload []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := bridgeRejectDuplicateKeys(decoder); err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil || object == nil {
		return nil, errors.New("receipt must be a JSON object")
	}
	return object, nil
}

func bridgeRejectDuplicateKeys(decoder *json.Decoder) error {
	var value func() error
	value = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, isDelim := token.(json.Delim)
		if !isDelim {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if _, exists := seen[name]; exists {
					return fmt.Errorf("duplicate JSON key %q", name)
				}
				seen[name] = struct{}{}
				if err := value(); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := value(); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := value(); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing JSON value")
	}
	_, err := decoder.Token()
	if err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func bridgeAllowed(object map[string]json.RawMessage, required []string, allowed ...string) error {
	set := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		set[name] = struct{}{}
	}
	for name := range object {
		if _, ok := set[name]; !ok {
			return fmt.Errorf("unknown receipt field %q", name)
		}
	}
	for _, name := range required {
		if _, ok := object[name]; !ok {
			return fmt.Errorf("required receipt field %q is missing", name)
		}
	}
	// Canonical payloads always omit the attestation envelope.  Permitting it
	// would create a signature-over-signature recursion and make the covered
	// bytes ambiguous to receipt readers.
	if _, ok := object["attestation"]; ok {
		return errors.New("attestation is not part of a canonical signing payload")
	}
	return nil
}

func bridgeString(object map[string]json.RawMessage, name string) (string, bool) {
	value, ok := object[name]
	if !ok {
		return "", false
	}
	var decoded string
	if json.Unmarshal(value, &decoded) != nil || decoded == "" {
		return "", false
	}
	return decoded, true
}

func bridgeBool(object map[string]json.RawMessage, name string) bool {
	value, ok := object[name]
	if !ok {
		return false
	}
	var decoded bool
	return json.Unmarshal(value, &decoded) == nil
}

func bridgeSHA256(object map[string]json.RawMessage, name string) bool {
	value, ok := bridgeString(object, name)
	return ok && bridgeSHA256Pattern.MatchString(value)
}

func bridgeObject(object map[string]json.RawMessage, name string) (map[string]json.RawMessage, bool) {
	value, ok := object[name]
	if !ok {
		return nil, false
	}
	decoded, err := bridgeJSONObject(value)
	return decoded, err == nil
}

func bridgeTimestamp(object map[string]json.RawMessage, name string) bool {
	value, ok := bridgeString(object, name)
	if !ok {
		return false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && !parsed.IsZero()
}

func validateBridgeNativeRun(object map[string]json.RawMessage) error {
	required := []string{"schema_version", "success", "profile", "transport", "identity_sha256", "adapter_version", "tools", "operation_id", "binding_sha256", "receipt_state", "replayed", "state", "admission", "receipt", "telemetry"}
	allowed := append(required, "qualification_receipt_sha256", "tool_receipt", "controller", "provider_error_class", "error_sha256", "attestation")
	if err := bridgeAllowed(object, required, allowed...); err != nil {
		return err
	}
	if object["schema_version"] == nil || object["transport"] == nil {
		return errors.New("native schema fields missing")
	}
	if schema, _ := bridgeString(object, "schema_version"); schema != "ntm.provider-native-run.v2" {
		return errors.New("native schema mismatch")
	}
	if transport, _ := bridgeString(object, "transport"); transport != "zai_native_api" {
		return errors.New("native transport mismatch")
	}
	for _, name := range []string{"identity_sha256", "binding_sha256"} {
		if !bridgeSHA256(object, name) {
			return fmt.Errorf("invalid native digest %q", name)
		}
	}
	for _, name := range []string{"profile", "adapter_version", "operation_id", "receipt_state", "state"} {
		if _, ok := bridgeString(object, name); !ok {
			return fmt.Errorf("invalid native field %q", name)
		}
	}
	if !bridgeBool(object, "success") || !bridgeBool(object, "tools") || !bridgeBool(object, "replayed") {
		// A false boolean cannot be distinguished from a malformed field using
		// bridgeBool, so decode these explicitly below.
		for _, name := range []string{"success", "tools", "replayed"} {
			var value bool
			if json.Unmarshal(object[name], &value) != nil {
				return fmt.Errorf("native field %q is not boolean", name)
			}
		}
	}
	if value, ok := object["qualification_receipt_sha256"]; ok {
		var digest string
		if json.Unmarshal(value, &digest) != nil || !bridgeSHA256Pattern.MatchString(digest) {
			return errors.New("invalid qualification receipt digest")
		}
	}
	if value, ok := object["error_sha256"]; ok {
		var digest string
		if json.Unmarshal(value, &digest) != nil || !bridgeSHA256Pattern.MatchString(digest) {
			return errors.New("invalid native error digest")
		}
	}
	if err := validateBridgeAdmission(object); err != nil {
		return err
	}
	if err := validateBridgeNativeReceipt(object); err != nil {
		return err
	}
	return validateBridgeTelemetry(object)
}

func validateBridgeAdmission(object map[string]json.RawMessage) error {
	admission, ok := bridgeObject(object, "admission")
	if !ok {
		return errors.New("admission is not an object")
	}
	if err := bridgeAllowed(admission, []string{"allowed", "no_failover", "capacity_control_scope"}, "allowed", "reason", "retry_at", "no_failover", "capacity_control_scope"); err != nil {
		return err
	}
	for _, name := range []string{"allowed", "no_failover"} {
		var value bool
		if json.Unmarshal(admission[name], &value) != nil {
			return fmt.Errorf("admission field %q is not boolean", name)
		}
	}
	if _, ok := bridgeString(admission, "capacity_control_scope"); !ok {
		return errors.New("admission capacity scope is invalid")
	}
	if _, ok := admission["retry_at"]; ok && !bridgeTimestamp(admission, "retry_at") {
		return errors.New("admission retry timestamp is invalid")
	}
	return nil
}

func validateBridgeNativeReceipt(object map[string]json.RawMessage) error {
	receipt, ok := bridgeObject(object, "receipt")
	if !ok {
		return errors.New("native receipt is not an object")
	}
	required := []string{"usage", "tool_call_count", "tool_calls_sha256", "output_sha256", "nonce_verified", "http_status", "cancellation", "started_at", "completed_at"}
	allowed := append(required, "model", "provider_request_id_sha256", "completion_id_sha256", "provider_session_id_sha256", "finish_reason", "error_code", "error_type")
	if err := bridgeAllowed(receipt, required, allowed...); err != nil {
		return err
	}
	for _, name := range []string{"tool_calls_sha256", "output_sha256"} {
		if !bridgeSHA256(receipt, name) {
			return fmt.Errorf("invalid native receipt digest %q", name)
		}
	}
	for _, name := range []string{"provider_request_id_sha256", "completion_id_sha256", "provider_session_id_sha256"} {
		if _, ok := receipt[name]; ok && !bridgeSHA256(receipt, name) {
			return fmt.Errorf("invalid native receipt digest %q", name)
		}
	}
	for _, name := range []string{"started_at", "completed_at"} {
		if !bridgeTimestamp(receipt, name) {
			return fmt.Errorf("invalid native receipt timestamp %q", name)
		}
	}
	return nil
}

func validateBridgeTelemetry(object map[string]json.RawMessage) error {
	telemetry, ok := bridgeObject(object, "telemetry")
	if !ok {
		return errors.New("telemetry is not an object")
	}
	if err := bridgeAllowed(telemetry, []string{"state"}, "state", "observation_id", "observation_sha256", "error_sha256"); err != nil {
		return err
	}
	if _, ok := bridgeString(telemetry, "state"); !ok {
		return errors.New("telemetry state is invalid")
	}
	for _, name := range []string{"observation_sha256", "error_sha256"} {
		if _, ok := telemetry[name]; ok && !bridgeSHA256(telemetry, name) {
			return fmt.Errorf("invalid telemetry digest %q", name)
		}
	}
	return nil
}

func validateBridgeQualification(object map[string]json.RawMessage) error {
	required := []string{"schema_version", "mode", "provider", "transport", "identity_sha256", "policy_sha256", "runtime_version", "started_at", "completed_at", "disposable_repo_sha256", "checks", "passed", "receipt_sha256"}
	allowed := append(required, "attestation")
	if err := bridgeAllowed(object, required, allowed...); err != nil {
		return err
	}
	if schema, _ := bridgeString(object, "schema_version"); schema != "ntm.provider-qualification.v1" {
		return errors.New("qualification schema mismatch")
	}
	if mode, _ := bridgeString(object, "mode"); mode != "live" {
		return errors.New("qualification mode mismatch")
	}
	for _, name := range []string{"provider", "transport", "runtime_version"} {
		if _, ok := bridgeString(object, name); !ok {
			return fmt.Errorf("invalid qualification field %q", name)
		}
	}
	for _, name := range []string{"identity_sha256", "policy_sha256", "disposable_repo_sha256", "receipt_sha256"} {
		if !bridgeSHA256(object, name) {
			return fmt.Errorf("invalid qualification digest %q", name)
		}
	}
	for _, name := range []string{"started_at", "completed_at"} {
		if !bridgeTimestamp(object, name) {
			return fmt.Errorf("invalid qualification timestamp %q", name)
		}
	}
	var passed bool
	if json.Unmarshal(object["passed"], &passed) != nil {
		return errors.New("qualification passed is invalid")
	}
	checksRaw := object["checks"]
	var checks []json.RawMessage
	if json.Unmarshal(checksRaw, &checks) != nil || len(checks) == 0 {
		return errors.New("qualification checks are invalid")
	}
	seen := map[string]struct{}{}
	for _, raw := range checks {
		check, err := bridgeJSONObject(raw)
		if err != nil {
			return err
		}
		if err := bridgeAllowed(check, []string{"name", "passed", "provenance"}, "name", "passed", "provenance", "evidence_sha256", "detail"); err != nil {
			return err
		}
		name, ok := bridgeString(check, "name")
		if !ok {
			return errors.New("qualification check name is invalid")
		}
		if _, duplicate := seen[name]; duplicate {
			return errors.New("qualification check name is duplicated")
		}
		seen[name] = struct{}{}
		var passed bool
		if json.Unmarshal(check["passed"], &passed) != nil {
			return errors.New("qualification check passed is invalid")
		}
		provenance, ok := bridgeString(check, "provenance")
		if !ok || provenance != "live" && provenance != "local_authoritative" {
			return errors.New("qualification check provenance is invalid")
		}
		if _, ok := check["evidence_sha256"]; ok && !bridgeSHA256(check, "evidence_sha256") {
			return errors.New("qualification check evidence digest is invalid")
		}
	}
	return nil
}

func validateBridgeSession(object map[string]json.RawMessage) error {
	required := []string{"schema_version", "success", "profile", "transport", "identity_sha256", "policy", "policy_sha256", "config_sha256", "binary_sha256", "cwd_sha256", "worktree_sha256", "dispatched", "admission", "receipt", "telemetry"}
	allowed := append(required, "failure_code", "error_sha256", "attestation")
	if err := bridgeAllowed(object, required, allowed...); err != nil {
		return err
	}
	if schema, _ := bridgeString(object, "schema_version"); schema != "ntm.provider-session.v2" {
		return errors.New("session schema mismatch")
	}
	if transport, _ := bridgeString(object, "transport"); transport != "xai_headless_session" {
		return errors.New("session transport mismatch")
	}
	for _, name := range []string{"identity_sha256", "policy_sha256", "config_sha256", "binary_sha256", "cwd_sha256", "worktree_sha256"} {
		if !bridgeSHA256(object, name) {
			return fmt.Errorf("invalid session digest %q", name)
		}
	}
	for _, name := range []string{"profile", "policy"} {
		if _, ok := bridgeString(object, name); !ok {
			return fmt.Errorf("invalid session field %q", name)
		}
	}
	for _, name := range []string{"success", "dispatched"} {
		var value bool
		if json.Unmarshal(object[name], &value) != nil {
			return fmt.Errorf("session field %q is not boolean", name)
		}
	}
	if value, ok := object["error_sha256"]; ok {
		var digest string
		if json.Unmarshal(value, &digest) != nil || !bridgeSHA256Pattern.MatchString(digest) {
			return errors.New("invalid session error digest")
		}
	}
	if err := validateBridgeAdmission(object); err != nil {
		return err
	}
	if err := validateBridgeSessionReceipt(object); err != nil {
		return err
	}
	return validateBridgeTelemetry(object)
}

func validateBridgeSessionReceipt(object map[string]json.RawMessage) error {
	receipt, ok := bridgeObject(object, "receipt")
	if !ok {
		return errors.New("session receipt is not an object")
	}
	required := []string{"action", "fork", "parent_session_sha256", "cwd_sha256", "worktree_sha256", "policy_sha256", "lineage_bound", "provider_acknowledged", "completion_confirmed", "stderr", "cancellation"}
	allowed := append(required, "child_session_sha256", "config_sha256", "binary_sha256", "nonce_sha256", "stop_reason", "requested_model", "expected_receipt_model", "model", "model_evidence", "usage", "output_sha256", "exit_code")
	if err := bridgeAllowed(receipt, required, allowed...); err != nil {
		return err
	}
	for _, name := range []string{"parent_session_sha256", "cwd_sha256", "worktree_sha256", "policy_sha256"} {
		if !bridgeSHA256(receipt, name) {
			return fmt.Errorf("invalid session receipt digest %q", name)
		}
	}
	for _, name := range []string{"child_session_sha256", "config_sha256", "binary_sha256", "nonce_sha256", "output_sha256"} {
		if _, ok := receipt[name]; ok && !bridgeSHA256(receipt, name) {
			return fmt.Errorf("invalid session receipt digest %q", name)
		}
	}
	if action, ok := bridgeString(receipt, "action"); !ok || action != "resume" && action != "fork" {
		return errors.New("session receipt action is invalid")
	}
	_, hasRequestedModel := receipt["requested_model"]
	_, hasExpectedReceiptModel := receipt["expected_receipt_model"]
	if hasRequestedModel != hasExpectedReceiptModel {
		return errors.New("session receipt model binding is incomplete")
	}
	for _, name := range []string{"stop_reason", "requested_model", "expected_receipt_model", "model", "model_evidence"} {
		if _, present := receipt[name]; present {
			value, valid := bridgeString(receipt, name)
			if !valid || len(value) > 4096 || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
				return fmt.Errorf("session receipt field %q is invalid", name)
			}
		}
	}
	for _, name := range []string{"fork", "lineage_bound", "provider_acknowledged", "completion_confirmed"} {
		var value bool
		if json.Unmarshal(receipt[name], &value) != nil {
			return fmt.Errorf("session receipt field %q is not boolean", name)
		}
	}
	stderr, ok := bridgeObject(receipt, "stderr")
	if !ok || bridgeAllowed(stderr, []string{"bytes", "sha256", "truncated"}, "bytes", "sha256", "truncated") != nil || !bridgeSHA256(stderr, "sha256") {
		return errors.New("session stderr digest is invalid")
	}
	cancellation, ok := bridgeObject(receipt, "cancellation")
	if !ok || bridgeAllowed(cancellation, []string{"provider_acknowledged", "local_termination", "residual_pids", "observed_at"}, "provider_acknowledged", "local_termination", "residual_pids", "observed_at") != nil || !bridgeTimestamp(cancellation, "observed_at") {
		return errors.New("session cancellation receipt is invalid")
	}
	var providerAcknowledged bool
	var residualPIDs []int32
	if _, valid := bridgeString(cancellation, "local_termination"); !valid || json.Unmarshal(cancellation["provider_acknowledged"], &providerAcknowledged) != nil || json.Unmarshal(cancellation["residual_pids"], &residualPIDs) != nil || residualPIDs == nil {
		return errors.New("session cancellation receipt fields are invalid")
	}
	return nil
}
