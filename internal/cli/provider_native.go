package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/state"
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

const (
	providerNativeRunSchema      = "ntm.provider-native-run.v1"
	providerNativeAdapterVersion = "zai-native-http-v1"
	providerNativeRunTimeout     = 2 * time.Minute
	providerNativeOperationScope = "provider:zai-native-http"
)

type providerNativeRunOptions struct {
	profile     string
	prompt      string
	operationID string
	live        bool
}

// providerNativeOperationLedger is deliberately the existing durable
// send-operation ledger. Native requests never use stale takeover: after a
// request reaches the client boundary, its remote outcome is unknowable until
// an authoritative receipt is persisted.
type providerNativeOperationLedger interface {
	ClaimSendOperation(*state.SendOperation) (*state.SendOperation, bool, error)
	ReleaseSendOperation(operationID, sessionName string) error
	CompleteSendOperation(operationID, sessionName, outcomeJSON string, completedAt time.Time) error
}

type providerNativeAdmission interface {
	Acquire(provider.Identity) ratelimit.Decision
	Release(provider.Identity, ratelimit.Decision)
	RecordSuccess(provider.Identity)
	RecordResult(provider.Identity, ratelimit.ErrorClass, time.Duration) ratelimit.Decision
	CapacityStatus() ratelimit.CapacityStatus
}

type providerNativeRunDependencies struct {
	loadConfig func() *config.Config
	lookupEnv  func(string) (string, bool)
	newNonce   func() (string, error)
	run        func(context.Context, zai.NativeHTTPClient, zai.NativeRequest) (zai.NativeReceipt, error)
	client     zai.NativeHTTPClient
	admission  providerNativeAdmission
	openLedger func() (providerNativeOperationLedger, func() error, error)
	now        func() time.Time
}

var providerNativeRunDeps = providerNativeRunDependencies{
	loadConfig: loadSelectedConfigOrDefault,
	lookupEnv:  os.LookupEnv,
	newNonce:   providerNativeNonce,
	run:        zai.RunNative,
	client:     zai.DefaultNativeHTTPClient(),
	admission:  ratelimit.DefaultAdmissionController(),
	openLedger: openProviderNativeLedger,
	now:        func() time.Time { return time.Now().UTC() },
}

type providerNativeAdmissionEvidence struct {
	Allowed              bool                          `json:"allowed"`
	Reason               ratelimit.ErrorClass          `json:"reason,omitempty"`
	RetryAt              *time.Time                    `json:"retry_at,omitempty"`
	NoFailover           bool                          `json:"no_failover"`
	CapacityControlScope provider.CapacityControlScope `json:"capacity_control_scope"`
}

// providerNativeRunOutput deliberately contains no prompt, nonce, API key, or
// raw provider body. zai.NativeReceipt keeps identifiers hash-bound as well.
type providerNativeRunOutput struct {
	SchemaVersion      string                          `json:"schema_version"`
	Success            bool                            `json:"success"`
	Profile            string                          `json:"profile"`
	Transport          string                          `json:"transport"`
	IdentitySHA256     string                          `json:"identity_sha256"`
	AdapterVersion     string                          `json:"adapter_version"`
	OperationID        string                          `json:"operation_id"`
	BindingSHA256      string                          `json:"binding_sha256"`
	ReceiptState       string                          `json:"receipt_state"`
	Replayed           bool                            `json:"replayed"`
	State              string                          `json:"state"`
	Admission          providerNativeAdmissionEvidence `json:"admission"`
	Receipt            zai.NativeReceipt               `json:"receipt"`
	ProviderErrorClass provider.ErrorClass             `json:"provider_error_class,omitempty"`
	ErrorSHA256        string                          `json:"error_sha256,omitempty"`
}

func newProviderNativeRunCmd() *cobra.Command {
	opts := providerNativeRunOptions{}
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run one nonce-bound no-tool native Z.ai request",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProviderNative(cmd, opts, providerNativeRunDeps)
		},
	}
	cmd.Flags().StringVar(&opts.profile, "profile", "", "Exact configured native Z.ai provider profile (required)")
	cmd.Flags().StringVar(&opts.prompt, "prompt", "", "Prompt to execute (required; never retained)")
	cmd.Flags().StringVar(&opts.operationID, "operation-id", "", "Durable idempotency key required for --live; ambiguous operations are never automatically replayed")
	cmd.Flags().BoolVar(&opts.live, "live", false, "Explicitly authorize one real native Z.ai API request")
	return cmd
}

func runProviderNative(cmd *cobra.Command, opts providerNativeRunOptions, deps providerNativeRunDependencies) error {
	if strings.TrimSpace(opts.profile) == "" || strings.TrimSpace(opts.prompt) == "" {
		return errors.New("provider run requires exact --profile and --prompt values")
	}
	if !opts.live {
		return errors.New("provider run makes a real native Z.ai API request; pass --live to authorize it")
	}
	opID := strings.TrimSpace(opts.operationID)
	if !validProviderNativeOperationID(opID) {
		return errors.New("provider run requires --operation-id with 1-128 letters, digits, dot, colon, underscore, or hyphen")
	}
	if deps.loadConfig == nil || deps.lookupEnv == nil || deps.newNonce == nil || deps.run == nil || deps.client == nil || deps.admission == nil || deps.openLedger == nil || deps.now == nil {
		return errors.New("provider native run dependencies are incomplete")
	}
	cfg := deps.loadConfig()
	if cfg == nil {
		return errors.New("provider run requires loaded configuration")
	}
	profile, err := cfg.ProviderProfile(opts.profile)
	if err != nil {
		return err
	}
	identity, err := profile.Identity()
	if err != nil {
		return err
	}
	if identity.Provider() != "zai" || identity.Entitlement() != provider.EntitlementNativeAPI || identity.CredentialClass() != provider.CredentialClassAPIKey || identity.BillingClass() != provider.BillingClassAPIUsage || identity.Runtime() != "zai-api" || identity.Endpoint() != zai.NativeChatCompletionsEndpoint || profile.Command != "" || profile.AutomationPolicy != provider.NativeZAINoToolsPolicyName || !profile.ExactTargetOnly || !profile.ProbeRequired || profile.RuntimeVersion != providerNativeAdapterVersion {
		return errors.New("provider run requires an exact pinned Z.ai native_api profile")
	}
	key, keyPresent := deps.lookupEnv("ZAI_NATIVE_API_KEY")
	if !keyPresent || strings.TrimSpace(key) == "" {
		return errors.New("provider run requires ZAI_NATIVE_API_KEY; other provider credentials are not accepted")
	}
	status := deps.admission.CapacityStatus()
	if status.Scope != provider.CapacityControlScopeLocalShared {
		return errors.New("provider run requires the cross-process local shared capacity store")
	}
	logicalPrompt := strings.TrimSpace(opts.prompt)
	binding := providerNativeBindingHash(identity, logicalPrompt)
	requestID := providerNativeRequestID(binding, opID)
	output := providerNativeRunOutput{SchemaVersion: providerNativeRunSchema, Profile: opts.profile, Transport: "zai_native_api", IdentitySHA256: identity.Hash(), AdapterVersion: providerNativeAdapterVersion, OperationID: opID, BindingSHA256: binding, ReceiptState: "not_claimed", State: "preflight"}
	ledger, closeLedger, err := deps.openLedger()
	if err != nil || ledger == nil {
		output.State, output.ReceiptState = "ledger_unavailable", "claim_failed"
		output.ErrorSHA256 = safeErrorDigest(err)
		return finishProviderNative(cmd, output, errors.New("provider run requires a healthy durable operation ledger before dispatch"))
	}
	if closeLedger != nil {
		defer func() { _ = closeLedger() }()
	}
	claimed, wonClaim, claimErr := ledger.ClaimSendOperation(&state.SendOperation{
		OperationID: opID, SessionName: providerNativeOperationScope, BindingHash: binding,
		PayloadSHA256: sha256StringCLI(logicalPrompt), PayloadBytes: int64(len(logicalPrompt)), CreatedAt: deps.now(),
	})
	if claimErr != nil {
		output.State, output.ReceiptState = "ledger_unavailable", "claim_failed"
		output.ErrorSHA256 = safeErrorDigest(claimErr)
		return finishProviderNative(cmd, output, errors.New("provider run durable operation claim failed before dispatch"))
	}
	if !wonClaim {
		if claimed.BindingHash != binding {
			output.State, output.ReceiptState = "binding_conflict", "conflict"
			output.ErrorSHA256 = sha256StringCLI("binding_conflict")
			return finishProviderNative(cmd, output, errors.New("operation ID is already bound to a different native Z.ai identity, prompt, policy, or adapter"))
		}
		if claimed.Status != state.SendOperationCompleted {
			output.State, output.ReceiptState = "outcome_unknown", "outcome_unknown"
			output.ErrorSHA256 = sha256StringCLI("outcome_unknown")
			return finishProviderNative(cmd, output, errors.New("native Z.ai operation is already in progress or has an unrecorded outcome; do not redispatch"))
		}
		if err := json.Unmarshal([]byte(claimed.OutcomeJSON), &output); err != nil {
			output.State, output.ReceiptState = "outcome_unknown", "corrupt"
			output.ErrorSHA256 = safeErrorDigest(err)
			return finishProviderNative(cmd, output, errors.New("stored native Z.ai operation receipt is unreadable; do not redispatch"))
		}
		if !validRecordedProviderNativeOutput(output, opID, binding, opts.profile, identity.Hash()) {
			output.Success, output.State, output.ReceiptState = false, "outcome_unknown", "corrupt"
			output.ErrorSHA256 = sha256StringCLI("stored_receipt_binding_mismatch")
			return finishProviderNative(cmd, output, errors.New("stored native Z.ai operation receipt does not match its durable binding; do not redispatch"))
		}
		output.Replayed, output.ReceiptState = true, "replayed"
		return finishProviderNative(cmd, output, providerNativeRecordedError(output))
	}
	output.ReceiptState, output.State = "claimed", "admission_pending"
	decision := deps.admission.Acquire(identity)
	admission := providerNativeAdmissionEvidence{Allowed: decision.Allowed, Reason: decision.Reason, RetryAt: decision.RetryAt, NoFailover: decision.NoFailover, CapacityControlScope: status.Scope}
	output.Admission = admission
	if !decision.Allowed || !decision.NoFailover {
		output.State = "admission_denied"
		output.ProviderErrorClass = provider.ErrorClass(decision.Reason)
		output.ErrorSHA256 = sha256StringCLI(string(decision.Reason) + fmt.Sprint(decision.NoFailover))
		if decision.Allowed {
			deps.admission.Release(identity, decision)
		}
		if releaseErr := ledger.ReleaseSendOperation(claimed.OperationID, claimed.SessionName); releaseErr != nil {
			output.State, output.ReceiptState = "outcome_unknown", "release_failed"
			output.ErrorSHA256 = safeErrorDigest(releaseErr)
		}
		return finishProviderNative(cmd, output, errors.New("provider capacity admission denied for the exact Z.ai identity"))
	}
	defer deps.admission.Release(identity, decision)

	nonce, err := deps.newNonce()
	if err != nil {
		_ = ledger.ReleaseSendOperation(claimed.OperationID, claimed.SessionName)
		return err
	}
	prompt := logicalPrompt + "\n\nWhen finished, return this exact acknowledgement token on its own line and no other final text: " + nonce
	runCtx, cancel := context.WithTimeout(providerCommandContext(cmd), providerNativeRunTimeout)
	receipt, runErr := deps.run(runCtx, deps.client, zai.NativeRequest{Endpoint: identity.Endpoint(), Model: identity.Model(), Prompt: prompt, ExpectedNonce: nonce, ExpectedRequestID: requestID, NativeAPIKey: key, ExplicitOptIn: true, AllowTools: false})
	cancel()
	output.Receipt = receipt
	if runErr != nil {
		class := provider.ClassifyProviderError(receipt.HTTPStatus, receipt.ErrorCode)
		// Only a structured provider response is provider/account circuit
		// evidence. Local cancellation, DNS, TLS, and client/protocol failures
		// must not permanently poison the exact identity as "unknown".
		providerFailureObserved := receipt.ErrorCode != "" || receipt.HTTPStatus != 0 && (receipt.HTTPStatus < http.StatusOK || receipt.HTTPStatus >= http.StatusMultipleChoices)
		if providerFailureObserved {
			deps.admission.RecordResult(identity, class, 0)
		}
		output.ProviderErrorClass, output.ErrorSHA256 = class, safeErrorDigest(runErr)
		if !providerFailureObserved {
			// The request might have reached the provider. Keep the claim
			// in-progress forever rather than risking a duplicate paid run.
			output.State, output.ReceiptState = "outcome_unknown", "outcome_unknown"
			return finishProviderNative(cmd, output, runErr)
		}
		output.State, output.ReceiptState = "provider_failure", "completed"
		if persistErr := completeProviderNativeOperation(ledger, claimed, output, deps.now()); persistErr != nil {
			output.State, output.ReceiptState = "outcome_unknown", "persistence_failed"
			output.ErrorSHA256 = safeErrorDigest(persistErr)
			return finishProviderNative(cmd, output, errors.New("native Z.ai provider response was received but its durable receipt was not recorded; do not redispatch"))
		}
		return finishProviderNative(cmd, output, runErr)
	}
	deps.admission.RecordSuccess(identity)
	output.Success, output.State, output.ReceiptState = true, "completed", "completed"
	if persistErr := completeProviderNativeOperation(ledger, claimed, output, deps.now()); persistErr != nil {
		output.Success, output.State, output.ReceiptState = false, "outcome_unknown", "persistence_failed"
		output.ErrorSHA256 = safeErrorDigest(persistErr)
		return finishProviderNative(cmd, output, errors.New("native Z.ai request may have completed but its durable receipt was not recorded; do not redispatch"))
	}
	return finishProviderNative(cmd, output, nil)
}

func finishProviderNative(cmd *cobra.Command, output providerNativeRunOutput, runErr error) error {
	if IsJSONOutput() {
		if err := encodeIndentedJSON(cmd.OutOrStdout(), output); err != nil {
			return err
		}
		if runErr != nil {
			return errJSONFailure
		}
		return nil
	}
	if output.Success {
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "Native Z.ai request completed.\nOperation: %s (%s)\nIdentity: %s\nReceipt: %s\n", output.OperationID, output.ReceiptState, output.IdentitySHA256, digestSafeJSON(output.Receipt))
		return err
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Native Z.ai request failed.\nOperation: %s (%s)\nIdentity: %s\nReceipt: %s\n", output.OperationID, output.ReceiptState, output.IdentitySHA256, digestSafeJSON(output.Receipt)); err != nil {
		return err
	}
	return &providerNativeRunExitError{class: output.ProviderErrorClass}
}

func openProviderNativeLedger() (providerNativeOperationLedger, func() error, error) {
	store, err := state.Open("")
	if err != nil {
		return nil, nil, err
	}
	if err := store.Migrate(); err != nil {
		_ = store.Close()
		return nil, nil, err
	}
	return store, store.Close, nil
}

func validProviderNativeOperationID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '-', '_', '.', ':':
			continue
		default:
			return false
		}
	}
	return true
}

func providerNativeBindingHash(identity provider.Identity, prompt string) string {
	fields := []string{
		"ntm.zai-native.binding.v1", identity.Hash(), sha256StringCLI(strings.TrimSpace(prompt)),
		sha256StringCLI(provider.NativeZAINoToolsPolicyName), sha256StringCLI(providerNativeAdapterVersion),
	}
	return sha256StringCLI(strings.Join(fields, "\x00"))
}

// providerNativeRequestID is deterministic from the durable binding and exact
// operation ID, not from raw prompt or credential material. Including the
// operation ID keeps distinct authorized operations unique even when their
// identity and prompt are identical. Its 64 ASCII characters meet Z.ai's
// documented request_id size limit while durable receipts retain only hashes.
func providerNativeRequestID(binding, operationID string) string {
	correlation := strings.Join([]string{"ntm.zai-native.request-id.v1", binding, operationID}, "\x00")
	return "ntm-" + sha256StringCLI(correlation)[:60]
}

func validRecordedProviderNativeOutput(output providerNativeRunOutput, operationID, binding, profile, identitySHA256 string) bool {
	return output.SchemaVersion == providerNativeRunSchema &&
		output.Transport == "zai_native_api" &&
		output.AdapterVersion == providerNativeAdapterVersion &&
		output.OperationID == operationID &&
		output.BindingSHA256 == binding &&
		output.Profile == profile &&
		output.IdentitySHA256 == identitySHA256 &&
		output.ReceiptState == "completed" &&
		(output.State == "completed" || output.State == "provider_failure")
}

func completeProviderNativeOperation(ledger providerNativeOperationLedger, claimed *state.SendOperation, output providerNativeRunOutput, completedAt time.Time) error {
	if ledger == nil || claimed == nil {
		return errors.New("native operation ledger is unavailable")
	}
	data, err := json.Marshal(output)
	if err != nil {
		return fmt.Errorf("encode native operation receipt: %w", err)
	}
	if err := ledger.CompleteSendOperation(claimed.OperationID, claimed.SessionName, string(data), completedAt); err != nil {
		return fmt.Errorf("persist native operation receipt: %w", err)
	}
	return nil
}

func providerNativeRecordedError(output providerNativeRunOutput) error {
	if output.Success {
		return nil
	}
	return &providerNativeRunExitError{class: output.ProviderErrorClass}
}

type providerNativeRunExitError struct{ class provider.ErrorClass }

func (e *providerNativeRunExitError) Error() string {
	if e.class == "" {
		return "native Z.ai provider request failed"
	}
	return "native Z.ai provider request failed: " + string(e.class)
}
func (*providerNativeRunExitError) ExitCode() int { return 1 }

func providerNativeNonce() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate provider native nonce: %w", err)
	}
	return "NTM_ACK_" + hex.EncodeToString(raw), nil
}
