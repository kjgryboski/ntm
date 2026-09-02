package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/providertelemetry"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/state"
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

const (
	providerNativeRunSchema      = "ntm.provider-native-run.v2"
	providerNativeAdapterVersion = "zai-native-http-v1"
	providerNativeRunTimeout     = 2 * time.Minute
	providerNativeOperationScope = "provider:zai-native-http"
)

type providerNativeRunOptions struct {
	profile          string
	prompt           string
	operationID      string
	live             bool
	tools            bool
	worktree         string
	revision         string
	commands         []string
	qualificationDir string
	qualificationAge time.Duration
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
	loadConfig         func() *config.Config
	credential         providerCredentialStore
	newNonce           func() (string, error)
	run                func(context.Context, zai.NativeHTTPClient, zai.NativeRequest) (zai.NativeReceipt, error)
	runTools           func(context.Context, zai.NativeHTTPClient, zai.NativeToolRequest) (zai.NativeToolReceipt, error)
	newController      func(context.Context, providerNativeRunOptions) (providerNativeToolController, error)
	sign               func(context.Context, []byte) (providerattestation.SignatureMetadata, error)
	recordTelemetry    func(context.Context, providertelemetry.Observation) (providertelemetry.Observation, error)
	qualificationStore func(string, string) (providerqualification.Receipt, string, error)
	client             zai.NativeHTTPClient
	admission          providerNativeAdmission
	openLedger         func() (providerNativeOperationLedger, func() error, error)
	now                func() time.Time
}

var providerNativeRunDeps = providerNativeRunDependencies{
	loadConfig:         loadSelectedConfigOrDefault,
	credential:         providerCredentialDeps.store,
	newNonce:           providerNativeNonce,
	run:                zai.RunNative,
	runTools:           zai.RunNativeTools,
	newController:      newProviderNativeController,
	sign:               signProviderReceiptPayload,
	recordTelemetry:    recordProviderTelemetryDefault,
	qualificationStore: providerqualification.LoadLatest,
	client:             zai.DefaultNativeHTTPClient(),
	admission:          ratelimit.DefaultAdmissionController(),
	openLedger:         openProviderNativeLedger,
	now:                func() time.Time { return time.Now().UTC() },
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
	SchemaVersion       string                                 `json:"schema_version"`
	Success             bool                                   `json:"success"`
	Profile             string                                 `json:"profile"`
	Transport           string                                 `json:"transport"`
	IdentitySHA256      string                                 `json:"identity_sha256"`
	AdapterVersion      string                                 `json:"adapter_version"`
	Tools               bool                                   `json:"tools"`
	QualificationSHA256 string                                 `json:"qualification_receipt_sha256,omitempty"`
	OperationID         string                                 `json:"operation_id"`
	BindingSHA256       string                                 `json:"binding_sha256"`
	ReceiptState        string                                 `json:"receipt_state"`
	Replayed            bool                                   `json:"replayed"`
	State               string                                 `json:"state"`
	Admission           providerNativeAdmissionEvidence        `json:"admission"`
	Receipt             zai.NativeReceipt                      `json:"receipt"`
	ToolReceipt         *zai.NativeToolReceipt                 `json:"tool_receipt,omitempty"`
	Controller          *providerNativeControllerReceipt       `json:"controller,omitempty"`
	ProviderErrorClass  provider.ErrorClass                    `json:"provider_error_class,omitempty"`
	ErrorSHA256         string                                 `json:"error_sha256,omitempty"`
	Telemetry           providerTelemetryEvidence              `json:"telemetry"`
	Attestation         *providerattestation.SignatureMetadata `json:"attestation,omitempty"`
}

func newProviderNativeRunCmd() *cobra.Command {
	opts := providerNativeRunOptions{qualificationAge: 24 * time.Hour}
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run one nonce-bound native Z.ai request",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProviderNative(cmd, opts, providerNativeRunDeps)
		},
	}
	cmd.Flags().StringVar(&opts.profile, "profile", "", "Exact configured native Z.ai provider profile (required)")
	cmd.Flags().StringVar(&opts.prompt, "prompt", "", "Prompt to execute (required; never retained)")
	cmd.Flags().StringVar(&opts.operationID, "operation-id", "", "Durable idempotency key required for --live; ambiguous operations are never automatically replayed")
	cmd.Flags().BoolVar(&opts.live, "live", false, "Explicitly authorize one real native Z.ai API request")
	cmd.Flags().BoolVar(&opts.tools, "tools", false, "Enable controller-owned workspace tools for a separately qualified tools profile")
	cmd.Flags().StringVar(&opts.worktree, "worktree", "", "Exact linked disposable worktree used by --tools")
	cmd.Flags().StringVar(&opts.revision, "revision", "", "Exact current Git revision used by --tools")
	cmd.Flags().StringSliceVar(&opts.commands, "verify-commands", nil, "Fixed approved verifier IDs used by --tools")
	cmd.Flags().StringVar(&opts.qualificationDir, "qualification-store", "", "Override native tools qualification receipt directory")
	cmd.Flags().DurationVar(&opts.qualificationAge, "max-qualification-age", opts.qualificationAge, "Maximum age of the signed native tools qualification")
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
	if deps.loadConfig == nil || deps.credential == nil || deps.newNonce == nil || deps.client == nil || deps.admission == nil || deps.openLedger == nil || deps.now == nil || deps.sign == nil || deps.recordTelemetry == nil || !opts.tools && deps.run == nil || opts.tools && (deps.runTools == nil || deps.newController == nil || deps.qualificationStore == nil) {
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
	expectedPolicy := provider.NativeZAINoToolsPolicyName
	if opts.tools {
		expectedPolicy = provider.NativeZAIToolsPolicyName
	}
	if identity.Provider() != "zai" || identity.Entitlement() != provider.EntitlementNativeAPI || identity.CredentialClass() != provider.CredentialClassAPIKey || identity.BillingClass() != provider.BillingClassAPIUsage || identity.Runtime() != "zai-api" || identity.Endpoint() != zai.NativeChatCompletionsEndpoint || profile.Command != "" || profile.AutomationPolicy != expectedPolicy || !profile.ExactTargetOnly || !profile.ProbeRequired || profile.RuntimeVersion != providerNativeAdapterVersion {
		return errors.New("provider run requires an exact pinned Z.ai native_api profile")
	}
	if opts.tools && (strings.TrimSpace(opts.worktree) == "" || strings.TrimSpace(opts.revision) == "" || len(opts.commands) == 0 || opts.qualificationAge <= 0) {
		return errors.New("provider run --tools requires an exact --worktree, --revision, and --verify-commands manifest")
	}
	qualificationSHA256 := ""
	if opts.tools {
		qualificationSHA256, err = requireProviderNativeToolsQualification(identity, opts, deps)
		if err != nil {
			return err
		}
	}
	if err := preflightProviderReceiptSigner(providerCommandContext(cmd), deps.sign); err != nil {
		return fmt.Errorf("provider run requires an initialized receipt signing key before dispatch: %w", err)
	}
	keyBytes, credentialErr := deps.credential.Get(providerCommandContext(cmd), providerCredentialID(identity))
	if credentialErr != nil || len(keyBytes) == 0 {
		return errors.New("provider run requires the exact native Z.ai credential in OS-protected storage")
	}
	defer zeroProviderSecret(keyBytes)
	key := string(keyBytes)
	status := deps.admission.CapacityStatus()
	if status.Scope != provider.CapacityControlScopeLocalShared {
		return errors.New("provider run requires the cross-process local shared capacity store")
	}
	logicalPrompt := strings.TrimSpace(opts.prompt)
	binding := providerNativeBindingHashForPolicy(identity, logicalPrompt, expectedPolicy, providerNativeToolManifestBinding(opts))
	requestID := providerNativeRequestID(binding, opID)
	output := providerNativeRunOutput{SchemaVersion: providerNativeRunSchema, Profile: opts.profile, Transport: "zai_native_api", IdentitySHA256: identity.Hash(), AdapterVersion: providerNativeAdapterVersion, Tools: opts.tools, QualificationSHA256: qualificationSHA256, OperationID: opID, BindingSHA256: binding, ReceiptState: "not_claimed", State: "preflight"}
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
	var receipt zai.NativeReceipt
	var runErr error
	if opts.tools {
		controller, controllerErr := deps.newController(runCtx, opts)
		if controllerErr != nil {
			cancel()
			_ = ledger.ReleaseSendOperation(claimed.OperationID, claimed.SessionName)
			return finishProviderNative(cmd, output, controllerErr)
		}
		toolReceipt, toolErr := deps.runTools(runCtx, deps.client, zai.NativeToolRequest{
			NativeRequest: zai.NativeRequest{Endpoint: identity.Endpoint(), Model: identity.Model(), Prompt: prompt, ExpectedNonce: nonce, ExpectedRequestID: requestID, NativeAPIKey: key, ExplicitOptIn: true, AllowTools: true},
			Tools:         providerNativeToolDefinitions(), Executor: controller,
		})
		output.ToolReceipt = &toolReceipt
		controllerReceipt := controller.Receipt()
		output.Controller = &controllerReceipt
		receipt, runErr = toolReceipt.NativeReceipt, toolErr
		if runErr == nil && !controller.CompletedVerification() {
			runErr = errors.New("native Z.ai tool run completed without a revision-bound controller verification after its last write")
		}
	} else {
		receipt, runErr = deps.run(runCtx, deps.client, zai.NativeRequest{Endpoint: identity.Endpoint(), Model: identity.Model(), Prompt: prompt, ExpectedNonce: nonce, ExpectedRequestID: requestID, NativeAPIKey: key, ExplicitOptIn: true, AllowTools: false})
	}
	cancel()
	output.Receipt = receipt
	if runErr != nil {
		class := provider.ClassifyProviderError(receipt.HTTPStatus, receipt.ErrorCode)
		// Only a structured provider response is provider/account circuit
		// evidence. Local cancellation, DNS, TLS, and client/protocol failures
		// must not permanently poison the exact identity as "unknown".
		providerFailureObserved := receipt.ErrorCode != "" || receipt.HTTPStatus != 0 && (receipt.HTTPStatus < http.StatusOK || receipt.HTTPStatus >= http.StatusMultipleChoices)
		circuitDecision := ratelimit.Decision{NoFailover: true}
		circuitState := "unchanged"
		if providerFailureObserved {
			circuitDecision = deps.admission.RecordResult(identity, class, 0)
			circuitState = "terminal"
			if circuitDecision.RetryAt != nil {
				circuitState = "retry_scheduled"
			}
		}
		output.ProviderErrorClass, output.ErrorSHA256 = class, safeErrorDigest(runErr)
		output.Telemetry = recordProviderTelemetryEvidence(providerCommandContext(cmd), deps.recordTelemetry, providerNativeTelemetryObservation(identity, expectedPolicy, receipt, class, circuitState, circuitDecision, deps.now()))
		if !providerFailureObserved {
			// The request might have reached the provider. Keep the claim
			// in-progress forever rather than risking a duplicate paid run.
			output.State, output.ReceiptState = "outcome_unknown", "outcome_unknown"
			return finishProviderNative(cmd, output, runErr)
		}
		output.State, output.ReceiptState = "provider_failure", "completed"
		if signErr := sealProviderNativeOutput(providerCommandContext(cmd), &output, deps.sign); signErr != nil {
			output.State, output.ReceiptState = "outcome_unknown", "attestation_failed"
			output.ErrorSHA256 = safeErrorDigest(signErr)
			return finishProviderNative(cmd, output, errors.New("native Z.ai provider response was received but its receipt could not be attested; do not redispatch"))
		}
		if persistErr := completeProviderNativeOperation(ledger, claimed, output, deps.now()); persistErr != nil {
			output.State, output.ReceiptState = "outcome_unknown", "persistence_failed"
			output.ErrorSHA256 = safeErrorDigest(persistErr)
			return finishProviderNative(cmd, output, errors.New("native Z.ai provider response was received but its durable receipt was not recorded; do not redispatch"))
		}
		return finishProviderNative(cmd, output, runErr)
	}
	deps.admission.RecordSuccess(identity)
	output.Success, output.State, output.ReceiptState = true, "completed", "completed"
	output.Telemetry = recordProviderTelemetryEvidence(providerCommandContext(cmd), deps.recordTelemetry, providerNativeTelemetryObservation(identity, expectedPolicy, receipt, "", "closed", decision, deps.now()))
	if signErr := sealProviderNativeOutput(providerCommandContext(cmd), &output, deps.sign); signErr != nil {
		output.Success, output.State, output.ReceiptState = false, "outcome_unknown", "attestation_failed"
		output.ErrorSHA256 = safeErrorDigest(signErr)
		return finishProviderNative(cmd, output, errors.New("native Z.ai request completed but its receipt could not be attested; do not redispatch"))
	}
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
	return providerNativeBindingHashForPolicy(identity, prompt, provider.NativeZAINoToolsPolicyName, "")
}

func providerNativeBindingHashForPolicy(identity provider.Identity, prompt, policy, extra string) string {
	fields := []string{
		"ntm.zai-native.binding.v1", identity.Hash(), sha256StringCLI(strings.TrimSpace(prompt)),
		sha256StringCLI(policy), sha256StringCLI(providerNativeAdapterVersion), sha256StringCLI(extra),
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
	if output.Attestation == nil {
		return false
	}
	payload, err := canonicalProviderNativeOutput(output)
	if err != nil || providerattestation.Verify(payload, *output.Attestation) != nil {
		return false
	}
	toolsEvidenceValid := !output.Tools && output.QualificationSHA256 == "" && output.ToolReceipt == nil && output.Controller == nil ||
		output.Tools && validProviderNativeDigest(output.QualificationSHA256) && output.ToolReceipt != nil && output.Controller != nil
	return output.SchemaVersion == providerNativeRunSchema &&
		output.Transport == "zai_native_api" &&
		output.AdapterVersion == providerNativeAdapterVersion &&
		output.OperationID == operationID &&
		output.BindingSHA256 == binding &&
		output.Profile == profile &&
		output.IdentitySHA256 == identitySHA256 &&
		toolsEvidenceValid &&
		validProviderTelemetryEvidence(output.Telemetry) &&
		output.ReceiptState == "completed" &&
		(output.State == "completed" || output.State == "provider_failure")
}

func requireProviderNativeToolsQualification(identity provider.Identity, opts providerNativeRunOptions, deps providerNativeRunDependencies) (string, error) {
	receipt, _, err := deps.qualificationStore(opts.qualificationDir, identity.Hash())
	if err != nil {
		return "", errors.New("provider run --tools requires a current signed native tools qualification receipt")
	}
	if err := receipt.Validate(); err != nil {
		return "", fmt.Errorf("provider run --tools qualification receipt is invalid: %w", err)
	}
	if receipt.Attestation == nil || !receipt.Passed || receipt.Provider != "zai" || receipt.Transport != "zai_native_api" || receipt.IdentitySHA256 != identity.Hash() || receipt.PolicySHA256 != providerNativeToolsPolicySHA256() || receipt.RuntimeVersion != providerNativeAdapterVersion {
		return "", errors.New("provider run --tools qualification does not bind the exact identity, transport, policy, adapter, and complete live matrix")
	}
	now := deps.now().UTC()
	if receipt.CompletedAt.After(now) || now.Sub(receipt.CompletedAt) > opts.qualificationAge {
		return "", errors.New("provider run --tools qualification receipt is future-dated or stale")
	}
	return receipt.ReceiptSHA256, nil
}

func validProviderNativeDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func providerNativeTelemetryObservation(identity provider.Identity, policyName string, receipt zai.NativeReceipt, class provider.ErrorClass, circuitState string, decision ratelimit.Decision, observedAt time.Time) providertelemetry.Observation {
	completedAt := receipt.CompletedAt
	if completedAt.IsZero() {
		completedAt = observedAt.UTC()
	}
	return providerTelemetryObservation(providerTelemetryObservationInput{
		Identity: identity, Model: identity.Model(), Transport: "zai_native_api", Adapter: providerNativeAdapterVersion,
		Runtime: identity.Runtime(), PolicySHA256: agentlessNativePolicySHA256(policyName), FixtureVersion: "zai-native-v4-v1",
		StartedAt: receipt.StartedAt, CompletedAt: completedAt,
		InputTokens: nativeUsageValue(receipt.Usage.InputTokens), OutputTokens: nativeUsageValue(receipt.Usage.OutputTokens), CachedTokens: nativeUsageValue(receipt.Usage.CachedInputTokens),
		ProviderError: class, QuotaState: providerTelemetryQuotaState(class), CircuitState: circuitState, CircuitOpenUntil: decision.RetryAt, NoFailover: decision.NoFailover,
	})
}

func agentlessNativePolicySHA256(policyName string) string {
	switch policyName {
	case provider.NativeZAIToolsPolicyName:
		return providerNativeToolsPolicySHA256()
	default:
		return providerNativeNoToolsPolicySHA256()
	}
}

func nativeUsageValue(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

func sealProviderNativeOutput(ctx context.Context, output *providerNativeRunOutput, sign func(context.Context, []byte) (providerattestation.SignatureMetadata, error)) error {
	if output == nil || sign == nil {
		return errors.New("native provider receipt attestor is unavailable")
	}
	payload, err := canonicalProviderNativeOutput(*output)
	if err != nil {
		return err
	}
	signature, err := sign(ctx, payload)
	if err != nil {
		return err
	}
	if err := providerattestation.Verify(payload, signature); err != nil {
		return errors.New("native provider receipt attestation verification failed")
	}
	output.Attestation = &signature
	return nil
}

func canonicalProviderNativeOutput(output providerNativeRunOutput) ([]byte, error) {
	output.Attestation = nil
	return json.Marshal(output)
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
