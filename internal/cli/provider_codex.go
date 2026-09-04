package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/state"
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

const (
	providerCodexRunSchema              = "ntm.provider-codex-run.v1"
	providerCodexRunTimeout             = 20 * time.Minute
	providerCodexOperationScope         = "provider:zai-codex-runtime"
	providerCodexWorkloadImplementation = "implementation"
	providerCodexWorkloadReview         = "review"
	providerCodexWorkloadBulk           = "bulk"
	providerCodexTerminalModelEvidence  = "turn.completed.server_model"
	providerCodexQualificationModelGate = "terminal_turn_completed_server_model_exact_match"
)

// providerCodexSubscriptionAdmission is intentionally distinct from the
// generic native-API admission interface. The Coding Plan lane holds both an
// exact-identity lease and a shared subscription lease, and reconciliation
// only accepts provider-resolved usage.
type providerCodexSubscriptionAdmission interface {
	Acquire(provider.Identity) ratelimit.SubscriptionDecision
	Release(provider.Identity, ratelimit.SubscriptionDecision)
	RecordUsage(provider.Identity, ratelimit.SubscriptionDecision, string, ratelimit.TokenUsage, time.Time) error
	RecordConservativeUsage(provider.Identity, ratelimit.SubscriptionDecision, ratelimit.TokenUsage, time.Time) error
	BindReservation(provider.Identity, ratelimit.SubscriptionDecision, string, string) error
	// RecordUnknownUsage must conservatively reserve/freeze the subscription
	// scope after a process was dispatched but its cost cannot be reconciled.
	// It is intentionally not a retry or provider-selection hook.
	RecordUnknownUsage(provider.Identity, ratelimit.SubscriptionDecision) error
	// CancelReservation is valid only when the controller can prove the
	// provider process never started.
	CancelReservation(provider.Identity, ratelimit.SubscriptionDecision) error
	RecordSuccess(provider.Identity)
	RecordResult(provider.Identity, ratelimit.ErrorClass, time.Duration) ratelimit.Decision
	CapacityStatus() ratelimit.CapacityStatus
}

var (
	providerCodexSubscriptionAdmissionOnce    sync.Once
	providerCodexSubscriptionAdmissionDefault *ratelimit.SubscriptionAdmissionController
)

func defaultProviderCodexSubscriptionAdmission() *ratelimit.SubscriptionAdmissionController {
	providerCodexSubscriptionAdmissionOnce.Do(func() {
		storePath := ""
		if base, err := os.UserConfigDir(); err == nil && base != "" {
			storePath = filepath.Join(base, "ntm", "zai-coding-plan-capacity.json")
		}
		controller, err := ratelimit.NewSubscriptionAdmissionController(ratelimit.DefaultSubscriptionAdmissionConfig(), storePath, nil, nil)
		if err != nil {
			// Keep the failure visible to the caller: runProviderCodex requires a
			// local shared store and will refuse dispatch from this fallback.
			controller, err = ratelimit.NewSubscriptionAdmissionController(ratelimit.DefaultSubscriptionAdmissionConfig(), "", nil, nil)
			if err != nil {
				panic(err)
			}
		}
		providerCodexSubscriptionAdmissionDefault = controller
	})
	return providerCodexSubscriptionAdmissionDefault
}

type providerCodexRunOptions struct {
	profile          string
	prompt           string
	operationID      string
	cwd              string
	parentSession    string
	workloadClass    string
	live             bool
	workspaceWrite   bool
	timeout          time.Duration
	qualificationDir string
	qualificationAge time.Duration
}

type providerCodexRunDependencies struct {
	loadConfig         func() *config.Config
	attest             func(context.Context, zai.CodexManifestExpectation) (zai.CodexManifestAttestation, error)
	run                func(context.Context, zai.CodexRunSpec) (zai.CodexRunReceipt, error)
	newNonce           func() (string, error)
	isLinkedWorktree   func(context.Context, string) (bool, error)
	sign               func(context.Context, []byte) (providerattestation.SignatureMetadata, error)
	pinnedSigner       func(config.ProviderProfileConfig) (func(context.Context, []byte) (providerattestation.SignatureMetadata, error), error)
	authorizeOperation func(providerOperationAuthorization) (string, error)
	admission          providerCodexSubscriptionAdmission
	openLedger         func() (providerNativeOperationLedger, func() error, error)
	now                func() time.Time
}

var providerCodexRunDeps = providerCodexRunDependencies{
	loadConfig:         loadSelectedConfigOrDefault,
	attest:             zai.AttestCodexManifest,
	run:                zai.RunCodexStructured,
	newNonce:           providerCodexNonce,
	isLinkedWorktree:   providerIsLinkedGitWorktree,
	pinnedSigner:       providerCodexPinnedSigner,
	authorizeOperation: authorizeProviderOperation,
	admission:          defaultProviderCodexSubscriptionAdmission(),
	openLedger:         openProviderNativeLedger,
	now:                func() time.Time { return time.Now().UTC() },
}

// providerCodexRunOutput never retains prompt, nonce, credential, command
// output, session id, or literal filesystem paths. A false success value can
// still be a terminal, signed observation (for example, Codex completed but
// omitted provider-reported model identity).
type providerCodexRunOutput struct {
	SchemaVersion          string                                     `json:"schema_version"`
	Success                bool                                       `json:"success"`
	Profile                string                                     `json:"profile"`
	Transport              string                                     `json:"transport"`
	IdentitySHA256         string                                     `json:"identity_sha256"`
	ConfigSHA256           string                                     `json:"config_sha256"`
	BinarySHA256           string                                     `json:"binary_sha256"`
	BrokerCommandSHA256    string                                     `json:"broker_command_sha256"`
	CredentialBridgeSHA256 string                                     `json:"credential_bridge_sha256"`
	RuntimeVersion         string                                     `json:"runtime_version"`
	BrokerCredentialSHA256 string                                     `json:"broker_credential_sha256"`
	QualificationSHA256    string                                     `json:"qualification_receipt_sha256"`
	OperationIDSHA256      string                                     `json:"operation_id_sha256"`
	BindingSHA256          string                                     `json:"binding_sha256"`
	ReceiptState           string                                     `json:"receipt_state"`
	State                  string                                     `json:"state"`
	ProviderErrorClass     provider.ErrorClass                        `json:"provider_error_class,omitempty"`
	ErrorSHA256            string                                     `json:"error_sha256,omitempty"`
	Admission              providerCodexSubscriptionAdmissionEvidence `json:"admission"`
	Receipt                zai.CodexRunReceipt                        `json:"receipt"`
	Attestation            *providerattestation.SignatureMetadata     `json:"attestation,omitempty"`
}

// providerCodexSubscriptionAdmissionEvidence is safe to sign and persist. It
// records the paired decision without exposing account aliases, endpoints,
// credentials, requested-model usage, or store paths. The current strict
// signing schema deliberately excludes live capacity snapshots.
type providerCodexSubscriptionAdmissionEvidence struct {
	Allowed              bool                          `json:"allowed"`
	Reason               ratelimit.ErrorClass          `json:"reason,omitempty"`
	RetryAt              *time.Time                    `json:"retry_at,omitempty"`
	NoFailover           bool                          `json:"no_failover"`
	CapacityControlScope provider.CapacityControlScope `json:"capacity_control_scope"`
}

func newProviderCodexCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "codex", Short: "Operate the isolated Z.ai Coding Plan Codex lane"}
	cmd.AddCommand(newProviderCodexRunCmd(), newProviderCodexRecoverCapacityCmd())
	return cmd
}

func newProviderCodexRunCmd() *cobra.Command {
	opts := providerCodexRunOptions{timeout: providerCodexRunTimeout, workloadClass: providerCodexWorkloadImplementation, qualificationAge: 24 * time.Hour}
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run one manifest-attested structured Z.ai Codex turn",
		Long: `Run one exact Z.ai Coding Plan Codex turn through the CAAM credential broker.

This production transport requires a current signed qualification for the exact
requested review or workspace-write operation. It never falls through to
OpenAI, Anthropic, or native API billing.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProviderCodex(cmd, opts, providerCodexRunDeps)
		},
	}
	cmd.Flags().StringVar(&opts.profile, "profile", "", "Exact configured Z.ai codex_responses profile (required)")
	cmd.Flags().StringVar(&opts.prompt, "prompt", "", "Prompt to execute (required; never retained)")
	cmd.Flags().StringVar(&opts.operationID, "operation-id", "", "Durable idempotency key (required)")
	cmd.Flags().StringVar(&opts.cwd, "cwd", "", "Exact existing working directory (required)")
	cmd.Flags().StringVar(&opts.parentSession, "resume", "", "Exact parent session id to qualify resume (never retained)")
	cmd.Flags().StringVar(&opts.workloadClass, "workload-class", opts.workloadClass, "Exact workload policy: implementation, review, or off-peak bulk")
	cmd.Flags().BoolVar(&opts.workspaceWrite, "workspace-write", false, "Allow Codex workspace-write only inside a linked Git worktree")
	cmd.Flags().BoolVar(&opts.live, "live", false, "Explicitly authorize one real Coding Plan call")
	cmd.Flags().DurationVar(&opts.timeout, "timeout", opts.timeout, "Bounded runtime timeout")
	cmd.Flags().StringVar(&opts.qualificationDir, "qualification-store", "", "Override signed operation qualification receipt directory")
	cmd.Flags().DurationVar(&opts.qualificationAge, "max-qualification-age", opts.qualificationAge, "Maximum age of the signed operation qualification")
	return cmd
}

func runProviderCodex(cmd *cobra.Command, opts providerCodexRunOptions, deps providerCodexRunDependencies) (returnErr error) {
	if strings.TrimSpace(opts.profile) == "" || strings.TrimSpace(opts.prompt) == "" || strings.TrimSpace(opts.cwd) == "" {
		return errors.New("provider codex run requires exact --profile, --prompt, and --cwd values")
	}
	if !opts.live {
		return errors.New("provider codex run makes a real Z.ai Coding Plan call; pass --live to authorize it")
	}
	if !validProviderNativeOperationID(strings.TrimSpace(opts.operationID)) {
		return errors.New("provider codex run requires a valid --operation-id")
	}
	if opts.qualificationAge == 0 {
		opts.qualificationAge = 24 * time.Hour
	}
	if opts.timeout <= 0 || opts.qualificationAge <= 0 {
		return errors.New("provider codex run timeout and qualification age must be positive")
	}
	if deps.loadConfig == nil || deps.attest == nil || deps.run == nil || deps.newNonce == nil || deps.isLinkedWorktree == nil || (deps.sign == nil && deps.pinnedSigner == nil) || deps.authorizeOperation == nil || deps.admission == nil || deps.openLedger == nil || deps.now == nil {
		return errors.New("provider codex run dependencies are incomplete")
	}
	cfg := deps.loadConfig()
	if cfg == nil {
		return errors.New("provider codex run requires loaded configuration")
	}
	profile, err := cfg.ProviderProfile(opts.profile)
	if err != nil {
		return err
	}
	identity, err := profile.Identity()
	if err != nil {
		return err
	}
	if identity.Provider() != "zai" || identity.Runtime() != "codex" || identity.Endpoint() != zai.OfficialCodexEndpoint || identity.CredentialClass() != provider.CredentialClassCodingPlan || identity.BillingClass() != provider.BillingClassCodingPlan || identity.Entitlement() != provider.EntitlementCodexResponses || profile.AutomationPolicy != provider.DefaultZAICodexAutomationPolicyName || !profile.ExactTargetOnly || !profile.ProbeRequired {
		return errors.New("provider codex run requires an exact isolated Z.ai Coding Plan Codex profile")
	}
	workload, err := validateProviderCodexWorkload(identity.Model(), opts.workloadClass, deps.now())
	if err != nil {
		return err
	}
	opts.workloadClass = workload
	cwd, err := filepath.Abs(opts.cwd)
	if err != nil {
		return errors.New("provider codex run could not resolve its working directory")
	}
	info, err := os.Stat(cwd)
	if err != nil || !info.IsDir() {
		return errors.New("provider codex run working directory must be an existing directory")
	}
	if opts.workspaceWrite {
		checkCtx, cancel := context.WithTimeout(providerCommandContext(cmd), 5*time.Second)
		linked, checkErr := deps.isLinkedWorktree(checkCtx, cwd)
		cancel()
		if checkErr != nil || !linked {
			return errors.New("workspace-write Z.ai Codex runs require a linked disposable Git worktree")
		}
	}
	commandCtx := providerCommandContext(cmd)
	manifestExpectation := zai.CodexManifestExpectation{
		RuntimeHome: profile.RuntimeHome, Account: identity.AccountAlias(), Endpoint: identity.Endpoint(), Model: identity.Model(),
		BrokerCredentialID: profile.BrokerCredentialID, Binary: profile.Command, BinarySHA256: profile.RuntimeSHA256,
		BrokerCommand: profile.BrokerCommand, BrokerCommandSHA256: profile.BrokerCommandSHA256,
		CredentialBridgeCommand: profile.CredentialBridgeCommand, CredentialBridgeCommandSHA256: profile.CredentialBridgeCommandSHA256,
		Version: profile.RuntimeVersion, ConfigSHA256: profile.ConfigSHA256,
	}
	manifest, err := deps.attest(commandCtx, manifestExpectation)
	if err != nil {
		return fmt.Errorf("provider codex manifest attestation failed: %w", err)
	}
	sign := deps.sign
	if deps.pinnedSigner != nil {
		sign, err = deps.pinnedSigner(profile)
		if err != nil {
			return fmt.Errorf("provider codex pinned receipt signer is unavailable: %w", err)
		}
	}
	signerPreflight, err := preflightProviderReceiptSignerMetadata(commandCtx, sign)
	if err != nil {
		return fmt.Errorf("provider codex run requires an initialized receipt signing key before dispatch: %w", err)
	}
	requiredOperation := providerOperationReview
	if opts.workspaceWrite {
		requiredOperation = providerOperationWorkspaceWrite
	}
	qualificationSHA256, err := deps.authorizeOperation(providerOperationAuthorization{
		Identity: identity, Transport: "zai_codex_runtime", PolicySHA256: providerCodexPolicySHA256(), RuntimeVersion: manifest.RuntimeVersion, RuntimeSHA256: manifest.BinarySHA256,
		Operation: requiredOperation, QualificationDir: opts.qualificationDir, MaxQualificationAge: opts.qualificationAge,
		TrustedSigner: signerPreflight.KeyMetadata,
	})
	if err != nil {
		return fmt.Errorf("provider codex operation gate denied dispatch: %w", err)
	}
	status := deps.admission.CapacityStatus()
	if status.Scope != provider.CapacityControlScopeLocalShared {
		return errors.New("provider codex run requires the cross-process local shared capacity store")
	}
	logicalPrompt := strings.TrimSpace(opts.prompt)
	operationID := strings.TrimSpace(opts.operationID)
	binding := providerCodexBindingHash(identity, logicalPrompt, cwd, opts, manifest)
	output := providerCodexRunOutput{
		SchemaVersion: providerCodexRunSchema, Profile: opts.profile, Transport: "zai_codex_runtime",
		IdentitySHA256: identity.Hash(), ConfigSHA256: manifest.ConfigSHA256, BinarySHA256: manifest.BinarySHA256,
		BrokerCommandSHA256: manifest.AuthHelperSHA256, CredentialBridgeSHA256: manifest.CredentialBridgeSHA256,
		RuntimeVersion: manifest.RuntimeVersion, BrokerCredentialSHA256: sha256StringCLI(profile.BrokerCredentialID),
		QualificationSHA256: qualificationSHA256,
		OperationIDSHA256:   sha256StringCLI(operationID), BindingSHA256: binding,
		ReceiptState: "not_claimed", State: "preflight",
	}
	ledger, closeLedger, err := deps.openLedger()
	if err != nil || ledger == nil {
		output.State, output.ReceiptState = "ledger_unavailable", "claim_failed"
		return finishProviderCodex(cmd, output, errors.New("provider codex run requires a healthy durable operation ledger"))
	}
	if closeLedger != nil {
		defer func() { _ = closeLedger() }()
	}
	claimed, won, err := ledger.ClaimSendOperation(&state.SendOperation{
		OperationID: operationID, SessionName: providerCodexOperationScope, BindingHash: binding,
		PayloadSHA256: sha256StringCLI(logicalPrompt), PayloadBytes: int64(len(logicalPrompt)), CreatedAt: deps.now(),
	})
	if err != nil {
		output.State, output.ReceiptState = "ledger_unavailable", "claim_failed"
		return finishProviderCodex(cmd, output, errors.New("provider codex durable operation claim failed before dispatch"))
	}
	if !won {
		return replayProviderCodex(cmd, output, claimed, identity, signerPreflight.KeyMetadata)
	}
	output.ReceiptState, output.State = "claimed", "admission_pending"
	decision := deps.admission.Acquire(identity)
	output.Admission = providerCodexSubscriptionAdmissionEvidence{
		Allowed: decision.Allowed, Reason: decision.Reason, RetryAt: decision.RetryAt, NoFailover: decision.NoFailover,
		CapacityControlScope: status.Scope,
	}
	if !decision.Allowed || !decision.NoFailover {
		output.State = "admission_denied"
		if decision.Allowed {
			deps.admission.Release(identity, decision)
		}
		if releaseErr := ledger.ReleaseSendOperation(claimed.OperationID, claimed.SessionName); releaseErr != nil {
			output.State, output.ReceiptState = "outcome_unknown", "release_failed"
		}
		return finishProviderCodex(cmd, output, errors.New("provider capacity admission denied for the exact Z.ai Coding Plan identity"))
	}
	defer func() {
		if observer, ok := deps.admission.(interface {
			ReleaseObserved(provider.Identity, ratelimit.SubscriptionDecision) provider.CapacityReleaseObservation
		}); ok {
			if err := provider.ObserveCapacityRelease(commandCtx, observer.ReleaseObserved(identity, decision)); err != nil {
				returnErr = errors.Join(returnErr, errors.New("local capacity observation could not be persisted"))
			}
		} else {
			deps.admission.Release(identity, decision)
		}
	}()
	nonce, err := deps.newNonce()
	if err != nil {
		_ = ledger.ReleaseSendOperation(claimed.OperationID, claimed.SessionName)
		if cancelErr := deps.admission.CancelReservation(identity, decision); cancelErr != nil {
			return errors.New("provider codex failed before dispatch and could not cancel its subscription reservation")
		}
		return err
	}
	if err := deps.admission.BindReservation(identity, decision, binding, sha256StringCLI(nonce)); err != nil {
		_ = ledger.ReleaseSendOperation(claimed.OperationID, claimed.SessionName)
		if cancelErr := deps.admission.CancelReservation(identity, decision); cancelErr != nil {
			return errors.New("provider codex reservation binding failed before dispatch and its capacity reservation could not be canceled")
		}
		return errors.New("provider codex reservation binding failed before dispatch")
	}
	runCtx, cancel := context.WithTimeout(commandCtx, opts.timeout)
	receipt, runErr := deps.run(runCtx, zai.CodexRunSpec{
		Binary: profile.Command, BrokerCommand: profile.BrokerCommand, CredentialBridgeCommand: profile.CredentialBridgeCommand, RuntimeHome: profile.RuntimeHome, CWD: cwd,
		Prompt: logicalPrompt, ExpectedNonce: nonce, RequestedModel: identity.Model(), ParentSession: strings.TrimSpace(opts.parentSession),
		ConfigSHA256: manifest.ConfigSHA256, BinarySHA256: manifest.BinarySHA256,
		BrokerCommandSHA256: manifest.AuthHelperSHA256, CredentialBridgeCommandSHA256: manifest.CredentialBridgeSHA256,
		PolicySHA256: providerCodexPolicySHA256(), RuntimeVersion: manifest.RuntimeVersion,
		WorkspaceWrite: opts.workspaceWrite, Resume: strings.TrimSpace(opts.parentSession) != "",
		ManifestVerifier: func(verifyCtx context.Context) error {
			observed, verifyErr := deps.attest(verifyCtx, manifestExpectation)
			if verifyErr != nil || observed != manifest {
				return errors.New("Codex manifest re-attestation mismatch")
			}
			return nil
		},
	})
	cancel()
	output.Receipt = receipt
	usageReconciliationFailed := false
	unknownUsageReserved := false
	reserveUnknownUsage := func() error {
		if unknownUsageReserved {
			return nil
		}
		if err := deps.admission.RecordUnknownUsage(identity, decision); err != nil {
			return err
		}
		unknownUsageReserved = true
		return nil
	}
	if runErr == nil {
		if receiptErr := validateProviderCodexTerminalReceipt(receipt, identity, logicalPrompt, nonce, cwd, opts, manifest, true); receiptErr != nil {
			runErr = fmt.Errorf("provider codex returned an invalid successful receipt: %w", receiptErr)
		} else if usageErr := reconcileProviderCodexSubscriptionUsage(deps.admission, identity, decision, receipt); usageErr != nil {
			// A real provider turn without authoritative shared-plan accounting is
			// outcome-unknown. Do not clear the circuit, record success, or allow
			// a retry/failover that could spend the subscription twice.
			runErr = fmt.Errorf("provider codex subscription usage reconciliation failed: %w", usageErr)
			usageReconciliationFailed = true
		} else {
			deps.admission.RecordSuccess(identity)
			output.Success, output.State, output.ReceiptState = true, "completed", "completed"
		}
	}
	if runErr != nil {
		if receipt.ProviderHTTPStatus != 0 || receipt.ProviderErrorCode != "" {
			class := provider.ClassifyProviderError(receipt.ProviderHTTPStatus, receipt.ProviderErrorCode)
			output.ProviderErrorClass = class
			output.ErrorSHA256 = sha256StringCLI(fmt.Sprintf("%d\x00%s", receipt.ProviderHTTPStatus, receipt.ProviderErrorCode))
			// Preserve provider evidence in both capacity scopes. A structured
			// permanent business error must not be retried as an opaque local
			// failure, while a 429/overload receives the controller's backoff.
			_ = deps.admission.RecordResult(identity, class, 0)
		}
		completedWithoutModel := validateProviderCodexTerminalReceipt(receipt, identity, logicalPrompt, nonce, cwd, opts, manifest, false) == nil
		// A started process may have sent a billable provider request even when
		// its structured result is incomplete (including stock Codex builds with
		// no terminal server_model field). Never leave only the normal tiny
		// admission reservation in place after such a dispatch.
		if receipt.ProcessStarted && completedWithoutModel {
			usage := ratelimit.TokenUsage{InputTokens: receipt.Usage.InputTokens, CachedInputTokens: receipt.Usage.CachedInputTokens, OutputTokens: receipt.Usage.OutputTokens}
			if reconciliationErr := deps.admission.RecordConservativeUsage(identity, decision, usage, receipt.CompletedAt); reconciliationErr != nil {
				if reservationErr := reserveUnknownUsage(); reservationErr != nil {
					output.State, output.ReceiptState = "outcome_unknown", "outcome_unknown"
					return finishProviderCodex(cmd, output, errors.New("provider codex completed without model evidence, but neither conservative accounting nor an unknown-usage reservation could be recorded; do not redispatch"))
				}
				output.State, output.ReceiptState = "outcome_unknown", "outcome_unknown"
				return finishProviderCodex(cmd, output, errors.New("provider codex completed without model evidence; conservative accounting failed and the subscription was frozen as unknown; do not redispatch"))
			}
		} else if receipt.ProcessStarted {
			if reservationErr := reserveUnknownUsage(); reservationErr != nil {
				output.State, output.ReceiptState = "outcome_unknown", "outcome_unknown"
				return finishProviderCodex(cmd, output, errors.New("provider codex dispatched an unreconciled request and the subscription scope could not be conservatively reserved; do not redispatch"))
			}
		}
		if usageReconciliationFailed {
			output.State, output.ReceiptState = "outcome_unknown", "outcome_unknown"
			return finishProviderCodex(cmd, output, errors.New("provider codex subscription usage is not authoritatively reconciled; do not redispatch"))
		}
		switch {
		case completedWithoutModel:
			// This is the expected fail-closed state when Codex JSONL does not
			// expose terminal server_model evidence, so execution can be
			// recorded but cannot qualify or become primary.
			output.State, output.ReceiptState = "completed_unqualified", "completed"
		case receipt.ProcessStarted:
			output.State, output.ReceiptState = "outcome_unknown", "outcome_unknown"
			return finishProviderCodex(cmd, output, errors.New("provider codex outcome is incomplete; the claimed operation remains blocked from redispatch"))
		default:
			output.State, output.ReceiptState = "not_dispatched", "released"
			if cancelErr := deps.admission.CancelReservation(identity, decision); cancelErr != nil {
				output.State, output.ReceiptState = "capacity_unknown", "release_failed"
				return finishProviderCodex(cmd, output, errors.New("provider codex did not dispatch, but its subscription reservation could not be canceled"))
			}
			if releaseErr := ledger.ReleaseSendOperation(claimed.OperationID, claimed.SessionName); releaseErr != nil {
				output.State, output.ReceiptState = "outcome_unknown", "release_failed"
			}
			return finishProviderCodex(cmd, output, runErr)
		}
	}
	if err := sealProviderCodexOutput(commandCtx, &output, sign, signerPreflight.KeyMetadata); err != nil {
		output.Success, output.State, output.ReceiptState = false, "outcome_unknown", "attestation_failed"
		return finishProviderCodex(cmd, output, errors.New("provider codex outcome could not be attested; do not redispatch"))
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		output.Success, output.State, output.ReceiptState = false, "outcome_unknown", "persistence_failed"
		return finishProviderCodex(cmd, output, errors.New("provider codex outcome could not be encoded for durable recording; do not redispatch"))
	}
	if err := ledger.CompleteSendOperation(claimed.OperationID, claimed.SessionName, string(encoded), deps.now()); err != nil {
		output.Success, output.State, output.ReceiptState = false, "outcome_unknown", "persistence_failed"
		return finishProviderCodex(cmd, output, errors.New("provider codex outcome could not be durably recorded; do not redispatch"))
	}
	return finishProviderCodex(cmd, output, runErr)
}

func reconcileProviderCodexSubscriptionUsage(admission providerCodexSubscriptionAdmission, identity provider.Identity, decision ratelimit.SubscriptionDecision, receipt zai.CodexRunReceipt) error {
	if admission == nil || !decision.Allowed || !decision.NoFailover || !providerCodexReceiptHasExactModelEvidence(receipt, identity) || receipt.CompletedAt.IsZero() {
		return errors.New("authoritative model, completion time, or subscription decision is unavailable")
	}
	usage := ratelimit.TokenUsage{InputTokens: receipt.Usage.InputTokens, CachedInputTokens: receipt.Usage.CachedInputTokens, OutputTokens: receipt.Usage.OutputTokens}
	if usage.InputTokens < 0 || usage.CachedInputTokens < 0 || usage.OutputTokens < 0 || usage.InputTokens+usage.CachedInputTokens+usage.OutputTokens <= 0 {
		return errors.New("provider receipt lacks authoritative token usage")
	}
	return admission.RecordUsage(identity, decision, receipt.ResolvedModel, usage, receipt.CompletedAt)
}

func providerCodexPinnedSigner(profile config.ProviderProfileConfig) (func(context.Context, []byte) (providerattestation.SignatureMetadata, error), error) {
	return providerProfilePinnedSigner(profile)
}

func replayProviderCodex(cmd *cobra.Command, expected providerCodexRunOutput, claimed *state.SendOperation, identity provider.Identity, trustedSigner providerattestation.KeyMetadata) error {
	if claimed == nil || claimed.BindingHash != expected.BindingSHA256 {
		expected.State, expected.ReceiptState = "binding_conflict", "conflict"
		return finishProviderCodex(cmd, expected, errors.New("operation ID is already bound to a different Z.ai Codex operation"))
	}
	var recorded providerCodexRunOutput
	if claimed.Status != state.SendOperationCompleted || json.Unmarshal([]byte(claimed.OutcomeJSON), &recorded) != nil || !validRecordedProviderCodexOutput(recorded, expected, identity, trustedSigner) {
		expected.Success, expected.State, expected.ReceiptState = false, "outcome_unknown", "corrupt"
		return finishProviderCodex(cmd, expected, errors.New("stored Z.ai Codex operation is incomplete or invalid; do not redispatch"))
	}
	if recorded.Success {
		return finishProviderCodex(cmd, recorded, nil)
	}
	return finishProviderCodex(cmd, recorded, errors.New("replayed Z.ai Codex operation did not qualify"))
}

func validRecordedProviderCodexOutput(output, expected providerCodexRunOutput, identity provider.Identity, trustedSigner providerattestation.KeyMetadata) bool {
	if output.SchemaVersion != providerCodexRunSchema || output.Transport != "zai_codex_runtime" || output.IdentitySHA256 != identity.Hash() || output.Attestation == nil ||
		output.Attestation.KeyMetadata != trustedSigner ||
		output.Profile != expected.Profile || output.ConfigSHA256 != expected.ConfigSHA256 || output.BinarySHA256 != expected.BinarySHA256 ||
		output.BrokerCommandSHA256 != expected.BrokerCommandSHA256 || output.CredentialBridgeSHA256 != expected.CredentialBridgeSHA256 ||
		output.RuntimeVersion != expected.RuntimeVersion || output.BrokerCredentialSHA256 != expected.BrokerCredentialSHA256 ||
		output.QualificationSHA256 != expected.QualificationSHA256 || !validProviderNativeDigest(output.QualificationSHA256) ||
		output.OperationIDSHA256 != expected.OperationIDSHA256 || output.BindingSHA256 != expected.BindingSHA256 ||
		!providerCodexReceiptHasNoResiduals(output.Receipt) {
		return false
	}
	payload, err := canonicalProviderCodexOutput(output)
	return err == nil && providerattestation.ValidateBridgePayload(payload) == nil && providerattestation.Verify(payload, *output.Attestation) == nil
}

func sealProviderCodexOutput(ctx context.Context, output *providerCodexRunOutput, sign func(context.Context, []byte) (providerattestation.SignatureMetadata, error), trustedSigner providerattestation.KeyMetadata) error {
	payload, err := canonicalProviderCodexOutput(*output)
	if err != nil {
		return err
	}
	if err := providerattestation.ValidateBridgePayload(payload); err != nil {
		return fmt.Errorf("Codex receipt violates the signing bridge contract: %w", err)
	}
	signature, err := sign(ctx, payload)
	if err != nil {
		return err
	}
	if signature.KeyMetadata != trustedSigner {
		return errors.New("Codex receipt signer changed after preflight")
	}
	if err := providerattestation.Verify(payload, signature); err != nil {
		return err
	}
	output.Attestation = &signature
	return nil
}

func canonicalProviderCodexOutput(output providerCodexRunOutput) ([]byte, error) {
	output.Attestation = nil
	return json.Marshal(output)
}

func validateProviderCodexTerminalReceipt(receipt zai.CodexRunReceipt, identity provider.Identity, prompt, nonce, cwd string, opts providerCodexRunOptions, manifest zai.CodexManifestAttestation, requireModel bool) error {
	action := "start"
	if strings.TrimSpace(opts.parentSession) != "" {
		action = "resume"
	}
	if receipt.AdapterVersion != zai.CodexRuntimeAdapterVersion || receipt.Action != action || receipt.RequestedModel != identity.Model() ||
		receipt.ConfigSHA256 != manifest.ConfigSHA256 || receipt.BinarySHA256 != manifest.BinarySHA256 ||
		receipt.BrokerCommandSHA256 != manifest.AuthHelperSHA256 || receipt.CredentialBridgeSHA256 != manifest.CredentialBridgeSHA256 ||
		receipt.PolicySHA256 != providerCodexPolicySHA256() || receipt.RuntimeVersion != manifest.RuntimeVersion ||
		receipt.CWDSHA256 != sha256StringCLI(filepath.Clean(cwd)) || receipt.PromptSHA256 != sha256StringCLI(strings.TrimSpace(prompt)) ||
		receipt.NonceSHA256 != sha256StringCLI(nonce) {
		return errors.New("receipt binding mismatch")
	}
	if receipt.SessionIDSHA256 == "" || receipt.OutputSHA256 == "" || receipt.EventStreamSHA256 == "" || receipt.StderrSHA256 == "" || receipt.ToolEventsSHA256 == "" ||
		receipt.StartedAt.IsZero() || receipt.CompletedAt.IsZero() || receipt.CompletedAt.Before(receipt.StartedAt) || receipt.Cancellation.ObservedAt.IsZero() ||
		!receipt.ProcessStarted || !receipt.ProviderStarted || !receipt.OutcomeKnown || !receipt.CompletionConfirmed || !receipt.NonceVerified ||
		!receipt.LineageVerified || !providerCodexReceiptHasNoResiduals(receipt) || receipt.ExitCode != 0 || strings.TrimSpace(receipt.StopReason) == "" {
		return errors.New("receipt lifecycle evidence is incomplete")
	}
	if !providerCodexRuntimeEventContractValid(receipt, identity, provider.RuntimeEventRequirements{ToolLifecycle: opts.workspaceWrite}, requireModel) {
		return errors.New("receipt shared runtime-event contract is invalid or incomplete")
	}
	if action == "resume" {
		if receipt.ParentSessionSHA256 != sha256StringCLI(strings.TrimSpace(opts.parentSession)) {
			return errors.New("receipt resume lineage mismatch")
		}
	} else if receipt.ParentSessionSHA256 != "" {
		return errors.New("receipt start unexpectedly contains parent lineage")
	}
	if requireModel && !providerCodexReceiptHasExactModelEvidence(receipt, identity) {
		return errors.New("receipt lacks exact provider-reported model evidence")
	}
	if !requireModel && receipt.ModelVerified {
		return errors.New("unqualified receipt unexpectedly claims verified model identity")
	}
	return nil
}

func providerCodexReceiptHasNoResiduals(receipt zai.CodexRunReceipt) bool {
	return receipt.ZeroResiduals && receipt.Cancellation.ResidualProcessIDs != nil && len(receipt.Cancellation.ResidualProcessIDs) == 0
}

func providerCodexReceiptHasExactModelEvidence(receipt zai.CodexRunReceipt, identity provider.Identity) bool {
	return receipt.ModelVerified && receipt.RequestedModel == identity.Model() && receipt.ResolvedModel == identity.Model() && receipt.ModelEvidence == providerCodexTerminalModelEvidence
}

func providerCodexRuntimeEventContractValid(receipt zai.CodexRunReceipt, identity provider.Identity, requirements provider.RuntimeEventRequirements, requirePass bool) bool {
	if receipt.RuntimeEvents == nil || receipt.RuntimeEventRequirements != requirements {
		return false
	}
	recomputed := provider.ValidateRuntimeEventsForOperation(identity, receipt.RuntimeEvents, requirements)
	stored := receipt.RuntimeEventContract
	if stored.Required != recomputed.Required || stored.Observed != recomputed.Observed || stored.Passed != recomputed.Passed || stored.ReceiptSHA256 != recomputed.ReceiptSHA256 || !slices.Equal(stored.Violations, recomputed.Violations) {
		return false
	}
	return !requirePass || stored.Passed
}

func providerCodexBindingHash(identity provider.Identity, prompt, cwd string, opts providerCodexRunOptions, manifest zai.CodexManifestAttestation) string {
	return providerCodexBindingHashFromDigests(
		identity,
		sha256StringCLI(prompt),
		sha256StringCLI(filepath.Clean(cwd)),
		opts.workspaceWrite,
		opts.workloadClass,
		strings.TrimSpace(opts.parentSession) != "",
		sha256StringCLI(strings.TrimSpace(opts.parentSession)),
		manifest,
	)
}

func providerCodexBindingHashFromDigests(identity provider.Identity, promptSHA256, cwdSHA256 string, workspaceWrite bool, workloadClass string, resume bool, parentSessionSHA256 string, manifest zai.CodexManifestAttestation) string {
	fields := []string{
		providerCodexRunSchema, identity.Hash(), promptSHA256, cwdSHA256,
		fmt.Sprint(workspaceWrite), workloadClass, fmt.Sprint(resume), parentSessionSHA256,
		manifest.ConfigSHA256, manifest.BinarySHA256, manifest.AuthHelperSHA256, manifest.CredentialBridgeSHA256, providerCodexPolicySHA256(),
	}
	return sha256StringCLI(strings.Join(fields, "\x00"))
}

func validateProviderCodexWorkload(model, workload string, observedAt time.Time) (string, error) {
	workload = strings.ToLower(strings.TrimSpace(workload))
	if workload == "" {
		workload = providerCodexWorkloadImplementation
	}
	switch workload {
	case providerCodexWorkloadImplementation, providerCodexWorkloadReview:
		if model != "glm-5.3" {
			return "", fmt.Errorf("Z.ai %s workloads require the exact glm-5.3 profile; NTM will not silently change models or providers", workload)
		}
	case providerCodexWorkloadBulk:
		if model != "glm-5.3-flash" {
			return "", errors.New("Z.ai bulk workloads require an explicitly selected glm-5.3-flash profile; NTM will not silently change models or providers")
		}
		if observedAt.IsZero() {
			return "", errors.New("Z.ai bulk scheduling requires an authoritative local clock")
		}
		singapore := observedAt.In(time.FixedZone("Asia/Singapore", 8*60*60))
		weekday := singapore.Weekday() >= time.Monday && singapore.Weekday() <= time.Friday
		if weekday && singapore.Hour() >= 14 && singapore.Hour() < 18 {
			retry := time.Date(singapore.Year(), singapore.Month(), singapore.Day(), 18, 0, 0, 0, singapore.Location()).UTC()
			return "", fmt.Errorf("Z.ai bulk workload is held for off-peak pricing; retry after %s", retry.Format(time.RFC3339))
		}
	default:
		return "", errors.New("provider codex workload-class must be implementation, review, or bulk")
	}
	return workload, nil
}

func providerCodexPolicySHA256() string {
	sum := sha256.Sum256([]byte(provider.DefaultZAICodexAutomationPolicyName))
	return hex.EncodeToString(sum[:])
}

func providerCodexNonce() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("generate provider codex nonce")
	}
	return "NTM_ACK_" + hex.EncodeToString(value), nil
}

func finishProviderCodex(cmd *cobra.Command, output providerCodexRunOutput, runErr error) error {
	if IsJSONOutput() {
		if err := encodeIndentedJSON(cmd.OutOrStdout(), output); err != nil {
			return err
		}
		if runErr != nil {
			return errJSONFailure
		}
		return nil
	}
	status := "failed"
	if output.Success {
		status = "completed"
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Z.ai Codex run %s.\nOperation SHA-256: %s (%s)\nIdentity: %s\nReceipt: %s\n", status, output.OperationIDSHA256, output.ReceiptState, output.IdentitySHA256, digestSafeJSON(output.Receipt)); err != nil {
		return err
	}
	return runErr
}
