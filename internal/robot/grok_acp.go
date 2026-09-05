package robot

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	agentpkg "github.com/Dicklesworthstone/ntm/internal/agent"
	"github.com/Dicklesworthstone/ntm/internal/grok"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/state"
)

// GrokACPOperationOptions is the deliberately narrow input for one direct
// Grok ACP operation. Prompt and nonce are accepted only as input; neither is
// returned in the robot receipt.
type GrokACPOperationOptions struct {
	Prompt         string
	CWD            string
	Binary         string
	RuntimeHome    string
	Model          string
	RuntimeVersion string
	OperationID    string
	Nonce          string
	Identity       provider.Identity
	// OperationScope is the permission level being requested. It is part of the
	// durable idempotency binding: an operation ID admitted for review can never
	// be replayed as a workspace-write request. Empty means observe only.
	OperationScope GrokACPOperationScope
	// AutomationPolicy is resolved from the exact provider profile. An empty
	// value preserves the read-only policy for compatibility.
	AutomationPolicy string
	// Broker is constructed only by NTM for the workspace-write policy. The
	// descriptor has no exported executable/argument fields, preventing a
	// caller from widening it after validation.
	Broker        *grok.WorkspaceBrokerDescriptor
	ReceiptSigner func(context.Context, []byte) (providerattestation.SignatureMetadata, error)
	TrustedSigner providerattestation.KeyMetadata
	BeforeCleanup func(provider.ProtocolObservation) error
}

// GrokACPOperationScope identifies the operation-level promotion being used by
// a direct ACP dispatch. Observe is deliberately the default and does not
// consult a qualification authorizer. Review and workspace-write require a
// current signed qualification receipt from the caller's authority boundary.
type GrokACPOperationScope string

const (
	GrokACPOperationScopeObserve        GrokACPOperationScope = "observe"
	GrokACPOperationScopeReview         GrokACPOperationScope = "review"
	GrokACPOperationScopeWorkspaceWrite GrokACPOperationScope = "workspace-write"
)

// GrokACPOperationAuthorization is the non-secret result of operation-scoped
// qualification verification. The hash refers to a signed durable receipt; it
// is bound into the local operation ledger and robot receipt, while the signed
// receipt content itself is never copied into the ACP request or robot output.
type GrokACPOperationAuthorization struct {
	QualificationReceiptSHA256 string
}

// GrokACPOperationAuthorizer is intentionally injected at the robot boundary.
// The CLI owns profile discovery and signed qualification verification, while
// this lower layer makes it impossible for an internal caller to dispatch a
// review or workspace-write operation without that verified result.
type GrokACPOperationAuthorizer interface {
	AuthorizeGrokACPOperation(context.Context, GrokACPOperationScope, provider.Identity) (GrokACPOperationAuthorization, error)
}

// GrokACPOperationAuthorizerFunc adapts a narrow closure at the CLI boundary.
type GrokACPOperationAuthorizerFunc func(context.Context, GrokACPOperationScope, provider.Identity) (GrokACPOperationAuthorization, error)

func (f GrokACPOperationAuthorizerFunc) AuthorizeGrokACPOperation(ctx context.Context, scope GrokACPOperationScope, identity provider.Identity) (GrokACPOperationAuthorization, error) {
	return f(ctx, scope, identity)
}

// GrokACPTokenUsage and GrokACPCost are optional provider metadata. The ACP
// engine does not invent them; an adapter may attach them only from a
// structured provider completion record.
type GrokACPTokenUsage struct {
	Input  *int64 `json:"input,omitempty"`
	Output *int64 `json:"output,omitempty"`
	Total  *int64 `json:"total,omitempty"`
}

type GrokACPCost struct {
	Currency string `json:"currency"`
	Micro    int64  `json:"micro"`
}

// GrokACPExecutionEvidence is intentionally safe to emit. It carries no
// provider text, prompt, credentials, or raw tool calls.
type GrokACPExecutionEvidence struct {
	TokenUsage   *GrokACPTokenUsage
	Cost         *GrokACPCost
	ExitCode     *int
	CleanupState string
}

// GrokACPOperationOutput is the robot-safe receipt for direct ACP execution.
// It embeds the standard envelope and exposes only hashes, counts, and
// completion metadata.
type GrokACPOperationOutput struct {
	RobotResponse
	OperationID                string                `json:"operation_id"`
	Provider                   string                `json:"provider"`
	OperationScope             GrokACPOperationScope `json:"operation_scope"`
	QualificationReceiptSHA256 string                `json:"qualification_receipt_sha256,omitempty"`
	ProviderIdentitySHA256     string                `json:"provider_identity_sha256"`
	// ProviderIdentityEvidence describes the complete tuple. Structured ACP
	// observations can prove session/model facts, but endpoint/config remain
	// profile-attested unless an adapter records separate runtime proof.
	ProviderIdentityEvidence provider.IdentityEvidenceGrade `json:"provider_identity_evidence"`
	RuntimeVersion           string                         `json:"runtime_version,omitempty"`
	Model                    string                         `json:"model,omitempty"`
	ModelEvidence            string                         `json:"model_evidence,omitempty"`
	ResolvedModel            string                         `json:"resolved_model,omitempty"`
	ResolvedModelEvidence    string                         `json:"resolved_model_evidence,omitempty"`
	Transport                string                         `json:"transport"`
	Target                   string                         `json:"target"`
	PromptSHA256             string                         `json:"prompt_sha256"`
	NonceSHA256              string                         `json:"nonce_sha256"`
	ToolDigest               string                         `json:"tool_digest,omitempty"`
	BrokerSHA256             string                         `json:"broker_sha256,omitempty"`
	ProviderSessionID        string                         `json:"provider_session_id,omitempty"`
	StopReason               string                         `json:"stop_reason,omitempty"`
	CompletionConfirmed      bool                           `json:"completion_confirmed"`
	AcknowledgementVerified  bool                           `json:"acknowledgement_verified"`
	AssistantTextChunks      int                            `json:"assistant_text_chunks"`
	AssistantTextBytes       int64                          `json:"assistant_text_bytes"`
	OutputSHA256             string                         `json:"output_sha256,omitempty"`
	ToolEventCount           int                            `json:"tool_event_count"`
	ToolEventsSHA256         string                         `json:"tool_events_sha256"`
	ToolRequestCount         int                            `json:"tool_request_count"`
	ToolCompleteCount        int                            `json:"tool_complete_count"`
	NonMessageUpdateCount    int                            `json:"non_message_update_count"`
	NonMessageUpdatesSHA256  string                         `json:"non_message_updates_sha256"`
	TokenUsage               *GrokACPTokenUsage             `json:"token_usage,omitempty"`
	Cost                     *GrokACPCost                   `json:"cost,omitempty"`
	ExitCode                 *int                           `json:"exit_code,omitempty"`
	CleanupState             string                         `json:"cleanup_state"`
	// Cancellation is ACP-agent acknowledgement evidence only. It must never
	// be read as proof that xAI stopped any accepted cloud inference.
	Cancellation grok.ACPCancellationReceipt `json:"cancellation"`
	// Cleanup is local process-tree and reaping evidence, intentionally kept
	// separate from ACP cancellation acknowledgement.
	Cleanup                  grok.ProcessCleanupReceipt             `json:"cleanup"`
	State                    string                                 `json:"state"`
	FailureCode              grok.ErrorCode                         `json:"failure_code,omitempty"`
	Admission                AdmissionEvidence                      `json:"admission"`
	StartedAt                time.Time                              `json:"started_at"`
	CompletedAt              time.Time                              `json:"completed_at"`
	RuntimeEvents            []provider.RuntimeEvent                `json:"runtime_events"`
	RuntimeEventRequirements provider.RuntimeEventRequirements      `json:"runtime_event_requirements"`
	RuntimeEventContract     provider.EventContractReport           `json:"runtime_event_contract"`
	BindingSHA256            string                                 `json:"binding_sha256"`
	ReceiptState             string                                 `json:"receipt_state"`
	Replayed                 bool                                   `json:"replayed"`
	Attestation              *providerattestation.SignatureMetadata `json:"attestation,omitempty"`
}

// GrokACPEngine is the injectable direct-provider boundary. It deliberately
// returns the redaction-safe grok.Result rather than text.
type GrokACPEngine interface {
	Run(context.Context, grok.Request) (grok.Result, error)
}

type grokACPEngineFunc func(context.Context, grok.Request) (grok.Result, error)

func (f grokACPEngineFunc) Run(ctx context.Context, req grok.Request) (grok.Result, error) {
	return f(ctx, req)
}

type nativeGrokACPEngine struct{}

func (nativeGrokACPEngine) Run(ctx context.Context, req grok.Request) (grok.Result, error) {
	return grok.Run(ctx, grok.OSRunner{}, req)
}

// GrokACPEvidenceProvider is optional because xAI completion metadata may not
// contain usage/cost or local process cleanup details on every CLI version.
// Omission is represented explicitly as "not_observed", never guessed.
type GrokACPEvidenceProvider interface {
	Evidence(grok.Result) GrokACPExecutionEvidence
}

// GrokACPOperationDeps makes the adapter fully offline-testable.
type GrokACPOperationDeps struct {
	Engine    GrokACPEngine
	Evidence  GrokACPEvidenceProvider
	Admission ProviderAdmission
	Random    io.Reader
	Now       func() time.Time
	Ledger    GrokACPOperationLedger
	// Authorizer is required for review and workspace-write. It is intentionally
	// unused for observe so a read-only dispatch never treats a local report as
	// a promotion authority.
	Authorizer GrokACPOperationAuthorizer
	// IsDisposableWorktree proves that a workspace-write request targets a
	// linked Git worktree rather than the repository's primary checkout.
	IsDisposableWorktree func(context.Context, string) (bool, error)
}

// ProviderAdmission is the exact-identity dispatch boundary. It exposes no
// target-selection or fallback method, so a denial cannot silently switch
// provider, account, model, endpoint, runtime, or config.
type ProviderAdmission interface {
	Acquire(provider.Identity) ratelimit.Decision
	Release(provider.Identity, ratelimit.Decision)
	RecordResult(provider.Identity, ratelimit.ErrorClass, time.Duration) ratelimit.Decision
	RecordSuccess(provider.Identity)
	CapacityStatus() ratelimit.CapacityStatus
}

type AdmissionEvidence struct {
	Allowed    bool                 `json:"allowed"`
	Reason     ratelimit.ErrorClass `json:"reason,omitempty"`
	RetryAt    *time.Time           `json:"retry_at,omitempty"`
	NoFailover bool                 `json:"no_failover"`
	// CapacityControlScope prevents a receipt from implying a fleet-wide quota.
	// The built-in controller is shared only across local NTM processes.
	CapacityControlScope provider.CapacityControlScope `json:"capacity_control_scope"`
}

const (
	grokACPProvider  = "xai"
	grokACPTransport = "acp_stdio"
	grokACPTarget    = "stdio"
)

// RunGrokACPOperation binds an operation ID and nonce to one ACP prompt. It
// never claims an acknowledgement from a mere local completion: the engine
// must have observed the exact nonce in an assistant text chunk.
func RunGrokACPOperation(ctx context.Context, opts GrokACPOperationOptions, deps GrokACPOperationDeps) (output *GrokACPOperationOutput, returnErr error) {
	if deps.Engine == nil {
		deps.Engine = nativeGrokACPEngine{}
	}
	if deps.Random == nil {
		deps.Random = rand.Reader
	}
	if deps.Now == nil {
		deps.Now = func() time.Time { return time.Now().UTC() }
	}
	if deps.Admission == nil {
		deps.Admission = ratelimit.DefaultAdmissionController()
	}
	if deps.IsDisposableWorktree == nil {
		deps.IsDisposableWorktree = isLinkedGitWorktree
	}
	operationScope, err := normalizeGrokACPOperationScope(opts.OperationScope)
	if err != nil {
		return invalidGrokACPOperationOutput(opts, deps.Now(), err), err
	}

	operationID, err := nonEmptyOrGenerated(opts.OperationID, "grok-acp-", deps.Random)
	if err != nil {
		return invalidGrokACPOperationOutput(opts, deps.Now(), err), err
	}
	if !validGrokACPOperationID(operationID) {
		err := errors.New("operation ID must be 1-128 characters using letters, digits, dot, colon, underscore, or hyphen")
		return invalidGrokACPOperationOutput(opts, deps.Now(), err), err
	}
	nonce, err := nonEmptyOrGenerated(opts.Nonce, "NTM_ACK_", deps.Random)
	if err != nil {
		return invalidGrokACPOperationOutput(opts, deps.Now(), err), err
	}
	if !grok.ValidNonce(nonce) {
		err := errors.New("nonce must be an NTM_ACK_ token with at least 128 bits of hex entropy")
		return invalidGrokACPOperationOutput(opts, deps.Now(), err), err
	}
	if strings.TrimSpace(opts.Prompt) == "" {
		err := errors.New("prompt is required")
		return invalidGrokACPOperationOutput(opts, deps.Now(), err), err
	}

	logicalPromptHash := sha256Hex(strings.TrimSpace(opts.Prompt))
	transmittedPrompt := bindNonceInstruction(opts.Prompt, nonce)
	promptHash := sha256Hex(transmittedPrompt)
	policyName := strings.TrimSpace(opts.AutomationPolicy)
	if policyName == "" {
		policyName = agentpkg.DefaultGrokAutomationPolicyName
	}
	if _, ok := agentpkg.GrokAutomationPolicy(policyName); !ok {
		err := fmt.Errorf("unknown Grok automation policy %q", policyName)
		return invalidGrokACPOperationOutput(opts, deps.Now(), err), err
	}
	// The public robot operation is bound to one compiled named policy. Callers
	// cannot expand permissions while presenting its digest.
	policyArgs := agentpkg.GrokAutomationACPPolicyArgs(policyName)
	toolDigest := agentpkg.GrokAutomationPolicySHA256(policyName)
	brokerDigest := ""
	if opts.Broker != nil {
		brokerDigest = opts.Broker.BindingSHA256()
	}
	output = &GrokACPOperationOutput{
		RobotResponse:            NewRobotResponse(true),
		OperationID:              operationID,
		Provider:                 grokACPProvider,
		OperationScope:           operationScope,
		ProviderIdentitySHA256:   opts.Identity.Hash(),
		ProviderIdentityEvidence: opts.Identity.EvidenceGrade(),
		RuntimeVersion:           strings.TrimSpace(opts.RuntimeVersion),
		// A requested model is not receipt evidence. Model stays empty until
		// Grok returns structured completion metadata naming the effective one.
		Model:        "",
		Transport:    grokACPTransport,
		Target:       grokACPTarget,
		PromptSHA256: promptHash,
		NonceSHA256:  sha256Hex(nonce),
		ToolDigest:   toolDigest,
		BrokerSHA256: brokerDigest,
		CleanupState: "not_observed",
		State:        grok.StateFailed,
		ReceiptState: "not_claimed",
		StartedAt:    deps.Now(),
	}
	if !opts.Identity.Valid() || opts.Identity.Provider() != grokACPProvider {
		err := errors.New("a valid xAI provider identity is required for Grok ACP admission")
		output.RobotResponse = NewErrorResponse(err, ErrCodeInvalidFlag, "Select an exact xAI provider profile")
		output.State = "admission_rejected"
		output.Admission = AdmissionEvidence{Reason: ratelimit.ErrorIdentityMismatch, NoFailover: true, CapacityControlScope: provider.CapacityControlScopeUnavailable}
		return output, err
	}
	if requestedModel := strings.TrimSpace(opts.Model); requestedModel != "" && requestedModel != opts.Identity.Model() {
		err := errors.New("requested Grok model does not match the selected provider identity")
		output.RobotResponse = NewErrorResponse(err, ErrCodeInvalidFlag, "Use the model bound by the exact provider profile")
		output.State = "identity_rejected"
		output.FailureCode = grok.ErrIdentityMismatch
		output.Admission = AdmissionEvidence{Reason: ratelimit.ErrorIdentityMismatch, NoFailover: true, CapacityControlScope: provider.CapacityControlScopeUnavailable}
		return output, err
	}
	if !grokACPPolicyAllowedForScope(operationScope, policyName) {
		err := fmt.Errorf("Grok ACP operation scope %q does not match automation policy %q", operationScope, policyName)
		output.RobotResponse = NewErrorResponse(err, ErrCodeInvalidFlag, "Use observe/review with grok-readonly-ci or workspace-write with grok-workspace-write-ci")
		output.State = "operation_scope_rejected"
		output.Admission = AdmissionEvidence{NoFailover: true, CapacityControlScope: provider.CapacityControlScopeUnavailable}
		return output, err
	}
	if policyName == agentpkg.GrokWorkspaceWritePolicyName {
		isolated, verifyErr := deps.IsDisposableWorktree(ctx, opts.CWD)
		if verifyErr != nil || !isolated {
			err := errors.New("Grok workspace-write policy requires a linked disposable Git worktree")
			if verifyErr != nil {
				err = fmt.Errorf("verify disposable Git worktree: %w", verifyErr)
			}
			output.RobotResponse = NewErrorResponse(err, ErrCodeInvalidFlag, "Create/select an isolated linked worktree or use the observe policy")
			output.State = "workspace_policy_rejected"
			output.Admission = AdmissionEvidence{NoFailover: true, CapacityControlScope: provider.CapacityControlScopeUnavailable}
			return output, err
		}
		if opts.Broker == nil {
			err := errors.New("Grok workspace-write policy requires NTM's typed workspace broker")
			output.RobotResponse = NewErrorResponse(err, ErrCodeDependencyMissing, "Bind the exact linked worktree and fixed verifier manifest before dispatch")
			output.State = "workspace_broker_rejected"
			output.Admission = AdmissionEvidence{NoFailover: true, CapacityControlScope: provider.CapacityControlScopeUnavailable}
			return output, err
		}
	} else if opts.Broker != nil {
		err := errors.New("Grok workspace broker is available only under the compiled workspace-write policy")
		output.RobotResponse = NewErrorResponse(err, ErrCodeInvalidFlag, "Remove the broker or select the exact workspace-write provider profile")
		output.State = "workspace_broker_rejected"
		output.Admission = AdmissionEvidence{NoFailover: true, CapacityControlScope: provider.CapacityControlScopeUnavailable}
		return output, err
	}
	if operationScope != GrokACPOperationScopeObserve {
		if deps.Authorizer == nil {
			err := errors.New("Grok ACP review and workspace-write operations require an injected qualification authorizer")
			output.RobotResponse = NewErrorResponse(err, ErrCodeDependencyMissing, "Authorize the exact signed qualification receipt before non-observe provider dispatch")
			output.State = "operation_authorization_rejected"
			output.Admission = AdmissionEvidence{NoFailover: true, CapacityControlScope: provider.CapacityControlScopeUnavailable}
			return output, err
		}
		authorization, authorizeErr := deps.Authorizer.AuthorizeGrokACPOperation(ctx, operationScope, opts.Identity)
		if authorizeErr != nil || !validGrokACPQualificationReceiptSHA256(authorization.QualificationReceiptSHA256) {
			err := errors.New("Grok ACP operation qualification authorization was rejected")
			output.RobotResponse = NewErrorResponse(err, ErrCodeDependencyMissing, "Provide a current signed qualification receipt for the exact operation scope")
			output.State = "operation_authorization_rejected"
			output.Admission = AdmissionEvidence{NoFailover: true, CapacityControlScope: provider.CapacityControlScopeUnavailable}
			if authorizeErr != nil {
				return output, fmt.Errorf("authorize Grok ACP %s operation: %w", operationScope, authorizeErr)
			}
			return output, err
		}
		output.QualificationReceiptSHA256 = authorization.QualificationReceiptSHA256
	}
	capacityStatus := deps.Admission.CapacityStatus()
	if capacityStatus.Scope != provider.CapacityControlScopeLocalShared {
		err := errors.New("Grok ACP requires the cross-process local shared capacity store")
		output.RobotResponse = NewErrorResponse(err, ErrCodeDependencyMissing, "Restore the exact-identity local shared lease/circuit store before provider dispatch")
		output.State = "capacity_unavailable"
		output.Admission = AdmissionEvidence{NoFailover: true, CapacityControlScope: capacityStatus.Scope}
		return output, err
	}
	// The durable operation binds the caller's logical work, not the generated
	// per-dispatch transport nonce. This lets an ordinary retry with the same
	// operation ID replay the stored receipt without retaining the nonce or
	// dispatching again. PromptSHA256 still records the exact nonce-bound packet.
	output.BindingSHA256 = grokACPBindingHash(opts.Identity, logicalPromptHash, opts.CWD, opts.Binary, opts.RuntimeHome, opts.RuntimeVersion, toolDigest, brokerDigest, operationScope, output.QualificationReceiptSHA256)
	if opts.ReceiptSigner != nil || opts.TrustedSigner.KeyID != "" {
		preflight := *output
		preflight.RobotResponse = NewRobotResponse(false)
		preflight.State = "signer_preflight"
		if err := sealGrokACPOperationOutput(ctx, &preflight, opts.ReceiptSigner, opts.TrustedSigner); err != nil {
			output.RobotResponse = NewErrorResponse(errors.New("Grok operation receipt signing preflight failed"), ErrCodeDependencyMissing, "Repair the exact pinned signer before dispatch; no provider work was started")
			output.State = "signer_unavailable"
			return output, err
		}
	}
	claimed, wonClaim, claimErr := claimGrokACPOperation(deps.Ledger, operationID, output.BindingSHA256, promptHash, int64(len(transmittedPrompt)), output.StartedAt)
	if claimErr != nil {
		output.RobotResponse = NewErrorResponse(errors.New("durable Grok ACP operation claim failed"), ErrCodeInternalError, "Repair the NTM state store before provider dispatch")
		output.ReceiptState = "claim_failed"
		return output, claimErr
	}
	if !wonClaim {
		if claimed.BindingHash != output.BindingSHA256 {
			err := errors.New("operation ID is already bound to a different Grok ACP request")
			output.RobotResponse = NewErrorResponse(err, ErrCodeIdempotencyConflict, "Use a new operation ID for different provider identity, prompt, path, executable, or policy")
			output.ReceiptState = "conflict"
			return output, err
		}
		if claimed.Status == state.SendOperationCompleted {
			if err := applyStoredGrokACPOutcome(output, claimed, opts.TrustedSigner); err != nil {
				output.RobotResponse = NewErrorResponse(errors.New("stored Grok ACP receipt is unreadable"), ErrCodeDispatchUnknown, "Do not redispatch; repair or reconcile the durable receipt")
				output.State = grok.StateOutcomeUnknown
				output.ReceiptState = "corrupt"
				return output, err
			}
			return output, replayedGrokACPError(output)
		}
		err := errors.New("Grok ACP operation is already in progress or has an unrecorded outcome")
		output.RobotResponse = NewErrorResponse(err, ErrCodeOperationInProgress, "Do not take over or replay; reconcile the original provider operation and use a new operation ID if needed")
		output.State = grok.StateOutcomeUnknown
		output.ReceiptState = "in_progress"
		return output, err
	}
	output.ReceiptState = "claimed"
	decision := deps.Admission.Acquire(opts.Identity)
	output.Admission = admissionEvidence(decision, deps.Admission)
	if !decision.Allowed || !decision.NoFailover {
		err := fmt.Errorf("provider admission denied for identity %s: %s", opts.Identity.Hash(), decision.Reason)
		output.RobotResponse = NewErrorResponse(err, ErrCodeResourceBusy, "Honor retry_at or remediate the exact provider profile; failover is prohibited")
		output.State = "admission_denied"
		if decision.Allowed {
			deps.Admission.Release(opts.Identity, decision)
		}
		if releaseErr := deps.Ledger.ReleaseSendOperation(claimed.OperationID, claimed.SessionName); releaseErr != nil {
			output.ReceiptState = "release_failed"
		}
		return output, err
	}
	defer func() {
		if observer, ok := deps.Admission.(interface {
			ReleaseObserved(provider.Identity, ratelimit.Decision) provider.CapacityReleaseObservation
		}); ok {
			if err := provider.ObserveCapacityRelease(ctx, observer.ReleaseObserved(opts.Identity, decision)); err != nil {
				returnErr = errors.Join(returnErr, errors.New("local capacity observation could not be persisted"))
			}
		} else {
			deps.Admission.Release(opts.Identity, decision)
		}
	}()
	dispatched := true
	defer func() {
		if !dispatched {
			return
		}
		if opts.ReceiptSigner != nil || opts.TrustedSigner.KeyID != "" {
			// Cancellation ends provider work, but its local terminal receipt still
			// needs a bounded opportunity to be signed and persisted.
			finalizeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			if err := sealGrokACPOperationOutput(finalizeCtx, output, opts.ReceiptSigner, opts.TrustedSigner); err != nil {
				returnErr = applyGrokACPLedgerFailure(output)
				return
			}
		}
		if err := completeGrokACPOperation(deps.Ledger, claimed, output, deps.Now()); err != nil {
			returnErr = applyGrokACPLedgerFailure(output)
		}
	}()

	result, runErr := deps.Engine.Run(ctx, grok.Request{
		Prompt:               transmittedPrompt,
		ExpectedNonce:        nonce,
		OperationID:          operationID,
		CWD:                  opts.CWD,
		Binary:               opts.Binary,
		RuntimeHome:          opts.RuntimeHome,
		Model:                opts.Model,
		RuntimeVersion:       opts.RuntimeVersion,
		AutomationPolicyArgs: policyArgs,
		Broker:               opts.Broker,
		BeforeCleanup:        opts.BeforeCleanup,
	})
	applyGrokACPResult(output, result, deps.Evidence)
	if runErr != nil {
		// Only exact provider/account conditions belong in the provider circuit.
		// Local launch, protocol, timeout, and outcome-unknown failures are not
		// evidence that this account/model is rate limited or permanently bad.
		if class, record := classifyGrokAdmissionError(runErr); record {
			deps.Admission.RecordResult(opts.Identity, class, 0)
		}
		applyGrokACPError(output, runErr)
		return output, runErr
	}
	if !result.CompletionConfirmed || strings.TrimSpace(result.StopReason) == "" {
		output.RobotResponse = NewErrorResponse(errors.New("Grok ACP completed without authoritative terminal metadata"), ErrCodeDispatchUnknown, "Inspect the provider session before retrying")
		output.State = grok.StateOutcomeUnknown
		output.FailureCode = grok.ErrOutcomeUnknown
		return output, &grok.Error{Code: grok.ErrOutcomeUnknown, Err: errors.New("completion or stop reason was not confirmed")}
	}
	if !output.AcknowledgementVerified {
		output.RobotResponse = NewErrorResponse(errors.New("Grok ACP completion did not include the required nonce acknowledgement"), string(grok.ErrAcknowledgementUnconfirmed), "Inspect the provider session; do not treat completion alone as acknowledged delivery")
		output.State = "acknowledgement_unconfirmed"
		output.FailureCode = grok.ErrAcknowledgementUnconfirmed
		return output, &grok.Error{Code: grok.ErrAcknowledgementUnconfirmed, Err: errors.New("required nonce acknowledgement was not observed")}
	}
	if strings.TrimSpace(result.Model) == "" || strings.TrimSpace(result.Model) != opts.Identity.Model() || !grokModelIdentityEvidenceConfirmed(result.ModelEvidence) {
		err := errors.New("Grok ACP completion did not provide session-scoped exact model identity evidence")
		output.Model = ""
		output.ModelEvidence = ""
		output.RobotResponse = NewErrorResponse(err, ErrCodeDispatchUnknown, "Inspect the exact xAI provider session and profile; provider failover is prohibited")
		output.State = "identity_unconfirmed"
		output.FailureCode = grok.ErrIdentityMismatch
		return output, &grok.Error{Code: grok.ErrIdentityMismatch, Err: err}
	}
	if strings.TrimSpace(opts.RuntimeVersion) != "" && (result.ResolvedModel != grok.ExpectedResolvedModel(strings.TrimSpace(opts.RuntimeVersion), opts.Identity.Model()) || result.ResolvedModelEvidence != "completion_metadata.usage.model_usage_singleton") {
		err := errors.New("Grok ACP completion did not provide the provider-resolved model bound to the pinned runtime")
		output.RobotResponse = NewErrorResponse(err, ErrCodeDispatchUnknown, "Requalify the exact Grok runtime/model alias; provider failover is prohibited")
		output.State = "identity_unconfirmed"
		output.FailureCode = grok.ErrIdentityMismatch
		return output, &grok.Error{Code: grok.ErrIdentityMismatch, Err: err}
	}
	if !result.RuntimeEventContract.Passed {
		err := errors.New("Grok ACP completion failed the shared runtime-event contract")
		output.RobotResponse = NewErrorResponse(err, ErrCodeDispatchUnknown, "Inspect the normalized tool, completion, usage, and cleanup lifecycle before retrying")
		output.State = grok.StateOutcomeUnknown
		output.FailureCode = grok.ErrOutcomeUnknown
		return output, &grok.Error{Code: grok.ErrOutcomeUnknown, Err: err}
	}
	// Do not clear transient backoff until the structured completion, nonce,
	// and exact model identity have all been verified.
	deps.Admission.RecordSuccess(opts.Identity)
	output.RobotResponse = NewRobotResponse(true)
	output.State = grok.StateCompleted
	return output, nil
}

// grokModelIdentityEvidenceConfirmed deliberately excludes a provider catalog:
// a catalog proves only availability, never which model served this session.
func grokModelIdentityEvidenceConfirmed(evidence string) bool {
	return strings.TrimSpace(evidence) == "completion_metadata"
}

func admissionEvidence(decision ratelimit.Decision, admission ProviderAdmission) AdmissionEvidence {
	scope := admission.CapacityStatus().Scope
	return AdmissionEvidence{Allowed: decision.Allowed, Reason: decision.Reason, RetryAt: decision.RetryAt, NoFailover: decision.NoFailover, CapacityControlScope: scope}
}

func isLinkedGitWorktree(ctx context.Context, cwd string) (bool, error) {
	if ctx == nil || strings.TrimSpace(cwd) == "" {
		return false, errors.New("context and cwd are required")
	}
	gitDir, err := gitPathForWorktree(ctx, cwd, "--absolute-git-dir")
	if err != nil {
		return false, err
	}
	commonDir, err := gitPathForWorktree(ctx, cwd, "--git-common-dir")
	if err != nil {
		return false, err
	}
	if !filepath.IsAbs(commonDir) {
		commonDir, err = filepath.Abs(filepath.Join(cwd, commonDir))
		if err != nil {
			return false, err
		}
	}
	return filepath.Clean(gitDir) != filepath.Clean(commonDir), nil
}

func gitPathForWorktree(ctx context.Context, cwd, flag string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", cwd, "rev-parse", flag)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(output))
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("git returned an invalid worktree path")
	}
	return value, nil
}

func classifyGrokAdmissionError(err error) (ratelimit.ErrorClass, bool) {
	var typed *grok.Error
	if !errors.As(err, &typed) {
		return ratelimit.ErrorUnknown, false
	}
	switch typed.Code {
	case grok.ErrAuthRequired, grok.ErrAuthFailed:
		return ratelimit.ErrorAuthentication, true
	default:
		return ratelimit.ErrorUnknown, false
	}
}

// PrintGrokACPOperation executes the production ACP adapter and emits exactly
// one robot envelope. Provider failures remain visible in the typed receipt
// while the returned process error preserves the robot exit contract.
func PrintGrokACPOperation(ctx context.Context, opts GrokACPOperationOptions) error {
	return PrintGrokACPOperationAuthorized(ctx, opts, nil)
}

// PrintGrokACPOperationAuthorized is the production printer for promoted ACP
// scopes. RunGrokACPOperation still owns the enforcement boundary; this helper
// only carries the CLI's exact signed-qualification verifier into that layer.
func PrintGrokACPOperationAuthorized(ctx context.Context, opts GrokACPOperationOptions, authorizer GrokACPOperationAuthorizer) error {
	output, _ := ExecuteGrokACPOperationAuthorized(ctx, opts, authorizer)
	if output == nil {
		return EncodeErrorJSON(errors.New("Grok ACP produced no receipt"), ErrCodeInternalError, "Inspect local Grok installation", "robot-grok-acp-run")
	}
	return encodeTerminalRobotOutput(output, output.RobotResponse, "Grok ACP operation failed")
}

// ExecuteGrokACPOperationAuthorized exposes the same durable production
// dispatcher to ordinary controls without coupling them to stdout formatting.
func ExecuteGrokACPOperationAuthorized(ctx context.Context, opts GrokACPOperationOptions, authorizer GrokACPOperationAuthorizer) (*GrokACPOperationOutput, error) {
	store := currentProjectionStore()
	if store == nil {
		var err error
		store, err = state.Open("")
		if err != nil {
			return nil, err
		}
		defer store.Close()
		if err := store.Migrate(); err != nil {
			return nil, err
		}
	}
	return RunGrokACPOperation(ctx, opts, GrokACPOperationDeps{Ledger: store, Authorizer: authorizer})
}

func sealGrokACPOperationOutput(ctx context.Context, output *GrokACPOperationOutput, sign func(context.Context, []byte) (providerattestation.SignatureMetadata, error), trusted providerattestation.KeyMetadata) error {
	if output == nil || sign == nil || trusted.KeyID == "" {
		return errors.New("Grok ACP receipt signer is unavailable")
	}
	payload, err := grokACPSignaturePayload(*output)
	if err != nil || providerattestation.ValidateBridgePayload(payload) != nil {
		return errors.New("Grok ACP receipt cannot be canonicalized for signing")
	}
	signature, err := sign(ctx, payload)
	if err != nil || signature.KeyMetadata != trusted || providerattestation.Verify(payload, signature) != nil {
		return errors.New("Grok ACP receipt signature is invalid")
	}
	output.Attestation = &signature
	return nil
}

func canonicalGrokACPOperationOutput(output GrokACPOperationOutput) ([]byte, error) {
	output.Attestation = nil
	// These describe local delivery of the same immutable provider outcome.
	// Ledger readers validate their state independently before returning it.
	output.ReceiptState = ""
	output.Replayed = false
	return json.Marshal(output)
}

// ValidGrokACPOperationSignature verifies the immutable outcome against the
// selected signer. Callers must also check the exact operation/profile binding.
func ValidGrokACPOperationSignature(output GrokACPOperationOutput, trusted providerattestation.KeyMetadata) bool {
	if output.Attestation == nil || trusted.KeyID == "" || output.Attestation.KeyMetadata != trusted {
		return false
	}
	payload, err := grokACPSignaturePayload(output)
	return err == nil && providerattestation.ValidateBridgePayload(payload) == nil && providerattestation.Verify(payload, *output.Attestation) == nil
}

func grokACPSignaturePayload(output GrokACPOperationOutput) ([]byte, error) {
	canonical, err := canonicalGrokACPOperationOutput(output)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	return json.Marshal(struct {
		SchemaVersion  string `json:"schema_version"`
		IdentitySHA256 string `json:"identity_sha256"`
		BindingSHA256  string `json:"binding_sha256"`
		ReceiptSHA256  string `json:"receipt_sha256"`
	}{"ntm.provider-grok-acp.v1", output.ProviderIdentitySHA256, output.BindingSHA256, hex.EncodeToString(digest[:])})
}

func applyGrokACPResult(output *GrokACPOperationOutput, result grok.Result, evidence GrokACPEvidenceProvider) {
	if output == nil {
		return
	}
	output.ProviderSessionID = result.ProviderSessionID
	output.StopReason = result.StopReason
	output.CompletionConfirmed = result.CompletionConfirmed
	// Completion alone is insufficient. This is true only after grok's bounded
	// matcher observed the exact transmitted nonce across assistant chunks.
	output.AcknowledgementVerified = result.CompletionConfirmed && result.AcknowledgementVerified
	output.AssistantTextChunks = result.AssistantTextChunks
	output.AssistantTextBytes = result.AssistantTextBytes
	output.OutputSHA256 = result.OutputSHA256
	output.ToolEventCount = result.ToolEventCount
	output.ToolEventsSHA256 = result.ToolEventsSHA256
	output.ToolRequestCount = result.ToolRequestCount
	output.ToolCompleteCount = result.ToolCompleteCount
	output.NonMessageUpdateCount = result.NonMessageUpdateCount
	output.NonMessageUpdatesSHA256 = result.NonMessageUpdatesSHA256
	if strings.TrimSpace(result.Model) != "" {
		output.Model = strings.TrimSpace(result.Model)
		output.ModelEvidence = strings.TrimSpace(result.ModelEvidence)
	}
	output.ResolvedModel = strings.TrimSpace(result.ResolvedModel)
	output.ResolvedModelEvidence = strings.TrimSpace(result.ResolvedModelEvidence)
	output.TokenUsage = grokUsageToReceipt(result.Usage)
	output.ExitCode = cloneGrokACPExitCode(result.ExitCode)
	output.Cancellation = result.Cancellation
	output.Cleanup = cloneGrokACPCleanup(result.Cleanup)
	output.RuntimeEvents = append([]provider.RuntimeEvent(nil), result.RuntimeEvents...)
	output.RuntimeEventRequirements = result.RuntimeEventRequirements
	output.RuntimeEventContract = result.RuntimeEventContract
	if strings.TrimSpace(result.CleanupState) != "" {
		output.CleanupState = strings.TrimSpace(result.CleanupState)
	}
	output.State = result.State
	output.FailureCode = result.FailureCode
	output.StartedAt = result.StartedAt
	output.CompletedAt = result.CompletedAt
	if evidence == nil {
		return
	}
	meta := evidence.Evidence(result)
	if output.TokenUsage == nil {
		output.TokenUsage = cloneGrokACPTokenUsage(meta.TokenUsage)
	}
	output.Cost = cloneGrokACPCost(meta.Cost)
	if output.ExitCode == nil {
		output.ExitCode = cloneGrokACPExitCode(meta.ExitCode)
	}
	if strings.TrimSpace(meta.CleanupState) != "" {
		output.CleanupState = strings.TrimSpace(meta.CleanupState)
	}
}

func applyGrokACPError(output *GrokACPOperationOutput, err error) {
	if output == nil {
		return
	}
	var typed *grok.Error
	if errors.As(err, &typed) {
		output.FailureCode = typed.Code
		switch typed.Code {
		case grok.ErrOutcomeUnknown:
			output.State = grok.StateOutcomeUnknown
			output.RobotResponse = NewErrorResponse(errors.New("Grok ACP outcome is unknown"), ErrCodeDispatchUnknown, "Inspect the provider session before retrying; do not blindly replay the operation")
			return
		case grok.ErrTimeout:
			output.State = grok.StateAbortedSafe
			output.RobotResponse = NewErrorResponse(errors.New("Grok ACP timed out before prompt acceptance"), ErrCodeTimeout, "Retry with the same operation intent only after confirming no provider session was created")
			return
		case grok.ErrAcknowledgementUnconfirmed:
			output.State = "acknowledgement_unconfirmed"
			output.RobotResponse = NewErrorResponse(errors.New("Grok ACP completion did not include the required nonce acknowledgement"), string(grok.ErrAcknowledgementUnconfirmed), "Inspect the provider session; do not treat completion alone as acknowledged delivery")
			return
		case grok.ErrCancelled:
			output.State = grok.StateCancelled
			output.RobotResponse = NewErrorResponse(errors.New("Grok ACP agent acknowledged cancellation"), "CANCELED", "The ACP agent acknowledged this session/prompt cancellation; this does not prove xAI cloud inference stopped")
			return
		case grok.ErrCancellationUnconfirmed:
			output.State = grok.StateOutcomeUnknown
			output.RobotResponse = NewErrorResponse(errors.New("Grok ACP cancellation acknowledgement was not confirmed"), ErrCodeDispatchUnknown, "Do not retry; inspect the original provider session because the cancellation outcome is unknown")
			return
		}
	}
	output.RobotResponse = NewErrorResponse(errors.New("Grok ACP operation failed"), ErrCodeInternalError, "Inspect the typed failure code; prompts, provider output, and credentials are intentionally not included")
}

func invalidGrokACPOperationOutput(opts GrokACPOperationOptions, now time.Time, err error) *GrokACPOperationOutput {
	return &GrokACPOperationOutput{
		RobotResponse:  NewErrorResponse(errors.New("invalid Grok ACP operation"), ErrCodeInvalidArgs, "Provide a non-empty prompt and valid operation identity"),
		Provider:       grokACPProvider,
		OperationScope: opts.OperationScope,
		Model:          "",
		Transport:      grokACPTransport,
		Target:         grokACPTarget,
		CleanupState:   "not_started",
		Cleanup: grok.ProcessCleanupReceipt{
			LocalTermination: "not_started",
			ResidualPIDs:     []int32{},
		},
		State:       grok.StateFailed,
		FailureCode: grok.ErrInvalidRequest,
		StartedAt:   now,
		CompletedAt: now,
	}
}

func normalizeGrokACPOperationScope(value GrokACPOperationScope) (GrokACPOperationScope, error) {
	scope := GrokACPOperationScope(strings.ToLower(strings.TrimSpace(string(value))))
	if scope == "" {
		return GrokACPOperationScopeObserve, nil
	}
	switch scope {
	case GrokACPOperationScopeObserve, GrokACPOperationScopeReview, GrokACPOperationScopeWorkspaceWrite:
		return scope, nil
	default:
		return "", fmt.Errorf("unsupported Grok ACP operation scope %q", value)
	}
}

func grokACPPolicyAllowedForScope(scope GrokACPOperationScope, policy string) bool {
	switch scope {
	case GrokACPOperationScopeObserve, GrokACPOperationScopeReview:
		return policy == agentpkg.DefaultGrokAutomationPolicyName
	case GrokACPOperationScopeWorkspaceWrite:
		return policy == agentpkg.GrokWorkspaceWritePolicyName
	default:
		return false
	}
}

func validGrokACPQualificationReceiptSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func bindNonceInstruction(prompt, nonce string) string {
	return strings.TrimSpace(prompt) + "\n\nAutomation acknowledgement: after completing the task, reply with this exact token and nothing else on one line: " + nonce
}

func nonEmptyOrGenerated(value, prefix string, random io.Reader) (string, error) {
	value = strings.TrimSpace(value)
	if value != "" {
		return value, nil
	}
	bytes := make([]byte, 16)
	if _, err := io.ReadFull(random, bytes); err != nil {
		return "", fmt.Errorf("generate Grok ACP identity: %w", err)
	}
	return prefix + hex.EncodeToString(bytes), nil
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func cloneGrokACPTokenUsage(value *GrokACPTokenUsage) *GrokACPTokenUsage {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func grokUsageToReceipt(value *grok.Usage) *GrokACPTokenUsage {
	if value == nil {
		return nil
	}
	return &GrokACPTokenUsage{
		Input:  cloneInt64(value.InputTokens),
		Output: cloneInt64(value.OutputTokens),
		Total:  cloneInt64(value.TotalTokens),
	}
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneGrokACPCost(value *GrokACPCost) *GrokACPCost {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneGrokACPExitCode(value *int) *int {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneGrokACPCleanup(value grok.ProcessCleanupReceipt) grok.ProcessCleanupReceipt {
	copy := value
	copy.ResidualPIDs = append([]int32{}, value.ResidualPIDs...)
	return copy
}
