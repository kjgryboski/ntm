package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/grok"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/robot"
	"github.com/Dicklesworthstone/ntm/internal/state"
	"github.com/spf13/cobra"
)

const providerControlScope = "provider:assignment-control"
const providerCancelScope = "provider:assignment-cancel"

// One immutable edge per completed turn prevents forks and duplicate work.
// An interrupted claimant is quarantined; elapsed time never grants takeover.
func claimGrokSessionSuccessor(ctx context.Context, ledger providerNativeOperationLedger, profile config.ProviderProfileConfig, identity provider.Identity, request providerAssignmentRequest, trusted providerattestation.KeyMetadata) (*robot.GrokACPOperationOutput, error) {
	if request.ParentSession == request.OperationID || !validProviderNativeOperationID(request.ParentSession) {
		return nil, errors.New("resume requires a distinct completed predecessor operation ID")
	}
	row, err := ledger.GetSendOperation(request.ParentSession, "provider:xai-acp")
	if err != nil {
		return nil, err
	}
	var parent robot.GrokACPOperationOutput
	if row == nil || row.Status != state.SendOperationCompleted || json.Unmarshal([]byte(row.OutcomeJSON), &parent) != nil || !robot.ValidGrokACPOperationSignature(parent, trusted) || parent.BindingSHA256 != row.BindingHash || parent.ProviderIdentitySHA256 != identity.Hash() || parent.WorkspaceSHA256 != sha256StringCLI(request.CWD) || parent.ProviderSessionID == "" || parent.SessionClosed || !parent.Cleanup.Reaped || parent.Cleanup.ResidualPIDs == nil || len(parent.Cleanup.ResidualPIDs) != 0 {
		return nil, errors.New("predecessor lacks a signed completed session for this exact identity and workspace")
	}
	// A confirmed cancellation may be closed without promoting it to completed
	// coding work. It cannot authorize another generation turn.
	closeCancelled := request.CloseSession && parent.State == grok.StateCancelled && parent.StopReason == "cancelled" && parent.Cancellation.Requested && parent.Cancellation.AgentACPAcknowledged && parent.Cancellation.SessionSHA256 == sha256StringCLI(parent.ProviderSessionID)
	completed := parent.State == grok.StateCompleted && parent.CompletionConfirmed && parent.AcknowledgementVerified && parent.ResolvedModel != "" && parent.ResolvedModel == grok.ExpectedResolvedModel(profile.RuntimeVersion, identity.Model()) && parent.RuntimeEventContract.Passed
	if (!completed && !closeCancelled) || parent.RuntimeVersion != profile.RuntimeVersion || parent.Model != identity.Model() || parent.Cleanup.ObservedAt.IsZero() {
		return nil, errors.New("predecessor runtime, model or terminal event evidence is incomplete")
	}
	control, err := ledger.GetSendOperation(request.ParentSession, providerControlScope)
	if err != nil {
		return nil, err
	}
	var outcome providerControlOutcome
	if control == nil || control.Status != state.SendOperationCompleted || json.Unmarshal([]byte(control.OutcomeJSON), &outcome) != nil || outcome.IdentitySHA256 != identity.Hash() || outcome.OperationBindingSHA256 != row.BindingHash || (!closeCancelled && !validProviderWorkspaceCompletion(outcome.WorkspaceCompletion, row, identity, trusted)) {
		return nil, errors.New("predecessor controller cleanup and workspace verification are incomplete")
	}
	capacity := outcome.Capacity
	if capacity == nil || capacity.IdentitySHA256 != identity.Hash() || capacity.Scope != provider.CapacityControlScopeLocalShared || !capacity.LocalSlotReleased || capacity.ObservedAt.IsZero() {
		return nil, errors.New("predecessor local capacity release is unverified")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	binding := sha256StringCLI(fmt.Sprintf("%s\x00%s\x00%s\x00%t", identity.Hash(), request.OperationID, sha256StringCLI(request.Prompt), request.CloseSession))
	edge, won, err := ledger.ClaimSendOperation(&state.SendOperation{OperationID: request.ParentSession, SessionName: "provider:grok-session-successor", BindingHash: binding, PayloadSHA256: sha256StringCLI(request.OperationID), CreatedAt: time.Now().UTC()})
	if err != nil {
		return nil, err
	}
	if !won && (edge == nil || edge.BindingHash != binding) {
		return nil, errors.New("session already has a successor; use the last completed operation or reconcile its uncertain outcome")
	}
	return &parent, nil
}

type providerControlOutcome struct {
	SetupFailure           *providerSetupFailure                `json:"setup_failure,omitempty"`
	IdentitySHA256         string                               `json:"identity_sha256"`
	OperationBindingSHA256 string                               `json:"operation_binding_sha256"`
	CancelObserved         bool                                 `json:"cancel_observed"`
	RestartOfSHA256        string                               `json:"restart_of_sha256,omitempty"`
	Capacity               *provider.CapacityReleaseObservation `json:"capacity,omitempty"`
	WorkspaceCompletion    *providerWorkspaceCompletion         `json:"workspace_completion,omitempty"`
}

type providerSetupFailure struct {
	Stage      string    `json:"stage"`
	Reason     string    `json:"reason"`
	ObservedAt time.Time `json:"observed_at"`
}

type providerSetupObserverKey struct{}

// Called only on the preparation error branch, before any campaign reservation
// or runtime adapter invocation. Raw errors can contain paths or payloads.
func recordProviderSetupFailure(ctx context.Context, cause error) error {
	reason := "prerequisite_rejected"
	if strings.HasPrefix(cause.Error(), "bind provider broker to disposable worktree:") {
		reason = "workspace_not_linked"
	}
	observe, ok := ctx.Value(providerSetupObserverKey{}).(func(providerSetupFailure) error)
	if !ok {
		return errors.New("setup failure observation owner unavailable")
	}
	return observe(providerSetupFailure{Stage: "before_attempt_reservation", Reason: reason, ObservedAt: time.Now().UTC()})
}

const providerSetupReviewScope = "provider:setup-refusal-review"
const providerSetupReviewPolicy = "ntm.reviewed-setup-refusal.v1"

type providerSetupRefusalReview struct {
	Schema            string                         `json:"schema_version"`
	Profile           string                         `json:"profile"`
	IdentitySHA256    string                         `json:"identity_sha256"`
	OperationIDSHA256 string                         `json:"operation_id_sha256"`
	ControllerSHA256  string                         `json:"controller_sha256"`
	LedgerSHA256      string                         `json:"ledger_sha256"`
	ErrorSHA256       string                         `json:"error_sha256"`
	SourceSHA256      string                         `json:"source_sha256"`
	Disposition       string                         `json:"disposition"`
	ReviewedAt        time.Time                      `json:"reviewed_at"`
	Envelope          *providerqualification.Receipt `json:"attestation_envelope,omitempty"`
}

func providerSetupReviewDigest(r providerSetupRefusalReview) string {
	r.Envelope = nil
	return digestSafeJSON(r)
}

// Reuse the existing pinned signing envelope, with one non-qualification check
// and a distinct policy. These records are never put in the qualification store.
func signProviderLocalReview(ctx context.Context, p config.ProviderProfileConfig, id provider.Identity, kind, digest string, at time.Time, sign func(context.Context, []byte) (providerattestation.SignatureMetadata, error)) (*providerqualification.Receipt, error) {
	runtimeHash, err := hashProviderSessionExecutable(p.Command)
	if err != nil {
		return nil, err
	}
	transport := "zai_codex_runtime"
	if id.Provider() == "xai" {
		transport = "xai_acp"
	}
	r := &providerqualification.Receipt{Mode: providerqualification.ModeLive, Provider: id.Provider(), Transport: transport, IdentitySHA256: id.Hash(), PolicySHA256: sha256StringCLI(kind), RuntimeVersion: p.RuntimeVersion, RuntimeSHA256: runtimeHash, StartedAt: at, CompletedAt: at, DisposableRepoHash: digest, Checks: []providerqualification.Check{{Name: "operation_binding", Passed: true, Provenance: "local_authoritative", EvidenceSHA256: digest, Detail: "explicit owner review; no runtime execution or qualification"}}}
	if err = r.Finalize(); err != nil {
		return nil, err
	}
	if err = signProviderQualificationReceiptWith(ctx, r, sign); err != nil {
		return nil, err
	}
	return r, nil
}

func validProviderLocalReview(r *providerqualification.Receipt, id provider.Identity, kind, digest string, at time.Time, trusted providerattestation.KeyMetadata, now time.Time) bool {
	return validProviderLocalReviewIdentity(r, id.Provider(), id.Hash(), kind, digest, at, trusted, now)
}

func validProviderLocalReviewIdentity(r *providerqualification.Receipt, providerName, identitySHA, kind, digest string, at time.Time, trusted providerattestation.KeyMetadata, now time.Time) bool {
	if r == nil || r.Passed || r.Validate() != nil || r.Attestation == nil || r.Attestation.KeyMetadata != trusted || r.IdentitySHA256 != identitySHA || r.Provider != providerName || r.PolicySHA256 != sha256StringCLI(kind) || r.DisposableRepoHash != digest || !r.StartedAt.Equal(at) || !r.CompletedAt.Equal(at) || at.IsZero() || at.After(now) || len(r.Checks) != 1 {
		return false
	}
	c := r.Checks[0]
	return c.Name == "operation_binding" && c.EvidenceSHA256 == digest && providerqualification.AuthoritativePassedCheck(c)
}

func decodeProviderLocalReview(data []byte, target any) error {
	if validateProviderReviewJSON(json.NewDecoder(bytes.NewReader(data)), 0) != nil {
		return errors.New("ambiguous local review")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(&struct{}{}) != io.EOF {
		return errors.New("invalid local review")
	}
	return nil
}

// Reject duplicate and case-folded keys before typed decoding, including keys
// inside the attestation's check array. The file reader bounds total input.
func validateProviderReviewJSON(d *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("review nesting exceeds limit")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, compound := token.(json.Delim)
	if !compound {
		if depth == 0 {
			return errors.New("review must be an object")
		}
		return nil
	}
	if delim != '{' && (delim != '[' || depth == 0) {
		return errors.New("invalid review structure")
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			keyToken, err := d.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok || seen[key] || key != strings.ToLower(key) {
				return errors.New("ambiguous review field")
			}
			seen[key] = true
		}
		if err := validateProviderReviewJSON(d, depth+1); err != nil {
			return err
		}
	}
	end, err := d.Token()
	if err != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
		return errors.New("unterminated review")
	}
	return nil
}

func withProviderLocalReviewTarget(cmd *cobra.Command, name string, visit func(config.ProviderProfileConfig, provider.Identity, providerNativeOperationLedger, func(context.Context, []byte) (providerattestation.SignatureMetadata, error), providerattestation.KeyMetadata) error) error {
	cfg := loadSelectedConfigOrDefault()
	if cfg == nil {
		return errors.New("configuration unavailable")
	}
	p, err := cfg.ProviderProfile(name)
	if err != nil {
		return err
	}
	id, err := p.Identity()
	if err != nil {
		return err
	}
	reviewer, err := providerHistoricalReviewSignerProfile(cmd, p)
	if err != nil {
		return err
	}
	sign, err := providerProfilePinnedSigner(reviewer)
	if err != nil {
		return err
	}
	trusted, err := preflightProviderReceiptSignerMetadataFor(providerCommandContext(cmd), sign, id.Provider() == "xai")
	if err != nil {
		return err
	}
	ledger, closeLedger, err := openProviderNativeLedger()
	if err != nil {
		return err
	}
	defer closeLedger()
	return visit(p, id, ledger, sign, trusted.KeyMetadata)
}

// An archived target is not a launchable signing profile. Explicit historical
// reviews may use the current protected reviewer for the same commercial owner.
// This chooses signing authority only; it never substitutes the target identity.
func providerHistoricalReviewSignerProfile(cmd *cobra.Command, target config.ProviderProfileConfig) (config.ProviderProfileConfig, error) {
	flag := cmd.Flags().Lookup("reviewer-profile")
	if flag == nil || flag.Value.String() == "" {
		return target, nil
	}
	selected := loadSelectedConfigOrDefault()
	if selected == nil {
		return config.ProviderProfileConfig{}, errors.New("reviewer configuration unavailable")
	}
	reviewer, err := selected.ProviderProfile(flag.Value.String())
	if err != nil {
		return config.ProviderProfileConfig{}, err
	}
	targetID, err := target.Identity()
	if err != nil {
		return config.ProviderProfileConfig{}, err
	}
	reviewerID, err := reviewer.Identity()
	if err != nil {
		return config.ProviderProfileConfig{}, err
	}
	if targetID.Provider() != "zai" || targetID.Runtime() != "codex" || targetID.Entitlement() != provider.EntitlementCodexResponses || reviewerID.Provider() != targetID.Provider() || reviewerID.Runtime() != targetID.Runtime() || reviewerID.AccountAlias() != targetID.AccountAlias() || reviewerID.SubscriptionCapacityScope() != targetID.SubscriptionCapacityScope() {
		return config.ProviderProfileConfig{}, errors.New("historical reviewer must belong to the exact original provider, account and subscription scope")
	}
	return reviewer, nil
}

func validateProviderSetupReview(r providerSetupRefusalReview, profile, ledgerSHA string, id provider.Identity, control, runtime *state.SendOperation, trusted providerattestation.KeyMetadata, now time.Time) error {
	var outcome providerControlOutcome
	if id.Provider() != "xai" || id.Runtime() != "grok" || control == nil || runtime != nil || control.SessionName != providerControlScope || control.Status != state.SendOperationCompleted || control.CompletedAt == nil || control.PayloadSHA256 != id.Hash() || json.Unmarshal([]byte(control.OutcomeJSON), &outcome) != nil || outcome.IdentitySHA256 != id.Hash() || outcome.OperationBindingSHA256 != "" || outcome.Capacity != nil || outcome.WorkspaceCompletion != nil {
		return errors.New("exact finalized controller without runtime evidence required")
	}
	if r.Schema != providerSetupReviewPolicy || r.Profile != profile || r.IdentitySHA256 != id.Hash() || r.OperationIDSHA256 != sha256StringCLI(control.OperationID) || r.ControllerSHA256 != digestSafeJSON(control) || r.LedgerSHA256 != ledgerSHA || !validProviderNativeDigest(r.ErrorSHA256) || !validProviderNativeDigest(r.SourceSHA256) || r.Disposition != "reviewed_refused_before_dispatch" || r.ReviewedAt.Before(*control.CompletedAt) || !validProviderLocalReview(r.Envelope, id, providerSetupReviewPolicy, providerSetupReviewDigest(r), r.ReviewedAt, trusted, now) {
		return errors.New("setup refusal review differs from exact controller, source or pinned signer")
	}
	return nil
}

func inspectProviderSetupRefusal(profile, operation, ledgerSHA string, id provider.Identity, ledger providerNativeOperationLedger, trusted providerattestation.KeyMetadata) (providerAssignmentStatus, error) {
	var out providerAssignmentStatus
	control, err := ledger.GetSendOperation(operation, providerControlScope)
	if err != nil {
		return out, err
	}
	runtime, err := ledger.GetSendOperation(operation, providerAssignmentScope(id))
	if err != nil {
		return out, err
	}
	row, err := ledger.GetSendOperation(operation, providerSetupReviewScope)
	if err != nil {
		return out, err
	}
	var review providerSetupRefusalReview
	if row == nil || row.Status != state.SendOperationCompleted || decodeProviderLocalReview([]byte(row.OutcomeJSON), &review) != nil || row.BindingHash != review.ControllerSHA256 || row.PayloadSHA256 != id.Hash() {
		return out, errors.New("provider assignment has no authenticated setup-refusal review")
	}
	if err := validateProviderSetupReview(review, profile, ledgerSHA, id, control, runtime, trusted, time.Now().UTC()); err != nil {
		return out, err
	}
	return providerAssignmentStatus{Schema: "ntm.provider-assignment-status.v1", Profile: profile, Provider: id.Provider(), Runtime: id.Runtime(), AccountSHA256: sha256StringCLI(id.AccountAlias()), IdentitySHA256: id.Hash(), OperationIDSHA256: sha256StringCLI(operation), BillingClass: id.BillingClass(), RequestedModel: id.Model(), State: "refused_before_dispatch", SetupRefusalVerified: true, SetupReviewSHA256: digestSafeJSON(review), IdentityBindingVerified: true, ControllerFinalized: true, StartedAt: control.CreatedAt, CompletedAt: control.CompletedAt, RecoveryDisposition: "reviewed_setup_refusal_no_runtime_receipt", RemoteTermination: "unverified"}, nil
}

func newProviderSetupRefusalCmd() *cobra.Command {
	return providerSetupRefusalCommand(withProviderLocalReviewTarget)
}

func providerSetupRefusalCommand(target func(*cobra.Command, string, func(config.ProviderProfileConfig, provider.Identity, providerNativeOperationLedger, func(context.Context, []byte) (providerattestation.SignatureMetadata, error), providerattestation.KeyMetadata) error) error) *cobra.Command {
	var name, operation, errorFile, sourceFile, reviewFile, output string
	var confirm, apply bool
	cmd := &cobra.Command{Use: "setup-refusal", Short: "Review or import a pinned owner disposition for an exact Grok setup refusal", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&name, "profile", "", "Exact original profile")
	cmd.Flags().StringVar(&operation, "operation", "", "Original controller operation")
	cmd.Flags().StringVar(&errorFile, "error-file", "", "Absolute saved error evidence")
	cmd.Flags().StringVar(&sourceFile, "source-file", "", "Absolute reviewed source and dispatch-order evidence")
	cmd.Flags().StringVar(&reviewFile, "review-file", "", "Absolute signed review to preview or import")
	cmd.Flags().StringVar(&output, "output", "", "New absolute signed review file")
	cmd.Flags().BoolVar(&confirm, "confirm-reviewed-predispatch", false, "Explicitly attest that source and original error prove refusal before runtime dispatch")
	cmd.Flags().BoolVar(&apply, "apply", false, "Import the validated signed review; default is preview")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if name == "" || !validProviderNativeOperationID(operation) || !filepath.IsAbs(errorFile) || !filepath.IsAbs(sourceFile) || (confirm && (apply || reviewFile != "" || !filepath.IsAbs(output))) || (!confirm && (output != "" || !filepath.IsAbs(reviewFile))) {
			return errors.New("exact target, error/source evidence and either explicit review signing or an existing signed review required")
		}
		errorData, err := readProviderUsageFile(errorFile)
		if err != nil {
			return err
		}
		sourceData, err := readProviderUsageFile(sourceFile)
		if err != nil {
			return err
		}
		var observed struct {
			Success *bool  `json:"success"`
			Error   string `json:"error"`
		}
		if validateProviderReviewJSON(json.NewDecoder(bytes.NewReader(errorData)), 0) != nil || json.Unmarshal(errorData, &observed) != nil || observed.Success == nil || *observed.Success || observed.Error != "bind provider broker to disposable worktree: workspace broker requires the exact current revision of a linked disposable worktree" || len(bytes.TrimSpace(sourceData)) == 0 {
			return errors.New("saved evidence is not the supported pre-dispatch workspace refusal")
		}
		return target(cmd, name, func(p config.ProviderProfileConfig, id provider.Identity, ledger providerNativeOperationLedger, sign func(context.Context, []byte) (providerattestation.SignatureMetadata, error), trusted providerattestation.KeyMetadata) error {
			control, err := ledger.GetSendOperation(operation, providerControlScope)
			if err != nil {
				return err
			}
			runtime, err := ledger.GetSendOperation(operation, providerAssignmentScope(id))
			if err != nil {
				return err
			}
			ledgerPath, err := filepath.Abs(state.DefaultPath())
			if err != nil {
				return err
			}
			r := providerSetupRefusalReview{Schema: providerSetupReviewPolicy, Profile: name, IdentitySHA256: id.Hash(), OperationIDSHA256: sha256StringCLI(operation), ControllerSHA256: digestSafeJSON(control), LedgerSHA256: sha256StringCLI(ledgerPath), ErrorSHA256: sha256TextCLI(errorData), SourceSHA256: sha256TextCLI(sourceData), Disposition: "reviewed_refused_before_dispatch", ReviewedAt: time.Now().UTC()}
			if confirm {
				// Signing is explicit owner review; the validator below still rejects
				// an active controller, existing runtime, or mismatched identity.
				r.Envelope, err = signProviderLocalReview(providerCommandContext(cmd), p, id, providerSetupReviewPolicy, providerSetupReviewDigest(r), r.ReviewedAt, sign)
				if err != nil {
					return err
				}
			} else {
				data, err := readProviderUsageFile(reviewFile)
				if err != nil {
					return err
				}
				if err = decodeProviderLocalReview(data, &r); err != nil {
					return err
				}
				if r.ErrorSHA256 != sha256TextCLI(errorData) || r.SourceSHA256 != sha256TextCLI(sourceData) {
					return errors.New("reviewed evidence bytes changed")
				}
			}
			if err = validateProviderSetupReview(r, name, sha256StringCLI(ledgerPath), id, control, runtime, trusted, time.Now().UTC()); err != nil {
				return err
			}
			data, err := json.MarshalIndent(r, "", "  ")
			if err != nil {
				return err
			}
			if confirm {
				f, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					return err
				}
				_, writeErr := f.Write(data)
				return errors.Join(writeErr, f.Sync(), f.Close())
			}
			if apply {
				old, won, err := ledger.ClaimSendOperation(&state.SendOperation{OperationID: operation, SessionName: providerSetupReviewScope, BindingHash: r.ControllerSHA256, PayloadSHA256: id.Hash(), CreatedAt: r.ReviewedAt})
				if err != nil {
					return err
				}
				if !won {
					if old.Status != state.SendOperationCompleted || old.BindingHash != r.ControllerSHA256 || old.OutcomeJSON != string(data) {
						return errors.New("conflicting or incomplete setup review; preserve and reconcile")
					}
				} else if err = ledger.CompleteSendOperation(operation, providerSetupReviewScope, string(data), time.Now().UTC()); err != nil {
					return err
				}
			}
			return encodeIndentedJSON(cmd.OutOrStdout(), map[string]any{"review_verified": true, "applied": apply, "classification": "refused_before_dispatch", "runtime_receipt_created": false, "qualification_granted": false, "generation_calls": 0})
		})
	}
	return cmd
}

// Independent verification supplements an exact signed runtime receipt. It
// cannot establish remote termination, served model identity or qualification.
type providerWorkspaceCompletion struct {
	IdentitySHA256         string                         `json:"identity_sha256"`
	OperationBindingSHA256 string                         `json:"operation_binding_sha256"`
	RuntimeReceiptSHA256   string                         `json:"runtime_receipt_sha256"`
	Verification           provider.VerificationReceipt   `json:"verification"`
	Verified               bool                           `json:"verified"`
	ObservedAt             time.Time                      `json:"observed_at"`
	Envelope               *providerqualification.Receipt `json:"attestation_envelope,omitempty"`
}

func providerWorkspaceCompletionDigest(out providerWorkspaceCompletion) string {
	out.Envelope = nil
	return digestSafeJSON(out)
}

func validProviderWorkspaceCompletion(out *providerWorkspaceCompletion, row *state.SendOperation, identity provider.Identity, trusted providerattestation.KeyMetadata) bool {
	if out == nil || row == nil || !out.Verified || out.IdentitySHA256 != identity.Hash() || out.OperationBindingSHA256 != row.BindingHash || out.RuntimeReceiptSHA256 != sha256StringCLI(row.OutcomeJSON) || out.Envelope == nil || out.Envelope.Passed || out.Envelope.Validate() != nil || out.Envelope.IdentitySHA256 != identity.Hash() || out.Envelope.Attestation == nil || out.Envelope.Attestation.KeyMetadata != trusted || len(out.Envelope.Checks) != 1 {
		return false
	}
	check := out.Envelope.Checks[0]
	v := &out.Verification
	if row.CompletedAt == nil || v.StartedAt.Before(*row.CompletedAt) || v.WorktreeSHA256 != out.Envelope.DisposableRepoHash {
		return false
	}
	return check.Name == "operation_binding" && check.EvidenceSHA256 == providerWorkspaceCompletionDigest(*out) && providerqualification.AuthoritativePassedCheck(check) && validProviderGrokVerificationReceipt(v, v.WorktreeSHA256, v.RevisionSHA256, v.ManifestSHA256, out.ObservedAt, out.Envelope.StartedAt, out.Envelope.CompletedAt)
}

func verifyProviderWorkspaceCompletion(ctx context.Context, request providerAssignmentRequest, profile config.ProviderProfileConfig, identity provider.Identity, row *state.SendOperation, ledger providerNativeOperationLedger) (*providerWorkspaceCompletion, error) {
	if row == nil || row.Status != state.SendOperationCompleted {
		return nil, nil
	}
	sign, err := providerProfilePinnedSigner(profile)
	if err != nil {
		return nil, err
	}
	trusted, err := preflightProviderReceiptSignerMetadataFor(ctx, sign, identity.Provider() == "xai")
	if err != nil {
		return nil, err
	}
	terminal := false
	transport := "xai_acp"
	if identity.Provider() == "xai" {
		var receipt robot.GrokACPOperationOutput
		if json.Unmarshal([]byte(row.OutcomeJSON), &receipt) == nil && robot.ValidGrokACPOperationSignature(receipt, trusted.KeyMetadata) && receipt.ProviderIdentitySHA256 == identity.Hash() && receipt.BindingSHA256 == row.BindingHash {
			terminal = receipt.State == grok.StateCompleted && receipt.CompletionConfirmed && receipt.AcknowledgementVerified && receipt.RuntimeEventContract.Passed && receipt.Model == identity.Model() && receipt.ResolvedModel != "" && receipt.ResolvedModel == grok.ExpectedResolvedModel(profile.RuntimeVersion, identity.Model()) && receipt.Cleanup.Reaped && !receipt.Cleanup.ObservedAt.IsZero() && receipt.Cleanup.ResidualPIDs != nil && len(receipt.Cleanup.ResidualPIDs) == 0
		}
	} else {
		transport = "zai_codex_runtime"
		var receipt providerCodexRunOutput
		terminal = json.Unmarshal([]byte(row.OutcomeJSON), &receipt) == nil && validProviderCodexStatusReceipt(receipt, row, request.Profile, identity, trusted.KeyMetadata) && receipt.State == "completed" && receipt.Receipt.RuntimeEventContract.Passed && receipt.Receipt.ResolvedModel == identity.Model() && receipt.Receipt.CompletionConfirmed && receipt.Receipt.NonceVerified && providerCodexReceiptHasNoResiduals(receipt.Receipt)
	}
	if !terminal {
		return nil, nil
	}
	verifier, err := providerVerifyDeps.newVerifier()
	if err != nil {
		return nil, err
	}
	started := time.Now().UTC()
	verification, verifyErr := verifier.Verify(ctx, provider.VerificationManifest{Worktree: request.CWD, Revision: request.BaseRevision, CommandIDs: []string{"go-test", "go-vet"}})
	out := &providerWorkspaceCompletion{IdentitySHA256: identity.Hash(), OperationBindingSHA256: row.BindingHash, RuntimeReceiptSHA256: sha256StringCLI(row.OutcomeJSON), Verification: verification, ObservedAt: time.Now().UTC()}
	out.Verified = verifyErr == nil && validProviderGrokVerificationReceipt(&verification, sha256StringCLI(request.CWD), sha256StringCLI(request.BaseRevision), sha256StringCLI(request.CWD+"\x00"+request.BaseRevision+"\x00go-test\x00go-vet"), out.ObservedAt, started, out.ObservedAt)
	// Save redacted observations before signing. Unsigned observations cannot
	// make the parent control record report workspace completion.
	encoded, err := json.Marshal(out)
	if err != nil {
		return out, err
	}
	const scope = "provider:workspace-verification-observation"
	_, won, err := ledger.ClaimSendOperation(&state.SendOperation{OperationID: request.OperationID, SessionName: scope, BindingHash: row.BindingHash, PayloadSHA256: identity.Hash(), CreatedAt: started})
	if err != nil || !won {
		return out, errors.New("workspace verification observation could not be claimed")
	}
	if err = ledger.CompleteSendOperation(request.OperationID, scope, string(encoded), out.ObservedAt); err != nil {
		return out, err
	}
	runtimeHash, err := hashProviderSessionExecutable(profile.Command)
	if err != nil {
		return out, err
	}
	envelope := providerqualification.Receipt{Mode: providerqualification.ModeLive, Provider: identity.Provider(), Transport: transport, IdentitySHA256: identity.Hash(), PolicySHA256: sha256StringCLI("shared-workspace-completion-v1"), RuntimeVersion: profile.RuntimeVersion, RuntimeSHA256: runtimeHash, StartedAt: started, CompletedAt: out.ObservedAt, DisposableRepoHash: sha256StringCLI(request.CWD), Checks: []providerqualification.Check{{Name: "operation_binding", Passed: true, Provenance: "local_authoritative", EvidenceSHA256: providerWorkspaceCompletionDigest(*out), Detail: "independent ordinary workspace verification; not a qualification"}}}
	if err = envelope.Finalize(); err != nil {
		return out, err
	}
	if err = signProviderQualificationReceiptWith(ctx, &envelope, sign); err != nil {
		return out, err
	}
	out.Envelope = &envelope
	if !validProviderWorkspaceCompletion(out, row, identity, trusted.KeyMetadata) {
		return out, errors.New("workspace completion could not be verified")
	}
	return out, nil
}

func providerAssignmentScope(identity provider.Identity) string {
	switch {
	case identity.Provider() == "xai" && identity.Runtime() == "grok":
		return "provider:xai-acp"
	case identity.Provider() == "zai" && identity.Runtime() == "codex":
		return providerCodexOperationScope
	case (identity.Provider() == "anthropic" && identity.Runtime() == "claude") || (identity.Provider() == "openai" && identity.Runtime() == "codex"):
		return primaryAssignmentScope
	default:
		return ""
	}
}

// The existing durable ledger owns cancellation requests and observations.
// No PID signalling, stale-row takeover, or automatic replay is permitted.
func beginProviderControl(ctx context.Context, ledger providerNativeOperationLedger, identity provider.Identity, request providerAssignmentRequest) (context.Context, func() error, error) {
	if ctx == nil || ledger == nil || !validProviderNativeOperationID(request.OperationID) || providerAssignmentScope(identity) == "" {
		return nil, nil, errors.New("provider operation control requires an exact supported assignment")
	}
	absolute, err := filepath.Abs(request.CWD)
	if err != nil {
		return nil, nil, err
	}
	binding := sha256StringCLI(identity.Hash() + "\x00" + request.OperationID + "\x00" + sha256StringCLI(request.Prompt) + "\x00" + absolute + "\x00" + request.ParentSession + "\x00" + request.RestartOf)
	if request.CloseSession {
		binding = sha256StringCLI(binding + "\x00session_close")
	}
	row, won, err := ledger.ClaimSendOperation(&state.SendOperation{OperationID: request.OperationID, SessionName: providerControlScope, BindingHash: binding, PayloadSHA256: identity.Hash(), CreatedAt: time.Now().UTC()})
	if err != nil {
		return nil, nil, err
	}
	if !won {
		if row.BindingHash != binding || row.PayloadSHA256 != identity.Hash() {
			return nil, nil, errors.New("provider control operation is bound to another assignment")
		}
		if row.Status != state.SendOperationCompleted {
			return nil, nil, errors.New("provider assignment is active or outcome unknown; do not replay")
		}
		original, err := ledger.GetSendOperation(request.OperationID, providerAssignmentScope(identity))
		if err != nil || original == nil || original.Status != state.SendOperationCompleted {
			return nil, nil, errors.New("previous assignment has no terminal receipt; use reconciliation before a new operation")
		}
		return ctx, func() error { return nil }, nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	var mu sync.Mutex
	outcome := providerControlOutcome{IdentitySHA256: identity.Hash()}
	runCtx = context.WithValue(runCtx, providerSetupObserverKey{}, func(failure providerSetupFailure) error {
		mu.Lock()
		defer mu.Unlock()
		outcome.SetupFailure = &failure
		data, err := json.Marshal(failure)
		if err != nil {
			return err
		}
		const scope = "provider:setup-failure-observation"
		_, won, err := ledger.ClaimSendOperation(&state.SendOperation{OperationID: request.OperationID, SessionName: scope, BindingHash: binding, PayloadSHA256: identity.Hash(), CreatedAt: failure.ObservedAt})
		if err != nil || !won {
			return errors.New("setup failure observation could not be persisted")
		}
		return ledger.CompleteSendOperation(request.OperationID, scope, string(data), failure.ObservedAt)
	})
	if request.RestartOf != "" {
		outcome.RestartOfSHA256 = sha256StringCLI(request.RestartOf)
	}
	runCtx = provider.WithCapacityObserver(runCtx, func(observation provider.CapacityReleaseObservation) error {
		if observation.IdentitySHA256 != identity.Hash() {
			return errors.New("capacity observation identity mismatch")
		}
		mu.Lock()
		defer mu.Unlock()
		outcome.Capacity = &observation
		return nil
	})
	done, exited := make(chan struct{}), make(chan struct{})
	var watchErr error
	go func() {
		defer close(exited)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-runCtx.Done():
				return
			case <-ticker.C:
				requestRow, err := ledger.GetSendOperation(request.OperationID, providerCancelScope)
				if err != nil {
					watchErr = errors.New("provider cancellation ledger became unavailable")
					cancel()
					return
				}
				if requestRow == nil {
					continue
				}
				if requestRow.BindingHash != binding || requestRow.PayloadSHA256 != identity.Hash() {
					watchErr = errors.New("provider cancellation binding mismatch")
					cancel()
					return
				}
				mu.Lock()
				outcome.CancelObserved = true
				mu.Unlock()
				cancel()
				return
			}
		}
	}()
	finish := func() error {
		close(done)
		cancel()
		<-exited
		mu.Lock()
		defer mu.Unlock()
		original, err := ledger.GetSendOperation(request.OperationID, providerAssignmentScope(identity))
		if err != nil {
			return err
		}
		if original != nil {
			outcome.OperationBindingSHA256 = original.BindingHash
		}
		var verificationErr error
		if request.VerificationProfile != nil {
			verifyCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 90*time.Second)
			outcome.WorkspaceCompletion, verificationErr = verifyProviderWorkspaceCompletion(verifyCtx, request, *request.VerificationProfile, identity, original, ledger)
			stop()
		}
		encoded, err := json.Marshal(outcome)
		if err != nil {
			return err
		}
		return errors.Join(watchErr, verificationErr, ledger.CompleteSendOperation(request.OperationID, providerControlScope, string(encoded), time.Now().UTC()))
	}
	return runCtx, finish, nil
}

func requestProviderCancellation(ledger providerNativeOperationLedger, identity provider.Identity, operationID string) error {
	if ledger == nil || !validProviderNativeOperationID(operationID) {
		return errors.New("exact provider operation ID is required")
	}
	row, err := ledger.GetSendOperation(operationID, providerControlScope)
	if err != nil {
		return err
	}
	if row == nil || row.PayloadSHA256 != identity.Hash() {
		return errors.New("no matching provider assignment owner was found")
	}
	if row.Status == state.SendOperationCompleted {
		return errors.New("provider assignment controller already finished; inspect its terminal receipt")
	}
	request, _, err := ledger.ClaimSendOperation(&state.SendOperation{OperationID: operationID, SessionName: providerCancelScope, BindingHash: row.BindingHash, PayloadSHA256: identity.Hash(), CreatedAt: time.Now().UTC()})
	if err != nil {
		return err
	}
	if request.BindingHash != row.BindingHash || request.PayloadSHA256 != identity.Hash() {
		return errors.New("provider cancellation request identity mismatch")
	}
	return nil
}

func runProviderInterrupt(cmd *cobra.Command, profileName, operationID string) error {
	loaded := loadSelectedConfigOrDefault()
	if loaded == nil {
		return errors.New("provider configuration is unavailable")
	}
	profile, err := loaded.ProviderProfile(profileName)
	if err != nil {
		return err
	}
	identity, err := profile.Identity()
	if err != nil {
		return err
	}
	ledger, closeLedger, err := openProviderNativeLedger()
	if err != nil {
		return err
	}
	defer closeLedger()
	if err := requestProviderCancellation(ledger, identity, operationID); err != nil {
		return err
	}
	if IsJSONOutput() {
		return encodeIndentedJSON(cmd.OutOrStdout(), map[string]any{"state": "cancel_requested", "identity_sha256": identity.Hash(), "operation_id": operationID, "remote_generation_termination": "unverified"})
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), "Cancellation requested for the exact assignment. Check status for the observed outcome; remote termination is unverified.")
	return err
}

func providerRestartAllowed(status providerAssignmentStatus) bool {
	c := status.CapacityObservation
	cancelled := (status.Provider == "xai" && status.State == grok.StateCancelled) ||
		(status.Provider == "zai" && status.State == "cancelled") ||
		((status.Provider == "anthropic" || status.Provider == "openai") && status.State == "cancelled_local")
	return status.IdentityBindingVerified && status.LocalCleanupVerified &&
		(status.CompletionConfirmed || cancelled) &&
		c != nil && c.IdentitySHA256 == status.IdentitySHA256 && c.Scope == provider.CapacityControlScopeLocalShared &&
		c.LocalSlotReleased && !c.ObservedAt.IsZero() &&
		(status.Provider != "zai" || (c.PlanSlotReleased && c.UsageState == "reconciled"))
}

func runProviderRestart(cmd *cobra.Command, sourceOperation string, request providerAssignmentRequest) error {
	if !validProviderNativeOperationID(sourceOperation) || !validProviderNativeOperationID(request.OperationID) || sourceOperation == request.OperationID {
		return errors.New("provider restart requires distinct original and new operation IDs")
	}
	return withProviderAssignmentStatus(cmd, request.Profile, sourceOperation, func(status providerAssignmentStatus) error {
		if !providerRestartAllowed(status) {
			return errors.New("restart requires a verified terminal outcome, local cleanup, and exact capacity release; unknown outcomes must be reconciled")
		}
		request.RestartOf = sourceOperation
		return dispatchProviderAssignment(cmd, request)
	})
}
