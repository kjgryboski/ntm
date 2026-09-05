package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
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

type providerControlOutcome struct {
	IdentitySHA256         string                               `json:"identity_sha256"`
	OperationBindingSHA256 string                               `json:"operation_binding_sha256"`
	CancelObserved         bool                                 `json:"cancel_observed"`
	RestartOfSHA256        string                               `json:"restart_of_sha256,omitempty"`
	Capacity               *provider.CapacityReleaseObservation `json:"capacity,omitempty"`
	WorkspaceCompletion    *providerWorkspaceCompletion         `json:"workspace_completion,omitempty"`
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
