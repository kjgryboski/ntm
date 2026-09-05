package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/grok"
	"github.com/Dicklesworthstone/ntm/internal/provider"
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
}

func providerAssignmentScope(identity provider.Identity) string {
	switch {
	case identity.Provider() == "xai" && identity.Runtime() == "grok":
		return "provider:xai-acp"
	case identity.Provider() == "zai" && identity.Runtime() == "codex":
		return providerCodexOperationScope
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
		encoded, err := json.Marshal(outcome)
		if err != nil {
			return err
		}
		return errors.Join(watchErr, ledger.CompleteSendOperation(request.OperationID, providerControlScope, string(encoded), time.Now().UTC()))
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
		(status.Provider == "zai" && status.State == "cancelled")
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
