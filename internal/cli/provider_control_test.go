package cli

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/state"
)

func TestProviderControlCrossConnectionCancellationAndCapacity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	owner, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err := owner.Migrate(); err != nil {
		t.Fatal(err)
	}
	other, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	identity, err := provider.NewIdentity("xai", "test-account", "grok-4.6", "https://api.x.ai/v1", "grok", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	request := providerAssignmentRequest{OperationID: "owned-task", Profile: "grok-test", Prompt: "bounded work", CWD: t.TempDir(), Timeout: time.Minute}
	ctx, finish, err := beginProviderControl(context.Background(), owner, identity, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := beginProviderControl(context.Background(), other, identity, request); err == nil {
		t.Fatal("duplicate controller admitted")
	}
	foreign, _ := provider.NewIdentity("xai", "other-account", "grok-4.6", "https://api.x.ai/v1", "grok", strings.Repeat("a", 64))
	if requestProviderCancellation(other, foreign, request.OperationID) == nil {
		t.Fatal("foreign cancellation accepted")
	}
	childCtx, childCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer childCancel()
	child := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestProviderInterruptCommandHelper$")
	child.Env = append(os.Environ(), "NTM_PROVIDER_INTERRUPT_HELPER=1", "NTM_CONFIG="+filepath.Join(filepath.Dir(path), "config.toml"))
	if data, err := child.CombinedOutput(); err != nil || !strings.Contains(string(data), "cancel_requested") {
		t.Fatalf("interrupt command err=%v output=%s", err, data)
	}
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("separate connection cancellation was not observed")
	}
	if err := provider.ObserveCapacityRelease(ctx, provider.CapacityReleaseObservation{IdentitySHA256: identity.Hash(), LeaseSHA256: strings.Repeat("b", 64), Scope: provider.CapacityControlScopeLocalShared, LocalSlotReleased: true, UsageState: "not_metered_by_controller", ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	_, _, err = owner.ClaimSendOperation(&state.SendOperation{OperationID: request.OperationID, SessionName: providerAssignmentScope(identity), BindingHash: "adapter-binding"})
	if err != nil {
		t.Fatal(err)
	}
	if err := finish(); err != nil {
		t.Fatal(err)
	}
	row, err := other.GetSendOperation(request.OperationID, providerControlScope)
	if err != nil {
		t.Fatal(err)
	}
	var observation providerControlOutcome
	if err := json.Unmarshal([]byte(row.OutcomeJSON), &observation); err != nil {
		t.Fatal(err)
	}
	if !observation.CancelObserved || observation.Capacity == nil || !observation.Capacity.LocalSlotReleased || observation.OperationBindingSHA256 != "adapter-binding" {
		t.Fatalf("observation=%+v", observation)
	}
	if _, _, err := beginProviderControl(context.Background(), other, identity, request); err == nil {
		t.Fatal("unknown original adapter outcome was replayed")
	}
}

func TestProviderInterruptCommandHelper(t *testing.T) {
	if os.Getenv("NTM_PROVIDER_INTERRUPT_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	cfg = &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"grok-test": {Provider: "xai", AccountAlias: "test-account", Model: "grok-4.6", Endpoint: "https://api.x.ai/v1", Runtime: "grok", ConfigSHA256: strings.Repeat("a", 64), ExactTargetOnly: true, Command: "/bin/true", AutomationPolicy: "grok-readonly-ci", RuntimeHome: filepath.Dir(os.Getenv("NTM_CONFIG")), CredentialBridgeCommand: "/bin/true", CredentialBridgeCommandSHA256: strings.Repeat("b", 64)}}}
	jsonOutput = true
	cmd := newInterruptCmd()
	cmd.SetArgs([]string{"--provider-profile", "grok-test", "--operation-id", "owned-task"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestProviderRestartRequiresTerminalCleanupAndCapacityEvidence(t *testing.T) {
	status := providerAssignmentStatus{Provider: "zai", IdentitySHA256: strings.Repeat("a", 64), IdentityBindingVerified: true, CompletionConfirmed: true, LocalCleanupVerified: true}
	if providerRestartAllowed(status) {
		t.Fatal("cleanup alone permitted restart")
	}
	status.CapacityObservation = &provider.CapacityReleaseObservation{IdentitySHA256: status.IdentitySHA256, Scope: provider.CapacityControlScopeLocalShared, LocalSlotReleased: true, PlanSlotReleased: true, UsageState: "unknown_reserved", ObservedAt: time.Now().UTC()}
	if providerRestartAllowed(status) {
		t.Fatal("unknown usage permitted restart")
	}
	status.CapacityObservation.UsageState = "reconciled"
	if !providerRestartAllowed(status) {
		t.Fatal("verified reconciled restart rejected")
	}
	status.CompletionConfirmed = false
	if providerRestartAllowed(status) {
		t.Fatal("unknown terminal outcome permitted restart")
	}
}

func TestProviderControllerExitCannotReplayUnknownAssignment(t *testing.T) {
	root := t.TempDir()
	childCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestProviderControllerExitHelper$")
	child.Env = append(os.Environ(), "NTM_PROVIDER_CONTROLLER_EXIT_HELPER="+root)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("controller helper: %v %s", err, output)
	}
	ledger, err := state.Open(filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	identity, _ := provider.NewIdentity("xai", "test-account", "grok-4.6", "https://api.x.ai/v1", "grok", strings.Repeat("a", 64))
	request := providerAssignmentRequest{OperationID: "crashed-task", CWD: root, Prompt: "bounded work"}
	if _, _, err := beginProviderControl(context.Background(), ledger, identity, request); err == nil || !strings.Contains(err.Error(), "outcome unknown") {
		t.Fatalf("orphaned assignment replay: %v", err)
	}
	row, err := ledger.GetSendOperation(request.OperationID, providerAssignmentScope(identity))
	if err != nil || row == nil || row.Status != state.SendOperationInProgress {
		t.Fatalf("unknown adapter row changed: %+v %v", row, err)
	}
}

func TestProviderControllerExitHelper(t *testing.T) {
	root := os.Getenv("NTM_PROVIDER_CONTROLLER_EXIT_HELPER")
	if root == "" {
		t.Skip("subprocess helper")
	}
	ledger, err := state.Open(filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err = ledger.Migrate(); err != nil {
		t.Fatal(err)
	}
	identity, _ := provider.NewIdentity("xai", "test-account", "grok-4.6", "https://api.x.ai/v1", "grok", strings.Repeat("a", 64))
	request := providerAssignmentRequest{OperationID: "crashed-task", CWD: root, Prompt: "bounded work"}
	if _, _, err = beginProviderControl(context.Background(), ledger, identity, request); err != nil {
		t.Fatal(err)
	}
	if _, _, err = ledger.ClaimSendOperation(&state.SendOperation{OperationID: request.OperationID, SessionName: providerAssignmentScope(identity), BindingHash: "uncertain-adapter-binding"}); err != nil {
		t.Fatal(err)
	}
	// This subprocess exits without invoking the owner's finish callback.
	// The parent must preserve both durable in-progress rows without replay.
}

func TestProviderRestartSurfaceRejectsSameIDAndPaneOverrides(t *testing.T) {
	for _, args := range [][]string{
		{"old", "--provider-profile", "grok-test", "--operation-id", "old", "--cwd", "/isolated", "--prompt", "work"},
		{"old", "--provider-profile", "grok-test", "--operation-id", "new", "--force"},
	} {
		cmd := newRespawnCmd()
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("unsafe provider restart accepted: %v", args)
		}
	}
}
