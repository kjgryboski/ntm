package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/state"
	"github.com/spf13/cobra"
)

func TestProviderAcceptanceSurfacePreservesReusableFixtureAndBudget(t *testing.T) {
	root := filepath.Join(t.TempDir(), "acceptance")
	cmd := newProviderAcceptanceCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--directory", root})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "acceptance.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		TestsSHA256   string `json:"tests_sha256"`
		ProviderCalls int    `json:"provider_calls"`
		Worktree      string `json:"worktree"`
	}
	if json.Unmarshal(data, &manifest) != nil || manifest.ProviderCalls != 0 {
		t.Fatal("fixture dispatched a provider")
	}
	tests, err := os.ReadFile(filepath.Join(root, "workspace", "calc_test.go"))
	if err != nil || sha256TextCLI(tests) != manifest.TestsSHA256 {
		t.Fatal("fixture tests differ from manifest")
	}
	if runtime.GOOS == "linux" {
		auditPath, guard, err := createPrimaryAssignmentAudit(manifest.Worktree, "fixture-audit")
		if err != nil {
			t.Fatal(err)
		}
		defer guard.Close()
		descriptor, err := providerWorkspaceBrokerDescriptorWithAudit(context.Background(), manifest.Worktree, auditPath)
		if err != nil {
			t.Fatal(err)
		}
		nonce := "NTM_ACK_" + strings.Repeat("a", 32)
		args, err := primaryClaudeArguments(t.TempDir(), "claude-fable-5", "Describe the change", nonce, descriptor)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for index, arg := range args {
			if arg == "--append-system-prompt" && index+1 < len(args) && strings.Contains(args[index+1], nonce) {
				found = true
			}
		}
		if !found {
			t.Fatal("controller completion contract missing from the system prompt")
		}
		if _, err := primaryClaudeArguments(t.TempDir(), "claude-fable-5", "Describe the change", "arbitrary prompt injection", descriptor); err == nil {
			t.Fatal("unbound acknowledgement accepted")
		}
		if _, _, err := createPrimaryAssignmentAudit(manifest.Worktree, "fixture-audit"); err == nil {
			t.Fatal("operation audit was overwritten")
		}
	}
	repeat := newProviderAcceptanceCmd()
	repeat.SetArgs([]string{"--directory", root})
	if repeat.Execute() == nil {
		t.Fatal("existing fixture overwritten")
	}
	ledger, err := state.Open(filepath.Join(root, "budget.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if err := ledger.Migrate(); err != nil {
		t.Fatal(err)
	}
	id, evidence := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := claimPrimaryComparisonExperiment(ledger, "one-attempt", id, evidence); err != nil {
		t.Fatal(err)
	}
	if claimPrimaryComparisonExperiment(ledger, "one-attempt", id, evidence) == nil {
		t.Fatal("paid experiment replayed")
	}
	if claimPrimaryComparisonExperiment(ledger, "new-attempt", id, "") == nil {
		t.Fatal("experiment admitted without relevant evidence binding")
	}
}

func TestPrimaryAssignmentSignedOutputSurvivesPrintingAndRejectsTampering(t *testing.T) {
	id, err := provider.NewIdentity("anthropic", "fixture", "claude-fable-5", "https://api.anthropic.com", "claude", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	row := &state.SendOperation{OperationID: "fixture-assignment", BindingHash: strings.Repeat("b", 64)}
	out := primaryAssignmentOutput{Schema: "ntm.primary-assignment.v1", IdentitySHA256: id.Hash(), OperationIDSHA256: sha256StringCLI(row.OperationID), BindingSHA256: row.BindingHash, RuntimeSHA256: strings.Repeat("c", 64), RequestedModel: id.Model(), State: "cancelled_local", StartedAt: now, CompletedAt: now, CleanupVerified: true}
	envelope := primaryAssignmentEnvelope(out, id, "2.1.252", "/fixture")
	if err := envelope.Finalize(); err != nil {
		t.Fatal(err)
	}
	if err := signProviderQualificationReceiptWith(context.Background(), &envelope, newProviderNativeTestSigner()); err != nil {
		t.Fatal(err)
	}
	out.Envelope = &envelope
	trusted := envelope.Attestation.KeyMetadata
	if !validPrimaryAssignment(out, row, id, trusted) || envelope.Passed {
		t.Fatal("ordinary signed output failed or became qualification")
	}
	prior := jsonOutput
	jsonOutput = true
	defer func() { jsonOutput = prior }()
	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	_ = printPrimaryAssignment(cmd, out)
	var printed primaryAssignmentOutput
	if json.Unmarshal(buf.Bytes(), &printed) != nil || !validPrimaryAssignment(printed, row, id, trusted) {
		t.Fatal("printer mutated signed output")
	}
	for _, mutate := range []func(*primaryAssignmentOutput){
		func(o *primaryAssignmentOutput) { o.State = "completed" },
		func(o *primaryAssignmentOutput) { o.WorkspaceVerified = true },
		func(o *primaryAssignmentOutput) { o.BindingSHA256 = strings.Repeat("d", 64) },
		func(o *primaryAssignmentOutput) { o.IdentitySHA256 = strings.Repeat("d", 64) },
	} {
		changed := out
		mutate(&changed)
		if validPrimaryAssignment(changed, row, id, trusted) {
			t.Fatal("tampered assignment accepted")
		}
	}
	status := providerAssignmentStatus{Provider: "anthropic", IdentitySHA256: id.Hash(), State: "cancelled_local", IdentityBindingVerified: true, LocalCleanupVerified: true, CapacityObservation: &provider.CapacityReleaseObservation{IdentitySHA256: id.Hash(), Scope: provider.CapacityControlScopeLocalShared, LocalSlotReleased: true, ObservedAt: now}}
	if !providerRestartAllowed(status) {
		t.Fatal("verified local cancellation cannot guarded-restart")
	}
	status.LocalCleanupVerified = false
	if providerRestartAllowed(status) {
		t.Fatal("unverified cleanup admitted restart")
	}
}

func TestPrimaryWorkspaceAcknowledgementRequiresControllerVerification(t *testing.T) {
	if primaryWorkspaceVerified(providerGrokWorkspaceAudit{}, "/fixture", "revision", time.Now(), time.Now()) {
		t.Fatal("empty audit grants workspace verification")
	}
	audit := providerGrokWorkspaceAudit{Events: []providerBrokerAuditEvent{{Tool: "verify_worktree", Success: true}}}
	if primaryWorkspaceVerified(audit, "/fixture", "revision", time.Now(), time.Now()) {
		t.Fatal("tool name without receipt grants verification")
	}
}

func TestPrimaryOrdinaryCompletionRequiresTerminalAndIndependentWorkspaceEvidence(t *testing.T) {
	out := primaryAssignmentOutput{RequestedModel: "claude-fable-5", CompletionEvidence: "runtime_terminal_and_controller_verifier", WorkspaceVerified: true, CleanupVerified: true, Observation: primaryComparisonObservation{ServedModel: "claude-fable-5", Completed: true, ExitOK: true}}
	if !primaryAssignmentCompleted(out) || out.Observation.exactModelVerified(out.RequestedModel) {
		t.Fatal("ordinary completion and nonce-bound qualification were conflated")
	}
	for _, invalidate := range []func(*primaryAssignmentOutput){
		func(o *primaryAssignmentOutput) { o.CompletionEvidence = "" },
		func(o *primaryAssignmentOutput) { o.WorkspaceVerified = false },
		func(o *primaryAssignmentOutput) { o.CleanupVerified = false },
		func(o *primaryAssignmentOutput) { o.Observation.Completed = false },
		func(o *primaryAssignmentOutput) { o.Observation.ExitOK = false },
		func(o *primaryAssignmentOutput) { o.Observation.ServedModel = "claude-other" },
		func(o *primaryAssignmentOutput) { o.Observation.ModelConflict = true },
		func(o *primaryAssignmentOutput) { o.Observation.Malformed = true },
		func(o *primaryAssignmentOutput) { o.Observation.UnexpectedTool = true },
	} {
		changed := out
		invalidate(&changed)
		if primaryAssignmentCompleted(changed) {
			t.Fatal("incomplete ordinary evidence granted completion")
		}
	}
}

func TestPrimaryClaudeSnapshotRejectsExpiredCredentialsBeforeDispatch(t *testing.T) {
	now := time.Now().UTC()
	for _, expiry := range []int64{0, now.Add(-time.Hour).UnixMilli(), now.Add(time.Minute).UnixMilli(), now.Add(5 * time.Minute).UnixMilli()} {
		data, _ := json.Marshal(map[string]any{"claudeAiOauth": map[string]any{"expiresAt": expiry}})
		if primaryCredentialSnapshotFresh(data, "claude", now) {
			t.Fatal("expired or expiring credential snapshot accepted")
		}
	}
	data, _ := json.Marshal(map[string]any{"claudeAiOauth": map[string]any{"expiresAt": now.Add(time.Hour).UnixMilli()}})
	if !primaryCredentialSnapshotFresh(data, "claude", now) {
		t.Fatal("fresh snapshot rejected")
	}
}
