package robot

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	agentpkg "github.com/Dicklesworthstone/ntm/internal/agent"
	"github.com/Dicklesworthstone/ntm/internal/grok"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/state"
)

func TestRunGrokACPOperationBindsNonceAndEmitsSafeReceipt(t *testing.T) {
	completedAt := time.Date(2026, 9, 1, 17, 0, 0, 0, time.UTC)
	engine := &recordingGrokACPEngine{result: grok.Result{
		Success:                 true,
		State:                   grok.StateCompleted,
		ProviderSessionID:       "grok-provider-session",
		StopReason:              "end_turn",
		CompletionConfirmed:     true,
		AcknowledgementVerified: true,
		Model:                   "grok-code",
		ModelEvidence:           "completion_metadata",
		AssistantTextChunks:     3,
		AssistantTextBytes:      44,
		OutputSHA256:            "output-digest",
		StartedAt:               completedAt.Add(-time.Second),
		CompletedAt:             completedAt,
		RuntimeEventContract:    passingGrokRuntimeContract(),
	}}
	exitCode := 0
	evidence := staticGrokACPEvidence{value: GrokACPExecutionEvidence{
		TokenUsage:   &GrokACPTokenUsage{Input: int64ptr(11), Output: int64ptr(22), Total: int64ptr(33)},
		Cost:         &GrokACPCost{Currency: "USD", Micro: 42},
		ExitCode:     &exitCode,
		CleanupState: "reaped",
	}}

	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt:      "inspect only the supplied repository",
		CWD:         "/repo",
		Model:       "grok-code",
		OperationID: "op-7",
		Nonce:       testGrokACPNonce,
		Identity:    testGrokACPIdentity(t),
	}, GrokACPOperationDeps{Engine: engine, Evidence: evidence, Admission: allowingAdmission{}, Ledger: testGrokACPLedger(t)})
	if err != nil {
		t.Fatalf("RunGrokACPOperation() error = %v", err)
	}
	if !output.Success || !output.CompletionConfirmed || !output.AcknowledgementVerified || output.State != grok.StateCompleted {
		t.Fatalf("output = %+v", output)
	}
	if output.Provider != "xai" || output.Transport != "acp_stdio" || output.Target != "stdio" || output.ProviderSessionID != "grok-provider-session" {
		t.Fatalf("provider receipt = %+v", output)
	}
	if output.ProviderIdentityEvidence != provider.IdentityEvidenceProfileAttested || output.Admission.CapacityControlScope != provider.CapacityControlScopeLocalShared {
		t.Fatalf("identity/capacity evidence = %+v", output)
	}
	if output.TokenUsage == nil || output.TokenUsage.Total == nil || *output.TokenUsage.Total != 33 || output.Cost == nil || output.Cost.Micro != 42 || output.ExitCode == nil || *output.ExitCode != 0 || output.CleanupState != "reaped" {
		t.Fatalf("execution evidence = %+v", output)
	}
	if !strings.Contains(engine.request.Prompt, testGrokACPNonce) || engine.request.ExpectedNonce != testGrokACPNonce || engine.request.OperationID != "op-7" || engine.request.Model != "grok-code" {
		t.Fatalf("nonce was not bound to outgoing request: %+v", engine.request)
	}
	if output.Model != "grok-code" {
		t.Fatalf("receipt did not preserve the verified provider model: %q", output.Model)
	}
	if engine.request.Prompt == "inspect only the supplied repository" {
		t.Fatal("outgoing prompt omitted acknowledgement instruction")
	}
	if output.ToolDigest != agentpkg.DefaultGrokAutomationPolicySHA256() || !slices.Equal(engine.request.AutomationPolicyArgs, agentpkg.DefaultGrokAutomationACPPolicyArgs()) {
		t.Fatalf("operation was not bound to the compiled Grok policy: output=%+v request=%+v", output, engine.request)
	}
	serialized := string(mustMarshalGrokACPOperation(t, output))
	for _, forbidden := range []string{"inspect only the supplied repository", testGrokACPNonce, "XAI_API_KEY"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("safe receipt leaked %q: %s", forbidden, serialized)
		}
	}
}

func TestRunGrokACPOperationBindsWorkspacePolicyInDisposableWorktree(t *testing.T) {
	engine := &recordingGrokACPEngine{result: grok.Result{
		Success: true, State: grok.StateCompleted, StopReason: "end_turn",
		CompletionConfirmed: true, AcknowledgementVerified: true,
		Model: "grok-code", ModelEvidence: "completion_metadata",
		RuntimeEventContract: passingGrokRuntimeContract(),
	}}
	broker, err := grok.NewWorkspaceBrokerDescriptor("/linked/worktree", strings.Repeat("a", 40), []string{"go-test"})
	if err != nil {
		t.Fatal(err)
	}
	verified := 0
	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "make the bounded edit", CWD: "/linked/worktree", OperationID: "op-workspace",
		Nonce: testGrokACPNonce, Identity: testGrokACPIdentity(t),
		OperationScope:   GrokACPOperationScopeWorkspaceWrite,
		AutomationPolicy: agentpkg.GrokWorkspaceWritePolicyName, Broker: broker,
	}, GrokACPOperationDeps{
		Engine: engine, Admission: allowingAdmission{}, Ledger: testGrokACPLedger(t),
		Authorizer:           staticGrokACPAuthorizer{authorization: GrokACPOperationAuthorization{QualificationReceiptSHA256: strings.Repeat("b", 64)}},
		IsDisposableWorktree: func(context.Context, string) (bool, error) { verified++; return true, nil },
	})
	if err != nil || verified != 1 || engine.calls != 1 {
		t.Fatalf("output=%+v err=%v verified=%d calls=%d", output, err, verified, engine.calls)
	}
	if output.ToolDigest != agentpkg.GrokAutomationPolicySHA256(agentpkg.GrokWorkspaceWritePolicyName) || !slices.Equal(engine.request.AutomationPolicyArgs, agentpkg.GrokAutomationACPPolicyArgs(agentpkg.GrokWorkspaceWritePolicyName)) || engine.request.Broker == nil {
		t.Fatalf("workspace policy binding output=%+v request=%+v", output, engine.request)
	}
	if output.OperationScope != GrokACPOperationScopeWorkspaceWrite || output.QualificationReceiptSHA256 != strings.Repeat("b", 64) {
		t.Fatalf("workspace authorization was not bound into receipt: %+v", output)
	}
}

func TestRunGrokACPOperationRequiresAuthorizerBeforeClaimAdmissionOrDispatch(t *testing.T) {
	ledger := testGrokACPLedger(t)
	engine := &recordingGrokACPEngine{}
	admission := &recordingAdmission{}
	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "review only", CWD: "/repo", OperationID: "op-review-no-authorizer", Nonce: testGrokACPNonce,
		Identity: testGrokACPIdentity(t), OperationScope: GrokACPOperationScopeReview,
	}, GrokACPOperationDeps{Engine: engine, Admission: admission, Ledger: ledger})
	if err == nil || output.State != "operation_authorization_rejected" || output.ErrorCode != ErrCodeDependencyMissing || engine.calls != 0 || admission.successCalls != 0 || admission.resultCalls != 0 {
		t.Fatalf("non-observe bypass result=%+v err=%v engine=%d admission=%+v", output, err, engine.calls, admission)
	}
	if _, receiptErr := GetGrokACPOperationReceipt("op-review-no-authorizer", ledger); receiptErr == nil {
		t.Fatal("authorization rejection must happen before a durable operation claim")
	}
}

func TestRunGrokACPOperationObserveDoesNotUseAuthorizer(t *testing.T) {
	engine := &recordingGrokACPEngine{result: grok.Result{
		Success: true, State: grok.StateCompleted, CompletionConfirmed: true, AcknowledgementVerified: true,
		Model: "grok-code", ModelEvidence: "completion_metadata", StopReason: "end_turn",
		RuntimeEventContract: passingGrokRuntimeContract(),
	}}
	authorizer := &recordingGrokACPAuthorizer{authorization: GrokACPOperationAuthorization{QualificationReceiptSHA256: strings.Repeat("c", 64)}}
	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "observe", CWD: "/repo", OperationID: "op-observe-no-authorize", Nonce: testGrokACPNonce, Identity: testGrokACPIdentity(t),
	}, GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: testGrokACPLedger(t), Authorizer: authorizer})
	if err != nil || output.OperationScope != GrokACPOperationScopeObserve || output.QualificationReceiptSHA256 != "" || authorizer.calls != 0 || engine.calls != 1 {
		t.Fatalf("observe unexpectedly used promotion authority: output=%+v err=%v authorizer=%+v engine=%d", output, err, authorizer, engine.calls)
	}
}

func TestRunGrokACPOperationReplayCannotCrossScopeOrQualification(t *testing.T) {
	ledger := testGrokACPLedger(t)
	engine := &recordingGrokACPEngine{result: grok.Result{
		Success: true, State: grok.StateCompleted, CompletionConfirmed: true, AcknowledgementVerified: true,
		Model: "grok-code", ModelEvidence: "completion_metadata", StopReason: "end_turn",
		RuntimeEventContract: passingGrokRuntimeContract(),
	}}
	reviewOpts := GrokACPOperationOptions{
		Prompt: "same task", CWD: "/repo", OperationID: "op-scope-bound", Nonce: testGrokACPNonce,
		Identity: testGrokACPIdentity(t), OperationScope: GrokACPOperationScopeReview,
	}
	firstAuth := staticGrokACPAuthorizer{authorization: GrokACPOperationAuthorization{QualificationReceiptSHA256: strings.Repeat("d", 64)}}
	if first, err := RunGrokACPOperation(t.Context(), reviewOpts, GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: ledger, Authorizer: firstAuth}); err != nil || !first.Success || engine.calls != 1 {
		t.Fatalf("initial review output=%+v err=%v engine=%d", first, err, engine.calls)
	}

	changedQualification := staticGrokACPAuthorizer{authorization: GrokACPOperationAuthorization{QualificationReceiptSHA256: strings.Repeat("e", 64)}}
	qualificationReplay, err := RunGrokACPOperation(t.Context(), reviewOpts, GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: ledger, Authorizer: changedQualification})
	if err == nil || qualificationReplay.ErrorCode != ErrCodeIdempotencyConflict || engine.calls != 1 {
		t.Fatalf("qualification-crossing replay output=%+v err=%v engine=%d", qualificationReplay, err, engine.calls)
	}

	broker, brokerErr := grok.NewWorkspaceBrokerDescriptor("/repo", strings.Repeat("a", 40), []string{"go-test"})
	if brokerErr != nil {
		t.Fatal(brokerErr)
	}
	workspaceOpts := reviewOpts
	workspaceOpts.OperationScope = GrokACPOperationScopeWorkspaceWrite
	workspaceOpts.AutomationPolicy = agentpkg.GrokWorkspaceWritePolicyName
	workspaceOpts.Broker = broker
	workspaceReplay, err := RunGrokACPOperation(t.Context(), workspaceOpts, GrokACPOperationDeps{
		Engine: engine, Admission: allowingAdmission{}, Ledger: ledger,
		Authorizer:           firstAuth,
		IsDisposableWorktree: func(context.Context, string) (bool, error) { return true, nil },
	})
	if err == nil || workspaceReplay.ErrorCode != ErrCodeIdempotencyConflict || engine.calls != 1 {
		t.Fatalf("scope-crossing replay output=%+v err=%v engine=%d", workspaceReplay, err, engine.calls)
	}
}

func TestRunGrokACPOperationRejectsWorkspacePolicyOutsideDisposableWorktree(t *testing.T) {
	engine := &recordingGrokACPEngine{}
	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "do not dispatch", CWD: "/primary/checkout", OperationID: "op-primary",
		Nonce: testGrokACPNonce, Identity: testGrokACPIdentity(t),
		OperationScope:   GrokACPOperationScopeWorkspaceWrite,
		AutomationPolicy: agentpkg.GrokWorkspaceWritePolicyName,
	}, GrokACPOperationDeps{
		Engine: engine, Admission: allowingAdmission{}, Ledger: testGrokACPLedger(t),
		IsDisposableWorktree: func(context.Context, string) (bool, error) { return false, nil },
	})
	if err == nil || engine.calls != 0 || output.State != "workspace_policy_rejected" || output.Admission.CapacityControlScope != provider.CapacityControlScopeUnavailable {
		t.Fatalf("output=%+v err=%v calls=%d", output, err, engine.calls)
	}
}

func TestRunGrokACPOperationDoesNotTreatCompletionAsAcknowledgement(t *testing.T) {
	engine := &recordingGrokACPEngine{result: grok.Result{
		Success:             true,
		State:               grok.StateCompleted,
		CompletionConfirmed: true,
		StopReason:          "end_turn",
		// A completion with no exact nonce evidence must not be promoted to ACK.
		AcknowledgementVerified: false,
	}}
	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "hello", CWD: "/repo", OperationID: "op", Nonce: testGrokACPNonce, Identity: testGrokACPIdentity(t),
	}, GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: testGrokACPLedger(t)})
	if err == nil {
		t.Fatal("RunGrokACPOperation() error = nil, want unacknowledged completion failure")
	}
	if output.Success || output.AcknowledgementVerified || output.FailureCode != grok.ErrAcknowledgementUnconfirmed || output.State != "acknowledgement_unconfirmed" {
		t.Fatalf("output = %+v, want unacknowledged completion failure", output)
	}
}

func TestRunGrokACPOperationMapsTypedUnconfirmedAcknowledgement(t *testing.T) {
	engine := &recordingGrokACPEngine{err: &grok.Error{Code: grok.ErrAcknowledgementUnconfirmed, Err: errors.New("nonce absent")}}
	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "hello", CWD: "/repo", OperationID: "op-typed-ack", Nonce: testGrokACPNonce, Identity: testGrokACPIdentity(t),
	}, GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: testGrokACPLedger(t)})
	if err == nil {
		t.Fatal("RunGrokACPOperation() error = nil, want typed acknowledgement failure")
	}
	if output.Success || output.State != "acknowledgement_unconfirmed" || output.FailureCode != grok.ErrAcknowledgementUnconfirmed || output.ErrorCode != string(grok.ErrAcknowledgementUnconfirmed) {
		t.Fatalf("typed acknowledgement output = %+v", output)
	}
}

func TestRunGrokACPOperationPreservesACPCancellationScopeAndLocalCleanup(t *testing.T) {
	engine := &recordingGrokACPEngine{result: grok.Result{
		State:               grok.StateCancelled,
		ProviderSessionID:   "provider-session",
		StopReason:          "cancelled",
		CompletionConfirmed: true,
		Cancellation: grok.ACPCancellationReceipt{
			Requested:                   true,
			NotificationWritten:         true,
			SessionSHA256:               "session-digest",
			OperationSHA256:             "operation-digest",
			PromptRequestID:             4,
			AgentACPAcknowledged:        true,
			Acknowledgement:             "session_prompt_stop_reason_cancelled",
			CloudInferenceStopConfirmed: false,
		},
		Cleanup: grok.ProcessCleanupReceipt{
			LocalTermination: "residual_processes_detected",
			ResidualPIDs:     []int32{101, 102},
			Reaped:           true,
		},
	}, err: &grok.Error{Code: grok.ErrCancelled, Err: context.Canceled}}
	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "hello", CWD: "/repo", OperationID: "op-cancel", Nonce: testGrokACPNonce, Identity: testGrokACPIdentity(t),
	}, GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: testGrokACPLedger(t)})
	if err == nil || output.ErrorCode != "CANCELED" || output.State != grok.StateCancelled || output.FailureCode != grok.ErrCancelled {
		t.Fatalf("cancellation output = %+v err=%v", output, err)
	}
	if !output.Cancellation.AgentACPAcknowledged || output.Cancellation.CloudInferenceStopConfirmed || output.Cancellation.OperationSHA256 != "operation-digest" || output.Cleanup.LocalTermination != "residual_processes_detected" || !slices.Equal(output.Cleanup.ResidualPIDs, []int32{101, 102}) || !output.Cleanup.Reaped {
		t.Fatalf("cancellation/cleanup scope was not preserved: %+v", output)
	}
}

func TestRunGrokACPOperationThreadsStructuredProviderMetadata(t *testing.T) {
	input, outputTokens := int64(17), int64(29)
	exitCode := -1
	engine := &recordingGrokACPEngine{result: grok.Result{
		Success:                 true,
		State:                   grok.StateCompleted,
		CompletionConfirmed:     true,
		AcknowledgementVerified: true,
		StopReason:              "end_turn",
		Model:                   "grok-code",
		ModelEvidence:           "completion_metadata",
		Usage:                   &grok.Usage{InputTokens: &input, OutputTokens: &outputTokens},
		ToolEventCount:          2,
		ToolEventsSHA256:        "event-sequence-sha256",
		NonMessageUpdateCount:   5,
		NonMessageUpdatesSHA256: "non-message-update-sequence-sha256",
		ExitCode:                &exitCode,
		CleanupState:            "reaped_after_termination",
		RuntimeEventContract:    passingGrokRuntimeContract(),
	}}
	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "hello", CWD: "/repo", Model: "grok-code", OperationID: "op", Nonce: testGrokACPNonce, Identity: testGrokACPIdentity(t),
	}, GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: testGrokACPLedger(t)})
	if err != nil {
		t.Fatal(err)
	}
	if output.Model != "grok-code" || output.TokenUsage == nil || output.TokenUsage.Input == nil || *output.TokenUsage.Input != 17 || output.TokenUsage.Output == nil || *output.TokenUsage.Output != 29 || output.TokenUsage.Total != nil || output.ToolEventCount != 2 || output.ToolEventsSHA256 != "event-sequence-sha256" || output.NonMessageUpdateCount != 5 || output.NonMessageUpdatesSHA256 != "non-message-update-sequence-sha256" || output.ExitCode == nil || *output.ExitCode != -1 || output.CleanupState != "reaped_after_termination" {
		t.Fatalf("structured provider receipt = %+v", output)
	}
}

func TestRunGrokACPOperationRejectsFailedRuntimeEventContract(t *testing.T) {
	admission := &recordingAdmission{}
	engine := &recordingGrokACPEngine{result: grok.Result{
		Success:                 true,
		State:                   grok.StateCompleted,
		CompletionConfirmed:     true,
		AcknowledgementVerified: true,
		StopReason:              "end_turn",
		Model:                   "grok-code",
		ModelEvidence:           "completion_metadata",
		RuntimeEventContract: provider.EventContractReport{
			Required:   7,
			Observed:   6,
			Passed:     false,
			Violations: []string{"tool request missing terminal completion"},
		},
	}}
	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "hello", CWD: "/repo", Model: "grok-code", OperationID: "op-contract-failed", Nonce: testGrokACPNonce, Identity: testGrokACPIdentity(t),
	}, GrokACPOperationDeps{Engine: engine, Admission: admission, Ledger: testGrokACPLedger(t)})
	if err == nil || output.Success || output.State != grok.StateOutcomeUnknown || output.FailureCode != grok.ErrOutcomeUnknown {
		t.Fatalf("failed runtime contract output = %+v, err = %v", output, err)
	}
	if output.RuntimeEventContract.Passed || len(output.RuntimeEventContract.Violations) != 1 || admission.successCalls != 0 || admission.resultCalls != 0 {
		t.Fatalf("failed runtime contract evidence/admission = output=%+v admission=%+v", output, admission)
	}
}

func TestRunGrokACPOperationPreservesOutcomeUnknownWithoutLeakingError(t *testing.T) {
	admission := &recordingAdmission{}
	engine := &recordingGrokACPEngine{
		result: grok.Result{State: grok.StateOutcomeUnknown, ProviderSessionID: "session-unknown"},
		err:    &grok.Error{Code: grok.ErrOutcomeUnknown, Err: errors.New("provider may have received secret prompt")},
	}
	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "secret prompt", CWD: "/repo", OperationID: "op", Nonce: testGrokACPNonce, Identity: testGrokACPIdentity(t),
	}, GrokACPOperationDeps{Engine: engine, Admission: admission, Ledger: testGrokACPLedger(t)})
	if err == nil {
		t.Fatal("RunGrokACPOperation() error = nil, want outcome unknown")
	}
	if output.State != grok.StateOutcomeUnknown || output.FailureCode != grok.ErrOutcomeUnknown || output.ErrorCode != ErrCodeDispatchUnknown || output.AcknowledgementVerified {
		t.Fatalf("output = %+v", output)
	}
	if strings.Contains(string(mustMarshalGrokACPOperation(t, output)), "secret prompt") || strings.Contains(string(mustMarshalGrokACPOperation(t, output)), "provider may") {
		t.Fatalf("outcome-unknown receipt leaked sensitive error context: %s", mustMarshalGrokACPOperation(t, output))
	}
	if admission.resultCalls != 0 || admission.successCalls != 0 {
		t.Fatalf("local/outcome-unknown failure poisoned provider capacity: results=%d successes=%d", admission.resultCalls, admission.successCalls)
	}
}

func TestRunGrokACPOperationRecordsOnlyExactProviderAdmissionEvidence(t *testing.T) {
	t.Run("authentication", func(t *testing.T) {
		admission := &recordingAdmission{}
		engine := &recordingGrokACPEngine{err: &grok.Error{Code: grok.ErrAuthFailed, Err: errors.New("rejected")}}
		_, _ = RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
			Prompt: "hello", CWD: "/repo", Nonce: testGrokACPNonce, Identity: testGrokACPIdentity(t),
		}, GrokACPOperationDeps{Engine: engine, Admission: admission, Ledger: testGrokACPLedger(t)})
		if admission.resultCalls != 1 || admission.lastClass != ratelimit.ErrorAuthentication || admission.successCalls != 0 {
			t.Fatalf("authentication admission evidence = %+v", admission)
		}
	})

	t.Run("unverified completion", func(t *testing.T) {
		admission := &recordingAdmission{}
		engine := &recordingGrokACPEngine{result: grok.Result{Success: true, State: grok.StateCompleted, CompletionConfirmed: true, StopReason: "end_turn", Model: "grok-code"}}
		_, _ = RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
			Prompt: "hello", CWD: "/repo", Nonce: testGrokACPNonce, Identity: testGrokACPIdentity(t),
		}, GrokACPOperationDeps{Engine: engine, Admission: admission, Ledger: testGrokACPLedger(t)})
		if admission.resultCalls != 0 || admission.successCalls != 0 {
			t.Fatalf("unverified completion changed provider capacity: %+v", admission)
		}
	})
}

func TestRunGrokACPOperationGeneratesCryptographicIdentity(t *testing.T) {
	engine := &recordingGrokACPEngine{result: grok.Result{Success: true, State: grok.StateCompleted, CompletionConfirmed: true, AcknowledgementVerified: true, Model: "grok-code", ModelEvidence: "completion_metadata", StopReason: "end_turn", RuntimeEventContract: passingGrokRuntimeContract()}}
	random := bytes.NewReader(bytes.Repeat([]byte{0xAB}, 32))
	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{Prompt: "hello", CWD: "/repo", Identity: testGrokACPIdentity(t)}, GrokACPOperationDeps{Engine: engine, Random: random, Admission: allowingAdmission{}, Ledger: testGrokACPLedger(t)})
	if err != nil {
		t.Fatal(err)
	}
	if output.OperationID != "grok-acp-"+strings.Repeat("ab", 16) || output.NonceSHA256 == "" || engine.request.ExpectedNonce != "NTM_ACK_"+strings.Repeat("ab", 16) {
		t.Fatalf("generated identity output=%+v request=%+v", output, engine.request)
	}
}

const testGrokACPNonce = "NTM_ACK_0123456789abcdef0123456789abcdef"

func TestRunGrokACPOperationRejectsWeakNonce(t *testing.T) {
	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "hello", CWD: "/repo", Nonce: "NTM_ACK_short", Identity: testGrokACPIdentity(t),
	}, GrokACPOperationDeps{Engine: &recordingGrokACPEngine{}, Admission: allowingAdmission{}, Ledger: testGrokACPLedger(t)})
	if err == nil || output.FailureCode != grok.ErrInvalidRequest {
		t.Fatalf("weak nonce result = %+v, err = %v", output, err)
	}
}

func TestRunGrokACPOperationRejectsProviderModelMismatch(t *testing.T) {
	for _, model := range []string{"", "other-model"} {
		t.Run("model="+model, func(t *testing.T) {
			engine := &recordingGrokACPEngine{result: grok.Result{Success: true, State: grok.StateCompleted, CompletionConfirmed: true, AcknowledgementVerified: true, Model: model, ModelEvidence: "completion_metadata", StopReason: "end_turn"}}
			output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{Prompt: "hello", CWD: "/repo", Nonce: testGrokACPNonce, Identity: testGrokACPIdentity(t)}, GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: testGrokACPLedger(t)})
			if err == nil || output.Success || output.State != "identity_unconfirmed" || output.FailureCode != grok.ErrIdentityMismatch || !output.Admission.NoFailover {
				t.Fatalf("model mismatch output = %+v, err = %v", output, err)
			}
		})
	}
}

func TestRunGrokACPOperationRejectsCatalogOnlyModelEvidence(t *testing.T) {
	engine := &recordingGrokACPEngine{result: grok.Result{
		Success: true, State: grok.StateCompleted, CompletionConfirmed: true,
		AcknowledgementVerified: true, Model: "grok-code",
		ModelEvidence: "provider_catalog_plus_exact_launch", StopReason: "end_turn",
	}}
	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "hello", CWD: "/repo", Nonce: testGrokACPNonce, Identity: testGrokACPIdentity(t),
	}, GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: testGrokACPLedger(t)})
	if err == nil || output.Success || output.State != "identity_unconfirmed" || output.FailureCode != grok.ErrIdentityMismatch || output.Model != "" || output.ModelEvidence != "" {
		t.Fatalf("catalog-only model evidence output = %+v, err = %v", output, err)
	}
}

func TestRunGrokACPOperationRequiresResolvedModelForPinnedRuntime(t *testing.T) {
	for _, resolved := range []string{"", "other-model"} {
		t.Run("resolved="+resolved, func(t *testing.T) {
			engine := &recordingGrokACPEngine{result: grok.Result{
				Success: true, State: grok.StateCompleted, CompletionConfirmed: true, AcknowledgementVerified: true,
				Model: "grok-code", ModelEvidence: "completion_metadata", ResolvedModel: resolved,
				ResolvedModelEvidence: "completion_metadata.usage.model_usage_singleton", StopReason: "end_turn",
				RuntimeEventContract: passingGrokRuntimeContract(),
			}}
			output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
				Prompt: "hello", CWD: "/repo", Nonce: testGrokACPNonce, Identity: testGrokACPIdentity(t), RuntimeVersion: "1.0.13",
			}, GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: testGrokACPLedger(t)})
			if err == nil || output.Success || output.State != "identity_unconfirmed" || output.FailureCode != grok.ErrIdentityMismatch {
				t.Fatalf("resolved model mismatch output = %+v, err = %v", output, err)
			}
		})
	}
}

func TestGrokModelIdentityEvidenceConfirmedRequiresTerminalCompletionMetadata(t *testing.T) {
	for evidence, want := range map[string]bool{
		"completion_metadata":                             true,
		"provider_session_notification_plus_exact_launch": false,
		"session_config_option_plus_exact_launch":         false,
		"session_model_state_plus_exact_launch":           false,
		"provider_catalog_plus_exact_launch":              false,
		"":                                                false,
	} {
		if got := grokModelIdentityEvidenceConfirmed(evidence); got != want {
			t.Fatalf("grokModelIdentityEvidenceConfirmed(%q)=%v, want %v", evidence, got, want)
		}
	}
}

func TestRunGrokACPOperationAdmissionDenialNeverDispatchesOrFailsOver(t *testing.T) {
	engine := &recordingGrokACPEngine{}
	retryAt := time.Now().UTC().Add(time.Minute)
	admission := denyingAdmission{decision: ratelimit.Decision{
		Reason: ratelimit.ErrorRateLimited, RetryAt: &retryAt, NoFailover: true,
	}}
	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "secret prompt", CWD: "/repo", Identity: testGrokACPIdentity(t),
	}, GrokACPOperationDeps{Engine: engine, Admission: admission, Ledger: testGrokACPLedger(t)})
	if err == nil || engine.calls != 0 {
		t.Fatalf("denied operation dispatched: err=%v calls=%d", err, engine.calls)
	}
	if output.State != "admission_denied" || output.Admission.Allowed || !output.Admission.NoFailover || output.Admission.RetryAt == nil || output.ErrorCode != ErrCodeResourceBusy {
		t.Fatalf("admission receipt = %+v", output)
	}
	if strings.Contains(string(mustMarshalGrokACPOperation(t, output)), "secret prompt") {
		t.Fatalf("denied receipt leaked prompt: %s", mustMarshalGrokACPOperation(t, output))
	}
}

func TestRunGrokACPOperationDurablyReplaysWithoutRedispatch(t *testing.T) {
	ledger := testGrokACPLedger(t)
	engine := &recordingGrokACPEngine{result: grok.Result{
		Success: true, State: grok.StateCompleted, CompletionConfirmed: true,
		AcknowledgementVerified: true, Model: "grok-code", ModelEvidence: "completion_metadata", StopReason: "end_turn",
		RuntimeEventContract: passingGrokRuntimeContract(),
	}}
	opts := GrokACPOperationOptions{
		Prompt: "inspect", CWD: "/repo", OperationID: "op-replay", Nonce: testGrokACPNonce,
		Model: "grok-code", Identity: testGrokACPIdentity(t),
	}
	first, err := RunGrokACPOperation(t.Context(), opts, GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: ledger})
	if err != nil || first.ReceiptState != "completed" || first.Replayed || engine.calls != 1 {
		t.Fatalf("first output=%+v err=%v calls=%d", first, err, engine.calls)
	}
	second, err := RunGrokACPOperation(t.Context(), opts, GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: ledger})
	if err != nil || !second.Success || !second.Replayed || second.ReceiptState != "replayed" || engine.calls != 1 {
		t.Fatalf("replay output=%+v err=%v calls=%d", second, err, engine.calls)
	}
	queried, err := GetGrokACPOperationReceipt(opts.OperationID, ledger)
	if err != nil || !queried.Success || queried.Replayed || queried.ReceiptState != "queried" || queried.BindingSHA256 == "" || engine.calls != 1 {
		t.Fatalf("query output=%+v err=%v calls=%d", queried, err, engine.calls)
	}
}

func TestApplyStoredGrokACPOutcomeRejectsReceiptBindingMismatch(t *testing.T) {
	expected := &GrokACPOperationOutput{
		OperationID: "op-bound", BindingSHA256: sha256String("binding"), ProviderIdentitySHA256: sha256String("identity"),
		Provider: grokACPProvider, Transport: grokACPTransport, Target: grokACPTarget, ToolDigest: sha256String("policy"), BrokerSHA256: sha256String("broker"),
		OperationScope: GrokACPOperationScopeReview, QualificationReceiptSHA256: strings.Repeat("a", 64),
	}
	for name, mutate := range map[string]func(*GrokACPOperationOutput){
		"operation":     func(value *GrokACPOperationOutput) { value.OperationID = "different" },
		"identity":      func(value *GrokACPOperationOutput) { value.ProviderIdentitySHA256 = sha256String("different") },
		"policy":        func(value *GrokACPOperationOutput) { value.ToolDigest = sha256String("different") },
		"broker":        func(value *GrokACPOperationOutput) { value.BrokerSHA256 = sha256String("different") },
		"scope":         func(value *GrokACPOperationOutput) { value.OperationScope = GrokACPOperationScopeWorkspaceWrite },
		"qualification": func(value *GrokACPOperationOutput) { value.QualificationReceiptSHA256 = strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			recorded := *expected
			recorded.ReceiptState = "completed"
			mutate(&recorded)
			data, err := json.Marshal(recorded)
			if err != nil {
				t.Fatal(err)
			}
			stored := &state.SendOperation{Status: state.SendOperationCompleted, BindingHash: expected.BindingSHA256, OutcomeJSON: string(data)}
			copy := *expected
			if err := applyStoredGrokACPOutcome(&copy, stored, providerattestation.KeyMetadata{}); err == nil {
				t.Fatalf("mismatched %s receipt was accepted: %+v", name, recorded)
			}
		})
	}
}

func TestRunGrokACPOperationReplaysWhenNonceIsNormallyGenerated(t *testing.T) {
	ledger := testGrokACPLedger(t)
	engine := &recordingGrokACPEngine{result: grok.Result{
		Success: true, State: grok.StateCompleted, CompletionConfirmed: true,
		AcknowledgementVerified: true, Model: "grok-code", ModelEvidence: "completion_metadata", StopReason: "end_turn",
		RuntimeEventContract: passingGrokRuntimeContract(),
	}}
	random := bytes.NewReader(append(bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 16)...))
	opts := GrokACPOperationOptions{
		Prompt: "inspect", CWD: "/repo", OperationID: "op-generated-nonce",
		Model: "grok-code", Identity: testGrokACPIdentity(t),
	}
	deps := GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: ledger, Random: random}
	first, err := RunGrokACPOperation(t.Context(), opts, deps)
	if err != nil || first.ReceiptState != "completed" || engine.calls != 1 {
		t.Fatalf("first output=%+v err=%v calls=%d", first, err, engine.calls)
	}
	second, err := RunGrokACPOperation(t.Context(), opts, deps)
	if err != nil || !second.Replayed || second.ReceiptState != "replayed" || engine.calls != 1 {
		t.Fatalf("generated-nonce replay output=%+v err=%v calls=%d", second, err, engine.calls)
	}
	if second.NonceSHA256 != first.NonceSHA256 || second.PromptSHA256 != first.PromptSHA256 || second.BindingSHA256 != first.BindingSHA256 {
		t.Fatalf("replay did not return original nonce-bound receipt: first=%+v second=%+v", first, second)
	}
}

func TestRunGrokACPOperationRejectsConflictingOperationBinding(t *testing.T) {
	ledger := testGrokACPLedger(t)
	engine := &recordingGrokACPEngine{result: grok.Result{
		Success: true, State: grok.StateCompleted, CompletionConfirmed: true,
		AcknowledgementVerified: true, Model: "grok-code", ModelEvidence: "completion_metadata", StopReason: "end_turn",
		RuntimeEventContract: passingGrokRuntimeContract(),
	}}
	base := GrokACPOperationOptions{Prompt: "first", CWD: "/repo", OperationID: "op-conflict", Nonce: testGrokACPNonce, Identity: testGrokACPIdentity(t)}
	if _, err := RunGrokACPOperation(t.Context(), base, GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: ledger}); err != nil {
		t.Fatal(err)
	}
	base.Prompt = "different"
	output, err := RunGrokACPOperation(t.Context(), base, GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: ledger})
	if err == nil || output.ErrorCode != ErrCodeIdempotencyConflict || output.ReceiptState != "conflict" || engine.calls != 1 {
		t.Fatalf("conflict output=%+v err=%v calls=%d", output, err, engine.calls)
	}
}

func TestRunGrokACPOperationNeverTakesOverUnknownInProgressClaim(t *testing.T) {
	ledger := testGrokACPLedger(t)
	identity := testGrokACPIdentity(t)
	prompt := bindNonceInstruction("inspect", testGrokACPNonce)
	promptHash := sha256Hex(prompt)
	binding := grokACPBindingHash(identity, sha256Hex("inspect"), "/repo", "", "", "", agentpkg.DefaultGrokAutomationPolicySHA256(), "", GrokACPOperationScopeObserve, "")
	if _, claimed, err := claimGrokACPOperation(ledger, "op-unknown", binding, promptHash, int64(len(prompt)), time.Now().UTC().Add(-24*time.Hour)); err != nil || !claimed {
		t.Fatalf("seed claim: claimed=%v err=%v", claimed, err)
	}
	engine := &recordingGrokACPEngine{}
	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "inspect", CWD: "/repo", OperationID: "op-unknown", Nonce: testGrokACPNonce, Identity: identity,
	}, GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: ledger})
	if err == nil || output.ErrorCode != ErrCodeOperationInProgress || output.State != grok.StateOutcomeUnknown || engine.calls != 0 {
		t.Fatalf("in-progress output=%+v err=%v calls=%d", output, err, engine.calls)
	}
	queried, queryErr := GetGrokACPOperationReceipt("op-unknown", ledger)
	if queryErr != nil || queried.ReceiptState != "in_progress" || queried.ErrorCode != ErrCodeOperationInProgress || queried.BindingSHA256 != binding {
		t.Fatalf("in-progress query=%+v err=%v", queried, queryErr)
	}
}

func TestRunGrokACPOperationRequiresDurableLedgerAndExactRequestedModel(t *testing.T) {
	engine := &recordingGrokACPEngine{}
	identity := testGrokACPIdentity(t)
	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "inspect", CWD: "/repo", OperationID: "op-no-ledger", Nonce: testGrokACPNonce, Identity: identity,
	}, GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}})
	if err == nil || output.ReceiptState != "claim_failed" || engine.calls != 0 {
		t.Fatalf("missing-ledger output=%+v err=%v calls=%d", output, err, engine.calls)
	}
	output, err = RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "inspect", CWD: "/repo", OperationID: "op-wrong-model", Nonce: testGrokACPNonce, Model: "other", Identity: identity,
	}, GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: testGrokACPLedger(t)})
	if err == nil || output.State != "identity_rejected" || output.FailureCode != grok.ErrIdentityMismatch || engine.calls != 0 {
		t.Fatalf("wrong-model output=%+v err=%v calls=%d", output, err, engine.calls)
	}
}

func TestRunGrokACPOperationRejectsProcessLocalCapacityBeforeDispatch(t *testing.T) {
	engine := &recordingGrokACPEngine{}
	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "inspect", CWD: "/repo", OperationID: "op-local-capacity", Nonce: testGrokACPNonce, Identity: testGrokACPIdentity(t),
	}, GrokACPOperationDeps{
		Engine:    engine,
		Admission: allowingAdmission{scope: provider.CapacityControlScopeProcessLocal},
		Ledger:    testGrokACPLedger(t),
	})
	if err == nil || output.State != "capacity_unavailable" || output.Admission.CapacityControlScope != provider.CapacityControlScopeProcessLocal || engine.calls != 0 {
		t.Fatalf("process-local capacity output=%+v err=%v engine_calls=%d", output, err, engine.calls)
	}
}

func TestRunGrokACPOperationRejectsAdmissionThatPermitsFailover(t *testing.T) {
	engine := &recordingGrokACPEngine{}
	admission := &failoverCapableAdmission{}
	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "inspect", CWD: "/repo", OperationID: "op-no-failover", Nonce: testGrokACPNonce, Identity: testGrokACPIdentity(t),
	}, GrokACPOperationDeps{Engine: engine, Admission: admission, Ledger: testGrokACPLedger(t)})
	if err == nil || output.State != "admission_denied" || engine.calls != 0 || admission.releases != 1 {
		t.Fatalf("output=%+v err=%v engine_calls=%d releases=%d", output, err, engine.calls, admission.releases)
	}
}

func TestRunGrokACPOperationSignsCancelledOutcomeWithBoundedFinalization(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDigest := sha256.Sum256(public)
	publicHash := hex.EncodeToString(publicDigest[:])
	trusted := providerattestation.KeyMetadata{
		Algorithm: providerattestation.AlgorithmEd25519, KeyID: "ed25519:" + publicHash,
		PublicKey: base64.RawURLEncoding.EncodeToString(public), PublicKeySHA256: publicHash,
		ProtectionEvidence: providerattestation.ProtectionOSProcessRead,
	}
	for _, signingFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "signed", true: "signer_failure"}[signingFails], func(t *testing.T) {
			type contextKey struct{}
			ctx, cancel := context.WithCancel(context.WithValue(t.Context(), contextKey{}, "local-observer"))
			defer cancel()
			engine := &recordingGrokACPEngine{
				onRun: func(runCtx context.Context) {
					cancel()
					if !errors.Is(runCtx.Err(), context.Canceled) {
						t.Fatal("provider did not receive cancellation")
					}
				},
				result: grok.Result{State: grok.StateCancelled, StopReason: "cancelled", CompletionConfirmed: true,
					Cancellation: grok.ACPCancellationReceipt{Requested: true, AgentACPAcknowledged: true}},
				err: &grok.Error{Code: grok.ErrCancelled, Err: context.Canceled},
			}
			var signingContext context.Context
			opts := GrokACPOperationOptions{
				Prompt: "inspect", CWD: "/repo", OperationID: "op-cancel-signed", Nonce: testGrokACPNonce,
				Identity: testGrokACPIdentity(t), TrustedSigner: trusted,
				ReceiptSigner: func(signCtx context.Context, payload []byte) (providerattestation.SignatureMetadata, error) {
					if engine.calls > 0 && signCtx.Value(contextKey{}) != nil {
						signingContext = signCtx
						deadline, bounded := signCtx.Deadline()
						if signCtx.Err() != nil || !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > 10*time.Second || signCtx.Value(contextKey{}) != "local-observer" {
							t.Fatal("finalization must preserve values with a live bounded context")
						}
						if signingFails {
							return providerattestation.SignatureMetadata{}, errors.New("signer unavailable")
						}
					}
					digest := sha256.Sum256(payload)
					return providerattestation.SignatureMetadata{KeyMetadata: trusted,
						PayloadSHA256: hex.EncodeToString(digest[:]),
						Signature:     base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, payload))}, nil
				},
			}
			ledger := testGrokACPLedger(t)
			deps := GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: ledger}
			output, runErr := RunGrokACPOperation(ctx, opts, deps)
			if runErr == nil || signingContext == nil || !errors.Is(signingContext.Err(), context.Canceled) {
				payload, payloadErr := grokACPSignaturePayload(*output)
				t.Fatalf("missing terminal error or finalization cleanup: %v; signing context=%v payload=%s marshal=%v validation=%v", runErr, signingContext, payload, payloadErr, providerattestation.ValidateBridgePayload(payload))
			}
			if signingFails {
				if output.ReceiptState != "persistence_failed" || output.Attestation != nil {
					t.Fatalf("unsigned outcome granted readiness: %+v", output)
				}
			} else if output.State != grok.StateCancelled || !output.Cancellation.AgentACPAcknowledged || !ValidGrokACPOperationSignature(*output, trusted) {
				t.Fatalf("cancelled outcome was not signed: %+v", output)
			}
			// A later invocation must read the durable result or remain uncertain;
			// neither a cancelled result nor a signing failure may replay work.
			replayed, _ := RunGrokACPOperation(t.Context(), opts, deps)
			if engine.calls != 1 {
				t.Fatal("terminal operation was dispatched again")
			}
			if !signingFails && (replayed.State != grok.StateCancelled || !ValidGrokACPOperationSignature(*replayed, trusted)) {
				t.Fatalf("durable signed cancellation was lost: %+v", replayed)
			}
			if !signingFails {
				queried, err := GetGrokACPOperationReceipt(opts.OperationID, ledger)
				if err != nil || !ValidGrokACPOperationSignature(*queried, trusted) {
					t.Fatalf("query invalidated signature: %v", err)
				}
				stdout, printErr := captureStdout(t, func() error {
					return encodeTerminalRobotOutput(queried, queried.RobotResponse, "cancelled")
				})
				var printed GrokACPOperationOutput
				if printErr == nil || json.Unmarshal([]byte(stdout), &printed) != nil || !ValidGrokACPOperationSignature(printed, trusted) {
					t.Fatalf("terminal printer invalidated signature: %v", printErr)
				}
				queried.Cancellation.AgentACPAcknowledged = false
				if ValidGrokACPOperationSignature(*queried, trusted) {
					t.Fatal("changed cancellation evidence retained signature validity")
				}
			}
		})
	}
}

func TestRunGrokACPOperationSignerPreflightRejectsBeforeDispatch(t *testing.T) {
	engine := &recordingGrokACPEngine{}
	output, err := RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "inspect", CWD: "/repo", OperationID: "op-signer-preflight", Nonce: testGrokACPNonce,
		Identity: testGrokACPIdentity(t), TrustedSigner: providerattestation.KeyMetadata{KeyID: "test"},
		ReceiptSigner: func(context.Context, []byte) (providerattestation.SignatureMetadata, error) {
			return providerattestation.SignatureMetadata{}, errors.New("old helper rejects schema")
		},
	}, GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: testGrokACPLedger(t)})
	if err == nil || output.State != "signer_unavailable" || engine.calls != 0 {
		t.Fatalf("unavailable signer allowed dispatch: output=%+v err=%v calls=%d", output, err, engine.calls)
	}
}

func TestRunGrokACPOperationForwardsPreCleanupDiagnostics(t *testing.T) {
	engine := &recordingGrokACPEngine{err: &grok.Error{Code: grok.ErrCancelled, Err: context.Canceled}}
	want := errors.New("diagnostic storage unavailable")
	_, _ = RunGrokACPOperation(t.Context(), GrokACPOperationOptions{
		Prompt: "inspect", CWD: "/repo", OperationID: "op-diagnostic", Nonce: testGrokACPNonce,
		Identity: testGrokACPIdentity(t), BeforeCleanup: func(provider.ProtocolObservation) error { return want },
	}, GrokACPOperationDeps{Engine: engine, Admission: allowingAdmission{}, Ledger: testGrokACPLedger(t)})
	if engine.request.BeforeCleanup == nil || !errors.Is(engine.request.BeforeCleanup(provider.ProtocolObservation{}), want) {
		t.Fatal("ordinary dispatch lost the pre-cleanup diagnostic sink")
	}
}

type recordingGrokACPEngine struct {
	request grok.Request
	result  grok.Result
	err     error
	calls   int
	onRun   func(context.Context)
}

func (e *recordingGrokACPEngine) Run(ctx context.Context, req grok.Request) (grok.Result, error) {
	e.calls++
	e.request = req
	if e.onRun != nil {
		e.onRun(ctx)
	}
	return e.result, e.err
}

type allowingAdmission struct{ scope provider.CapacityControlScope }

func (allowingAdmission) Acquire(provider.Identity) ratelimit.Decision {
	return ratelimit.Decision{Allowed: true, NoFailover: true}
}
func (allowingAdmission) Release(provider.Identity, ratelimit.Decision) {}
func (allowingAdmission) RecordResult(provider.Identity, ratelimit.ErrorClass, time.Duration) ratelimit.Decision {
	return ratelimit.Decision{NoFailover: true}
}
func (allowingAdmission) RecordSuccess(provider.Identity) {}
func (a allowingAdmission) CapacityStatus() ratelimit.CapacityStatus {
	scope := a.scope
	if scope == "" {
		scope = provider.CapacityControlScopeLocalShared
	}
	return ratelimit.CapacityStatus{Scope: scope}
}

type recordingAdmission struct {
	resultCalls  int
	successCalls int
	lastClass    ratelimit.ErrorClass
}

func (*recordingAdmission) Acquire(provider.Identity) ratelimit.Decision {
	return ratelimit.Decision{Allowed: true, NoFailover: true}
}
func (*recordingAdmission) Release(provider.Identity, ratelimit.Decision) {}
func (a *recordingAdmission) RecordResult(_ provider.Identity, class ratelimit.ErrorClass, _ time.Duration) ratelimit.Decision {
	a.resultCalls++
	a.lastClass = class
	return ratelimit.Decision{Reason: class, NoFailover: true}
}
func (a *recordingAdmission) RecordSuccess(provider.Identity) { a.successCalls++ }
func (*recordingAdmission) CapacityStatus() ratelimit.CapacityStatus {
	return ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}
}

type denyingAdmission struct{ decision ratelimit.Decision }

func (d denyingAdmission) Acquire(provider.Identity) ratelimit.Decision { return d.decision }
func (denyingAdmission) Release(provider.Identity, ratelimit.Decision)  {}
func (d denyingAdmission) RecordResult(provider.Identity, ratelimit.ErrorClass, time.Duration) ratelimit.Decision {
	return d.decision
}
func (denyingAdmission) RecordSuccess(provider.Identity) {}
func (denyingAdmission) CapacityStatus() ratelimit.CapacityStatus {
	return ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}
}

type failoverCapableAdmission struct{ releases int }

func (*failoverCapableAdmission) Acquire(provider.Identity) ratelimit.Decision {
	return ratelimit.Decision{Allowed: true, NoFailover: false}
}
func (a *failoverCapableAdmission) Release(provider.Identity, ratelimit.Decision) { a.releases++ }
func (*failoverCapableAdmission) RecordResult(provider.Identity, ratelimit.ErrorClass, time.Duration) ratelimit.Decision {
	return ratelimit.Decision{}
}
func (*failoverCapableAdmission) RecordSuccess(provider.Identity) {}
func (*failoverCapableAdmission) CapacityStatus() ratelimit.CapacityStatus {
	return ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}
}

func testGrokACPIdentity(t *testing.T) provider.Identity {
	t.Helper()
	identity, err := provider.NewIdentity(
		"xai", "test-account", "grok-code", "https://api.x.ai/v1", "grok", strings.Repeat("a", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

type staticGrokACPEvidence struct{ value GrokACPExecutionEvidence }

func (s staticGrokACPEvidence) Evidence(grok.Result) GrokACPExecutionEvidence { return s.value }

type staticGrokACPAuthorizer struct {
	authorization GrokACPOperationAuthorization
	err           error
}

func (s staticGrokACPAuthorizer) AuthorizeGrokACPOperation(context.Context, GrokACPOperationScope, provider.Identity) (GrokACPOperationAuthorization, error) {
	return s.authorization, s.err
}

type recordingGrokACPAuthorizer struct {
	authorization GrokACPOperationAuthorization
	err           error
	calls         int
}

func (r *recordingGrokACPAuthorizer) AuthorizeGrokACPOperation(_ context.Context, _ GrokACPOperationScope, _ provider.Identity) (GrokACPOperationAuthorization, error) {
	r.calls++
	return r.authorization, r.err
}

func mustMarshalGrokACPOperation(t *testing.T, output *GrokACPOperationOutput) []byte {
	t.Helper()
	data, err := jsonMarshal(output)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// jsonMarshal keeps this focused test decoupled from robot's custom encoders.
func jsonMarshal(value any) ([]byte, error) { return json.Marshal(value) }

func int64ptr(value int64) *int64 { return &value }

func passingGrokRuntimeContract() provider.EventContractReport {
	return provider.EventContractReport{Required: 7, Observed: 7, Passed: true, Violations: []string{}}
}

func testGrokACPLedger(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}
