package zai

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
)

const (
	codexTestSession      = "11111111-1111-4111-8111-111111111111"
	codexTestOtherSession = "22222222-2222-4222-8222-222222222222"
)

type codexRunnerFixture struct {
	outcome providerqualification.Outcome
	err     error
	seen    providerqualification.Invocation
}

func (f *codexRunnerFixture) Run(_ context.Context, invocation providerqualification.Invocation) (providerqualification.Outcome, error) {
	f.seen = invocation
	return f.outcome, f.err
}

func codexFixtureSpec(t *testing.T, runner providerqualification.Runner) CodexRunSpec {
	t.Helper()
	root := t.TempDir()
	runtimeBinary := filepath.Join(root, "codex")
	brokerBinary := filepath.Join(root, "caam")
	bridgeBinary := filepath.Join(root, "ntm-provider-bridge")
	writeExecutable := func(path, contents string) string {
		t.Helper()
		if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(contents))
		return fmt.Sprintf("%x", digest[:])
	}
	runtimeSHA := writeExecutable(runtimeBinary, "fixture codex runtime")
	brokerSHA := writeExecutable(brokerBinary, "fixture caam broker")
	bridgeSHA := writeExecutable(bridgeBinary, "fixture credential bridge")
	runtimeHome := filepath.Join(root, "profile", ".codex")
	if err := os.MkdirAll(runtimeHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtimeHome, "auth.json"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return CodexRunSpec{
		Binary:                        runtimeBinary,
		BrokerCommand:                 brokerBinary,
		CredentialBridgeCommand:       bridgeBinary,
		RuntimeHome:                   runtimeHome,
		CWD:                           filepath.Join(root, "worktree"),
		Prompt:                        "make one bounded edit",
		ExpectedNonce:                 "NTM_ACK_0123456789abcdef0123456789abcdef",
		RequestedModel:                "glm-5.3",
		ConfigSHA256:                  strings.Repeat("a", 64),
		BinarySHA256:                  runtimeSHA,
		BrokerCommandSHA256:           brokerSHA,
		CredentialBridgeCommandSHA256: bridgeSHA,
		PolicySHA256:                  strings.Repeat("c", 64),
		RuntimeVersion:                "0.149.0",
		WorkspaceWrite:                true,
		ManifestVerifier: func(context.Context) error {
			return nil
		},
		Runner: runner,
		CredentialBroker: CodexCredentialBrokerFunc(func(context.Context, CodexBrokerRequest) ([]byte, error) {
			return []byte("fixture-plan-token"), nil
		}),
		Env: []string{
			"PATH=/usr/bin",
			"HOME=/home/test",
			"NTM_WINDOWS_PROVIDER_BRIDGE=/mnt/c/bridge.exe",
			"OPENAI_API_KEY=must-not-pass",
			"ZAI_API_KEY=must-not-pass",
		},
	}
}

func codexJSONL(t *testing.T, values ...map[string]any) []byte {
	t.Helper()
	var out strings.Builder
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		out.Write(encoded)
		out.WriteByte('\n')
	}
	return []byte(out.String())
}

func codexSuccessEvents(t *testing.T, session, model, nonce string) []byte {
	t.Helper()
	return codexJSONL(t,
		map[string]any{"type": "thread.started", "thread_id": session},
		map[string]any{"type": "turn.started"},
		map[string]any{"type": "item.completed", "item": map[string]any{"id": "tool-1", "type": "command_execution", "aggregated_output": nonce, "exit_code": 0, "status": "completed"}},
		map[string]any{"type": "item.completed", "item": map[string]any{"id": "message-1", "type": "agent_message", "text": nonce}},
		map[string]any{"type": "turn.completed", "server_model": model, "usage": map[string]any{"input_tokens": 10, "cached_input_tokens": 2, "output_tokens": 3, "total_tokens": 13}},
	)
}

func TestRunCodexStructuredBindsOnlyFinalAgentNonce(t *testing.T) {
	runner := &codexRunnerFixture{}
	spec := codexFixtureSpec(t, runner)
	runner.outcome = providerqualification.Outcome{Stdout: codexSuccessEvents(t, codexTestSession, "glm-5.3", spec.ExpectedNonce), ExitCode: 0}
	receipt, err := RunCodexStructured(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.CompletionConfirmed || !receipt.NonceVerified || !receipt.ModelVerified || receipt.ToolEventCount != 1 || receipt.ResolvedModel != "glm-5.3" || receipt.Usage.TotalTokens != 13 || receipt.SessionIDSHA256 == "" {
		t.Fatalf("receipt = %+v", receipt)
	}
	if receipt.ModelEvidence != "turn.completed.server_model" {
		t.Fatalf("model evidence = %q", receipt.ModelEvidence)
	}
	joinedEnv := strings.Join(runner.seen.Env, "\n")
	envBlock := "\n" + joinedEnv + "\n"
	if strings.Contains(joinedEnv, "must-not-pass") || !strings.Contains(envBlock, "\nCODEX_HOME="+spec.RuntimeHome+"\n") || !strings.Contains(envBlock, "\nHOME="+filepath.Dir(spec.RuntimeHome)+"\n") || strings.Contains(envBlock, "\nHOME="+spec.RuntimeHome+"\n") || strings.Contains(joinedEnv, "NTM_WINDOWS_PROVIDER_BRIDGE=") || !strings.Contains(envBlock, "\nZAI_API_KEY=fixture-plan-token\n") {
		t.Fatalf("unsafe structured environment: %q", joinedEnv)
	}
	joinedArgs := strings.Join(runner.seen.Args, " ")
	if !strings.Contains(joinedArgs, `exec --strict-config --json -c default_permissions="zai_workspace_write"`) || strings.Contains(joinedArgs, "--sandbox") || !strings.Contains(joinedArgs, "--model glm-5.3") {
		t.Fatalf("unexpected argv: %q", joinedArgs)
	}
	if strings.Contains(joinedArgs, spec.Prompt) || string(runner.seen.Stdin) != spec.Prompt+"\n\nWhen finished, return this exact acknowledgement token as the final response and no other final text: "+spec.ExpectedNonce {
		t.Fatalf("prompt was not isolated on stdin: argv=%q stdin=%q", joinedArgs, runner.seen.Stdin)
	}
	encoded, _ := json.Marshal(receipt)
	if strings.Contains(string(encoded), spec.Prompt) || strings.Contains(string(encoded), spec.ExpectedNonce) || strings.Contains(string(encoded), "command_execution") {
		t.Fatalf("receipt retained sensitive execution text: %s", encoded)
	}
}

func TestRunCodexStructuredRejectsNonceOnlyInToolOutput(t *testing.T) {
	runner := &codexRunnerFixture{}
	spec := codexFixtureSpec(t, runner)
	runner.outcome.Stdout = codexJSONL(t,
		map[string]any{"type": "thread.started", "thread_id": codexTestSession, "model": "glm-5.3"},
		map[string]any{"type": "turn.started"},
		map[string]any{"type": "item.completed", "item": map[string]any{"id": "tool-1", "type": "command_execution", "aggregated_output": spec.ExpectedNonce, "status": "completed"}},
		map[string]any{"type": "item.completed", "item": map[string]any{"id": "message-1", "type": "agent_message", "text": "done"}},
		map[string]any{"type": "turn.completed"},
	)
	receipt, err := RunCodexStructured(context.Background(), spec)
	if err == nil || receipt.NonceVerified {
		t.Fatalf("tool-output nonce was accepted: receipt=%+v err=%v", receipt, err)
	}
}

func TestRunCodexStructuredRejectsGenericModelEchoAsResolvedEvidence(t *testing.T) {
	runner := &codexRunnerFixture{}
	spec := codexFixtureSpec(t, runner)
	runner.outcome.Stdout = codexJSONL(t,
		map[string]any{"type": "thread.started", "thread_id": codexTestSession, "model": "glm-5.3"},
		map[string]any{"type": "turn.started"},
		map[string]any{"type": "item.completed", "item": map[string]any{"id": "message-1", "type": "agent_message", "text": spec.ExpectedNonce}},
		map[string]any{"type": "turn.completed", "usage": map[string]any{"input_tokens": 1, "output_tokens": 1}},
	)
	receipt, err := RunCodexStructured(context.Background(), spec)
	if err == nil || receipt.ModelVerified || receipt.ResolvedModel != "" || receipt.ModelEvidence != "" {
		t.Fatalf("generic request-model echo was promoted: receipt=%+v err=%v", receipt, err)
	}
}

func TestRunCodexStructuredAcceptsOnlyTerminalServerModel(t *testing.T) {
	runner := &codexRunnerFixture{}
	spec := codexFixtureSpec(t, runner)
	runner.outcome.Stdout = codexJSONL(t,
		map[string]any{"type": "thread.started", "thread_id": codexTestSession, "model": "glm-5.3", "resolved_model": "glm-5.3-flash"},
		map[string]any{"type": "turn.started", "model": "glm-5.3-flash"},
		map[string]any{"type": "item.completed", "item": map[string]any{"id": "message-1", "type": "agent_message", "text": spec.ExpectedNonce}},
		map[string]any{"type": "turn.completed", "model": "glm-5.3-flash", "resolved_model": "glm-5.3-flash", "server_model": "glm-5.3", "usage": map[string]any{"input_tokens": 1, "output_tokens": 1}},
	)
	receipt, err := RunCodexStructured(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.ModelVerified || receipt.ResolvedModel != "glm-5.3" || receipt.ModelEvidence != "turn.completed.server_model" {
		t.Fatalf("terminal server model was not the sole evidence: %+v", receipt)
	}
}

func TestRunCodexStructuredRejectsPrematureOrInvalidServerModel(t *testing.T) {
	for _, test := range []struct {
		name  string
		first map[string]any
		last  map[string]any
	}{
		{name: "thread_started", first: map[string]any{"server_model": "glm-5.3"}},
		{name: "turn_started", first: map[string]any{"model": "glm-5.3"}, last: map[string]any{"server_model": "glm-5.3"}},
		{name: "terminal_non_string", first: map[string]any{}, last: map[string]any{"server_model": 53}},
		{name: "terminal_conflict", first: map[string]any{}, last: map[string]any{"server_model": "glm-5.3", "server_model_conflict": true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &codexRunnerFixture{}
			spec := codexFixtureSpec(t, runner)
			thread := map[string]any{"type": "thread.started", "thread_id": codexTestSession}
			for key, value := range test.first {
				thread[key] = value
			}
			turn := map[string]any{"type": "turn.started"}
			if test.name == "turn_started" {
				turn["server_model"] = "glm-5.3"
			}
			completed := map[string]any{"type": "turn.completed", "usage": map[string]any{"input_tokens": 1, "output_tokens": 1}}
			for key, value := range test.last {
				completed[key] = value
			}
			runner.outcome.Stdout = codexJSONL(t,
				thread,
				turn,
				map[string]any{"type": "item.completed", "item": map[string]any{"id": "message-1", "type": "agent_message", "text": spec.ExpectedNonce}},
				completed,
			)
			receipt, err := RunCodexStructured(context.Background(), spec)
			if err == nil || receipt.ModelVerified {
				t.Fatalf("invalid server-model evidence accepted: receipt=%+v err=%v", receipt, err)
			}
		})
	}
}

func TestRunCodexStructuredRejectsNonCanonicalTerminalServerModel(t *testing.T) {
	for _, serverModel := range []any{"", " glm-5.3", "glm-5.3 ", "GLM-5.3", "glm_5.3", "\tglm-5.3"} {
		t.Run(fmt.Sprintf("%q", serverModel), func(t *testing.T) {
			runner := &codexRunnerFixture{}
			spec := codexFixtureSpec(t, runner)
			runner.outcome.Stdout = codexJSONL(t,
				map[string]any{"type": "thread.started", "thread_id": codexTestSession},
				map[string]any{"type": "turn.started"},
				map[string]any{"type": "item.completed", "item": map[string]any{"id": "message-1", "type": "agent_message", "text": spec.ExpectedNonce}},
				map[string]any{"type": "turn.completed", "server_model": serverModel},
			)
			receipt, err := RunCodexStructured(context.Background(), spec)
			if err == nil || receipt.ModelVerified {
				t.Fatalf("non-canonical server model accepted: receipt=%+v err=%v", receipt, err)
			}
		})
	}
}

func TestParseCodexEventsRejectsServerModelOutsideTerminalCompletion(t *testing.T) {
	raw := codexJSONL(t,
		map[string]any{"type": "thread.started", "thread_id": codexTestSession},
		map[string]any{"type": "turn.started"},
		map[string]any{"type": "item.completed", "server_model": "glm-5.3", "item": map[string]any{"id": "message-1", "type": "agent_message", "text": "nonce"}},
		map[string]any{"type": "turn.completed", "server_model": "glm-5.3"},
	)
	if _, err := parseCodexEvents(raw, "nonce", "", false); err == nil {
		t.Fatal("non-terminal server_model was accepted")
	}
}

func TestRunCodexStructuredFailsClosedOnMissingOrRemappedModel(t *testing.T) {
	for _, test := range []struct {
		name  string
		model string
	}{
		{name: "missing"},
		{name: "remapped", model: "glm-5.3-flash"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &codexRunnerFixture{}
			spec := codexFixtureSpec(t, runner)
			runner.outcome.Stdout = codexSuccessEvents(t, codexTestSession, test.model, spec.ExpectedNonce)
			receipt, err := RunCodexStructured(context.Background(), spec)
			if err == nil || receipt.ModelVerified {
				t.Fatalf("model evidence accepted: receipt=%+v err=%v", receipt, err)
			}
			if test.model != "" && receipt.ResolvedModel != test.model {
				t.Fatalf("resolved model not recorded: %+v", receipt)
			}
		})
	}
}

func TestRunCodexStructuredBindsExpectedDeniedCommandWithoutRetainingIt(t *testing.T) {
	for _, test := range []struct {
		name     string
		status   string
		exitCode any
	}{
		{name: "completed_nonzero", status: "completed", exitCode: 1},
		{name: "failed", status: "failed", exitCode: 1},
		{name: "declined", status: "declined"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &codexRunnerFixture{}
			spec := codexFixtureSpec(t, runner)
			spec.ExpectedToolCommand = "cat -- .qualification-secret"
			var observedSession string
			spec.SessionObserver = func(session string) { observedSession = session }
			item := map[string]any{"id": "tool-1", "type": "command_execution", "command": spec.ExpectedToolCommand, "aggregated_output": "permission denied", "status": test.status}
			if test.exitCode != nil {
				item["exit_code"] = test.exitCode
			}
			runner.outcome.Stdout = codexJSONL(t,
				map[string]any{"type": "thread.started", "thread_id": codexTestSession},
				map[string]any{"type": "turn.started"},
				map[string]any{"type": "item.completed", "item": item},
				map[string]any{"type": "item.completed", "item": map[string]any{"id": "message-1", "type": "agent_message", "text": spec.ExpectedNonce}},
				map[string]any{"type": "turn.completed", "server_model": "glm-5.3"},
			)
			receipt, err := RunCodexStructured(context.Background(), spec)
			if err != nil {
				t.Fatal(err)
			}
			if !receipt.ExpectedToolObserved || !receipt.ExpectedToolDenied || receipt.ExpectedToolSHA256 != digestCodex([]byte(spec.ExpectedToolCommand)) || observedSession != codexTestSession {
				t.Fatalf("expected denied command evidence = %+v session=%q", receipt, observedSession)
			}
			encoded, _ := json.Marshal(receipt)
			if strings.Contains(string(encoded), spec.ExpectedToolCommand) || strings.Contains(string(encoded), "permission denied") {
				t.Fatalf("receipt retained tool text: %s", encoded)
			}
		})
	}
}

func TestRunCodexStructuredContinuesAfterUnrequestedFailedCommand(t *testing.T) {
	runner := &codexRunnerFixture{}
	spec := codexFixtureSpec(t, runner)
	runner.outcome.Stdout = codexJSONL(t,
		map[string]any{"type": "thread.started", "thread_id": codexTestSession},
		map[string]any{"type": "turn.started"},
		map[string]any{"type": "item.completed", "item": map[string]any{"id": "tool-1", "type": "command_execution", "command": "pwd", "aggregated_output": "denied", "exit_code": 1, "status": "failed"}},
		map[string]any{"type": "item.completed", "item": map[string]any{"id": "message-1", "type": "agent_message", "text": spec.ExpectedNonce}},
		map[string]any{"type": "turn.completed", "server_model": "glm-5.3", "usage": map[string]any{"input_tokens": 1, "output_tokens": 1}},
	)
	receipt, err := RunCodexStructured(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.CompletionConfirmed || !receipt.NonceVerified || receipt.ToolEventCount != 1 || !receipt.ModelVerified {
		t.Fatalf("receipt = %+v", receipt)
	}
}

func TestParseCodexEventsRejectsNonterminalOrUnknownToolStatus(t *testing.T) {
	for _, status := range []string{"in_progress", "unknown", ""} {
		t.Run(status, func(t *testing.T) {
			item := map[string]any{"id": "tool-1", "type": "command_execution", "command": "pwd", "exit_code": 0}
			if status != "" {
				item["status"] = status
			}
			raw := codexJSONL(t,
				map[string]any{"type": "thread.started", "thread_id": codexTestSession},
				map[string]any{"type": "turn.started"},
				map[string]any{"type": "item.completed", "item": item},
				map[string]any{"type": "item.completed", "item": map[string]any{"id": "message-1", "type": "agent_message", "text": "nonce"}},
				map[string]any{"type": "turn.completed", "server_model": "glm-5.3"},
			)
			if _, err := parseCodexEvents(raw, "nonce", "", false); err == nil {
				t.Fatalf("status %q was accepted", status)
			}
		})
	}
}

func TestRunCodexStructuredRejectsAmbiguousExpectedCommandDenial(t *testing.T) {
	for _, test := range []struct {
		name     string
		status   string
		exitCode any
	}{
		{name: "failed_missing_exit", status: "failed"},
		{name: "failed_zero_exit", status: "failed", exitCode: 0},
		{name: "declined_with_exit", status: "declined", exitCode: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &codexRunnerFixture{}
			spec := codexFixtureSpec(t, runner)
			spec.ExpectedToolCommand = "cat -- .qualification-secret"
			item := map[string]any{"id": "tool-1", "type": "command_execution", "command": spec.ExpectedToolCommand, "status": test.status}
			if test.exitCode != nil {
				item["exit_code"] = test.exitCode
			}
			runner.outcome.Stdout = codexJSONL(t,
				map[string]any{"type": "thread.started", "thread_id": codexTestSession},
				map[string]any{"type": "turn.started"},
				map[string]any{"type": "item.completed", "item": item},
				map[string]any{"type": "item.completed", "item": map[string]any{"id": "message-1", "type": "agent_message", "text": spec.ExpectedNonce}},
				map[string]any{"type": "turn.completed", "server_model": "glm-5.3"},
			)
			if receipt, err := RunCodexStructured(context.Background(), spec); err == nil || receipt.ExpectedToolDenied {
				t.Fatalf("ambiguous denial was accepted: receipt=%+v err=%v", receipt, err)
			}
		})
	}
}

func TestRunCodexStructuredBindsExpectedFileChangeWithoutRetainingPath(t *testing.T) {
	runner := &codexRunnerFixture{}
	spec := codexFixtureSpec(t, runner)
	spec.ExpectedFileChange = "qualification.go"
	runner.outcome.Stdout = codexJSONL(t,
		map[string]any{"type": "thread.started", "thread_id": codexTestSession},
		map[string]any{"type": "turn.started"},
		map[string]any{"type": "item.completed", "item": map[string]any{"id": "file-1", "type": "file_change", "changes": []map[string]any{{"path": spec.ExpectedFileChange, "kind": "add"}}, "status": "completed"}},
		map[string]any{"type": "item.completed", "item": map[string]any{"id": "message-1", "type": "agent_message", "text": spec.ExpectedNonce}},
		map[string]any{"type": "turn.completed", "server_model": "glm-5.3"},
	)
	receipt, err := RunCodexStructured(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.ExpectedFileObserved || receipt.ExpectedFileSHA256 != digestCodex([]byte(spec.ExpectedFileChange)) {
		t.Fatalf("expected file-change evidence = %+v", receipt)
	}
	encoded, _ := json.Marshal(receipt)
	if strings.Contains(string(encoded), spec.ExpectedFileChange) {
		t.Fatalf("receipt retained expected path: %s", encoded)
	}
}

func TestRunCodexStructuredRejectsExpectedCommandThatSucceeded(t *testing.T) {
	runner := &codexRunnerFixture{}
	spec := codexFixtureSpec(t, runner)
	spec.ExpectedToolCommand = "git push"
	runner.outcome.Stdout = codexJSONL(t,
		map[string]any{"type": "thread.started", "thread_id": codexTestSession},
		map[string]any{"type": "turn.started"},
		map[string]any{"type": "item.completed", "item": map[string]any{"id": "tool-1", "type": "command_execution", "command": spec.ExpectedToolCommand, "exit_code": 0, "status": "completed"}},
		map[string]any{"type": "item.completed", "item": map[string]any{"id": "message-1", "type": "agent_message", "text": spec.ExpectedNonce}},
		map[string]any{"type": "turn.completed", "server_model": "glm-5.3"},
	)
	receipt, err := RunCodexStructured(context.Background(), spec)
	if err == nil || receipt.ExpectedToolDenied {
		t.Fatalf("successful expected command was accepted: receipt=%+v err=%v", receipt, err)
	}
}

func TestRunCodexStructuredReattestsManifestAtAllBoundaries(t *testing.T) {
	runner := &codexRunnerFixture{}
	spec := codexFixtureSpec(t, runner)
	verifications := 0
	spec.ManifestVerifier = func(context.Context) error {
		verifications++
		return nil
	}
	runner.outcome.Stdout = codexSuccessEvents(t, codexTestSession, "glm-5.3", spec.ExpectedNonce)
	if _, err := RunCodexStructured(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if verifications != 3 {
		t.Fatalf("manifest verifications = %d, want 3", verifications)
	}
}

func TestRunCodexStructuredRejectsManifestDriftBeforeLaunch(t *testing.T) {
	runner := &codexRunnerFixture{}
	spec := codexFixtureSpec(t, runner)
	verifications := 0
	spec.ManifestVerifier = func(context.Context) error {
		verifications++
		if verifications == 2 {
			return errors.New("fixture drift")
		}
		return nil
	}
	if receipt, err := RunCodexStructured(context.Background(), spec); err == nil || receipt.ProcessStarted {
		t.Fatalf("manifest drift reached process: receipt=%+v err=%v", receipt, err)
	}
	if verifications != 2 || len(runner.seen.Args) != 0 {
		t.Fatalf("verifications=%d invocation=%+v", verifications, runner.seen)
	}
}

func TestRunCodexStructuredResumeRequiresExactLineage(t *testing.T) {
	for _, session := range []string{codexTestSession, codexTestOtherSession} {
		t.Run(session, func(t *testing.T) {
			runner := &codexRunnerFixture{}
			spec := codexFixtureSpec(t, runner)
			spec.Resume = true
			spec.ParentSession = codexTestSession
			runner.outcome.Stdout = codexSuccessEvents(t, session, "glm-5.3", spec.ExpectedNonce)
			receipt, err := RunCodexStructured(context.Background(), spec)
			if (session == spec.ParentSession) != (err == nil && receipt.LineageVerified) {
				t.Fatalf("lineage result receipt=%+v err=%v", receipt, err)
			}
			if !strings.Contains(strings.Join(runner.seen.Args, " "), "resume "+codexTestSession+" -") {
				t.Fatalf("resume argv = %v", runner.seen.Args)
			}
			if strings.Contains(strings.Join(runner.seen.Args, " "), "--model") {
				t.Fatalf("resume must not override the manifest-bound model: %v", runner.seen.Args)
			}
		})
	}
}

func TestRunCodexStructuredPreservesCancellationAndResidualEvidence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, residuals := range [][]int{nil, {404}} {
		runner := &codexRunnerFixture{
			outcome: providerqualification.Outcome{ExitCode: -1, ProcessTreeTerminated: len(residuals) == 0, ResidualProcessIDs: residuals, ResidualCheckPerformed: true},
			err:     context.Canceled,
		}
		spec := codexFixtureSpec(t, runner)
		receipt, err := RunCodexStructured(ctx, spec)
		if !errors.Is(err, context.Canceled) && err == nil {
			t.Fatal("cancelled execution succeeded")
		}
		if len(residuals) == 0 && receipt.Cancellation.LocalTermination != "observed_tree_terminated_verified" {
			t.Fatalf("clean cancellation = %+v", receipt.Cancellation)
		}
		if len(residuals) > 0 && (receipt.ZeroResiduals || receipt.Cancellation.LocalTermination != "residual_processes_detected") {
			t.Fatalf("residual cancellation = %+v", receipt)
		}
	}
}

func TestRunCodexStructuredRejectsTruncatedEventsBeforeParsing(t *testing.T) {
	runner := &codexRunnerFixture{outcome: providerqualification.Outcome{OutputTruncated: true, Stdout: []byte(`{"type":"thread.started"}`)}}
	spec := codexFixtureSpec(t, runner)
	receipt, err := RunCodexStructured(context.Background(), spec)
	if err == nil || receipt.CompletionConfirmed {
		t.Fatalf("truncated output was accepted: receipt=%+v err=%v", receipt, err)
	}
}

func TestParseCodexEventsRejectsPostTerminalInjection(t *testing.T) {
	raw := append(codexSuccessEvents(t, codexTestSession, "glm-5.3", "nonce"), []byte(`{"type":"item.completed","item":{"id":"late","type":"agent_message","text":"nonce"}}`+"\n")...)
	if _, err := parseCodexEvents(raw, "nonce", "", false); err == nil {
		t.Fatal("post-terminal event injection was accepted")
	}
}

func TestParseCodexEventsRejectsMultipleAgentMessages(t *testing.T) {
	raw := codexJSONL(t,
		map[string]any{"type": "thread.started", "thread_id": codexTestSession},
		map[string]any{"type": "turn.started"},
		map[string]any{"type": "item.completed", "item": map[string]any{"id": "message-1", "type": "agent_message", "text": "extra text"}},
		map[string]any{"type": "item.completed", "item": map[string]any{"id": "message-2", "type": "agent_message", "text": "nonce"}},
		map[string]any{"type": "turn.completed", "server_model": "glm-5.3"},
	)
	if _, err := parseCodexEvents(raw, "nonce", "", false); err == nil {
		t.Fatal("multiple agent messages were accepted as an exact final acknowledgement")
	}
}

func TestRunCodexStructuredRejectsOptionShapedResumeSession(t *testing.T) {
	runner := &codexRunnerFixture{}
	spec := codexFixtureSpec(t, runner)
	spec.Resume = true
	spec.ParentSession = "--dangerously-bypass-approvals-and-sandbox"
	if _, err := RunCodexStructured(context.Background(), spec); err == nil {
		t.Fatal("option-shaped resume session was accepted")
	}
	if len(runner.seen.Args) != 0 {
		t.Fatalf("invalid resume reached runner: %v", runner.seen.Args)
	}
}

func TestParseCodexEventsRejectsMalformedAndGenericModelOnlyEvidence(t *testing.T) {
	if _, err := parseCodexEvents([]byte("not-json\n"), "nonce", "", false); err == nil {
		t.Fatal("malformed event accepted")
	}
	raw := codexJSONL(t,
		map[string]any{"type": "thread.started", "thread_id": codexTestSession, "resolved_model": "glm-5.3"},
		map[string]any{"type": "turn.started", "resolved_model": "glm-5.3-flash"},
		map[string]any{"type": "item.completed", "item": map[string]any{"id": "message-1", "type": "agent_message", "text": "nonce"}},
		map[string]any{"type": "turn.completed", "resolved_model": "glm-5.3-flash"},
	)
	if _, err := parseCodexEvents(raw, "nonce", "", false); err == nil {
		t.Fatal("generic model fields were accepted as provider evidence")
	}
}
