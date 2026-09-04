package grok

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	agentpkg "github.com/Dicklesworthstone/ntm/internal/agent"
	"github.com/Dicklesworthstone/ntm/internal/provider"
)

func TestRunCompletesFromACPTranscript(t *testing.T) {
	transcript := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"},{"id":"xai.api_key"}]}}`,
		`{"jsonrpc":"2.0","id":2,"result":{}}`,
		`{"jsonrpc":"2.0","id":3,"result":{"sessionId":"grok-session-7"}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"agent_message_chunk","content":{"text":"hello "}}}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"agent_message_chunk","content":{"text":"world"}}}}`,
		`{"jsonrpc":"2.0","id":4,"result":{"stopReason":"end_turn"}}`,
	}, "\n") + "\n"
	stderr := strings.Repeat("diagnostic ", MaxStderrCaptureBytes/5+4)
	proc := newFakeProcess(strings.NewReader(transcript), strings.NewReader(stderr))
	runner := &fakeRunner{proc: proc}

	result, err := Run(t.Context(), runner, Request{
		Prompt: "secret prompt must not appear in the receipt",
		CWD:    "/work/project",
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !result.Success || result.State != StateCompleted || !result.CompletionConfirmed {
		t.Fatalf("result = %+v, want confirmed completion", result)
	}
	if !result.Authenticated || result.AuthenticationEvidence != "cached_token_authenticate_plus_completed_session" {
		t.Fatalf("completed cached authentication evidence = authenticated:%v evidence:%q", result.Authenticated, result.AuthenticationEvidence)
	}
	if result.ProviderSessionID != "grok-session-7" || result.StopReason != "end_turn" {
		t.Fatalf("provider receipt = %+v", result)
	}
	if result.AssistantTextChunks != 2 || result.AssistantTextBytes != int64(len("hello world")) {
		t.Fatalf("update summary = %+v", result)
	}
	wantOutput := sha256.Sum256([]byte("hello world"))
	if result.OutputSHA256 != hex.EncodeToString(wantOutput[:]) {
		t.Fatalf("output hash = %q", result.OutputSHA256)
	}
	wantStderr := sha256.Sum256([]byte(stderr))
	if result.Stderr.SHA256 != hex.EncodeToString(wantStderr[:]) || !result.Stderr.Truncated {
		t.Fatalf("stderr digest = %+v", result.Stderr)
	}
	if !proc.closed || proc.killCalls != 1 || proc.waitCalls != 1 {
		t.Fatalf("process cleanup = %+v", proc)
	}
	if got := runner.spec; got.Binary != "grok" || got.CWD != "/work/project" || !sameStrings(got.Args, append(append([]string{"--no-auto-update"}, defaultReadOnlyAutomationPolicyArgs()...), "agent", "stdio")) {
		t.Fatalf("start spec = %+v", got)
	}

	requests := decodeRequests(t, proc.stdin.String())
	if len(requests) != 4 {
		t.Fatalf("request count = %d, want 4", len(requests))
	}
	for index, want := range []string{"initialize", "authenticate", "session/new", "session/prompt"} {
		if got := requests[index].Method; got != want {
			t.Fatalf("request[%d].method = %q, want %q", index, got, want)
		}
	}
	if got := nestedString(t, requests[1].Params, "methodId"); got != "cached_token" {
		t.Fatalf("authenticate methodId = %q, want cached_token", got)
	}
	if strings.Contains(string(mustJSON(t, result)), "secret prompt") || strings.Contains(string(mustJSON(t, result)), "diagnostic") {
		t.Fatalf("receipt retained sensitive payload or stderr: %s", mustJSON(t, result))
	}
}

func TestRuntimeEventsPreserveACPCompletionBeforeRequest(t *testing.T) {
	updates := newUpdateAccumulator(io.Discard, "nonce", "grok-4.6")
	if err := updates.observe(json.RawMessage(`{"update":{"sessionUpdate":"tool_call_update","toolCallId":"opaque-tool-id","status":"completed"}}`)); err == nil {
		t.Fatal("completion-before-request was accepted")
	}
	if len(updates.runtimeToolEvents) != 0 {
		t.Fatalf("unmatched terminal update created lifecycle evidence: %+v", updates.runtimeToolEvents)
	}
}

func TestUpdateAccumulatorTracksACPToolLifecycleByOpaqueID(t *testing.T) {
	updates := newUpdateAccumulator(io.Discard, "nonce", "grok-4.6")
	for _, update := range []string{
		`{"update":{"sessionUpdate":"tool_call","toolCallId":"opaque-tool-id"}}`,
		`{"update":{"sessionUpdate":"tool_call_update","toolCallId":"opaque-tool-id","status":"pending"}}`,
		`{"update":{"sessionUpdate":"tool_call_update","toolCallId":"opaque-tool-id","status":"in_progress"}}`,
	} {
		if err := updates.observe(json.RawMessage(update)); err != nil {
			t.Fatal(err)
		}
	}
	if updates.toolRequestCount != 1 || updates.toolCompleteCount != 0 || len(updates.runtimeToolEvents) != 1 || updates.runtimeToolEvents[0].Type != provider.EventToolRequested {
		t.Fatalf("progress updates created a false completion: %+v", updates)
	}
	if err := updates.observe(json.RawMessage(`{"update":{"sessionUpdate":"tool_call_update","toolCallId":"opaque-tool-id","status":"completed"}}`)); err != nil {
		t.Fatal(err)
	}
	events := provider.NormalizeTerminalRuntimeObservation(provider.TerminalRuntimeObservation{
		SessionRef: "session-digest", Model: "grok-4.6", Accepted: true,
		ObservedToolEvents: updates.runtimeToolEvents, Completed: true, UsageObserved: true, CleanupObserved: true,
	})
	if len(events) < 4 || events[2].Type != provider.EventToolRequested || events[3].Type != provider.EventToolCompleted {
		t.Fatalf("tool lifecycle order was not preserved: %+v", events)
	}
	report := provider.ValidateRuntimeEventsForModel("grok-4.6", events, provider.RuntimeEventRequirements{ToolLifecycle: true})
	if !report.Passed {
		t.Fatalf("valid tool lifecycle failed: %+v", report)
	}
	serialized := string(mustJSON(t, events))
	if strings.Contains(serialized, "opaque-tool-id") {
		t.Fatalf("runtime events retained raw tool-call id: %s", serialized)
	}
}

func TestUpdateAccumulatorClosesFailedToolLifecycleWithoutClaimingSuccess(t *testing.T) {
	updates := newUpdateAccumulator(io.Discard, "nonce", "grok-4.6")
	if err := updates.observe(json.RawMessage(`{"update":{"sessionUpdate":"tool_call","toolCallId":"opaque-failed-id"}}`)); err != nil {
		t.Fatal(err)
	}
	if err := updates.observe(json.RawMessage(`{"update":{"sessionUpdate":"tool_call_update","toolCallId":"opaque-failed-id","status":"failed"}}`)); err != nil {
		t.Fatal(err)
	}
	if updates.toolRequestCount != 1 || updates.toolCompleteCount != 1 || len(updates.runtimeToolEvents) != 2 || updates.runtimeToolEvents[1].Type != provider.EventToolCompleted {
		t.Fatalf("failed terminal did not close normalized lifecycle: %+v", updates)
	}
	report := provider.ValidateRuntimeEventsForModel("grok-4.6", provider.NormalizeTerminalRuntimeObservation(provider.TerminalRuntimeObservation{
		SessionRef: "session-digest", Model: "grok-4.6", Accepted: true,
		ObservedToolEvents: updates.runtimeToolEvents, Completed: true, UsageObserved: true, CleanupObserved: true,
	}), provider.RuntimeEventRequirements{ToolLifecycle: true})
	if !report.Passed {
		t.Fatalf("terminal failed tool was mistaken for an open request: %+v", report)
	}
}

func TestRunPlacesNamedPolicyAndExactModelBeforeACPSubcommand(t *testing.T) {
	proc := newFakeProcess(strings.NewReader(successfulTranscript(`[{"id":"cached_token"}]`)), strings.NewReader(""))
	runner := &fakeRunner{proc: proc}
	policyArgs := agentpkg.GrokAutomationACPPolicyArgs(agentpkg.DefaultGrokAutomationPolicyName)
	_, err := Run(t.Context(), runner, Request{
		Prompt: "hello", CWD: "/repo", Model: "grok-exact-model",
		AutomationPolicyArgs: policyArgs,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := append([]string{"--no-auto-update"}, policyArgs...)
	want = append(want, "--model", "grok-exact-model", "agent", "stdio")
	if !sameStrings(runner.spec.Args, want) {
		t.Fatalf("ACP args = %#v, want %#v", runner.spec.Args, want)
	}
}

func TestRunPassesOnlyTypedNTMWorkspaceBrokerToSessionNew(t *testing.T) {
	proc := newFakeProcess(strings.NewReader(successfulTranscript(`[{"id":"cached_token"}]`)), strings.NewReader(""))
	broker, err := NewWorkspaceBrokerDescriptor("/tmp/linked", strings.Repeat("a", 40), []string{"go-test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(t.Context(), &fakeRunner{proc: proc}, Request{Prompt: "hello", CWD: "/repo", Broker: broker}); err != nil {
		t.Fatal(err)
	}
	requests := decodeRequests(t, proc.stdin.String())
	if len(requests) < 3 || requests[2].Method != "session/new" {
		t.Fatalf("session/new request = %#v", requests)
	}
	var params struct {
		MCPServers []struct {
			Name    string   `json:"name"`
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(requests[2].Params, &params); err != nil {
		t.Fatal(err)
	}
	if len(params.MCPServers) != 1 || params.MCPServers[0].Name != WorkspaceBrokerMCPName || !filepath.IsAbs(params.MCPServers[0].Command) || !slices.Equal(params.MCPServers[0].Args[:3], []string{"provider", "broker", "stdio"}) {
		t.Fatalf("session/new MCP descriptor = %+v", params.MCPServers)
	}
	if strings.Contains(string(requests[2].Params), "toolset") || strings.Contains(string(requests[2].Params), "protocol") {
		t.Fatalf("session/new included non-standard MCP fields: %s", requests[2].Params)
	}
}

func TestWorkspaceBrokerDescriptorWithAuditBindsExactTemporaryParentPath(t *testing.T) {
	parent := t.TempDir()
	worktree := filepath.Join(parent, "linked")
	auditFile := filepath.Join(parent, "broker-audit.jsonl")
	ordinary, err := NewWorkspaceBrokerDescriptor(worktree, strings.Repeat("a", 40), []string{"go-test"})
	if err != nil {
		t.Fatal(err)
	}
	audited, err := NewWorkspaceBrokerDescriptorWithAudit(worktree, strings.Repeat("a", 40), []string{"go-test"}, auditFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := audited.args; len(got) != 13 || got[9] != "--ntm-sha256" || !workspaceBrokerDigest(got[10]) || got[11] != "--audit-file" || got[12] != auditFile {
		t.Fatalf("audited descriptor args = %#v", got)
	}
	if !workspaceBrokerProcExePath(audited.command) || audited.args[10] != mustWorkspaceBrokerExecutableSHA256(t, audited.command) {
		t.Fatalf("descriptor did not bind current parent executable: command=%q args=%#v", audited.command, audited.args)
	}
	if audited.BindingSHA256() == "" || audited.BindingSHA256() == ordinary.BindingSHA256() {
		t.Fatalf("audit path was not bound: ordinary=%q audited=%q", ordinary.BindingSHA256(), audited.BindingSHA256())
	}
	for _, invalid := range []string{filepath.Join(worktree, "audit.jsonl"), filepath.Join(t.TempDir(), "audit.jsonl"), "relative-audit.jsonl"} {
		if _, err := NewWorkspaceBrokerDescriptorWithAudit(worktree, strings.Repeat("a", 40), []string{"go-test"}, invalid); err == nil {
			t.Fatalf("invalid audit path %q was accepted", invalid)
		}
	}
}

func mustWorkspaceBrokerExecutableSHA256(t *testing.T, path string) string {
	t.Helper()
	digest, err := workspaceBrokerExecutableSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestRunAfterPromptWrittenRunsOnceAfterAcceptedWriteAndContainsPanics(t *testing.T) {
	proc := newFakeProcess(strings.NewReader(successfulTranscript(`[{"id":"cached_token"}]`)), strings.NewReader(""))
	called := 0
	_, err := Run(t.Context(), &fakeRunner{proc: proc}, Request{
		Prompt: "hello", CWD: "/repo",
		AfterPromptWritten: func() {
			called++
			if !strings.Contains(proc.stdin.String(), `"method":"session/prompt"`) {
				t.Fatal("callback ran before session/prompt was written")
			}
			panic("qualification callback must not break ACP runner")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("callback count = %d, want 1", called)
	}
}

func TestRunRejectsAnythingOtherThanTheTypedNTMWorkspaceBroker(t *testing.T) {
	if _, err := NewWorkspaceBrokerDescriptor("/tmp/linked", strings.Repeat("a", 40), []string{"sh"}); err == nil {
		t.Fatal("unapproved verifier command was accepted")
	}
	if _, err := NewWorkspaceBrokerDescriptor("relative", strings.Repeat("a", 40), []string{"go-test"}); err == nil {
		t.Fatal("relative worktree was accepted")
	}
}

func TestRunRejectsUnsafeAutomationPolicyArgument(t *testing.T) {
	_, err := Run(t.Context(), &fakeRunner{proc: newFakeProcess(strings.NewReader(""), strings.NewReader(""))}, Request{
		Prompt: "hello", CWD: "/repo", AutomationPolicyArgs: []string{"--always-approve"},
	})
	assertCode(t, err, ErrInvalidRequest)
}

func TestRunRejectsPoliciesThatAreNotExactCompiledDescriptors(t *testing.T) {
	for _, policy := range [][]string{
		{"--permission-mode=dontAsk", "--allow=Read"},
		{"--sandbox=read-only", "--allow=Read"},
		{"--sandbox=workspace", "--permission-mode=dontAsk", "--allow=Read"},
		{"--sandbox=strict", "--permission-mode=dontAsk", "--allow=Read", "--allow=Grep", "--allow=Edit", "--deny=Bash(*)", "--deny=WebFetch", "--deny=WebSearch"},
	} {
		runner := &fakeRunner{proc: newFakeProcess(strings.NewReader(""), strings.NewReader(""))}
		_, err := Run(t.Context(), runner, Request{
			Prompt: "hello", CWD: "/repo", AutomationPolicyArgs: policy,
		})
		assertCode(t, err, ErrInvalidRequest)
		if runner.spec.Binary != "" {
			t.Fatalf("runner started for unsafe policy %#v: %+v", policy, runner.spec)
		}
	}
}

func TestRunAcceptsBothExactCompiledPolicies(t *testing.T) {
	for _, policyName := range []string{agentpkg.DefaultGrokAutomationPolicyName, agentpkg.GrokWorkspaceWritePolicyName} {
		policyArgs := agentpkg.GrokAutomationACPPolicyArgs(policyName)
		proc := newFakeProcess(strings.NewReader(successfulTranscript(`[{"id":"cached_token"}]`)), strings.NewReader(""))
		runner := &fakeRunner{proc: proc}
		if _, err := Run(t.Context(), runner, Request{Prompt: "hello", CWD: "/repo", AutomationPolicyArgs: policyArgs}); err != nil {
			t.Fatalf("Run(%s) error = %v", policyName, err)
		}
		if !slices.Equal(runner.spec.Args[1:1+len(policyArgs)], policyArgs) {
			t.Fatalf("Run(%s) args = %#v", policyName, runner.spec.Args)
		}
	}
}

func TestRunRejectsControlCharactersInModel(t *testing.T) {
	runner := &fakeRunner{proc: newFakeProcess(strings.NewReader(""), strings.NewReader(""))}
	_, err := Run(t.Context(), runner, Request{
		Prompt: "hello", CWD: "/repo", Model: "grok-safe\n--always-approve",
	})
	assertCode(t, err, ErrInvalidRequest)
	if runner.spec.Binary != "" {
		t.Fatalf("runner started for invalid model: %+v", runner.spec)
	}
}

func TestRunExposesConcreteReapAndExitEvidence(t *testing.T) {
	proc := newFakeProcess(strings.NewReader(successfulTranscript(`[{"id":"cached_token"}]`)), strings.NewReader(""))
	proc.waitErr = fakeExitError{code: -1}
	result, err := Run(t.Context(), &fakeRunner{proc: proc}, Request{Prompt: "hello", CWD: "/repo"})
	if err != nil {
		t.Fatal(err)
	}
	if result.CleanupState != "unsupported_and_reaped" || !result.Cleanup.Reaped || result.Cleanup.LocalTermination != "unsupported" || result.ExitCode == nil || *result.ExitCode != -1 {
		t.Fatalf("cleanup receipt = %+v", result)
	}
}

func TestRunUsesCachedTokenWithoutExposingCredentials(t *testing.T) {
	transcript := successfulTranscript(`[{"id":"cached_token"},{"id":"xai.api_key"}]`)
	proc := newFakeProcess(strings.NewReader(transcript), strings.NewReader(""))
	_, err := Run(t.Context(), &fakeRunner{proc: proc}, Request{Prompt: "hello", CWD: "/repo"})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	requests := decodeRequests(t, proc.stdin.String())
	if got := nestedString(t, requests[1].Params, "methodId"); got != "cached_token" {
		t.Fatalf("authenticate methodId = %q, want cached_token", got)
	}
	if strings.Contains(proc.stdin.String(), "XAI_API_KEY") || strings.Contains(proc.stdin.String(), "secret") {
		t.Fatalf("ACP wire request leaked a credential marker: %s", proc.stdin.String())
	}
}

func TestRunVerifiesNonceAcrossAssistantChunksWithoutRetainingOutput(t *testing.T) {
	transcript := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
		`{"jsonrpc":"2.0","id":2,"result":{}}`,
		`{"jsonrpc":"2.0","id":3,"result":{"sessionId":"s"}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"agent_message_chunk","content":{"text":"NTM_ACK_0123456789ab"}}}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"agent_message_chunk","content":{"text":"cdef0123456789abcdef\n"}}}}`,
		`{"jsonrpc":"2.0","id":4,"result":{"stopReason":"end_turn"}}`,
	}, "\n") + "\n"
	result, err := Run(t.Context(), &fakeRunner{proc: newFakeProcess(strings.NewReader(transcript), strings.NewReader(""))}, Request{
		Prompt:        "reply with nonce",
		ExpectedNonce: "NTM_ACK_0123456789abcdef0123456789abcdef",
		CWD:           "/repo",
	})
	if err != nil || !result.AcknowledgementVerified {
		t.Fatalf("result = %+v, err = %v; want verified acknowledgement", result, err)
	}
	if strings.Contains(string(mustJSON(t, result)), "NTM_ACK_0123456789abcdef0123456789abcdef") {
		t.Fatalf("result leaked acknowledgement token: %s", mustJSON(t, result))
	}
}

func TestRunRejectsWeakOrEmbeddedNonceAcknowledgement(t *testing.T) {
	weak := "NTM_ACK_short"
	_, err := Run(t.Context(), &fakeRunner{proc: newFakeProcess(strings.NewReader(successfulTranscript(`[{"id":"cached_token"}]`)), strings.NewReader(""))}, Request{Prompt: "hello", CWD: "/repo", ExpectedNonce: weak})
	assertCode(t, err, ErrInvalidRequest)

	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	transcript := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
		`{"jsonrpc":"2.0","id":2,"result":{}}`,
		`{"jsonrpc":"2.0","id":3,"result":{"sessionId":"s"}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"agent_message_chunk","content":{"text":"completed ` + nonce + ` successfully\n"}}}}`,
		`{"jsonrpc":"2.0","id":4,"result":{"stopReason":"end_turn"}}`,
	}, "\n") + "\n"
	result, err := Run(t.Context(), &fakeRunner{proc: newFakeProcess(strings.NewReader(transcript), strings.NewReader(""))}, Request{Prompt: "hello", CWD: "/repo", ExpectedNonce: nonce})
	assertCode(t, err, ErrAcknowledgementUnconfirmed)
	if result.Success || result.AcknowledgementVerified || result.CompletionConfirmed != true {
		t.Fatalf("embedded nonce result = %+v, err = %v", result, err)
	}
}

func TestRunDrainsPostResponseUpdatesBeforeReceipt(t *testing.T) {
	reader, writer := io.Pipe()
	proc := newFakeProcess(reader, strings.NewReader(""))
	go func() {
		for _, line := range []string{
			`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
			`{"jsonrpc":"2.0","id":2,"result":{}}`,
			`{"jsonrpc":"2.0","id":3,"result":{"sessionId":"s"}}`,
			`{"jsonrpc":"2.0","id":4,"result":{"stopReason":"end_turn"}}`,
		} {
			_, _ = io.WriteString(writer, line+"\n")
		}
		time.Sleep(time.Millisecond)
		_, _ = io.WriteString(writer, `{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"agent_message_chunk","content":{"text":"late update"}}}}`+"\n")
		_ = writer.Close()
	}()
	result, err := Run(t.Context(), &fakeRunner{proc: proc}, Request{Prompt: "hello", CWD: "/repo", PostResponseQuietWindow: 20 * time.Millisecond})
	if err != nil || result.AssistantTextChunks != 1 || result.AssistantTextBytes != int64(len("late update")) {
		t.Fatalf("late update receipt = %+v, err = %v", result, err)
	}
}

func TestRunRequiresStopReasonForAuthoritativeCompletion(t *testing.T) {
	result, err := Run(t.Context(), &fakeRunner{proc: newFakeProcess(strings.NewReader(strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
		`{"jsonrpc":"2.0","id":2,"result":{}}`,
		`{"jsonrpc":"2.0","id":3,"result":{"sessionId":"s"}}`,
		`{"jsonrpc":"2.0","id":4,"result":{}}`,
	}, "\n")+"\n"), strings.NewReader(""))}, Request{Prompt: "hello", CWD: "/repo"})
	assertCode(t, err, ErrOutcomeUnknown)
	if result.CompletionConfirmed || result.State != StateOutcomeUnknown || result.Authenticated || result.AuthenticationEvidence != "" {
		t.Fatalf("stop-reason-free receipt = %+v", result)
	}
}

func TestMinimalGrokEnvironmentExcludesUnrelatedValues(t *testing.T) {
	env := minimalGrokEnvironment([]string{"Path=C:\\tools", "XAI_API_KEY=secret", "xai_api_key=secret-lowercase", "AWS_SECRET_ACCESS_KEY=must-not-pass", "HTTPS_PROXY=https://user:secret@proxy.example", "http_proxy=http://proxy-token@proxy.example", "NO_PROXY=localhost", "SSL_CERT_FILE=/tmp/attacker-ca.pem", "SSL_CERT_DIR=/tmp/attacker-cas", "LANG=en_US.UTF-8", "HOME=/tmp/home", "systemroot=C:\\Windows"})
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "PATH=C:\\tools") || !strings.Contains(joined, "SystemRoot=C:\\Windows") || !strings.Contains(joined, "HOME=/tmp/home") || strings.Contains(strings.ToLower(joined), "xai_api_key") || strings.Contains(joined, "AWS_SECRET") || strings.Contains(joined, "LANG=") || strings.Contains(strings.ToLower(joined), "proxy=") || strings.Contains(joined, "SSL_CERT") {
		t.Fatalf("minimal environment = %q", joined)
	}
}

func TestIsolatedProcessEnvironmentReplacesAmbientProviderState(t *testing.T) {
	env, err := IsolatedProcessEnvironment([]string{
		"PATH=/bin", "HOME=/real-home", "XDG_CONFIG_HOME=/real-config",
		"GROK_HOME=/attacker", "GROK_DEFAULT_MODEL=third-party", "GROK_SANDBOX=off",
		"GROK_CLAUDE_MCPS_ENABLED=1", "XAI_API_KEY=secret", "HTTPS_PROXY=https://user:secret@example.invalid", "SSL_CERT_FILE=/tmp/attacker-ca.pem",
	}, "/profiles/grok-kevin/.grok", false)
	if err != nil {
		t.Fatal(err)
	}
	joined := "\n" + strings.Join(env, "\n") + "\n"
	for _, want := range []string{
		"\nHOME=/profiles/grok-kevin/.grok\n",
		"\nGROK_HOME=/profiles/grok-kevin/.grok\n",
		"\nGROK_WRITE_FILE=0\n",
		"\nGROK_CLAUDE_MCPS_ENABLED=0\n",
		"\nGROK_CURSOR_HOOKS_ENABLED=0\n",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("isolated environment omitted %q: %q", want, joined)
		}
	}
	for _, forbidden := range []string{"/real-home", "/attacker", "third-party", "GROK_SANDBOX", "XAI_API_KEY", "HTTPS_PROXY", "SSL_CERT_FILE", "attacker-ca", "secret"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("isolated environment retained %q: %q", forbidden, joined)
		}
	}
	if _, err := IsolatedProcessEnvironment(nil, "relative", false); err == nil {
		t.Fatal("relative runtime home was accepted")
	}
}

func TestRunSeparatesToolCallsFromOtherNonMessageUpdates(t *testing.T) {
	transcript := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
		`{"jsonrpc":"2.0","id":2,"result":{}}`,
		`{"jsonrpc":"2.0","id":3,"result":{"sessionId":"s"}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"tool_call","toolCallId":"opaque-tool-id","arguments":{"api_key":"must-not-retain"}}}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"tool_call_update","toolCallId":"opaque-tool-id","status":"completed","content":{"text":"must-not-retain"}}}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"tool_result","content":{"text":"must-not-retain"}}}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"agent_thought_chunk","content":{"text":"must-not-retain"}}}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"usage_update","used":12,"size":100}}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"update":[]}}`,
		`{"jsonrpc":"2.0","id":4,"result":{"stopReason":"end_turn","model":"grok-4.6","usage":{"inputTokens":12,"output_tokens":34}}}`,
	}, "\n") + "\n"
	result, err := Run(t.Context(), &fakeRunner{proc: newFakeProcess(strings.NewReader(transcript), strings.NewReader(""))}, Request{Prompt: "hello", CWD: "/repo"})
	if err != nil {
		t.Fatal(err)
	}
	if result.ToolEventCount != 2 || result.ToolEventsSHA256 != updateNameHash("tool_call", "tool_call_update") {
		t.Fatalf("tool evidence = %+v", result)
	}
	if result.NonMessageUpdateCount != 6 || result.NonMessageUpdatesSHA256 != updateNameHash("tool_call", "tool_call_update", "tool_result", "agent_thought_chunk", "usage_update", "unknown") {
		t.Fatalf("non-message update evidence = %+v", result)
	}
	if result.Model != "grok-4.6" || result.ModelEvidence != "completion_metadata" || result.Usage == nil || result.Usage.InputTokens == nil || *result.Usage.InputTokens != 12 || result.Usage.OutputTokens == nil || *result.Usage.OutputTokens != 34 || result.Usage.TotalTokens != nil {
		t.Fatalf("provider metadata = %+v", result)
	}
	serialized := string(mustJSON(t, result))
	if strings.Contains(serialized, "must-not-retain") || strings.Contains(serialized, "api_key") || strings.Contains(serialized, "opaque-tool-id") {
		t.Fatalf("receipt retained raw event material: %s", serialized)
	}
}

func TestRunUsesStructuredCatalogOnlyWithExactModelLaunchAssertion(t *testing.T) {
	transcript := strings.Join([]string{
		`{"jsonrpc":"2.0","method":"_x.ai/models/update","params":{"models":[{"id":"grok-4.6"},{"id":"grok-4.5"}]}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
		`{"jsonrpc":"2.0","id":2,"result":{}}`,
		`{"jsonrpc":"2.0","id":3,"result":{"sessionId":"s"}}`,
		`{"jsonrpc":"2.0","id":4,"result":{"stopReason":"end_turn"}}`,
	}, "\n") + "\n"
	result, err := Run(t.Context(), &fakeRunner{proc: newFakeProcess(strings.NewReader(transcript), strings.NewReader(""))}, Request{
		Prompt: "hello", CWD: "/repo", Model: "grok-4.6",
	})
	if err != nil || result.Model != "" || result.ModelEvidence != "" {
		t.Fatalf("catalog must not confirm session model identity: result=%+v err=%v", result, err)
	}

	result, err = Run(t.Context(), &fakeRunner{proc: newFakeProcess(strings.NewReader(transcript), strings.NewReader(""))}, Request{
		Prompt: "hello", CWD: "/repo", Model: "grok-unlisted",
	})
	if err != nil || result.Model != "" || result.ModelEvidence != "" {
		t.Fatalf("unlisted launch assertion became evidence: result=%+v err=%v", result, err)
	}
}

func TestRunUsesTerminalMetadataForPublicResolvedModelAndUsage(t *testing.T) {
	transcript := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
		`{"jsonrpc":"2.0","id":2,"result":{}}`,
		`{"jsonrpc":"2.0","id":3,"result":{"sessionId":"session-7","models":{"currentModelId":"grok-4.6","availableModels":[{"modelId":"grok-4.6"}]}}}`,
		`{"jsonrpc":"2.0","id":4,"result":{"stopReason":"end_turn","_meta":{"modelId":"grok-4.6","usage":{"inputTokens":12,"outputTokens":34,"totalTokens":46,"cachedReadTokens":5,"reasoningTokens":7,"modelCalls":1,"numTurns":1,"apiDurationMs":900,"costUsdTicks":2,"modelUsage":{"grok-4.6-build":{}}}}}}`,
	}, "\n") + "\n"
	result, err := Run(t.Context(), &fakeRunner{proc: newFakeProcess(strings.NewReader(transcript), strings.NewReader(""))}, Request{
		Prompt: "hello", CWD: "/repo", Model: "grok-4.6", RuntimeVersion: "1.0.13",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Model != "grok-4.6" || result.ModelEvidence != "completion_metadata" || result.ResolvedModel != "grok-4.6-build" || result.ResolvedModelEvidence != "completion_metadata.usage.model_usage_singleton" {
		t.Fatalf("terminal model metadata = %+v", result)
	}
	if result.Usage == nil || result.Usage.InputTokens == nil || *result.Usage.InputTokens != 12 || result.Usage.OutputTokens == nil || *result.Usage.OutputTokens != 34 || result.Usage.TotalTokens == nil || *result.Usage.TotalTokens != 46 || result.Usage.CachedReadTokens == nil || *result.Usage.CachedReadTokens != 5 || result.Usage.ReasoningTokens == nil || *result.Usage.ReasoningTokens != 7 {
		t.Fatalf("terminal usage metadata = %+v", result.Usage)
	}
	if !result.RuntimeEventContract.Passed || len(result.RuntimeEvents) < 2 || result.RuntimeEvents[1].ResolvedModel != "grok-4.6-build" {
		t.Fatalf("normalized terminal events = %+v report=%+v", result.RuntimeEvents, result.RuntimeEventContract)
	}
}

func TestRunRejectsTerminalResolvedModelOutsidePinnedRuntimeBinding(t *testing.T) {
	transcript := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
		`{"jsonrpc":"2.0","id":2,"result":{}}`,
		`{"jsonrpc":"2.0","id":3,"result":{"sessionId":"session-7"}}`,
		`{"jsonrpc":"2.0","id":4,"result":{"stopReason":"end_turn","_meta":{"modelId":"grok-4.6","usage":{"inputTokens":1,"outputTokens":1,"modelUsage":{"other-model":{}}}}}}`,
	}, "\n") + "\n"
	_, err := Run(t.Context(), &fakeRunner{proc: newFakeProcess(strings.NewReader(transcript), strings.NewReader(""))}, Request{
		Prompt: "hello", CWD: "/repo", Model: "grok-4.6", RuntimeVersion: "1.0.13",
	})
	assertCode(t, err, ErrIdentityMismatch)
}

func TestRunRejectsAmbiguousTerminalModelsAndConflictingUsage(t *testing.T) {
	for name, terminal := range map[string]string{
		"multiple models":          `{"stopReason":"end_turn","_meta":{"modelId":"grok-4.6","usage":{"inputTokens":1,"outputTokens":1,"modelUsage":{"grok-4.6-build":{},"other":{}}}}}`,
		"conflicting model fields": `{"stopReason":"end_turn","model":"grok-4.5","_meta":{"modelId":"grok-4.6","usage":{"inputTokens":1,"outputTokens":1,"modelUsage":{"grok-4.6-build":{}}}}}`,
		"conflicting usage":        `{"stopReason":"end_turn","model":"grok-4.6","usage":{"inputTokens":2},"_meta":{"modelId":"grok-4.6","usage":{"inputTokens":1,"outputTokens":1,"modelUsage":{"grok-4.6-build":{}}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			transcript := strings.Join([]string{
				`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
				`{"jsonrpc":"2.0","id":2,"result":{}}`,
				`{"jsonrpc":"2.0","id":3,"result":{"sessionId":"session-7"}}`,
				`{"jsonrpc":"2.0","id":4,"result":` + terminal + `}`,
			}, "\n") + "\n"
			_, err := Run(t.Context(), &fakeRunner{proc: newFakeProcess(strings.NewReader(transcript), strings.NewReader(""))}, Request{Prompt: "hello", CWD: "/repo"})
			assertCode(t, err, ErrProtocol)
		})
	}
}

func TestRunRetainsSessionBoundVendorModelSelectionWithoutPromotingIt(t *testing.T) {
	transcript := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
		`{"jsonrpc":"2.0","id":2,"result":{}}`,
		`{"jsonrpc":"2.0","id":3,"result":{"sessionId":"session-7"}}`,
		`{"jsonrpc":"2.0","method":"_x.ai/session/models/update","params":{"sessionId":"session-7","model":"grok-4.6"}}`,
		`{"jsonrpc":"2.0","id":4,"result":{"stopReason":"end_turn"}}`,
	}, "\n") + "\n"
	result, err := Run(t.Context(), &fakeRunner{proc: newFakeProcess(strings.NewReader(transcript), strings.NewReader(""))}, Request{
		Prompt: "hello", CWD: "/repo", Model: "grok-4.6",
	})
	if err != nil || result.Model != "" || result.ModelEvidence != "" || result.SessionSelectedModel != "grok-4.6" || result.SessionModelSelectionEvidence != "provider_session_notification_plus_exact_launch" {
		t.Fatalf("session-bound model selection result=%+v err=%v", result, err)
	}
}

func TestRunRetainsExactModelSelectionFromSessionConfigOption(t *testing.T) {
	transcript := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
		`{"jsonrpc":"2.0","id":2,"result":{}}`,
		`{"jsonrpc":"2.0","id":3,"result":{"sessionId":"session-7","configOptions":[{"id":"model","category":"model","type":"select","currentValue":"grok-4.6","options":[{"value":"grok-4.5"},{"value":"grok-4.6"}]}]}}`,
		`{"jsonrpc":"2.0","id":4,"result":{"stopReason":"end_turn"}}`,
	}, "\n") + "\n"
	result, err := Run(t.Context(), &fakeRunner{proc: newFakeProcess(strings.NewReader(transcript), strings.NewReader(""))}, Request{
		Prompt: "hello", CWD: "/repo", Model: "grok-4.6",
	})
	if err != nil || result.Model != "" || result.ModelEvidence != "" || result.SessionSelectedModel != "grok-4.6" || result.SessionModelSelectionEvidence != "session_config_option_plus_exact_launch" {
		t.Fatalf("session config model selection result=%+v err=%v", result, err)
	}
	if !result.Authenticated || result.AuthenticationEvidence != "cached_token_authenticate_plus_completed_session" {
		t.Fatalf("completed cached authentication was not recorded safely: authenticated=%v evidence=%q", result.Authenticated, result.AuthenticationEvidence)
	}
}

func TestRunRetainsExactModelSelectionFromTopLevelSessionModelState(t *testing.T) {
	transcript := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
		`{"jsonrpc":"2.0","id":2,"result":{}}`,
		`{"jsonrpc":"2.0","id":3,"result":{"sessionId":"session-7","models":{"currentModelId":"grok-4.6","availableModels":[{"modelId":"grok-4.5"},{"modelId":"grok-4.6"}]}}}`,
		`{"jsonrpc":"2.0","id":4,"result":{"stopReason":"end_turn"}}`,
	}, "\n") + "\n"
	result, err := Run(t.Context(), &fakeRunner{proc: newFakeProcess(strings.NewReader(transcript), strings.NewReader(""))}, Request{
		Prompt: "hello", CWD: "/repo", Model: "grok-4.6",
	})
	if err != nil || result.Model != "" || result.ModelEvidence != "" || result.SessionSelectedModel != "grok-4.6" || result.SessionModelSelectionEvidence != "session_model_state_plus_exact_launch" {
		t.Fatalf("top-level session model-state selection result=%+v err=%v", result, err)
	}
}

func TestSessionConfigExactModelRejectsAmbiguousOrUnboundOptions(t *testing.T) {
	valid := func() sessionConfigOption {
		return sessionConfigOption{
			Category: "model", Type: "select", CurrentValue: json.RawMessage(`"grok-4.6"`),
			Options: json.RawMessage(`[{"value":"grok-4.6"}]`),
		}
	}
	for name, options := range map[string][]sessionConfigOption{
		"missing":              nil,
		"wrong category":       {{Category: "Model", Type: "select", CurrentValue: json.RawMessage(`"grok-4.6"`), Options: json.RawMessage(`[{"value":"grok-4.6"}]`)}},
		"duplicate model":      {valid(), valid()},
		"wrong type":           {{Category: "model", Type: "boolean", CurrentValue: json.RawMessage(`"grok-4.6"`), Options: json.RawMessage(`[{"value":"grok-4.6"}]`)}},
		"wrong current value":  {{Category: "model", Type: "select", CurrentValue: json.RawMessage(`"grok-4.5"`), Options: json.RawMessage(`[{"value":"grok-4.5"}]`)}},
		"value absent options": {{Category: "model", Type: "select", CurrentValue: json.RawMessage(`"grok-4.6"`), Options: json.RawMessage(`[{"value":"grok-4.5"}]`)}},
	} {
		t.Run(name, func(t *testing.T) {
			if model, ok := sessionConfigExactModel(options, "grok-4.6"); ok || model != "" {
				t.Fatalf("unbound session config option became model evidence: model=%q ok=%v", model, ok)
			}
		})
	}
	if model, ok := sessionConfigExactModel([]sessionConfigOption{valid()}, "grok-4.6"); !ok || model != "grok-4.6" {
		t.Fatalf("exact session config option not accepted: model=%q ok=%v", model, ok)
	}
	duplicateValue := valid()
	duplicateValue.Options = json.RawMessage(`[{"value":"grok-4.6"},{"value":"grok-4.6"}]`)
	if model, ok := sessionConfigExactModel([]sessionConfigOption{duplicateValue}, "grok-4.6"); ok || model != "" {
		t.Fatalf("duplicate current model option value became evidence: model=%q ok=%v", model, ok)
	}

	for name, raw := range map[string]json.RawMessage{
		"wrong current":     json.RawMessage(`{"currentModelId":"grok-4.5","availableModels":[{"modelId":"grok-4.5"}]}`),
		"missing current":   json.RawMessage(`{"currentModelId":"grok-4.6","availableModels":[{"modelId":"grok-4.5"}]}`),
		"duplicate current": json.RawMessage(`{"currentModelId":"grok-4.6","availableModels":[{"modelId":"grok-4.6"},{"modelId":"grok-4.6"}]}`),
		"legacy id only":    json.RawMessage(`{"currentModelId":"grok-4.6","availableModels":[{"id":"grok-4.6"}]}`),
		"nested only":       json.RawMessage(`{"state":{"currentModelId":"grok-4.6","availableModels":[{"modelId":"grok-4.6"}]}}`),
	} {
		t.Run("model state "+name, func(t *testing.T) {
			if model, ok := sessionModelsExactModel(raw, "grok-4.6"); ok {
				t.Fatalf("unbound top-level model state became evidence: model=%q", model)
			}
		})
	}
}

func TestRunRejectsUnstructuredOrUnrelatedVendorModelSessionFields(t *testing.T) {
	for name, notification := range map[string]string{
		"split_list_elements": `{"jsonrpc":"2.0","method":"_x.ai/session/models/update","params":{"sessions":[{"sessionId":"session-7"},{"model":"grok-4.6"}]}}`,
		"global_index":        `{"jsonrpc":"2.0","method":"_x.ai/models/update","params":{"sessionId":"session-7","model":"grok-4.6"}}`,
		"nested_session_only": `{"jsonrpc":"2.0","method":"_x.ai/session/models/update","params":{"sessionId":"other-session","model":"grok-4.6","index":{"sessionId":"session-7"}}}`,
		"nested_model_only":   `{"jsonrpc":"2.0","method":"_x.ai/session/models/update","params":{"sessionId":"session-7","model":"other-model","index":{"model":"grok-4.6"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			transcript := strings.Join([]string{
				`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
				`{"jsonrpc":"2.0","id":2,"result":{}}`,
				`{"jsonrpc":"2.0","id":3,"result":{"sessionId":"session-7"}}`,
				notification,
				`{"jsonrpc":"2.0","id":4,"result":{"stopReason":"end_turn"}}`,
			}, "\n") + "\n"
			result, err := Run(t.Context(), &fakeRunner{proc: newFakeProcess(strings.NewReader(transcript), strings.NewReader(""))}, Request{
				Prompt: "hello", CWD: "/repo", Model: "grok-4.6",
			})
			if err != nil || result.Model != "" || result.ModelEvidence != "" {
				t.Fatalf("unstructured vendor fields became identity evidence: result=%+v err=%v", result, err)
			}
		})
	}
}

func TestRunAllowsOnlyKnownNoIDHousekeepingNotification(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	transcript := strings.Join([]string{
		`{"jsonrpc":"2.0","method":"_x.ai/mcp/servers_updated","params":{"servers":[]}}`,
		`{"jsonrpc":"2.0","method":"_x.ai/models/update","params":{"models":[]}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
		`{"jsonrpc":"2.0","id":2,"result":{}}`,
		`{"jsonrpc":"2.0","id":3,"result":{"sessionId":"s"}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"agent_message_chunk","content":{"text":"` + nonce + `\n"}}}}`,
		`{"jsonrpc":"2.0","id":4,"result":{"stopReason":"end_turn"}}`,
		`{"jsonrpc":"2.0","method":"_x.ai/mcp/servers_updated","params":{"servers":[]}}`,
	}, "\n") + "\n"
	result, err := Run(t.Context(), &fakeRunner{proc: newFakeProcess(strings.NewReader(transcript), strings.NewReader(""))}, Request{
		Prompt: "hello", ExpectedNonce: nonce, CWD: "/repo", PostResponseQuietWindow: time.Millisecond,
	})
	if err != nil || !result.AcknowledgementVerified {
		t.Fatalf("known housekeeping notification result=%+v err=%v", result, err)
	}

	serverRequest := strings.Join([]string{
		`{"jsonrpc":"2.0","id":99,"method":"_x.ai/mcp/servers_updated","params":{}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
	}, "\n") + "\n"
	_, err = Run(t.Context(), &fakeRunner{proc: newFakeProcess(strings.NewReader(serverRequest), strings.NewReader(""))}, Request{Prompt: "hello", CWD: "/repo"})
	assertCode(t, err, ErrProtocol)
}

func TestRunFailsClosedWhenAuthMethodUnavailable(t *testing.T) {
	proc := newFakeProcess(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"browser_login"}]}}`+"\n"), strings.NewReader(""))
	result, err := Run(t.Context(), &fakeRunner{proc: proc}, Request{Prompt: "hello", CWD: "/repo"})
	assertCode(t, err, ErrCachedAuthUnavailable)
	if result.State != StateFailed || result.ProviderSessionID != "" || result.FailureStage != "auth_method_selection" {
		t.Fatalf("result = %+v", result)
	}
}

func TestRunReportsBoundedSessionNewFailureStage(t *testing.T) {
	transcript := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
		`{"jsonrpc":"2.0","id":2,"result":{}}`,
		`{"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"redacted provider setup failure"}}`,
	}, "\n") + "\n"
	result, err := Run(t.Context(), &fakeRunner{proc: newFakeProcess(strings.NewReader(transcript), strings.NewReader("diagnostic body must not be retained"))}, Request{Prompt: "hello", CWD: "/repo"})
	assertCode(t, err, ErrProvider)
	if result.FailureStage != "session_new" || result.ProviderSessionID != "" || result.Stderr.SHA256 == "" || result.ProviderRPCErrorCode == nil || *result.ProviderRPCErrorCode != -32000 {
		t.Fatalf("result = %+v", result)
	}
	if strings.Contains(string(mustJSON(t, result)), "redacted provider setup failure") || strings.Contains(string(mustJSON(t, result)), "diagnostic body") {
		t.Fatal("bounded failure diagnostics retained provider text")
	}
}

func TestRunOmitsNonIntegerProviderErrorCode(t *testing.T) {
	transcript := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
		`{"jsonrpc":"2.0","id":2,"result":{}}`,
		`{"jsonrpc":"2.0","id":3,"error":{"code":"account-secret-shaped-code","message":"private provider text"}}`,
	}, "\n") + "\n"
	result, err := Run(t.Context(), &fakeRunner{proc: newFakeProcess(strings.NewReader(transcript), strings.NewReader(""))}, Request{Prompt: "hello", CWD: "/repo"})
	assertCode(t, err, ErrProvider)
	if result.ProviderRPCErrorCode != nil {
		t.Fatalf("non-integer provider error code was retained: %+v", result.ProviderRPCErrorCode)
	}
	if strings.Contains(string(mustJSON(t, result)), "account-secret-shaped-code") || strings.Contains(string(mustJSON(t, result)), "private provider text") {
		t.Fatal("provider error payload leaked into receipt")
	}
}

func TestRunRejectsOversizedProtocolLine(t *testing.T) {
	overseized := `{"jsonrpc":"2.0","id":1,"result":{"padding":"` + strings.Repeat("x", MaxProtocolLineBytes) + `"}}` + "\n"
	proc := newFakeProcess(strings.NewReader(overseized), strings.NewReader(""))
	_, err := Run(t.Context(), &fakeRunner{proc: proc}, Request{Prompt: "hello", CWD: "/repo"})
	assertCode(t, err, ErrProtocol)
}

func TestRunTimeoutBeforePromptIsSafelyAborted(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	proc := newBlockingTranscriptProcess([]string{
		`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
	})
	proc.onWrite = func(message wireRequest) {
		if message.Method == "authenticate" {
			cancel()
		}
	}
	result, err := Run(ctx, &fakeRunner{proc: proc}, Request{Prompt: "hello", CWD: "/repo"})
	assertCode(t, err, ErrTimeout)
	if result.State != StateAbortedSafe || result.ProviderSessionID != "" {
		t.Fatalf("result = %+v, want safe pre-prompt abort", result)
	}
}

func TestRunTimeoutAfterPromptWriteIsOutcomeUnknown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	proc := newBlockingTranscriptProcess([]string{
		`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
		`{"jsonrpc":"2.0","id":2,"result":{}}`,
		`{"jsonrpc":"2.0","id":3,"result":{"sessionId":"provider-session"}}`,
	})
	proc.onWrite = func(message wireRequest) {
		if message.Method == "session/prompt" {
			cancel()
		}
	}
	result, err := Run(ctx, &fakeRunner{proc: proc}, Request{Prompt: "hello", CWD: "/repo"})
	assertCode(t, err, ErrOutcomeUnknown)
	if result.State != StateOutcomeUnknown || result.ProviderSessionID != "provider-session" {
		t.Fatalf("result = %+v, want outcome unknown after prompt write", result)
	}
}

func TestRunCancellationBeforePromptWritesNoBytesIsSafelyAborted(t *testing.T) {
	proc := newFakeProcess(strings.NewReader(successfulTranscript(`[{"id":"cached_token"}]`)), strings.NewReader(""))
	proc.beforeWrite = func(message wireRequest) error {
		if message.Method == "session/prompt" {
			return context.Canceled
		}
		return nil
	}
	result, err := Run(t.Context(), &fakeRunner{proc: proc}, Request{Prompt: "hello", CWD: "/repo"})
	assertCode(t, err, ErrTimeout)
	if result.State != StateAbortedSafe || result.ProviderSessionID != "s" {
		t.Fatalf("result = %+v, want safe abort after a proven zero-byte prompt write", result)
	}
	requests := decodeRequests(t, proc.stdin.String())
	if len(requests) != 3 || requests[2].Method != "session/new" {
		t.Fatalf("requests = %+v, want no session/prompt bytes", requests)
	}
}

func TestRunCancellationRequiresOriginalPromptCancelledAcknowledgement(t *testing.T) {
	for name, completion := range map[string]string{
		"acknowledged":        `{"stopReason":"cancelled"}`,
		"missing stop reason": `{}`,
		"wrong stop reason":   `{"stopReason":"end_turn"}`,
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			proc, writer := cancellationTranscriptProcess(t)
			proc.onWrite = func(message wireRequest) {
				switch message.Method {
				case "session/prompt":
					cancel()
				case "session/cancel":
					_, _ = io.WriteString(writer, `{"jsonrpc":"2.0","id":4,"result":`+completion+"}\n")
					_ = writer.Close()
				}
			}
			result, err := Run(ctx, &fakeRunner{proc: proc}, Request{
				Prompt: "hello", CWD: "/repo", OperationID: "operation-cancelled",
				CancellationGracePeriod: 100 * time.Millisecond,
			})
			requests := decodeRequests(t, proc.stdin.String())
			if len(requests) != 5 || requests[4].Method != "session/cancel" || len(requests[4].ID) != 0 || nestedString(t, requests[4].Params, "sessionId") != "provider-session" {
				t.Fatalf("ACP cancellation wire sequence = %+v", requests)
			}
			if !result.Cancellation.Requested || !result.Cancellation.NotificationWritten || result.Cancellation.SessionSHA256 != acpCancellationHash("provider-session") || result.Cancellation.OperationSHA256 != acpOperationHash("operation-cancelled", "provider-session", 4) || result.Cancellation.PromptRequestID != 4 || result.Cancellation.CloudInferenceStopConfirmed {
				t.Fatalf("cancellation binding receipt = %+v", result.Cancellation)
			}
			if name == "acknowledged" {
				assertCode(t, err, ErrCancelled)
				if result.State != StateCancelled || !result.CompletionConfirmed || result.StopReason != "cancelled" || !result.Cancellation.AgentACPAcknowledged || result.Cancellation.Acknowledgement != "session_prompt_stop_reason_cancelled" {
					t.Fatalf("cancellation acknowledgement receipt = %+v", result)
				}
				return
			}
			assertCode(t, err, ErrCancellationUnconfirmed)
			if result.State != StateOutcomeUnknown || result.Cancellation.AgentACPAcknowledged || result.StopReason == "cancelled" {
				t.Fatalf("unconfirmed cancellation receipt = %+v", result)
			}
		})
	}
}

func TestRunCancellationTimeoutLeavesOutcomeUnknown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	proc, _ := cancellationTranscriptProcess(t)
	proc.onWrite = func(message wireRequest) {
		if message.Method == "session/prompt" {
			cancel()
		}
	}
	result, err := Run(ctx, &fakeRunner{proc: proc}, Request{
		Prompt: "hello", CWD: "/repo", OperationID: "operation-timeout",
		CancellationGracePeriod: 10 * time.Millisecond,
	})
	assertCode(t, err, ErrOutcomeUnknown)
	requests := decodeRequests(t, proc.stdin.String())
	if len(requests) != 5 || requests[4].Method != "session/cancel" || !result.Cancellation.Requested || !result.Cancellation.NotificationWritten || result.Cancellation.AgentACPAcknowledged || result.State != StateOutcomeUnknown {
		t.Fatalf("timeout cancellation receipt = %+v requests=%+v", result, requests)
	}
}

func TestCleanupACPProcessKeepsResidualTreeEvidenceSeparate(t *testing.T) {
	proc := newFakeProcess(strings.NewReader(""), strings.NewReader(""))
	proc.pid = 404
	cleanup := cleanupACPProcessWithTerminator(proc, func(context.Context, int32) CancellationReceipt {
		return CancellationReceipt{
			LocalTermination: "residual_processes_detected",
			ResidualPIDs:     []int32{404, 405},
			ObservedAt:       time.Unix(1, 0).UTC(),
		}
	})
	if cleanup.LocalTermination != "residual_processes_detected" || !slices.Equal(cleanup.ResidualPIDs, []int32{404, 405}) || cleanup.Reaped || cleanup.ObservedAt != time.Unix(1, 0).UTC() {
		t.Fatalf("cleanup = %+v", cleanup)
	}
}

func TestReconcileACPResidualsAfterReapPromotesOnlyGoneObservedPIDs(t *testing.T) {
	started := time.Unix(1, 0).UTC()
	base := ProcessCleanupReceipt{
		LocalTermination: "residual_processes_detected",
		ResidualPIDs:     []int32{404, 405},
		Reaped:           true,
		ObservedAt:       started,
	}

	t.Run("all previously observed residuals are gone after reap", func(t *testing.T) {
		inspector := &treeInspector{live: map[int32]bool{404: false, 405: false}}
		got := reconcileACPResidualsAfterReapWithInspector(base, inspector, 0)
		if got.LocalTermination != "observed_tree_terminated_verified" || len(got.ResidualPIDs) != 0 || !got.Reaped || !got.ObservedAt.After(started) {
			t.Fatalf("reconciled cleanup = %+v", got)
		}
	})

	t.Run("still-live observed residual stays explicit", func(t *testing.T) {
		inspector := &treeInspector{live: map[int32]bool{404: true, 405: false}}
		got := reconcileACPResidualsAfterReapWithInspector(base, inspector, 0)
		if got.LocalTermination != "residual_processes_detected" || !slices.Equal(got.ResidualPIDs, []int32{404}) || !got.Reaped || !got.ObservedAt.Equal(started) {
			t.Fatalf("residual cleanup was overclaimed: %+v", got)
		}
	})
}

func cancellationTranscriptProcess(t *testing.T) (*fakeProcess, *io.PipeWriter) {
	t.Helper()
	reader, writer := io.Pipe()
	proc := newFakeProcess(reader, strings.NewReader(""))
	proc.kill = func() { _ = writer.Close() }
	go func() {
		for _, line := range []string{
			`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`,
			`{"jsonrpc":"2.0","id":2,"result":{}}`,
			`{"jsonrpc":"2.0","id":3,"result":{"sessionId":"provider-session"}}`,
		} {
			_, _ = io.WriteString(writer, line+"\n")
		}
	}()
	return proc, writer
}

type fakeRunner struct {
	proc *fakeProcess
	spec StartSpec
	err  error
}

func (r *fakeRunner) Start(_ context.Context, spec StartSpec) (Process, error) {
	r.spec = spec
	if r.err != nil {
		return nil, r.err
	}
	return r.proc, nil
}

type fakeProcess struct {
	stdin       *recordingWriteCloser
	stdout      io.Reader
	stderr      io.Reader
	beforeWrite func(wireRequest) error
	onWrite     func(wireRequest)
	mu          sync.Mutex
	closed      bool
	killCalls   int
	waitCalls   int
	kill        func()
	waitErr     error
	pid         int32
}

func newFakeProcess(stdout, stderr io.Reader) *fakeProcess {
	return &fakeProcess{stdin: &recordingWriteCloser{}, stdout: stdout, stderr: stderr}
}

func newBlockingTranscriptProcess(lines []string) *fakeProcess {
	reader, writer := io.Pipe()
	proc := newFakeProcess(reader, strings.NewReader(""))
	proc.kill = func() { _ = writer.Close() }
	go func() {
		for _, line := range lines {
			_, _ = io.WriteString(writer, line+"\n")
		}
		// Keep the pipe open until Kill. This models an ACP child that accepted
		// a request but has not yet produced the next response.
	}()
	return proc
}

func (p *fakeProcess) Stdin() io.WriteCloser { return fakeStdin{parent: p} }
func (p *fakeProcess) Stdout() io.Reader     { return p.stdout }
func (p *fakeProcess) Stderr() io.Reader     { return p.stderr }
func (p *fakeProcess) Wait() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.waitCalls++
	return p.waitErr
}
func (p *fakeProcess) PID() int32 { return p.pid }

type fakeExitError struct{ code int }

func (e fakeExitError) Error() string { return "process exited" }
func (e fakeExitError) ExitCode() int { return e.code }
func (p *fakeProcess) Kill() error {
	p.mu.Lock()
	p.killCalls++
	kill := p.kill
	p.mu.Unlock()
	if kill != nil {
		kill()
	}
	return nil
}

type fakeStdin struct{ parent *fakeProcess }

func (s fakeStdin) Write(data []byte) (int, error) {
	var message wireRequest
	_ = json.Unmarshal(bytes.TrimSpace(data), &message)
	if s.parent.beforeWrite != nil {
		if err := s.parent.beforeWrite(message); err != nil {
			return 0, err
		}
	}
	n, err := s.parent.stdin.Write(data)
	if err != nil {
		return n, err
	}
	if json.Unmarshal(bytes.TrimSpace(data), &message) == nil && s.parent.onWrite != nil {
		s.parent.onWrite(message)
	}
	return n, nil
}

func (s fakeStdin) Close() error {
	s.parent.mu.Lock()
	s.parent.closed = true
	s.parent.mu.Unlock()
	return nil
}

type recordingWriteCloser struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *recordingWriteCloser) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(data)
}

func (w *recordingWriteCloser) Close() error { return nil }

func (w *recordingWriteCloser) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

type wireRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

func decodeRequests(t *testing.T, raw string) []wireRequest {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	requests := make([]wireRequest, 0, len(lines))
	for _, line := range lines {
		var request wireRequest
		if err := json.Unmarshal([]byte(line), &request); err != nil {
			t.Fatalf("decode request %q: %v", line, err)
		}
		requests = append(requests, request)
	}
	return requests
}

func nestedString(t *testing.T, raw json.RawMessage, key string) string {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode params: %v", err)
	}
	value, _ := decoded[key].(string)
	return value
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func sameStrings(a, b []string) bool { return strings.Join(a, "\x00") == strings.Join(b, "\x00") }

func assertCode(t *testing.T, err error, want ErrorCode) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != want {
		t.Fatalf("error = %v, want code %s", err, want)
	}
}

func successfulTranscript(authMethods string) string {
	return strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"result":{"authMethods":` + authMethods + `}}`,
		`{"jsonrpc":"2.0","id":2,"result":{}}`,
		`{"jsonrpc":"2.0","id":3,"result":{"sessionId":"s"}}`,
		`{"jsonrpc":"2.0","id":4,"result":{"stopReason":"end_turn"}}`,
	}, "\n") + "\n"
}

func updateNameHash(names ...string) string {
	hash := sha256.New()
	for _, name := range names {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(name)))
		_, _ = hash.Write(length[:])
		_, _ = io.WriteString(hash, name)
	}
	return hex.EncodeToString(hash.Sum(nil))
}
