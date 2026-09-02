package zai

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type nativeToolClientFake struct {
	t        *testing.T
	bodies   []string
	status   []int
	requests []*http.Request
}

func (f *nativeToolClientFake) Do(request *http.Request) (*http.Response, error) {
	f.t.Helper()
	data, err := io.ReadAll(request.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	request.Body = io.NopCloser(bytes.NewReader(data))
	f.requests = append(f.requests, request)
	index := len(f.requests) - 1
	if index >= len(f.bodies) {
		return nil, errors.New("unexpected native tool request")
	}
	status := http.StatusOK
	if index < len(f.status) && f.status[index] != 0 {
		status = f.status[index]
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(f.bodies[index])),
		Request:    request,
	}, nil
}

type nativeToolExecutorFake struct {
	calls  []NativeToolCall
	result NativeToolResult
	err    error
}

func (f *nativeToolExecutorFake) ExecuteNativeTool(_ context.Context, call NativeToolCall) (NativeToolResult, error) {
	f.calls = append(f.calls, call)
	return f.result, f.err
}

func nativeToolsTestHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func nativeToolsTestRequest(executor NativeToolExecutor) NativeToolRequest {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	return NativeToolRequest{
		NativeRequest: NativeRequest{
			Endpoint: NativeChatCompletionsEndpoint, Model: "glm-test",
			Prompt:        "perform bounded work and finish with " + nonce,
			ExpectedNonce: nonce, ExpectedRequestID: "ntm-request-000001",
			NativeAPIKey: "native-test-key", ExplicitOptIn: true, AllowTools: true,
		},
		Tools: []NativeFunctionDefinition{{
			Name: "verify_manifest", Description: "Run one controller-owned approved verification manifest",
			Parameters: json.RawMessage(`{"type":"object","properties":{"command_id":{"type":"string"}},"required":["command_id"]}`),
		}},
		Executor: executor, MaxRounds: 3,
	}
}

func TestRunNativeToolsExecutesControllerCallAndBindsEveryRound(t *testing.T) {
	executor := &nativeToolExecutorFake{result: NativeToolResult{Content: `{"exit_code":0,"receipt":"safe"}`, EvidenceSHA256: nativeToolsTestHash("broker-receipt")}}
	request := nativeToolsTestRequest(executor)
	secondRequestID := nativeToolRoundRequestID(request.ExpectedRequestID, 2)
	client := &nativeToolClientFake{t: t, bodies: []string{
		`{"id":"completion-one","request_id":"ntm-request-000001","model":"glm-test","choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"call-one","type":"function","function":{"name":"verify_manifest","arguments":{"command_id":"go-test"}}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5,"prompt_tokens_details":{"cached_tokens":1}}}`,
		`{"id":"completion-two","request_id":"` + secondRequestID + `","model":"glm-test","choices":[{"message":{"role":"assistant","content":"NTM_ACK_0123456789abcdef0123456789abcdef\n"},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":4,"total_tokens":11,"prompt_tokens_details":{"cached_tokens":5}}}`,
	}}
	receipt, err := RunNativeTools(t.Context(), client, request)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.NonceVerified || !receipt.ControllerOwnedExecutor || receipt.Rounds != 2 || receipt.ToolCallCount != 1 || len(receipt.ToolExecutions) != 1 || !receipt.ToolExecutions[0].Succeeded || len(receipt.RoundRequestIDSHA256) != 2 {
		t.Fatalf("receipt=%+v", receipt)
	}
	if len(executor.calls) != 1 || executor.calls[0].Name != "verify_manifest" || string(executor.calls[0].Arguments) != `{"command_id":"go-test"}` {
		t.Fatalf("calls=%+v", executor.calls)
	}
	if receipt.Usage.InputTokens == nil || *receipt.Usage.InputTokens != 10 || receipt.Usage.OutputTokens == nil || *receipt.Usage.OutputTokens != 6 || receipt.Usage.TotalTokens == nil || *receipt.Usage.TotalTokens != 16 || receipt.Usage.CachedInputTokens == nil || *receipt.Usage.CachedInputTokens != 6 {
		t.Fatalf("usage=%+v", receipt.Usage)
	}
	if len(client.requests) != 2 {
		t.Fatalf("requests=%d", len(client.requests))
	}
	secondBody, _ := io.ReadAll(client.requests[1].Body)
	for _, want := range []string{`"role":"assistant"`, `"role":"tool"`, `"tool_call_id":"call-one"`, `"request_id":"` + secondRequestID + `"`} {
		if !bytes.Contains(secondBody, []byte(want)) {
			t.Fatalf("second request omitted %s: %s", want, secondBody)
		}
	}
	encoded, _ := json.Marshal(receipt)
	for _, prohibited := range []string{"native-test-key", "go-test", "call-one", "safe"} {
		if bytes.Contains(encoded, []byte(prohibited)) {
			t.Fatalf("receipt leaked %q: %s", prohibited, encoded)
		}
	}
}

func TestRunNativeToolsRejectsUnadvertisedOrMalformedCallsBeforeExecutor(t *testing.T) {
	for _, body := range []string{
		`{"id":"c","request_id":"ntm-request-000001","model":"glm-test","choices":[{"message":{"tool_calls":[{"id":"call","type":"function","function":{"name":"shell","arguments":{}}}]},"finish_reason":"tool_calls"}]}`,
		`{"id":"c","request_id":"ntm-request-000001","model":"glm-test","choices":[{"message":{"tool_calls":[{"id":"call","type":"function","function":{"name":"verify_manifest","arguments":[]}}]},"finish_reason":"tool_calls"}]}`,
	} {
		executor := &nativeToolExecutorFake{result: NativeToolResult{Content: "ok", EvidenceSHA256: nativeToolsTestHash("evidence")}}
		client := &nativeToolClientFake{t: t, bodies: []string{body}}
		if _, err := RunNativeTools(t.Context(), client, nativeToolsTestRequest(executor)); err == nil || len(executor.calls) != 0 {
			t.Fatalf("err=%v calls=%+v", err, executor.calls)
		}
	}
}

func TestRunNativeToolsFailsClosedOnPolicyAndExecutorEvidence(t *testing.T) {
	request := nativeToolsTestRequest(nil)
	if _, err := RunNativeTools(t.Context(), &nativeToolClientFake{t: t}, request); err == nil {
		t.Fatal("nil executor was accepted")
	}
	executor := &nativeToolExecutorFake{result: NativeToolResult{Content: "result", EvidenceSHA256: "not-a-digest"}}
	request = nativeToolsTestRequest(executor)
	client := &nativeToolClientFake{t: t, bodies: []string{`{"id":"c","request_id":"ntm-request-000001","model":"glm-test","choices":[{"message":{"tool_calls":[{"id":"call","type":"function","function":{"name":"verify_manifest","arguments":{}}}]},"finish_reason":"tool_calls"}]}`}}
	receipt, err := RunNativeTools(t.Context(), client, request)
	if err == nil || len(receipt.ToolExecutions) != 1 || receipt.ToolExecutions[0].Succeeded || receipt.ToolExecutions[0].ErrorSHA256 == "" {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
}

func TestRunNativeToolsRequiresExactModelRequestAndNonce(t *testing.T) {
	executor := &nativeToolExecutorFake{result: NativeToolResult{Content: "ok", EvidenceSHA256: nativeToolsTestHash("evidence")}}
	for _, body := range []string{
		`{"id":"c","request_id":"different-request","model":"glm-test","choices":[{"message":{"content":"NTM_ACK_0123456789abcdef0123456789abcdef\n"},"finish_reason":"stop"}]}`,
		`{"id":"c","request_id":"ntm-request-000001","model":"different-model","choices":[{"message":{"content":"NTM_ACK_0123456789abcdef0123456789abcdef\n"},"finish_reason":"stop"}]}`,
		`{"id":"c","request_id":"ntm-request-000001","model":"glm-test","choices":[{"message":{"content":"not-the-nonce"},"finish_reason":"stop"}]}`,
	} {
		client := &nativeToolClientFake{t: t, bodies: []string{body}}
		if _, err := RunNativeTools(t.Context(), client, nativeToolsTestRequest(executor)); err == nil {
			t.Fatalf("invalid response accepted: %s", body)
		}
	}
}

func TestRunNativeToolsPreservesStructuredProviderFailureAndBodyCleanup(t *testing.T) {
	executor := &nativeToolExecutorFake{result: NativeToolResult{Content: "ok", EvidenceSHA256: nativeToolsTestHash("evidence")}}
	client := &nativeToolClientFake{t: t, status: []int{http.StatusUnauthorized}, bodies: []string{`{"error":{"code":"1001","type":"authentication_failed"}}`}}
	receipt, err := RunNativeTools(t.Context(), client, nativeToolsTestRequest(executor))
	if err == nil || receipt.HTTPStatus != http.StatusUnauthorized || receipt.ErrorCode != "1001" || receipt.ErrorType != "authentication_failed" || !receipt.Cancellation.LocalBodyClosed || len(executor.calls) != 0 {
		t.Fatalf("receipt=%+v err=%v calls=%+v", receipt, err, executor.calls)
	}
}
