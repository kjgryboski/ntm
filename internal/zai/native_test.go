package zai

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

type nativeClient struct {
	response *http.Response
	request  *http.Request
}

func (c *nativeClient) Do(r *http.Request) (*http.Response, error) {
	c.request = r
	if c.response != nil && c.response.Request == nil {
		c.response.Request = r
	}
	return c.response, nil
}

func TestRunNativeRedactsToolsAndBindsNonce(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	body := "data: {\"id\":\"completion-1\",\"request_id\":\"request-1\",\"model\":\"glm-test\",\"session_id\":\"session-1\",\"choices\":[{\"delta\":{\"content\":\"" + nonce + "\\n\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":5}}\n\ndata: [DONE]\n"
	c := &nativeClient{response: &http.Response{StatusCode: 200, Header: http.Header{"X-Request-Id": []string{"request-1"}}, Body: ioNop(bytes.NewBufferString(body))}}
	prompt := "secret prompt; return " + nonce
	r, err := RunNative(t.Context(), c, NativeRequest{Endpoint: NativeChatCompletionsEndpoint, Model: "glm-test", Prompt: prompt, ExpectedNonce: nonce, ExpectedRequestID: "request-1", NativeAPIKey: "secret-key", ExplicitOptIn: true})
	if err != nil || !r.NonceVerified || r.ToolCallCount != 0 || r.FinishReason != "stop" || !r.Cancellation.LocalBodyClosed || r.ProviderRequestIDSHA256 == "" || r.CompletionIDSHA256 == "" || r.ProviderSessionIDSHA256 == "" {
		t.Fatalf("receipt=%+v err=%v", r, err)
	}
	if r.ToolCallsSHA256 == "" || r.OutputSHA256 == "" || c.request.Header.Get("Authorization") != "Bearer secret-key" {
		t.Fatalf("bad transport receipt/request")
	}
	var sent nativeRequestPayload
	if err := json.NewDecoder(c.request.Body).Decode(&sent); err != nil || sent.RequestID != "request-1" {
		t.Fatalf("payload=%+v err=%v", sent, err)
	}
	encoded, _ := json.Marshal(r)
	if strings.Contains(string(encoded), "request-1") || strings.Contains(string(encoded), "completion-1") || strings.Contains(string(encoded), "session-1") || strings.Contains(string(encoded), "secret") {
		t.Fatalf("native receipt retained raw identifiers or secrets: %s", encoded)
	}
}

func TestRunNativeRequiresOptInAndProductionHost(t *testing.T) {
	c := &nativeClient{}
	_, err := RunNative(t.Context(), c, NativeRequest{Endpoint: "https://evil.example/chat", Model: "m", Prompt: "p", NativeAPIKey: "key", ExplicitOptIn: true})
	if err == nil {
		t.Fatal("non-Z.ai production host accepted")
	}
	_, err = RunNative(t.Context(), c, NativeRequest{Endpoint: NativeChatCompletionsEndpoint, Model: "m", Prompt: "p", NativeAPIKey: "key"})
	if err == nil {
		t.Fatal("missing opt-in accepted")
	}
	_, err = RunNative(t.Context(), c, NativeRequest{Endpoint: NativeChatCompletionsEndpoint, Model: "m", Prompt: "p", NativeAPIKey: "key", ExplicitOptIn: true, AllowTools: true})
	if err == nil {
		t.Fatal("unimplemented native tool execution accepted")
	}
}

func TestRunNativeRequiresExactDocumentedEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"http://api.z.ai/api/paas/v4/chat/completions",
		"https://api.z.ai:443/api/paas/v4/chat/completions",
		"https://user@api.z.ai/api/paas/v4/chat/completions",
		"https://api.z.ai/api/paas/v4/chat/completions/",
		"https://api.z.ai/api/paas/v4/chat/completions?model=other",
		"https://api.z.ai/api/paas/v4/chat/completions#fragment",
	} {
		input := nativeRequest("")
		input.Endpoint = endpoint
		if err := validateNativeRequest(input); err == nil {
			t.Fatalf("endpoint %q accepted", endpoint)
		}
	}
	if err := validateNativeRequest(nativeRequest("")); err != nil {
		t.Fatalf("documented endpoint rejected: %v", err)
	}
}

func TestRunNativeValidatesCallerRequestID(t *testing.T) {
	for _, value := range []string{"", "short", strings.Repeat("a", 65), "valid-req\n"} {
		request := nativeRequest("")
		request.ExpectedRequestID = value
		if err := validateNativeRequest(request); err == nil {
			t.Fatalf("invalid caller request ID %q accepted", value)
		}
	}
}

func TestRunNativeRejectsMissingTerminalMarker(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	body := "data: {\"model\":\"glm-test\",\"choices\":[{\"delta\":{\"content\":\"" + nonce + "\\n\"},\"finish_reason\":\"stop\"}]}\n"
	r, err := RunNative(t.Context(), nativeResponse(body), nativeRequest(nonce))
	if err == nil || r.Cancellation.ProviderAcknowledged || !r.Cancellation.LocalBodyClosed {
		t.Fatalf("receipt=%+v err=%v", r, err)
	}
}

func TestRunNativeRequiresExactSSERequestIDEcho(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	request := nativeRequest(nonce)

	t.Run("missing from stream", func(t *testing.T) {
		body := "data: {\"model\":\"glm-test\",\"choices\":[{\"delta\":{\"content\":\"" + nonce + "\\n\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n"
		if _, err := RunNative(t.Context(), nativeResponse(body), request); err == nil {
			t.Fatal("stream without caller request ID accepted")
		}
	})
	t.Run("matching header alone", func(t *testing.T) {
		body := "data: {\"model\":\"glm-test\",\"choices\":[{\"delta\":{\"content\":\"" + nonce + "\\n\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n"
		client := nativeResponse(body)
		client.response.Header.Set("X-Request-Id", request.ExpectedRequestID)
		if _, err := RunNative(t.Context(), client, request); err == nil {
			t.Fatal("header-only request correlation accepted")
		}
	})
	t.Run("conflicting stream ID", func(t *testing.T) {
		body := "data: {\"request_id\":\"other-request-123\",\"model\":\"glm-test\",\"choices\":[{\"delta\":{\"content\":\"" + nonce + "\\n\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n"
		if _, err := RunNative(t.Context(), nativeResponse(body), request); err == nil {
			t.Fatal("conflicting caller request ID accepted")
		}
	})
}

func TestRunNativeRejectsMissingFinishReason(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	body := "data: {\"model\":\"glm-test\",\"choices\":[{\"delta\":{\"content\":\"" + nonce + "\\n\"}}]}\n\ndata: [DONE]\n"
	r, err := RunNative(t.Context(), nativeResponse(body), nativeRequest(nonce))
	if err == nil || r.Cancellation.ProviderAcknowledged || !r.Cancellation.LocalBodyClosed {
		t.Fatalf("receipt=%+v err=%v", r, err)
	}
}

func TestRunNativeRejectsModelMismatch(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	body := "data: {\"model\":\"other-model\",\"choices\":[{\"delta\":{\"content\":\"" + nonce + "\\n\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n"
	r, err := RunNative(t.Context(), nativeResponse(body), nativeRequest(nonce))
	if err == nil || r.Model != "" || r.Cancellation.ProviderAcknowledged || !r.Cancellation.LocalBodyClosed {
		t.Fatalf("receipt=%+v err=%v", r, err)
	}
}

func TestRunNativeRejectsAmbiguousChoices(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	body := "data: {\"model\":\"glm-test\",\"choices\":[{\"delta\":{\"content\":\"" + nonce + "\\n\"},\"finish_reason\":\"stop\"},{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n"
	if _, err := RunNative(t.Context(), nativeResponse(body), nativeRequest(nonce)); err == nil {
		t.Fatal("multiple choices accepted")
	}
}

func TestRunNativeRejectsConflictingFinishReasons(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	body := "data: {\"model\":\"glm-test\",\"choices\":[{\"delta\":{\"content\":\"" + nonce + "\\n\"},\"finish_reason\":\"stop\"}]}\n\ndata: {\"model\":\"glm-test\",\"choices\":[{\"delta\":{},\"finish_reason\":\"length\"}]}\n\ndata: [DONE]\n"
	if _, err := RunNative(t.Context(), nativeResponse(body), nativeRequest(nonce)); err == nil {
		t.Fatal("conflicting finish reasons accepted")
	}
}

func TestRunNativeRejectsNegativeUsage(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	body := "data: {\"model\":\"glm-test\",\"choices\":[{\"delta\":{\"content\":\"" + nonce + "\\n\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":-1}}\n\ndata: [DONE]\n"
	if _, err := RunNative(t.Context(), nativeResponse(body), nativeRequest(nonce)); err == nil {
		t.Fatal("negative usage accepted")
	}
}

func TestRunNativeRejectsUnsolicitedToolCall(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	body := "data: {\"model\":\"glm-test\",\"choices\":[{\"delta\":{\"content\":\"" + nonce + "\\n\",\"tool_calls\":[{\"function\":{\"name\":\"Read\",\"arguments\":\"secret=never-retain\"}}]},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n"
	r, err := RunNative(t.Context(), nativeResponse(body), nativeRequest(nonce))
	if err == nil || r.ToolCallCount != 1 || r.ToolCallsSHA256 == hashNative(nil) {
		t.Fatalf("unsolicited tool receipt=%+v err=%v", r, err)
	}
}

func TestRunNativeRejectsMismatchedResponseEndpointAndUnsafeErrorIdentifier(t *testing.T) {
	request := nativeRequest("")
	wrongRequest, err := http.NewRequest(http.MethodPost, "https://api.z.ai/api/paas/v4/other", nil)
	if err != nil {
		t.Fatal(err)
	}
	client := nativeResponse("data: [DONE]\n")
	client.response.Request = wrongRequest
	if _, err := RunNative(t.Context(), client, request); err == nil {
		t.Fatal("mismatched response endpoint accepted")
	}

	body := `{"error":{"code":"unsafe secret prose","type":"bad type"}}`
	client = &nativeClient{response: &http.Response{StatusCode: http.StatusBadRequest, Header: make(http.Header), Body: ioNop(bytes.NewBufferString(body))}}
	receipt, err := RunNative(t.Context(), client, request)
	if err == nil || receipt.ErrorCode != "" || receipt.ErrorType != "" {
		t.Fatalf("unsafe structured error receipt=%+v err=%v", receipt, err)
	}
}

func nativeRequest(nonce string) NativeRequest {
	if nonce == "" {
		nonce = "NTM_ACK_0123456789abcdef0123456789abcdef"
	}
	return NativeRequest{Endpoint: NativeChatCompletionsEndpoint, Model: "glm-test", Prompt: "secret prompt; return " + nonce, ExpectedNonce: nonce, ExpectedRequestID: "ntm-request-0123456789abcdef", NativeAPIKey: "secret-key", ExplicitOptIn: true}
}

func nativeResponse(body string) *nativeClient {
	return &nativeClient{response: &http.Response{StatusCode: 200, Header: make(http.Header), Body: ioNop(bytes.NewBufferString(body))}}
}

type nopBody struct{ *bytes.Buffer }

func (nopBody) Close() error        { return nil }
func ioNop(b *bytes.Buffer) nopBody { return nopBody{b} }
