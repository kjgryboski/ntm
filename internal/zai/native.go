package zai

// Native Z.ai transport is intentionally separate from the Claude-compatible
// Coding Plan lane. It requires a separately authorized native API credential
// and an explicit caller opt-in for every production request.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const NativeChatCompletionsEndpoint = "https://api.z.ai/api/paas/v4/chat/completions"

type NativeRequest struct {
	Endpoint          string
	Model             string
	Prompt            string
	ExpectedNonce     string
	ExpectedRequestID string
	NativeAPIKey      string
	ExplicitOptIn     bool
	AllowTools        bool
}

// NativeReceipt contains structured evidence, never prompt text, key material,
// raw output, or tool arguments. Tool arguments are represented by one hash.
type NativeReceipt struct {
	Model                   string             `json:"model,omitempty"`
	ProviderRequestIDSHA256 string             `json:"provider_request_id_sha256,omitempty"`
	CompletionIDSHA256      string             `json:"completion_id_sha256,omitempty"`
	ProviderSessionIDSHA256 string             `json:"provider_session_id_sha256,omitempty"`
	FinishReason            string             `json:"finish_reason,omitempty"`
	Usage                   NativeUsage        `json:"usage"`
	ToolCallCount           int                `json:"tool_call_count"`
	ToolCallsSHA256         string             `json:"tool_calls_sha256"`
	OutputSHA256            string             `json:"output_sha256"`
	NonceVerified           bool               `json:"nonce_verified"`
	HTTPStatus              int                `json:"http_status"`
	ErrorCode               string             `json:"error_code,omitempty"`
	ErrorType               string             `json:"error_type,omitempty"`
	Cancellation            NativeCancellation `json:"cancellation"`
	StartedAt               time.Time          `json:"started_at"`
	CompletedAt             time.Time          `json:"completed_at"`
	requestID               string
	completionID            string
	sessionID               string
}

type NativeUsage struct {
	InputTokens  *int64 `json:"input_tokens,omitempty"`
	OutputTokens *int64 `json:"output_tokens,omitempty"`
	TotalTokens  *int64 `json:"total_tokens,omitempty"`
}
type NativeCancellation struct {
	ProviderAcknowledged bool `json:"provider_acknowledged"`
	LocalRequestCanceled bool `json:"local_request_canceled"`
	LocalBodyClosed      bool `json:"local_body_closed"`
}

// NativeHTTPClient exists so all protocol behavior is testable without a
// credential or network. http.Client satisfies it.
type NativeHTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// DefaultNativeHTTPClient refuses redirects so an authorization header can
// never be replayed to a different URL by redirect handling.
func DefaultNativeHTTPClient() *http.Client {
	return &http.Client{
		Timeout: DefaultProbeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func RunNative(ctx context.Context, client NativeHTTPClient, input NativeRequest) (r NativeReceipt, returnErr error) {
	r = NativeReceipt{StartedAt: time.Now().UTC(), ToolCallsSHA256: hashNative(nil), OutputSHA256: hashNative(nil)}
	if ctx == nil || client == nil {
		return finishNative(r, errors.New("Z.ai native transport requires context and HTTP client"))
	}
	if err := validateNativeRequest(input); err != nil {
		return finishNative(r, err)
	}
	body, err := json.Marshal(nativeRequestPayload{
		Model: input.Model, Stream: true, RequestID: input.ExpectedRequestID,
		Messages: []map[string]string{{"role": "user", "content": input.Prompt}},
	})
	if err != nil {
		return finishNative(r, err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, input.Endpoint, bytes.NewReader(body))
	if err != nil {
		return finishNative(r, err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+input.NativeAPIKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	slog.Info("zai native request", "model", input.Model, "endpoint_host", endpointHost(input.Endpoint), "prompt_sha256", hashNative([]byte(input.Prompt)))
	resp, err := client.Do(httpReq)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			r.Cancellation.LocalRequestCanceled = true
		}
		return finishNative(r, err)
	}
	defer func() {
		if err := resp.Body.Close(); err == nil {
			r.Cancellation.LocalBodyClosed = true
		}
	}()
	r.HTTPStatus = resp.StatusCode
	if resp.Request == nil || resp.Request.URL == nil || resp.Request.URL.String() != NativeChatCompletionsEndpoint {
		return finishNative(r, errors.New("Z.ai native transport response came from an unexpected endpoint"))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		parseNativeError(resp.Body, &r)
		return finishNative(r, fmt.Errorf("Z.ai native HTTP status %d", resp.StatusCode))
	}
	if err := consumeNativeSSE(ctx, resp.Body, input, &r); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			r.Cancellation.LocalRequestCanceled = true
		}
		return finishNative(r, err)
	}
	if input.ExpectedNonce != "" && !r.NonceVerified {
		return finishNative(r, errors.New("Z.ai native completion did not return the required exact nonce"))
	}
	r.CompletedAt = time.Now().UTC()
	return r, nil
}

func validateNativeRequest(in NativeRequest) error {
	if !in.ExplicitOptIn {
		return errors.New("Z.ai native transport requires explicit opt-in")
	}
	if strings.TrimSpace(in.NativeAPIKey) == "" || in.NativeAPIKey != strings.TrimSpace(in.NativeAPIKey) || hasControl(in.NativeAPIKey) || len(in.NativeAPIKey) > 1<<16 {
		return errors.New("Z.ai native transport requires separately authorized native API credentials")
	}
	if strings.TrimSpace(in.Model) == "" || in.Model != strings.TrimSpace(in.Model) || len(in.Model) > 256 || strings.TrimSpace(in.Prompt) == "" || len(in.Prompt) > 1<<20 || hasControl(in.Model) {
		return errors.New("Z.ai native transport requires model and prompt")
	}
	if strings.TrimSpace(in.ExpectedNonce) == "" || in.ExpectedNonce != strings.TrimSpace(in.ExpectedNonce) || hasControl(in.ExpectedNonce) || len(in.ExpectedNonce) > 256 || !strings.Contains(in.Prompt, in.ExpectedNonce) {
		return errors.New("Z.ai native transport requires a prompt-bound acknowledgement nonce")
	}
	if !validNativeClientRequestID(in.ExpectedRequestID) {
		return errors.New("Z.ai native transport requires a caller-provided 6-64 character request identifier")
	}
	if in.AllowTools {
		return errors.New("Z.ai native tool execution is not enabled by this adapter")
	}
	u, err := url.Parse(in.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host != "api.z.ai" || u.User != nil || u.Path != "/api/paas/v4/chat/completions" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return errors.New("Z.ai native transport requires the exact documented chat completions endpoint")
	}
	return nil
}

func consumeNativeSSE(ctx context.Context, body io.Reader, input NativeRequest, r *NativeReceipt) error {
	s := bufio.NewScanner(body)
	s.Buffer(make([]byte, 4096), maxProbeOutput)
	output := sha256.New()
	tools := sha256.New()
	matcher := nativeNonceMatcher{needle: input.ExpectedNonce}
	// A successful HTTP response is not a successful inference. Require the
	// bounded, structured evidence emitted by the stream itself: a provider
	// model that exactly matches the requested literal, a non-empty completion
	// reason, and the terminal SSE marker. Do not infer any model aliases.
	evidence := nativeCompletionEvidence{}
	for s.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := s.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			evidence.terminalSeen = true
			break
		}
		var event nativeEvent
		if json.Unmarshal([]byte(data), &event) != nil {
			return errors.New("Z.ai native SSE emitted invalid JSON")
		}
		if event.RequestID != "" {
			if !validNativeIdentifier(event.RequestID) || event.RequestID != input.ExpectedRequestID || r.requestID != "" && r.requestID != event.RequestID {
				return errors.New("Z.ai native SSE emitted a conflicting request identifier")
			}
			r.requestID = event.RequestID
			r.ProviderRequestIDSHA256 = hashNative([]byte(event.RequestID))
			evidence.exactRequestIDSeen = true
		}
		if event.ID != "" {
			if !validNativeIdentifier(event.ID) || r.completionID != "" && r.completionID != event.ID {
				return errors.New("Z.ai native SSE emitted a conflicting completion identifier")
			}
			r.completionID = event.ID
			r.CompletionIDSHA256 = hashNative([]byte(event.ID))
		}
		if event.SessionID != "" {
			if !validNativeIdentifier(event.SessionID) || r.sessionID != "" && r.sessionID != event.SessionID {
				return errors.New("Z.ai native SSE emitted a conflicting session identifier")
			}
			r.sessionID = event.SessionID
			r.ProviderSessionIDSHA256 = hashNative([]byte(event.SessionID))
		}
		if event.Model != "" {
			if event.Model != input.Model {
				return errors.New("Z.ai native completion model does not exactly match requested model")
			}
			r.Model = event.Model
			evidence.exactModelSeen = true
		}
		if event.Error != nil {
			if !assignNativeError(r, event.Error) {
				return errors.New("Z.ai native provider returned an invalid structured error identifier")
			}
			return errors.New("Z.ai native provider returned structured error")
		}
		if len(event.Choices) > 1 {
			return errors.New("Z.ai native SSE emitted ambiguous multiple choices")
		}
		for _, choice := range event.Choices {
			if strings.TrimSpace(choice.FinishReason) != "" {
				if evidence.finishReasonSeen && r.FinishReason != choice.FinishReason {
					return errors.New("Z.ai native SSE emitted conflicting finish reasons")
				}
				r.FinishReason = choice.FinishReason
				evidence.finishReasonSeen = true
			}
			text := choice.Delta.Content
			if text != "" {
				_, _ = io.WriteString(output, text)
				matcher.write(text)
			}
			for _, call := range choice.Delta.ToolCalls {
				_, _ = io.WriteString(tools, call.Function.Name+"\x00"+hashNative([]byte(call.Function.Arguments))+"\x00")
				r.ToolCallCount++
			}
			if len(choice.Delta.ToolCalls) != 0 {
				r.ToolCallsSHA256 = hex.EncodeToString(tools.Sum(nil))
				return errors.New("Z.ai native no-tool request emitted an unsolicited tool call")
			}
		}
		if event.Usage != nil {
			if event.Usage.hasNegativeCounter() {
				return errors.New("Z.ai native SSE emitted negative usage")
			}
			r.Usage = event.Usage.canonical()
		}
	}
	if err := s.Err(); err != nil {
		return err
	}
	if !evidence.terminalSeen {
		return errors.New("Z.ai native SSE omitted terminal [DONE] marker")
	}
	if !evidence.exactModelSeen || r.Model != input.Model {
		return errors.New("Z.ai native completion omitted exact requested model")
	}
	if !evidence.finishReasonSeen || strings.TrimSpace(r.FinishReason) == "" {
		return errors.New("Z.ai native completion omitted finish reason")
	}
	if !evidence.exactRequestIDSeen || r.requestID != input.ExpectedRequestID {
		return errors.New("Z.ai native completion omitted the exact caller request identifier")
	}
	matcher.finalize()
	r.NonceVerified = matcher.verified
	r.OutputSHA256 = hex.EncodeToString(output.Sum(nil))
	r.ToolCallsSHA256 = hex.EncodeToString(tools.Sum(nil))
	return nil
}

// nativeCompletionEvidence is deliberately local to one bounded SSE body.
// It is not an assertion based on HTTP status, request headers, or a locally
// closed response body; those do not attest to provider-side completion.
type nativeCompletionEvidence struct {
	terminalSeen       bool
	exactModelSeen     bool
	exactRequestIDSeen bool
	finishReasonSeen   bool
}

type nativeRequestPayload struct {
	Model     string              `json:"model"`
	Stream    bool                `json:"stream"`
	RequestID string              `json:"request_id"`
	Messages  []map[string]string `json:"messages"`
}

type nativeEvent struct {
	ID        string         `json:"id"`
	RequestID string         `json:"request_id"`
	Model     string         `json:"model"`
	SessionID string         `json:"session_id"`
	Choices   []nativeChoice `json:"choices"`
	Usage     *nativeUsage   `json:"usage"`
	Error     *nativeError   `json:"error"`
}
type nativeChoice struct {
	Delta        nativeDelta `json:"delta"`
	FinishReason string      `json:"finish_reason"`
}
type nativeDelta struct {
	Content   string           `json:"content"`
	ToolCalls []nativeToolCall `json:"tool_calls"`
}
type nativeToolCall struct {
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}
type nativeUsage struct {
	PromptTokens     *int64 `json:"prompt_tokens"`
	CompletionTokens *int64 `json:"completion_tokens"`
	TotalTokens      *int64 `json:"total_tokens"`
}

func (u nativeUsage) hasNegativeCounter() bool {
	for _, value := range []*int64{u.PromptTokens, u.CompletionTokens, u.TotalTokens} {
		if value != nil && *value < 0 {
			return true
		}
	}
	return false
}

func (u nativeUsage) canonical() NativeUsage {
	return NativeUsage{InputTokens: u.PromptTokens, OutputTokens: u.CompletionTokens, TotalTokens: u.TotalTokens}
}

type nativeError struct {
	Code string `json:"code"`
	Type string `json:"type"`
}

func parseNativeError(body io.Reader, r *NativeReceipt) {
	data, _ := io.ReadAll(io.LimitReader(body, 64<<10))
	var event nativeEvent
	if json.Unmarshal(data, &event) == nil && event.Error != nil {
		assignNativeError(r, event.Error)
	}
}

func assignNativeError(r *NativeReceipt, value *nativeError) bool {
	if r == nil || value == nil || !validNativeErrorIdentifier(value.Code) || value.Type != "" && !validNativeErrorIdentifier(value.Type) {
		return false
	}
	r.ErrorCode, r.ErrorType = value.Code, value.Type
	return true
}

func validNativeErrorIdentifier(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '-' || char == '.' || char == ':' {
			continue
		}
		return false
	}
	return true
}
func finishNative(r NativeReceipt, err error) (NativeReceipt, error) {
	if r.CompletedAt.IsZero() {
		r.CompletedAt = time.Now().UTC()
	}
	return r, err
}
func endpointHost(value string) string { u, _ := url.Parse(value); return u.Hostname() }
func hashNative(v []byte) string       { sum := sha256.Sum256(v); return hex.EncodeToString(sum[:]) }

func validNativeIdentifier(value string) bool {
	return strings.TrimSpace(value) != "" && value == strings.TrimSpace(value) && len(value) <= 4096 && !hasControl(value)
}

// validNativeClientRequestID follows Z.ai's documented request_id size
// contract. The identifier is an application correlation value, not a secret;
// callers must retain only its digest in durable evidence.
func validNativeClientRequestID(value string) bool {
	return len(value) >= 6 && len(value) <= 64 && validNativeIdentifier(value)
}

type nativeNonceMatcher struct {
	needle   string
	line     string
	verified bool
}

func (m *nativeNonceMatcher) write(value string) {
	if m.needle == "" || m.verified {
		return
	}
	for _, part := range strings.SplitAfter(value, "\n") {
		m.line += part
		if strings.HasSuffix(part, "\n") {
			if strings.TrimSpace(m.line) == m.needle {
				m.verified = true
			}
			m.line = ""
		}
	}
}
func (m *nativeNonceMatcher) finalize() {
	if m.needle != "" && strings.TrimSpace(m.line) == m.needle {
		m.verified = true
	}
}
