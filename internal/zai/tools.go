package zai

// This file implements the structured native Z.ai tool loop. The model only
// proposes function calls; a controller-owned executor validates and performs
// them. Raw arguments, results, prompts, and credentials are never retained in
// the returned receipt.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	defaultNativeToolRounds = 6
	maxNativeToolRounds     = 16
	maxNativeToolResult     = 64 << 10
	maxNativeToolArguments  = 64 << 10
)

// NativeFunctionDefinition is the exact JSON-schema contract exposed to the
// provider. The controller remains responsible for enforcing a stricter local
// policy before executing a proposed call.
type NativeFunctionDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

// NativeToolCall is untrusted provider output. Arguments are normalized into a
// JSON object but remain subject to executor-side schema and policy checks.
type NativeToolCall struct {
	ID        string
	Name      string
	Arguments json.RawMessage
}

// NativeToolResult is returned by the controller-owned executor. Content is
// sent to the provider for the next turn but is never stored in the receipt.
// EvidenceSHA256 binds the result to an independently retained broker receipt.
type NativeToolResult struct {
	Content        string
	EvidenceSHA256 string
}

// NativeToolExecutor is deliberately caller-owned. The transport never runs a
// shell, reads a file, or mutates a worktree by itself.
type NativeToolExecutor interface {
	ExecuteNativeTool(context.Context, NativeToolCall) (NativeToolResult, error)
}

type NativeToolRequest struct {
	NativeRequest
	Tools     []NativeFunctionDefinition
	Executor  NativeToolExecutor
	MaxRounds int
}

type NativeToolExecutionReceipt struct {
	Round             int    `json:"round"`
	CallIDSHA256      string `json:"call_id_sha256"`
	Name              string `json:"name"`
	ArgumentsSHA256   string `json:"arguments_sha256"`
	ResultSHA256      string `json:"result_sha256,omitempty"`
	BrokerEvidenceSHA string `json:"broker_evidence_sha256,omitempty"`
	Succeeded         bool   `json:"succeeded"`
	ErrorSHA256       string `json:"error_sha256,omitempty"`
}

type NativeToolReceipt struct {
	NativeReceipt
	Rounds                  int                          `json:"rounds"`
	RoundRequestIDSHA256    []string                     `json:"round_request_id_sha256"`
	ToolExecutions          []NativeToolExecutionReceipt `json:"tool_executions"`
	ControllerOwnedExecutor bool                         `json:"controller_owned_executor"`
}

type nativeToolWireDefinition struct {
	Type     string                   `json:"type"`
	Function NativeFunctionDefinition `json:"function"`
}

type nativeToolMessage struct {
	Role       string               `json:"role"`
	Content    string               `json:"content,omitempty"`
	ToolCallID string               `json:"tool_call_id,omitempty"`
	ToolCalls  []nativeWireToolCall `json:"tool_calls,omitempty"`
}

type nativeToolPayload struct {
	Model      string                     `json:"model"`
	Stream     bool                       `json:"stream"`
	RequestID  string                     `json:"request_id"`
	Messages   []nativeToolMessage        `json:"messages"`
	Tools      []nativeToolWireDefinition `json:"tools"`
	ToolChoice string                     `json:"tool_choice"`
}

type nativeSyncResponse struct {
	ID        string             `json:"id"`
	RequestID string             `json:"request_id"`
	Model     string             `json:"model"`
	Choices   []nativeSyncChoice `json:"choices"`
	Usage     *nativeUsage       `json:"usage"`
	Error     *nativeError       `json:"error"`
}

type nativeSyncChoice struct {
	Message      nativeSyncMessage `json:"message"`
	FinishReason string            `json:"finish_reason"`
}

type nativeSyncMessage struct {
	Role      string               `json:"role"`
	Content   string               `json:"content"`
	ToolCalls []nativeWireToolCall `json:"tool_calls"`
}

type nativeWireToolCall struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Function nativeWireToolFunction `json:"function"`
}

type nativeWireToolFunction struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// RunNativeTools executes a bounded, synchronous provider/tool loop. It uses a
// unique request_id for every provider turn, requires an exact model echo, and
// accepts completion only when the final response acknowledges the supplied
// nonce. Cancellation remains local-client-only because Z.ai has no documented
// chat cancellation acknowledgement.
func RunNativeTools(ctx context.Context, client NativeHTTPClient, input NativeToolRequest) (r NativeToolReceipt, returnErr error) {
	r.NativeReceipt = NativeReceipt{StartedAt: time.Now().UTC(), ToolCallsSHA256: hashNative(nil), OutputSHA256: hashNative(nil)}
	r.RoundRequestIDSHA256 = []string{}
	r.ToolExecutions = []NativeToolExecutionReceipt{}
	if ctx == nil || client == nil {
		return finishNativeTools(r, errors.New("Z.ai native tool transport requires context and HTTP client"))
	}
	if err := validateNativeToolRequest(input); err != nil {
		return finishNativeTools(r, err)
	}
	r.ControllerOwnedExecutor = true
	rounds := input.MaxRounds
	if rounds == 0 {
		rounds = defaultNativeToolRounds
	}
	wireTools := make([]nativeToolWireDefinition, len(input.Tools))
	allowed := make(map[string]struct{}, len(input.Tools))
	for i, definition := range input.Tools {
		wireTools[i] = nativeToolWireDefinition{Type: "function", Function: definition}
		allowed[definition.Name] = struct{}{}
	}
	messages := []nativeToolMessage{{Role: "user", Content: input.Prompt}}
	toolDigest := sha256.New()
	outputDigest := sha256.New()
	for round := 1; round <= rounds; round++ {
		if err := ctx.Err(); err != nil {
			r.Cancellation.LocalRequestCanceled = true
			return finishNativeTools(r, err)
		}
		requestID := input.ExpectedRequestID
		if round > 1 {
			requestID = nativeToolRoundRequestID(input.ExpectedRequestID, round)
		}
		r.RoundRequestIDSHA256 = append(r.RoundRequestIDSHA256, hashNative([]byte(requestID)))
		response, status, bodyClosed, err := runNativeToolRound(ctx, client, input, requestID, messages, wireTools)
		r.Cancellation.LocalBodyClosed = r.Cancellation.LocalBodyClosed || bodyClosed
		r.Rounds = round
		r.HTTPStatus = status
		if err != nil {
			if response.Error != nil {
				_ = assignNativeError(&r.NativeReceipt, response.Error)
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				r.Cancellation.LocalRequestCanceled = true
			}
			return finishNativeTools(r, err)
		}
		if response.Error != nil {
			if !assignNativeError(&r.NativeReceipt, response.Error) {
				return finishNativeTools(r, errors.New("Z.ai native provider returned an invalid structured error identifier"))
			}
			return finishNativeTools(r, errors.New("Z.ai native provider returned structured error"))
		}
		if response.RequestID != requestID || !validNativeClientRequestID(response.RequestID) {
			return finishNativeTools(r, errors.New("Z.ai native tool response omitted the exact caller request identifier"))
		}
		r.requestID = response.RequestID
		r.ProviderRequestIDSHA256 = hashNative([]byte(response.RequestID))
		if response.Model != input.Model {
			return finishNativeTools(r, errors.New("Z.ai native tool response model does not exactly match requested model"))
		}
		r.Model = response.Model
		if response.ID == "" || !validNativeIdentifier(response.ID) {
			return finishNativeTools(r, errors.New("Z.ai native tool response omitted a valid completion identifier"))
		}
		r.completionID = response.ID
		r.CompletionIDSHA256 = hashNative([]byte(response.ID))
		if len(response.Choices) != 1 {
			return finishNativeTools(r, errors.New("Z.ai native tool response must contain exactly one choice"))
		}
		choice := response.Choices[0]
		if strings.TrimSpace(choice.FinishReason) == "" {
			return finishNativeTools(r, errors.New("Z.ai native tool response omitted finish reason"))
		}
		r.FinishReason = choice.FinishReason
		if response.Usage != nil {
			if response.Usage.hasNegativeCounter() {
				return finishNativeTools(r, errors.New("Z.ai native tool response emitted negative usage"))
			}
			r.Usage = addNativeUsage(r.Usage, response.Usage.canonical())
		}
		if len(choice.Message.ToolCalls) == 0 {
			if choice.FinishReason == "tool_calls" {
				return finishNativeTools(r, errors.New("Z.ai native tool response claimed tool_calls without calls"))
			}
			_, _ = io.WriteString(outputDigest, choice.Message.Content)
			matcher := nativeNonceMatcher{needle: input.ExpectedNonce}
			matcher.write(choice.Message.Content)
			matcher.finalize()
			if !matcher.verified {
				return finishNativeTools(r, errors.New("Z.ai native tool completion did not return the required exact nonce"))
			}
			r.NonceVerified = true
			r.OutputSHA256 = hex.EncodeToString(outputDigest.Sum(nil))
			r.ToolCallsSHA256 = hex.EncodeToString(toolDigest.Sum(nil))
			r.CompletedAt = time.Now().UTC()
			return r, nil
		}
		if choice.FinishReason != "tool_calls" {
			return finishNativeTools(r, errors.New("Z.ai native tool response emitted calls without tool_calls finish reason"))
		}
		assistant := nativeToolMessage{Role: "assistant", Content: choice.Message.Content, ToolCalls: choice.Message.ToolCalls}
		messages = append(messages, assistant)
		seenCalls := make(map[string]struct{}, len(choice.Message.ToolCalls))
		for _, wireCall := range choice.Message.ToolCalls {
			call, err := normalizeNativeToolCall(wireCall, allowed)
			if err != nil {
				return finishNativeTools(r, err)
			}
			if _, duplicate := seenCalls[call.ID]; duplicate {
				return finishNativeTools(r, errors.New("Z.ai native tool response reused a tool call identifier"))
			}
			seenCalls[call.ID] = struct{}{}
			argumentHash := hashNative(call.Arguments)
			_, _ = io.WriteString(toolDigest, call.ID+"\x00"+call.Name+"\x00"+argumentHash+"\x00")
			execution := NativeToolExecutionReceipt{Round: round, CallIDSHA256: hashNative([]byte(call.ID)), Name: call.Name, ArgumentsSHA256: argumentHash}
			result, executeErr := input.Executor.ExecuteNativeTool(ctx, call)
			if executeErr != nil {
				execution.ErrorSHA256 = hashNative([]byte(executeErr.Error()))
				r.ToolExecutions = append(r.ToolExecutions, execution)
				return finishNativeTools(r, errors.New("controller-owned native tool execution failed"))
			}
			if err := validateNativeToolResult(result); err != nil {
				execution.ErrorSHA256 = hashNative([]byte(err.Error()))
				r.ToolExecutions = append(r.ToolExecutions, execution)
				return finishNativeTools(r, err)
			}
			execution.Succeeded = true
			execution.ResultSHA256 = hashNative([]byte(result.Content))
			execution.BrokerEvidenceSHA = result.EvidenceSHA256
			r.ToolExecutions = append(r.ToolExecutions, execution)
			messages = append(messages, nativeToolMessage{Role: "tool", ToolCallID: call.ID, Content: result.Content})
		}
		r.ToolCallCount += len(choice.Message.ToolCalls)
	}
	return finishNativeTools(r, errors.New("Z.ai native tool loop exceeded its bounded round limit"))
}

func validateNativeToolRequest(input NativeToolRequest) error {
	if !input.AllowTools {
		return errors.New("Z.ai native tool transport requires explicit tool opt-in")
	}
	base := input.NativeRequest
	base.AllowTools = false
	if err := validateNativeRequest(base); err != nil {
		return err
	}
	if input.Executor == nil || len(input.Tools) == 0 || len(input.Tools) > 128 {
		return errors.New("Z.ai native tool transport requires an executor and 1-128 function definitions")
	}
	if input.MaxRounds < 0 || input.MaxRounds > maxNativeToolRounds {
		return fmt.Errorf("Z.ai native tool rounds must be between 1 and %d", maxNativeToolRounds)
	}
	seen := make(map[string]struct{}, len(input.Tools))
	for _, definition := range input.Tools {
		if !validNativeToolName(definition.Name) || strings.TrimSpace(definition.Description) == "" || definition.Description != strings.TrimSpace(definition.Description) || len(definition.Description) > 4096 || hasControl(definition.Description) {
			return errors.New("Z.ai native tool definition has invalid name or description")
		}
		if _, duplicate := seen[definition.Name]; duplicate {
			return errors.New("Z.ai native tool definitions must have unique names")
		}
		seen[definition.Name] = struct{}{}
		var schema map[string]json.RawMessage
		if len(definition.Parameters) == 0 || len(definition.Parameters) > maxNativeToolArguments || json.Unmarshal(definition.Parameters, &schema) != nil || string(schema["type"]) != `"object"` {
			return errors.New("Z.ai native tool parameters must be a bounded JSON Schema object")
		}
	}
	return nil
}

func runNativeToolRound(ctx context.Context, client NativeHTTPClient, input NativeToolRequest, requestID string, messages []nativeToolMessage, tools []nativeToolWireDefinition) (nativeSyncResponse, int, bool, error) {
	payload := nativeToolPayload{Model: input.Model, Stream: false, RequestID: requestID, Messages: messages, Tools: tools, ToolChoice: "auto"}
	body, err := json.Marshal(payload)
	if err != nil {
		return nativeSyncResponse{}, 0, false, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, input.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nativeSyncResponse{}, 0, false, err
	}
	request.Header.Set("Authorization", "Bearer "+input.NativeAPIKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nativeSyncResponse{}, 0, false, err
	}
	closeBody := func() bool { return response.Body.Close() == nil }
	if response.Request == nil || response.Request.URL == nil || response.Request.URL.String() != NativeChatCompletionsEndpoint {
		return nativeSyncResponse{}, response.StatusCode, closeBody(), errors.New("Z.ai native tool response came from an unexpected endpoint")
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maxProbeOutput+1))
	if readErr != nil {
		return nativeSyncResponse{}, response.StatusCode, closeBody(), readErr
	}
	if len(data) > maxProbeOutput {
		return nativeSyncResponse{}, response.StatusCode, closeBody(), errors.New("Z.ai native tool response exceeded the bounded output limit")
	}
	var decoded nativeSyncResponse
	if json.Unmarshal(data, &decoded) != nil {
		return nativeSyncResponse{}, response.StatusCode, closeBody(), errors.New("Z.ai native tool response emitted invalid JSON")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return decoded, response.StatusCode, closeBody(), fmt.Errorf("Z.ai native HTTP status %d", response.StatusCode)
	}
	return decoded, response.StatusCode, closeBody(), nil
}

func normalizeNativeToolCall(value nativeWireToolCall, allowed map[string]struct{}) (NativeToolCall, error) {
	if value.Type != "function" || !validNativeIdentifier(value.ID) || len(value.ID) > 256 || !validNativeToolName(value.Function.Name) {
		return NativeToolCall{}, errors.New("Z.ai native tool response emitted an invalid function call")
	}
	if _, ok := allowed[value.Function.Name]; !ok {
		return NativeToolCall{}, errors.New("Z.ai native tool response requested an unadvertised function")
	}
	arguments := bytes.TrimSpace(value.Function.Arguments)
	if len(arguments) == 0 || len(arguments) > maxNativeToolArguments {
		return NativeToolCall{}, errors.New("Z.ai native tool response emitted missing or oversized arguments")
	}
	if arguments[0] == '"' {
		var encoded string
		if json.Unmarshal(arguments, &encoded) != nil {
			return NativeToolCall{}, errors.New("Z.ai native tool response emitted invalid encoded arguments")
		}
		arguments = []byte(encoded)
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(arguments, &object) != nil || object == nil {
		return NativeToolCall{}, errors.New("Z.ai native tool arguments must be a JSON object")
	}
	canonical, err := json.Marshal(object)
	if err != nil {
		return NativeToolCall{}, errors.New("Z.ai native tool arguments could not be canonicalized")
	}
	return NativeToolCall{ID: value.ID, Name: value.Function.Name, Arguments: canonical}, nil
}

func validateNativeToolResult(result NativeToolResult) error {
	if result.Content == "" || len(result.Content) > maxNativeToolResult || !utf8.ValidString(result.Content) {
		return errors.New("controller-owned native tool result must be bounded UTF-8 content")
	}
	if len(result.EvidenceSHA256) != sha256.Size*2 || strings.ToLower(result.EvidenceSHA256) != result.EvidenceSHA256 {
		return errors.New("controller-owned native tool result requires a broker evidence SHA-256")
	}
	if _, err := hex.DecodeString(result.EvidenceSHA256); err != nil {
		return errors.New("controller-owned native tool result requires a broker evidence SHA-256")
	}
	return nil
}

func nativeToolRoundRequestID(base string, round int) string {
	return "ntm-" + hashNative([]byte(fmt.Sprintf("ntm.zai-native.tool-round.v1\x00%s\x00%d", base, round)))[:60]
}

func validNativeToolName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func addNativeUsage(left, right NativeUsage) NativeUsage {
	return NativeUsage{
		InputTokens:       addNativeCounter(left.InputTokens, right.InputTokens),
		OutputTokens:      addNativeCounter(left.OutputTokens, right.OutputTokens),
		TotalTokens:       addNativeCounter(left.TotalTokens, right.TotalTokens),
		CachedInputTokens: addNativeCounter(left.CachedInputTokens, right.CachedInputTokens),
	}
}

func addNativeCounter(left, right *int64) *int64 {
	if left == nil && right == nil {
		return nil
	}
	var total int64
	if left != nil {
		total += *left
	}
	if right != nil {
		total += *right
	}
	return &total
}

func finishNativeTools(receipt NativeToolReceipt, err error) (NativeToolReceipt, error) {
	if receipt.CompletedAt.IsZero() {
		receipt.CompletedAt = time.Now().UTC()
	}
	return receipt, err
}
