// Package grok contains the provider-native Grok transports. It deliberately
// does not depend on tmux: ACP sessions have their own authoritative identity
// and completion receipt.
package grok

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
	"unicode"

	agentpkg "github.com/Dicklesworthstone/ntm/internal/agent"
)

const (
	// MaxProtocolLineBytes bounds a single JSON-RPC message. ACP is line
	// delimited; accepting an unbounded line would let a faulty child exhaust
	// the NTM process.
	MaxProtocolLineBytes = 1 << 20
	// MaxStderrCaptureBytes bounds the diagnostic material retained from the
	// provider. The stream is still drained beyond this cap so the child cannot
	// block on a full stderr pipe.
	MaxStderrCaptureBytes = 64 << 10
	// DefaultPostResponseQuietWindow captures late session/update events that
	// xAI may emit just after a session/prompt response. It is bounded and
	// remains subject to the caller's context.
	DefaultPostResponseQuietWindow = 100 * time.Millisecond
	maxPostResponseQuietWindow     = 5 * time.Second
)

// ErrorCode is the stable, provider-native failure classification. It is
// intentionally separate from robot error codes; the robot adapter can map it
// without parsing error text.
type ErrorCode string

const (
	ErrInvalidRequest    ErrorCode = "GROK_ACP_INVALID_REQUEST"
	ErrDependencyMissing ErrorCode = "DEPENDENCY_MISSING"
	ErrProtocol          ErrorCode = "GROK_ACP_PROTOCOL_ERROR"
	// ErrCachedAuthUnavailable means the local CLI did not advertise its
	// cached-login authentication method. Automated ACP intentionally never
	// falls back to an exported API key, so an operator must establish a cached
	// CLI login in the local account before retrying.
	ErrCachedAuthUnavailable ErrorCode = "GROK_ACP_CACHED_AUTH_UNAVAILABLE"
	ErrAuthRequired          ErrorCode = "GROK_ACP_AUTH_REQUIRED"
	ErrAuthFailed            ErrorCode = "GROK_ACP_AUTH_FAILED"
	ErrUnsupported           ErrorCode = "GROK_ACP_UNSUPPORTED"
	ErrTimeout               ErrorCode = "TIMEOUT"
	ErrOutcomeUnknown        ErrorCode = "DISPATCH_UNKNOWN"
	ErrProvider              ErrorCode = "GROK_ACP_PROVIDER_ERROR"
	ErrProcessFailed         ErrorCode = "GROK_ACP_PROCESS_FAILED"
	// ErrAcknowledgementUnconfirmed means ACP completed but did not emit the
	// nonce-bound acknowledgement required by the orchestrator's contract.
	ErrAcknowledgementUnconfirmed ErrorCode = "GROK_ACP_ACK_UNCONFIRMED"
	ErrIdentityMismatch           ErrorCode = "GROK_ACP_IDENTITY_MISMATCH"
	// ErrCancelled is returned only after this ACP agent acknowledged the
	// cancellation notification by completing the original session/prompt call
	// with stopReason=cancelled. It never claims that xAI stopped any upstream
	// cloud inference that may already have been accepted.
	ErrCancelled ErrorCode = "GROK_ACP_CANCELLED"
	// ErrCancellationUnconfirmed means NTM requested cancellation, but the
	// original prompt response did not provide the exact ACP acknowledgement
	// required to bind that request to the active session and operation.
	ErrCancellationUnconfirmed ErrorCode = "GROK_ACP_CANCEL_ACK_UNCONFIRMED"
)

// Error adds a machine-readable classification without exposing protocol
// packets, prompts, credentials, or provider output.
type Error struct {
	Code ErrorCode
	Err  error
}

func (e *Error) Error() string {
	if e == nil || e.Err == nil {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %v", e.Code, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// StartSpec is the narrow process boundary. Credentials are intentionally not
// represented here: automated ACP uses only the CLI's existing cached login,
// and ACP authenticate carries only the cached_token method identifier.
type StartSpec struct {
	Binary string
	Args   []string
	CWD    string
}

// Process is the testable subset of an ACP child process.
type Process interface {
	Stdin() io.WriteCloser
	Stdout() io.Reader
	Stderr() io.Reader
	Wait() error
	Kill() error
	PID() int32
}

// Runner starts the provider process. Tests supply a transcript-backed fake;
// OSRunner is the production implementation, but this package never starts a
// process by itself until an adapter calls Run.
type Runner interface {
	Start(context.Context, StartSpec) (Process, error)
}

// OSRunner starts the official local Grok CLI.
type OSRunner struct{}

func (OSRunner) Start(_ context.Context, spec StartSpec) (Process, error) {
	// Run owns cancellation after session/prompt becomes replay-unsafe. Do not
	// bind this child to ctx: CommandContext would kill it before Run can send
	// the ACP session/cancel notification and wait for the original response.
	cmd := exec.Command(spec.Binary, spec.Args...)
	cmd.Dir = spec.CWD
	cmd.Env = minimalGrokEnvironment(os.Environ())
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return osProcess{cmd: cmd, stdin: stdin, stdout: stdout, stderr: stderr}, nil
}

type osProcess struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
}

func (p osProcess) Stdin() io.WriteCloser { return p.stdin }
func (p osProcess) Stdout() io.Reader     { return p.stdout }
func (p osProcess) Stderr() io.Reader     { return p.stderr }
func (p osProcess) Wait() error           { return p.cmd.Wait() }
func (p osProcess) PID() int32 {
	if p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return int32(p.cmd.Process.Pid)
}
func (p osProcess) Kill() error {
	if p.cmd.Process == nil {
		return nil
	}
	return p.cmd.Process.Kill()
}

// Request is one direct, single-prompt ACP execution.
type Request struct {
	Prompt string
	CWD    string
	Binary string
	// Model is passed as an exact --model value before the ACP subcommand. It
	// is not echoed in Result unless the provider's completion metadata confirms
	// the effective model.
	Model string
	// ExpectedNonce is a non-secret acknowledgement token supplied by an
	// orchestrator. It is never retained in Result; only the verified boolean
	// is exposed after a bounded streaming match over assistant chunks.
	ExpectedNonce string
	// OperationID is a caller-owned durable identifier when one exists. It is
	// hashed in cancellation evidence; NTM never emits the raw value here.
	// Empty is allowed for direct library callers, whose cancellation receipt is
	// still bound to the generated ACP session and original prompt request ID.
	OperationID string
	// PostResponseQuietWindow bounds the drain of updates that are emitted
	// after session/prompt completes. Zero selects the safe default.
	PostResponseQuietWindow time.Duration
	// CancellationGracePeriod bounds how long NTM waits for the original
	// session/prompt response after writing the ACP session/cancel
	// notification. Zero selects the safe default. It is not a cloud-inference
	// deadline; timeout leaves the accepted operation outcome unknown.
	CancellationGracePeriod time.Duration
	// AutomationPolicyArgs are the named, per-invocation least-privilege
	// --allow/--deny flags placed before `agent stdio`. Raw approval bypasses
	// such as --always-approve are rejected rather than silently accepted.
	AutomationPolicyArgs []string
}

// defaultReadOnlyAutomationPolicyArgs returns a fresh copy of the compiled
// observe policy. Keeping one policy authority avoids a weaker adapter-local
// default silently omitting the credential-path denials in the named policy.
func defaultReadOnlyAutomationPolicyArgs() []string {
	return agentpkg.GrokAutomationACPPolicyArgs(agentpkg.DefaultGrokAutomationPolicyName)
}

// StderrDigest is safe diagnostic evidence. It contains no stderr body.
type StderrDigest struct {
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
	Truncated bool   `json:"truncated"`
}

// Result is a redaction-safe provider receipt. Assistant output is never
// retained, only counted and hashed.
type Result struct {
	Success                 bool      `json:"success"`
	State                   string    `json:"state"`
	FailureCode             ErrorCode `json:"failure_code,omitempty"`
	ProviderSessionID       string    `json:"provider_session_id,omitempty"`
	StopReason              string    `json:"stop_reason,omitempty"`
	CompletionConfirmed     bool      `json:"completion_confirmed"`
	AcknowledgementVerified bool      `json:"acknowledgement_verified"`
	AssistantTextChunks     int       `json:"assistant_text_chunks"`
	AssistantTextBytes      int64     `json:"assistant_text_bytes"`
	OutputSHA256            string    `json:"output_sha256,omitempty"`
	// ToolEventCount and ToolEventsSHA256 cover only the ACP tool_call and
	// tool_call_update session-update variants. They never include raw tool
	// arguments, results, or any other update payload.
	ToolEventCount   int    `json:"tool_event_count"`
	ToolEventsSHA256 string `json:"tool_events_sha256"`
	// NonMessageUpdateCount and NonMessageUpdatesSHA256 retain a redaction-safe
	// name-only sequence of every session/update other than agent_message_chunk,
	// including tool updates and unknown or malformed updates. This prevents
	// lifecycle, usage, plan, and thought updates from being mislabeled as tools.
	NonMessageUpdateCount   int    `json:"non_message_update_count"`
	NonMessageUpdatesSHA256 string `json:"non_message_updates_sha256"`
	Model                   string `json:"model,omitempty"`
	ModelEvidence           string `json:"model_evidence,omitempty"`
	// Authenticated records only a completed ACP session whose cached_token
	// authenticate request succeeded. It identifies neither an account nor an
	// entitlement, and therefore is safe to expose in a redacted receipt.
	Authenticated          bool   `json:"authenticated"`
	AuthenticationEvidence string `json:"authentication_evidence,omitempty"`
	Usage                  *Usage `json:"usage,omitempty"`
	ExitCode               *int   `json:"exit_code,omitempty"`
	CleanupState           string `json:"cleanup_state,omitempty"`
	// Cancellation is distinct from Cleanup. ACP acknowledgement proves only
	// that the local Grok agent completed this session/prompt as cancelled;
	// Cleanup proves local process-tree control and reaping separately.
	Cancellation ACPCancellationReceipt `json:"cancellation"`
	Cleanup      ProcessCleanupReceipt  `json:"cleanup"`
	Stderr       StderrDigest           `json:"stderr"`
	StartedAt    time.Time              `json:"started_at"`
	CompletedAt  time.Time              `json:"completed_at"`
}

const (
	StateCompleted      = "completed"
	StateAbortedSafe    = "aborted_safe"
	StateOutcomeUnknown = "outcome_unknown"
	StateFailed         = "failed"
	StateCancelled      = "cancelled_acknowledged"
)

const (
	DefaultCancellationGracePeriod = 3 * time.Second
	maxCancellationGracePeriod     = 10 * time.Second
)

// ACPCancellationReceipt is narrowly scoped evidence for a cancellation
// request. ACP acknowledgement is intentionally not labelled provider-cloud
// cancellation: the protocol proves only that the Grok ACP agent completed
// the exact original prompt with stopReason=cancelled.
type ACPCancellationReceipt struct {
	Requested                   bool      `json:"requested"`
	NotificationWritten         bool      `json:"notification_written"`
	SessionSHA256               string    `json:"session_sha256,omitempty"`
	OperationSHA256             string    `json:"operation_sha256,omitempty"`
	PromptRequestID             int       `json:"prompt_request_id,omitempty"`
	AgentACPAcknowledged        bool      `json:"agent_acp_acknowledged"`
	Acknowledgement             string    `json:"acknowledgement,omitempty"`
	CloudInferenceStopConfirmed bool      `json:"cloud_inference_stop_confirmed"`
	RequestedAt                 time.Time `json:"requested_at,omitempty"`
	AcknowledgedAt              time.Time `json:"acknowledged_at,omitempty"`
}

// ProcessCleanupReceipt describes only local process ownership. The process
// tree and reaping facts must not be read as xAI/ACP cancellation evidence.
type ProcessCleanupReceipt struct {
	LocalTermination string    `json:"local_termination"`
	ResidualPIDs     []int32   `json:"residual_pids"`
	Reaped           bool      `json:"reaped"`
	ObservedAt       time.Time `json:"observed_at"`
}

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

type rpcError struct {
	Code    json.RawMessage `json:"code"`
	Message string          `json:"message"`
}

type rpcEvent struct {
	message rpcMessage
	err     error
}

// Run executes the minimal ACP lifecycle. The caller's context is honored at
// every request boundary. A timeout before session/prompt is safely abortable;
// after the prompt has been accepted, a timeout is explicitly outcome-unknown
// because the provider may continue the already-accepted request.
func Run(ctx context.Context, runner Runner, req Request) (result Result, returnErr error) {
	started := time.Now().UTC()
	result = Result{
		State:        StateFailed,
		StartedAt:    started,
		Cancellation: ACPCancellationReceipt{},
		Cleanup: ProcessCleanupReceipt{
			LocalTermination: "not_started",
			ResidualPIDs:     []int32{},
		},
	}
	if ctx == nil {
		return finishFailure(result, ErrInvalidRequest, errors.New("context is required"))
	}
	if runner == nil {
		return finishFailure(result, ErrInvalidRequest, errors.New("runner is required"))
	}
	if strings.TrimSpace(req.Prompt) == "" {
		return finishFailure(result, ErrInvalidRequest, errors.New("prompt is required"))
	}
	if strings.TrimSpace(req.CWD) == "" {
		return finishFailure(result, ErrInvalidRequest, errors.New("cwd is required"))
	}
	if req.ExpectedNonce != "" && !ValidNonce(req.ExpectedNonce) {
		return finishFailure(result, ErrInvalidRequest, errors.New("expected nonce must be an NTM_ACK_ token with at least 128 bits of hex entropy"))
	}
	if err := ctx.Err(); err != nil {
		return finishFailure(result, ErrTimeout, err)
	}
	if strings.TrimSpace(req.Binary) == "" {
		req.Binary = "grok"
	}
	if len(req.AutomationPolicyArgs) == 0 {
		req.AutomationPolicyArgs = defaultReadOnlyAutomationPolicyArgs()
	}
	if err := validateAutomationPolicyArgs(req.AutomationPolicyArgs); err != nil {
		return finishFailure(result, ErrInvalidRequest, err)
	}
	args := make([]string, 0, 2+len(req.AutomationPolicyArgs)+4)
	args = append(args, "--no-auto-update")
	args = append(args, req.AutomationPolicyArgs...)
	if model := strings.TrimSpace(req.Model); model != "" {
		if strings.IndexFunc(model, unicode.IsControl) >= 0 {
			return finishFailure(result, ErrInvalidRequest, errors.New("model must not contain control characters"))
		}
		args = append(args, "--model", model)
	}
	args = append(args, "agent", "stdio")

	proc, err := runner.Start(ctx, StartSpec{
		Binary: req.Binary,
		Args:   args,
		CWD:    req.CWD,
	})
	if err != nil {
		return finishFailure(result, ErrDependencyMissing, fmt.Errorf("start grok ACP: %w", err))
	}

	stderrDone := make(chan StderrDigest, 1)
	go func() { stderrDone <- drainAndDigest(proc.Stderr(), MaxStderrCaptureBytes) }()
	events := readRPCEvents(proc.Stdout())

	// Closing stdin and reaping the child is mandatory even after a confirmed
	// reply: this is a one-shot adapter, not a daemon owner. This local cleanup
	// is deliberately recorded separately from any ACP cancellation receipt.
	defer func() {
		_ = proc.Stdin().Close()
		result.Cleanup = cleanupACPProcess(proc)
		waitErr := proc.Wait()
		_, exited := exitCodeFromError(waitErr)
		if waitErr == nil || exited {
			result.Cleanup.Reaped = true
			// A killed process can remain visible as a zombie until Wait reaps
			// it. Recheck only the residual PIDs already observed before Wait;
			// never discover or claim control over a fresh process tree here.
			result.Cleanup = reconcileACPResidualsAfterReap(result.Cleanup)
		}
		result.CleanupState = result.Cleanup.LocalTermination
		if result.Cleanup.Reaped {
			result.CleanupState += "_and_reaped"
		}
		if waitErr != nil {
			if exitCode, ok := exitCodeFromError(waitErr); ok {
				result.ExitCode = &exitCode
			} else {
				result.CleanupState = result.Cleanup.LocalTermination + "_wait_failed"
			}
		}
		result.Stderr = <-stderrDone
		result.CompletedAt = time.Now().UTC()
	}()

	// Once session/prompt has been written, the provider may accept it even if
	// the local response is lost. From that point a timeout is never safe to
	// replay automatically.
	promptMayHaveBeenAccepted := false
	outputHasher := sha256.New()
	updates := newUpdateAccumulator(outputHasher, req.ExpectedNonce, strings.TrimSpace(req.Model))
	nextID := 1
	call := func(method string, params any) (json.RawMessage, error) {
		id := nextID
		nextID++
		if err := writeRequest(ctx, proc.Stdin(), id, method, params); err != nil {
			return nil, err
		}
		return waitResponse(ctx, events, id, &updates)
	}

	initRaw, err := call("initialize", initializeParams{
		ProtocolVersion:    1,
		ClientCapabilities: map[string]any{},
	})
	if err != nil {
		return contextAwareFailure(result, promptMayHaveBeenAccepted, err)
	}
	var init initializeResult
	if err := json.Unmarshal(initRaw, &init); err != nil {
		return finishFailure(result, ErrProtocol, fmt.Errorf("decode initialize result: %w", err))
	}
	methodID, err := selectAuthMethod(init.AuthMethods)
	if err != nil {
		return finishFailure(result, ErrCachedAuthUnavailable, err)
	}
	cachedTokenAuthenticated := false
	if _, err := call("authenticate", authenticateParams{MethodID: methodID, Meta: map[string]bool{"headless": true}}); err != nil {
		if isRPCError(err) {
			return finishFailure(result, ErrAuthFailed, err)
		}
		return contextAwareFailure(result, promptMayHaveBeenAccepted, err)
	}
	// Do not expose this as authenticated until a terminal session/prompt
	// completion is also observed below. A successful authenticate RPC alone
	// does not establish that the cache can serve a completed session.
	cachedTokenAuthenticated = true

	newRaw, err := call("session/new", sessionNewParams{CWD: req.CWD, MCPServers: []any{}})
	if err != nil {
		return contextAwareFailure(result, promptMayHaveBeenAccepted, err)
	}
	var session sessionNewResult
	if err := json.Unmarshal(newRaw, &session); err != nil || strings.TrimSpace(session.SessionID) == "" {
		if err == nil {
			err = errors.New("session/new result omitted sessionId")
		}
		return finishFailure(result, ErrProtocol, fmt.Errorf("decode session/new result: %w", err))
	}
	result.ProviderSessionID = session.SessionID
	updates.providerSessionID = session.SessionID
	sessionConfigModel, sessionConfigModelObserved := sessionConfigExactModel(session.ConfigOptions, strings.TrimSpace(req.Model))
	sessionModelStateModel, sessionModelStateObserved := sessionModelsExactModel(session.Models, strings.TrimSpace(req.Model))

	promptID := nextID
	nextID++
	promptMayHaveBeenAccepted, err = writeRequestWithEvidence(ctx, proc.Stdin(), promptID, "session/prompt", sessionPromptParams{
		SessionID: session.SessionID,
		Prompt:    []promptPart{{Type: "text", Text: req.Prompt}},
	})
	if err != nil {
		return contextAwareFailure(result, promptMayHaveBeenAccepted, err)
	}
	promptRaw, cancellation, err := waitPromptResponseOrCancellation(
		ctx,
		proc.Stdin(),
		events,
		promptID,
		session.SessionID,
		req.OperationID,
		&updates,
		cancellationGracePeriod(req.CancellationGracePeriod),
	)
	result.Cancellation = cancellation
	if err != nil {
		if cancellation.Requested {
			return finishCancellationFailure(result, ErrOutcomeUnknown, err)
		}
		return contextAwareFailure(result, promptMayHaveBeenAccepted, err)
	}
	var prompt sessionPromptResult
	if err := json.Unmarshal(promptRaw, &prompt); err != nil {
		return finishFailure(result, ErrProtocol, fmt.Errorf("decode session/prompt result: %w", err))
	}
	// Once a terminal response has been matched to the original prompt request,
	// retain only the receipt-safe metadata before deciding whether it was a
	// normal completion or a cancellation acknowledgement.
	result.StopReason = prompt.StopReason
	result.Model = strings.TrimSpace(prompt.Model)
	if result.Model != "" {
		result.ModelEvidence = "completion_metadata"
	} else if updates.sessionModelObserved {
		result.Model = strings.TrimSpace(req.Model)
		result.ModelEvidence = "provider_session_notification_plus_exact_launch"
	} else if sessionConfigModelObserved {
		result.Model = sessionConfigModel
		result.ModelEvidence = "session_config_option_plus_exact_launch"
	} else if sessionModelStateObserved {
		result.Model = sessionModelStateModel
		result.ModelEvidence = "session_model_state_plus_exact_launch"
	}
	result.Usage = prompt.Usage.canonical()
	if cancellation.Requested {
		result.CompletionConfirmed = strings.TrimSpace(result.StopReason) != ""
		applyUpdateReceipt(&result, &updates, outputHasher)
		if result.StopReason != "cancelled" {
			return finishCancellationFailure(result, ErrCancellationUnconfirmed, errors.New("ACP session/cancel was not acknowledged by the original session/prompt response with stopReason=cancelled"))
		}
		result.Cancellation.AgentACPAcknowledged = true
		result.Cancellation.Acknowledgement = "session_prompt_stop_reason_cancelled"
		result.Cancellation.AcknowledgedAt = time.Now().UTC()
		// No field in the ACP cancellation acknowledgement proves whether a
		// previously accepted cloud inference request was stopped upstream.
		result.Cancellation.CloudInferenceStopConfirmed = false
		return finishCancellationFailure(result, ErrCancelled, context.Cause(ctx))
	}
	if strings.TrimSpace(prompt.StopReason) == "" {
		return finishFailure(result, ErrOutcomeUnknown, errors.New("session/prompt completion omitted stopReason"))
	}
	if err := drainPostResponseUpdates(ctx, events, &updates, postResponseQuietWindow(req.PostResponseQuietWindow)); err != nil {
		return contextAwareFailure(result, promptMayHaveBeenAccepted, err)
	}
	result.CompletionConfirmed = true
	applyUpdateReceipt(&result, &updates, outputHasher)
	if req.ExpectedNonce != "" && !result.AcknowledgementVerified {
		return finishFailure(result, ErrAcknowledgementUnconfirmed, errors.New("session/prompt completion omitted the required standalone nonce acknowledgement"))
	}
	result.Success = true
	result.State = StateCompleted
	if cachedTokenAuthenticated {
		result.Authenticated = true
		result.AuthenticationEvidence = "cached_token_authenticate_plus_completed_session"
	}
	return result, nil
}

func applyUpdateReceipt(result *Result, updates *updateAccumulator, outputHasher hash.Hash) {
	if result == nil || updates == nil || outputHasher == nil {
		return
	}
	updates.nonce.Finalize()
	result.AssistantTextChunks = updates.chunks
	result.AssistantTextBytes = updates.bytes
	result.AcknowledgementVerified = updates.nonce.verified
	result.OutputSHA256 = hex.EncodeToString(outputHasher.Sum(nil))
	result.ToolEventCount = updates.toolEventCount
	result.ToolEventsSHA256 = hex.EncodeToString(updates.toolEventHasher.Sum(nil))
	result.NonMessageUpdateCount = updates.nonMessageUpdateCount
	result.NonMessageUpdatesSHA256 = hex.EncodeToString(updates.nonMessageUpdateHasher.Sum(nil))
}

func postResponseQuietWindow(value time.Duration) time.Duration {
	if value <= 0 {
		return DefaultPostResponseQuietWindow
	}
	if value > maxPostResponseQuietWindow {
		return maxPostResponseQuietWindow
	}
	return value
}

func cancellationGracePeriod(value time.Duration) time.Duration {
	if value <= 0 {
		return DefaultCancellationGracePeriod
	}
	if value > maxCancellationGracePeriod {
		return maxCancellationGracePeriod
	}
	return value
}

type sessionCancelParams struct {
	SessionID string `json:"sessionId"`
}

// waitPromptResponseOrCancellation keeps one reader for ACP stdout. Once the
// original session/prompt request has been written, caller-context
// cancellation first writes the ACP v1 session/cancel notification and then
// waits on a fresh bounded context for the response with that *same* prompt
// request ID. A response for any other request is rejected by waitResponse.
func waitPromptResponseOrCancellation(
	ctx context.Context,
	writer io.Writer,
	events <-chan rpcEvent,
	promptID int,
	sessionID string,
	operationID string,
	updates *updateAccumulator,
	grace time.Duration,
) (json.RawMessage, ACPCancellationReceipt, error) {
	for {
		// Prefer a response that is already available. This prevents an
		// operator interrupt racing a completed prompt from rewriting a known
		// terminal outcome as a cancellation attempt.
		select {
		case event, ok := <-events:
			if !ok {
				return nil, ACPCancellationReceipt{}, io.EOF
			}
			raw, done, err := consumeResponseEvent(event, promptID, updates)
			if err != nil || done {
				return raw, ACPCancellationReceipt{}, err
			}
			continue
		default:
		}

		select {
		case event, ok := <-events:
			if !ok {
				return nil, ACPCancellationReceipt{}, io.EOF
			}
			raw, done, err := consumeResponseEvent(event, promptID, updates)
			if err != nil || done {
				return raw, ACPCancellationReceipt{}, err
			}
		case <-ctx.Done():
			cancellation := ACPCancellationReceipt{
				Requested:       true,
				SessionSHA256:   acpCancellationHash(sessionID),
				OperationSHA256: acpOperationHash(operationID, sessionID, promptID),
				PromptRequestID: promptID,
				RequestedAt:     time.Now().UTC(),
			}
			cancelCtx, cancel := context.WithTimeout(context.Background(), grace)
			written, err := writeNotificationWithEvidence(cancelCtx, writer, "session/cancel", sessionCancelParams{SessionID: sessionID})
			cancellation.NotificationWritten = written
			if err != nil {
				cancel()
				return nil, cancellation, fmt.Errorf("write ACP session/cancel notification: %w", err)
			}
			raw, err := waitResponse(cancelCtx, events, promptID, updates)
			cancel()
			if err != nil {
				return nil, cancellation, fmt.Errorf("wait for original ACP session/prompt cancellation response: %w", err)
			}
			return raw, cancellation, nil
		}
	}
}

func acpCancellationHash(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// acpOperationHash makes the cancellation receipt bind both the durable
// caller operation (when present) and the exact ACP session/prompt request.
// The source identifiers are never retained in the receipt.
func acpOperationHash(operationID, sessionID string, promptID int) string {
	return acpCancellationHash(fmt.Sprintf("%s\x00%s\x00%d", operationID, sessionID, promptID))
}

// drainPostResponseUpdates receives all notifications that arrive before one
// complete quiet window. It does not retain their text; updateAccumulator only
// maintains the receipt's hashes, counters, and bounded nonce-line state.
func drainPostResponseUpdates(ctx context.Context, events <-chan rpcEvent, updates *updateAccumulator, quietWindow time.Duration) error {
	timer := time.NewTimer(quietWindow)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		case event, ok := <-events:
			if !ok {
				return nil
			}
			if event.err != nil {
				return event.err
			}
			if isBenignACPNotification(event.message) {
				updates.observeVendorNotification(event.message.Method, event.message.Params)
				continue
			}
			if event.message.Method != "session/update" {
				return errors.New("unexpected ACP message after session/prompt response")
			}
			updates.observe(event.message.Params)
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(quietWindow)
		}
	}
}

func validateAutomationPolicyArgs(args []string) error {
	for _, policyName := range []string{
		agentpkg.DefaultGrokAutomationPolicyName,
		agentpkg.GrokWorkspaceWritePolicyName,
	} {
		if slices.Equal(args, agentpkg.GrokAutomationACPPolicyArgs(policyName)) {
			return nil
		}
	}
	return errors.New("automation policy arguments must exactly match a compiled NTM Grok policy")
}

func exitCodeFromError(err error) (int, bool) {
	var exitCoder interface{ ExitCode() int }
	if errors.As(err, &exitCoder) {
		return exitCoder.ExitCode(), true
	}
	return 0, false
}

func finishFailure(result Result, code ErrorCode, err error) (Result, error) {
	result.Success = false
	result.FailureCode = code
	result.State = StateFailed
	if code == ErrTimeout {
		result.State = StateAbortedSafe
	}
	if code == ErrOutcomeUnknown {
		result.State = StateOutcomeUnknown
	}
	if result.CompletedAt.IsZero() {
		result.CompletedAt = time.Now().UTC()
	}
	return result, &Error{Code: code, Err: err}
}

func finishCancellationFailure(result Result, code ErrorCode, err error) (Result, error) {
	result.Success = false
	result.FailureCode = code
	if code == ErrCancelled {
		result.State = StateCancelled
	} else {
		// A cancellation notification without the required matching original
		// prompt response leaves the accepted provider operation unknown.
		result.State = StateOutcomeUnknown
	}
	if result.CompletedAt.IsZero() {
		result.CompletedAt = time.Now().UTC()
	}
	return result, &Error{Code: code, Err: err}
}

func contextAwareFailure(result Result, promptAccepted bool, err error) (Result, error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		if promptAccepted {
			return finishFailure(result, ErrOutcomeUnknown, err)
		}
		return finishFailure(result, ErrTimeout, err)
	}
	if isRPCError(err) {
		return finishFailure(result, ErrProvider, err)
	}
	return finishFailure(result, ErrProtocol, err)
}

func cleanupACPProcess(proc Process) ProcessCleanupReceipt {
	return cleanupACPProcessWithTerminator(proc, TerminateAndVerify)
}

func cleanupACPProcessWithTerminator(proc Process, terminate func(context.Context, int32) CancellationReceipt) ProcessCleanupReceipt {
	receipt := ProcessCleanupReceipt{
		LocalTermination: "unsupported",
		ResidualPIDs:     []int32{},
		ObservedAt:       time.Now().UTC(),
	}
	if proc == nil || terminate == nil {
		return receipt
	}
	pid := proc.PID()
	if pid > 0 {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		terminated := terminate(cleanupCtx, pid)
		cancel()
		receipt.LocalTermination = terminated.LocalTermination
		receipt.ResidualPIDs = append(receipt.ResidualPIDs, terminated.ResidualPIDs...)
		receipt.ObservedAt = terminated.ObservedAt
		// A failed/incomplete tree inspection must not leave the owned parent
		// running. This fallback does not upgrade the tree receipt: residuals
		// stay explicit and only the parent kill was attempted.
		if receipt.LocalTermination != "observed_tree_terminated_verified" && receipt.LocalTermination != "already_exited_verified" {
			if err := proc.Kill(); err != nil {
				receipt.LocalTermination += "_parent_kill_failed"
			}
		}
		return receipt
	}
	// Test doubles and platforms without a PID cannot prove a complete tree,
	// but still need a best-effort parent termination before Wait can reap it.
	if err := proc.Kill(); err != nil {
		receipt.LocalTermination = "parent_termination_failed"
	}
	return receipt
}

const postReapResidualRecheckWindow = 250 * time.Millisecond

// reconcileACPResidualsAfterReap retries only PIDs that the original
// termination pass already observed as residual. In particular, it never
// walks the process tree again: reaping the owned root may remove a zombie,
// but does not authorize discovery or control of any subsequently appearing
// process. A successful recheck proves local process cleanup only.
func reconcileACPResidualsAfterReap(receipt ProcessCleanupReceipt) ProcessCleanupReceipt {
	return reconcileACPResidualsAfterReapWithInspector(receipt, osInspector{}, postReapResidualRecheckWindow)
}

func reconcileACPResidualsAfterReapWithInspector(receipt ProcessCleanupReceipt, inspector ProcessInspector, window time.Duration) ProcessCleanupReceipt {
	if receipt.LocalTermination != "residual_processes_detected" || len(receipt.ResidualPIDs) == 0 || !receipt.Reaped || inspector == nil {
		return receipt
	}
	observed := append([]int32{}, receipt.ResidualPIDs...)
	check := func() bool {
		remaining := remainingPIDs(observed, inspector)
		if len(remaining) != 0 {
			receipt.ResidualPIDs = remaining
			return false
		}
		receipt.LocalTermination = "observed_tree_terminated_verified"
		receipt.ResidualPIDs = []int32{}
		receipt.ObservedAt = time.Now().UTC()
		return true
	}
	if check() || window <= 0 {
		return receipt
	}

	deadline := time.NewTimer(window)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline.C:
			return receipt
		case <-tick.C:
			if check() {
				return receipt
			}
		}
	}
}

type initializeParams struct {
	ProtocolVersion    int            `json:"protocolVersion"`
	ClientCapabilities map[string]any `json:"clientCapabilities"`
}

type authMethod struct {
	ID string `json:"id"`
}

type initializeResult struct {
	AuthMethods []authMethod `json:"authMethods"`
}

type authenticateParams struct {
	MethodID string          `json:"methodId"`
	Meta     map[string]bool `json:"_meta"`
}

type sessionNewParams struct {
	CWD        string `json:"cwd"`
	MCPServers []any  `json:"mcpServers"`
}

type sessionNewResult struct {
	SessionID     string                `json:"sessionId"`
	ConfigOptions []sessionConfigOption `json:"configOptions"`
	Models        json.RawMessage       `json:"models"`
}

// sessionConfigOption retains only the wire fields needed to bind a model to
// one exact ACP session. The raw values prevent unrelated or future option
// shapes from becoming a decoding or identity authority.
type sessionConfigOption struct {
	Category     string          `json:"category"`
	Type         string          `json:"type"`
	CurrentValue json.RawMessage `json:"currentValue"`
	Options      json.RawMessage `json:"options"`
}

// sessionConfigExactModel accepts only the stable ACP select option dedicated
// to the model category. A catalog, display name, model-like option id, or an
// ambiguous duplicate cannot establish the model that served this session.
func sessionConfigExactModel(configOptions []sessionConfigOption, requested string) (string, bool) {
	if requested == "" {
		return "", false
	}
	var modelOption *sessionConfigOption
	for index := range configOptions {
		option := &configOptions[index]
		if option.Category != "model" {
			continue
		}
		if modelOption != nil {
			return "", false
		}
		modelOption = option
	}
	if modelOption == nil || modelOption.Type != "select" {
		return "", false
	}
	var currentValue string
	if json.Unmarshal(modelOption.CurrentValue, &currentValue) != nil || currentValue != requested {
		return "", false
	}
	var options []struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(modelOption.Options, &options) != nil {
		return "", false
	}
	matches := 0
	for _, option := range options {
		if option.Value == currentValue {
			matches++
		}
	}
	if matches != 1 {
		return "", false
	}
	return currentValue, true
}

// sessionModelsExactModel accepts only Grok's top-level typed session model
// state. It deliberately ignores vendor metadata and any nested lookalikes:
// currentModelId must be the exact requested launch model and that modelId must
// appear exactly once in availableModels.
func sessionModelsExactModel(raw json.RawMessage, requested string) (string, bool) {
	if len(raw) == 0 || requested == "" {
		return "", false
	}
	var state struct {
		CurrentModelID  string `json:"currentModelId"`
		AvailableModels []struct {
			ModelID string `json:"modelId"`
		} `json:"availableModels"`
	}
	if json.Unmarshal(raw, &state) != nil || state.CurrentModelID != requested {
		return "", false
	}
	matches := 0
	for _, model := range state.AvailableModels {
		if model.ModelID == state.CurrentModelID {
			matches++
		}
	}
	if matches != 1 {
		return "", false
	}
	return state.CurrentModelID, true
}

type promptPart struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type sessionPromptParams struct {
	SessionID string       `json:"sessionId"`
	Prompt    []promptPart `json:"prompt"`
}

type sessionPromptResult struct {
	StopReason string      `json:"stopReason"`
	Model      string      `json:"model"`
	Usage      promptUsage `json:"usage"`
}

// Usage records only provider-supplied counters. Nil means the corresponding
// counter was absent, rather than falsely asserting a zero value.
type Usage struct {
	InputTokens  *int64 `json:"input_tokens,omitempty"`
	OutputTokens *int64 `json:"output_tokens,omitempty"`
	TotalTokens  *int64 `json:"total_tokens,omitempty"`
}

type promptUsage struct {
	InputTokens       *int64 `json:"inputTokens"`
	OutputTokens      *int64 `json:"outputTokens"`
	TotalTokens       *int64 `json:"totalTokens"`
	InputTokensSnake  *int64 `json:"input_tokens"`
	OutputTokensSnake *int64 `json:"output_tokens"`
	TotalTokensSnake  *int64 `json:"total_tokens"`
}

func (u promptUsage) canonical() *Usage {
	usage := &Usage{
		InputTokens:  firstNonNilInt64(u.InputTokens, u.InputTokensSnake),
		OutputTokens: firstNonNilInt64(u.OutputTokens, u.OutputTokensSnake),
		TotalTokens:  firstNonNilInt64(u.TotalTokens, u.TotalTokensSnake),
	}
	if usage.InputTokens == nil && usage.OutputTokens == nil && usage.TotalTokens == nil {
		return nil
	}
	return usage
}

func firstNonNilInt64(values ...*int64) *int64 {
	for _, value := range values {
		if value != nil {
			copy := *value
			return &copy
		}
	}
	return nil
}

func selectAuthMethod(methods []authMethod) (string, error) {
	available := make(map[string]struct{}, len(methods))
	for _, method := range methods {
		available[method.ID] = struct{}{}
	}
	if _, ok := available["cached_token"]; ok {
		return "cached_token", nil
	}
	return "", errors.New("Grok ACP did not offer cached_token; establish a cached Grok CLI login before automated ACP use")
}

func writeRequest(ctx context.Context, writer io.Writer, id int, method string, params any) error {
	_, err := writeRequestWithEvidence(ctx, writer, id, method, params)
	return err
}

// writeRequestWithEvidence distinguishes a locally proven zero-byte failure
// from a write that may have reached the provider. The latter must be treated
// as replay-unsafe for session/prompt even when the response is lost.
func writeRequestWithEvidence(ctx context.Context, writer io.Writer, id int, method string, params any) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	payload, err := json.Marshal(struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Method  string `json:"method"`
		Params  any    `json:"params"`
	}{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	if err != nil {
		return false, fmt.Errorf("encode %s request: %w", method, err)
	}
	payload = append(payload, '\n')
	written, err := writer.Write(payload)
	mayHaveReachedProvider := written > 0
	if err != nil {
		return mayHaveReachedProvider, fmt.Errorf("write %s request: %w", method, err)
	}
	if written != len(payload) {
		return mayHaveReachedProvider, fmt.Errorf("write %s request: %w", method, io.ErrShortWrite)
	}
	return true, nil
}

// writeNotificationWithEvidence writes a JSON-RPC notification (no id) and
// returns whether any byte entered the local ACP pipe. That is delivery to the
// local Grok agent only; its separate session/prompt response is the sole
// acknowledgement accepted by the cancellation contract.
func writeNotificationWithEvidence(ctx context.Context, writer io.Writer, method string, params any) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	payload, err := json.Marshal(struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		Params  any    `json:"params"`
	}{JSONRPC: "2.0", Method: method, Params: params})
	if err != nil {
		return false, fmt.Errorf("encode %s notification: %w", method, err)
	}
	payload = append(payload, '\n')
	written, err := writer.Write(payload)
	mayHaveReachedAgent := written > 0
	if err != nil {
		return mayHaveReachedAgent, fmt.Errorf("write %s notification: %w", method, err)
	}
	if written != len(payload) {
		return mayHaveReachedAgent, fmt.Errorf("write %s notification: %w", method, io.ErrShortWrite)
	}
	return true, nil
}

func readRPCEvents(reader io.Reader) <-chan rpcEvent {
	events := make(chan rpcEvent, 1)
	go func() {
		defer close(events)
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 32<<10), MaxProtocolLineBytes)
		for scanner.Scan() {
			var message rpcMessage
			if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
				events <- rpcEvent{err: fmt.Errorf("decode ACP message: %w", err)}
				return
			}
			if message.JSONRPC != "2.0" {
				events <- rpcEvent{err: fmt.Errorf("invalid ACP jsonrpc version %q", message.JSONRPC)}
				return
			}
			events <- rpcEvent{message: message}
		}
		if err := scanner.Err(); err != nil {
			events <- rpcEvent{err: fmt.Errorf("read ACP message: %w", err)}
		}
	}()
	return events
}

func waitResponse(ctx context.Context, events <-chan rpcEvent, requestID int, updates *updateAccumulator) (json.RawMessage, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case event, ok := <-events:
			if !ok {
				return nil, io.EOF
			}
			if event.err != nil {
				return nil, event.err
			}
			raw, done, err := consumeResponseEvent(event, requestID, updates)
			if err != nil || done {
				return raw, err
			}
		}
	}
}

// consumeResponseEvent processes notifications and accepts a response only
// when it is bound to the exact request ID the caller is awaiting.
func consumeResponseEvent(event rpcEvent, requestID int, updates *updateAccumulator) (json.RawMessage, bool, error) {
	if event.err != nil {
		return nil, false, event.err
	}
	if event.message.Method == "session/update" {
		updates.observe(event.message.Params)
		return nil, false, nil
	}
	if isBenignACPNotification(event.message) {
		updates.observeVendorNotification(event.message.Method, event.message.Params)
		return nil, false, nil
	}
	if event.message.Method != "" {
		return nil, false, fmt.Errorf("unexpected ACP notification %q", event.message.Method)
	}
	wantID := fmt.Sprintf("%d", requestID)
	if string(event.message.ID) != wantID {
		return nil, false, fmt.Errorf("unexpected ACP response id %s, want %s", string(event.message.ID), wantID)
	}
	if event.message.Error != nil {
		return nil, false, &providerError{message: event.message.Error.Message}
	}
	if len(event.message.Result) == 0 {
		return nil, false, errors.New("ACP response omitted both result and error")
	}
	return event.message.Result, true, nil
}

// isBenignACPNotification recognizes xAI's vendor-extension notification
// namespace. The CLI emits several evolving housekeeping methods during
// initialization (models, settings, announcements, MCP, and session indexes).
// They are accepted only without a request ID, contribute no completion or
// identity evidence, and cannot widen permissions. Provider-to-client requests
// and non-vendor unknown methods continue to fail closed.
func isBenignACPNotification(message rpcMessage) bool {
	return len(message.ID) == 0 && strings.HasPrefix(message.Method, "_x.ai/")
}

type providerError struct{ message string }

func (e *providerError) Error() string {
	if e == nil || e.message == "" {
		return "Grok ACP provider returned an error"
	}
	return "Grok ACP provider: " + e.message
}

func isRPCError(err error) bool {
	var provider *providerError
	return errors.As(err, &provider)
}

type updateAccumulator struct {
	hasher                 io.Writer
	chunks                 int
	bytes                  int64
	nonce                  nonceMatcher
	toolEventHasher        hash.Hash
	toolEventCount         int
	nonMessageUpdateHasher hash.Hash
	nonMessageUpdateCount  int
	expectedModel          string
	sessionModelObserved   bool
	providerSessionID      string
}

func newUpdateAccumulator(hasher io.Writer, nonce, expectedModel string) updateAccumulator {
	return updateAccumulator{
		hasher: hasher, nonce: newNonceMatcher(nonce), toolEventHasher: sha256.New(), nonMessageUpdateHasher: sha256.New(),
		expectedModel: strings.TrimSpace(expectedModel),
	}
}

// grokSessionModelNotification is the reviewed Grok CLI 1.0.13 notification
// contract for session-scoped model evidence. Other xAI notifications are
// tolerated as housekeeping only; they cannot confirm an operation identity.
const grokSessionModelNotification = "_x.ai/session/models/update"

type grokSessionModelNotificationParams struct {
	SessionID string `json:"sessionId"`
	Model     string `json:"model"`
}

// observeVendorNotification accepts model evidence only from the reviewed
// notification and only when its top-level sessionId and model fields bind the
// same record to this ACP session and exact launch. Raw catalogs, nested
// indexes, and unrelated vendor metadata are intentionally not evidence.
func (a *updateAccumulator) observeVendorNotification(method string, params json.RawMessage) {
	if a == nil || method != grokSessionModelNotification || a.expectedModel == "" || a.providerSessionID == "" {
		return
	}
	var notification grokSessionModelNotificationParams
	if err := json.Unmarshal(params, &notification); err != nil {
		return
	}
	if notification.SessionID == a.providerSessionID && notification.Model == a.expectedModel {
		a.sessionModelObserved = true
	}
}

func (a *updateAccumulator) observe(params json.RawMessage) {
	var envelope struct {
		Update struct {
			SessionUpdate string `json:"sessionUpdate"`
			Content       struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"update"`
	}
	if json.Unmarshal(params, &envelope) != nil {
		a.recordNonMessageUpdate("unknown")
		return
	}
	if envelope.Update.SessionUpdate != "agent_message_chunk" {
		name := envelope.Update.SessionUpdate
		if name == "" {
			name = "unknown"
		}
		a.recordNonMessageUpdate(name)
		if name == "tool_call" || name == "tool_call_update" {
			a.recordToolEvent(name)
		}
		return
	}
	if envelope.Update.Content.Text == "" {
		return
	}
	_, _ = io.WriteString(a.hasher, envelope.Update.Content.Text)
	a.nonce.WriteString(envelope.Update.Content.Text)
	a.chunks++
	a.bytes += int64(len(envelope.Update.Content.Text))
}

func (a *updateAccumulator) recordToolEvent(name string) {
	if a == nil {
		return
	}
	a.recordUpdateName(a.toolEventHasher, &a.toolEventCount, name)
}

func (a *updateAccumulator) recordNonMessageUpdate(name string) {
	if a == nil {
		return
	}
	a.recordUpdateName(a.nonMessageUpdateHasher, &a.nonMessageUpdateCount, name)
}

func (a *updateAccumulator) recordUpdateName(hasher hash.Hash, count *int, name string) {
	if hasher == nil || count == nil {
		return
	}
	// Length-prefixing makes the sequence unambiguous while hashing only the
	// classified sessionUpdate names, never raw params, tool arguments, or
	// tool results.
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(name)))
	_, _ = hasher.Write(length[:])
	_, _ = io.WriteString(hasher, name)
	*count++
}

const maxAcknowledgementLineBytes = 256

// nonceMatcher retains only one bounded candidate line. Acknowledgements are
// accepted only when the trimmed assistant line is exactly the nonce; a nonce
// embedded in prose, a tool result, or another token is never evidence.
type nonceMatcher struct {
	needle   string
	line     []byte
	overlong bool
	verified bool
}

func newNonceMatcher(needle string) nonceMatcher {
	return nonceMatcher{needle: needle, line: make([]byte, 0, len(needle)+8)}
}

func (m *nonceMatcher) WriteString(chunk string) {
	if m == nil || m.needle == "" || m.verified {
		return
	}
	for i := 0; i < len(chunk); i++ {
		if chunk[i] == '\n' {
			m.finishLine()
			continue
		}
		if len(m.line) >= maxAcknowledgementLineBytes {
			m.overlong = true
			continue
		}
		m.line = append(m.line, chunk[i])
	}
}

// Finalize treats a final unterminated assistant line as a line at the end of
// the response stream. This preserves split-chunk matching without requiring
// the provider to append a newline.
func (m *nonceMatcher) Finalize() {
	if m == nil || m.verified {
		return
	}
	m.finishLine()
}

func (m *nonceMatcher) finishLine() {
	if !m.overlong && strings.TrimSpace(string(m.line)) == m.needle {
		m.verified = true
	}
	m.line = m.line[:0]
	m.overlong = false
}

// ValidNonce accepts only the generated-token format: an NTM_ACK_ prefix and
// at least 128 bits (32 lowercase hex characters) of entropy. It rejects
// whitespace, controls, and hand-authored short tokens.
func ValidNonce(value string) bool {
	const prefix = "NTM_ACK_"
	if !strings.HasPrefix(value, prefix) || len(value) < len(prefix)+32 || len(value) > len(prefix)+128 {
		return false
	}
	for _, char := range value[len(prefix):] {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func minimalGrokEnvironment(environ []string) []string {
	order := []string{
		"PATH", "HOME", "USERPROFILE", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
		"SSL_CERT_FILE", "SSL_CERT_DIR", "TMPDIR", "TMP", "TEMP",
		"SystemRoot", "WINDIR", "ComSpec", "PATHEXT",
	}
	allowed := make(map[string]string, len(order))
	allowedFolded := make(map[string]string, len(order))
	for _, canonical := range order {
		allowed[canonical] = canonical
		// The folded lookup handles Windows' case-insensitive environment
		// (notably Path, SystemRoot, and ComSpec) without broadening the
		// allowlist. Proxy variables are intentionally excluded because proxy
		// URLs can embed credentials; automated ACP uses a direct child with no
		// inherited credential-bearing network configuration.
		folded := strings.ToLower(canonical)
		if _, exists := allowedFolded[folded]; !exists {
			allowedFolded[folded] = canonical
		}
	}
	values := make(map[string]string, len(order))
	for _, entry := range environ {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		canonical, ok := allowed[name]
		if !ok {
			canonical, ok = allowedFolded[strings.ToLower(name)]
		}
		if ok {
			values[canonical] = value
		}
	}
	result := make([]string, 0, len(values))
	for _, name := range order {
		if value, ok := values[name]; ok {
			result = append(result, name+"="+value)
		}
	}
	return result
}

func drainAndDigest(reader io.Reader, capBytes int64) StderrDigest {
	if reader == nil {
		return StderrDigest{SHA256: hex.EncodeToString(sha256.New().Sum(nil))}
	}
	hash := sha256.New()
	buffer := make([]byte, 32<<10)
	var total int64
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
			total += int64(n)
		}
		if err != nil {
			break
		}
	}
	return StderrDigest{Bytes: total, SHA256: hex.EncodeToString(hash.Sum(nil)), Truncated: total > capBytes}
}
