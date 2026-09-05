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
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
	"unicode"

	agentpkg "github.com/Dicklesworthstone/ntm/internal/agent"
	"github.com/Dicklesworthstone/ntm/internal/provider"
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

// protocolFailure carries only a bounded reason, never the rejected message.
type protocolFailure struct {
	reason provider.ProtocolFailureReason
}

func (e *protocolFailure) Error() string { return "Grok ACP protocol failure: " + string(e.reason) }

func protocolError(reason provider.ProtocolFailureReason) error {
	return &protocolFailure{reason: reason}
}

// StartSpec is the narrow process boundary. Credentials are intentionally not
// represented here: automated ACP uses only the CLI's existing cached login,
// and ACP authenticate carries only the cached_token method identifier.
type StartSpec struct {
	Binary         string
	Args           []string
	CWD            string
	RuntimeHome    string
	WorkspaceWrite bool
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
	env, err := IsolatedProcessEnvironment(os.Environ(), spec.RuntimeHome, spec.WorkspaceWrite)
	if err != nil {
		return nil, err
	}
	cmd.Env = env
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
	// RuntimeHome is the dedicated GROK_HOME selected by the exact provider
	// profile. Production runners reject an absent or relative value so user
	// auth/config, compatibility scanners, and session state cannot bleed in.
	RuntimeHome string
	// Model is passed as an exact --model value before the ACP subcommand. It
	// is not echoed in Result unless the provider's completion metadata confirms
	// the effective model.
	Model string
	// RuntimeVersion selects the reviewed public-to-resolved model binding for
	// terminal usage metadata. Production adapters supply the exact pinned CLI
	// version; an unknown version cannot inherit another version's alias map.
	RuntimeVersion string
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
	// Broker is the sole MCP server shape accepted by this ACP adapter.  It is
	// deliberately a controller-owned workspace broker, not an arbitrary MCP
	// configuration passed through from a prompt or provider response.
	Broker *WorkspaceBrokerDescriptor
	// AfterPromptWritten is invoked once after the complete session/prompt RPC
	// request has been written. It is intended for deterministic qualification
	// cancellation tests. A callback panic is contained and cannot interrupt an
	// accepted provider operation.
	AfterPromptWritten func()
	// BeforeCleanup persists a redacted observation before stdin closure and
	// process reaping. Failure is reported after mandatory cleanup; a callback
	// cannot suppress cleanup or turn an unsuccessful run into success.
	BeforeCleanup func(provider.ProtocolObservation) error
}

// WorkspaceBrokerDescriptor describes the sole local NTM MCP service an ACP
// session may receive. Its executable and arguments are private so callers
// cannot substitute a shell, remote transport, environment, or arbitrary MCP
// server after NTM has constructed the descriptor.
type WorkspaceBrokerDescriptor struct {
	command    string
	args       []string
	controller ControllerBrokerFactory
}

const WorkspaceBrokerMCPName = "ntm-controlled-workspace"

// NewWorkspaceBrokerDescriptor is the sole construction path. It binds the
// server to this exact running NTM executable rather than accepting a caller-
// supplied program. Arguments are passed directly to the process, never
// through a shell.
func NewWorkspaceBrokerDescriptor(worktree, revision string, commands []string) (*WorkspaceBrokerDescriptor, error) {
	return newWorkspaceBrokerDescriptor(worktree, revision, commands, "")
}

// NewWorkspaceBrokerDescriptorWithAudit constructs the bounded broker with a
// pre-created, private redacted JSONL audit file. The audit file must be a
// direct child of the linked worktree's exact temporary parent, never inside
// the worktree. Its path is part of BindingSHA256 and therefore cannot be
// changed after admission without invalidating the descriptor binding.
func NewWorkspaceBrokerDescriptorWithAudit(worktree, revision string, commands []string, auditFile string) (*WorkspaceBrokerDescriptor, error) {
	return newWorkspaceBrokerDescriptor(worktree, revision, commands, auditFile)
}

func newWorkspaceBrokerDescriptor(worktree, revision string, commands []string, auditFile string) (*WorkspaceBrokerDescriptor, error) {
	if runtime.GOOS != "linux" || os.Getpid() <= 0 {
		return nil, errors.New("ACP workspace broker requires Linux parent executable binding")
	}
	command := fmt.Sprintf("/proc/%d/exe", os.Getpid())
	commandSHA256, err := workspaceBrokerExecutableSHA256(command)
	if err != nil {
		return nil, errors.New("hash current NTM executable for ACP workspace broker")
	}
	if !filepath.IsAbs(worktree) || len(worktree) > 4096 || strings.IndexFunc(worktree, unicode.IsControl) >= 0 || len(revision) < 40 || len(revision) > sha256.Size*2 || strings.IndexFunc(revision, func(r rune) bool { return !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) }) >= 0 {
		return nil, errors.New("ACP workspace broker binding is invalid")
	}
	if len(commands) == 0 || len(commands) > 8 {
		return nil, errors.New("ACP workspace broker requires a bounded verifier manifest")
	}
	allowed := map[string]bool{"go-test": true, "go-vet": true, "cargo-test": true}
	seen := make(map[string]bool, len(commands))
	for _, id := range commands {
		if !allowed[id] || seen[id] {
			return nil, errors.New("ACP workspace broker has an unapproved verifier command")
		}
		seen[id] = true
	}
	args := []string{
		"provider", "broker", "stdio", "--worktree", worktree, "--revision", revision, "--commands", strings.Join(commands, ","), "--ntm-sha256", commandSHA256,
	}
	if auditFile != "" {
		if err := validateWorkspaceBrokerAuditFile(worktree, auditFile); err != nil {
			return nil, err
		}
		args = append(args, "--audit-file", auditFile)
	}
	return &WorkspaceBrokerDescriptor{command: command, args: args}, nil
}

func (d WorkspaceBrokerDescriptor) validate() error {
	if !filepath.IsAbs(d.command) || len(d.command) > 4096 || strings.IndexFunc(d.command, unicode.IsControl) >= 0 {
		return errors.New("ACP workspace broker descriptor is invalid")
	}
	if runtime.GOOS != "linux" || !workspaceBrokerProcExePath(d.command) {
		return errors.New("ACP workspace broker descriptor requires Linux parent executable binding")
	}
	if (len(d.args) != 11 && len(d.args) != 13) || !slices.Equal(d.args[:3], []string{"provider", "broker", "stdio"}) || d.args[3] != "--worktree" || d.args[5] != "--revision" || d.args[7] != "--commands" || d.args[9] != "--ntm-sha256" || !workspaceBrokerDigest(d.args[10]) {
		return errors.New("ACP workspace broker descriptor is incomplete")
	}
	for _, value := range d.args {
		if value == "" || len(value) > 4096 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return errors.New("ACP workspace broker descriptor has invalid arguments")
		}
	}
	if len(d.args) == 13 {
		if d.args[11] != "--audit-file" {
			return errors.New("ACP workspace broker descriptor has invalid audit arguments")
		}
		if err := validateWorkspaceBrokerAuditFile(d.args[4], d.args[12]); err != nil {
			return err
		}
	}
	return nil
}

func validateWorkspaceBrokerAuditFile(worktree, auditFile string) error {
	if !filepath.IsAbs(auditFile) || len(auditFile) > 4096 || strings.IndexFunc(auditFile, unicode.IsControl) >= 0 {
		return errors.New("ACP workspace broker audit path is invalid")
	}
	worktree = filepath.Clean(worktree)
	auditFile = filepath.Clean(auditFile)
	if filepath.Dir(auditFile) != filepath.Dir(worktree) {
		return errors.New("ACP workspace broker audit path must be under the linked worktree temporary parent")
	}
	return nil
}

func workspaceBrokerExecutableSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func workspaceBrokerProcExePath(path string) bool {
	if !strings.HasPrefix(path, "/proc/") || !strings.HasSuffix(path, "/exe") {
		return false
	}
	middle := strings.TrimSuffix(strings.TrimPrefix(path, "/proc/"), "/exe")
	if middle == "" || strings.IndexFunc(middle, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return false
	}
	return filepath.Clean(path) == path
}

func workspaceBrokerDigest(value string) bool {
	return len(value) == sha256.Size*2 && strings.IndexFunc(value, func(r rune) bool { return !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) }) < 0
}

func (d WorkspaceBrokerDescriptor) MarshalJSON() ([]byte, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Name    string   `json:"name"`
		Command string   `json:"command"`
		Args    []string `json:"args"`
		// ACP v1 requires env even when the controller intentionally passes no
		// environment variables to the broker. Keep the value structurally
		// present and empty so credentials cannot be inherited through this
		// descriptor and strict agents do not reject session/new.
		Env []any `json:"env"`
	}{Name: WorkspaceBrokerMCPName, Command: d.command, Args: append([]string(nil), d.args...), Env: []any{}})
}

// BindingSHA256 is safe receipt evidence for the exact current executable,
// worktree, revision, and verifier manifest. It exposes none of those values.
func (d WorkspaceBrokerDescriptor) BindingSHA256() string {
	if err := d.validate(); err != nil {
		return ""
	}
	fields := append([]string{d.command}, d.args...)
	if d.controller != nil {
		fields = append(fields, "controller-acp-v1")
	}
	sum := sha256.Sum256([]byte(strings.Join(fields, "\x00")))
	return hex.EncodeToString(sum[:])
}

// SessionMCPServers returns the exact redaction-safe descriptor shape sent in
// session/new. It returns no servers unless NTM explicitly supplied the typed
// workspace broker above.
func (r Request) SessionMCPServers() ([]WorkspaceBrokerDescriptor, error) {
	if r.Broker == nil {
		return []WorkspaceBrokerDescriptor{}, nil
	}
	if err := r.Broker.validate(); err != nil {
		return nil, err
	}
	if r.Broker.controller != nil {
		return []WorkspaceBrokerDescriptor{}, nil
	}
	copy := *r.Broker
	copy.args = append([]string(nil), r.Broker.args...)
	return []WorkspaceBrokerDescriptor{copy}, nil
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
	Success     bool      `json:"success"`
	State       string    `json:"state"`
	FailureCode ErrorCode `json:"failure_code,omitempty"`
	// FailureStage is a bounded controller label, never provider text. It lets
	// operators distinguish setup/handshake/tooling failures without retaining
	// stderr, RPC payloads, prompts, paths, or credentials.
	FailureStage          string                         `json:"failure_stage,omitempty"`
	ProtocolFailureReason provider.ProtocolFailureReason `json:"protocol_failure_reason,omitempty"`
	ProtocolObservation   provider.ProtocolObservation   `json:"protocol_observation"`
	// ProviderRPCErrorCode retains only a JSON-RPC integer code. Provider
	// messages and non-integer vendor payloads remain excluded from receipts.
	ProviderRPCErrorCode    *int64 `json:"provider_rpc_error_code,omitempty"`
	ProviderSessionID       string `json:"provider_session_id,omitempty"`
	StopReason              string `json:"stop_reason,omitempty"`
	CompletionConfirmed     bool   `json:"completion_confirmed"`
	AcknowledgementVerified bool   `json:"acknowledgement_verified"`
	AssistantTextChunks     int    `json:"assistant_text_chunks"`
	AssistantTextBytes      int64  `json:"assistant_text_bytes"`
	OutputSHA256            string `json:"output_sha256,omitempty"`
	// ToolEventCount and ToolEventsSHA256 cover only the ACP tool_call and
	// tool_call_update session-update variants. They never include raw tool
	// arguments, results, tool-call IDs, or any other update payload.
	ToolEventCount    int    `json:"tool_event_count"`
	ToolEventsSHA256  string `json:"tool_events_sha256"`
	ToolRequestCount  int    `json:"tool_request_count"`
	ToolCompleteCount int    `json:"tool_complete_count"`
	// NonMessageUpdateCount and NonMessageUpdatesSHA256 retain a redaction-safe
	// name-only sequence of every session/update other than agent_message_chunk,
	// including tool updates and unknown or malformed updates. This prevents
	// lifecycle, usage, plan, and thought updates from being mislabeled as tools.
	NonMessageUpdateCount   int    `json:"non_message_update_count"`
	NonMessageUpdatesSHA256 string `json:"non_message_updates_sha256"`
	Model                   string `json:"model,omitempty"`
	ModelEvidence           string `json:"model_evidence,omitempty"`
	ResolvedModel           string `json:"resolved_model,omitempty"`
	ResolvedModelEvidence   string `json:"resolved_model_evidence,omitempty"`
	// SessionSelectedModel is diagnostic selection state observed before the
	// terminal completion. It must never be treated as proof of the model that
	// actually served the request: a provider can remap after session creation.
	SessionSelectedModel          string `json:"session_selected_model,omitempty"`
	SessionModelSelectionEvidence string `json:"session_model_selection_evidence,omitempty"`
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
	Cancellation             ACPCancellationReceipt            `json:"cancellation"`
	Cleanup                  ProcessCleanupReceipt             `json:"cleanup"`
	Stderr                   StderrDigest                      `json:"stderr"`
	StartedAt                time.Time                         `json:"started_at"`
	CompletedAt              time.Time                         `json:"completed_at"`
	RuntimeEvents            []provider.RuntimeEvent           `json:"runtime_events"`
	RuntimeEventRequirements provider.RuntimeEventRequirements `json:"runtime_event_requirements"`
	RuntimeEventContract     provider.EventContractReport      `json:"runtime_event_contract"`
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
	failureStage := "request_validation"
	defer func() {
		if returnErr != nil && result.FailureStage == "" {
			result.FailureStage = failureStage
		}
	}()
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
	mcpServers, err := req.SessionMCPServers()
	if err != nil {
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
	var controller ControllerBroker
	var controllerServers []controllerMCPRegistration
	controllerID := ""
	controllerToolsEnabled := false
	if req.Broker != nil && req.Broker.controller != nil {
		if req.RuntimeVersion != "1.0.13" {
			return finishFailure(result, ErrInvalidRequest, errors.New("controller MCP requires the reviewed Grok 1.0.13 protocol"))
		}
		failureStage = "process_start"
		controller, err = req.Broker.openController(ctx)
		if err != nil || controller == nil {
			return finishFailure(result, ErrDependencyMissing, errors.New("initialize controller workspace broker"))
		}
		defer func() {
			if err := controller.Close(); err != nil {
				result.Success = false
				result.State = StateFailed
				returnErr = errors.Join(returnErr, errors.New("close controller workspace broker"))
			}
		}()
		controllerID, err = newControllerMCPID()
		if err != nil {
			return finishFailure(result, ErrDependencyMissing, err)
		}
		controllerServers = []controllerMCPRegistration{{Name: WorkspaceBrokerMCPName, ServerID: controllerID}}
	}

	failureStage = "process_start"
	proc, err := runner.Start(ctx, StartSpec{
		Binary:         req.Binary,
		Args:           args,
		CWD:            req.CWD,
		RuntimeHome:    req.RuntimeHome,
		WorkspaceWrite: req.Broker != nil,
	})
	if err != nil {
		return finishFailure(result, ErrDependencyMissing, fmt.Errorf("start grok ACP: %w", err))
	}

	stderrDone := make(chan StderrDigest, 1)
	go func() { stderrDone <- drainAndDigest(proc.Stderr(), MaxStderrCaptureBytes) }()
	events := readRPCEvents(proc.Stdout())
	promptMayHaveBeenAccepted := false
	var updates updateAccumulator

	// Closing stdin and reaping the child is mandatory even after a confirmed
	// reply: this is a one-shot adapter, not a daemon owner. This local cleanup
	// is deliberately recorded separately from any ACP cancellation receipt.
	defer func() {
		observation := updates.protocolObservation
		observation.Stage = failureStage
		observation.Reason = result.ProtocolFailureReason
		observation.ToolEvents = updates.toolEventCount
		observation.ToolRequests = updates.toolRequestCount
		observation.ToolCompletions = updates.toolCompleteCount
		observation.PermissionDenials = updates.permissionDenials
		observation.AssistantTextChunks = updates.chunks
		observation.AssistantTextBytes = updates.bytes
		observation.ReplyBoundaries = updates.replyBoundaries
		observation.AcknowledgementVerified = updates.nonce.verified
		result.ProtocolObservation = observation.Redacted()
		// Preserve counters on every exit, including a protocol failure before
		// the successful-result construction below.
		result.ToolEventCount = updates.toolEventCount
		result.ToolRequestCount = updates.toolRequestCount
		result.ToolCompleteCount = updates.toolCompleteCount
		if req.BeforeCleanup != nil {
			if err := persistBeforeCleanup(req.BeforeCleanup, result.ProtocolObservation); err != nil {
				result.Success = false
				result.State = StateFailed
				returnErr = errors.Join(returnErr, errors.New("ACP pre-cleanup diagnostic persistence failed"))
			}
		}
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
		result.RuntimeEventRequirements = provider.RuntimeEventRequirements{
			ToolLifecycle: req.Broker != nil, CancellationRequested: result.Cancellation.Requested,
		}
		inputTokens, outputTokens, usageObserved := int64(0), int64(0), false
		if result.Usage != nil {
			usageObserved = result.Usage.InputTokens != nil || result.Usage.OutputTokens != nil || result.Usage.TotalTokens != nil
			if result.Usage.InputTokens != nil {
				inputTokens = *result.Usage.InputTokens
			}
			if result.Usage.OutputTokens != nil {
				outputTokens = *result.Usage.OutputTokens
			}
		}
		sessionRef := ""
		if result.ProviderSessionID != "" {
			sessionDigest := sha256.Sum256([]byte(result.ProviderSessionID))
			sessionRef = hex.EncodeToString(sessionDigest[:])
		}
		result.RuntimeEvents = provider.NormalizeTerminalRuntimeObservation(provider.TerminalRuntimeObservation{
			SessionRef: sessionRef, Model: result.Model, ResolvedModel: result.ResolvedModel, Accepted: promptMayHaveBeenAccepted,
			ObservedToolEvents:       updates.runtimeToolEvents,
			CancellationAcknowledged: result.Cancellation.AgentACPAcknowledged,
			Completed:                result.CompletionConfirmed, UsageObserved: usageObserved,
			InputTokens: inputTokens, OutputTokens: outputTokens,
			CleanupObserved:   !result.Cleanup.ObservedAt.IsZero() && result.Cleanup.ResidualPIDs != nil && result.Cleanup.Reaped,
			ResidualProcesses: len(result.Cleanup.ResidualPIDs),
		})
		result.RuntimeEventContract = provider.ValidateRuntimeEventsForModel(strings.TrimSpace(req.Model), result.RuntimeEvents, result.RuntimeEventRequirements)
	}()

	// Once session/prompt has been written, the provider may accept it even if
	// the local response is lost. From that point a timeout is never safe to
	// replay automatically.
	outputHasher := sha256.New()
	updates = newUpdateAccumulator(outputHasher, req.ExpectedNonce, strings.TrimSpace(req.Model))
	updates.denyPermission = func(message rpcMessage) error {
		return denyACPPermission(ctx, proc.Stdin(), updates.providerSessionID, message)
	}
	if controller != nil {
		seen := make(map[string]bool)
		updates.controllerMCP = func(message rpcMessage) error {
			return replyControllerMCP(ctx, proc.Stdin(), controller, controllerID, controllerToolsEnabled, seen, message)
		}
	}
	nextID := 1
	call := func(method string, params any) (json.RawMessage, error) {
		id := nextID
		nextID++
		if err := writeRequest(ctx, proc.Stdin(), id, method, params); err != nil {
			return nil, err
		}
		return waitResponse(ctx, events, id, &updates)
	}

	failureStage = "initialize"
	initRaw, err := call("initialize", initializeParams{
		ProtocolVersion: 1,
		ClientCapabilities: clientCapabilities{
			FS:       fileSystemCapabilities{},
			Terminal: false,
		},
		Meta: initializeMeta{
			StartupHints:  ntmStartupHints(),
			ClientType:    "ntm",
			ClientVersion: "provider-acp-v1",
		},
	})
	if err != nil {
		return contextAwareFailure(result, promptMayHaveBeenAccepted, err)
	}
	var init initializeResult
	if err := json.Unmarshal(initRaw, &init); err != nil {
		return finishFailure(result, ErrProtocol, protocolError(provider.ProtocolInvalidResult))
	}
	methodID, err := selectAuthMethod(init.AuthMethods)
	if err != nil {
		failureStage = "auth_method_selection"
		return finishFailure(result, ErrCachedAuthUnavailable, err)
	}
	cachedTokenAuthenticated := false
	failureStage = "authenticate"
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

	failureStage = "session_new"
	newRaw, err := call("session/new", sessionNewParams{
		CWD: req.CWD, MCPServers: mcpServers,
		Meta: sessionNewMeta{StartupHints: ntmStartupHints(), ModelID: strings.TrimSpace(req.Model), MCPServers: controllerServers},
	})
	if err != nil {
		return contextAwareFailure(result, promptMayHaveBeenAccepted, err)
	}
	var session sessionNewResult
	if err := json.Unmarshal(newRaw, &session); err != nil || strings.TrimSpace(session.SessionID) == "" {
		return finishFailure(result, ErrProtocol, protocolError(provider.ProtocolInvalidResult))
	}
	result.ProviderSessionID = session.SessionID
	updates.providerSessionID = session.SessionID
	sessionConfigModel, sessionConfigModelObserved := sessionConfigExactModel(session.ConfigOptions, strings.TrimSpace(req.Model))
	sessionModelStateModel, sessionModelStateObserved := sessionModelsExactModel(session.Models, strings.TrimSpace(req.Model))

	promptID := nextID
	nextID++
	failureStage = "prompt_write"
	promptMayHaveBeenAccepted, err = writeRequestWithEvidence(ctx, proc.Stdin(), promptID, "session/prompt", sessionPromptParams{
		SessionID: session.SessionID,
		Prompt:    []promptPart{{Type: "text", Text: req.Prompt}},
	})
	if err != nil {
		return contextAwareFailure(result, promptMayHaveBeenAccepted, err)
	}
	invokeAfterPromptWritten(req.AfterPromptWritten)
	controllerToolsEnabled = true
	failureStage = "prompt_response"
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
		return finishFailure(result, ErrProtocol, protocolError(provider.ProtocolInvalidResult))
	}
	failureStage = "completion_metadata"
	promptModel, resolvedModel, usage, err := prompt.completionMetadata()
	if err != nil {
		return finishFailure(result, ErrProtocol, err)
	}
	if strings.TrimSpace(req.RuntimeVersion) != "" && !cancellation.Requested {
		expectedResolvedModel := ExpectedResolvedModel(strings.TrimSpace(req.RuntimeVersion), strings.TrimSpace(req.Model))
		if expectedResolvedModel == "" || resolvedModel != expectedResolvedModel {
			return finishFailure(result, ErrIdentityMismatch, errors.New("ACP terminal provider model does not match the reviewed runtime binding"))
		}
	}
	// Once a terminal response has been matched to the original prompt request,
	// retain only the receipt-safe metadata before deciding whether it was a
	// normal completion or a cancellation acknowledgement.
	result.StopReason = prompt.StopReason
	result.Model = promptModel
	if result.Model != "" {
		// Only terminal completion metadata is served-model evidence. Session
		// selection state is retained separately below and cannot promote an
		// operation because it cannot rule out a provider-side remap.
		result.ModelEvidence = "completion_metadata"
	}
	result.ResolvedModel = resolvedModel
	if result.ResolvedModel != "" {
		result.ResolvedModelEvidence = "completion_metadata.usage.model_usage_singleton"
	}
	switch {
	case updates.sessionModelObserved:
		result.SessionSelectedModel = strings.TrimSpace(req.Model)
		result.SessionModelSelectionEvidence = "provider_session_notification_plus_exact_launch"
	case sessionConfigModelObserved:
		result.SessionSelectedModel = sessionConfigModel
		result.SessionModelSelectionEvidence = "session_config_option_plus_exact_launch"
	case sessionModelStateObserved:
		result.SessionSelectedModel = sessionModelStateModel
		result.SessionModelSelectionEvidence = "session_model_state_plus_exact_launch"
	}
	result.Usage = usage
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
	failureStage = "post_response_updates"
	if err := drainPostResponseUpdates(ctx, events, &updates, postResponseQuietWindow(req.PostResponseQuietWindow)); err != nil {
		return contextAwareFailure(result, promptMayHaveBeenAccepted, err)
	}
	result.CompletionConfirmed = true
	applyUpdateReceipt(&result, &updates, outputHasher)
	if req.ExpectedNonce != "" && !result.AcknowledgementVerified {
		failureStage = "completion_validation"
		return finishFailure(result, ErrAcknowledgementUnconfirmed, errors.New("session/prompt completion omitted the required standalone nonce acknowledgement"))
	}
	result.Success = true
	result.State = StateCompleted
	result.FailureStage = ""
	if cachedTokenAuthenticated {
		result.Authenticated = true
		result.AuthenticationEvidence = "cached_token_authenticate_plus_completed_session"
	}
	return result, nil
}

func invokeAfterPromptWritten(callback func()) {
	if callback == nil {
		return
	}
	defer func() {
		// This hook is deliberately observational/control-plane only. A panic
		// must not turn a successfully written provider request into a broken
		// runner or conceal its outcome from the normal ACP receipt path.
		_ = recover()
	}()
	callback()
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
	result.ToolRequestCount = updates.toolRequestCount
	result.ToolCompleteCount = updates.toolCompleteCount
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
			updates.observeProtocol(event)
			if event.err != nil {
				return event.err
			}
			if event.message.Method == "session/request_permission" && updates.denyPermission != nil {
				if err := updates.denyPermission(event.message); err != nil {
					return err
				}
				updates.permissionDenials++
				continue
			}
			if event.message.Method != "" && len(event.message.ID) != 0 {
				return protocolError(provider.ProtocolUnexpectedRequest)
			}
			if isBenignACPNotification(event.message) {
				if err := updates.observeVendorNotification(event.message.Method, event.message.Params); err != nil {
					return err
				}
				continue
			}
			if event.message.Method != "session/update" {
				if event.message.Method == "" {
					return protocolError(provider.ProtocolResponseIDMismatch)
				}
				return protocolError(provider.ProtocolUnknownMethod)
			}
			if err := updates.observe(event.message.Params); err != nil {
				return err
			}
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
	result.ProtocolFailureReason = protocolReason(err, code)
	result.ProviderRPCErrorCode = providerRPCErrorCode(err)
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
	result.ProtocolFailureReason = protocolReason(err, code)
	result.ProviderRPCErrorCode = providerRPCErrorCode(err)
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

func protocolReason(err error, code ErrorCode) provider.ProtocolFailureReason {
	var failure *protocolFailure
	if errors.As(err, &failure) && failure.reason != "" && failure.reason.Valid() {
		return failure.reason
	}
	if code != ErrProtocol {
		return ""
	}
	if errors.Is(err, io.EOF) {
		return provider.ProtocolStreamClosed
	}
	return provider.ProtocolOther
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
	ProtocolVersion    int                `json:"protocolVersion"`
	ClientCapabilities clientCapabilities `json:"clientCapabilities"`
	Meta               initializeMeta     `json:"_meta"`
}

// NTM deliberately does not advertise ACP reverse filesystem or terminal
// services. Grok receives all workspace authority through the typed MCP broker
// instead. Explicit false values keep the capability boundary unambiguous.
type clientCapabilities struct {
	FS       fileSystemCapabilities `json:"fs"`
	Terminal bool                   `json:"terminal"`
}

type fileSystemCapabilities struct {
	ReadTextFile  bool `json:"readTextFile"`
	WriteTextFile bool `json:"writeTextFile"`
}

type grokStartupHints struct {
	NonInteractive    bool `json:"nonInteractive"`
	SkipGitStatus     bool `json:"skipGitStatus"`
	SkipProjectLayout bool `json:"skipProjectLayout"`
}

func ntmStartupHints() grokStartupHints {
	return grokStartupHints{NonInteractive: true, SkipGitStatus: true, SkipProjectLayout: true}
}

type initializeMeta struct {
	StartupHints  grokStartupHints `json:"startupHints"`
	ClientType    string           `json:"clientType"`
	ClientVersion string           `json:"clientVersion"`
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
	CWD        string                      `json:"cwd"`
	MCPServers []WorkspaceBrokerDescriptor `json:"mcpServers"`
	Meta       sessionNewMeta              `json:"_meta"`
}

type sessionNewMeta struct {
	MCPServers   []controllerMCPRegistration `json:"x.ai/mcp/servers,omitempty"`
	StartupHints grokStartupHints            `json:"startupHints"`
	ModelID      string                      `json:"modelId,omitempty"`
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
	StopReason string                `json:"stopReason"`
	Model      string                `json:"model"`
	Usage      promptUsage           `json:"usage"`
	Meta       sessionPromptMetadata `json:"_meta"`
}

type sessionPromptMetadata struct {
	ModelID string              `json:"modelId"`
	Usage   promptMetadataUsage `json:"usage"`
}

type promptMetadataUsage struct {
	InputTokens         *int64                     `json:"inputTokens"`
	OutputTokens        *int64                     `json:"outputTokens"`
	TotalTokens         *int64                     `json:"totalTokens"`
	CachedReadTokens    *int64                     `json:"cachedReadTokens"`
	CacheCreationTokens *int64                     `json:"cacheCreationTokens"`
	ReasoningTokens     *int64                     `json:"reasoningTokens"`
	ModelCalls          *int64                     `json:"modelCalls"`
	NumTurns            *int64                     `json:"numTurns"`
	APIDurationMS       *int64                     `json:"apiDurationMs"`
	CostUSDTicks        *int64                     `json:"costUsdTicks"`
	ModelUsage          map[string]json.RawMessage `json:"modelUsage"`
}

// Usage records only provider-supplied counters. Nil means the corresponding
// counter was absent, rather than falsely asserting a zero value.
type Usage struct {
	InputTokens         *int64 `json:"input_tokens,omitempty"`
	OutputTokens        *int64 `json:"output_tokens,omitempty"`
	TotalTokens         *int64 `json:"total_tokens,omitempty"`
	CachedReadTokens    *int64 `json:"cached_read_tokens,omitempty"`
	CacheCreationTokens *int64 `json:"cache_creation_tokens,omitempty"`
	ReasoningTokens     *int64 `json:"reasoning_tokens,omitempty"`
	ModelCalls          *int64 `json:"model_calls,omitempty"`
	NumTurns            *int64 `json:"num_turns,omitempty"`
	APIDurationMS       *int64 `json:"api_duration_ms,omitempty"`
	CostUSDTicks        *int64 `json:"cost_usd_ticks,omitempty"`
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

func (p sessionPromptResult) completionMetadata() (string, string, *Usage, error) {
	topLevelModel := strings.TrimSpace(p.Model)
	metaModel := strings.TrimSpace(p.Meta.ModelID)
	if topLevelModel != "" && metaModel != "" && topLevelModel != metaModel {
		return "", "", nil, errors.New("ACP terminal completion reported conflicting model identifiers")
	}
	model := firstNonEmpty(topLevelModel, metaModel)
	if len(model) > 4096 || strings.IndexFunc(model, unicode.IsControl) >= 0 {
		return "", "", nil, errors.New("ACP terminal completion reported an invalid model identifier")
	}
	resolvedModel, err := p.Meta.Usage.resolvedModel()
	if err != nil {
		return "", "", nil, err
	}
	usage, err := mergePromptUsage(p.Usage.canonical(), p.Meta.Usage.canonical())
	if err != nil {
		return "", "", nil, err
	}
	return model, resolvedModel, usage, nil
}

func (u promptMetadataUsage) resolvedModel() (string, error) {
	if len(u.ModelUsage) == 0 {
		return "", nil
	}
	if len(u.ModelUsage) != 1 {
		return "", errors.New("ACP terminal completion reported multiple provider models")
	}
	for model := range u.ModelUsage {
		model = strings.TrimSpace(model)
		if model == "" || len(model) > 4096 || strings.IndexFunc(model, unicode.IsControl) >= 0 {
			return "", errors.New("ACP terminal completion reported an invalid resolved model")
		}
		return model, nil
	}
	return "", nil
}

func (u promptMetadataUsage) canonical() *Usage {
	usage := &Usage{
		InputTokens: cloneInt64Pointer(u.InputTokens), OutputTokens: cloneInt64Pointer(u.OutputTokens), TotalTokens: cloneInt64Pointer(u.TotalTokens),
		CachedReadTokens: cloneInt64Pointer(u.CachedReadTokens), CacheCreationTokens: cloneInt64Pointer(u.CacheCreationTokens), ReasoningTokens: cloneInt64Pointer(u.ReasoningTokens),
		ModelCalls: cloneInt64Pointer(u.ModelCalls), NumTurns: cloneInt64Pointer(u.NumTurns), APIDurationMS: cloneInt64Pointer(u.APIDurationMS), CostUSDTicks: cloneInt64Pointer(u.CostUSDTicks),
	}
	if usage.InputTokens == nil && usage.OutputTokens == nil && usage.TotalTokens == nil && usage.CachedReadTokens == nil && usage.CacheCreationTokens == nil && usage.ReasoningTokens == nil && usage.ModelCalls == nil && usage.NumTurns == nil && usage.APIDurationMS == nil && usage.CostUSDTicks == nil {
		return nil
	}
	return usage
}

func mergePromptUsage(primary, metadata *Usage) (*Usage, error) {
	if primary == nil {
		return metadata, nil
	}
	if metadata == nil {
		return primary, nil
	}
	for _, pair := range [][2]*int64{{primary.InputTokens, metadata.InputTokens}, {primary.OutputTokens, metadata.OutputTokens}, {primary.TotalTokens, metadata.TotalTokens}} {
		if pair[0] != nil && pair[1] != nil && *pair[0] != *pair[1] {
			return nil, errors.New("ACP terminal completion reported conflicting usage counters")
		}
	}
	merged := *metadata
	if merged.InputTokens == nil {
		merged.InputTokens = cloneInt64Pointer(primary.InputTokens)
	}
	if merged.OutputTokens == nil {
		merged.OutputTokens = cloneInt64Pointer(primary.OutputTokens)
	}
	if merged.TotalTokens == nil {
		merged.TotalTokens = cloneInt64Pointer(primary.TotalTokens)
	}
	return &merged, nil
}

func cloneInt64Pointer(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
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
				events <- rpcEvent{err: protocolError(provider.ProtocolMalformedMessage)}
				return
			}
			if message.JSONRPC != "2.0" {
				events <- rpcEvent{err: protocolError(provider.ProtocolInvalidVersion)}
				return
			}
			events <- rpcEvent{message: message}
		}
		if err := scanner.Err(); err != nil {
			events <- rpcEvent{err: protocolError(provider.ProtocolStreamRead)}
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
	updates.observeProtocol(event)
	if event.err != nil {
		return nil, false, event.err
	}
	if event.message.Method == controllerMCPMethod && updates != nil && updates.controllerMCP != nil {
		return nil, false, updates.controllerMCP(event.message)
	}
	if event.message.Method == "session/request_permission" && updates != nil && updates.denyPermission != nil {
		if err := updates.denyPermission(event.message); err != nil {
			return nil, false, err
		}
		updates.permissionDenials++
		return nil, false, nil
	}
	if event.message.Method != "" && len(event.message.ID) != 0 {
		return nil, false, protocolError(provider.ProtocolUnexpectedRequest)
	}
	if event.message.Method == "session/update" {
		if err := updates.observe(event.message.Params); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}
	if isBenignACPNotification(event.message) {
		if err := updates.observeVendorNotification(event.message.Method, event.message.Params); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}
	if event.message.Method != "" {
		return nil, false, protocolError(provider.ProtocolUnknownMethod)
	}
	wantID := fmt.Sprintf("%d", requestID)
	if string(event.message.ID) != wantID {
		return nil, false, protocolError(provider.ProtocolResponseIDMismatch)
	}
	if event.message.Error != nil {
		return nil, false, &providerError{message: event.message.Error.Message, code: parseRPCErrorCode(event.message.Error.Code)}
	}
	if len(event.message.Result) == 0 {
		return nil, false, protocolError(provider.ProtocolMissingResult)
	}
	return event.message.Result, true, nil
}

// grokV1013BenignNotifications is pinned to xai-org/grok-build commit
// bb7f39d5858cbf5e00de639367f59debbdcb0138. Runtime upgrades must update this
// list and its protocol fixtures deliberately.
var grokV1013BenignNotifications = map[string]struct{}{
	"x.ai/announcements/update":    {},
	"x.ai/git/worktree/status":     {},
	"x.ai/git_head_changed":        {},
	"x.ai/mcp/init_progress":       {},
	"x.ai/mcp/server_status":       {},
	"x.ai/mcp/servers_updated":     {},
	"x.ai/mcp/tools_changed":       {},
	"x.ai/mcp_initialized":         {},
	"x.ai/models/update":           {},
	"x.ai/queue/changed":           {},
	"x.ai/session/models/update":   {},
	"x.ai/session/prompt_complete": {},
	"x.ai/session_notification":    {},
	"x.ai/sessions/changed":        {},
	"x.ai/settings/update":         {},
}

// isBenignACPNotification recognizes only the reviewed notification methods
// emitted by the pinned Grok 1.0.13 runtime. ACP's underscore-prefixed vendor
// envelope is accepted for the same exact methods, never as a namespace
// wildcard. Messages with request IDs, permission prompts, task/scheduler
// events, and unknown methods continue to fail closed.
func isBenignACPNotification(message rpcMessage) bool {
	if len(message.ID) != 0 {
		return false
	}
	method := message.Method
	if strings.HasPrefix(method, "_x.ai/") {
		method = strings.TrimPrefix(method, "_")
	}
	_, ok := grokV1013BenignNotifications[method]
	return ok
}

type providerError struct {
	message string
	code    *int64
}

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

func parseRPCErrorCode(raw json.RawMessage) *int64 {
	var code int64
	if len(raw) == 0 || json.Unmarshal(raw, &code) != nil {
		return nil
	}
	return &code
}

func providerRPCErrorCode(err error) *int64 {
	var provider *providerError
	if !errors.As(err, &provider) || provider == nil || provider.code == nil {
		return nil
	}
	code := *provider.code
	return &code
}

type updateAccumulator struct {
	denyPermission         func(rpcMessage) error
	controllerMCP          func(rpcMessage) error
	permissionDenials      int
	protocolObservation    provider.ProtocolObservation
	hasher                 io.Writer
	chunks                 int
	bytes                  int64
	nonce                  nonceMatcher
	replyBoundaries        int
	toolEventHasher        hash.Hash
	toolEventCount         int
	toolRequestCount       int
	toolCompleteCount      int
	runtimeToolEvents      []provider.RuntimeEvent
	toolCalls              map[string]acpToolCall
	nonMessageUpdateHasher hash.Hash
	nonMessageUpdateCount  int
	expectedModel          string
	sessionModelObserved   bool
	providerSessionID      string
}

// denyACPPermission implements only reject_once from ACP schema 0.11.4's
// RequestPermissionResponse/SelectedPermissionOutcome. No option is approved,
// no remembered permission is created, and no provider tool is executed here.
func denyACPPermission(ctx context.Context, writer io.Writer, session string, message rpcMessage) error {
	if len(message.ID) == 0 || string(message.ID) == "null" {
		return protocolError(provider.ProtocolUnexpectedRequest)
	}
	var numericID int64
	var stringID string
	if json.Unmarshal(message.ID, &numericID) != nil && json.Unmarshal(message.ID, &stringID) != nil {
		return protocolError(provider.ProtocolMalformedMessage)
	}
	var request struct {
		SessionID string `json:"sessionId"`
		ToolCall  struct {
			ID string `json:"toolCallId"`
		} `json:"toolCall"`
		Options []struct {
			ID   string `json:"optionId"`
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"options"`
	}
	if json.Unmarshal(message.Params, &request) != nil || request.ToolCall.ID == "" || request.Options == nil {
		return protocolError(provider.ProtocolMalformedMessage)
	}
	if session == "" || request.SessionID != session {
		return protocolError(provider.ProtocolSessionMismatch)
	}
	selected := ""
	seen := map[string]bool{}
	for _, option := range request.Options {
		if option.ID == "" || seen[option.ID] {
			return protocolError(provider.ProtocolMalformedMessage)
		}
		seen[option.ID] = true
		switch option.Kind {
		case "allow_once", "allow_always", "reject_always":
		case "reject_once":
			if selected == "" {
				selected = option.ID
			}
		default:
			return protocolError(provider.ProtocolMalformedMessage)
		}
	}
	outcome := map[string]string{"outcome": "selected", "optionId": selected}
	if ctx.Err() != nil {
		// ACP requires pending permission requests to receive cancelled when
		// their prompt is cancelled. This never grants or remembers permission.
		outcome = map[string]string{"outcome": "cancelled"}
	} else if selected == "" {
		return protocolError(provider.ProtocolUnexpectedRequest)
	}
	payload, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  any             `json:"result"`
	}{"2.0", message.ID, map[string]any{"outcome": outcome}})
	if err != nil {
		return protocolError(provider.ProtocolMalformedMessage)
	}
	payload = append(payload, '\n')
	written, err := writer.Write(payload)
	if err != nil {
		return errors.New("ACP permission denial write failed")
	}
	if written != len(payload) {
		return io.ErrShortWrite
	}
	return nil
}

func persistBeforeCleanup(callback func(provider.ProtocolObservation) error, observation provider.ProtocolObservation) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("diagnostic callback panicked")
		}
	}()
	return callback(observation)
}

func (a *updateAccumulator) observeProtocol(event rpcEvent) {
	if a == nil {
		return
	}
	o := provider.ProtocolObservation{Method: event.message.Method, RequestIDKind: "present", SessionMatch: "absent"}
	if o.Method == "" {
		o.Method = "absent"
	}
	if len(event.message.ID) == 0 {
		o.RequestIDKind = "absent"
	} else if string(event.message.ID) == "null" {
		o.RequestIDKind = "null"
	}
	// Inspect only the documented carrier. Values are compared transiently
	// and are never retained, including values inside vendor envelopes.
	params := event.message.Params
	if isBenignACPNotification(rpcMessage{Method: event.message.Method}) {
		if unwrapped, err := directOrWrappedVendorParams(event.message.Method, strings.TrimPrefix(event.message.Method, "_"), params); err == nil {
			params = unwrapped
		}
	}
	if len(params) != 0 {
		var fields map[string]json.RawMessage
		if json.Unmarshal(params, &fields) != nil {
			o.SessionMatch = "malformed"
		} else if raw, exists := fields["sessionId"]; exists {
			var session string
			if json.Unmarshal(raw, &session) != nil || session == "" {
				o.SessionMatch = "malformed"
			} else if a.providerSessionID == "" {
				o.SessionMatch = "unbound"
			} else if session == a.providerSessionID {
				o.SessionMatch = "match"
			} else {
				o.SessionMatch = "mismatch"
			}
		}
	}
	a.protocolObservation = o.Redacted()
}

func newUpdateAccumulator(hasher io.Writer, nonce, expectedModel string) updateAccumulator {
	return updateAccumulator{
		hasher: hasher, nonce: newNonceMatcher(nonce), toolEventHasher: sha256.New(), nonMessageUpdateHasher: sha256.New(),
		expectedModel: strings.TrimSpace(expectedModel), toolCalls: make(map[string]acpToolCall),
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

// observeVendorNotification records reviewed vendor lifecycle traffic without
// treating it as completion evidence. Session-scoped carriers must bind to the
// active provider session before their update names enter the receipt. The one
// legacy model-selection notification remains secondary evidence only and can
// never replace terminal served-model metadata.
func (a *updateAccumulator) observeVendorNotification(method string, params json.RawMessage) error {
	if a == nil {
		return errors.New("ACP vendor notification accumulator is unavailable")
	}
	canonical := strings.TrimPrefix(method, "_")
	switch canonical {
	case "x.ai/session_notification":
		payload, err := directOrWrappedVendorParams(method, canonical, params)
		if err != nil {
			return err
		}
		var notification struct {
			SessionID string `json:"sessionId"`
			Update    struct {
				SessionUpdate string `json:"sessionUpdate"`
			} `json:"update"`
		}
		if err := json.Unmarshal(payload, &notification); err != nil || notification.SessionID == "" || notification.Update.SessionUpdate == "" {
			return protocolError(provider.ProtocolMalformedSessionUpdate)
		}
		if a.providerSessionID == "" || notification.SessionID != a.providerSessionID {
			return nil
		}
		// Reviewed sampling_events.rs emits this marker before the response's
		// first text chunk. Clearing a candidate cannot manufacture an ACK.
		if notification.Update.SessionUpdate == "response_started" {
			a.resetReplyCandidate()
		}
		// xAI's SessionUpdate is distinct from the standard ACP update enum.
		// Retain only its redacted name; this carrier must never manufacture
		// assistant acknowledgements or authoritative tool lifecycle events.
		a.recordNonMessageUpdate("xai_session_" + notification.Update.SessionUpdate)
		return nil
	case "x.ai/session/prompt_complete":
		payload, err := directOrWrappedVendorParams(method, canonical, params)
		if err != nil {
			return err
		}
		var notification struct {
			SessionID string `json:"sessionId"`
		}
		if err := json.Unmarshal(payload, &notification); err != nil || notification.SessionID == "" {
			return protocolError(provider.ProtocolMalformedSessionUpdate)
		}
		if a.providerSessionID != "" && notification.SessionID == a.providerSessionID {
			a.recordNonMessageUpdate("xai_session_prompt_complete")
		}
		return nil
	case "x.ai/session/models/update":
		if method != grokSessionModelNotification || a.expectedModel == "" || a.providerSessionID == "" {
			return nil
		}
		var notification grokSessionModelNotificationParams
		if err := json.Unmarshal(params, &notification); err != nil {
			return nil
		}
		if notification.SessionID == a.providerSessionID && notification.Model == a.expectedModel {
			a.sessionModelObserved = true
		}
		return nil
	default:
		a.recordNonMessageUpdate("xai_housekeeping_" + strings.ReplaceAll(canonical, "/", "_"))
		return nil
	}
}

// directOrWrappedVendorParams accepts the flat payload emitted by pinned
// agent-client-protocol 0.10.4 / schema 0.11.4 (ExtNotification is serde
// transparent), including with the `_` method prefix. Grok's leader fixtures
// also describe a nested envelope. An explicit envelope must bind its inner
// method exactly; it cannot smuggle a different event type.
func directOrWrappedVendorParams(method, canonical string, params json.RawMessage) (json.RawMessage, error) {
	if method == canonical {
		return params, nil
	}
	if method != "_"+canonical {
		return nil, protocolError(provider.ProtocolUnknownMethod)
	}
	var envelope struct {
		Method json.RawMessage `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(params, &envelope); err != nil {
		return nil, protocolError(provider.ProtocolMalformedEnvelope)
	}
	if len(envelope.Method) == 0 && len(envelope.Params) == 0 {
		return params, nil
	}
	var innerMethod string
	if err := json.Unmarshal(envelope.Method, &innerMethod); err != nil || innerMethod == "" || len(envelope.Params) == 0 {
		return nil, protocolError(provider.ProtocolMalformedEnvelope)
	}
	if innerMethod != canonical {
		return nil, protocolError(provider.ProtocolEnvelopeMethodMismatch)
	}
	return envelope.Params, nil
}

func (a *updateAccumulator) observe(params json.RawMessage) error {
	var envelope struct {
		SessionID string `json:"sessionId"`
		Update    struct {
			SessionUpdate string          `json:"sessionUpdate"`
			ToolCallID    string          `json:"toolCallId"`
			Status        json.RawMessage `json:"status"`
			// ACP message chunks use a content object; tool calls/updates use
			// an array of ToolCallContent. Decode only the selected variant so a
			// valid tool result array cannot discard its terminal status.
			Content json.RawMessage `json:"content"`
		} `json:"update"`
	}
	if json.Unmarshal(params, &envelope) != nil {
		a.recordNonMessageUpdate("unknown")
		return nil
	}
	if a.providerSessionID != "" && envelope.SessionID != "" && envelope.SessionID != a.providerSessionID {
		return protocolError(provider.ProtocolSessionMismatch)
	}
	if envelope.Update.SessionUpdate != "agent_message_chunk" {
		name := envelope.Update.SessionUpdate
		if name == "" {
			name = "unknown"
		}
		a.recordNonMessageUpdate(name)
		if name == "tool_call" || name == "tool_call_update" {
			if err := a.recordToolEvent(name, envelope.Update.ToolCallID, envelope.Update.Status); err != nil {
				return err
			}
		}
		return nil
	}
	var content struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(envelope.Update.Content, &content) != nil {
		return protocolError(provider.ProtocolMalformedSessionUpdate)
	}
	if content.Text == "" {
		return nil
	}
	_, _ = io.WriteString(a.hasher, content.Text)
	a.nonce.WriteString(content.Text)
	a.chunks++
	a.bytes += int64(len(content.Text))
	return nil
}

type acpToolCall struct {
	ref      string
	terminal bool
}

func (a *updateAccumulator) recordToolEvent(name, toolCallID string, rawStatus json.RawMessage) error {
	if a == nil {
		return errors.New("ACP tool lifecycle accumulator is unavailable")
	}
	key, err := acpToolCallKey(toolCallID)
	if err != nil {
		return err
	}
	switch name {
	case "tool_call":
		if _, exists := a.toolCalls[key]; exists {
			return protocolError(provider.ProtocolInvalidToolLifecycle)
		}
		a.toolRequestCount++
		a.resetReplyCandidate()
		ref := fmt.Sprintf("tool-%06d", a.toolRequestCount)
		a.toolCalls[key] = acpToolCall{ref: ref}
		a.runtimeToolEvents = append(a.runtimeToolEvents, provider.RuntimeEvent{
			Type: provider.EventToolRequested, Tool: ref,
		})
	case "tool_call_update":
		status, present, err := acpToolStatus(rawStatus)
		if err != nil {
			return err
		}
		if !present || status == "pending" || status == "in_progress" {
			break
		}
		call, exists := a.toolCalls[key]
		if !exists {
			return protocolError(provider.ProtocolInvalidToolLifecycle)
		}
		if call.terminal {
			return protocolError(provider.ProtocolInvalidToolLifecycle)
		}
		call.terminal = true
		a.resetReplyCandidate()
		a.toolCalls[key] = call
		// EventToolCompleted means the requested tool reached a terminal state,
		// not that it succeeded. Provider-specific evidence retains the outcome;
		// the shared contract uses this event to close the request lifecycle for
		// completed, failed, and policy-denied calls alike.
		a.toolCompleteCount++
		a.runtimeToolEvents = append(a.runtimeToolEvents, provider.RuntimeEvent{
			Type: provider.EventToolCompleted, Tool: call.ref,
		})
	default:
		return protocolError(provider.ProtocolInvalidToolLifecycle)
	}
	a.recordUpdateName(a.toolEventHasher, &a.toolEventCount, name)
	return nil
}

// ACP chunks from separate model responses need not contain a separating
// newline. A tool transition ends the earlier reply; only subsequent assistant
// text may acknowledge the finished assignment. Output hashes still cover all
// text, and tool contents never enter this candidate.
func (a *updateAccumulator) resetReplyCandidate() {
	a.nonce = newNonceMatcher(a.nonce.needle)
	a.replyBoundaries++
}

func acpToolCallKey(toolCallID string) (string, error) {
	if toolCallID == "" || len(toolCallID) > 512 || strings.IndexFunc(toolCallID, unicode.IsControl) >= 0 {
		return "", protocolError(provider.ProtocolInvalidToolLifecycle)
	}
	// The raw provider ID is used only while parsing this notification. The
	// accumulator keeps a digest key and receipts expose only synthetic refs.
	sum := sha256.Sum256([]byte(toolCallID))
	return hex.EncodeToString(sum[:]), nil
}

func acpToolStatus(raw json.RawMessage) (string, bool, error) {
	if len(raw) == 0 {
		return "", false, nil
	}
	var status string
	if err := json.Unmarshal(raw, &status); err != nil || status == "" {
		return "", false, protocolError(provider.ProtocolInvalidToolLifecycle)
	}
	switch status {
	case "pending", "in_progress", "completed", "failed":
		return status, true, nil
	default:
		return "", false, protocolError(provider.ProtocolInvalidToolLifecycle)
	}
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
		"TMPDIR", "TMP", "TEMP",
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

// IsolatedProcessEnvironment returns the only environment accepted by live
// Grok automation. It deliberately replaces HOME/XDG state and disables every
// documented Claude/Cursor compatibility scanner so an ambient profile cannot
// add tools, hooks, rules, agents, or credentials. Project configuration is
// separately rejected by the live `grok inspect --json` authority check.
func IsolatedProcessEnvironment(environ []string, runtimeHome string, workspaceWrite bool) ([]string, error) {
	runtimeHome = filepath.Clean(strings.TrimSpace(runtimeHome))
	if !filepath.IsAbs(runtimeHome) || runtimeHome == "." || len(runtimeHome) > 4096 || strings.IndexFunc(runtimeHome, unicode.IsControl) >= 0 {
		return nil, errors.New("Grok runtime home must be an absolute isolated path")
	}
	base := minimalGrokEnvironment(environ)
	overrides := map[string]string{
		"HOME":                       runtimeHome,
		"USERPROFILE":                runtimeHome,
		"XDG_CONFIG_HOME":            filepath.Join(runtimeHome, ".xdg-config"),
		"XDG_CACHE_HOME":             filepath.Join(runtimeHome, ".cache"),
		"XDG_DATA_HOME":              filepath.Join(runtimeHome, ".local", "share"),
		"GROK_HOME":                  runtimeHome,
		"GROK_DISABLE_AUTOUPDATER":   "1",
		"GROK_MEMORY":                "0",
		"GROK_SUBAGENTS":             "0",
		"GROK_TOOL_SEARCH":           "0",
		"GROK_LSP_TOOLS":             "0",
		"GROK_CURSOR_SKILLS_ENABLED": "0",
		"GROK_CURSOR_RULES_ENABLED":  "0",
		"GROK_CURSOR_AGENTS_ENABLED": "0",
		"GROK_CURSOR_MCPS_ENABLED":   "0",
		"GROK_CURSOR_HOOKS_ENABLED":  "0",
		"GROK_CLAUDE_SKILLS_ENABLED": "0",
		"GROK_CLAUDE_RULES_ENABLED":  "0",
		"GROK_CLAUDE_AGENTS_ENABLED": "0",
		"GROK_CLAUDE_MCPS_ENABLED":   "0",
		"GROK_CLAUDE_HOOKS_ENABLED":  "0",
	}
	// Workspace mutations are available only through the typed NTM MCP
	// broker. Grok's built-in write surface remains disabled in every mode.
	overrides["GROK_WRITE_FILE"] = "0"
	_ = workspaceWrite

	order := []string{
		"PATH", "TMPDIR", "TMP", "TEMP", "SystemRoot", "WINDIR", "ComSpec", "PATHEXT",
		"HOME", "USERPROFILE", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "GROK_HOME",
		"GROK_DISABLE_AUTOUPDATER", "GROK_MEMORY", "GROK_SUBAGENTS", "GROK_WRITE_FILE", "GROK_TOOL_SEARCH", "GROK_LSP_TOOLS",
		"GROK_CURSOR_SKILLS_ENABLED", "GROK_CURSOR_RULES_ENABLED", "GROK_CURSOR_AGENTS_ENABLED", "GROK_CURSOR_MCPS_ENABLED", "GROK_CURSOR_HOOKS_ENABLED",
		"GROK_CLAUDE_SKILLS_ENABLED", "GROK_CLAUDE_RULES_ENABLED", "GROK_CLAUDE_AGENTS_ENABLED", "GROK_CLAUDE_MCPS_ENABLED", "GROK_CLAUDE_HOOKS_ENABLED",
	}
	values := make(map[string]string, len(base)+len(overrides))
	for _, entry := range base {
		name, value, ok := strings.Cut(entry, "=")
		if ok {
			values[name] = value
		}
	}
	for name, value := range overrides {
		values[name] = value
	}
	result := make([]string, 0, len(order))
	for _, name := range order {
		if value, ok := values[name]; ok {
			result = append(result, name+"="+value)
		}
	}
	return result, nil
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
