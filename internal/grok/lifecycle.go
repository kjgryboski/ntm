package grok

// This file owns the narrow, headless session lifecycle contract.  ACP is the
// preferred one-shot transport; the CLI session store is deliberately a
// separate transport because its receipts are not ACP receipts.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

const HeadlessStreamingJSON = "streaming-json"

// SessionAction names the only two persistent-session transitions supported
// by the Grok CLI.  Fork is always a resume with --fork-session, never an
// attempt to clone files or session records ourselves.
type SessionAction string

const (
	SessionResume SessionAction = "resume"
	SessionFork   SessionAction = "fork"
)

// SessionRequest never includes credentials.  ExpectedNonce is included in
// the outgoing prompt by the caller, but only its hash is retained below.
type SessionRequest struct {
	Action        SessionAction
	SessionID     string
	Prompt        string
	CWD           string
	Binary        string
	Model         string
	ExpectedNonce string
	PolicyArgs    []string
}

// SessionReceipt is deliberately redacted.  A CLI-reported session ID is
// represented only by its digest so durable storage does not become a session
// discovery mechanism.
type SessionReceipt struct {
	Action               SessionAction       `json:"action"`
	ParentSessionSHA256  string              `json:"parent_session_sha256"`
	ChildSessionSHA256   string              `json:"child_session_sha256,omitempty"`
	NonceSHA256          string              `json:"nonce_sha256,omitempty"`
	LineageBound         bool                `json:"lineage_bound"`
	ProviderAcknowledged bool                `json:"provider_acknowledged"`
	CompletionConfirmed  bool                `json:"completion_confirmed"`
	StopReason           string              `json:"stop_reason,omitempty"`
	Model                string              `json:"model,omitempty"`
	ModelEvidence        string              `json:"model_evidence,omitempty"`
	Usage                *Usage              `json:"usage,omitempty"`
	OutputSHA256         string              `json:"output_sha256,omitempty"`
	Stderr               StderrDigest        `json:"stderr"`
	ExitCode             *int                `json:"exit_code,omitempty"`
	Cancellation         CancellationReceipt `json:"cancellation"`
}

// BuildSessionSpec compiles a native headless resume/fork command.  The
// caller must run it through its own durable operation store and parse a
// structured response before treating a transition as complete.
func BuildSessionSpec(req SessionRequest) (StartSpec, SessionReceipt, error) {
	if req.Action != SessionResume && req.Action != SessionFork {
		return StartSpec{}, SessionReceipt{}, errors.New("Grok session action must be resume or fork")
	}
	if strings.TrimSpace(req.SessionID) == "" || strings.TrimSpace(req.Prompt) == "" || strings.TrimSpace(req.CWD) == "" {
		return StartSpec{}, SessionReceipt{}, errors.New("Grok session id, prompt, and cwd are required")
	}
	if len(req.SessionID) > 4096 || strings.IndexFunc(req.SessionID, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return StartSpec{}, SessionReceipt{}, errors.New("Grok session id is invalid")
	}
	if len(req.Prompt) > MaxProtocolLineBytes {
		return StartSpec{}, SessionReceipt{}, errors.New("Grok lifecycle prompt exceeded the size limit")
	}
	if req.ExpectedNonce != "" && !ValidNonce(req.ExpectedNonce) {
		return StartSpec{}, SessionReceipt{}, errors.New("Grok lifecycle nonce is invalid")
	}
	if req.Binary == "" {
		req.Binary = "grok"
	}
	if len(req.PolicyArgs) == 0 {
		req.PolicyArgs = defaultReadOnlyAutomationPolicyArgs()
	}
	if err := validateAutomationPolicyArgs(req.PolicyArgs); err != nil {
		return StartSpec{}, SessionReceipt{}, err
	}
	args := []string{"--no-auto-update"}
	args = append(args, req.PolicyArgs...)
	if strings.TrimSpace(req.Model) != "" {
		if strings.IndexFunc(req.Model, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return StartSpec{}, SessionReceipt{}, errors.New("Grok model contains a control character")
		}
		args = append(args, "--model", req.Model)
	}
	args = append(args, "-p", req.Prompt, "--output-format", HeadlessStreamingJSON, "--resume", req.SessionID, "--cwd", req.CWD)
	if req.Action == SessionFork {
		args = append(args, "--fork-session")
	}
	receipt := SessionReceipt{Action: req.Action, ParentSessionSHA256: lifecycleHash(req.SessionID), NonceSHA256: lifecycleHash(req.ExpectedNonce)}
	return StartSpec{Binary: req.Binary, Args: args, CWD: req.CWD}, receipt, nil
}

// BindSessionLineage accepts only a child ID that differs from the resumed
// parent.  It is used after a structured CLI completion has bound the same
// nonce to the returned child session.  Empty and same-ID fork results are not
// evidence of a fork.
func BindSessionLineage(receipt SessionReceipt, childSessionID string, nonceAcknowledged bool) (SessionReceipt, error) {
	if strings.TrimSpace(childSessionID) == "" {
		return receipt, errors.New("Grok lifecycle completion omitted child session id")
	}
	childHash := lifecycleHash(childSessionID)
	if receipt.Action == SessionFork && childHash == receipt.ParentSessionSHA256 {
		return receipt, errors.New("Grok fork returned the parent session id")
	}
	if !nonceAcknowledged {
		return receipt, errors.New("Grok lifecycle completion did not acknowledge its nonce")
	}
	receipt.ChildSessionSHA256 = childHash
	receipt.ProviderAcknowledged = true
	receipt.LineageBound = true
	return receipt, nil
}

func lifecycleHash(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// CancellationReceipt keeps local termination separate from any provider
// acknowledgement.  Killing a local child is never evidence that xAI cancelled
// an already accepted request.
type CancellationReceipt struct {
	ProviderAcknowledged bool      `json:"provider_acknowledged"`
	LocalTermination     string    `json:"local_termination"`
	ResidualPIDs         []int32   `json:"residual_pids"`
	ObservedAt           time.Time `json:"observed_at"`
}

// LifecycleProcess is the one-shot headless-process boundary. PID is required
// so cancellation can use the reviewed observed-tree verifier rather than
// equating a killed parent with provider cancellation.
type LifecycleProcess interface {
	Stdout() io.Reader
	Stderr() io.Reader
	Wait() error
	PID() int32
}
type LifecycleRunner interface {
	Start(context.Context, StartSpec) (LifecycleProcess, error)
}

// HeadlessOSRunner executes native Grok headless lifecycle calls. It avoids
// CommandContext because ExecuteSession owns cancellation and must inspect the
// process tree before returning a local-termination receipt.
type HeadlessOSRunner struct{}
type headlessOSProcess struct {
	cmd            *exec.Cmd
	stdout, stderr io.ReadCloser
}

func (HeadlessOSRunner) Start(_ context.Context, spec StartSpec) (LifecycleProcess, error) {
	cmd := exec.Command(spec.Binary, spec.Args...)
	cmd.Dir, cmd.Env = spec.CWD, minimalGrokEnvironment(os.Environ())
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
	return headlessOSProcess{cmd: cmd, stdout: stdout, stderr: stderr}, nil
}
func (p headlessOSProcess) Stdout() io.Reader { return p.stdout }
func (p headlessOSProcess) Stderr() io.Reader { return p.stderr }
func (p headlessOSProcess) Wait() error       { return p.cmd.Wait() }
func (p headlessOSProcess) PID() int32 {
	if p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return int32(p.cmd.Process.Pid)
}

// ExecuteSession is the CLI-usable native lifecycle executor. It accepts only
// bounded newline JSON, never retains raw provider output, and binds lineage
// only after one completion record carries both the exact nonce and a returned
// session id. A local kill does not imply provider cancellation.
func ExecuteSession(ctx context.Context, runner LifecycleRunner, req SessionRequest) (receipt SessionReceipt, returnErr error) {
	return executeSession(ctx, runner, req, parseLifecycleStream)
}

// lifecycleParser is deliberately injected into the executor in tests so a
// parser fixture cannot be mistaken for a live provider interaction.
type lifecycleParser func(io.Reader, string, string) lifecycleParseResult

func executeSession(ctx context.Context, runner LifecycleRunner, req SessionRequest, parser lifecycleParser) (receipt SessionReceipt, returnErr error) {
	spec, receipt, err := BuildSessionSpec(req)
	if err != nil {
		return receipt, err
	}
	if ctx == nil || runner == nil || parser == nil {
		return receipt, errors.New("Grok lifecycle context and runner are required")
	}
	if req.ExpectedNonce == "" {
		return receipt, errors.New("Grok lifecycle execution requires a nonce")
	}
	if err := ctx.Err(); err != nil {
		receipt.Cancellation = CancellationReceipt{LocalTermination: "not_started", ObservedAt: time.Now().UTC(), ResidualPIDs: []int32{}}
		return receipt, &Error{Code: ErrOutcomeUnknown, Err: err}
	}
	proc, err := runner.Start(ctx, spec)
	if err != nil {
		return receipt, fmt.Errorf("start Grok headless lifecycle: %w", err)
	}
	// Drain stderr without retaining its body; otherwise a noisy child can block.
	stderrDone := make(chan StderrDigest, 1)
	go func() { stderrDone <- drainAndDigest(proc.Stderr(), MaxStderrCaptureBytes) }()
	parsed := make(chan lifecycleParseResult, 1)
	go func() { parsed <- parser(proc.Stdout(), req.ExpectedNonce, req.Model) }()
	waited := make(chan error, 1)
	go func() { waited <- proc.Wait() }()
	var parsedResult lifecycleParseResult
	var waitErr error
	parsedReady, waitReady := false, false
	for !parsedReady || !waitReady {
		select {
		case <-ctx.Done():
			terminationCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			receipt.Cancellation = TerminateAndVerify(terminationCtx, proc.PID())
			cancel()
			// Provider cancellation remains false unless a future structured
			// protocol field explicitly says otherwise.
			select {
			case waitErr = <-waited:
				waitReady = true
			case <-time.After(3 * time.Second):
			}
			select {
			case receipt.Stderr = <-stderrDone:
			case <-time.After(time.Second):
			}
			return receipt, &Error{Code: ErrOutcomeUnknown, Err: ctx.Err()}
		case parsedResult = <-parsed:
			parsedReady = true
		case waitErr = <-waited:
			waitReady = true
		}
	}
	receipt.Stderr = <-stderrDone
	exitCode := 0
	if waitErr != nil {
		exitCode = -1
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}
	receipt.ExitCode = &exitCode
	if waitErr != nil {
		return receipt, &Error{Code: ErrProcessFailed, Err: waitErr}
	}
	if parsedResult.err != nil {
		return receipt, &Error{Code: ErrProtocol, Err: parsedResult.err}
	}
	// Preserve the bounded, non-secret provider evidence even when a later
	// identity or acknowledgement check fails. Lineage remains unbound until
	// every fail-closed check below succeeds.
	receipt.CompletionConfirmed = parsedResult.completion
	receipt.StopReason = parsedResult.stopReason
	receipt.Model = parsedResult.model
	receipt.ModelEvidence = parsedResult.modelEvidence
	receipt.Usage = parsedResult.usage
	receipt.OutputSHA256 = parsedResult.outputSHA256
	if !parsedResult.completion {
		return receipt, &Error{Code: ErrOutcomeUnknown, Err: errors.New("headless stream omitted successful completion")}
	}
	if !parsedResult.nonceAcknowledged {
		return receipt, &Error{Code: ErrAcknowledgementUnconfirmed, Err: errors.New("headless completion omitted exact nonce acknowledgement")}
	}
	if req.Model != "" && parsedResult.model != req.Model {
		return receipt, &Error{Code: ErrIdentityMismatch, Err: errors.New("headless completion model does not match requested model")}
	}
	receipt, err = BindSessionLineage(receipt, parsedResult.sessionID, parsedResult.nonceAcknowledged)
	if err != nil {
		return receipt, &Error{Code: ErrProtocol, Err: err}
	}
	return receipt, nil
}

type lifecycleParseResult struct {
	completion, nonceAcknowledged               bool
	sessionID, stopReason, model, modelEvidence string
	outputSHA256                                string
	usage                                       *Usage
	err                                         error
}
type headlessEvent struct {
	Type            string                     `json:"type"`
	Subtype         string                     `json:"subtype"`
	Data            string                     `json:"data"`
	SessionID       string                     `json:"session_id"`
	SessionIDCamel  string                     `json:"sessionId"`
	Model           string                     `json:"model"`
	ModelUsage      map[string]json.RawMessage `json:"modelUsage"`
	StopReason      string                     `json:"stop_reason"`
	StopReasonCamel string                     `json:"stopReason"`
	Result          string                     `json:"result"`
	IsError         bool                       `json:"is_error"`
	Usage           promptUsage                `json:"usage"`
	Delta           struct {
		Text string `json:"text"`
	} `json:"delta"`
	Message struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"message"`
}

func parseLifecycleStream(reader io.Reader, nonce, expectedModel string) lifecycleParseResult {
	if reader == nil {
		return lifecycleParseResult{err: errors.New("headless stdout is nil")}
	}
	hasher := sha256.New()
	nonceMatcher := newExactTextMatcher(nonce)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 32<<10), MaxProtocolLineBytes)
	result := lifecycleParseResult{}
	for scanner.Scan() {
		var event headlessEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return lifecycleParseResult{err: fmt.Errorf("decode headless JSON: %w", err)}
		}
		for _, text := range lifecycleTexts(event) {
			_, _ = io.WriteString(hasher, text)
			if event.Type == "text" {
				nonceMatcher.Write(text)
			}
		}
		if event.Type == "error" {
			return lifecycleParseResult{err: errors.New("headless stream reported an error event")}
		}
		if event.Type == "result" && event.Subtype == "success" && !event.IsError {
			if result.completion {
				return lifecycleParseResult{err: errors.New("headless stream reported multiple completion events")}
			}
			if strings.TrimSpace(event.SessionID) == "" {
				return lifecycleParseResult{err: errors.New("successful headless completion omitted session id")}
			}
			if nonce != "" && event.Result == nonce {
				result.nonceAcknowledged = true
			}
			result.completion, result.sessionID, result.stopReason = true, event.SessionID, event.StopReason
			result.model, result.modelEvidence, result.usage = event.Model, "legacy_result.model", event.Usage.canonical()
		}
		if event.Type == "end" && !event.IsError {
			if result.completion {
				return lifecycleParseResult{err: errors.New("headless stream reported multiple completion events")}
			}
			sessionID := firstNonEmpty(event.SessionIDCamel, event.SessionID)
			stopReason := firstNonEmpty(event.StopReasonCamel, event.StopReason)
			if strings.TrimSpace(sessionID) == "" {
				return lifecycleParseResult{err: errors.New("headless end event omitted session id")}
			}
			if strings.TrimSpace(stopReason) == "" {
				return lifecycleParseResult{err: errors.New("headless end event omitted stop reason")}
			}
			model, evidence, err := endEventModel(event)
			if err != nil {
				return lifecycleParseResult{err: err}
			}
			result.completion, result.sessionID, result.stopReason = true, sessionID, stopReason
			result.model, result.modelEvidence, result.usage = model, evidence, event.Usage.canonical()
			result.nonceAcknowledged = nonceMatcher.Matched()
		}
	}
	if err := scanner.Err(); err != nil {
		return lifecycleParseResult{err: fmt.Errorf("read headless JSON: %w", err)}
	}
	if result.completion {
		if err := validateLifecycleCompletion(result, expectedModel); err != nil {
			return lifecycleParseResult{err: err}
		}
	}
	result.outputSHA256 = hex.EncodeToString(hasher.Sum(nil))
	return result
}
func lifecycleTexts(event headlessEvent) []string {
	texts := make([]string, 0, len(event.Message.Content)+2)
	if event.Type == "text" && event.Data != "" {
		texts = append(texts, event.Data)
	}
	if event.Delta.Text != "" {
		texts = append(texts, event.Delta.Text)
	}
	for _, content := range event.Message.Content {
		if content.Type == "text" && content.Text != "" {
			texts = append(texts, content.Text)
		}
	}
	if event.Type == "result" && event.Result != "" {
		texts = append(texts, event.Result)
	}
	return texts
}

// exactTextMatcher verifies a streamed acknowledgement without retaining raw
// model output. The caller feeds only assistant text events, never thoughts or
// command metadata.
type exactTextMatcher struct {
	expected string
	offset   int
	mismatch bool
}

func newExactTextMatcher(expected string) *exactTextMatcher {
	return &exactTextMatcher{expected: expected}
}

func (m *exactTextMatcher) Write(value string) {
	if m == nil || m.mismatch || value == "" {
		return
	}
	if m.offset+len(value) > len(m.expected) || m.expected[m.offset:m.offset+len(value)] != value {
		m.mismatch = true
		return
	}
	m.offset += len(value)
}

func (m *exactTextMatcher) Matched() bool {
	return m != nil && !m.mismatch && m.expected != "" && m.offset == len(m.expected)
}

func endEventModel(event headlessEvent) (string, string, error) {
	if len(event.ModelUsage) > 1 {
		return "", "", errors.New("headless end event reported multiple provider models")
	}
	if len(event.ModelUsage) == 1 {
		for model := range event.ModelUsage {
			return model, "end.modelUsage_singleton", nil
		}
	}
	if strings.TrimSpace(event.Model) != "" {
		return event.Model, "end.model", nil
	}
	return "", "", nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func validateLifecycleCompletion(result lifecycleParseResult, expectedModel string) error {
	for name, value := range map[string]string{
		"session id":  result.sessionID,
		"stop reason": result.stopReason,
		"model":       result.model,
	} {
		if len(value) > 4096 || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return fmt.Errorf("headless completion reported an invalid %s", name)
		}
	}
	if strings.TrimSpace(result.stopReason) == "" {
		return errors.New("headless completion omitted stop reason")
	}
	if expectedModel != "" && strings.TrimSpace(result.model) == "" {
		return errors.New("headless completion omitted provider model evidence")
	}
	if result.usage != nil {
		for _, value := range []*int64{result.usage.InputTokens, result.usage.OutputTokens, result.usage.TotalTokens} {
			if value != nil && *value < 0 {
				return errors.New("headless completion reported negative token usage")
			}
		}
	}
	return nil
}

// ProcessInspector isolates process-tree inspection so tests can cover the
// truthfulness contract without starting real children.
type ProcessInspector interface {
	Children(int32) ([]int32, error)
	Exists(int32) (bool, error)
	Kill(int32) error
}

type osInspector struct{}

func (osInspector) Children(pid int32) ([]int32, error) {
	p, err := process.NewProcess(pid)
	if err != nil {
		return nil, err
	}
	children, err := p.Children()
	if err != nil {
		return nil, err
	}
	ids := make([]int32, 0, len(children))
	for _, child := range children {
		ids = append(ids, child.Pid)
	}
	return ids, nil
}
func (osInspector) Exists(pid int32) (bool, error) { return process.PidExists(pid) }
func (osInspector) Kill(pid int32) error {
	p, err := process.NewProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

// TerminateAndVerify kills every observed descendant before its owner and
// polls the complete observed tree. It proves only that observed PIDs are
// gone; a child that appears after the snapshot is deliberately not claimed.
// Permission/inspection gaps stay explicit.
func TerminateAndVerify(ctx context.Context, rootPID int32) CancellationReceipt {
	return terminateAndVerify(ctx, rootPID, osInspector{})
}

func terminateAndVerify(ctx context.Context, rootPID int32, inspector ProcessInspector) CancellationReceipt {
	r := CancellationReceipt{LocalTermination: "unverified", ObservedAt: time.Now().UTC(), ResidualPIDs: []int32{}}
	if ctx == nil || rootPID <= 0 || inspector == nil {
		r.LocalTermination = "unsupported"
		return r
	}
	exists, err := inspector.Exists(rootPID)
	if err != nil {
		r.LocalTermination = "inspection_failed"
		return r
	}
	if !exists {
		r.LocalTermination = "already_exited_verified"
		return r
	}
	seen := map[int32]bool{}
	ids := make([]int32, 0)
	var visit func(int32) bool
	visit = func(pid int32) bool {
		if seen[pid] {
			return true
		}
		seen[pid] = true
		children, err := inspector.Children(pid)
		if err != nil {
			return false
		}
		for _, child := range children {
			if !visit(child) {
				return false
			}
		}
		// Append after visiting descendants so termination order is structural,
		// not an unsafe assumption about monotonically increasing PIDs.
		ids = append(ids, pid)
		return true
	}
	if !visit(rootPID) {
		r.LocalTermination = "inspection_failed"
		return r
	}
	for _, id := range ids {
		if err := inspector.Kill(id); err != nil {
			r.LocalTermination = "termination_failed"
			return r
		}
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		remaining := remainingPIDs(ids, inspector)
		if len(remaining) == 0 {
			r.LocalTermination = "observed_tree_terminated_verified"
			return r
		}
		select {
		case <-ctx.Done():
			r.LocalTermination = "verification_canceled"
			r.ResidualPIDs = remaining
			return r
		case <-deadline.C:
			r.LocalTermination = "residual_processes_detected"
			r.ResidualPIDs = remaining
			return r
		case <-tick.C:
		}
	}
}

func remainingPIDs(ids []int32, inspector ProcessInspector) []int32 {
	remaining := make([]int32, 0)
	for _, id := range ids {
		exists, err := inspector.Exists(id)
		if err != nil || exists {
			remaining = append(remaining, id)
		}
	}
	return remaining
}

// LocalTerminationSupported documents the platform boundary for callers that
// need to preflight instead of discovering it during cancellation.
func LocalTerminationSupported() bool { return runtime.GOOS != "plan9" && os.Getpid() > 0 }
