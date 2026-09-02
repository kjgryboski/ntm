//go:build integration

package grok

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestLiveACPReadOnlyRoundTrip is an explicitly opted-in, no-write provider
// check. It uses only an existing cached Grok login and never emits the
// prompt, nonce, provider text, or credential material. Normal unit and
// integration runs skip it unless NTM_LIVE_GROK_ACP=1 is set. Exporting
// XAI_API_KEY is deliberately not a substitute for a cached login.
func TestLiveACPReadOnlyRoundTrip(t *testing.T) {
	if os.Getenv("NTM_LIVE_GROK_ACP") != "1" {
		t.Skip("set NTM_LIVE_GROK_ACP=1 for the authenticated no-write ACP check")
	}
	model := strings.TrimSpace(os.Getenv("NTM_LIVE_GROK_MODEL"))
	if model == "" {
		model = "grok-4.6"
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	nonce := "NTM_ACK_" + hex.EncodeToString(random)
	cwd := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	result, err := Run(ctx, OSRunner{}, Request{
		Prompt:                  "Do not call any tools. Reply with this exact token and nothing else on one line: " + nonce,
		ExpectedNonce:           nonce,
		CWD:                     cwd,
		Binary:                  "grok",
		Model:                   model,
		AutomationPolicyArgs:    defaultReadOnlyAutomationPolicyArgs(),
		PostResponseQuietWindow: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("live ACP check failed with code %q and state %q: %v", result.FailureCode, result.State, err)
	}
	if !result.Success || !result.CompletionConfirmed || !result.AcknowledgementVerified || strings.TrimSpace(result.StopReason) == "" {
		t.Fatalf("live ACP receipt was not authoritative: success=%v completion=%v acknowledgement=%v stop_reason_present=%v", result.Success, result.CompletionConfirmed, result.AcknowledgementVerified, result.StopReason != "")
	}
	// This check does not require an exact model: a global catalog is not a
	// session identity observation. If this CLI emits stronger evidence, it must
	// be one of the two session-scoped forms; catalog-only promotion is invalid.
	if result.ModelEvidence == "provider_catalog_plus_exact_launch" {
		t.Fatalf("catalog-only live transport promoted model identity: model %q", result.Model)
	}
	if result.ModelEvidence != "" && result.ModelEvidence != "completion_metadata" && result.ModelEvidence != "provider_session_notification_plus_exact_launch" && result.ModelEvidence != "session_config_option_plus_exact_launch" && result.ModelEvidence != "session_model_state_plus_exact_launch" {
		t.Fatalf("live ACP returned unknown model evidence %q", result.ModelEvidence)
	}
	if result.ModelEvidence != "" && strings.TrimSpace(result.Model) != model {
		t.Fatalf("session-scoped live model evidence named %q, want exact selected model %q", result.Model, model)
	}
	if entries, err := os.ReadDir(cwd); err != nil {
		t.Fatal(err)
	} else if len(entries) != 0 {
		t.Fatalf("no-write ACP check left %d filesystem entries", len(entries))
	}
}

// TestLiveACPSessionNewModelStateDiagnostic is an owner-gated, no-write
// diagnostic for a pinned Grok CLI whose completion omitted model metadata.
// It retains and prints only session/new field names plus model-selector
// category/type/currentValue/option values; it never retains a session ID,
// prompt, assistant text, authentication material, endpoint, or raw ACP line.
func TestLiveACPSessionNewModelStateDiagnostic(t *testing.T) {
	if os.Getenv("NTM_LIVE_GROK_ACP_MODEL_DIAGNOSTIC") != "1" {
		t.Skip("set NTM_LIVE_GROK_ACP_MODEL_DIAGNOSTIC=1 for the redacted session/new model-state diagnostic")
	}
	model := strings.TrimSpace(os.Getenv("NTM_LIVE_GROK_MODEL"))
	if model == "" {
		model = "grok-4.6"
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	nonce := "NTM_ACK_" + hex.EncodeToString(random)
	cwd := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	observer := &liveACPSessionNewModelObserver{}
	result, err := Run(ctx, liveACPSessionNewModelObserverRunner{base: OSRunner{}, observer: observer}, Request{
		Prompt:                  "Do not call tools or access files. Reply with this exact token and nothing else on one line: " + nonce,
		ExpectedNonce:           nonce,
		CWD:                     cwd,
		Binary:                  "grok",
		Model:                   model,
		AutomationPolicyArgs:    defaultReadOnlyAutomationPolicyArgs(),
		PostResponseQuietWindow: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("live session/new model-state diagnostic failed: code=%q state=%q", result.FailureCode, result.State)
	}
	if !result.Success || !result.CompletionConfirmed || !result.AcknowledgementVerified {
		t.Fatalf("live session/new diagnostic violated completion constraints: success=%v completion=%v acknowledgement=%v", result.Success, result.CompletionConfirmed, result.AcknowledgementVerified)
	}
	if result.ToolEventCount > 0 && strings.TrimSpace(result.ToolEventsSHA256) == "" {
		t.Fatalf("live session/new diagnostic observed %d tool event(s) without a receipt digest", result.ToolEventCount)
	}
	t.Logf("redacted session/new model-state diagnostic: %+v", observer.Snapshot())
	if entries, readErr := os.ReadDir(cwd); readErr != nil {
		t.Fatal(readErr)
	} else if len(entries) != 0 {
		t.Fatalf("no-write session/new diagnostic left %d filesystem entries", len(entries))
	}
}

// liveACPSessionNewModelDiagnostic is intentionally limited to model selector
// metadata that can guide a future parser change. It contains no raw protocol
// payloads or identifier values.
type liveACPSessionNewModelDiagnostic struct {
	SessionNewObserved bool
	Truncated          bool
	ResultFieldNames   []string
	Models             liveACPTopLevelModelStateDiagnostic
	ModelSelectors     []liveACPModelSelectorDiagnostic
}

// liveACPTopLevelModelStateDiagnostic retains only the typed fields needed to
// assess Grok's top-level models state. It intentionally excludes every other
// value from the session/new response.
type liveACPTopLevelModelStateDiagnostic struct {
	Observed                 bool
	FieldNames               []string
	CurrentModelID           string
	AvailableModelFieldNames []string
	AvailableModelIDs        []string
}

type liveACPModelSelectorDiagnostic struct {
	FieldPath    string
	FieldNames   []string
	Category     string
	Type         string
	CurrentValue string
	OptionValues []string
}

type liveACPSessionNewModelObserverRunner struct {
	base     Runner
	observer *liveACPSessionNewModelObserver
}

func (r liveACPSessionNewModelObserverRunner) Start(ctx context.Context, spec StartSpec) (Process, error) {
	proc, err := r.base.Start(ctx, spec)
	if err != nil {
		return nil, err
	}
	return liveACPSessionNewModelObserverProcess{
		Process: proc,
		stdout:  &liveACPSessionNewModelObserverReader{Reader: proc.Stdout(), observer: r.observer},
	}, nil
}

type liveACPSessionNewModelObserverProcess struct {
	Process
	stdout io.Reader
}

func (p liveACPSessionNewModelObserverProcess) Stdout() io.Reader { return p.stdout }

type liveACPSessionNewModelObserver struct {
	mu     sync.Mutex
	result liveACPSessionNewModelDiagnostic
}

func (o *liveACPSessionNewModelObserver) Observe(raw json.RawMessage) {
	if o == nil {
		return
	}
	diagnostic := redactLiveACPSessionNewModelState(raw)
	o.mu.Lock()
	if !o.result.SessionNewObserved {
		diagnostic.Truncated = diagnostic.Truncated || o.result.Truncated
		o.result = diagnostic
	}
	o.mu.Unlock()
}

func (o *liveACPSessionNewModelObserver) MarkTruncated() {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.result.Truncated = true
	o.mu.Unlock()
}

func (o *liveACPSessionNewModelObserver) Snapshot() liveACPSessionNewModelDiagnostic {
	if o == nil {
		return liveACPSessionNewModelDiagnostic{}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	result := o.result
	result.ResultFieldNames = append([]string(nil), result.ResultFieldNames...)
	result.Models.FieldNames = append([]string(nil), result.Models.FieldNames...)
	result.Models.AvailableModelFieldNames = append([]string(nil), result.Models.AvailableModelFieldNames...)
	result.Models.AvailableModelIDs = append([]string(nil), result.Models.AvailableModelIDs...)
	result.ModelSelectors = append([]liveACPModelSelectorDiagnostic(nil), result.ModelSelectors...)
	for index := range result.ModelSelectors {
		result.ModelSelectors[index].FieldNames = append([]string(nil), result.ModelSelectors[index].FieldNames...)
		result.ModelSelectors[index].OptionValues = append([]string(nil), result.ModelSelectors[index].OptionValues...)
	}
	return result
}

type liveACPSessionNewModelObserverReader struct {
	io.Reader
	observer *liveACPSessionNewModelObserver

	mu      sync.Mutex
	pending []byte
}

func (r *liveACPSessionNewModelObserverReader) Read(value []byte) (int, error) {
	n, err := r.Reader.Read(value)
	if n > 0 {
		r.observe(value[:n])
	}
	return n, err
}

func (r *liveACPSessionNewModelObserverReader) observe(value []byte) {
	const maxDiagnosticLineBytes = MaxProtocolLineBytes
	r.mu.Lock()
	r.pending = append(r.pending, value...)
	for {
		index := bytes.IndexByte(r.pending, '\n')
		if index < 0 {
			if len(r.pending) > maxDiagnosticLineBytes {
				r.pending = nil
				r.observer.MarkTruncated()
			}
			break
		}
		line := r.pending[:index]
		r.pending = r.pending[index+1:]
		if len(line) > maxDiagnosticLineBytes {
			r.observer.MarkTruncated()
			continue
		}
		var envelope struct {
			ID     json.RawMessage `json:"id"`
			Result json.RawMessage `json:"result"`
		}
		if json.Unmarshal(line, &envelope) != nil {
			continue
		}
		var id int
		if json.Unmarshal(envelope.ID, &id) == nil && id == 3 && len(envelope.Result) != 0 {
			r.observer.Observe(envelope.Result)
		}
	}
	r.mu.Unlock()
}

func redactLiveACPSessionNewModelState(raw json.RawMessage) liveACPSessionNewModelDiagnostic {
	result := liveACPSessionNewModelDiagnostic{SessionNewObserved: true, ResultFieldNames: []string{}, Models: liveACPTopLevelModelStateDiagnostic{FieldNames: []string{}, AvailableModelIDs: []string{}}, ModelSelectors: []liveACPModelSelectorDiagnostic{}}
	var root map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil {
		return result
	}
	for field := range root {
		result.ResultFieldNames = append(result.ResultFieldNames, field)
	}
	sort.Strings(result.ResultFieldNames)
	result.Models = redactLiveACPTopLevelModelState(root["models"])
	collectLiveACPModelSelectors(raw, "result", 0, &result)
	return result
}

func redactLiveACPTopLevelModelState(raw json.RawMessage) liveACPTopLevelModelStateDiagnostic {
	result := liveACPTopLevelModelStateDiagnostic{FieldNames: []string{}, AvailableModelFieldNames: []string{}, AvailableModelIDs: []string{}}
	if len(raw) == 0 {
		return result
	}
	var state map[string]json.RawMessage
	if json.Unmarshal(raw, &state) != nil {
		return result
	}
	result.Observed = true
	for field := range state {
		result.FieldNames = append(result.FieldNames, field)
	}
	sort.Strings(result.FieldNames)
	result.CurrentModelID = liveACPStringField(state["currentModelId"])
	var models []map[string]json.RawMessage
	if json.Unmarshal(state["availableModels"], &models) != nil {
		return result
	}
	for _, model := range models {
		for field := range model {
			if !containsLiveACPFieldName(result.AvailableModelFieldNames, field) {
				result.AvailableModelFieldNames = append(result.AvailableModelFieldNames, field)
			}
		}
		if id := liveACPStringField(model["modelId"]); id != "" {
			result.AvailableModelIDs = append(result.AvailableModelIDs, id)
		}
	}
	sort.Strings(result.AvailableModelFieldNames)
	return result
}

func containsLiveACPFieldName(fields []string, want string) bool {
	for _, field := range fields {
		if field == want {
			return true
		}
	}
	return false
}

func collectLiveACPModelSelectors(raw json.RawMessage, path string, depth int, result *liveACPSessionNewModelDiagnostic) {
	if result == nil || depth > 8 {
		return
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) == nil {
		if category := liveACPStringField(object["category"]); category == "model" {
			selector := liveACPModelSelectorDiagnostic{FieldPath: path, FieldNames: []string{}, Category: category, Type: liveACPStringField(object["type"]), CurrentValue: liveACPStringField(object["currentValue"]), OptionValues: []string{}}
			for field := range object {
				selector.FieldNames = append(selector.FieldNames, field)
			}
			sort.Strings(selector.FieldNames)
			var options []map[string]json.RawMessage
			if json.Unmarshal(object["options"], &options) == nil {
				for _, option := range options {
					if value := liveACPStringField(option["value"]); value != "" {
						selector.OptionValues = append(selector.OptionValues, value)
					}
				}
			}
			result.ModelSelectors = append(result.ModelSelectors, selector)
		}
		for field, child := range object {
			collectLiveACPModelSelectors(child, path+"."+field, depth+1, result)
		}
		return
	}
	var array []json.RawMessage
	if json.Unmarshal(raw, &array) == nil {
		for _, child := range array {
			collectLiveACPModelSelectors(child, path+"[]", depth+1, result)
		}
	}
}

func liveACPStringField(raw json.RawMessage) string {
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	return value
}

// TestLiveACPCancellationAcknowledgementAndLocalCleanup is an owner-gated,
// no-write cancellation check. The wrapper observes the complete prompt JSON
// entering the local ACP pipe before it cancels the caller context. ACP v1 has
// no earlier provider-side "prompt accepted" response: the required original
// session/prompt response with stopReason=cancelled is the only authoritative
// agent acknowledgement this test can require. It deliberately does not claim
// that cloud inference stopped.
func TestLiveACPCancellationAcknowledgementAndLocalCleanup(t *testing.T) {
	if os.Getenv("NTM_LIVE_GROK_ACP_CANCEL") != "1" {
		t.Skip("set NTM_LIVE_GROK_ACP_CANCEL=1 for the cached-login ACP cancellation check")
	}
	if !LocalTerminationSupported() {
		t.Skip("local process-tree termination is unsupported on this platform")
	}

	model := strings.TrimSpace(os.Getenv("NTM_LIVE_GROK_MODEL"))
	if model == "" {
		model = "grok-4.6"
	}
	cwd := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	observer := &liveACPPromptObserver{cancel: cancel}
	result, err := Run(ctx, liveACPPromptObserverRunner{base: OSRunner{}, observer: observer}, Request{
		Prompt:                  "Do not call tools, access files, or produce a response; this no-write ACP cancellation check will cancel the request immediately.",
		CWD:                     cwd,
		Binary:                  "grok",
		Model:                   model,
		OperationID:             "live-acp-cancellation-check",
		AutomationPolicyArgs:    defaultReadOnlyAutomationPolicyArgs(),
		CancellationGracePeriod: 10 * time.Second,
	})
	if !observer.PromptWritten() {
		t.Fatal("live cancellation finished before the complete ACP prompt entered the local pipe")
	}
	var grokErr *Error
	if !errors.As(err, &grokErr) || grokErr.Code != ErrCancelled {
		t.Fatalf("live ACP cancellation did not receive the required ACP acknowledgement: code=%q state=%q", result.FailureCode, result.State)
	}
	if result.State != StateCancelled || !result.CompletionConfirmed || result.StopReason != "cancelled" ||
		!result.Cancellation.Requested || !result.Cancellation.NotificationWritten || !result.Cancellation.AgentACPAcknowledged ||
		result.Cancellation.CloudInferenceStopConfirmed {
		t.Fatalf("live ACP cancellation receipt was not correctly scoped: state=%q completion=%v stop_reason=%q requested=%v notification_written=%v agent_acknowledged=%v cloud_stop_confirmed=%v",
			result.State, result.CompletionConfirmed, result.StopReason, result.Cancellation.Requested, result.Cancellation.NotificationWritten,
			result.Cancellation.AgentACPAcknowledged, result.Cancellation.CloudInferenceStopConfirmed)
	}
	// The read-only automation profile permits selected read/search tools, and
	// ACP may emit their lifecycle updates even when cancellation follows the
	// prompt write immediately. Tool activity is therefore receipt evidence,
	// not a failure of this cancellation/cleanup qualification. Any observed
	// sequence must still be represented by a redaction-safe digest.
	if result.ToolEventCount > 0 && strings.TrimSpace(result.ToolEventsSHA256) == "" {
		t.Fatalf("live ACP cancellation observed %d tool event(s) without a receipt digest", result.ToolEventCount)
	}
	if !result.Cleanup.Reaped || len(result.Cleanup.ResidualPIDs) != 0 ||
		(result.Cleanup.LocalTermination != "observed_tree_terminated_verified" && result.Cleanup.LocalTermination != "already_exited_verified") {
		t.Fatalf("local ACP process cleanup was not authoritative: termination=%q reaped=%v residual_processes=%d",
			result.Cleanup.LocalTermination, result.Cleanup.Reaped, len(result.Cleanup.ResidualPIDs))
	}
	if entries, readErr := os.ReadDir(cwd); readErr != nil {
		t.Fatal(readErr)
	} else if len(entries) != 0 {
		t.Fatalf("no-write ACP cancellation check left %d filesystem entries", len(entries))
	}
}

// liveACPPromptObserverRunner adds only a local-pipe observation hook for the
// integration test. It does not inspect or retain provider output.
type liveACPPromptObserverRunner struct {
	base     Runner
	observer *liveACPPromptObserver
}

func (r liveACPPromptObserverRunner) Start(ctx context.Context, spec StartSpec) (Process, error) {
	proc, err := r.base.Start(ctx, spec)
	if err != nil {
		return nil, err
	}
	return liveACPPromptObserverProcess{
		Process: proc,
		stdin: &liveACPPromptObserverWriter{
			WriteCloser: proc.Stdin(),
			observer:    r.observer,
		},
	}, nil
}

type liveACPPromptObserverProcess struct {
	Process
	stdin io.WriteCloser
}

func (p liveACPPromptObserverProcess) Stdin() io.WriteCloser { return p.stdin }

type liveACPPromptObserver struct {
	mu      sync.Mutex
	written bool
	cancel  context.CancelFunc
}

func (o *liveACPPromptObserver) MarkPromptWritten() {
	if o == nil {
		return
	}
	o.mu.Lock()
	if o.written {
		o.mu.Unlock()
		return
	}
	o.written = true
	cancel := o.cancel
	o.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (o *liveACPPromptObserver) PromptWritten() bool {
	if o == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.written
}

type liveACPPromptObserverWriter struct {
	io.WriteCloser
	observer *liveACPPromptObserver

	mu      sync.Mutex
	pending []byte
}

func (w *liveACPPromptObserverWriter) Write(value []byte) (int, error) {
	n, err := w.WriteCloser.Write(value)
	if n > 0 {
		w.observe(value[:n])
	}
	return n, err
}

func (w *liveACPPromptObserverWriter) observe(value []byte) {
	w.mu.Lock()
	w.pending = append(w.pending, value...)
	for {
		index := bytes.IndexByte(w.pending, '\n')
		if index < 0 {
			break
		}
		line := w.pending[:index]
		w.pending = w.pending[index+1:]
		var envelope struct {
			Method string `json:"method"`
		}
		if json.Unmarshal(line, &envelope) == nil && envelope.Method == "session/prompt" {
			w.mu.Unlock()
			w.observer.MarkPromptWritten()
			return
		}
	}
	w.mu.Unlock()
}
