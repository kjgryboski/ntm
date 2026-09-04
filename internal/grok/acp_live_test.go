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
	"os/exec"
	"path/filepath"
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
	runtimeHome := liveGrokRuntimeHome(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	result, err := Run(ctx, OSRunner{}, Request{
		Prompt:                  "Do not call any tools. Reply with this exact token and nothing else on one line: " + nonce,
		ExpectedNonce:           nonce,
		CWD:                     cwd,
		RuntimeHome:             runtimeHome,
		Binary:                  "grok",
		Model:                   model,
		RuntimeVersion:          "1.0.13",
		AutomationPolicyArgs:    defaultReadOnlyAutomationPolicyArgs(),
		PostResponseQuietWindow: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("live ACP check failed with code %q and state %q: %v", result.FailureCode, result.State, err)
	}
	if !result.Success || !result.CompletionConfirmed || !result.AcknowledgementVerified || strings.TrimSpace(result.StopReason) == "" {
		t.Fatalf("live ACP receipt was not authoritative: success=%v completion=%v acknowledgement=%v stop_reason_present=%v", result.Success, result.CompletionConfirmed, result.AcknowledgementVerified, result.StopReason != "")
	}
	// This check does not require an exact served model. Selection state and a
	// global catalog remain diagnostic only; only terminal completion metadata
	// can become served-model evidence.
	if result.ModelEvidence == "provider_catalog_plus_exact_launch" {
		t.Fatalf("catalog-only live transport promoted model identity: model %q", result.Model)
	}
	if result.ModelEvidence != "" && result.ModelEvidence != "completion_metadata" {
		t.Fatalf("live ACP returned unknown model evidence %q", result.ModelEvidence)
	}
	if result.ModelEvidence != "" && strings.TrimSpace(result.Model) != model {
		t.Fatalf("session-scoped live model evidence named %q, want exact selected model %q", result.Model, model)
	}
	if result.Model != model || result.ModelEvidence != "completion_metadata" || result.ResolvedModel != ExpectedResolvedModel("1.0.13", model) || result.ResolvedModelEvidence != "completion_metadata.usage.model_usage_singleton" {
		t.Fatalf("live ACP completion omitted exact public/resolved model evidence: public=%q public_evidence=%q resolved=%q resolved_evidence=%q", result.Model, result.ModelEvidence, result.ResolvedModel, result.ResolvedModelEvidence)
	}
	if result.Usage == nil || result.Usage.InputTokens == nil || result.Usage.OutputTokens == nil || result.Usage.TotalTokens == nil || !result.RuntimeEventContract.Passed {
		t.Fatalf("live ACP completion omitted normalized usage/runtime evidence: usage_present=%v contract=%+v", result.Usage != nil, result.RuntimeEventContract)
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
	runtimeHome := liveGrokRuntimeHome(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	observer := &liveACPSessionNewModelObserver{expectedModel: model}
	result, err := Run(ctx, liveACPSessionNewModelObserverRunner{base: OSRunner{}, observer: observer}, Request{
		Prompt:                  "Do not call tools or access files. Reply with this exact token and nothing else on one line: " + nonce,
		ExpectedNonce:           nonce,
		CWD:                     cwd,
		RuntimeHome:             runtimeHome,
		Binary:                  "grok",
		Model:                   model,
		RuntimeVersion:          "1.0.13",
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
	t.Logf("redacted session/new and terminal model/usage diagnostic: %+v", observer.Snapshot())
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
	PromptObserved     bool
	Truncated          bool
	ResultFieldNames   []string
	Models             liveACPTopLevelModelStateDiagnostic
	ModelSelectors     []liveACPModelSelectorDiagnostic
	Prompt             liveACPPromptResultDiagnostic
}

// liveACPPromptResultDiagnostic retains only terminal field names, JSON types,
// and whether a model string exactly matched the already-configured model. It
// never retains an unexpected model value, token count, prompt, output, or ID.
type liveACPPromptResultDiagnostic struct {
	FieldNames          []string
	ModelFieldPresent   bool
	ModelFieldType      string
	ExactModelMatch     bool
	UsageFieldPresent   bool
	UsageFieldType      string
	UsageFieldNameTypes []liveACPFieldNameType
	MetadataFieldTypes  []liveACPFieldPathType
	ExactModelPaths     []string
}

type liveACPFieldNameType struct {
	Name string
	Type string
}

type liveACPFieldPathType struct {
	Path string
	Type string
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
	mu            sync.Mutex
	expectedModel string
	result        liveACPSessionNewModelDiagnostic
}

func (o *liveACPSessionNewModelObserver) ObserveSessionNew(raw json.RawMessage) {
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

func (o *liveACPSessionNewModelObserver) ObservePrompt(raw json.RawMessage) {
	if o == nil {
		return
	}
	diagnostic := redactLiveACPPromptResult(raw, o.expectedModel)
	o.mu.Lock()
	if !o.result.PromptObserved {
		o.result.PromptObserved = true
		o.result.Prompt = diagnostic
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
	result.Prompt.FieldNames = append([]string(nil), result.Prompt.FieldNames...)
	result.Prompt.UsageFieldNameTypes = append([]liveACPFieldNameType(nil), result.Prompt.UsageFieldNameTypes...)
	result.Prompt.MetadataFieldTypes = append([]liveACPFieldPathType(nil), result.Prompt.MetadataFieldTypes...)
	result.Prompt.ExactModelPaths = append([]string(nil), result.Prompt.ExactModelPaths...)
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
		if json.Unmarshal(envelope.ID, &id) != nil || len(envelope.Result) == 0 {
			continue
		}
		switch id {
		case 3:
			r.observer.ObserveSessionNew(envelope.Result)
		case 4:
			r.observer.ObservePrompt(envelope.Result)
		}
	}
	r.mu.Unlock()
}

func redactLiveACPPromptResult(raw json.RawMessage, expectedModel string) liveACPPromptResultDiagnostic {
	result := liveACPPromptResultDiagnostic{FieldNames: []string{}, UsageFieldNameTypes: []liveACPFieldNameType{}, MetadataFieldTypes: []liveACPFieldPathType{}, ExactModelPaths: []string{}}
	var root map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil {
		return result
	}
	for field := range root {
		result.FieldNames = append(result.FieldNames, field)
	}
	sort.Strings(result.FieldNames)
	if modelRaw, ok := root["model"]; ok {
		result.ModelFieldPresent = true
		result.ModelFieldType = liveACPJSONType(modelRaw)
		var model string
		result.ExactModelMatch = json.Unmarshal(modelRaw, &model) == nil && expectedModel != "" && model == expectedModel
	}
	if usageRaw, ok := root["usage"]; ok {
		result.UsageFieldPresent = true
		result.UsageFieldType = liveACPJSONType(usageRaw)
		var usage map[string]json.RawMessage
		if json.Unmarshal(usageRaw, &usage) == nil {
			for name, value := range usage {
				result.UsageFieldNameTypes = append(result.UsageFieldNameTypes, liveACPFieldNameType{Name: name, Type: liveACPJSONType(value)})
			}
			sort.Slice(result.UsageFieldNameTypes, func(i, j int) bool { return result.UsageFieldNameTypes[i].Name < result.UsageFieldNameTypes[j].Name })
		}
	}
	collectLiveACPTerminalMetadata(root["_meta"], "result._meta", expectedModel, 0, &result)
	return result
}

func collectLiveACPTerminalMetadata(raw json.RawMessage, path, expectedModel string, depth int, result *liveACPPromptResultDiagnostic) {
	const maxMetadataFields = 64
	if result == nil || len(raw) == 0 || depth > 8 || len(result.MetadataFieldTypes) >= maxMetadataFields {
		return
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) == nil {
		fields := make([]string, 0, len(object))
		for field := range object {
			fields = append(fields, field)
		}
		sort.Strings(fields)
		for _, field := range fields {
			if len(result.MetadataFieldTypes) >= maxMetadataFields {
				return
			}
			child := object[field]
			childPath := path + "." + field
			result.MetadataFieldTypes = append(result.MetadataFieldTypes, liveACPFieldPathType{Path: childPath, Type: liveACPJSONType(child)})
			var value string
			if expectedModel != "" && json.Unmarshal(child, &value) == nil && value == expectedModel {
				result.ExactModelPaths = append(result.ExactModelPaths, childPath)
			}
			collectLiveACPTerminalMetadata(child, childPath, expectedModel, depth+1, result)
		}
		return
	}
	var array []json.RawMessage
	if json.Unmarshal(raw, &array) == nil {
		for _, child := range array {
			collectLiveACPTerminalMetadata(child, path+"[]", expectedModel, depth+1, result)
		}
	}
}

func liveACPJSONType(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "missing"
	}
	switch trimmed[0] {
	case '{':
		return "object"
	case '[':
		return "array"
	case '"':
		return "string"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	default:
		var number json.Number
		if json.Unmarshal(trimmed, &number) == nil {
			return "number"
		}
		return "invalid"
	}
}

func TestRedactLiveACPPromptResultRetainsNoValues(t *testing.T) {
	raw := json.RawMessage(`{"stopReason":"end_turn","model":"unexpected-secret-model","usage":{"inputTokens":123,"nested":{"secret":"must-not-retain"}},"_meta":{"served":{"model":"grok-4.6","secret":"must-not-retain"}},"prompt":"must-not-retain","sessionId":"must-not-retain"}`)
	diagnostic := redactLiveACPPromptResult(raw, "grok-4.6")
	encoded, err := json.Marshal(diagnostic)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, forbidden := range []string{"unexpected-secret-model", "must-not-retain", "123", "end_turn"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("redacted terminal diagnostic retained %q: %s", forbidden, text)
		}
	}
	if !diagnostic.ModelFieldPresent || diagnostic.ModelFieldType != "string" || diagnostic.ExactModelMatch || !diagnostic.UsageFieldPresent || diagnostic.UsageFieldType != "object" {
		t.Fatalf("terminal diagnostic shape = %+v", diagnostic)
	}
	if len(diagnostic.ExactModelPaths) != 1 || diagnostic.ExactModelPaths[0] != "result._meta.served.model" {
		t.Fatalf("terminal exact-model paths = %+v", diagnostic.ExactModelPaths)
	}
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

// TestLiveACPBootstrapHeadlessForkAndResumeLineage proves that a session
// created by the primary ACP adapter can be consumed by the separately
// receipt-bearing headless lifecycle adapter. It uses an isolated copy of the
// cached login and a disposable linked worktree so provider session state and
// repository metadata disappear with the test. This is no-write lifecycle
// evidence; it does not qualify workspace mutation or production dispatch.
func TestLiveACPBootstrapHeadlessForkAndResumeLineage(t *testing.T) {
	if os.Getenv("NTM_LIVE_GROK_ACP_LINEAGE") != "1" {
		t.Skip("set NTM_LIVE_GROK_ACP_LINEAGE=1 for the cached-login ACP/headless lineage check")
	}
	model := strings.TrimSpace(os.Getenv("NTM_LIVE_GROK_MODEL"))
	if model == "" {
		model = "grok-4.6"
	}
	runtimeHome := liveIsolatedGrokRuntimeHome(t)
	worktree := liveGrokLinkedWorktree(t)

	bootstrapNonce := liveGrokNonce(t)
	bootstrapCtx, bootstrapCancel := context.WithTimeout(context.Background(), 90*time.Second)
	bootstrap, err := Run(bootstrapCtx, OSRunner{}, Request{
		Prompt:        "Do not call tools. Reply with this exact token and nothing else on one line: " + bootstrapNonce,
		ExpectedNonce: bootstrapNonce, CWD: worktree, RuntimeHome: runtimeHome,
		Binary: "grok", Model: model, RuntimeVersion: "1.0.13",
		AutomationPolicyArgs: defaultReadOnlyAutomationPolicyArgs(),
	})
	bootstrapCancel()
	if err != nil || !bootstrap.Success || bootstrap.ProviderSessionID == "" || !bootstrap.AcknowledgementVerified {
		t.Fatalf("ACP lineage bootstrap failed: success=%v session=%v acknowledgement=%v err=%v", bootstrap.Success, bootstrap.ProviderSessionID != "", bootstrap.AcknowledgementVerified, err)
	}

	runLifecycle := func(action SessionAction) SessionReceipt {
		t.Helper()
		nonce := liveGrokNonce(t)
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		receipt, runErr := ExecuteSession(ctx, HeadlessOSRunner{}, SessionRequest{
			Action: action, SessionID: bootstrap.ProviderSessionID,
			Prompt:        "Do not call tools. Reply with this exact token and nothing else on one line: " + nonce,
			ExpectedNonce: nonce, CWD: worktree, Worktree: worktree,
			RuntimeHome: runtimeHome, Binary: "grok", Model: model, RuntimeVersion: "1.0.13",
			PolicyArgs: defaultReadOnlyLifecyclePolicyArgs(),
		})
		cancel()
		if runErr != nil {
			t.Fatalf("headless %s failed: %v", action, runErr)
		}
		if !receipt.CompletionConfirmed || !receipt.ProviderAcknowledged || !receipt.LineageBound || receipt.Model != ExpectedResolvedModel("1.0.13", model) || receipt.ModelEvidence != "end.modelUsage_singleton" || receipt.Cancellation.LocalTermination != "not_required_process_exited" || len(receipt.Cancellation.ResidualPIDs) != 0 {
			t.Fatalf("headless %s receipt is incomplete: %+v", action, receipt)
		}
		return receipt
	}

	fork := runLifecycle(SessionFork)
	if fork.ChildSessionSHA256 == fork.ParentSessionSHA256 {
		t.Fatal("headless fork did not produce distinct child lineage")
	}
	resume := runLifecycle(SessionResume)
	if resume.ChildSessionSHA256 != resume.ParentSessionSHA256 || resume.ParentSessionSHA256 != fork.ParentSessionSHA256 || resume.WorktreeSHA256 != fork.WorktreeSHA256 {
		t.Fatal("headless resume/fork receipts did not preserve parent and worktree lineage")
	}
}

func liveGrokNonce(t *testing.T) string {
	t.Helper()
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	return "NTM_ACK_" + hex.EncodeToString(random)
}

func liveIsolatedGrokRuntimeHome(t *testing.T) string {
	t.Helper()
	source := filepath.Join(liveGrokRuntimeHome(t), "auth.json")
	auth, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read cached Grok login: %v", err)
	}
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "auth.json"), auth, 0o600); err != nil {
		t.Fatalf("create isolated Grok login cache: %v", err)
	}
	return home
}

func liveGrokLinkedWorktree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	primary, linked := filepath.Join(root, "primary"), filepath.Join(root, "linked")
	if err := os.Mkdir(primary, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(primary, "README.md"), []byte("lineage qualification\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit := func(dir string, args ...string) {
		t.Helper()
		command := exec.Command("git", append([]string{"-C", dir}, args...)...)
		command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "LANG=C"}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("prepare disposable Grok worktree: %v (%s)", err, strings.TrimSpace(string(output)))
		}
	}
	runGit(primary, "init", "-b", "main")
	runGit(primary, "config", "user.email", "qualification@example.invalid")
	runGit(primary, "config", "user.name", "NTM Qualification")
	runGit(primary, "add", "README.md")
	runGit(primary, "commit", "-m", "lineage seed")
	runGit(primary, "worktree", "add", "--detach", linked, "HEAD")
	return linked
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
	runtimeHome := liveGrokRuntimeHome(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	observer := &liveACPPromptObserver{cancel: cancel}
	result, err := Run(ctx, liveACPPromptObserverRunner{base: OSRunner{}, observer: observer}, Request{
		Prompt:                  "Do not call tools, access files, or produce a response; this no-write ACP cancellation check will cancel the request immediately.",
		CWD:                     cwd,
		RuntimeHome:             runtimeHome,
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

func liveGrokRuntimeHome(t *testing.T) string {
	t.Helper()
	home := filepath.Clean(strings.TrimSpace(os.Getenv("NTM_LIVE_GROK_HOME")))
	if home == "." || !filepath.IsAbs(home) {
		t.Fatal("set NTM_LIVE_GROK_HOME to the absolute isolated GROK_HOME containing the authorized cached login")
	}
	return home
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
