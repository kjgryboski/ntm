package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// RuntimeEventType is the provider-neutral lifecycle vocabulary. Adapters are
// required to normalize their wire protocols into these names before NTM makes
// an admission or lifecycle claim.
type RuntimeEventType string

const (
	EventAccepted                 RuntimeEventType = "accepted"
	EventModelObserved            RuntimeEventType = "model_observed"
	EventToolRequested            RuntimeEventType = "tool_requested"
	EventToolCompleted            RuntimeEventType = "tool_completed"
	EventCheckpoint               RuntimeEventType = "checkpoint"
	EventCancellationAcknowledged RuntimeEventType = "cancellation_acknowledged"
	EventCompleted                RuntimeEventType = "completed"
	EventUsage                    RuntimeEventType = "usage"
	EventCleanup                  RuntimeEventType = "cleanup"
)

var runtimeEventOrder = []RuntimeEventType{
	EventAccepted, EventModelObserved, EventToolRequested, EventToolCompleted,
	EventCheckpoint, EventCancellationAcknowledged, EventCompleted, EventUsage, EventCleanup,
}

var baselineRequiredRuntimeEvents = []RuntimeEventType{
	EventAccepted, EventModelObserved, EventCompleted, EventUsage, EventCleanup,
}

// RuntimeEventRequirements describes what the controller actually requested.
// A no-tool success must not fabricate tool or cancellation events; a cancel
// qualification, by contrast, must explicitly require its acknowledgement.
type RuntimeEventRequirements struct {
	ToolLifecycle         bool `json:"tool_lifecycle"`
	Checkpoint            bool `json:"checkpoint"`
	CancellationRequested bool `json:"cancellation_requested"`
}

func (r RuntimeEventRequirements) eventTypes() []RuntimeEventType {
	required := append([]RuntimeEventType(nil), baselineRequiredRuntimeEvents...)
	if r.ToolLifecycle {
		required = append(required, EventToolRequested, EventToolCompleted)
	}
	if r.Checkpoint {
		required = append(required, EventCheckpoint)
	}
	if r.CancellationRequested {
		required = append(required, EventCancellationAcknowledged)
	}
	return required
}

// RuntimeEvent contains redaction-safe fields shared by ACP and Responses.
// It deliberately has no prompt, output, command, path, or credential field.
type RuntimeEvent struct {
	Type              RuntimeEventType  `json:"type"`
	SessionID         string            `json:"session_id,omitempty"`
	Model             string            `json:"model,omitempty"`
	ResolvedModel     string            `json:"resolved_model,omitempty"`
	Tool              string            `json:"tool,omitempty"`
	CheckpointID      string            `json:"checkpoint_id,omitempty"`
	Error             *ErrorObservation `json:"error,omitempty"`
	InputTokens       int64             `json:"input_tokens,omitempty"`
	OutputTokens      int64             `json:"output_tokens,omitempty"`
	ResidualProcesses int               `json:"residual_processes,omitempty"`
}

// TerminalRuntimeObservation is the redaction-safe common input used by live
// provider adapters after their wire-specific parser has validated ordering
// and terminal state. SessionRef must already be a non-secret stable digest.
// Tool counts describe structured terminal tool observations, never inferred
// prompt intent or raw arguments.
type TerminalRuntimeObservation struct {
	SessionRef    string
	Model         string
	ResolvedModel string
	Accepted      bool
	// ObservedToolEvents preserves the redaction-safe order in which the
	// adapter observed tool lifecycle frames. When present, it must contain
	// only EventToolRequested and EventToolCompleted values. Adapters must not
	// replace this sequence with aggregate counts: doing so could turn a
	// completion-before-request protocol violation into an apparently valid
	// lifecycle.
	ObservedToolEvents       []RuntimeEvent
	ToolRequests             int
	ToolCompletions          int
	CheckpointRef            string
	CancellationAcknowledged bool
	Completed                bool
	UsageObserved            bool
	InputTokens              int64
	OutputTokens             int64
	CleanupObserved          bool
	ResidualProcesses        int
}

// NormalizeTerminalRuntimeObservation emits the same ordered vocabulary for
// ACP and Responses adapters. Missing evidence stays missing so the contract
// validator can fail closed instead of manufacturing a successful lifecycle.
func NormalizeTerminalRuntimeObservation(observation TerminalRuntimeObservation) []RuntimeEvent {
	toolEventCapacity := observation.ToolRequests + observation.ToolCompletions
	if observation.ObservedToolEvents != nil {
		toolEventCapacity = len(observation.ObservedToolEvents)
	}
	events := make([]RuntimeEvent, 0, 7+toolEventCapacity)
	appendEvent := func(event RuntimeEvent) {
		event.SessionID = observation.SessionRef
		events = append(events, event)
	}
	if observation.Accepted {
		appendEvent(RuntimeEvent{Type: EventAccepted})
	}
	if strings.TrimSpace(observation.Model) != "" {
		appendEvent(RuntimeEvent{Type: EventModelObserved, Model: strings.TrimSpace(observation.Model), ResolvedModel: strings.TrimSpace(observation.ResolvedModel)})
	}
	if observation.ObservedToolEvents != nil {
		for _, observed := range observation.ObservedToolEvents {
			// Retain only the shared, redaction-safe lifecycle fields. A malformed
			// type is deliberately retained for the validator to reject; silently
			// dropping it would conceal protocol evidence.
			appendEvent(RuntimeEvent{Type: observed.Type, Tool: strings.TrimSpace(observed.Tool)})
		}
	} else {
		// This compatibility path is for callers that have no structured tool
		// stream. Live adapters must supply ObservedToolEvents.
		for index := 0; index < observation.ToolRequests; index++ {
			appendEvent(RuntimeEvent{Type: EventToolRequested, Tool: fmt.Sprintf("tool-%06d", index+1)})
		}
		for index := 0; index < observation.ToolCompletions; index++ {
			appendEvent(RuntimeEvent{Type: EventToolCompleted, Tool: fmt.Sprintf("tool-%06d", index+1)})
		}
	}
	if strings.TrimSpace(observation.CheckpointRef) != "" {
		appendEvent(RuntimeEvent{Type: EventCheckpoint, CheckpointID: strings.TrimSpace(observation.CheckpointRef)})
	}
	if observation.CancellationAcknowledged {
		appendEvent(RuntimeEvent{Type: EventCancellationAcknowledged})
	}
	if observation.Completed {
		appendEvent(RuntimeEvent{Type: EventCompleted})
	}
	if observation.UsageObserved {
		appendEvent(RuntimeEvent{Type: EventUsage, InputTokens: observation.InputTokens, OutputTokens: observation.OutputTokens})
	}
	if observation.CleanupObserved {
		appendEvent(RuntimeEvent{Type: EventCleanup, ResidualProcesses: observation.ResidualProcesses})
	}
	return events
}

// WireEvent is a redacted protocol frame. The fixture format intentionally
// permits only scalar metadata; unknown frame names fail closed.
type WireEvent struct {
	Type              string `json:"type"`
	SessionID         string `json:"session_id,omitempty"`
	Model             string `json:"model,omitempty"`
	ResolvedModel     string `json:"resolved_model,omitempty"`
	Tool              string `json:"tool,omitempty"`
	CheckpointID      string `json:"checkpoint_id,omitempty"`
	HTTPStatus        int    `json:"http_status,omitempty"`
	Code              string `json:"code,omitempty"`
	InputTokens       int64  `json:"input_tokens,omitempty"`
	OutputTokens      int64  `json:"output_tokens,omitempty"`
	ResidualProcesses int    `json:"residual_processes,omitempty"`
}

// NormalizeWireEvents maps the two supported wire families into the one
// contract. The mapping is intentionally closed: a newly observed wire event
// must be reviewed before it can influence lifecycle evidence.
func NormalizeWireEvents(family string, wire []WireEvent) ([]RuntimeEvent, error) {
	var mapping map[string]RuntimeEventType
	switch family {
	case "acp":
		mapping = map[string]RuntimeEventType{
			"session/prompt": EventAccepted, "session/model": EventModelObserved,
			"tool/call": EventToolRequested, "tool/result": EventToolCompleted,
			"session/checkpoint": EventCheckpoint, "session/cancelled": EventCancellationAcknowledged,
			"session/complete": EventCompleted, "session/usage": EventUsage, "session/cleanup": EventCleanup,
		}
	case "responses":
		mapping = map[string]RuntimeEventType{
			"response.created": EventAccepted, "response.model": EventModelObserved,
			"response.tool_call": EventToolRequested, "response.tool_result": EventToolCompleted,
			"response.checkpoint": EventCheckpoint, "response.cancelled": EventCancellationAcknowledged,
			"response.completed": EventCompleted, "response.usage": EventUsage, "response.cleanup": EventCleanup,
		}
	default:
		return nil, fmt.Errorf("unsupported provider wire family %q", family)
	}
	events := make([]RuntimeEvent, 0, len(wire))
	for index, frame := range wire {
		kind, ok := mapping[frame.Type]
		if !ok {
			return nil, fmt.Errorf("%s frame %d has unknown type %q", family, index, frame.Type)
		}
		event := RuntimeEvent{Type: kind, SessionID: frame.SessionID, Model: frame.Model, ResolvedModel: frame.ResolvedModel, Tool: frame.Tool, CheckpointID: frame.CheckpointID, InputTokens: frame.InputTokens, OutputTokens: frame.OutputTokens, ResidualProcesses: frame.ResidualProcesses}
		if frame.HTTPStatus != 0 || frame.Code != "" {
			event.Error = &ErrorObservation{HTTPStatus: frame.HTTPStatus, Code: frame.Code, Expected: ClassifyProviderError(frame.HTTPStatus, frame.Code)}
		}
		events = append(events, event)
	}
	return events, nil
}

// EventContractReport is a replayable assertion about a normalized stream.
// ReceiptSHA256 is a tamper-evident digest, not a signature. Offline fixture
// authenticity is established separately by OfflineGoldenSignature.
type EventContractReport struct {
	Required      int      `json:"required"`
	Observed      int      `json:"observed"`
	Passed        bool     `json:"passed"`
	Violations    []string `json:"violations"`
	ReceiptSHA256 string   `json:"receipt_sha256"`
}

func ValidateRuntimeEvents(identity Identity, events []RuntimeEvent) EventContractReport {
	return ValidateRuntimeEventsForOperation(identity, events, RuntimeEventRequirements{})
}

func ValidateRuntimeEventsForOperation(identity Identity, events []RuntimeEvent, requirements RuntimeEventRequirements) EventContractReport {
	return validateRuntimeEventsForModel(identity.Model(), events, requirements)
}

// ValidateRuntimeEventsForModel lets a wire adapter validate the common event
// stream before the CLI layer binds the same report to the full immutable
// provider identity. Requested configuration is not itself model evidence: a
// model_observed event must still be present in the parsed stream.
func ValidateRuntimeEventsForModel(model string, events []RuntimeEvent, requirements RuntimeEventRequirements) EventContractReport {
	return validateRuntimeEventsForModel(strings.TrimSpace(model), events, requirements)
}

func validateRuntimeEventsForModel(expectedModel string, events []RuntimeEvent, requirements RuntimeEventRequirements) EventContractReport {
	requiredEvents := requirements.eventTypes()
	report := EventContractReport{Required: len(requiredEvents), Violations: []string{}}
	seen := make(map[RuntimeEventType]bool, len(runtimeEventOrder))
	models := make(map[string]bool)
	firstIndex := make(map[RuntimeEventType]int, len(runtimeEventOrder))
	supported := make(map[RuntimeEventType]bool, len(runtimeEventOrder))
	for _, kind := range runtimeEventOrder {
		supported[kind] = true
	}
	sessionID := ""
	pendingTools := make(map[string]int)
	for index, event := range events {
		if event.Type == "" {
			report.Violations = append(report.Violations, fmt.Sprintf("event %d has no normalized type", index))
			continue
		}
		if !supported[event.Type] {
			report.Violations = append(report.Violations, fmt.Sprintf("event %d has unsupported normalized type %q", index, event.Type))
			continue
		}
		if !seen[event.Type] {
			firstIndex[event.Type] = index
		}
		seen[event.Type] = true
		if event.SessionID == "" {
			report.Violations = append(report.Violations, fmt.Sprintf("%s has no session id", event.Type))
		} else {
			if sessionID == "" {
				sessionID = event.SessionID
			} else if event.SessionID != sessionID {
				report.Violations = append(report.Violations, fmt.Sprintf("%s is bound to a conflicting session id", event.Type))
			}
		}
		switch event.Type {
		case EventModelObserved:
			if event.Model == "" {
				report.Violations = append(report.Violations, "model_observed has no model")
			} else {
				models[event.Model] = true
			}
			if len(event.ResolvedModel) > 4096 || strings.IndexFunc(event.ResolvedModel, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
				report.Violations = append(report.Violations, "model_observed has invalid resolved model")
			}
		case EventToolRequested:
			if event.Tool == "" {
				report.Violations = append(report.Violations, fmt.Sprintf("%s has no tool", event.Type))
			} else {
				pendingTools[event.Tool]++
			}
		case EventToolCompleted:
			if event.Tool == "" {
				report.Violations = append(report.Violations, fmt.Sprintf("%s has no tool", event.Type))
			} else if pendingTools[event.Tool] == 0 {
				report.Violations = append(report.Violations, "tool_completed has no matching request")
			} else {
				pendingTools[event.Tool]--
			}
		case EventCheckpoint:
			if event.CheckpointID == "" {
				report.Violations = append(report.Violations, "checkpoint has no checkpoint id")
			}
		case EventUsage:
			if event.InputTokens < 0 || event.OutputTokens < 0 {
				report.Violations = append(report.Violations, "usage has negative token count")
			}
		case EventCleanup:
			if event.ResidualProcesses != 0 {
				report.Violations = append(report.Violations, "cleanup reports residual processes")
			}
		}
	}
	for tool, count := range pendingTools {
		if count != 0 {
			report.Violations = append(report.Violations, fmt.Sprintf("tool %q has %d incomplete request(s)", tool, count))
		}
	}
	for _, kind := range requiredEvents {
		if seen[kind] {
			report.Observed++
		} else {
			report.Violations = append(report.Violations, "missing "+string(kind))
		}
	}
	if len(models) != 1 || expectedModel == "" || !models[expectedModel] {
		report.Violations = append(report.Violations, "observed model does not exactly match provider identity")
	}
	for earlier := 0; earlier < len(runtimeEventOrder); earlier++ {
		before, beforeOK := firstIndex[runtimeEventOrder[earlier]]
		if !beforeOK {
			continue
		}
		for later := earlier + 1; later < len(runtimeEventOrder); later++ {
			after, afterOK := firstIndex[runtimeEventOrder[later]]
			if afterOK && after < before {
				report.Violations = append(report.Violations, fmt.Sprintf("%s occurred before %s", runtimeEventOrder[later], runtimeEventOrder[earlier]))
			}
		}
	}
	report.Passed = len(report.Violations) == 0
	report.ReceiptSHA256 = runtimeEventDigest(events)
	return report
}

func runtimeEventDigest(events []RuntimeEvent) string {
	parts := make([]string, 0, len(events))
	for _, event := range events {
		errorClass := ""
		if event.Error != nil {
			errorClass = string(event.Error.Expected)
		}
		part := strings.Join([]string{string(event.Type), event.SessionID, event.Model, event.Tool, event.CheckpointID, errorClass, fmt.Sprint(event.InputTokens), fmt.Sprint(event.OutputTokens), fmt.Sprint(event.ResidualProcesses)}, "\x00")
		if event.ResolvedModel != "" {
			part += "\x00resolved=" + event.ResolvedModel
		}
		parts = append(parts, part)
	}
	// Event order is security-relevant lifecycle evidence. Reordering a
	// completion before acceptance or a tool result before its request must
	// change the receipt and fail validation rather than normalize away.
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}
