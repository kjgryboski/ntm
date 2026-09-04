package provider

import "testing"

func TestNormalizeTerminalRuntimeObservationProducesSharedLiveContract(t *testing.T) {
	events := NormalizeTerminalRuntimeObservation(TerminalRuntimeObservation{
		SessionRef: "0123456789abcdef", Model: "grok-code", Accepted: true,
		ToolRequests: 1, ToolCompletions: 1, CheckpointRef: "checkpoint-sha256",
		CancellationAcknowledged: true, Completed: true, UsageObserved: true,
		InputTokens: 11, OutputTokens: 7, CleanupObserved: true,
	})
	report := ValidateRuntimeEventsForModel("grok-code", events, RuntimeEventRequirements{
		ToolLifecycle: true, Checkpoint: true, CancellationRequested: true,
	})
	if !report.Passed || report.Observed != report.Required || report.ReceiptSHA256 == "" {
		t.Fatalf("live event contract = %+v", report)
	}
}

func TestNormalizeTerminalRuntimeObservationDoesNotInventMissingEvidence(t *testing.T) {
	events := NormalizeTerminalRuntimeObservation(TerminalRuntimeObservation{
		SessionRef: "0123456789abcdef", Model: "glm-5.3", Accepted: true, Completed: true,
	})
	report := ValidateRuntimeEventsForModel("glm-5.3", events, RuntimeEventRequirements{})
	if report.Passed {
		t.Fatalf("missing usage/cleanup unexpectedly passed: %+v", report)
	}
	for _, event := range events {
		if event.Type == EventUsage || event.Type == EventCleanup {
			t.Fatalf("missing evidence was fabricated as %s", event.Type)
		}
	}
}

func TestNormalizeTerminalRuntimeObservationPreservesObservedToolOrder(t *testing.T) {
	events := NormalizeTerminalRuntimeObservation(TerminalRuntimeObservation{
		SessionRef: "0123456789abcdef", Model: "grok-code", Accepted: true,
		ObservedToolEvents: []RuntimeEvent{
			{Type: EventToolCompleted, Tool: "tool-000001"},
			{Type: EventToolRequested, Tool: "tool-000001"},
		},
		Completed: true, UsageObserved: true, CleanupObserved: true,
	})
	if events[2].Type != EventToolCompleted || events[3].Type != EventToolRequested {
		t.Fatalf("tool order was normalized instead of preserved: %+v", events)
	}
	report := ValidateRuntimeEventsForModel("grok-code", events, RuntimeEventRequirements{ToolLifecycle: true})
	if report.Passed {
		t.Fatalf("completion-before-request unexpectedly passed: %+v", report)
	}
}
