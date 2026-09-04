package provider

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeRuntime struct {
	identityHash string
	model        string
	completion   bool
	cancel       CancelObservation
	errors       []ErrorObservation
	launchErr    error
	errorsErr    error
	resume       ResumeObservation
}

func (f fakeRuntime) Launch(context.Context, Identity) (LaunchObservation, error) {
	return LaunchObservation{IdentityHash: f.identityHash, SessionID: "fake-session", NoWrites: true}, f.launchErr
}
func (f fakeRuntime) Deliver(_ context.Context, _ string, nonce string) (DeliveryObservation, error) {
	return DeliveryObservation{Submitted: true, AcknowledgedNonce: nonce, CompletionAuthoritative: f.completion}, nil
}
func (f fakeRuntime) Cancel(context.Context, string) (CancelObservation, error) { return f.cancel, nil }
func (f fakeRuntime) Recover(context.Context, string) (RecoveryObservation, error) {
	return RecoveryObservation{OutcomeUnknown: true, AutomaticReplayBlocked: true}, nil
}
func (f fakeRuntime) Resume(context.Context, string) (ResumeObservation, error) {
	return f.resume, nil
}
func (f fakeRuntime) Cleanup(context.Context, string) (CleanupObservation, error) {
	return CleanupObservation{ZeroResiduals: true}, nil
}
func (f fakeRuntime) ProviderErrors(context.Context) ([]ErrorObservation, error) {
	return f.errors, f.errorsErr
}
func (f fakeRuntime) RuntimeEvents(context.Context) ([]RuntimeEvent, error) {
	return []RuntimeEvent{
		{Type: EventAccepted, SessionID: "fake-session"},
		{Type: EventModelObserved, SessionID: "fake-session", Model: f.model},
		{Type: EventCompleted, SessionID: "fake-session"},
		{Type: EventUsage, SessionID: "fake-session", InputTokens: 1, OutputTokens: 1},
		{Type: EventCleanup, SessionID: "fake-session", ResidualProcesses: 0},
	}, nil
}

func conformanceIdentity(t *testing.T) Identity {
	t.Helper()
	id, err := NewIdentity("xai", "kevin", "grok-4", "https://api.x.ai", "grok", testConfigHash)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func zaiConformanceIdentity(t *testing.T) Identity {
	t.Helper()
	id, err := NewIdentity("zai", "kevin", "glm-5.3-flash", "https://api.z.ai/api/anthropic", "claude-glm", testConfigHash)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func conformanceFixture(id Identity) FixtureProvenance {
	return FixtureProvenance{
		FixtureID: "fixture-v1", CapturedAt: time.Now().UTC(), RuntimeVersion: "test",
		ProviderIdentityHash: id.Hash(), Source: "fake", Redacted: true,
		GoldenSignatureKeyID: "test-signer", GoldenPayloadSHA256: "test-payload-sha256", GoldenSignatureValid: true,
	}
}
func genericErrors() []ErrorObservation {
	return []ErrorObservation{{HTTPStatus: 429, Code: "rate_limit", Expected: ErrorRateLimited}, {HTTPStatus: 503, Code: "overloaded", Expected: ErrorOverloaded}}
}
func zaiErrors() []ErrorObservation {
	return []ErrorObservation{
		{429, "1302", ErrorRateLimited}, {429, "1305", ErrorOverloaded}, {429, "1308", ErrorLongPeriodQuota}, {429, "1309", ErrorPlanExpired},
		{429, "1311", ErrorUnsupportedModel}, {429, "1313", ErrorUsageRestricted}, {429, "1113", ErrorInsufficientBalance}, {401, "1000", ErrorAuthentication},
	}
}

func TestCapabilityMatrixPreservesEvidenceBoundaries(t *testing.T) {
	t.Parallel()
	matrix := CapabilityMatrix()
	if got := matrix["xai_acp"].Completion; got != EvidenceAuthoritative {
		t.Fatalf("xAI ACP completion = %q, want authoritative", got)
	}
	if got := matrix["xai_acp"].Resume; got != EvidenceUnavailable {
		t.Fatalf("xAI ACP resume = %q, want unavailable until production session/load is implemented", got)
	}
	if got := matrix["xai_acp"]; got.Cancellation != EvidenceAuthoritative || got.CancellationAuthorityScope != EvidenceAuthorityScopeAgentACP || got.Cleanup != EvidenceAuthoritative || got.CleanupAuthorityScope != EvidenceAuthorityScopeLocalProcessTree {
		t.Fatalf("xAI ACP cancellation/cleanup matrix = %+v", got)
	}
	if got := matrix["xai_grok_tui"]; got.Delivery != EvidenceSubmission || got.Completion != EvidenceUnavailable {
		t.Fatalf("Grok TUI matrix = %+v, want submission-only", got)
	}
	for transport, capabilities := range matrix {
		want := EvidenceSubmission
		if transport == "xai_headless_session" || transport == "xai_acp" || transport == "zai_codex_runtime" {
			want = EvidenceAuthoritative
		}
		if capabilities.Cleanup != want {
			t.Fatalf("%s cleanup = %q, want %q", transport, capabilities.Cleanup, want)
		}
		for name, scope := range map[string]EvidenceAuthorityScope{
			"completion":   capabilities.CompletionAuthorityScope,
			"cancellation": capabilities.CancellationAuthorityScope,
			"cleanup":      capabilities.CleanupAuthorityScope,
		} {
			if scope == "" {
				t.Fatalf("%s %s authority scope is omitted", transport, name)
			}
		}
	}
	if got := matrix["xai_headless_session"]; got.Completion != EvidenceAuthoritative || got.CompletionAuthorityScope != EvidenceAuthorityScopeProvider || got.Resume != EvidenceAuthoritative || got.Cancellation != EvidenceAuthoritative || got.CancellationAuthorityScope != EvidenceAuthorityScopeLocalProcessTree || got.Cleanup != EvidenceAuthoritative || got.CleanupAuthorityScope != EvidenceAuthorityScopeLocalProcessTree || got.CapacityControlScope != CapacityControlScopeLocalShared {
		t.Fatalf("xAI headless session matrix = %+v", got)
	}
	if got := matrix["zai_claude_runtime"]; !got.IdentityProbeRequired || got.Delivery != EvidenceSubmission || got.IdentityEvidence != IdentityEvidenceProfileAttested || got.CapacityControlScope != CapacityControlScopeLocalShared {
		t.Fatalf("Z.ai Claude-runtime matrix = %+v", got)
	}
	if got := matrix["zai_codex_runtime"]; !got.IdentityProbeRequired || got.Launch != EvidenceAuthoritative || got.Delivery != EvidenceAuthoritative || got.Completion != EvidenceAuthoritative || got.CompletionAuthorityScope != EvidenceAuthorityScopeProvider || got.Cancellation != EvidenceAuthoritative || got.CancellationAuthorityScope != EvidenceAuthorityScopeLocalProcessTree || got.Resume != EvidenceAuthoritative || got.Cleanup != EvidenceAuthoritative || got.CleanupAuthorityScope != EvidenceAuthorityScopeLocalProcessTree || got.LaunchCapacityControl != EvidenceAuthoritative || got.RequestCapacityControl != EvidenceAuthoritative || got.CapacityControlScope != CapacityControlScopeLocalShared {
		t.Fatalf("Z.ai Codex-runtime matrix = %+v", got)
	}
	if got := matrix["zai_native_api"]; !got.IdentityProbeRequired || got.Launch != EvidenceAuthoritative || got.Delivery != EvidenceAuthoritative || got.Completion != EvidenceAuthoritative || got.CompletionAuthorityScope != EvidenceAuthorityScopeProvider || got.LiveErrorFeedback != EvidenceAuthoritative || got.Cancellation != EvidenceUnavailable || got.CancellationAuthorityScope != EvidenceAuthorityScopeUnavailable || got.Resume != EvidenceUnavailable || got.Cleanup != EvidenceSubmission || got.CleanupAuthorityScope != EvidenceAuthorityScopeLocalClient || got.CapacityControlScope != CapacityControlScopeLocalShared {
		t.Fatalf("Z.ai native API matrix = %+v", got)
	}
}

func TestRunConformanceGrokHeadlessBindsResumeWithoutProviderCancelOverclaim(t *testing.T) {
	t.Parallel()
	id := conformanceIdentity(t)
	report := RunConformance(context.Background(), fakeRuntime{
		identityHash: id.Hash(), model: id.Model(), completion: true,
		cancel: CancelObservation{Attempted: true, Authoritative: true},
		resume: ResumeObservation{Resumed: true, SameSessionID: true},
		errors: genericErrors(),
	}, "xai_headless_session", id, conformanceFixture(id), "nonce-headless")
	if !report.Passed() {
		t.Fatalf("headless report = %+v", report)
	}
}

func TestRunConformanceACPAuthoritativeCompletion(t *testing.T) {
	t.Parallel()
	id := conformanceIdentity(t)
	report := RunConformance(context.Background(), fakeRuntime{identityHash: id.Hash(), model: id.Model(), completion: true, cancel: CancelObservation{Attempted: true, AgentACPAcknowledged: true}, errors: genericErrors()}, "xai_acp", id, conformanceFixture(id), "nonce-1")
	if !report.Passed() {
		t.Fatalf("report = %+v", report)
	}
}

func TestRunConformanceACPRejectsCloudCancellationOverclaim(t *testing.T) {
	t.Parallel()
	id := conformanceIdentity(t)
	report := RunConformance(context.Background(), fakeRuntime{
		identityHash: id.Hash(), model: id.Model(), completion: true,
		cancel: CancelObservation{Attempted: true, AgentACPAcknowledged: true, CloudInferenceStopConfirmed: true},
		errors: genericErrors(),
	}, "xai_acp", id, conformanceFixture(id), "nonce-cloud-overclaim")
	if report.Passed() || checkByName(report, "cancellation_semantics").Passed {
		t.Fatalf("xAI ACP cloud cancellation overclaim was accepted: %+v", report)
	}
}

func TestRunConformanceZAIRequiresEveryExactErrorClass(t *testing.T) {
	t.Parallel()
	id := zaiConformanceIdentity(t)
	report := RunConformance(context.Background(), fakeRuntime{identityHash: id.Hash(), model: id.Model(), cancel: CancelObservation{Attempted: true}, errors: zaiErrors()}, "zai_claude_runtime", id, conformanceFixture(id), "nonce-1")
	if !report.Passed() {
		t.Fatalf("report = %+v", report)
	}
	report = RunConformance(context.Background(), fakeRuntime{identityHash: id.Hash(), model: id.Model(), cancel: CancelObservation{Attempted: true}, errors: zaiErrors()[:7]}, "zai_claude_runtime", id, conformanceFixture(id), "nonce-1")
	if report.Passed() || checkByName(report, "provider_error_taxonomy").Passed {
		t.Fatalf("incomplete Z.ai taxonomy must fail: %+v", report)
	}
}

func TestRunConformanceZAINativeDoesNotPromoteUnavailableLifecycle(t *testing.T) {
	t.Parallel()
	id := zaiConformanceIdentity(t)
	baseline := fakeRuntime{identityHash: id.Hash(), model: id.Model(), completion: true, cancel: CancelObservation{Attempted: true}, errors: zaiErrors()}
	report := RunConformance(context.Background(), baseline, "zai_native_api", id, conformanceFixture(id), "nonce-native")
	if !report.Passed() {
		t.Fatalf("native baseline report = %+v", report)
	}
	unsupported := baseline
	unsupported.cancel = CancelObservation{Attempted: true, Authoritative: true}
	unsupported.resume = ResumeObservation{Resumed: true, SameSessionID: true}
	report = RunConformance(context.Background(), unsupported, "zai_native_api", id, conformanceFixture(id), "nonce-native-overclaim")
	if report.Passed() || len(report.Discrepancies) == 0 || checkByName(report, "session_resumption").Passed {
		t.Fatalf("native lifecycle overclaim was accepted: %+v", report)
	}
}

func TestRunConformanceRejectsUnsupportedAuthoritativeCancellation(t *testing.T) {
	t.Parallel()
	id := conformanceIdentity(t)
	report := RunConformance(context.Background(), fakeRuntime{identityHash: id.Hash(), model: id.Model(), cancel: CancelObservation{Attempted: true, Authoritative: true}, errors: genericErrors()}, "xai_grok_tui", id, conformanceFixture(id), "nonce-2")
	if report.Passed() || len(report.Discrepancies) == 0 {
		t.Fatalf("unsupported authoritative cancellation must be a discrepancy: %+v", report)
	}
}

func TestRunConformanceEarlyFailureHasFixedSevenCheckCoverage(t *testing.T) {
	t.Parallel()
	id := conformanceIdentity(t)
	report := RunConformance(context.Background(), fakeRuntime{identityHash: id.Hash(), model: id.Model(), launchErr: errors.New("token=super-secret")}, "xai_acp", id, conformanceFixture(id), "nonce")
	if report.Coverage.Required != 7 || len(report.Checks) != 7 || report.Coverage.Satisfied != 0 || report.Passed() {
		t.Fatalf("early failure coverage = %+v", report)
	}
}

func TestRunConformanceRejectsUnknownOutcomeAutomaticReplay(t *testing.T) {
	t.Parallel()
	id := conformanceIdentity(t)
	runtime := unsafeReplayRuntime{fakeRuntime: fakeRuntime{
		identityHash: id.Hash(),
		model:        id.Model(),
		completion:   true,
		cancel:       CancelObservation{Attempted: true},
		errors:       genericErrors(),
	}}
	report := RunConformance(context.Background(), runtime, "xai_acp", id, conformanceFixture(id), "nonce-replay")
	if report.Passed() || checkByName(report, "crash_outcome_unknown_recovery").Passed {
		t.Fatalf("outcome-unknown recovery must block automatic replay: %+v", report)
	}
}

type unsafeReplayRuntime struct{ fakeRuntime }

func (unsafeReplayRuntime) Recover(context.Context, string) (RecoveryObservation, error) {
	return RecoveryObservation{OutcomeUnknown: true, AutomaticReplayBlocked: false}, nil
}

func TestConformanceReceiptNeverSerializesFixtureOrErrorSecrets(t *testing.T) {
	t.Parallel()
	id := conformanceIdentity(t)
	fixture := conformanceFixture(id)
	fixture.FixtureID, fixture.RuntimeVersion, fixture.Source = "fixture-secret-123", "runtime-secret-456", "source-secret-789"
	report := RunConformance(context.Background(), fakeRuntime{identityHash: id.Hash(), model: id.Model(), launchErr: errors.New("provider response token=error-secret-000")}, "xai_acp", id, fixture, "nonce")
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"fixture-secret-123", "runtime-secret-456", "source-secret-789", "error-secret-000"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("receipt leaked %q: %s", secret, encoded)
		}
	}
	if checkByName(report, "no_write_launch_identity").ErrorSHA256 == "" || report.FixtureReceiptSHA256 == "" {
		t.Fatalf("safe receipt hashes missing: %+v", report)
	}
}

func TestClassifyTransportErrorExact(t *testing.T) {
	t.Parallel()
	if got := ClassifyTransportError(429, "anything"); got != TransportRateLimited {
		t.Fatalf("429 = %q", got)
	}
	if got := ClassifyTransportError(400, "unsupported_model"); got != TransportUnsupportedModel {
		t.Fatalf("unsupported model = %q", got)
	}
}

func TestSharedProviderRuntimeContractReplaysRedactedWireFixtures(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, transport, providerName, model string }{
		{"grok ACP", "xai_acp", "xai", "grok-code"},
		{"Z.ai Responses", "zai_codex_runtime", "zai", "glm-5.3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scenario, found, err := LoadOfflineScenario(tc.transport)
			if err != nil || !found {
				t.Fatalf("LoadOfflineScenario() found=%v err=%v", found, err)
			}
			if err := scenario.VerifyGoldenSignature(); err != nil {
				t.Fatalf("scenario=%s golden signature: %v", scenario.ID, err)
			}
			identity, err := NewIdentity(tc.providerName, "fixture", tc.model, "https://fixture.invalid", "fixture", testConfigHash)
			if err != nil {
				t.Fatal(err)
			}
			events, err := scenario.Normalize()
			if err != nil {
				t.Fatal(err)
			}
			report := ValidateRuntimeEventsForOperation(identity, events, scenario.Requirements)
			if !scenario.ExpectedPass || !report.Passed || report.Observed != report.Required || report.ReceiptSHA256 == "" {
				t.Fatalf("scenario=%s report=%+v", scenario.ID, report)
			}
			if rerun := ValidateRuntimeEventsForOperation(identity, events, scenario.Requirements); rerun.ReceiptSHA256 != report.ReceiptSHA256 {
				t.Fatalf("scenario=%s receipt digest drifted: %s != %s", scenario.ID, rerun.ReceiptSHA256, report.ReceiptSHA256)
			}
			tampered := scenario
			tampered.Events = append([]WireEvent(nil), scenario.Events...)
			tampered.Events[0].SessionID = "tampered"
			if err := tampered.VerifyGoldenSignature(); err == nil {
				t.Fatalf("scenario=%s accepted a fixture mutation under the golden signature", scenario.ID)
			}
		})
	}
}

func TestSharedProviderRuntimeContractFaultInjection(t *testing.T) {
	t.Parallel()
	for _, lab := range []struct {
		name, transport, providerName, model, session, remappedModel string
	}{
		{"Grok ACP", "xai_acp", "xai", "grok-code", "redacted-acp-session", "grok-other"},
		{"Z.ai Responses", "zai_codex_runtime", "zai", "glm-5.3", "redacted-response", "glm-4"},
	} {
		t.Run(lab.name, func(t *testing.T) {
			scenario, found, err := LoadOfflineScenario(lab.transport)
			if err != nil || !found {
				t.Fatalf("fixture: found=%v err=%v", found, err)
			}
			identity, err := NewIdentity(lab.providerName, "fixture", lab.model, "https://fixture.invalid", "fixture", testConfigHash)
			if err != nil {
				t.Fatal(err)
			}
			base, err := scenario.Normalize()
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				name   string
				mutate func([]RuntimeEvent) []RuntimeEvent
			}{
				{"missing model id", func(events []RuntimeEvent) []RuntimeEvent { events[1].Model = ""; return events }},
				{"conflicting model id", func(events []RuntimeEvent) []RuntimeEvent {
					return append(events, RuntimeEvent{Type: EventModelObserved, SessionID: lab.session, Model: "other"})
				}},
				{"remapped model id", func(events []RuntimeEvent) []RuntimeEvent { events[1].Model = lab.remappedModel; return events }},
				{"conflicting session", func(events []RuntimeEvent) []RuntimeEvent { events[2].SessionID = "other-session"; return events }},
				{"reordered lifecycle", func(events []RuntimeEvent) []RuntimeEvent { events[0], events[6] = events[6], events[0]; return events }},
				{"tool result before request", func(events []RuntimeEvent) []RuntimeEvent { events[2], events[3] = events[3], events[2]; return events }},
				{"crash without completion", func(events []RuntimeEvent) []RuntimeEvent { return append(events[:6], events[7:]...) }},
				{"residual process", func(events []RuntimeEvent) []RuntimeEvent { events[len(events)-1].ResidualProcesses = 1; return events }},
			} {
				t.Run(tc.name, func(t *testing.T) {
					events := append([]RuntimeEvent(nil), base...)
					if report := ValidateRuntimeEventsForOperation(identity, tc.mutate(events), scenario.Requirements); report.Passed {
						t.Fatalf("fault was accepted: %+v", report)
					}
				})
			}
		})
	}
	for _, malformed := range []struct{ family, event string }{{"responses", "response.unknown"}, {"acp", "session/unknown"}} {
		if _, err := NormalizeWireEvents(malformed.family, []WireEvent{{Type: malformed.event}}); err == nil {
			t.Fatalf("malformed %s event was accepted", malformed.family)
		}
	}
	for _, quotaCase := range []struct{ family, event string }{{"responses", "response.completed"}, {"acp", "session/complete"}} {
		quota, err := NormalizeWireEvents(quotaCase.family, []WireEvent{{Type: quotaCase.event, SessionID: "s", HTTPStatus: 429, Code: "1308"}})
		if err != nil || quota[0].Error == nil || quota[0].Error.Expected != ErrorLongPeriodQuota {
			t.Fatalf("%s quota normalization=%+v err=%v", quotaCase.family, quota, err)
		}
	}
}

func TestSharedProviderRuntimeContractDoesNotFabricateOptionalEvents(t *testing.T) {
	identity, err := NewIdentity("xai", "fixture", "grok-code", "https://fixture.invalid", "fixture", testConfigHash)
	if err != nil {
		t.Fatal(err)
	}
	events := []RuntimeEvent{
		{Type: EventAccepted, SessionID: "observe"},
		{Type: EventModelObserved, SessionID: "observe", Model: "grok-code"},
		{Type: EventCompleted, SessionID: "observe"},
		{Type: EventUsage, SessionID: "observe", InputTokens: 1, OutputTokens: 1},
		{Type: EventCleanup, SessionID: "observe"},
	}
	if report := ValidateRuntimeEvents(identity, events); !report.Passed || report.Required != len(baselineRequiredRuntimeEvents) {
		t.Fatalf("no-tool observe stream should pass without fabricated tool/cancel events: %+v", report)
	}
	if report := ValidateRuntimeEventsForOperation(identity, events, RuntimeEventRequirements{CancellationRequested: true}); report.Passed {
		t.Fatalf("cancel-requested operation accepted without acknowledgement: %+v", report)
	}
}

func checkByName(report ConformanceReport, name string) CheckResult {
	for _, check := range report.Checks {
		if check.Name == name {
			return check
		}
	}
	return CheckResult{}
}
