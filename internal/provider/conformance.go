package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

const conformanceRequiredChecks = 7

var conformanceCheckNames = []string{
	"no_write_launch_identity", "delivery_nonce_acknowledgement", "provider_error_taxonomy",
	"cancellation_semantics", "crash_outcome_unknown_recovery", "session_resumption", "zero_residual_cleanup",
}

// FixtureProvenance identifies a redacted, replayable fake-runtime fixture.
// Its raw locator/version/source remain available locally, but are intentionally
// never serialized in a conformance receipt.
type FixtureProvenance struct {
	FixtureID            string    `json:"-"`
	CapturedAt           time.Time `json:"captured_at"`
	RuntimeVersion       string    `json:"-"`
	ProviderIdentityHash string    `json:"provider_identity_hash"`
	// SignedEventModel is the exact model recorded inside a verified offline
	// protocol fixture. It scopes only the replay contract; it is never live
	// evidence for the operator-selected provider identity.
	SignedEventModel     string `json:"signed_event_model,omitempty"`
	Source               string `json:"-"`
	Redacted             bool   `json:"redacted"`
	GoldenSignatureKeyID string `json:"golden_signature_key_id,omitempty"`
	GoldenPayloadSHA256  string `json:"golden_payload_sha256,omitempty"`
	GoldenSignatureValid bool   `json:"golden_signature_valid"`
}

func (f FixtureProvenance) ReceiptHash() string {
	return hashSafe(strings.Join([]string{f.FixtureID, f.CapturedAt.UTC().Format(time.RFC3339Nano), f.RuntimeVersion, f.ProviderIdentityHash, f.SignedEventModel, f.Source, boolString(f.Redacted), f.GoldenSignatureKeyID, f.GoldenPayloadSHA256, boolString(f.GoldenSignatureValid)}, "\x00"))
}

type LaunchObservation struct {
	IdentityHash, SessionID string
	NoWrites                bool
}
type DeliveryObservation struct {
	Submitted               bool
	AcknowledgedNonce       string
	CompletionAuthoritative bool
}
type CancelObservation struct {
	Attempted     bool
	Authoritative bool
	// AgentACPAcknowledged is valid only for an agent_acp capability scope. It
	// means the original session/prompt response reported stopReason=cancelled
	// for this operation; it does not claim cloud-inference cancellation.
	AgentACPAcknowledged        bool
	CloudInferenceStopConfirmed bool
}
type RecoveryObservation struct {
	OutcomeUnknown         bool
	AutomaticReplayBlocked bool
}
type ResumeObservation struct {
	Resumed       bool
	SameSessionID bool
}
type CleanupObservation struct{ ZeroResiduals bool }

// ErrorObservation has no provider-message field by design. Raw provider
// responses remain outside the fixture and receipt path.
type ErrorObservation struct {
	HTTPStatus int
	Code       string
	Expected   ErrorClass
}

// Runtime is deliberately small and fake-friendly. Production adapters can
// implement it later, but this package does not launch a runtime or read a
// credential by itself.
type Runtime interface {
	Launch(context.Context, Identity) (LaunchObservation, error)
	Deliver(context.Context, string, string) (DeliveryObservation, error)
	Cancel(context.Context, string) (CancelObservation, error)
	Recover(context.Context, string) (RecoveryObservation, error)
	Resume(context.Context, string) (ResumeObservation, error)
	Cleanup(context.Context, string) (CleanupObservation, error)
	ProviderErrors(context.Context) ([]ErrorObservation, error)
}

// EventRuntime is implemented by adapters that can replay or emit the shared
// provider-runtime contract. Keeping it optional preserves legacy lifecycle
// adapters while the robot conformance surface always exercises it.
type EventRuntime interface {
	RuntimeEvents(context.Context) ([]RuntimeEvent, error)
}

type EventRuntimeRequirementSource interface {
	RuntimeEventRequirements() RuntimeEventRequirements
}

type CheckResult struct {
	Name        string `json:"name"`
	Passed      bool   `json:"passed"`
	Detail      string `json:"detail,omitempty"`
	ErrorSHA256 string `json:"error_sha256,omitempty"`
}

type ConformanceReport struct {
	Fixture              FixtureProvenance     `json:"fixture"`
	FixtureReceiptSHA256 string                `json:"fixture_receipt_sha256"`
	Transport            string                `json:"transport"`
	Capabilities         OperationCapabilities `json:"capabilities"`
	Checks               []CheckResult         `json:"checks"`
	Coverage             CoverageReport        `json:"coverage"`
	Discrepancies        []string              `json:"discrepancies"`
	EventContract        *EventContractReport  `json:"event_contract,omitempty"`
}

type CoverageReport struct {
	Required  int `json:"required"`
	Satisfied int `json:"satisfied"`
}

func (r ConformanceReport) Passed() bool {
	if r.Coverage.Required != conformanceRequiredChecks || r.Coverage.Satisfied != conformanceRequiredChecks || len(r.Checks) != conformanceRequiredChecks || len(r.Discrepancies) != 0 {
		return false
	}
	if r.EventContract != nil && !r.EventContract.Passed {
		return false
	}
	for _, check := range r.Checks {
		if !check.Passed {
			return false
		}
	}
	return true
}

// RunConformance verifies seven lifecycle claims against a fake Runtime. It
// never creates sessions or makes network/provider calls itself. Every report
// has all seven checks, including when launch/fixture validation fails.
func RunConformance(ctx context.Context, runtime Runtime, transport string, identity Identity, fixture FixtureProvenance, nonce string) (report ConformanceReport) {
	report = ConformanceReport{Fixture: fixture, FixtureReceiptSHA256: fixture.ReceiptHash(), Transport: transport, Checks: newChecks(), Discrepancies: []string{}}
	defer func() { report.Coverage = coverageFor(report.Checks) }()
	capabilities, known := CapabilityMatrix()[transport]
	if !known {
		report.failAll("unknown transport")
		return report
	}
	report.Capabilities = capabilities
	if runtime == nil || nonce == "" || fixture.FixtureID == "" || !fixture.Redacted || fixture.ProviderIdentityHash != identity.Hash() {
		report.failAll("invalid runtime, nonce, or redacted fixture provenance")
		return report
	}
	if eventRuntime, ok := runtime.(EventRuntime); ok {
		events, eventErr := eventRuntime.RuntimeEvents(ctx)
		if eventErr != nil {
			contract := EventContractReport{Required: len(baselineRequiredRuntimeEvents), Violations: []string{"event replay failed"}}
			report.EventContract = &contract
		} else if len(events) == 0 {
			contract := EventContractReport{Required: len(baselineRequiredRuntimeEvents), Violations: []string{"transport has no signed offline protocol fixture"}}
			report.EventContract = &contract
		} else {
			if !fixture.GoldenSignatureValid || fixture.GoldenSignatureKeyID == "" || fixture.GoldenPayloadSHA256 == "" {
				contract := EventContractReport{Required: len(baselineRequiredRuntimeEvents), Violations: []string{"event runtime fixture lacks a verified golden signature"}}
				report.EventContract = &contract
			} else {
				requirements := RuntimeEventRequirements{}
				if source, ok := runtime.(EventRuntimeRequirementSource); ok {
					requirements = source.RuntimeEventRequirements()
				}
				// A signed offline capture may intentionally use a different model
				// than the selected local profile. Validate the capture against the
				// model it actually contains; profile identity remains the separate
				// launch/admission boundary and receives no live qualification from
				// this synthetic report.
				expectedModel := identity.Model()
				if strings.TrimSpace(fixture.SignedEventModel) != "" {
					expectedModel = strings.TrimSpace(fixture.SignedEventModel)
				}
				contract := ValidateRuntimeEventsForModel(expectedModel, events, requirements)
				report.EventContract = &contract
			}
		}
	} else {
		contract := EventContractReport{Required: len(baselineRequiredRuntimeEvents), Violations: []string{"runtime does not implement the shared provider event contract"}}
		report.EventContract = &contract
	}

	launch, err := runtime.Launch(ctx, identity)
	report.set("no_write_launch_identity", err == nil && launch.NoWrites && launch.IdentityHash == identity.Hash() && launch.SessionID != "", "launch must be no-write and identity-bound", err)
	if err != nil || launch.SessionID == "" {
		report.failRemaining("launch did not establish a session")
		return report
	}

	delivery, err := runtime.Deliver(ctx, launch.SessionID, nonce)
	deliveryPass := err == nil && delivery.Submitted && delivery.AcknowledgedNonce == nonce
	if capabilities.Completion == EvidenceAuthoritative {
		deliveryPass = deliveryPass && delivery.CompletionAuthoritative
	}
	report.set("delivery_nonce_acknowledgement", deliveryPass, "delivery must acknowledge the supplied nonce at the transport's declared grade", err)
	if delivery.CompletionAuthoritative && capabilities.Completion != EvidenceAuthoritative {
		report.Discrepancies = append(report.Discrepancies, "transport reported authoritative completion contrary to capability matrix")
	}

	observations, observationErr := runtime.ProviderErrors(ctx)
	report.set("provider_error_taxonomy", validateErrorObservations(identity.Provider(), observations, observationErr), "provider errors must match exact status/code taxonomy", observationErr)

	cancel, err := runtime.Cancel(ctx, launch.SessionID)
	cancelPass := err == nil && cancel.Attempted
	if capabilities.Cancellation == EvidenceAuthoritative {
		switch capabilities.CancellationAuthorityScope {
		case EvidenceAuthorityScopeAgentACP:
			cancelPass = cancelPass && cancel.AgentACPAcknowledged && !cancel.CloudInferenceStopConfirmed
		case EvidenceAuthorityScopeProvider, EvidenceAuthorityScopeLocalProcessTree:
			cancelPass = cancelPass && cancel.Authoritative
		default:
			cancelPass = false
		}
	} else if cancel.Authoritative {
		cancelPass = false
		report.Discrepancies = append(report.Discrepancies, "cancellation was claimed authoritative although matrix does not establish it")
	}
	report.set("cancellation_semantics", cancelPass, "cancellation evidence must not exceed transport capability", err)

	recovery, err := runtime.Recover(ctx, launch.SessionID)
	report.set("crash_outcome_unknown_recovery", err == nil && recovery.OutcomeUnknown && recovery.AutomaticReplayBlocked, "crash recovery must preserve unknown outcome and block automatic replay", err)
	resume, err := runtime.Resume(ctx, launch.SessionID)
	resumePass := err == nil
	switch capabilities.Resume {
	case EvidenceAuthoritative:
		resumePass = resumePass && resume.Resumed && resume.SameSessionID
	case EvidenceSubmission:
		resumePass = resumePass && resume.Resumed
	case EvidenceUnavailable:
		resumePass = resumePass && !resume.Resumed && !resume.SameSessionID
	default:
		resumePass = false
	}
	report.set("session_resumption", resumePass, "resumption evidence must exactly match the transport capability", err)
	cleanup, err := runtime.Cleanup(ctx, launch.SessionID)
	report.set("zero_residual_cleanup", err == nil && cleanup.ZeroResiduals, "cleanup must report no residual sessions/processes/leases", err)
	return report
}

func validateErrorObservations(providerName string, observations []ErrorObservation, err error) bool {
	if err != nil || len(observations) == 0 {
		return false
	}
	seen := make(map[ErrorClass]bool, len(observations))
	for _, observation := range observations {
		if observation.Expected == "" || ClassifyProviderError(observation.HTTPStatus, observation.Code) != observation.Expected {
			return false
		}
		seen[observation.Expected] = true
	}
	if providerName == "zai" {
		for _, required := range RequiredZAIErrorClasses() {
			if !seen[required] {
				return false
			}
		}
	}
	return true
}

func newChecks() []CheckResult {
	checks := make([]CheckResult, len(conformanceCheckNames))
	for i, name := range conformanceCheckNames {
		checks[i].Name = name
	}
	return checks
}
func coverageFor(checks []CheckResult) CoverageReport {
	coverage := CoverageReport{Required: conformanceRequiredChecks}
	for _, check := range checks {
		if check.Passed {
			coverage.Satisfied++
		}
	}
	return coverage
}
func (r *ConformanceReport) set(name string, passed bool, detail string, err error) {
	for i := range r.Checks {
		if r.Checks[i].Name == name {
			r.Checks[i].Passed, r.Checks[i].Detail = passed, detail
			if err != nil {
				r.Checks[i].ErrorSHA256 = hashSafe(err.Error())
			}
			return
		}
	}
}
func (r *ConformanceReport) failAll(detail string) {
	for i := range r.Checks {
		r.Checks[i].Detail = detail
	}
}
func (r *ConformanceReport) failRemaining(detail string) {
	for i := range r.Checks {
		if !r.Checks[i].Passed && r.Checks[i].Detail == "" {
			r.Checks[i].Detail = detail
		}
	}
}
func hashSafe(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

// Compatibility aliases preserve existing callers while every classification
// now shares the admission taxonomy.
type TransportErrorClass = ErrorClass

const (
	TransportRateLimited      = ErrorRateLimited
	TransportOverloaded       = ErrorOverloaded
	TransportPlanExpired      = ErrorPlanExpired
	TransportUnsupportedModel = ErrorUnsupportedModel
	TransportAuthentication   = ErrorAuthentication
	TransportUnknown          = ErrorUnknown
)

func ClassifyTransportError(status int, code string) TransportErrorClass {
	return ClassifyProviderError(status, code)
}
