package cli

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providertelemetry"
)

const (
	providerTelemetryStateRecorded = "recorded"
	providerTelemetryStateFailed   = "failed"
)

var providerTelemetrySafePart = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)

type providerTelemetryEvidence struct {
	State             string `json:"state"`
	ObservationID     string `json:"observation_id,omitempty"`
	ObservationSHA256 string `json:"observation_sha256,omitempty"`
	ErrorSHA256       string `json:"error_sha256,omitempty"`
}

type providerTelemetryObservationInput struct {
	Identity         provider.Identity
	Model            string
	Transport        string
	Adapter          string
	Runtime          string
	PolicySHA256     string
	FixtureVersion   string
	StartedAt        time.Time
	CompletedAt      time.Time
	InputTokens      int64
	OutputTokens     int64
	CachedTokens     int64
	ProviderError    provider.ErrorClass
	QuotaState       string
	CircuitState     string
	CircuitFailures  uint32
	CircuitOpenUntil *time.Time
	NoFailover       bool
}

func recordProviderTelemetryDefault(ctx context.Context, observation providertelemetry.Observation) (providertelemetry.Observation, error) {
	store, err := providertelemetry.Open(providertelemetry.DefaultStoreDir(), providertelemetry.Options{})
	if err != nil {
		return providertelemetry.Observation{}, err
	}
	return store.Record(ctx, observation)
}

func providerTelemetryObservation(input providerTelemetryObservationInput) providertelemetry.Observation {
	completed := input.CompletedAt.UTC()
	if completed.IsZero() {
		completed = time.Now().UTC()
	}
	started := input.StartedAt.UTC()
	if started.IsZero() || started.After(completed) {
		started = completed
	}
	quota := strings.TrimSpace(input.QuotaState)
	if quota == "" {
		quota = "unknown"
	}
	circuit := strings.TrimSpace(input.CircuitState)
	if circuit == "" {
		circuit = "unknown"
	}
	return providertelemetry.Observation{
		IdentitySHA256:              input.Identity.Hash(),
		ObservedAt:                  completed,
		Model:                       providerTelemetryIdentifier(input.Model, "model"),
		Transport:                   providerTelemetryIdentifier(input.Transport, "transport"),
		Adapter:                     providerTelemetryIdentifier(input.Adapter, "adapter"),
		Runtime:                     providerTelemetryIdentifier(input.Runtime, "runtime"),
		PolicySHA256:                input.PolicySHA256,
		CompatibilityFixtureVersion: providerTelemetryIdentifier(input.FixtureVersion, "fixture"),
		LatencyMicros:               completed.Sub(started).Microseconds(),
		InputTokens:                 max(input.InputTokens, 0),
		OutputTokens:                max(input.OutputTokens, 0),
		CachedTokens:                max(min(input.CachedTokens, input.InputTokens), 0),
		ProviderErrorClass:          providerTelemetryErrorClass(input.ProviderError),
		Quota:                       providertelemetry.QuotaFact{State: providerTelemetryIdentifier(quota, "quota")},
		Circuit: providertelemetry.CircuitFact{
			State: providerTelemetryIdentifier(circuit, "circuit"), FailureCount: input.CircuitFailures, OpenUntil: utcTimePointer(input.CircuitOpenUntil),
		},
		NoFailover: input.NoFailover,
	}
}

func recordProviderTelemetryEvidence(ctx context.Context, recorder func(context.Context, providertelemetry.Observation) (providertelemetry.Observation, error), observation providertelemetry.Observation) providerTelemetryEvidence {
	if recorder == nil {
		return providerTelemetryEvidence{State: providerTelemetryStateFailed, ErrorSHA256: sha256StringCLI("telemetry_recorder_unavailable")}
	}
	recorded, err := recorder(ctx, observation)
	if err != nil {
		return providerTelemetryEvidence{State: providerTelemetryStateFailed, ErrorSHA256: safeErrorDigest(err)}
	}
	return providerTelemetryEvidence{State: providerTelemetryStateRecorded, ObservationID: recorded.ID, ObservationSHA256: digestSafeJSON(recorded)}
}

func validProviderTelemetryEvidence(evidence providerTelemetryEvidence) bool {
	switch evidence.State {
	case providerTelemetryStateRecorded:
		return evidence.ObservationID != "" && evidence.ObservationSHA256 != "" && evidence.ErrorSHA256 == ""
	case providerTelemetryStateFailed:
		return evidence.ObservationID == "" && evidence.ObservationSHA256 == "" && evidence.ErrorSHA256 != ""
	default:
		return false
	}
}

func providerTelemetryIdentifier(value, prefix string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if providerTelemetrySafePart.MatchString(normalized) {
		return normalized
	}
	return prefix + "-" + sha256StringCLI(value)[:16]
}

func providerTelemetryErrorClass(class provider.ErrorClass) string {
	if class == "" {
		return "none"
	}
	return providerTelemetryIdentifier(string(class), "error")
}

func utcTimePointer(value *time.Time) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	copy := value.UTC()
	return &copy
}

func providerTelemetryQuotaState(class provider.ErrorClass) string {
	switch class {
	case provider.ErrorLongPeriodQuota:
		return "exhausted"
	case provider.ErrorPlanExpired, provider.ErrorInsufficientBalance:
		return "commercial_block"
	case provider.ErrorUsageRestricted:
		return "policy_block"
	case provider.ErrorAuthentication:
		return "auth_block"
	default:
		return "unknown"
	}
}
