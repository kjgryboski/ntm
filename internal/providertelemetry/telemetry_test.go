package providertelemetry

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func testObservation(id string, observedAt time.Time) Observation {
	cost := int64(42)
	remaining := int64(7)
	return Observation{
		SchemaVersion: SchemaVersion, ID: id, ObservedAt: observedAt.UTC(),
		IdentitySHA256: strings.Repeat("a", 64), Model: "grok-4.6", Transport: "acp", Adapter: "native_acp",
		Runtime: "1.0.13", PolicySHA256: strings.Repeat("b", 64), CompatibilityFixtureVersion: "grok-1.0.13-v2",
		LatencyMicros: 1500, InputTokens: 10, OutputTokens: 4, CachedTokens: 3, CostMicros: &cost,
		Quota: QuotaFact{State: "available", Remaining: &remaining}, Circuit: CircuitFact{State: "closed"}, NoFailover: true,
	}
}

func TestRecordIsCreateOnlyAndLoadLatestIsBounded(t *testing.T) {
	store, err := Open(t.TempDir(), Options{MaxObservations: 2})
	if err != nil {
		t.Fatal(err)
	}
	first := testObservation("11111111111111111111111111111111", time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC))
	if _, err := store.Record(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Record(t.Context(), first); !errors.Is(err, ErrRecordCollision) {
		t.Fatalf("second write error = %v, want collision", err)
	}
	second := testObservation("22222222222222222222222222222222", first.ObservedAt.Add(time.Minute))
	if _, err := store.Record(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	latest, err := store.LoadLatest(t.Context(), 1)
	if err != nil || len(latest) != 1 || latest[0].ID != second.ID {
		t.Fatalf("latest = %+v, %v", latest, err)
	}
	third := testObservation("33333333333333333333333333333333", second.ObservedAt.Add(time.Minute))
	if _, err := store.Record(t.Context(), third); !errors.Is(err, ErrStateCapacity) {
		t.Fatalf("capacity error = %v, want capacity", err)
	}
}

func TestValidateFailsClosedOnUnsafeOrInconsistentFields(t *testing.T) {
	valid := testObservation("11111111111111111111111111111111", time.Now().UTC())
	for name, mutate := range map[string]func(*Observation){
		"raw error":            func(observation *Observation) { observation.ProviderErrorClass = "provider error: raw details" },
		"bad identity":         func(observation *Observation) { observation.IdentitySHA256 = "not-a-digest" },
		"cached exceeds input": func(observation *Observation) { observation.CachedTokens = observation.InputTokens + 1 },
		"non-UTC time": func(observation *Observation) {
			observation.ObservedAt = observation.ObservedAt.In(time.FixedZone("local", 1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			observation := valid
			mutate(&observation)
			if !errors.Is(Validate(observation), ErrInvalidObservation) {
				t.Fatalf("unsafe observation accepted: %+v", observation)
			}
		})
	}
}

func TestSummaryReportsCompatibilityAgeDriftAndStaleness(t *testing.T) {
	store, err := Open(t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	observedAt := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	if _, err := store.Record(context.Background(), testObservation("11111111111111111111111111111111", observedAt)); err != nil {
		t.Fatal(err)
	}
	summary, err := store.Summarize(t.Context(), SummaryOptions{
		Now: observedAt.Add(2 * time.Hour), ExpectedFixtureVersion: "grok-1.0.13-v3", CompatibilityMaxAge: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.ObservationCount != 1 || summary.Latest == nil || !summary.Compatibility.Drifted || !summary.Compatibility.Stale || summary.Compatibility.Age != 2*time.Hour {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}

func TestOpenReadOnlyDoesNotCreateMissingStateDirectory(t *testing.T) {
	missing := t.TempDir() + "/does-not-exist"
	if _, err := OpenReadOnly(missing, Options{}); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("OpenReadOnly missing dir error = %v, want unavailable", err)
	}
}
