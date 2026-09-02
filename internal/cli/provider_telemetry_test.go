package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/providertelemetry"
)

func TestProviderTelemetryReplaysRedactedGrokAndZAIFixtures(t *testing.T) {
	store := t.TempDir()
	fixtureDir := filepath.Join("testdata", "provider_telemetry")
	for _, name := range []string{
		"obs-11111111111111111111111111111111.json",
		"obs-22222222222222222222222222222222.json",
	} {
		contents, err := os.ReadFile(filepath.Join(fixtureDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(store, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := &cobra.Command{}
	var output bytes.Buffer
	cmd.SetOut(&output)
	if err := runProviderTelemetry(cmd, providerTelemetryOptions{
		store: store, limit: 2, fixtureVersion: "zai-native-v4-v2", fixtureMaxAge: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{"Provider telemetry: 2 observations", "zai-native-v4-v1", "drifted=true", "grok-4.6", "glm-5.3"} {
		if !strings.Contains(text, want) {
			t.Fatalf("telemetry replay omitted %q: %s", want, text)
		}
	}
	for _, forbidden := range []string{"prompt", "credential", "secret", "/"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Fatalf("telemetry replay exposed forbidden material %q: %s", forbidden, text)
		}
	}
}

func TestProviderTelemetryRequiresExistingReadOnlyStore(t *testing.T) {
	cmd := &cobra.Command{}
	if err := runProviderTelemetry(cmd, providerTelemetryOptions{store: filepath.Join(t.TempDir(), "missing"), limit: 1}); err == nil {
		t.Fatal("missing telemetry state directory was accepted")
	}
}

func TestProviderTelemetryObservationHashesUnsafeIdentifiersAndBoundsCounters(t *testing.T) {
	identity, err := providerNativeProfile().Identity()
	if err != nil {
		t.Fatal(err)
	}
	observation := providerTelemetryObservation(providerTelemetryObservationInput{
		Identity: identity, Model: "unsafe model/with path", Transport: "zai_native_api", Adapter: "native", Runtime: "api",
		PolicySHA256: providerTestHash("policy"), FixtureVersion: "fixture-v1",
		StartedAt: time.Unix(2, 0).UTC(), CompletedAt: time.Unix(1, 0).UTC(), InputTokens: -1, OutputTokens: -2, CachedTokens: 99,
		QuotaState: "unknown", CircuitState: "closed", NoFailover: true,
	})
	observation.SchemaVersion = providertelemetry.SchemaVersion
	observation.ID = "33333333333333333333333333333333"
	if err := providertelemetry.Validate(observation); err != nil {
		t.Fatalf("sanitized telemetry invalid: %v (%+v)", err, observation)
	}
	if strings.Contains(observation.Model, "path") || observation.InputTokens != 0 || observation.OutputTokens != 0 || observation.CachedTokens != 0 || observation.LatencyMicros != 0 {
		t.Fatalf("unsafe telemetry was not normalized: %+v", observation)
	}
}
