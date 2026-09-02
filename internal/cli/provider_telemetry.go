package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/providertelemetry"
)

const providerTelemetryReportSchema = "ntm.provider-telemetry-report.v1"

type providerTelemetryOptions struct {
	store           string
	limit           int
	fixtureVersion  string
	fixtureMaxAge   time.Duration
	maxObservations int
}

type providerTelemetryReport struct {
	SchemaVersion string                          `json:"schema_version"`
	Summary       providertelemetry.Summary       `json:"summary"`
	Observations  []providertelemetry.Observation `json:"observations"`
}

func newProviderTelemetryCmd() *cobra.Command {
	opts := providerTelemetryOptions{store: providertelemetry.DefaultStoreDir(), limit: 20, fixtureMaxAge: 30 * 24 * time.Hour}
	cmd := &cobra.Command{
		Use:   "telemetry",
		Short: "Read redacted provider drift and economics telemetry",
		Long:  "Read a create-only provider telemetry store. This command never creates, edits, or removes observations and never reads provider credentials or raw provider traffic.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProviderTelemetry(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.store, "store", opts.store, "Existing telemetry state directory (read-only)")
	cmd.Flags().IntVar(&opts.limit, "limit", opts.limit, "Number of newest observations to return (1-256)")
	cmd.Flags().StringVar(&opts.fixtureVersion, "fixture-version", "", "Expected compatibility fixture version for drift detection")
	cmd.Flags().DurationVar(&opts.fixtureMaxAge, "fixture-max-age", opts.fixtureMaxAge, "Maximum fixture age before stale status")
	cmd.Flags().IntVar(&opts.maxObservations, "max-observations", 0, "Expected store capacity (0 uses default)")
	return cmd
}

func runProviderTelemetry(cmd *cobra.Command, opts providerTelemetryOptions) error {
	if strings.TrimSpace(opts.store) == "" {
		return errors.New("provider telemetry requires an exact --store directory")
	}
	if opts.limit < 1 || opts.limit > 256 || opts.fixtureMaxAge < 0 {
		return errors.New("provider telemetry limit or fixture age is invalid")
	}
	store, err := providertelemetry.OpenReadOnly(opts.store, providertelemetry.Options{MaxObservations: opts.maxObservations})
	if err != nil {
		return errors.New("provider telemetry store is unavailable or invalid")
	}
	ctx := providerCommandContext(cmd)
	summary, err := store.Summarize(ctx, providertelemetry.SummaryOptions{
		ExpectedFixtureVersion: opts.fixtureVersion, CompatibilityMaxAge: opts.fixtureMaxAge,
	})
	if err != nil {
		return errors.New("provider telemetry summary could not be validated")
	}
	observations, err := store.LoadLatest(ctx, opts.limit)
	if err != nil {
		return errors.New("provider telemetry observations could not be validated")
	}
	report := providerTelemetryReport{SchemaVersion: providerTelemetryReportSchema, Summary: summary, Observations: observations}
	if IsJSONOutput() {
		return encodeIndentedJSON(cmd.OutOrStdout(), report)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Provider telemetry: %d observations\n", summary.ObservationCount)
	if summary.Latest == nil {
		fmt.Fprintln(cmd.OutOrStdout(), "Compatibility: no observations")
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Compatibility: fixture=%s age=%s drifted=%t stale=%t\n", summary.Compatibility.FixtureVersion, summary.Compatibility.Age.Round(time.Second), summary.Compatibility.Drifted, summary.Compatibility.Stale)
	fmt.Fprintln(cmd.OutOrStdout(), "OBSERVED_AT\tIDENTITY\tMODEL\tTRANSPORT\tLATENCY_MS\tTOKENS\tCACHED\tERROR\tCIRCUIT\tNO_FAILOVER")
	for _, observation := range observations {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\t%.3f\t%d\t%d\t%s\t%s\t%t\n",
			observation.ObservedAt.Format(time.RFC3339), observation.IdentitySHA256, observation.Model, observation.Transport,
			float64(observation.LatencyMicros)/1000, observation.InputTokens+observation.OutputTokens, observation.CachedTokens,
			observation.ProviderErrorClass, observation.Circuit.State, observation.NoFailover)
	}
	return nil
}
