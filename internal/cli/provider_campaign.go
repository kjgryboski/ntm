package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/Dicklesworthstone/ntm/internal/grok"
	"github.com/Dicklesworthstone/ntm/internal/state"
	"github.com/Dicklesworthstone/ntm/internal/zai"
	"github.com/spf13/cobra"
)

var providerCampaignID string

func openProviderCampaignStore() (*state.Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	// Deliberately independent of --config and its operation ledger.
	return state.Open(filepath.Join(home, ".local", "state", "ntm", "provider-campaigns.db"))
}

func runBudgetedGrok(ctx context.Context, runner grok.Runner, request grok.Request) (grok.Result, error) {
	target := sha256StringCLI(request.RuntimeHome + "\x00" + request.Model + "\x00" + request.Binary)
	if err := reserveProviderExperiment("grok-"+sha256StringCLI(request.ExpectedNonce), target, sha256StringCLI(request.Prompt)); err != nil {
		return grok.Result{}, err
	}
	return grok.Run(ctx, runner, request)
}

func runBudgetedGrokSession(ctx context.Context, runner grok.LifecycleRunner, request grok.SessionRequest) (grok.SessionReceipt, error) {
	if err := reserveProviderExperiment("grok-session-"+sha256StringCLI(request.ExpectedNonce), request.ConfigSHA256, sha256StringCLI(request.Prompt)); err != nil {
		return grok.SessionReceipt{}, err
	}
	return grok.ExecuteSession(ctx, runner, request)
}

func newProviderCampaignCmd() *cobra.Command {
	var id, evidence string
	var limit, previous int
	cmd := &cobra.Command{Use: "campaign", Short: "Inspect or explicitly authorize a total provider experiment budget", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&id, "id", "", "Campaign identifier")
	cmd.Flags().IntVar(&limit, "limit", 0, "Authorize this total attempt ceiling (1-100); omitted reads status")
	cmd.Flags().IntVar(&previous, "previous-limit", 0, "Required current ceiling when explicitly authorizing an increase")
	cmd.Flags().StringVar(&evidence, "authorization-sha256", "", "Digest of the authorization for creating or increasing this campaign")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if !validProviderNativeOperationID(id) {
			return errors.New("valid campaign ID required")
		}
		store, err := openProviderCampaignStore()
		if err != nil {
			return err
		}
		defer store.Close()
		if limit != 0 {
			if !validProviderNativeDigest(evidence) {
				return errors.New("campaign authorization digest required")
			}
			if err = store.ConfigureProviderCampaign(id, limit, previous, evidence); err != nil {
				return err
			}
		}
		out, err := store.ProviderCampaign(id)
		if err != nil {
			return err
		}
		return encodeIndentedJSON(cmd.OutOrStdout(), out)
	}
	return cmd
}

func reserveProviderExperiment(attempt, identity, evidence string) error {
	if !validProviderNativeOperationID(providerCampaignID) || !validProviderNativeOperationID(attempt) || !validProviderNativeDigest(identity) || !validProviderNativeDigest(evidence) {
		return errors.New("managed provider dispatch requires --campaign-id and a bound attempt")
	}
	store, err := openProviderCampaignStore()
	if err != nil {
		return err
	}
	defer store.Close()
	return store.ReserveProviderCampaignAttempt(providerCampaignID, attempt, identity, evidence)
}

func runBudgetedCodexStructured(ctx context.Context, spec zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
	// The canonical manifest binds the exact account/provider/runtime/model.
	// Every qualification turn has a fresh nonce, so multi-turn suites consume
	// one campaign slot per actual dispatch, not one per enclosing command.
	if err := reserveProviderExperiment("codex-"+sha256StringCLI(spec.ExpectedNonce), spec.ConfigSHA256, sha256StringCLI(spec.Prompt)); err != nil {
		return zai.CodexRunReceipt{}, err
	}
	return zai.RunCodexStructured(ctx, spec)
}
