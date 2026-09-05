package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/Dicklesworthstone/ntm/internal/grok"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/state"
	"github.com/Dicklesworthstone/ntm/internal/zai"
	"github.com/spf13/cobra"
)

var providerCampaignID string

type unaccountedQualificationRunner struct{}

func (unaccountedQualificationRunner) Run(context.Context, providerqualification.Invocation) (providerqualification.Outcome, error) {
	return providerqualification.Outcome{ExitCode: -1}, errors.New("opaque Z.ai Claude qualification cannot account for individual requests; structured admission is required before live dispatch")
}

func runAccountedLegacyQualification(ctx context.Context, options providerqualification.Options) providerqualification.Receipt {
	// Preserve diagnostic receipt production, but the legacy opaque transport
	// cannot be used to evade the Coding Plan admission/usage boundary.
	options.Runner = unaccountedQualificationRunner{}
	return providerqualification.Run(ctx, options)
}

func validateProviderCampaignRoute(cmd *cobra.Command) error {
	if providerCampaignID == "" {
		return nil
	}
	for parent := cmd; parent != nil; parent = parent.Parent() {
		if parent.Name() == "provider" {
			return nil
		}
	}
	if cmd.Parent() == nil && robotGrokACPRun {
		return nil
	}
	if cmd.Name() == "assign" || cmd.Name() == "send" || cmd.Name() == "spawn" || cmd.Name() == "respawn" || cmd.Name() == "interrupt" || cmd.Name() == "status" {
		if flag := cmd.Flags().Lookup("provider-profile"); flag != nil && flag.Value.String() != "" {
			return nil
		}
	}
	return errors.New("--campaign-id requires a managed provider route; raw pane commands cannot provide campaign or qualification enforcement")
}

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
		return encodeIndentedJSON(cmd.OutOrStdout(), providerCampaignObservation(out))
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

// Native tool rounds each send a generation request. Counting only the outer
// tool loop would allow its round limit to multiply the campaign allowance.
type providerBudgetedNativeClient struct {
	client                        zai.NativeHTTPClient
	requestID, identity, evidence string
	round                         atomic.Uint64
}

func (c *providerBudgetedNativeClient) Do(request *http.Request) (*http.Response, error) {
	attempt := "native-" + sha256StringCLI(fmt.Sprintf("%s:%d", c.requestID, c.round.Add(1)))
	if err := reserveProviderExperiment(attempt, c.identity, c.evidence); err != nil {
		return nil, err
	}
	return c.client.Do(request)
}

func budgetedNativeClient(client zai.NativeHTTPClient, request zai.NativeRequest) zai.NativeHTTPClient {
	return &providerBudgetedNativeClient{client: client, requestID: request.ExpectedRequestID,
		identity: sha256StringCLI(request.Endpoint + "\x00" + request.Model + "\x00" + request.ExpectedRequestID),
		evidence: sha256StringCLI(request.Prompt)}
}

func runBudgetedNative(ctx context.Context, client zai.NativeHTTPClient, request zai.NativeRequest) (zai.NativeReceipt, error) {
	return zai.RunNative(ctx, budgetedNativeClient(client, request), request)
}

func runBudgetedNativeTools(ctx context.Context, client zai.NativeHTTPClient, request zai.NativeToolRequest) (zai.NativeToolReceipt, error) {
	return zai.RunNativeTools(ctx, budgetedNativeClient(client, request.NativeRequest), request)
}
