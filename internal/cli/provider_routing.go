package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/agent"
	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

const providerRoutingSchema = "ntm.provider-routing.v1"

const (
	providerRouteOutcomeAdmitted            = "admitted"
	providerRouteOutcomeAuthentication      = "authentication_required"
	providerRouteOutcomeOverloaded          = "provider_overloaded"
	providerRouteOutcomeRateLimited         = "rate_limited"
	providerRouteOutcomeFiveHourExhausted   = "five_hour_exhausted"
	providerRouteOutcomeWeeklyExhausted     = "weekly_exhausted"
	providerRouteOutcomeEntitlementDenied   = "entitlement_denied"
	providerRouteOutcomeUnsupportedModel    = "unsupported_model"
	providerRouteOutcomeUsageRestricted     = "usage_policy_restricted"
	providerRouteOutcomeInsufficientBalance = "insufficient_balance"
	providerRouteOutcomeUnknown             = "unknown_provider_outcome"

	providerWorkflowZAIImplementStage = "zai_implements"
	providerWorkflowGrokReviewStage   = "grok_independent_review"
	providerWorkflowReconcileStage    = "ntm_reconcile_signed_receipts"
)

type providerRoutePlan struct {
	SchemaVersion  string `json:"schema_version"`
	Profile        string `json:"profile"`
	Workload       string `json:"workload"`
	Transport      string `json:"transport"`
	IdentitySHA256 string `json:"identity_sha256"`
	RequestedModel string `json:"requested_model"`
	Outcome        string `json:"outcome"`
	Action         string `json:"action"`
	NoFailover     bool   `json:"no_failover"`
	Fallback       string `json:"fallback"`
}

type providerWorkflowStage struct {
	Name               string `json:"name"`
	ProviderProfile    string `json:"provider_profile"`
	IdentitySHA256     string `json:"identity_sha256"`
	PolicySHA256       string `json:"policy_sha256"`
	Transport          string `json:"transport"`
	AgentType          string `json:"agent_type"`
	RequiredOperation  string `json:"required_operation"`
	ExpectedModel      string `json:"expected_model,omitempty"`
	Dispatch           string `json:"dispatch"`
	ReceiptRequirement string `json:"receipt_requirement"`
}

type providerWorkflowPlan struct {
	SchemaVersion        string                  `json:"schema_version"`
	Workflow             string                  `json:"workflow"`
	WorkflowSHA256       string                  `json:"workflow_sha256"`
	DisposableWorktree   bool                    `json:"disposable_worktree"`
	WorktreeSHA256       string                  `json:"worktree_sha256"`
	ZAIOperationIDSHA256 string                  `json:"zai_operation_id_sha256"`
	GrokParentSHA256     string                  `json:"grok_parent_session_sha256"`
	NoAutomaticFailover  bool                    `json:"no_automatic_failover"`
	ReconciliationPolicy string                  `json:"reconciliation_policy"`
	Stages               []providerWorkflowStage `json:"stages"`
}

type providerWorkflowReconciliation struct {
	SchemaVersion     string `json:"schema_version"`
	Workflow          string `json:"workflow"`
	ZAIReceiptSHA256  string `json:"zai_receipt_sha256"`
	GrokReceiptSHA256 string `json:"grok_receipt_sha256"`
	WorkflowSHA256    string `json:"workflow_sha256"`
	BothReceiptsValid bool   `json:"both_receipts_valid"`
	Decision          string `json:"decision"`
	AutomaticDispatch bool   `json:"automatic_dispatch"`
	AutomaticFailover bool   `json:"automatic_failover"`
}

type providerRouteDependencies struct {
	loadConfig func() *config.Config
	now        func() time.Time
	admission  interface {
		Snapshot(provider.Identity) ratelimit.SubscriptionCapacitySnapshot
	}
	isLinkedWorktree     func(context.Context, string) (bool, error)
	readFile             func(string) ([]byte, error)
	trustedSigner        func(context.Context) (providerattestation.KeyMetadata, error)
	profileTrustedSigner func(context.Context, config.ProviderProfileConfig) (providerattestation.KeyMetadata, error)
}

var providerRouteDeps = providerRouteDependencies{
	loadConfig:           loadSelectedConfigOrDefault,
	now:                  func() time.Time { return time.Now().UTC() },
	admission:            defaultProviderCodexSubscriptionAdmission(),
	isLinkedWorktree:     providerIsLinkedGitWorktree,
	readFile:             os.ReadFile,
	trustedSigner:        providerRouteTrustedSigner,
	profileTrustedSigner: providerRouteProfileTrustedSigner,
}

func providerRouteTrustedSigner(ctx context.Context) (providerattestation.KeyMetadata, error) {
	preflight, err := preflightProviderReceiptSignerMetadata(ctx, signProviderReceiptPayload)
	if err != nil {
		return providerattestation.KeyMetadata{}, err
	}
	return preflight.KeyMetadata, nil
}

func providerRouteProfileTrustedSigner(ctx context.Context, profile config.ProviderProfileConfig) (providerattestation.KeyMetadata, error) {
	sign, err := providerProfilePinnedSigner(profile)
	if err != nil {
		return providerattestation.KeyMetadata{}, err
	}
	preflight, err := preflightProviderReceiptSignerMetadata(ctx, sign)
	if err != nil {
		return providerattestation.KeyMetadata{}, err
	}
	return preflight.KeyMetadata, nil
}

// newProviderRoutingCmd is registered by newProviderCmd. It is deliberately a
// plan/verification surface: it never launches a provider process, creates a
// worktree, changes a provider profile, or chooses another provider.
func newProviderRoutingCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "route", Short: "Plan exact-provider subscription work and review workflows"}
	cmd.AddCommand(newProviderRoutePlanCmd(), newProviderRouteClassifyCmd(), newProviderRouteWorkflowCmd())
	return cmd
}

func newProviderRoutePlanCmd() *cobra.Command {
	var profile, workload string
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Plan one exact Z.ai Coding Plan workload without dispatching it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			plan, err := planZAISubscriptionRoute(profile, workload, providerRouteDeps)
			if err != nil {
				return err
			}
			return printProviderRouteJSON(cmd, plan)
		},
	}
	cmd.Flags().StringVar(&profile, "profile", "", "Exact configured Z.ai codex_responses profile (required)")
	cmd.Flags().StringVar(&workload, "workload", providerCodexWorkloadImplementation, "Workload: implementation, review, bulk, bulk-triage, or bulk-review")
	return cmd
}

func newProviderRouteClassifyCmd() *cobra.Command {
	var providerCode string
	var httpStatus int
	cmd := &cobra.Command{
		Use:   "classify",
		Short: "Classify a Z.ai response without retrying or failing over",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			plan := classifyZAIRouteOutcome(httpStatus, providerCode)
			return printProviderRouteJSON(cmd, plan)
		},
	}
	cmd.Flags().IntVar(&httpStatus, "http-status", 0, "HTTP status observed from the exact provider")
	cmd.Flags().StringVar(&providerCode, "provider-code", "", "Normalized Z.ai provider error code")
	return cmd
}

func newProviderRouteWorkflowCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "workflow", Short: "Plan or reconcile the explicit Z.ai implementation and Grok review workflow"}
	cmd.AddCommand(newProviderRouteWorkflowPlanCmd(), newProviderRouteWorkflowReconcileCmd())
	return cmd
}

func newProviderRouteWorkflowPlanCmd() *cobra.Command {
	var zaiProfile, grokProfile, worktree, zaiOperationID, grokParentSession string
	var disposable bool
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Plan Z.ai implementation followed by independent Grok review",
		Long: `Plan the built-in, deliberately non-autonomous provider workflow.

Z.ai may edit only the declared disposable linked worktree. Grok receives an
independent review stage; it is never a fallback for a Z.ai failure. NTM then
requires a separate signed-receipt reconciliation command before a human makes
any merge or follow-up decision. This command does not dispatch either model.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			plan, err := planZAIGrokWorkflow(cmd.Context(), zaiProfile, grokProfile, worktree, zaiOperationID, grokParentSession, disposable, providerRouteDeps)
			if err != nil {
				return err
			}
			return printProviderRouteJSON(cmd, plan)
		},
	}
	cmd.Flags().StringVar(&zaiProfile, "zai-profile", "", "Exact configured Z.ai Coding Plan Codex profile (required)")
	cmd.Flags().StringVar(&grokProfile, "grok-profile", "", "Exact configured Grok ACP profile (required)")
	cmd.Flags().StringVar(&worktree, "worktree", "", "Existing disposable linked Git worktree (required)")
	cmd.Flags().StringVar(&zaiOperationID, "zai-operation-id", "", "Exact Z.ai durable operation ID to bind (required; only its hash is emitted)")
	cmd.Flags().StringVar(&grokParentSession, "grok-parent-session", "", "Exact Grok parent session ID to bind (required; only its hash is emitted)")
	cmd.Flags().BoolVar(&disposable, "disposable-worktree", false, "Confirm the declared worktree is disposable")
	return cmd
}

func newProviderRouteWorkflowReconcileCmd() *cobra.Command {
	var planPath, zaiReceipt, grokReceipt string
	cmd := &cobra.Command{
		Use:   "reconcile",
		Short: "Verify both signed workflow receipts and record a manual decision gate",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, err := reconcileZAIGrokWorkflow(cmd.Context(), planPath, zaiReceipt, grokReceipt, providerRouteDeps)
			if err != nil {
				return err
			}
			return printProviderRouteJSON(cmd, result)
		},
	}
	cmd.Flags().StringVar(&planPath, "plan", "", "Exact workflow plan JSON file (required)")
	cmd.Flags().StringVar(&zaiReceipt, "zai-receipt", "", "Signed Z.ai Codex JSON receipt file (required)")
	cmd.Flags().StringVar(&grokReceipt, "grok-receipt", "", "Signed Grok session JSON receipt file (required)")
	return cmd
}

func planZAISubscriptionRoute(profileName, workload string, deps providerRouteDependencies) (providerRoutePlan, error) {
	if deps.loadConfig == nil || deps.now == nil || deps.admission == nil {
		return providerRoutePlan{}, errors.New("provider route dependencies are incomplete")
	}
	_, identity, err := exactZAICodexRouteProfile(profileName, deps.loadConfig())
	if err != nil {
		return providerRoutePlan{}, err
	}
	requestedWorkload := strings.ToLower(strings.TrimSpace(workload))
	workload, err = validateProviderCodexWorkload(identity.Model(), routeWorkloadClass(requestedWorkload), deps.now())
	if err != nil {
		return providerRoutePlan{}, err
	}
	if requestedWorkload == "bulk-triage" || requestedWorkload == "bulk-review" {
		workload = requestedWorkload
	}
	plan := providerRoutePlan{SchemaVersion: providerRoutingSchema, Profile: strings.TrimSpace(profileName), Workload: workload, Transport: "zai_codex_runtime", IdentitySHA256: identity.Hash(), RequestedModel: identity.Model(), NoFailover: true, Fallback: "none: exact provider, account, entitlement, and billing class are mandatory"}
	snapshot := deps.admission.Snapshot(identity)
	plan.Outcome, plan.Action = subscriptionRouteCapacityOutcome(snapshot)
	return plan, nil
}

// routeWorkloadClass keeps the execution adapter's deliberately small
// workload vocabulary while giving the planner precise names for the two
// Flash-appropriate jobs. Both aliases still require an explicit
// glm-5.3-flash profile and map to the adapter's existing bulk class.
func routeWorkloadClass(workload string) string {
	switch workload {
	case "bulk-triage", "bulk-review":
		return providerCodexWorkloadBulk
	default:
		return workload
	}
}

func exactZAICodexRouteProfile(profileName string, cfg *config.Config) (config.ProviderProfileConfig, provider.Identity, error) {
	if strings.TrimSpace(profileName) == "" || cfg == nil {
		return config.ProviderProfileConfig{}, provider.Identity{}, errors.New("provider route requires an exact configured --profile")
	}
	profile, err := cfg.ProviderProfile(profileName)
	if err != nil {
		return config.ProviderProfileConfig{}, provider.Identity{}, err
	}
	identity, err := profile.Identity()
	if err != nil {
		return config.ProviderProfileConfig{}, provider.Identity{}, err
	}
	if identity.Provider() != "zai" || identity.Runtime() != "codex" || identity.Endpoint() != zai.OfficialCodexEndpoint || identity.CredentialClass() != provider.CredentialClassCodingPlan || identity.BillingClass() != provider.BillingClassCodingPlan || identity.Entitlement() != provider.EntitlementCodexResponses || !profile.ExactTargetOnly || !profile.ProbeRequired {
		return config.ProviderProfileConfig{}, provider.Identity{}, errors.New("provider route requires an exact Z.ai Coding Plan Codex profile; native API, Claude-compatible, OpenAI, and cross-provider fallbacks are prohibited")
	}
	return profile, identity, nil
}

func subscriptionRouteCapacityOutcome(snapshot ratelimit.SubscriptionCapacitySnapshot) (string, string) {
	if snapshot.UnknownUsageReserved {
		return providerRouteOutcomeWeeklyExhausted, "hold the exact Coding Plan lane until its unknown dispatched usage is reconciled; do not fail over"
	}
	if snapshot.FiveHourCreditsLimit > 0 && snapshot.FiveHourCreditsUsed+snapshot.AdmissionReservation > snapshot.FiveHourCreditsLimit {
		return providerRouteOutcomeFiveHourExhausted, "hold until the recorded five-hour window resets; do not retry on another model or provider"
	}
	if snapshot.WeeklyCreditsLimit > 0 && snapshot.WeeklyCreditsUsed+snapshot.AdmissionReservation > snapshot.WeeklyCreditsLimit {
		return providerRouteOutcomeWeeklyExhausted, "hold until the recorded weekly window resets; do not retry on another model or provider"
	}
	if snapshot.Scope != provider.CapacityControlScopeLocalShared {
		return providerRouteOutcomeUnknown, "hold: shared local subscription capacity evidence is unavailable; do not dispatch or fail over"
	}
	return providerRouteOutcomeAdmitted, "dispatch only this exact profile after its operation-scoped doctor gate admits the requested operation"
}

func classifyZAIRouteOutcome(httpStatus int, code string) providerRoutePlan {
	class := provider.ClassifyProviderError(httpStatus, strings.TrimSpace(code))
	plan := providerRoutePlan{SchemaVersion: providerRoutingSchema, Outcome: providerRouteOutcomeUnknown, NoFailover: true, Fallback: "none: classification never changes provider, account, entitlement, billing class, or model"}
	switch class {
	case provider.ErrorAuthentication:
		plan.Outcome, plan.Action = providerRouteOutcomeAuthentication, "hold and re-authorize the exact credential class; do not substitute a native API key"
	case provider.ErrorOverloaded:
		plan.Outcome, plan.Action = providerRouteOutcomeOverloaded, "retry the exact lane with bounded backoff only; do not fail over"
	case provider.ErrorRateLimited:
		plan.Outcome, plan.Action = providerRouteOutcomeRateLimited, "wait for the exact provider throttle window; do not change provider or model"
	case provider.ErrorLongPeriodQuota, provider.ErrorPlanExpired:
		plan.Outcome, plan.Action = providerRouteOutcomeWeeklyExhausted, "hold until entitlement/quota evidence is refreshed; determine five-hour versus weekly from the signed local subscription ledger, not response prose"
	case provider.ErrorUnsupportedModel:
		plan.Outcome, plan.Action = providerRouteOutcomeUnsupportedModel, "hold and correct the exact profile; model remapping is not accepted as identity evidence"
	case provider.ErrorUsageRestricted:
		plan.Outcome, plan.Action = providerRouteOutcomeUsageRestricted, "hold: the requested operation is not authorized for this entitlement"
	case provider.ErrorInsufficientBalance:
		plan.Outcome, plan.Action = providerRouteOutcomeInsufficientBalance, "hold this pay-as-you-go lane; never reinterpret it as a Coding Plan entitlement"
	case provider.ErrorIdentityMismatch:
		plan.Outcome, plan.Action = providerRouteOutcomeEntitlementDenied, "hold: immutable provider identity or entitlement does not match the requested lane"
	default:
		plan.Action = "hold and preserve the exact provider lane pending a classified receipt; do not retry through another provider"
	}
	return plan
}

func planZAIGrokWorkflow(ctx context.Context, zaiProfileName, grokProfileName, worktree, zaiOperationID, grokParentSession string, disposable bool, deps providerRouteDependencies) (providerWorkflowPlan, error) {
	if deps.loadConfig == nil || deps.isLinkedWorktree == nil {
		return providerWorkflowPlan{}, errors.New("provider workflow dependencies are incomplete")
	}
	cfg := deps.loadConfig()
	_, zaiIdentity, err := exactZAICodexRouteProfile(zaiProfileName, cfg)
	if err != nil {
		return providerWorkflowPlan{}, err
	}
	if strings.TrimSpace(grokProfileName) == "" || cfg == nil {
		return providerWorkflowPlan{}, errors.New("provider workflow requires an exact configured --grok-profile")
	}
	grokProfile, err := cfg.ProviderProfile(grokProfileName)
	if err != nil {
		return providerWorkflowPlan{}, err
	}
	grokIdentity, err := grokProfile.Identity()
	if err != nil {
		return providerWorkflowPlan{}, err
	}
	if grokIdentity.Provider() != "xai" || grokIdentity.Runtime() != "grok" || !grokProfile.ExactTargetOnly {
		return providerWorkflowPlan{}, errors.New("provider workflow requires an exact native Grok profile; generic Claude or another provider is not a review fallback")
	}
	if _, ok := agent.GrokAutomationPolicy(grokProfile.AutomationPolicy); !ok {
		return providerWorkflowPlan{}, errors.New("provider workflow Grok profile lacks a recognized automation policy")
	}
	if !disposable || strings.TrimSpace(worktree) == "" {
		return providerWorkflowPlan{}, errors.New("provider workflow requires --disposable-worktree and an existing --worktree; NTM will not treat a main checkout as disposable")
	}
	if !validProviderNativeOperationID(strings.TrimSpace(zaiOperationID)) || strings.TrimSpace(grokParentSession) == "" {
		return providerWorkflowPlan{}, errors.New("provider workflow requires a valid --zai-operation-id and exact --grok-parent-session")
	}
	absolute, err := filepath.Abs(worktree)
	if err != nil {
		return providerWorkflowPlan{}, fmt.Errorf("resolve workflow worktree: %w", err)
	}
	linked, err := deps.isLinkedWorktree(ctx, absolute)
	if err != nil || !linked {
		return providerWorkflowPlan{}, errors.New("provider workflow requires an existing linked Git worktree; no worktree was created or changed")
	}
	plan := providerWorkflowPlan{
		SchemaVersion: providerRoutingSchema, Workflow: "zai-implement-grok-review", DisposableWorktree: true,
		WorktreeSHA256:       sha256StringCLI(filepath.Clean(absolute)),
		ZAIOperationIDSHA256: sha256StringCLI(strings.TrimSpace(zaiOperationID)), GrokParentSHA256: sha256StringCLI(strings.TrimSpace(grokParentSession)),
		NoAutomaticFailover:  true,
		ReconciliationPolicy: "manual controller decision after both independently signed receipts verify; no automatic merge, retry, or provider substitution",
		Stages: []providerWorkflowStage{
			{Name: providerWorkflowZAIImplementStage, ProviderProfile: zaiProfileName, IdentitySHA256: zaiIdentity.Hash(), PolicySHA256: providerCodexPolicySHA256(), Transport: "zai_codex_runtime", AgentType: "zai", RequiredOperation: providerOperationWorkspaceWrite, ExpectedModel: zaiIdentity.Model(), Dispatch: "explicit owner-authorized provider codex run only", ReceiptRequirement: "signed exact-model Z.ai Codex receipt bound to this operation and worktree"},
			{Name: providerWorkflowGrokReviewStage, ProviderProfile: grokProfileName, IdentitySHA256: grokIdentity.Hash(), PolicySHA256: agent.GrokAutomationPolicySHA256(grokProfile.AutomationPolicy), Transport: "xai_headless_session", AgentType: "grok", RequiredOperation: providerOperationReview, Dispatch: "explicit independent provider session resume review only", ReceiptRequirement: "signed Grok session receipt bound to this parent and worktree"},
			{Name: providerWorkflowReconcileStage, ProviderProfile: "ntm-controller", Transport: "controller", AgentType: "controller", RequiredOperation: "manual", Dispatch: "provider route workflow reconcile", ReceiptRequirement: "both preceding receipt signatures must verify"},
		},
	}
	plan.WorkflowSHA256 = providerWorkflowPlanDigest(plan)
	return plan, nil
}

func providerWorkflowPlanDigest(plan providerWorkflowPlan) string {
	plan.WorkflowSHA256 = ""
	encoded, err := json.Marshal(plan)
	if err != nil {
		return ""
	}
	return sha256StringCLI(string(encoded))
}

func reconcileZAIGrokWorkflow(ctx context.Context, planPath, zaiReceiptPath, grokReceiptPath string, deps providerRouteDependencies) (providerWorkflowReconciliation, error) {
	if ctx == nil || deps.readFile == nil || deps.trustedSigner == nil || strings.TrimSpace(planPath) == "" || strings.TrimSpace(zaiReceiptPath) == "" || strings.TrimSpace(grokReceiptPath) == "" {
		return providerWorkflowReconciliation{}, errors.New("provider workflow reconcile requires --plan, --zai-receipt, and --grok-receipt")
	}
	planBytes, err := deps.readFile(planPath)
	if err != nil {
		return providerWorkflowReconciliation{}, fmt.Errorf("read provider workflow plan: %w", err)
	}
	var plan providerWorkflowPlan
	if err := decodeProviderNativeToolArgs(planBytes, &plan); err != nil || !validProviderWorkflowPlan(plan) {
		return providerWorkflowReconciliation{}, errors.New("provider workflow plan is invalid or its digest does not match")
	}
	var zaiSigner, grokSigner providerattestation.KeyMetadata
	if deps.profileTrustedSigner != nil && deps.loadConfig != nil {
		cfg := deps.loadConfig()
		if cfg == nil {
			return providerWorkflowReconciliation{}, errors.New("provider workflow reconcile requires configured exact provider profiles")
		}
		zaiProfile, profileErr := cfg.ProviderProfile(plan.Stages[0].ProviderProfile)
		if profileErr != nil {
			return providerWorkflowReconciliation{}, errors.New("provider workflow reconcile could not resolve the exact Z.ai profile")
		}
		grokProfile, profileErr := cfg.ProviderProfile(plan.Stages[1].ProviderProfile)
		if profileErr != nil {
			return providerWorkflowReconciliation{}, errors.New("provider workflow reconcile could not resolve the exact Grok profile")
		}
		zaiSigner, err = deps.profileTrustedSigner(ctx, zaiProfile)
		if err != nil || strings.TrimSpace(zaiSigner.KeyID) == "" {
			return providerWorkflowReconciliation{}, errors.New("provider workflow reconcile requires the exact Z.ai profile-pinned receipt signer")
		}
		grokSigner, err = deps.profileTrustedSigner(ctx, grokProfile)
		if err != nil || strings.TrimSpace(grokSigner.KeyID) == "" {
			return providerWorkflowReconciliation{}, errors.New("provider workflow reconcile requires the exact Grok profile-pinned receipt signer")
		}
	} else {
		// Focused legacy unit-test seam. Production always resolves both profile
		// pins above; it never selects an ambient signing bridge.
		trustedSigner, signerErr := deps.trustedSigner(ctx)
		if signerErr != nil || strings.TrimSpace(trustedSigner.KeyID) == "" {
			return providerWorkflowReconciliation{}, errors.New("provider workflow reconcile requires the trusted local receipt signer")
		}
		zaiSigner, grokSigner = trustedSigner, trustedSigner
	}
	zaiBytes, err := deps.readFile(zaiReceiptPath)
	if err != nil {
		return providerWorkflowReconciliation{}, fmt.Errorf("read Z.ai receipt: %w", err)
	}
	grokBytes, err := deps.readFile(grokReceiptPath)
	if err != nil {
		return providerWorkflowReconciliation{}, fmt.Errorf("read Grok receipt: %w", err)
	}
	zaiOutput, err := verifyZAICodexWorkflowReceipt(zaiBytes, zaiSigner, plan.Stages[0].ExpectedModel)
	if err != nil {
		return providerWorkflowReconciliation{}, err
	}
	grokOutput, err := verifyGrokWorkflowReceipt(grokBytes, grokSigner)
	if err != nil {
		return providerWorkflowReconciliation{}, err
	}
	if zaiOutput.Profile != plan.Stages[0].ProviderProfile || zaiOutput.IdentitySHA256 != plan.Stages[0].IdentitySHA256 || zaiOutput.Receipt.PolicySHA256 != plan.Stages[0].PolicySHA256 || zaiOutput.OperationIDSHA256 != plan.ZAIOperationIDSHA256 || zaiOutput.Receipt.CWDSHA256 != plan.WorktreeSHA256 || !zaiOutput.Admission.Allowed || !zaiOutput.Admission.NoFailover || zaiOutput.Admission.CapacityControlScope != provider.CapacityControlScopeLocalShared {
		return providerWorkflowReconciliation{}, errors.New("Z.ai receipt is valid but does not match the exact workflow plan")
	}
	if grokOutput.Profile != plan.Stages[1].ProviderProfile || grokOutput.IdentitySHA256 != plan.Stages[1].IdentitySHA256 || grokOutput.PolicySHA256 != plan.Stages[1].PolicySHA256 || grokOutput.WorktreeSHA256 != plan.WorktreeSHA256 || grokOutput.Receipt.WorktreeSHA256 != plan.WorktreeSHA256 || grokOutput.Receipt.ParentSessionSHA256 != plan.GrokParentSHA256 || !grokOutput.Admission.Allowed || !grokOutput.Admission.NoFailover || grokOutput.Admission.CapacityControlScope != provider.CapacityControlScopeLocalShared {
		return providerWorkflowReconciliation{}, errors.New("Grok receipt is valid but does not match the exact workflow plan")
	}
	return providerWorkflowReconciliation{SchemaVersion: providerRoutingSchema, Workflow: plan.Workflow, WorkflowSHA256: plan.WorkflowSHA256, ZAIReceiptSHA256: sha256StringCLI(string(zaiBytes)), GrokReceiptSHA256: sha256StringCLI(string(grokBytes)), BothReceiptsValid: true, Decision: "manual_review_required", AutomaticDispatch: false, AutomaticFailover: false}, nil
}

func validProviderWorkflowPlan(plan providerWorkflowPlan) bool {
	return plan.SchemaVersion == providerRoutingSchema && plan.Workflow == "zai-implement-grok-review" && plan.DisposableWorktree && plan.NoAutomaticFailover && len(plan.Stages) == 3 &&
		plan.WorkflowSHA256 != "" && plan.WorkflowSHA256 == providerWorkflowPlanDigest(plan) && validProviderNativeDigest(plan.WorktreeSHA256) && validProviderNativeDigest(plan.ZAIOperationIDSHA256) && validProviderNativeDigest(plan.GrokParentSHA256) &&
		plan.Stages[0].Name == providerWorkflowZAIImplementStage && plan.Stages[0].Transport == "zai_codex_runtime" && plan.Stages[0].RequiredOperation == providerOperationWorkspaceWrite && strings.TrimSpace(plan.Stages[0].ExpectedModel) != "" && validProviderNativeDigest(plan.Stages[0].IdentitySHA256) && validProviderNativeDigest(plan.Stages[0].PolicySHA256) &&
		plan.Stages[1].Name == providerWorkflowGrokReviewStage && plan.Stages[1].Transport == "xai_headless_session" && plan.Stages[1].RequiredOperation == providerOperationReview && validProviderNativeDigest(plan.Stages[1].IdentitySHA256) && validProviderNativeDigest(plan.Stages[1].PolicySHA256) &&
		plan.Stages[2].Name == providerWorkflowReconcileStage && plan.Stages[2].Transport == "controller"
}

func verifyZAICodexWorkflowReceipt(data []byte, trustedSigner providerattestation.KeyMetadata, expectedModel string) (providerCodexRunOutput, error) {
	var output providerCodexRunOutput
	if err := decodeProviderNativeToolArgs(data, &output); err != nil {
		return providerCodexRunOutput{}, errors.New("Z.ai workflow receipt is not valid JSON")
	}
	if !output.Success || output.Transport != "zai_codex_runtime" || output.Attestation == nil || output.Attestation.KeyMetadata != trustedSigner || !validProviderNativeDigest(output.QualificationSHA256) || !providerCodexWorkflowModelEvidence(output.Receipt, expectedModel) || !providerCodexWorkflowRuntimeContract(output.Receipt) {
		return providerCodexRunOutput{}, errors.New("Z.ai workflow receipt is not a successful signed Codex operation")
	}
	payload, err := canonicalProviderCodexOutput(output)
	if err != nil {
		return providerCodexRunOutput{}, fmt.Errorf("Z.ai workflow receipt canonicalization failed: %w", err)
	}
	if err := providerattestation.ValidateBridgePayload(payload); err != nil {
		return providerCodexRunOutput{}, fmt.Errorf("Z.ai workflow receipt violates the signing contract: %w", err)
	}
	if err := providerattestation.Verify(payload, *output.Attestation); err != nil {
		return providerCodexRunOutput{}, fmt.Errorf("Z.ai workflow receipt signature is invalid: %w", err)
	}
	return output, nil
}

func providerCodexWorkflowRuntimeContract(receipt zai.CodexRunReceipt) bool {
	requirements := provider.RuntimeEventRequirements{ToolLifecycle: true}
	if receipt.RuntimeEventRequirements != requirements {
		return false
	}
	recomputed := provider.ValidateRuntimeEventsForModel(receipt.ResolvedModel, receipt.RuntimeEvents, requirements)
	claimed := receipt.RuntimeEventContract
	return recomputed.Required == claimed.Required && recomputed.Observed == claimed.Observed && recomputed.Passed && claimed.Passed &&
		recomputed.ReceiptSHA256 == claimed.ReceiptSHA256 && slices.Equal(recomputed.Violations, claimed.Violations)
}

// providerCodexWorkflowModelEvidence keeps reconciliation from laundering a
// merely requested Z.ai model into a served-model claim. The profile binding is
// verified at dispatch; reconciliation accepts only the terminal structured
// served-model evidence required by the Coding Plan lane.
func providerCodexWorkflowModelEvidence(receipt zai.CodexRunReceipt, expectedModel string) bool {
	return receipt.ModelVerified && receipt.ModelEvidence == providerCodexTerminalModelEvidence &&
		strings.TrimSpace(expectedModel) != "" && receipt.RequestedModel == expectedModel && receipt.ResolvedModel == expectedModel
}

func verifyGrokWorkflowReceipt(data []byte, trustedSigner providerattestation.KeyMetadata) (providerSessionOutput, error) {
	var output providerSessionOutput
	if err := decodeProviderNativeToolArgs(data, &output); err != nil {
		return providerSessionOutput{}, errors.New("Grok workflow receipt is not valid JSON")
	}
	if !output.Success || output.Transport != "xai_headless_session" || output.Attestation == nil || output.Attestation.KeyMetadata != trustedSigner || !validProviderSessionOutput(output) {
		return providerSessionOutput{}, errors.New("Grok workflow receipt is not a successful valid signed session operation")
	}
	return output, nil
}

func printProviderRouteJSON(cmd *cobra.Command, value any) error {
	if cmd == nil {
		return errors.New("provider route command is unavailable")
	}
	return encodeIndentedJSON(cmd.OutOrStdout(), value)
}
