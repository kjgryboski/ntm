package cli

// One-shot recovery for a legacy Z.ai Codex turn that completed at the
// provider but whose older NTM parser left a full-week unknown reservation.
// This command never contacts a provider and never turns recovery evidence
// into model-identity or qualification evidence.

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/state"
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

const providerCodexCapacityRecoverySchema = "ntm.provider-codex-capacity-recovery.v1"

type providerCodexCapacityRecoveryOptions struct {
	profile             string
	operationID         string
	rolloutFile         string
	apply               bool
	acceptUnboundLegacy bool
}

type providerCodexCapacityRecoveryAdmission interface {
	CapacityStatus() ratelimit.CapacityStatus
	Snapshot(provider.Identity) ratelimit.SubscriptionCapacitySnapshot
	ApplyLegacyUnknownUsageAuthorization(provider.Identity, ratelimit.TokenUsage, time.Time, string) (float64, error)
}

type providerCodexCapacityRecoveryDependencies struct {
	loadConfig       func() *config.Config
	attest           func(context.Context, zai.CodexManifestExpectation) (zai.CodexManifestAttestation, error)
	pinnedSigner     func(config.ProviderProfileConfig) (func(context.Context, []byte) (providerattestation.SignatureMetadata, error), error)
	admission        providerCodexCapacityRecoveryAdmission
	openLedger       func() (providerNativeOperationLedger, func() error, error)
	readRollout      func(string, string, string) (zai.CodexRolloutRecoveryEvidence, error)
	store            func(string, providerqualification.Receipt) (string, error)
	recoveryStoreDir func() string
	now              func() time.Time
}

var providerCodexCapacityRecoveryDeps = providerCodexCapacityRecoveryDependencies{
	loadConfig:       loadSelectedConfigOrDefault,
	attest:           zai.AttestCodexManifest,
	pinnedSigner:     providerCodexPinnedSigner,
	admission:        defaultProviderCodexSubscriptionAdmission(),
	openLedger:       openProviderNativeLedger,
	readRollout:      zai.ReadCodexRolloutRecoveryEvidence,
	store:            providerqualification.Store,
	recoveryStoreDir: providerCodexCapacityRecoveryStoreDir,
	now:              func() time.Time { return time.Now().UTC() },
}

type providerCodexCapacityRecoveryOutput struct {
	SchemaVersion        string  `json:"schema_version"`
	Success              bool    `json:"success"`
	State                string  `json:"state"`
	Profile              string  `json:"profile"`
	IdentitySHA256       string  `json:"identity_sha256"`
	OperationIDSHA256    string  `json:"operation_id_sha256"`
	RolloutSHA256        string  `json:"rollout_sha256"`
	ConservativeCredits  float64 `json:"conservative_credits"`
	UnknownUsageReserved bool    `json:"unknown_usage_reserved"`
	ConservativeUsage    bool    `json:"conservative_usage_recorded"`
	LegacyAuthorization  bool    `json:"legacy_owner_authorized_recovery"`
	ReceiptPath          string  `json:"receipt_path"`
	ReceiptSHA256        string  `json:"receipt_sha256"`
}

func newProviderCodexRecoverCapacityCmd() *cobra.Command {
	opts := providerCodexCapacityRecoveryOptions{}
	cmd := &cobra.Command{
		Use:   "recover-capacity",
		Short: "Authorize one explicitly unbound legacy Codex accounting repair",
		Long: `Replace exactly one recent full-week unknown Coding Plan reservation with
a worst-case token charge derived from a strict isolated Codex rollout. Legacy
records do not contain an operation-to-rollout or operation-to-reservation
cryptographic link, so this requires a separate explicit acceptance flag and a
signed authorization record. It makes no provider call, proves no model
identity, and cannot qualify or promote the Z.ai lane.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProviderCodexCapacityRecovery(cmd, opts, providerCodexCapacityRecoveryDeps)
		},
	}
	cmd.Flags().StringVar(&opts.profile, "profile", "", "Exact configured Z.ai codex_responses profile (required)")
	cmd.Flags().StringVar(&opts.operationID, "operation-id", "", "Original blocked operation id (required)")
	cmd.Flags().StringVar(&opts.rolloutFile, "rollout-file", "", "Exact rollout JSONL below the isolated runtime session store (required)")
	cmd.Flags().BoolVar(&opts.apply, "apply", false, "Apply the bounded local capacity repair")
	cmd.Flags().BoolVar(&opts.acceptUnboundLegacy, "accept-unbound-legacy-evidence", false, "Acknowledge that legacy evidence has no cryptographic operation-to-usage link")
	return cmd
}

func runProviderCodexCapacityRecovery(cmd *cobra.Command, opts providerCodexCapacityRecoveryOptions, deps providerCodexCapacityRecoveryDependencies) error {
	if strings.TrimSpace(opts.profile) == "" || strings.TrimSpace(opts.profile) != opts.profile || strings.TrimSpace(opts.rolloutFile) == "" || strings.TrimSpace(opts.rolloutFile) != opts.rolloutFile {
		return errors.New("provider codex recover-capacity requires exact --profile and --rollout-file values")
	}
	if !validProviderNativeOperationID(opts.operationID) || strings.TrimSpace(opts.operationID) != opts.operationID {
		return errors.New("provider codex recover-capacity requires a valid exact --operation-id")
	}
	if !opts.apply {
		return errors.New("provider codex recover-capacity changes local subscription accounting; pass --apply to authorize it")
	}
	if !opts.acceptUnboundLegacy {
		return errors.New("legacy Codex records have no cryptographic operation-to-usage link; pass --accept-unbound-legacy-evidence only for an explicit owner-authorized exception")
	}
	if deps.loadConfig == nil || deps.attest == nil || deps.pinnedSigner == nil || deps.admission == nil || deps.openLedger == nil || deps.readRollout == nil || deps.store == nil || deps.recoveryStoreDir == nil || deps.now == nil {
		return errors.New("provider codex recover-capacity dependencies are incomplete")
	}
	cfg := deps.loadConfig()
	if cfg == nil {
		return errors.New("provider codex recover-capacity requires loaded configuration")
	}
	profile, err := cfg.ProviderProfile(opts.profile)
	if err != nil {
		return err
	}
	identity, err := profile.Identity()
	if err != nil {
		return err
	}
	if identity.Provider() != "zai" || identity.Runtime() != "codex" || identity.Endpoint() != zai.OfficialCodexEndpoint || identity.CredentialClass() != provider.CredentialClassCodingPlan || identity.BillingClass() != provider.BillingClassCodingPlan || identity.Entitlement() != provider.EntitlementCodexResponses || profile.AutomationPolicy != provider.DefaultZAICodexAutomationPolicyName || !profile.ExactTargetOnly || !profile.ProbeRequired {
		return errors.New("provider codex recover-capacity requires an exact isolated Z.ai Coding Plan Codex profile")
	}

	ctx := providerCommandContext(cmd)
	manifestExpectation := zai.CodexManifestExpectation{
		RuntimeHome: profile.RuntimeHome, Account: identity.AccountAlias(), Model: identity.Model(),
		BrokerCredentialID: profile.BrokerCredentialID, Binary: profile.Command, BinarySHA256: profile.RuntimeSHA256,
		BrokerCommand: profile.BrokerCommand, BrokerCommandSHA256: profile.BrokerCommandSHA256,
		CredentialBridgeCommand: profile.CredentialBridgeCommand, CredentialBridgeCommandSHA256: profile.CredentialBridgeCommandSHA256,
		Version: profile.RuntimeVersion, ConfigSHA256: profile.ConfigSHA256,
	}
	manifest, err := deps.attest(ctx, manifestExpectation)
	if err != nil {
		return fmt.Errorf("provider codex recovery manifest attestation failed: %w", err)
	}
	sign, err := deps.pinnedSigner(profile)
	if err != nil {
		return fmt.Errorf("provider codex recovery pinned receipt signer is unavailable: %w", err)
	}
	if err := preflightProviderReceiptSigner(ctx, sign); err != nil {
		return fmt.Errorf("provider codex recovery requires a working pinned receipt signer before mutation: %w", err)
	}
	if deps.admission.CapacityStatus().Scope != provider.CapacityControlScopeLocalShared {
		return errors.New("provider codex recovery requires the cross-process local shared capacity store")
	}

	ledger, closeLedger, err := deps.openLedger()
	if err != nil || ledger == nil {
		return errors.New("provider codex recovery requires a healthy durable operation ledger")
	}
	if closeLedger != nil {
		defer func() { _ = closeLedger() }()
	}
	original, err := ledger.GetSendOperation(opts.operationID, providerCodexOperationScope)
	if err != nil || !validBlockedProviderCodexOperation(original) {
		return errors.New("provider codex recovery requires the exact original blocked operation")
	}

	evidence, err := deps.readRollout(opts.rolloutFile, profile.RuntimeHome, manifest.RuntimeVersion)
	if err != nil {
		return fmt.Errorf("provider codex recovery rollout evidence is invalid: %w", err)
	}
	if err := evidence.Validate(); err != nil || evidence.RuntimeVersion != manifest.RuntimeVersion {
		return errors.New("provider codex recovery rollout evidence does not bind the attested runtime")
	}
	now := deps.now().UTC()
	if now.IsZero() || evidence.CompletedAt.Before(original.CreatedAt.Add(-5*time.Second)) || evidence.CompletedAt.After(original.CreatedAt.Add(30*time.Minute)) || evidence.CompletedAt.After(now.Add(time.Minute)) {
		return errors.New("provider codex recovery rollout is outside the original operation window")
	}
	expectedBinding := providerCodexBindingHashFromDigests(identity, original.PayloadSHA256, evidence.CWDSHA256, false, providerCodexWorkloadImplementation, false, sha256StringCLI(""), manifest)
	if original.BindingHash != expectedBinding {
		return errors.New("provider codex recovery rollout does not match the original read-only operation's recorded CWD and profile envelope")
	}

	before := deps.admission.Snapshot(identity)
	if before.Scope != provider.CapacityControlScopeLocalShared || before.IdentityHash != identity.Hash() || !before.UnknownUsageReserved || !validProviderNativeDigest(before.SubscriptionScopeSHA256) {
		return errors.New("provider codex recovery requires exactly one locally frozen subscription scope")
	}
	if current, readErr := ledger.GetSendOperation(opts.operationID, providerCodexOperationScope); readErr != nil || !sameBlockedProviderCodexOperation(original, current) {
		return errors.New("provider codex recovery operation changed before capacity mutation")
	}

	receipt := providerqualification.Receipt{
		Mode:               providerqualification.ModeLive,
		Provider:           "zai",
		Transport:          "zai_codex_capacity_recovery_authorization",
		IdentitySHA256:     identity.Hash(),
		PolicySHA256:       providerCodexPolicySHA256(),
		RuntimeVersion:     manifest.RuntimeVersion,
		RuntimeSHA256:      manifest.BinarySHA256,
		StartedAt:          original.CreatedAt.UTC(),
		CompletedAt:        deps.now().UTC(),
		DisposableRepoHash: sha256StringCLI(strings.Join([]string{"codex-capacity-recovery-anchor-v1", evidence.RolloutSHA256, original.BindingHash, original.PayloadSHA256}, "\x00")),
		Checks:             providerCodexCapacityRecoveryAuthorizationChecks(),
	}
	if receipt.CompletedAt.Before(receipt.StartedAt) {
		return errors.New("provider codex recovery completion clock regressed")
	}
	setProviderCodexCapacityRecoveryCheck(&receipt, "profile_manifest", "local_authoritative", sha256StringCLI(strings.Join([]string{manifest.ConfigSHA256, manifest.BinarySHA256, manifest.AuthHelperSHA256, manifest.CredentialBridgeSHA256, manifest.RuntimeVersion}, "\x00")), "Exact pinned Z.ai Coding Plan Codex manifest")
	setProviderCodexCapacityRecoveryCheck(&receipt, "operation_ledger", "local_authoritative", digestProviderCodexBlockedOperation(original), fmt.Sprintf("status=in_progress;payload_bytes=%d;created_at=%s", original.PayloadBytes, original.CreatedAt.UTC().Format(time.RFC3339)))
	setProviderCodexCapacityRecoveryCheck(&receipt, "isolated_rollout", "live", evidence.RolloutSHA256, "Bounded JSONL inside the isolated Codex session store")
	setProviderCodexCapacityRecoveryCheck(&receipt, "nonce_completion", "live", evidence.NonceSHA256, "Terminal nonce acknowledgement observed")
	usageDetail := fmt.Sprintf("input_tokens=%d;cached_input_tokens=%d;output_tokens=%d;completed_at=%s", evidence.InputTokens, evidence.CachedTokens, evidence.OutputTokens, evidence.CompletedAt.UTC().Format(time.RFC3339))
	setProviderCodexCapacityRecoveryCheck(&receipt, "provider_usage", "live", sha256StringCLI("codex-capacity-recovery-usage-v1:"+usageDetail), usageDetail)
	setProviderCodexCapacityRecoveryCheck(&receipt, "unknown_reservation_observed", "local_authoritative", sha256StringCLI(strings.Join([]string{before.SubscriptionScopeSHA256, fmt.Sprintf("%.9f", before.WeeklyCreditsUsed), fmt.Sprint(before.UnknownUsageReserved)}, "\x00")), "unknown_usage_reserved=true;event_linkage=legacy_unavailable")
	limitation := "Owner authorizes a legacy local accounting exception; this does not prove an operation-to-rollout or operation-to-reservation link"
	setProviderCodexCapacityRecoveryCheck(&receipt, "owner_authorized_unbound_exception", "local_authoritative", sha256StringCLI(strings.Join([]string{"codex-owner-authorized-unbound-v1", sha256StringCLI(opts.operationID), evidence.RolloutSHA256, before.SubscriptionScopeSHA256}, "\x00")), limitation)
	if err := receipt.Finalize(); err != nil {
		return fmt.Errorf("finalize provider codex recovery receipt: %w", err)
	}
	payload, err := receipt.CanonicalPayload()
	if err != nil {
		return err
	}
	if err := providerattestation.ValidateBridgePayload(payload); err != nil {
		return fmt.Errorf("provider codex recovery receipt violates the signing bridge contract: %w", err)
	}
	signature, err := sign(ctx, payload)
	if err != nil {
		return fmt.Errorf("sign provider codex recovery receipt: %w", err)
	}
	if err := receipt.AttachAttestation(signature); err != nil {
		return err
	}
	path, err := deps.store(deps.recoveryStoreDir(), receipt)
	if err != nil {
		return fmt.Errorf("store provider codex recovery authorization before mutation: %w", err)
	}
	if current, readErr := ledger.GetSendOperation(opts.operationID, providerCodexOperationScope); readErr != nil || !sameBlockedProviderCodexOperation(original, current) {
		return errors.New("provider codex recovery operation changed after authorization; capacity was not mutated")
	}

	usage := ratelimit.TokenUsage{InputTokens: evidence.InputTokens, CachedInputTokens: evidence.CachedTokens, OutputTokens: evidence.OutputTokens}
	credits, err := deps.admission.ApplyLegacyUnknownUsageAuthorization(identity, usage, evidence.CompletedAt, receipt.ReceiptSHA256)
	if err != nil {
		return fmt.Errorf("provider codex capacity recovery was refused after recording authorization: %w", err)
	}
	after := deps.admission.Snapshot(identity)
	if after.Scope != provider.CapacityControlScopeLocalShared || after.IdentityHash != identity.Hash() || after.SubscriptionScopeSHA256 != before.SubscriptionScopeSHA256 || after.UnknownUsageReserved || !after.ConservativeUsage || !after.LegacyRecoveryAuthorized || credits <= 0 || after.FiveHourCreditsUsed > after.FiveHourCreditsLimit || after.WeeklyCreditsUsed > after.WeeklyCreditsLimit {
		return errors.New("provider codex recovery produced an invalid state; inspect the signed authorization and capacity journal before any dispatch")
	}
	blockedAfter, err := ledger.GetSendOperation(opts.operationID, providerCodexOperationScope)
	if err != nil || !sameBlockedProviderCodexOperation(original, blockedAfter) {
		return errors.New("provider codex recovery left the original operation in an unexpected state; do not redispatch it")
	}

	output := providerCodexCapacityRecoveryOutput{
		SchemaVersion:        providerCodexCapacityRecoverySchema,
		Success:              true,
		State:                "owner_authorized_legacy_repair_unqualified",
		Profile:              opts.profile,
		IdentitySHA256:       identity.Hash(),
		OperationIDSHA256:    sha256StringCLI(opts.operationID),
		RolloutSHA256:        evidence.RolloutSHA256,
		ConservativeCredits:  credits,
		UnknownUsageReserved: after.UnknownUsageReserved,
		ConservativeUsage:    after.ConservativeUsage,
		LegacyAuthorization:  after.LegacyRecoveryAuthorized,
		ReceiptPath:          path,
		ReceiptSHA256:        receipt.ReceiptSHA256,
	}
	if IsJSONOutput() {
		return encodeIndentedJSON(cmd.OutOrStdout(), output)
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Z.ai Codex capacity repaired under an explicit signed legacy exception; the evidence remains unbound, the original operation remains blocked, and the provider lane remains unqualified.\nAuthorization: %s\n", path)
	return err
}

func providerCodexCapacityRecoveryStoreDir() string {
	return filepath.Join(filepath.Dir(providerqualification.DefaultStoreDir()), "provider-capacity-recoveries")
}

func providerCodexCapacityRecoveryAuthorizationChecks() []providerqualification.Check {
	names := providerqualification.CodexCapacityRecoveryAuthorizationRequiredChecks()
	checks := make([]providerqualification.Check, len(names))
	for index, name := range names {
		checks[index].Name = name
	}
	return checks
}

func setProviderCodexCapacityRecoveryCheck(receipt *providerqualification.Receipt, name, provenance, evidence, detail string) {
	for index := range receipt.Checks {
		if receipt.Checks[index].Name == name {
			receipt.Checks[index].Passed = true
			receipt.Checks[index].Provenance = provenance
			receipt.Checks[index].EvidenceSHA256 = evidence
			receipt.Checks[index].Detail = detail
			return
		}
	}
}

func validBlockedProviderCodexOperation(operation *state.SendOperation) bool {
	return operation != nil && operation.SessionName == providerCodexOperationScope && validProviderNativeOperationID(operation.OperationID) && operation.Status == state.SendOperationInProgress && operation.OutcomeJSON == "" && operation.CompletedAt == nil && !operation.CreatedAt.IsZero() && operation.PayloadBytes > 0 && validProviderNativeDigest(operation.BindingHash) && validProviderNativeDigest(operation.PayloadSHA256)
}

func sameBlockedProviderCodexOperation(expected, observed *state.SendOperation) bool {
	return validBlockedProviderCodexOperation(expected) && validBlockedProviderCodexOperation(observed) && *expected == *observed
}

func digestProviderCodexBlockedOperation(operation *state.SendOperation) string {
	if !validBlockedProviderCodexOperation(operation) {
		return sha256StringCLI("invalid-blocked-provider-codex-operation")
	}
	return sha256StringCLI(strings.Join([]string{sha256StringCLI(operation.OperationID), operation.SessionName, operation.BindingHash, operation.PayloadSHA256, fmt.Sprint(operation.PayloadBytes), operation.Status, operation.CreatedAt.UTC().Format(time.RFC3339Nano)}, "\x00"))
}
