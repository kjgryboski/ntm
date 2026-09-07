package cli

// One-shot recovery for a legacy Z.ai Codex turn that completed at the
// provider but whose older NTM parser left a full-week unknown reservation.
// This command never contacts a provider and never turns recovery evidence
// into model-identity or qualification evidence.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

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

// This is a source-bound review record, not provider attestation. Matching a
// caller's claims to local ledger fields cannot establish remote authenticity.
type providerUsageEvidence struct {
	SchemaVersion      string     `json:"schema_version"`
	IdentitySHA256     string     `json:"identity_sha256"`
	AccountAliasSHA256 string     `json:"account_alias_sha256"`
	OperationIDSHA256  string     `json:"operation_id_sha256"`
	OperationBinding   string     `json:"operation_binding_sha256"`
	ProviderAccount    string     `json:"provider_account_sha256"`
	ProviderRequest    string     `json:"provider_request_sha256"`
	SourceKind         string     `json:"source_kind"`
	SourceSHA256       string     `json:"source_sha256"`
	TerminalStatus     string     `json:"terminal_status"`
	BillingUnits       string     `json:"billing_units"`
	FinalUsage         *float64   `json:"final_usage"`
	SettlementScope    string     `json:"settlement_scope"`
	OutstandingUsage   *float64   `json:"outstanding_usage"`
	RequestCompletedAt time.Time  `json:"request_completed_at"`
	RequestStartedAt   *time.Time `json:"request_started_at,omitempty"`
	SettledThrough     time.Time  `json:"settled_through"`
	ObservedAt         time.Time  `json:"observed_at"`
}

type providerUsageImportResult struct {
	SchemaVersion       string                 `json:"schema_version"`
	ValidationPassed    bool                   `json:"validation_passed"`
	Reasons             []string               `json:"reasons"`
	EvidenceSHA256      string                 `json:"evidence_sha256"`
	SourceSHA256        string                 `json:"source_sha256"`
	Authority           string                 `json:"authority"`
	ProviderAssociation string                 `json:"provider_association"`
	GenerationCalls     int                    `json:"generation_calls"`
	AccountingMutated   bool                   `json:"accounting_mutated"`
	AdmissionGranted    bool                   `json:"admission_granted"`
	Evidence            *providerUsageEvidence `json:"evidence,omitempty"`
}

func newProviderUsageImportCmd() *cobra.Command {
	return providerUsageImportCommand(resolveProviderUsageTarget)
}

// This is an operator's signed review of an authenticated source, not a
// provider signature. The importer deliberately cannot manufacture it.
type providerUsageSourceReview struct {
	Envelope                        *providerqualification.Receipt         `json:"attestation_envelope,omitempty"`
	HistoricalIdentityMappingSHA256 string                                 `json:"historical_identity_mapping_sha256,omitempty"`
	Schema                          string                                 `json:"schema_version"`
	EvidenceSHA256                  string                                 `json:"evidence_sha256"`
	SourceSHA256                    string                                 `json:"source_sha256"`
	IdentitySHA256                  string                                 `json:"identity_sha256"`
	OperationBinding                string                                 `json:"operation_binding_sha256"`
	NonceSHA256                     string                                 `json:"nonce_sha256"`
	LegacyReservationSHA256         string                                 `json:"legacy_reservation_sha256,omitempty"`
	LegacyAssociation               string                                 `json:"legacy_association,omitempty"`
	OrphanReservationSHA256         string                                 `json:"orphan_reservation_sha256,omitempty"`
	SubscriptionScopeSHA256         string                                 `json:"subscription_scope_sha256,omitempty"`
	LedgerPathSHA256                string                                 `json:"ledger_path_sha256,omitempty"`
	OrphanAssociation               string                                 `json:"orphan_association,omitempty"`
	ProviderAccount                 string                                 `json:"provider_account_sha256"`
	ProviderRequest                 string                                 `json:"provider_request_sha256"`
	SourceAuthentication            string                                 `json:"source_authentication"`
	RequestAssociation              string                                 `json:"request_association"`
	ReviewedAt                      time.Time                              `json:"reviewed_at"`
	Attestation                     *providerattestation.SignatureMetadata `json:"attestation,omitempty"`
}

func verifyProviderUsageSourceReview(review providerUsageSourceReview, imported providerUsageImportResult, trusted providerattestation.KeyMetadata, now time.Time) error {
	e := imported.Evidence
	bound := review.Schema == "ntm.provider-usage-source-review.v1" && validProviderNativeDigest(review.NonceSHA256) && review.LegacyReservationSHA256 == "" && review.LegacyAssociation == ""
	legacy := review.Schema == "ntm.provider-usage-source-review.v2" && review.NonceSHA256 == "" && validProviderNativeDigest(review.LegacyReservationSHA256) && review.LegacyAssociation == "exact_local_reservation_associated_with_authenticated_original_request"
	orphan := review.Schema == "ntm.provider-usage-source-review.v3" && validProviderNativeDigest(review.NonceSHA256) && validProviderNativeDigest(review.OrphanReservationSHA256) && validProviderNativeDigest(review.SubscriptionScopeSHA256) && validProviderNativeDigest(review.LedgerPathSHA256) && review.LegacyReservationSHA256 == "" && review.LegacyAssociation == "" && review.OrphanAssociation == "original_runtime_identity_binding_nonce_and_exact_row_associated_with_authenticated_request"
	if (bound || legacy) && (review.OrphanReservationSHA256 != "" || review.SubscriptionScopeSHA256 != "" || review.LedgerPathSHA256 != "" || review.OrphanAssociation != "") {
		return errors.New("orphan fields require the separate orphan settlement contract")
	}
	if review.HistoricalIdentityMappingSHA256 != "" && (!orphan || !validProviderNativeDigest(review.HistoricalIdentityMappingSHA256)) {
		return errors.New("historical identity mapping requires exact orphan review")
	}
	if !imported.ValidationPassed || e == nil || (!bound && !legacy && !orphan) || (review.Attestation == nil) == (review.Envelope == nil) || review.EvidenceSHA256 != imported.EvidenceSHA256 || review.SourceSHA256 != imported.SourceSHA256 || review.IdentitySHA256 != e.IdentitySHA256 || review.OperationBinding != e.OperationBinding || review.ProviderAccount != e.ProviderAccount || review.ProviderRequest != e.ProviderRequest || review.RequestAssociation != "original_request_confirmed_by_provider_source" || (review.SourceAuthentication != "authenticated_account_export_reviewed" && review.SourceAuthentication != "authenticated_support_reply_reviewed") || review.ReviewedAt.Before(e.ObservedAt) || review.ReviewedAt.After(now) {
		return errors.New("authenticated source review and exact request association are required")
	}
	if review.Envelope != nil {
		if !validProviderLocalReviewIdentity(review.Envelope, "zai", review.IdentitySHA256, providerUsageReviewPolicy, providerUsageReviewDigest(review), review.ReviewedAt, trusted, now) {
			return errors.New("usage review envelope differs from the exact source review or pinned signer")
		}
		return nil
	}
	if review.Attestation.KeyMetadata != trusted {
		return errors.New("usage review signer differs from pinned authority")
	}
	signature := *review.Attestation
	review.Attestation = nil
	payload, err := json.Marshal(review)
	if err != nil {
		return err
	}
	return providerattestation.Verify(payload, signature)
}

func newProviderUsageSettlementCmd() *cobra.Command {
	trust := func(cmd *cobra.Command, profile string) (providerattestation.KeyMetadata, error) {
		cfg := loadSelectedConfigOrDefault()
		if cfg == nil {
			return providerattestation.KeyMetadata{}, errors.New("configuration unavailable")
		}
		p, err := cfg.ProviderProfile(profile)
		if err != nil {
			return providerattestation.KeyMetadata{}, err
		}
		reviewer, err := providerHistoricalReviewSignerProfile(cmd, p)
		if err != nil {
			return providerattestation.KeyMetadata{}, err
		}
		sign, err := providerProfilePinnedSigner(reviewer)
		if err != nil {
			return providerattestation.KeyMetadata{}, err
		}
		trusted, err := preflightProviderReceiptSignerMetadataFor(providerCommandContext(cmd), sign, false)
		return trusted.KeyMetadata, err
	}
	cmd := providerUsageSettlementCommand(resolveProviderUsageTarget, defaultProviderCodexSubscriptionAdmission, trust)
	cmd.AddCommand(providerOrphanUsageSettlementCommand(withProviderOrphanLedgerGuard, defaultProviderCodexSubscriptionAdmission, trust))
	cmd.AddCommand(newProviderHistoricalIdentityMapCmd())
	cmd.AddCommand(providerUsageSourceSigningCommand(withProviderLocalReviewTarget))
	return cmd
}

const providerUsageReviewPolicy = "ntm.authenticated-provider-usage-source-review.v1"

func providerUsageReviewDigest(r providerUsageSourceReview) string {
	r.Attestation = nil
	r.Envelope = nil
	return digestSafeJSON(r)
}

// Signing records an explicit owner's source review only. The settlement
// command independently checks source bytes, request evidence and current state.
func providerUsageSourceSigningCommand(target func(*cobra.Command, string, func(config.ProviderProfileConfig, provider.Identity, providerNativeOperationLedger, func(context.Context, []byte) (providerattestation.SignatureMetadata, error), providerattestation.KeyMetadata) error) error) *cobra.Command {
	var name, input, output string
	var confirm bool
	cmd := &cobra.Command{Use: "sign-source-review", Short: "Sign an explicitly authenticated orphan usage review without settling or granting admission", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&name, "profile", "", "Exact original Z.ai target")
	cmd.Flags().String("reviewer-profile", "", "Explicit current protected reviewer for the same provider, account and subscription scope")
	cmd.Flags().StringVar(&input, "review-file", "", "Absolute unsigned v3 review of authenticated provider evidence")
	cmd.Flags().StringVar(&output, "output", "", "New absolute signed review file")
	cmd.Flags().BoolVar(&confirm, "confirm-authenticated-source-review", false, "Attest that the actual provider source authenticates this exact request, account, explicit usage units and settlement coverage")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if !confirm || name == "" || !filepath.IsAbs(input) || !filepath.IsAbs(output) {
			return errors.New("exact target, unsigned review, new output and explicit authenticated-source confirmation required")
		}
		data, err := readProviderUsageFile(input)
		if err != nil {
			return err
		}
		var r providerUsageSourceReview
		if err = decodeProviderLocalReview(data, &r); err != nil {
			return err
		}
		if r.Schema != "ntm.provider-usage-source-review.v3" || r.Attestation != nil || r.Envelope != nil || r.ReviewedAt.IsZero() || r.ReviewedAt.After(time.Now().UTC()) || r.LegacyReservationSHA256 != "" || r.LegacyAssociation != "" || r.OrphanAssociation != "original_runtime_identity_binding_nonce_and_exact_row_associated_with_authenticated_request" || r.RequestAssociation != "original_request_confirmed_by_provider_source" || (r.SourceAuthentication != "authenticated_support_reply_reviewed" && r.SourceAuthentication != "authenticated_account_export_reviewed") {
			return errors.New("unsigned exact orphan authenticated-source review required")
		}
		for _, digest := range []string{r.IdentitySHA256, r.EvidenceSHA256, r.SourceSHA256, r.OperationBinding, r.NonceSHA256, r.OrphanReservationSHA256, r.SubscriptionScopeSHA256, r.LedgerPathSHA256, r.ProviderAccount, r.ProviderRequest} {
			if !validProviderNativeDigest(digest) {
				return errors.New("source review contains an invalid binding digest")
			}
		}
		if r.HistoricalIdentityMappingSHA256 != "" && !validProviderNativeDigest(r.HistoricalIdentityMappingSHA256) {
			return errors.New("invalid historical mapping digest")
		}
		return target(cmd, name, func(p config.ProviderProfileConfig, id provider.Identity, _ providerNativeOperationLedger, sign func(context.Context, []byte) (providerattestation.SignatureMetadata, error), trusted providerattestation.KeyMetadata) error {
			if id.Provider() != "zai" || id.Runtime() != "codex" || id.Entitlement() != provider.EntitlementCodexResponses || r.SubscriptionScopeSHA256 != sha256StringCLI(string(id.SubscriptionCapacityScope())) {
				return errors.New("source review differs from exact Z.ai subscription scope")
			}
			if r.IdentitySHA256 != id.Hash() {
				old, err := provider.NewIdentityWithAuthorization(p.Provider, p.AccountAlias, p.Model, p.Endpoint, p.Runtime, p.CredentialClass, p.BillingClass, p.Entitlement, p.ConfigSHA256)
				if err != nil || r.HistoricalIdentityMappingSHA256 == "" || old.Hash() != r.IdentitySHA256 {
					return errors.New("source review identity differs from current or explicitly mapped historical target")
				}
				id = old
			}
			r.Envelope, err = signProviderLocalReview(providerCommandContext(cmd), p, id, providerUsageReviewPolicy, providerUsageReviewDigest(r), r.ReviewedAt, sign)
			if err != nil {
				return err
			}
			if !validProviderLocalReview(r.Envelope, id, providerUsageReviewPolicy, providerUsageReviewDigest(r), r.ReviewedAt, trusted, time.Now().UTC()) {
				return errors.New("signed usage-source envelope could not be verified")
			}
			encoded, err := json.MarshalIndent(r, "", "  ")
			if err != nil {
				return err
			}
			f, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			_, writeErr := f.Write(encoded)
			return errors.Join(writeErr, f.Sync(), f.Close())
		})
	}
	return cmd
}

func providerUsageSettlementCommand(resolve func(string, string) (provider.Identity, *state.SendOperation, error), admission func() *ratelimit.SubscriptionAdmissionController, trust func(*cobra.Command, string) (providerattestation.KeyMetadata, error)) *cobra.Command {
	var profile, operation, evidenceFile, sourceFile, reviewFile string
	var apply, inspectLegacy bool
	cmd := &cobra.Command{Use: "settle-reviewed-usage", Short: "Verify a signed authenticated-source review and atomically settle its exact reservation", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&profile, "profile", "", "Exact Z.ai Codex profile")
	cmd.Flags().StringVar(&operation, "operation-id", "", "Original bound operation")
	cmd.Flags().StringVar(&evidenceFile, "evidence-file", "", "Absolute structured usage evidence")
	cmd.Flags().StringVar(&sourceFile, "source-file", "", "Absolute authenticated provider source")
	cmd.Flags().StringVar(&reviewFile, "review-file", "", "Absolute review signed by the pinned owner reviewer")
	cmd.Flags().BoolVar(&apply, "apply", false, "Apply the verified exact settlement")
	cmd.Flags().BoolVar(&inspectLegacy, "inspect-legacy-reservations", false, "Show local nonce-less row fingerprints for review; does not prove request association")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if !validProviderNativeOperationID(operation) || (!inspectLegacy && (!filepath.IsAbs(evidenceFile) || !filepath.IsAbs(sourceFile) || !filepath.IsAbs(reviewFile))) || (inspectLegacy && (apply || evidenceFile != "" || sourceFile != "" || reviewFile != "")) {
			return errors.New("absolute evidence, source, review and exact operation are required")
		}
		id, row, err := resolve(profile, operation)
		if err != nil {
			return err
		}
		if inspectLegacy {
			rows, err := admission().LegacyUsageReservations(id)
			if err != nil {
				return err
			}
			return encodeIndentedJSON(cmd.OutOrStdout(), map[string]any{"schema_version": "ntm.legacy-reservation-inspection.v1", "identity_sha256": id.Hash(), "reservation_sha256": rows, "provider_association": "unverified", "accounting_mutated": false, "admission_granted": false, "generation_calls": 0})
		}
		data, err := readProviderUsageFile(evidenceFile)
		if err != nil {
			return err
		}
		source, err := readProviderUsageFile(sourceFile)
		if err != nil {
			return err
		}
		reviewData, err := readProviderUsageFile(reviewFile)
		if err != nil {
			return err
		}
		var review providerUsageSourceReview
		if err := validateProviderReviewJSON(json.NewDecoder(bytes.NewReader(reviewData)), 0); err != nil {
			return errors.New("ambiguous source review")
		}
		decoder := json.NewDecoder(bytes.NewReader(reviewData))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&review) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			return errors.New("invalid source review")
		}
		trusted, err := trust(cmd, profile)
		if err != nil {
			return err
		}
		imported := validateProviderUsageEvidence(data, source, id, operation, row, time.Now().UTC())
		if review.Schema == "ntm.provider-usage-source-review.v3" {
			return errors.New("orphan review requires the orphan subcommand")
		}
		if err := verifyProviderUsageSourceReview(review, imported, trusted, time.Now().UTC()); err != nil {
			return err
		}
		if review.LegacyReservationSHA256 != "" {
			if err := admission().ReviewLegacyUsage(id, row.BindingHash, review.LegacyReservationSHA256, *imported.Evidence.FinalUsage, imported.Evidence.RequestCompletedAt, sha256TextCLI(reviewData), apply); err != nil {
				return err
			}
		} else {
			controller := admission()
			var err error
			if apply {
				err = controller.SettleReviewedUsage(id, row.BindingHash, review.NonceSHA256, *imported.Evidence.FinalUsage, imported.Evidence.RequestCompletedAt, sha256TextCLI(reviewData))
			} else {
				err = controller.ReviewBoundUsage(id, row.BindingHash, review.NonceSHA256, *imported.Evidence.FinalUsage, imported.Evidence.RequestCompletedAt, sha256TextCLI(reviewData), false)
			}
			if err != nil {
				return err
			}
		}
		return encodeIndentedJSON(cmd.OutOrStdout(), map[string]any{"schema_version": "ntm.provider-usage-settlement.v1", "review_verified": true, "settlement_applied_or_already_present": apply, "admission_granted": false, "generation_calls": 0, "review_sha256": sha256TextCLI(reviewData), "authority": "pinned_owner_authenticated_source_review"})
	}
	return cmd
}

// Keep the selected ledger locked across absence validation and the capacity
// transaction. This creates no operation and prevents a concurrent claim from
// racing the absence check. Errors, missing ledgers and matching outcome bodies
// all fail closed; no timestamp-based association is inferred.
func withProviderOrphanLedgerGuard(cmd *cobra.Command, profile, binding string, visit func(provider.Identity, string) error) error {
	cfg := loadSelectedConfigOrDefault()
	if cfg == nil {
		return errors.New("configuration unavailable")
	}
	p, err := cfg.ProviderProfile(profile)
	if err != nil {
		return err
	}
	id, err := p.Identity()
	if err != nil {
		return err
	}
	if id.Provider() != "zai" || id.Runtime() != "codex" || id.Entitlement() != provider.EntitlementCodexResponses || !validProviderNativeDigest(binding) {
		return errors.New("exact original Z.ai Codex identity and binding required")
	}
	path, err := filepath.Abs(state.DefaultPath())
	if err != nil {
		return err
	}
	return withProviderOrphanLedgerPathGuard(providerCommandContext(cmd), path, binding, func(ledgerSHA string) error { return visit(id, ledgerSHA) })
}

func withProviderOrphanLedgerPathGuard(parent context.Context, path, binding string, visit func(string) error) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("existing regular selected ledger required")
	}
	store, err := state.Open(path)
	if err != nil {
		return err
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	conn, err := store.DB().Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return errors.New("exclusive ledger absence guard unavailable")
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	var matches int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM send_operations WHERE binding_hash = ? OR instr(COALESCE(outcome_json, ''), ?) > 0", binding, binding).Scan(&matches); err != nil {
		return errors.New("ledger absence could not be established")
	}
	if matches != 0 {
		return errors.New("binding is present in selected ledger; use its original operation settlement")
	}
	return visit(sha256StringCLI(path))
}

func providerOrphanUsageSettlementCommand(guard func(*cobra.Command, string, string, func(provider.Identity, string) error) error, admission func() *ratelimit.SubscriptionAdmissionController, trust func(*cobra.Command, string) (providerattestation.KeyMetadata, error)) *cobra.Command {
	var profile, binding, evidenceFile, sourceFile, reviewFile string
	var mappingFile, originalFile, requestFile, bridgeFile string
	var inspect, apply bool
	cmd := &cobra.Command{Use: "orphan", Short: "Inspect or settle an exact nonce-bound reservation absent from the selected ledger", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&profile, "profile", "", "Exact original runtime identity profile; a successor is not a substitute")
	cmd.Flags().StringVar(&binding, "binding-sha256", "", "Original reservation operation binding")
	cmd.Flags().BoolVar(&inspect, "inspect", false, "Read local row fingerprint and ledger absence; does not authenticate provider association")
	cmd.Flags().StringVar(&evidenceFile, "evidence-file", "", "Absolute v2 original-request usage evidence")
	cmd.Flags().StringVar(&sourceFile, "source-file", "", "Absolute authenticated provider source")
	cmd.Flags().StringVar(&reviewFile, "review-file", "", "Absolute pinned signed v3 source and original runtime association review")
	cmd.Flags().BoolVar(&apply, "apply", false, "Apply the exact verified settlement; preview is the default")
	cmd.Flags().StringVar(&mappingFile, "identity-map-file", "", "Absolute pinned signed historical identity mapping")
	cmd.Flags().String("reviewer-profile", "", "Explicit current signing profile for the same historical provider, account and subscription scope")
	cmd.Flags().StringVar(&originalFile, "original-profile-file", "", "Absolute preserved original profile projection")
	cmd.Flags().StringVar(&requestFile, "request-evidence-file", "", "Absolute reviewed original request and bridge evidence")
	cmd.Flags().StringVar(&bridgeFile, "request-bridge-file", "", "Absolute retained original request bridge binary")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		mapped := mappingFile != ""
		if reviewer, _ := cmd.Flags().GetString("reviewer-profile"); reviewer != "" && !mapped {
			return errors.New("separate reviewer requires a historical identity mapping")
		}
		if (mapped && (inspect || !filepath.IsAbs(mappingFile) || !filepath.IsAbs(originalFile) || !filepath.IsAbs(requestFile) || !filepath.IsAbs(bridgeFile))) || (!mapped && (originalFile != "" || requestFile != "" || bridgeFile != "")) {
			return errors.New("historical mapping requires all original evidence files and settlement mode")
		}
		if profile == "" || !validProviderNativeDigest(binding) || (inspect && (apply || evidenceFile != "" || sourceFile != "" || reviewFile != "")) || (!inspect && (!filepath.IsAbs(evidenceFile) || !filepath.IsAbs(sourceFile) || !filepath.IsAbs(reviewFile))) {
			return errors.New("exact profile, binding and either inspection or absolute evidence/source/review required")
		}
		return guard(cmd, profile, binding, func(id provider.Identity, ledgerSHA string) error {
			controller := admission()
			reservation, err := controller.InspectBoundUsage(id, binding)
			if err != nil {
				return err
			}
			scopeSHA := sha256StringCLI(string(id.SubscriptionCapacityScope()))
			if inspect {
				return encodeIndentedJSON(cmd.OutOrStdout(), map[string]any{"schema_version": "ntm.orphan-reservation-inspection.v1", "identity_sha256": id.Hash(), "subscription_scope_sha256": scopeSHA, "ledger_path_sha256": ledgerSHA, "reservation": reservation, "provider_association": "unverified", "original_runtime_identity": "requires_authenticated_review", "accounting_mutated": false, "admission_granted": false, "generation_calls": 0})
			}
			data, err := readProviderUsageFile(evidenceFile)
			if err != nil {
				return err
			}
			source, err := readProviderUsageFile(sourceFile)
			if err != nil {
				return err
			}
			reviewData, err := readProviderUsageFile(reviewFile)
			if err != nil {
				return err
			}
			var review providerUsageSourceReview
			if validateProviderReviewJSON(json.NewDecoder(bytes.NewReader(reviewData)), 0) != nil {
				return errors.New("ambiguous orphan source review")
			}
			decoder := json.NewDecoder(bytes.NewReader(reviewData))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&review) != nil || decoder.Decode(&struct{}{}) != io.EOF {
				return errors.New("invalid orphan source review")
			}
			if review.Schema != "ntm.provider-usage-source-review.v3" || review.OrphanReservationSHA256 != reservation.SHA256 || review.NonceSHA256 != reservation.Nonce || review.SubscriptionScopeSHA256 != scopeSHA || review.LedgerPathSHA256 != ledgerSHA {
				return errors.New("orphan review differs from current exact reservation, scope or ledger")
			}
			trusted, err := trust(cmd, profile)
			if err != nil {
				return err
			}
			now := time.Now().UTC()
			evidenceIdentity := id
			if mapped {
				mappingData, err := readProviderUsageFile(mappingFile)
				if err != nil {
					return err
				}
				var mapping providerHistoricalIdentityMap
				if err = decodeProviderLocalReview(mappingData, &mapping); err != nil {
					return err
				}
				evidenceIdentity, err = validateProviderHistoricalIdentityMap(mapping, profile, id, reservation, ledgerSHA, originalFile, requestFile, bridgeFile, trusted, now)
				if err != nil {
					return err
				}
				if review.HistoricalIdentityMappingSHA256 != sha256TextCLI(mappingData) {
					return errors.New("usage source review does not bind this exact historical mapping")
				}
			} else if review.HistoricalIdentityMappingSHA256 != "" {
				return errors.New("historical mapping evidence missing")
			}
			imported := validateProviderUsageTargetEvidence(data, source, evidenceIdentity, "", binding, reservation.ObservedAt, now, true)
			if err := verifyProviderUsageSourceReview(review, imported, trusted, now); err != nil {
				return err
			}
			if err := controller.ReviewOrphanUsage(id, binding, reservation.Nonce, reservation.SHA256, *imported.Evidence.FinalUsage, imported.Evidence.RequestCompletedAt, sha256TextCLI(reviewData), apply); err != nil {
				return err
			}
			return encodeIndentedJSON(cmd.OutOrStdout(), map[string]any{"schema_version": "ntm.orphan-usage-settlement.v1", "review_verified": true, "settlement_applied_or_already_present": apply, "reservation_sha256": reservation.SHA256, "review_sha256": sha256TextCLI(reviewData), "authority": "pinned_owner_authenticated_source_review", "operation_created": false, "admission_granted": false, "generation_calls": 0})
		})
	}
	return cmd
}

const providerHistoricalMapPolicy = "ntm.historical-provider-identity-map.v1"

// This maps one reservation across the pre-bridge identity schema. It never
// changes an active profile, runtime dispatch identity, or subscription scope.
type providerHistoricalIdentityMap struct {
	Schema                   string                         `json:"schema_version"`
	Profile                  string                         `json:"profile"`
	HistoricalIdentitySHA256 string                         `json:"historical_identity_sha256"`
	CurrentIdentitySHA256    string                         `json:"current_identity_sha256"`
	ConfigSHA256             string                         `json:"config_sha256"`
	OriginalProfileSHA256    string                         `json:"original_profile_sha256"`
	RequestEvidenceSHA256    string                         `json:"request_evidence_sha256"`
	RequestBridgeSHA256      string                         `json:"request_bridge_sha256"`
	Binding                  string                         `json:"operation_binding_sha256"`
	Nonce                    string                         `json:"nonce_sha256"`
	ReservationSHA256        string                         `json:"reservation_sha256"`
	LedgerSHA256             string                         `json:"ledger_sha256"`
	ScopeSHA256              string                         `json:"subscription_scope_sha256"`
	Association              string                         `json:"association"`
	ReviewedAt               time.Time                      `json:"reviewed_at"`
	Envelope                 *providerqualification.Receipt `json:"attestation_envelope,omitempty"`
}

func providerHistoricalMapDigest(r providerHistoricalIdentityMap) string {
	r.Envelope = nil
	return digestSafeJSON(r)
}

func providerHistoricalIdentityFromFiles(name string, id provider.Identity, originalFile, requestFile, bridgeFile string) (provider.Identity, string, string, string, error) {
	var zero provider.Identity
	if id.Provider() != "zai" || id.Runtime() != "codex" || id.Entitlement() != provider.EntitlementCodexResponses || !filepath.IsAbs(originalFile) || !filepath.IsAbs(requestFile) || !filepath.IsAbs(bridgeFile) {
		return zero, "", "", "", errors.New("exact original Z.ai Codex files required")
	}
	data, err := readProviderUsageFile(originalFile)
	if err != nil {
		return zero, "", "", "", err
	}
	var archived struct {
		Profiles map[string]config.ProviderProfileConfig `toml:"provider_profiles"`
	}
	meta, err := toml.Decode(string(data), &archived)
	if err != nil || len(meta.Undecoded()) != 0 || len(archived.Profiles) != 1 {
		return zero, "", "", "", errors.New("one unambiguous original profile required")
	}
	p, ok := archived.Profiles[name]
	if !ok {
		return zero, "", "", "", errors.New("renamed historical profile refused")
	}
	old, err := provider.NewIdentityWithAuthorization(p.Provider, p.AccountAlias, p.Model, p.Endpoint, p.Runtime, p.CredentialClass, p.BillingClass, p.Entitlement, p.ConfigSHA256)
	if err != nil || p.AccountAlias != id.AccountAlias() || p.Provider != id.Provider() || p.Model != id.Model() || p.Endpoint != id.Endpoint() || p.Runtime != id.Runtime() || p.ConfigSHA256 != id.ConfigSHA256() || p.CredentialClass != id.CredentialClass() || p.BillingClass != id.BillingClass() || p.Entitlement != id.Entitlement() || old.Hash() == id.Hash() || old.SubscriptionCapacityScope() != id.SubscriptionCapacityScope() {
		return zero, "", "", "", errors.New("historical tuple differs from selected account, model, commercial scope or configuration")
	}
	request, err := readProviderUsageFile(requestFile)
	if err != nil || len(bytes.TrimSpace(request)) == 0 {
		return zero, "", "", "", errors.New("original request evidence unavailable")
	}
	bridgeSHA, err := hashProviderSessionExecutable(bridgeFile)
	if err != nil {
		return zero, "", "", "", err
	}
	return old, sha256TextCLI(data), sha256TextCLI(request), bridgeSHA, nil
}

func validateProviderHistoricalIdentityMap(r providerHistoricalIdentityMap, name string, id provider.Identity, row ratelimit.BoundUsageReservation, ledgerSHA, originalFile, requestFile, bridgeFile string, trusted providerattestation.KeyMetadata, now time.Time) (provider.Identity, error) {
	old, originalSHA, requestSHA, bridgeSHA, err := providerHistoricalIdentityFromFiles(name, id, originalFile, requestFile, bridgeFile)
	if err != nil {
		return provider.Identity{}, err
	}
	if r.Schema != providerHistoricalMapPolicy || r.Profile != name || r.CurrentIdentitySHA256 != id.Hash() || r.HistoricalIdentitySHA256 != old.Hash() || r.ConfigSHA256 != id.ConfigSHA256() || r.OriginalProfileSHA256 != originalSHA || r.RequestEvidenceSHA256 != requestSHA || r.RequestBridgeSHA256 != bridgeSHA || r.Binding != row.Binding || r.Nonce != row.Nonce || r.ReservationSHA256 != row.SHA256 || r.LedgerSHA256 != ledgerSHA || r.ScopeSHA256 != sha256StringCLI(string(id.SubscriptionCapacityScope())) || r.Association != "reviewed_original_configuration_and_request_time_bridge_for_exact_reservation" || r.ReviewedAt.Before(row.ObservedAt) || !validProviderLocalReview(r.Envelope, id, providerHistoricalMapPolicy, providerHistoricalMapDigest(r), r.ReviewedAt, trusted, now) {
		return provider.Identity{}, errors.New("historical identity mapping is unsigned, changed or bound to another reservation")
	}
	return old, nil
}

func newProviderHistoricalIdentityMapCmd() *cobra.Command {
	return providerHistoricalIdentityMapCommand(withProviderLocalReviewTarget, withProviderOrphanLedgerGuard, defaultProviderCodexSubscriptionAdmission)
}

func providerHistoricalIdentityMapCommand(target func(*cobra.Command, string, func(config.ProviderProfileConfig, provider.Identity, providerNativeOperationLedger, func(context.Context, []byte) (providerattestation.SignatureMetadata, error), providerattestation.KeyMetadata) error) error, guard func(*cobra.Command, string, string, func(provider.Identity, string) error) error, admission func() *ratelimit.SubscriptionAdmissionController) *cobra.Command {
	var name, binding, originalFile, requestFile, bridgeFile, output string
	var confirm bool
	cmd := &cobra.Command{Use: "identity-map", Short: "Inspect or explicitly sign an exact historical identity mapping without settling usage", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&name, "profile", "", "Exact original profile name under the current identity schema")
	cmd.Flags().String("reviewer-profile", "", "Explicit current signing profile for the same historical provider, account and subscription scope")
	cmd.Flags().StringVar(&binding, "binding-sha256", "", "Original reservation binding")
	cmd.Flags().StringVar(&originalFile, "original-profile-file", "", "Absolute preserved profile projection")
	cmd.Flags().StringVar(&requestFile, "request-evidence-file", "", "Absolute reviewed original request and bridge evidence")
	cmd.Flags().StringVar(&bridgeFile, "request-bridge-file", "", "Absolute retained original request bridge")
	cmd.Flags().StringVar(&output, "output", "", "New absolute signed mapping file")
	cmd.Flags().BoolVar(&confirm, "confirm-reviewed-identity-mapping", false, "Attest the original configuration and request-time bridge association for this exact reservation")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if name == "" || !validProviderNativeDigest(binding) || !filepath.IsAbs(originalFile) || !filepath.IsAbs(requestFile) || !filepath.IsAbs(bridgeFile) || (confirm && !filepath.IsAbs(output)) || (!confirm && output != "") {
			return errors.New("exact profile, original evidence and explicit signing output required; default is inspection")
		}
		return target(cmd, name, func(p config.ProviderProfileConfig, id provider.Identity, _ providerNativeOperationLedger, sign func(context.Context, []byte) (providerattestation.SignatureMetadata, error), trusted providerattestation.KeyMetadata) error {
			return guard(cmd, name, binding, func(guardID provider.Identity, ledgerSHA string) error {
				if guardID.Hash() != id.Hash() {
					return errors.New("identity changed during mapping review")
				}
				row, err := admission().InspectBoundUsage(id, binding)
				if err != nil {
					return err
				}
				old, originalSHA, requestSHA, bridgeSHA, err := providerHistoricalIdentityFromFiles(name, id, originalFile, requestFile, bridgeFile)
				if err != nil {
					return err
				}
				r := providerHistoricalIdentityMap{Schema: providerHistoricalMapPolicy, Profile: name, HistoricalIdentitySHA256: old.Hash(), CurrentIdentitySHA256: id.Hash(), ConfigSHA256: id.ConfigSHA256(), OriginalProfileSHA256: originalSHA, RequestEvidenceSHA256: requestSHA, RequestBridgeSHA256: bridgeSHA, Binding: binding, Nonce: row.Nonce, ReservationSHA256: row.SHA256, LedgerSHA256: ledgerSHA, ScopeSHA256: sha256StringCLI(string(id.SubscriptionCapacityScope())), Association: "reviewed_original_configuration_and_request_time_bridge_for_exact_reservation", ReviewedAt: time.Now().UTC()}
				if !confirm {
					return encodeIndentedJSON(cmd.OutOrStdout(), map[string]any{"mapping": r, "trust": "unsigned_inspection_only", "accounting_mutated": false, "generation_calls": 0})
				}
				r.Envelope, err = signProviderLocalReview(providerCommandContext(cmd), p, id, providerHistoricalMapPolicy, providerHistoricalMapDigest(r), r.ReviewedAt, sign)
				if err != nil {
					return err
				}
				if _, err = validateProviderHistoricalIdentityMap(r, name, id, row, ledgerSHA, originalFile, requestFile, bridgeFile, trusted, time.Now().UTC()); err != nil {
					return err
				}
				data, err := json.MarshalIndent(r, "", "  ")
				if err != nil {
					return err
				}
				f, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					return err
				}
				_, writeErr := f.Write(data)
				return errors.Join(writeErr, f.Sync(), f.Close())
			})
		})
	}
	return cmd
}

// Review records contain objects and scalar values only. Check every object,
// including the signature, before Go's case-insensitive typed JSON decoding.
func validateProviderUsageObject(decoder *json.Decoder, depth int) error {
	if depth > 8 {
		return errors.New("usage record nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("usage record must be an object")
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] || key != strings.ToLower(key) {
			return errors.New("ambiguous usage field")
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return errors.New("invalid usage field")
		}
		value = bytes.TrimSpace(value)
		if len(value) == 0 || value[0] == '[' {
			return errors.New("invalid usage field shape")
		}
		if value[0] == '{' {
			if err := validateProviderUsageObject(json.NewDecoder(bytes.NewReader(value)), depth+1); err != nil {
				return err
			}
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return errors.New("incomplete usage record")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing usage data")
	}
	return nil
}

func resolveProviderUsageTarget(profile, operation string) (provider.Identity, *state.SendOperation, error) {
	cfg := loadSelectedConfigOrDefault()
	if cfg == nil {
		return provider.Identity{}, nil, errors.New("configuration unavailable")
	}
	p, err := cfg.ProviderProfile(profile)
	if err != nil {
		return provider.Identity{}, nil, err
	}
	id, err := p.Identity()
	if err != nil {
		return provider.Identity{}, nil, err
	}
	if id.Provider() != "zai" || id.Runtime() != "codex" || id.Entitlement() != provider.EntitlementCodexResponses {
		return provider.Identity{}, nil, errors.New("usage import requires an exact Z.ai Coding Plan Codex identity")
	}
	ledger, closeLedger, err := openProviderNativeLedger()
	if err != nil {
		return provider.Identity{}, nil, err
	}
	defer closeLedger()
	row, err := ledger.GetSendOperation(operation, providerCodexOperationScope)
	if err != nil {
		return provider.Identity{}, nil, err
	}
	if row == nil {
		return provider.Identity{}, nil, errors.New("original operation was not found")
	}
	return id, row, nil
}

func providerUsageImportCommand(resolve func(string, string) (provider.Identity, *state.SendOperation, error)) *cobra.Command {
	var profile, operation, evidenceFile, sourceFile, output string
	var template bool
	cmd := &cobra.Command{Use: "import-usage-evidence", Short: "Validate and retain request usage evidence for external-source review; never release capacity", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&profile, "profile", "", "Exact Z.ai Codex profile")
	cmd.Flags().StringVar(&operation, "operation-id", "", "Original operation in the selected ledger")
	cmd.Flags().StringVar(&evidenceFile, "evidence-file", "", "Absolute structured review record")
	cmd.Flags().StringVar(&sourceFile, "source-file", "", "Absolute original provider export or support reply; only its digest is retained")
	cmd.Flags().StringVar(&output, "output", "", "New absolute output file; existing evidence is never replaced")
	cmd.Flags().BoolVar(&template, "template", false, "Print a locally bound template with missing provider evidence left empty")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if !validProviderNativeOperationID(operation) || (template && (evidenceFile != "" || sourceFile != "" || output != "")) || (!template && (!filepath.IsAbs(evidenceFile) || !filepath.IsAbs(sourceFile) || !filepath.IsAbs(output))) {
			return errors.New("usage import requires exact operation and either template or absolute evidence, source and new output paths")
		}
		id, row, err := resolve(profile, operation)
		if err != nil {
			return err
		}
		if row == nil {
			return errors.New("original operation was not found")
		}
		if template {
			return encodeIndentedJSON(cmd.OutOrStdout(), map[string]any{"authority": "external_source_review_required", "accounting_mutated": false, "admission_granted": false, "generation_calls": 0, "template": providerUsageEvidence{SchemaVersion: "ntm.provider-usage-evidence.v1", IdentitySHA256: id.Hash(), AccountAliasSHA256: sha256StringCLI(id.AccountAlias()), OperationIDSHA256: sha256StringCLI(operation), OperationBinding: row.BindingHash, BillingUnits: "coding_plan_credit", SettlementScope: "original_request_only"}})
		}
		evidence, err := readProviderUsageFile(evidenceFile)
		if err != nil {
			return err
		}
		source, err := readProviderUsageFile(sourceFile)
		if err != nil {
			return err
		}
		result := validateProviderUsageEvidence(evidence, source, id, operation, row, time.Now().UTC())
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')
		file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return errors.New("usage import requires a new writable output; existing evidence is preserved")
		}
		_, writeErr := file.Write(data)
		if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
			return errors.New("usage evidence export failed; partial record retained")
		}
		if _, err := cmd.OutOrStdout().Write(data); err != nil {
			return err
		}
		if !result.ValidationPassed {
			return errors.New("usage evidence failed consistency checks; capacity unchanged")
		}
		return nil
	}
	return cmd
}

func readProviderUsageFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 {
		return nil, errors.New("usage evidence requires a bounded regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("usage evidence could not be opened")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(b) == 0 || len(b) > 1<<20 {
		return nil, errors.New("usage evidence size is invalid")
	}
	return b, nil
}

func decodeProviderUsageEvidence(data []byte) (providerUsageEvidence, error) {
	// Detect duplicate top-level keys before normal typed decoding. All record
	// values are scalar, so nested objects are rejected by the typed decoder.
	var evidence providerUsageEvidence
	if len(data) == 0 || len(data) > 1<<20 {
		return evidence, errors.New("invalid usage record size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return evidence, errors.New("invalid usage record")
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] || key != strings.ToLower(key) {
			return evidence, errors.New("ambiguous usage record")
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return evidence, errors.New("invalid usage field")
		}
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&evidence) != nil {
		return evidence, errors.New("invalid usage record fields")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return evidence, errors.New("trailing usage data")
	}
	return evidence, nil
}

func validateProviderUsageEvidence(data, source []byte, id provider.Identity, operation string, row *state.SendOperation, now time.Time) providerUsageImportResult {
	if row == nil || row.OperationID != operation {
		return providerUsageImportResult{SchemaVersion: "ntm.provider-usage-import.v1", Reasons: []string{"local_identity_or_operation_mismatch"}, EvidenceSHA256: sha256TextCLI(data), SourceSHA256: sha256TextCLI(source), Authority: "external_source_review_required", ProviderAssociation: "unverified_source_claim"}
	}
	return validateProviderUsageTargetEvidence(data, source, id, sha256StringCLI(operation), row.BindingHash, row.CreatedAt, now, false)
}

func validateProviderUsageTargetEvidence(data, source []byte, id provider.Identity, operationSHA, binding string, createdAt, now time.Time, orphan bool) providerUsageImportResult {
	out := providerUsageImportResult{SchemaVersion: "ntm.provider-usage-import.v1", Reasons: []string{}, EvidenceSHA256: sha256TextCLI(data), SourceSHA256: sha256TextCLI(source), Authority: "external_source_review_required", ProviderAssociation: "unverified_source_claim"}
	e, err := decodeProviderUsageEvidence(data)
	if err != nil {
		out.Reasons = append(out.Reasons, "malformed_or_ambiguous_record")
		return out
	}
	expectedSchema := "ntm.provider-usage-evidence.v1"
	if orphan {
		expectedSchema = "ntm.provider-usage-evidence.v2"
	}
	if e.SchemaVersion != expectedSchema {
		out.Reasons = append(out.Reasons, "unsupported_schema")
	}
	if e.IdentitySHA256 != id.Hash() || e.AccountAliasSHA256 != sha256StringCLI(id.AccountAlias()) || e.OperationIDSHA256 != operationSHA || e.OperationBinding != binding {
		out.Reasons = append(out.Reasons, "local_identity_or_operation_mismatch")
	}
	if !validProviderNativeDigest(e.ProviderAccount) || !validProviderNativeDigest(e.ProviderRequest) || !validProviderNativeDigest(e.OperationBinding) {
		out.Reasons = append(out.Reasons, "provider_binding_fields_missing")
	}
	if (e.SourceKind != "provider_support_reply" && e.SourceKind != "provider_account_export") || e.SourceSHA256 != out.SourceSHA256 || len(source) == 0 {
		out.Reasons = append(out.Reasons, "source_binding_mismatch")
	}
	if e.TerminalStatus != "completed" && e.TerminalStatus != "failed" && e.TerminalStatus != "cancelled" {
		out.Reasons = append(out.Reasons, "terminal_status_missing")
	}
	if e.BillingUnits != "coding_plan_credit" || e.FinalUsage == nil || math.IsNaN(*e.FinalUsage) || math.IsInf(*e.FinalUsage, 0) || *e.FinalUsage < 0 {
		out.Reasons = append(out.Reasons, "invalid_usage_or_units")
	}
	if e.SettlementScope != "original_request_only" || e.OutstandingUsage == nil || *e.OutstandingUsage != 0 {
		out.Reasons = append(out.Reasons, "request_settlement_incomplete")
	}
	start := createdAt
	if orphan {
		if e.RequestStartedAt == nil || e.RequestStartedAt.IsZero() || e.RequestStartedAt.After(createdAt) || createdAt.After(e.ObservedAt) {
			out.Reasons = append(out.Reasons, "original_request_window_missing")
		} else {
			start = *e.RequestStartedAt
		}
	} else if e.RequestStartedAt != nil {
		out.Reasons = append(out.Reasons, "unexpected_orphan_request_window")
	}
	if e.RequestCompletedAt.IsZero() || e.RequestCompletedAt.Before(start) || e.SettledThrough.Before(e.RequestCompletedAt) || e.ObservedAt.Before(e.SettledThrough) || e.ObservedAt.After(now) {
		out.Reasons = append(out.Reasons, "settlement_window_invalid")
	}
	out.ValidationPassed = len(out.Reasons) == 0
	if out.ValidationPassed {
		out.Evidence = &e
	}
	return out
}

func newProviderCodexReconciliationPlanCmd() *cobra.Command {
	var name, operation string
	cmd := &cobra.Command{Use: "reconciliation-plan", Short: "Show the missing evidence for an uncertain Coding Plan reservation without changing admission", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&name, "profile", "", "Exact Z.ai Codex profile")
	cmd.Flags().StringVar(&operation, "operation-id", "", "Original uncertain operation to correlate; never grants an identity binding")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		cfg := loadSelectedConfigOrDefault()
		if cfg == nil {
			return errors.New("configuration unavailable")
		}
		p, err := cfg.ProviderProfile(name)
		if err != nil {
			return err
		}
		id, err := p.Identity()
		if err != nil {
			return err
		}
		if id.Provider() != "zai" || id.Runtime() != "codex" || id.Entitlement() != provider.EntitlementCodexResponses {
			return errors.New("exact Z.ai Coding Plan Codex profile required")
		}
		snapshot := defaultProviderCodexSubscriptionAdmission().Snapshot(id)
		out := providerCodexReconciliationPlan(id, snapshot)
		if operation != "" {
			if !validProviderNativeOperationID(operation) {
				return errors.New("valid original operation ID required")
			}
			ledger, closeLedger, err := openProviderNativeLedger()
			if err != nil {
				return err
			}
			defer closeLedger()
			row, err := ledger.GetSendOperation(operation, providerCodexOperationScope)
			if err != nil {
				return err
			}
			out["original_operation"] = providerReconciliationOperationTarget(operation, row)
		}
		return encodeIndentedJSON(cmd.OutOrStdout(), out)
	}
	return cmd
}

func providerCodexReconciliationPlan(id provider.Identity, snapshot ratelimit.SubscriptionCapacitySnapshot) map[string]any {
	return map[string]any{
		"schema_version": "ntm.provider-reconciliation-plan.v1", "identity_sha256": id.Hash(),
		"subscription_scope_sha256": snapshot.SubscriptionScopeSHA256, "unknown_usage_reserved": snapshot.UnknownUsageReserved,
		"generation_calls": 0, "accounting_mutated": false, "admission_granted": false,
		"settlement_path":       []string{"bind provider account and original request to the uncertain operation", "obtain terminal provider usage in the applicable billing units", "verify provider settlement cutoff covers the request and all outstanding usage", "persist reviewed evidence before an atomic reservation reconciliation"},
		"bounded_headroom_path": []string{"obtain authoritative account quota and billing units", "establish an enforceable upper bound for every outstanding request", "deduct those bounds and concurrent reservations atomically from fresh remaining quota", "retain the historical operation as unknown unless separately settled"},
		"insufficient_evidence": []string{"aggregate model usage or quota alone", "elapsed time or controller reset estimate", "local process exit without provider settlement", "a local signer repeating an unverified provider claim", "a legacy unbound rollout treated as authoritative settlement"},
		"next_generation":       "strict exact served-model preflight only after authoritative admission",
		"legacy_recovery":       "recover-capacity is an explicit owner-authorized unbound accounting exception; it is not this authoritative settlement path",
		"legacy_authoritative_resolution": map[string]any{
			"state":                   "evidence_required_no_automatic_migration",
			"nonce_may_be_fabricated": false,
			"current_settlement_accepts_nonce_less_rows": true,
			"required_provider_evidence": []string{
				"authenticated provider account identity and immutable source/export or support response",
				"provider request identifier correlated to the original operation timestamp and recorded binding; timestamp proximity alone is insufficient",
				"terminal status, final Coding Plan charge and units, and settlement coverage of the request",
				"if request correlation is unavailable: provider-authoritative accounting of all requests in the affected account/window, including outstanding liabilities and settlement cutoff",
			},
			"required_review": "Inspect the exact local row fingerprint, then obtain a pinned signed v2 source review associating it with the authenticated original request. Preview and apply settle-reviewed-usage use the same atomic engine, require one unknown row and no active leases, preserve the absent nonce, and reject stale or conflicting evidence. Full-window evidence without exact request association is not supported by this migration.",
			"next_action":     "Obtain the account-bound provider response/export and retain its source digest; keep the unknown reservation until its coverage can be verified.",
		},
		"evidence_sources": []map[string]string{
			{"source": "account-owner provider dashboard/export or provider support", "obtain": "account-bound request/usage identifier, terminal usage in Coding Plan credits, final status and settlement cutoff covering outstanding requests", "limitation": "a local operation hash is only a correlation reference until the provider binds it"},
			{"source": "official aggregate quota and model-usage endpoints", "obtain": "fresh quota/units plus account scope", "limitation": "existing aggregate responses do not identify or settle the uncertain operation; no public per-request settlement endpoint has been established by this integration"},
			{"source": "provider's authoritative outstanding-request accounting contract", "obtain": "enforceable maximum outstanding cost and coverage of concurrent requests", "limitation": "the configured full-week uncertainty reservation is not an enforceable request cost bound"},
		},
		"evidence_record_fields": []string{"provider_account_binding", "original_request_binding", "terminal_status", "billing_units", "final_usage", "settled_through", "outstanding_requests_and_bounds", "provider_source", "observed_at", "source_digest"},
	}
}

func providerReconciliationOperationTarget(operation string, row *state.SendOperation) map[string]any {
	out := map[string]any{"operation_id_sha256": sha256StringCLI(operation), "found_in_selected_ledger": row != nil, "provider_request_binding": "not_established", "settlement": "unverified", "changes_admission": false}
	if row != nil {
		out["recorded_binding_sha256"] = row.BindingHash
		out["recorded_payload_sha256"] = row.PayloadSHA256
		out["recorded_state"] = row.Status
		out["created_at"] = row.CreatedAt
		out["completed_at"] = row.CompletedAt
	}
	return out
}

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
		RuntimeHome: profile.RuntimeHome, Account: identity.AccountAlias(), Endpoint: identity.Endpoint(), Model: identity.Model(),
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
