package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/state"
	"github.com/spf13/cobra"
)

type providerReadinessEvidence struct {
	Operation      string     `json:"operation"`
	State          string     `json:"state"`
	Source         string     `json:"source"`
	EvidenceSHA256 string     `json:"evidence_sha256,omitempty"`
	ObservedAt     *time.Time `json:"observed_at,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
}

type providerReadinessLane struct {
	Profile                string                        `json:"profile"`
	Identity               providerDoctorIdentity        `json:"identity"`
	AccountSHA256          string                        `json:"account_sha256"`
	Transport              string                        `json:"transport"`
	WorkspaceEvidence      string                        `json:"workspace_evidence"`
	AdmissionState         string                        `json:"admission_state"`
	Blockers               []string                      `json:"blockers"`
	DispatchAuthorized     bool                          `json:"dispatch_authorized"`
	Credential             map[string]any                `json:"credential"`
	Qualification          providerDoctorQualification   `json:"qualification"`
	QualificationExpiresAt *time.Time                    `json:"qualification_expires_at,omitempty"`
	UsableUntil            *time.Time                    `json:"usable_until,omitempty"`
	RequestedDuration      time.Duration                 `json:"requested_duration_ns"`
	DurationFits           bool                          `json:"duration_fits"`
	CapabilitySummary      []providerReadinessCapability `json:"capability_summary"`
	EvidenceDiscoveryLimit int                           `json:"evidence_discovery_limit"`
	EvidenceTruncated      bool                          `json:"evidence_truncated"`
	EvidenceErrors         []string                      `json:"evidence_errors,omitempty"`
	Capacity               map[string]any                `json:"capacity"`
	Checks                 []providerReadinessEvidence   `json:"checks"`
	Operations             []providerAssignmentStatus    `json:"operations"`
	RemoteTermination      string                        `json:"remote_generation_termination"`
}

type providerReadinessCapability struct {
	Operation          string `json:"operation"`
	State              string `json:"state"`
	ObservationIndexes []int  `json:"observation_indexes"`
}

// This is a single read surface over existing admission and receipt owners.
// It never reserves capacity, sends a prompt, or manufactures a qualification.
func newProviderReadinessCmd() *cobra.Command {
	var profiles, operations []string
	var cwd string
	var duration time.Duration
	cmd := &cobra.Command{Use: "readiness", Short: "Compare exact provider readiness, capability evidence and separate capacity units without generation", Args: cobra.NoArgs}
	cmd.Flags().StringSliceVar(&profiles, "profile", nil, "Exact provider profiles; repeat to compare providers")
	cmd.Flags().StringSliceVar(&operations, "operation", nil, "Existing task evidence as PROFILE=OPERATION_ID; repeat for completion and cancellation")
	cmd.Flags().StringVar(&cwd, "cwd", "", "Absolute intended workspace for local policy inspection; defaults to current directory")
	cmd.Flags().DurationVar(&duration, "task-timeout", 5*time.Minute, "Intended task duration for credential and qualification window checks")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if len(profiles) == 0 || len(profiles) > 16 {
			return errors.New("readiness requires 1-16 exact profiles")
		}
		if duration <= 0 {
			return errors.New("readiness task timeout must be positive")
		}
		if cwd != "" && !filepath.IsAbs(cwd) {
			return errors.New("readiness workspace must be absolute")
		}
		bindings, err := providerReadinessOperationBindings(profiles, operations)
		if err != nil {
			return err
		}
		loaded := loadSelectedConfigOrDefault()
		if loaded == nil {
			return errors.New("configuration unavailable")
		}
		lanes := make([]providerReadinessLane, 0, len(profiles))
		for _, name := range profiles {
			lane, err := buildProviderReadiness(cmd, loaded, name, cwd)
			if err != nil {
				return err
			}
			store, err := state.Open("")
			if err != nil {
				return err
			}
			automatic, truncated, discoverErr := discoverProviderReadinessOperations(store, lane.Identity.SHA256)
			closeErr := store.Close()
			if err = errors.Join(discoverErr, closeErr); err != nil {
				return err
			}
			lane.EvidenceDiscoveryLimit, lane.EvidenceTruncated = 64, truncated
			selected := append(append([]string{}, bindings[name]...), automatic...)
			seen := map[string]bool{}
			explicit := map[string]bool{}
			for _, operation := range bindings[name] {
				explicit[operation] = true
			}
			for _, operation := range selected {
				if seen[operation] {
					continue
				}
				seen[operation] = true
				if err = withProviderAssignmentStatus(cmd, name, operation, func(status providerAssignmentStatus) error {
					lane.Operations = append(lane.Operations, status)
					return nil
				}); err != nil {
					if explicit[operation] {
						return err
					}
					lane.EvidenceErrors = append(lane.EvidenceErrors, "unverifiable_task_reference:"+sha256StringCLI(operation))
				}
			}
			lane.Checks = append(lane.Checks, providerTaskEvidence(lane.Operations)...)
			lane.CapabilitySummary = summarizeProviderReadiness(lane.Checks)
			applyProviderReadinessWindow(&lane, duration, time.Now().UTC())
			lanes = append(lanes, lane)
		}
		if IsJSONOutput() {
			return encodeIndentedJSON(cmd.OutOrStdout(), map[string]any{"schema_version": "ntm.provider-readiness.v1", "generated_at": time.Now().UTC(), "generation_calls": 0, "dispatch_authorized": false, "note": "Evidence and local prerequisites only. Dispatch rechecks exact identity, credential, workspace, qualification, capacity and campaign. Historical task evidence never renews qualification.", "providers": lanes})
		}
		for _, lane := range lanes {
			fmt.Fprintf(cmd.OutOrStdout(), "%s (%s / %s): workspace evidence %s; admission %s\n", lane.Profile, lane.Identity.Provider, lane.Identity.Model, lane.WorkspaceEvidence, lane.AdmissionState)
			fmt.Fprintf(cmd.OutOrStdout(), "Credential: %v; blockers: %s\n", lane.Credential["state"], strings.Join(lane.Blockers, ", "))
			fmt.Fprintf(cmd.OutOrStdout(), "Usable until: %v; task duration fits: %t\n", lane.UsableUntil, lane.DurationFits)
			if lane.EvidenceTruncated || len(lane.EvidenceErrors) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "Task evidence: history truncated=%t; unverifiable references=%d (see JSON details)\n", lane.EvidenceTruncated, len(lane.EvidenceErrors))
			}
			for _, check := range lane.CapabilitySummary {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s: %s (%d retained observations)\n", check.Operation, check.State, len(check.ObservationIndexes))
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Execution slots, experiment attempts and billing usage are separate. This inspection grants no dispatch.")
		}
		return nil
	}
	return cmd
}

// Candidate discovery is not verification. Every selected row is subsequently
// verified by withProviderAssignmentStatus against the exact configured identity
// and currently trusted signer. Never discover by account alias or model alone.
func discoverProviderReadinessOperations(store *state.Store, identity string) ([]string, bool, error) {
	if store == nil || !validProviderNativeDigest(identity) {
		return nil, false, errors.New("task evidence discovery requires an exact identity and store")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := store.DB().QueryContext(ctx, `SELECT operation_id FROM send_operations
		WHERE payload_sha256 = ? AND session_name IN (?, ?)
		GROUP BY operation_id ORDER BY MAX(created_at) DESC, operation_id LIMIT 65`, identity, providerControlScope, primaryAssignmentScope)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	result := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, false, err
		}
		if !validProviderNativeOperationID(id) {
			return nil, false, errors.New("invalid task evidence reference")
		}
		result = append(result, id)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(result) > 64 {
		return result[:64], true, nil
	}
	return result, false, nil
}

func summarizeProviderReadiness(observations []providerReadinessEvidence) []providerReadinessCapability {
	result := []providerReadinessCapability{}
	positions := map[string]int{}
	// Passed means demonstrated at least once. All failed and untested
	// observations remain referenced; this summary never authorizes dispatch.
	rank := map[string]int{"untested": 0, "unsupported": 1, "failed": 2, "passed": 3}
	for i, observation := range observations {
		position, exists := positions[observation.Operation]
		if !exists {
			position = len(result)
			positions[observation.Operation] = position
			result = append(result, providerReadinessCapability{Operation: observation.Operation, State: observation.State})
		}
		entry := &result[position]
		entry.ObservationIndexes = append(entry.ObservationIndexes, i)
		if rank[observation.State] > rank[entry.State] {
			entry.State = observation.State
		}
	}
	return result
}

func applyProviderReadinessWindow(lane *providerReadinessLane, duration time.Duration, now time.Time) {
	lane.RequestedDuration = duration
	lane.UsableUntil = lane.QualificationExpiresAt
	if expires, ok := lane.Credential["expires_at"].(time.Time); ok && (lane.UsableUntil == nil || expires.Before(*lane.UsableUntil)) {
		lane.UsableUntil = &expires
	}
	lane.DurationFits = duration > 0 && lane.UsableUntil != nil && now.Add(duration).Before(*lane.UsableUntil)
	if !lane.DurationFits {
		lane.Blockers = append(lane.Blockers, "task_timeout_exceeds_known_validity_window")
		lane.AdmissionState = "blocked"
	}
}

func providerReadinessOperationBindings(profiles, operations []string) (map[string][]string, error) {
	result := map[string][]string{}
	for _, name := range profiles {
		if name == "" || strings.TrimSpace(name) != name {
			return nil, errors.New("exact profile required")
		}
		if _, ok := result[name]; ok {
			return nil, errors.New("duplicate profile")
		}
		result[name] = []string{}
	}
	if len(operations) > 64 {
		return nil, errors.New("at most 64 task evidence bindings are allowed")
	}
	seen := map[string]bool{}
	for _, binding := range operations {
		name, id, ok := strings.Cut(binding, "=")
		if !ok || !validProviderNativeOperationID(id) {
			return nil, errors.New("task evidence must be PROFILE=OPERATION_ID")
		}
		if _, ok = result[name]; !ok {
			return nil, errors.New("task evidence profile must be selected explicitly")
		}
		if seen[binding] {
			return nil, errors.New("duplicate task evidence")
		}
		seen[binding] = true
		result[name] = append(result[name], id)
	}
	return result, nil
}

func buildProviderReadiness(cmd *cobra.Command, cfg *config.Config, name, cwd string) (providerReadinessLane, error) {
	p, err := cfg.ProviderProfile(name)
	if err != nil {
		return providerReadinessLane{}, err
	}
	id, err := p.Identity()
	if err != nil {
		return providerReadinessLane{}, err
	}
	report := providerDoctorReport{Profile: name, Identity: providerDoctorIdentity{SHA256: id.Hash(), Provider: id.Provider(), Model: id.Model(), Runtime: id.Runtime(), CredentialClass: id.CredentialClass(), BillingClass: id.BillingClass(), Entitlement: id.Entitlement(), Evidence: id.EvidenceGrade()}}
	credential := map[string]any{"state": "unverified", "scope": "offline inspection does not authenticate to provider"}
	blockers := []string{}
	primary := id.Provider() == "openai" || id.Provider() == "anthropic"
	if primary {
		_, report.Transport, err = validatePrimaryComparisonProfile(p)
		if err != nil {
			return providerReadinessLane{}, err
		}
		report.Capabilities = provider.CapabilityMatrix()[report.Transport]
		err = inspectPrimaryReadiness(cmd, name, func(out map[string]any) error {
			report.Runtime.Drift = "none"
			if reason, _ := out["reason"].(string); reason != "ready" {
				blockers = append(blockers, reason)
				if reason == "runtime_pin_mismatch" || reason == "companion_unavailable" {
					report.Runtime.Drift = "mismatch"
				}
			}
			if fresh, _ := out["credential_fresh"].(bool); fresh {
				credential["state"] = "fresh_local_snapshot"
			} else {
				credential["state"] = "missing_or_expired"
			}
			credential["scope"] = "local profile binding; provider session validity is checked at dispatch"
			if expires, ok := out["credential_expires_at"]; ok {
				credential["expires_at"] = expires
			}
			if q, ok := out["qualification_report"].(providerDoctorQualification); ok {
				report.Qualification = q
			}
			return nil
		})
		if err != nil {
			return providerReadinessLane{}, err
		}
		report.Capacity, _ = diagnoseProviderCapacity(id, providerDoctorDeps, nil)
	} else {
		deps := providerDoctorDeps
		if cwd != "" && deps.inspectGrok != nil {
			inspect := deps.inspectGrok
			deps.inspectGrok = func(ctx context.Context, binary, _ string, home string) (providerGrokInspection, error) {
				return inspect(ctx, binary, cwd, home)
			}
		}
		report, err = buildProviderDoctorReport(providerCommandContext(cmd), cfg, providerCommandOptions{profile: name, timeout: 60 * time.Second, qualificationAge: 24 * time.Hour, requireOperation: providerOperationWorkspaceWrite}, deps)
		if err != nil {
			return providerReadinessLane{}, err
		}
		for _, check := range report.Checks {
			if check.Status == providerDoctorFail && check.ID != "qualification" && check.ID != "lifecycle_authority" {
				blockers = append(blockers, check.ID+": "+check.Summary)
			}
		}
		if report.Transport == "zai_claude_runtime" {
			blockers = append(blockers, "opaque_transport_has_no_authoritative_request_accounting")
		}
	}
	if block := providerDoctorCapacityAdmissionBlock(report.Capacity); block != "" {
		blockers = append(blockers, block)
	}
	lane := providerReadinessFromReport(report, credential, blockers)
	lane.AccountSHA256 = sha256StringCLI(id.AccountAlias())
	campaign, err := providerReadinessCampaign()
	if err != nil {
		return lane, err
	}
	lane.Capacity = providerReadinessCapacity(report.Capacity, campaign)
	if campaign != nil && campaign.Used >= campaign.Limit {
		lane.Blockers = append(lane.Blockers, "selected_campaign_exhausted")
		lane.AdmissionState = "blocked"
	}
	return lane, nil
}

func providerReadinessFromReport(report providerDoctorReport, credential map[string]any, blockers []string) providerReadinessLane {
	lane := providerReadinessLane{Profile: report.Profile, Identity: report.Identity, Transport: report.Transport, Credential: credential, Qualification: report.Qualification, WorkspaceEvidence: "unqualified", AdmissionState: "blocked", Blockers: append([]string{}, blockers...), Checks: []providerReadinessEvidence{}, Operations: []providerAssignmentStatus{}, RemoteTermination: "unverified"}
	baseline := providerBaselineForReport(report)
	passed := map[string]bool{}
	for _, check := range baseline.Checks {
		evidence := providerReadinessEvidence{Operation: check.Operation, State: check.State, Source: "qualification", EvidenceSHA256: check.EvidenceSHA256}
		if check.EvidenceSHA256 != "" && !report.Qualification.CompletedAt.IsZero() {
			observed := report.Qualification.CompletedAt
			expires := observed.Add(24 * time.Hour)
			evidence.ObservedAt = &observed
			evidence.ExpiresAt = &expires
		}
		lane.Checks = append(lane.Checks, evidence)
		passed[check.Operation] = check.State == "passed"
	}
	if !report.Qualification.CompletedAt.IsZero() {
		expires := report.Qualification.CompletedAt.Add(24 * time.Hour)
		lane.QualificationExpiresAt = &expires
	}
	if passed["model_identity"] && passed["workspace_edit"] && passed["test_execution"] && passed["permission_denial"] && passed["cleanup"] {
		lane.WorkspaceEvidence = "qualified"
	}
	if lane.WorkspaceEvidence != "qualified" {
		lane.Blockers = append(lane.Blockers, "workspace_qualification_missing_stale_or_incomplete")
	}
	if report.Identity.Provider == "zai" && !passed["capacity_accounting"] {
		lane.Blockers = append(lane.Blockers, "capacity_accounting_not_qualified")
	}
	if len(lane.Blockers) == 0 {
		lane.AdmissionState = "ready_for_dispatch_checks"
	}
	return lane
}

func providerReadinessCampaign() (*state.ProviderCampaign, error) {
	if providerCampaignID == "" {
		return nil, nil
	}
	store, err := openProviderCampaignStore()
	if err != nil {
		return nil, err
	}
	defer store.Close()
	campaign, err := store.ProviderCampaign(providerCampaignID)
	if err != nil {
		return nil, err
	}
	return &campaign, nil
}

func providerCampaignObservation(c state.ProviderCampaign) map[string]any {
	return map[string]any{"id": c.ID, "limit": c.Limit, "used": c.Used, "remaining": max(0, c.Limit-c.Used), "authorization_sha256": c.AuthorizationSHA256, "unit": "dispatch_attempt", "runtime_transports": "one attempt per runtime dispatch; may contain multiple provider requests", "native_api": "one attempt per HTTP generation round", "billing_usage": false, "refunded_on_failure": false}
}

func providerReadinessCapacity(capacity providerDoctorCapacity, campaign *state.ProviderCampaign) map[string]any {
	experiment := map[string]any{"state": "not_selected", "unit": "dispatch_attempt", "billing_usage": false}
	if campaign != nil {
		experiment = providerCampaignObservation(*campaign)
	}
	billing := map[string]any{"state": "not_metered_by_controller", "settlement": "unverified"}
	if capacity.Subscription != nil {
		billing = map[string]any{"state": "local_conservative_reservation", "settlement": "unverified", "unit": "coding_plan_credit", "snapshot": capacity.Subscription, "unknown_usage_reserved": capacity.Subscription.UnknownUsageReserved}
	}
	return map[string]any{"execution_slots": map[string]any{"scope": capacity.Scope, "running": capacity.Running, "unit": "local_process_slot", "observed_at": time.Now().UTC()}, "experiment_attempts": experiment, "billing_usage": billing}
}

// Ordinary-task evidence is kept separate from the qualification row and its
// expiry. A later failed task cannot erase earlier independently passed checks.
func providerTaskEvidence(operations []providerAssignmentStatus) []providerReadinessEvidence {
	result := []providerReadinessEvidence{}
	for _, op := range operations {
		if !op.IdentityBindingVerified || op.OutcomeSHA256 == "" {
			continue
		}
		observations := map[string]bool{"launch": op.CompletionConfirmed, "assignment": op.CompletionConfirmed, "prompt_delivery": op.CompletionConfirmed, "workspace_edit": op.WorkspaceVerified, "test_execution": op.WorkspaceVerified, "completion_detection": op.CompletionConfirmed, "cleanup": op.LocalCleanupVerified, "ordinary_task": op.CompletionConfirmed, "local_cancellation": op.CancellationObserved && op.LocalCleanupVerified, "local_slot_release": op.CapacityObservation != nil && op.CapacityObservation.LocalSlotReleased, "guarded_fresh_restart": op.CompletionConfirmed && op.RestartOfSHA256 != ""}
		for _, name := range []string{"launch", "assignment", "prompt_delivery", "workspace_edit", "test_execution", "completion_detection", "cleanup", "ordinary_task", "local_cancellation", "local_slot_release", "guarded_fresh_restart"} {
			state := "untested"
			if observations[name] {
				state = "passed"
			} else if name == "ordinary_task" && op.State == "failed" {
				state = "failed"
			}
			result = append(result, providerReadinessEvidence{Operation: name, State: state, Source: "task_signed_runtime_and_local_controller", EvidenceSHA256: op.OutcomeSHA256, ObservedAt: op.CompletedAt})
		}
	}
	for _, name := range []string{"ordinary_task", "local_cancellation", "local_slot_release", "guarded_fresh_restart"} {
		found := false
		for _, row := range result {
			if row.Operation == name {
				found = true
			}
		}
		if !found {
			result = append(result, providerReadinessEvidence{Operation: name, State: "untested", Source: "no_task_evidence_selected"})
		}
	}
	result = append(result, providerReadinessEvidence{Operation: "remote_generation_termination", State: "untested", Source: "no_provider_authoritative_evidence"}, providerReadinessEvidence{Operation: "billing_settlement", State: "untested", Source: "local_release_is_not_provider_settlement"})
	return result
}
