package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	AssignmentPreview      providerAssignmentPreview     `json:"assignment_preview"`
	TaskStatistics         providerTaskStatistics        `json:"task_statistics"`
	Operator               providerOperatorReadiness     `json:"operator"`
}

type providerOperatorReadiness struct {
	AuthorizedAttempts      *int     `json:"authorized_attempts"`
	AttemptCeilingRemaining *int     `json:"attempt_ceiling_remaining"`
	AttemptAuthorization    string   `json:"attempt_authorization"`
	NextActions             []string `json:"next_actions"`
}

type providerAssignmentPreview struct {
	Eligible     bool     `json:"eligible"`
	Requirements []string `json:"requirements"`
	Reasons      []string `json:"reasons"`
}

type providerTaskStatistics struct {
	Completed               int      `json:"completed"`
	Failed                  int      `json:"failed"`
	Cancelled               int      `json:"cancelled"`
	Unresolved              int      `json:"unresolved"`
	MeasuredDurations       int      `json:"measured_durations"`
	MeanLocalElapsedSeconds *float64 `json:"mean_local_elapsed_seconds,omitempty"`
	BillingCost             string   `json:"billing_cost"`
	HumanInterventions      string   `json:"human_interventions"`
}

type providerReadinessCapability struct {
	Operation          string     `json:"operation"`
	State              string     `json:"state"`
	ObservationIndexes []int      `json:"observation_indexes"`
	FailedObservations int        `json:"failed_observations"`
	LatestDatedStates  []string   `json:"latest_dated_states"`
	LatestObservedAt   *time.Time `json:"latest_observed_at,omitempty"`
}

// Evidence exports use the same signature and binding verifier as status and
// readiness. They contain observations, not portable dispatch authority.
func newProviderEvidenceCmd() *cobra.Command {
	return providerEvidenceCommand(withProviderAssignmentStatus)
}

func providerEvidenceCommand(inspect func(*cobra.Command, string, string, func(providerAssignmentStatus) error) error) *cobra.Command {
	var profile, operation, require, parent, output string
	var contract bool
	cmd := &cobra.Command{Use: "evidence", Short: "Verify saved task evidence and export acceptance results without generation", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&profile, "profile", "", "Exact configured profile")
	cmd.Flags().StringVar(&operation, "operation", "", "Existing operation ID")
	cmd.Flags().StringVar(&require, "require", "completion", "Required result: completion, local-cancellation, guarded-restart, session-resume")
	cmd.Flags().StringVar(&parent, "restart-of", "", "Exact predecessor operation required for guarded-restart or session-resume")
	cmd.Flags().StringVar(&output, "output", "", "Optional new absolute JSON file; never replaces existing evidence")
	cmd.Flags().BoolVar(&contract, "contract", false, "Describe lifecycle guarantees and evidence requirements without inspecting a task")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if contract {
			if profile != "" || operation != "" || parent != "" || output != "" || cmd.Flags().Changed("require") {
				return errors.New("contract cannot be combined with task evidence options")
			}
			return encodeIndentedJSON(cmd.OutOrStdout(), map[string]any{
				"schema_version": "ntm.provider-lifecycle-contract.v1", "generation_calls": 0, "dispatch_authorized": false,
				"completion":            "exact signed terminal outcome, independent workspace verification, cleanup and local slot release",
				"local_cancellation":    "exact signed canceled outcome, observed controller cancellation, cleanup and local slot release",
				"guarded_fresh_restart": "verified eligible parent and distinct completed child with matching exact identity and parent digest; fresh dispatch admission required",
				"controller_crash":      "quarantine uncertain ownership; never replay, infer completion, release uncertain usage or take over from PID/age alone",
				"session_resume":        "Grok ACP requires a signed completed predecessor, exact identity and workspace, exclusive successor ownership, advertised resume and verified next-turn completion",
				"remote_termination":    "requires provider-authoritative terminal request evidence; local process exit is insufficient",
				"billing_settlement":    "requires authoritative exact request/account usage and settlement coverage; local slot release and aggregate quota are insufficient",
			})
		}
		if strings.TrimSpace(profile) == "" || !validProviderNativeOperationID(operation) || (output != "" && !filepath.IsAbs(output)) {
			return errors.New("evidence requires exact profile, operation and optional absolute output path")
		}
		if require != "completion" && require != "local-cancellation" && require != "guarded-restart" && require != "session-resume" {
			return errors.New("unsupported evidence requirement")
		}
		needsParent := require == "guarded-restart" || require == "session-resume"
		if (needsParent && (!validProviderNativeOperationID(parent) || parent == operation)) || (!needsParent && parent != "") {
			return errors.New("restart or resume requires a distinct exact predecessor operation; other requirements do not accept a predecessor")
		}
		var current, original providerAssignmentStatus
		if err := inspect(cmd, profile, operation, func(s providerAssignmentStatus) error { current = s; return nil }); err != nil {
			return err
		}
		if parent != "" {
			if err := inspect(cmd, profile, parent, func(s providerAssignmentStatus) error { original = s; return nil }); err != nil {
				return err
			}
		}
		passed := providerTaskRequirementPassed(current, original, require, sha256StringCLI(parent))
		observations := []providerAssignmentStatus{current}
		if parent != "" {
			observations = append(observations, original)
		}
		result := map[string]any{"schema_version": "ntm.provider-task-evidence.v1", "generated_at": time.Now().UTC(), "generation_calls": 0, "dispatch_authorized": false, "requirement": require, "passed": passed, "operation_id_sha256": sha256StringCLI(operation), "status": current, "checks": providerTaskEvidence(observations), "human_interventions": "not_measured", "note": "Verified from the live ledger and pinned signer. Export is a local observation, not a new signed receipt, qualification or billing settlement."}
		if parent != "" {
			result["parent_status"] = original
		}
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')
		if output != "" {
			file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return errors.New("evidence export requires a new writable file; existing evidence is preserved")
			}
			_, writeErr := file.Write(data)
			err = errors.Join(writeErr, file.Sync(), file.Close())
			if err != nil {
				return errors.New("evidence export failed; partial file retained, no replay required")
			}
		}
		if _, err := cmd.OutOrStdout().Write(data); err != nil {
			return err
		}
		if !passed {
			return errors.New("saved evidence does not satisfy the requested result; inspect it without replaying generation")
		}
		return nil
	}
	return cmd
}

func providerTaskRequirementPassed(current, parent providerAssignmentStatus, require, parentSHA string) bool {
	if !current.IdentityBindingVerified || current.OutcomeSHA256 == "" || !current.ControllerFinalized || !providerRestartAllowed(current) {
		return false
	}
	switch require {
	case "completion":
		return current.CompletionConfirmed && current.WorkspaceVerified
	case "local-cancellation":
		return current.CancellationObserved && !current.CompletionConfirmed && (current.State == "cancelled_local" || current.State == "cancelled" || current.State == "cancelled_acknowledged")
	case "guarded-restart":
		return current.CompletionConfirmed && current.WorkspaceVerified && current.RestartOfSHA256 == parentSHA && parent.OperationIDSHA256 == parentSHA && parent.ControllerFinalized && parent.OutcomeSHA256 != "" && parent.IdentitySHA256 == current.IdentitySHA256 && providerRestartAllowed(parent)
	case "session-resume":
		return current.Provider == "xai" && current.SessionResumed && !current.SessionClosed && current.CompletionConfirmed && current.WorkspaceVerified && current.ParentOperationSHA256 == parentSHA && parent.OperationIDSHA256 == parentSHA && parent.CompletionConfirmed && parent.WorkspaceVerified && parent.ControllerFinalized && parent.OutcomeSHA256 != "" && parent.IdentitySHA256 == current.IdentitySHA256 && providerRestartAllowed(parent)
	default:
		return false
	}
}

// This is a single read surface over existing admission and receipt owners.
// It never reserves capacity, sends a prompt, or manufactures a qualification.
func newProviderReadinessCmd() *cobra.Command {
	var profiles, operations, requirements []string
	var cwd string
	var duration time.Duration
	cmd := &cobra.Command{Use: "readiness", Aliases: []string{"preview"}, Short: "Compare exact provider readiness, capability evidence and separate capacity units without generation", Args: cobra.NoArgs}
	cmd.Flags().StringSliceVar(&requirements, "require", []string{"model_identity", "workspace_edit", "test_execution", "permission_denial", "cleanup"}, "Required demonstrated capabilities for the read-only assignment preview")
	cmd.Flags().StringSliceVar(&profiles, "profile", nil, "Exact provider profiles; repeat to compare providers")
	cmd.Flags().StringSliceVar(&operations, "operation", nil, "Existing task evidence as PROFILE=OPERATION_ID; repeat for completion and cancellation")
	cmd.Flags().StringVar(&cwd, "cwd", "", "Absolute intended workspace for local policy inspection; defaults to current directory")
	cmd.Flags().DurationVar(&duration, "task-timeout", 5*time.Minute, "Intended task duration for credential and qualification window checks")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if err := validateProviderPreviewRequirements(requirements); err != nil {
			return err
		}
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
			lane.AssignmentPreview = previewProviderAssignment(lane, requirements)
			lane.TaskStatistics = summarizeProviderTasks(lane.Operations)
			lane.Operator = providerOperatorView(lane)
			lanes = append(lanes, lane)
		}
		if IsJSONOutput() {
			return encodeIndentedJSON(cmd.OutOrStdout(), map[string]any{"schema_version": "ntm.provider-readiness.v1", "generated_at": time.Now().UTC(), "generation_calls": 0, "dispatch_authorized": false, "note": "Evidence and local prerequisites only. Dispatch rechecks exact identity, credential, workspace, qualification, capacity and campaign. Historical task evidence never renews qualification.", "providers": lanes})
		}
		for _, lane := range lanes {
			fmt.Fprintf(cmd.OutOrStdout(), "%s (%s / %s): workspace evidence %s; admission %s\n", lane.Profile, lane.Identity.Provider, lane.Identity.Model, lane.WorkspaceEvidence, lane.AdmissionState)
			fmt.Fprintf(cmd.OutOrStdout(), "Credential: %v; blockers: %s\n", lane.Credential["state"], strings.Join(lane.Blockers, ", "))
			fmt.Fprintf(cmd.OutOrStdout(), "Usable until: %v; task duration fits: %t\n", lane.UsableUntil, lane.DurationFits)
			fmt.Fprintf(cmd.OutOrStdout(), "Assignment preview: eligible=%t; reasons: %s\n", lane.AssignmentPreview.Eligible, strings.Join(lane.AssignmentPreview.Reasons, ", "))
			fmt.Fprintf(cmd.OutOrStdout(), "Attempt authorization: %s\n", lane.Operator.AttemptAuthorization)
			if lane.Operator.AttemptCeilingRemaining != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Unused attempt ceiling: %d (conditional authorization still applies)\n", *lane.Operator.AttemptCeilingRemaining)
			}
			for _, action := range lane.Operator.NextActions {
				fmt.Fprintf(cmd.OutOrStdout(), "Next: %s\n", action)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Verified task history: %d completed, %d failed, %d cancelled, %d unresolved; billing cost and human interventions unavailable\n", lane.TaskStatistics.Completed, lane.TaskStatistics.Failed, lane.TaskStatistics.Cancelled, lane.TaskStatistics.Unresolved)
			if lane.EvidenceTruncated || len(lane.EvidenceErrors) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "Task evidence: history truncated=%t; unverifiable references=%d (see JSON details)\n", lane.EvidenceTruncated, len(lane.EvidenceErrors))
			}
			for _, check := range lane.CapabilitySummary {
				fmt.Fprintln(cmd.OutOrStdout(), providerReadinessCapabilityText(check))
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Execution slots, experiment attempts and billing usage are separate. This inspection grants no dispatch.")
		}
		return nil
	}
	return cmd
}

// A campaign records a ceiling and the digest of external authorization, not
// its conditions. Never turn an unused conditional slot into permission to retry.
func providerOperatorView(lane providerReadinessLane) providerOperatorReadiness {
	out := providerOperatorReadiness{AttemptAuthorization: "no_campaign_selected", NextActions: []string{}}
	zero := 0
	out.AuthorizedAttempts = &zero
	if attempts, ok := lane.Capacity["experiment_attempts"].(map[string]any); ok {
		if remaining, ok := attempts["remaining"].(int); ok {
			out.AttemptCeilingRemaining = &remaining
			if remaining <= 0 {
				out.AttemptAuthorization = "campaign_exhausted"
			} else {
				out.AuthorizedAttempts = nil
				out.AttemptAuthorization = "conditions_require_review_of_bound_authorization"
			}
		}
	}
	if lane.Credential["state"] == "missing_or_expired" {
		out.NextActions = append(out.NextActions, "Restore and verify the exact account's credential before generation.")
	}
	if lane.Identity.Provider == "zai" && len(lane.Blockers) > 0 {
		out.NextActions = append(out.NextActions, "Resolve held usage with authenticated account/request evidence; then pass admission before the strict served-model preflight.")
	} else if lane.WorkspaceEvidence != "qualified" {
		out.NextActions = append(out.NextActions, "Inspect the latest qualification failure, correct its cause, and qualify this exact profile within a new authorized scope.")
	} else if len(lane.Blockers) > 0 {
		out.NextActions = append(out.NextActions, "Resolve the listed admission blockers and recheck the intended task duration.")
	}
	for _, capability := range lane.CapabilitySummary {
		if capability.Operation == "resume" {
			latestFailed := false
			for _, state := range capability.LatestDatedStates {
				latestFailed = latestFailed || state == "failed"
			}
			if capability.State != "passed" || latestFailed {
				out.NextActions = append(out.NextActions, "Keep resumed work unavailable until its failed or missing lifecycle evidence is resolved; preserve uncertain session ownership.")
			}
		}
	}
	switch out.AttemptAuthorization {
	case "no_campaign_selected":
		out.NextActions = append(out.NextActions, "Select the exact campaign and review its authorization conditions before dispatch.")
	case "campaign_exhausted":
		out.NextActions = append(out.NextActions, "The selected campaign is spent; a new scoped authorization is required for further generation.")
	default:
		out.NextActions = append(out.NextActions, "Review the selected campaign's authorization digest and conditions; an unused slot alone does not authorize a retry.")
	}
	if lane.AssignmentPreview.Eligible {
		out.NextActions = append(out.NextActions, "Assign ordinary workspace work through the shared controls after current dispatch checks and authorization pass.")
	}
	return out
}

func validateProviderPreviewRequirements(requirements []string) error {
	allowed := map[string]bool{}
	for _, name := range []string{"model_identity", "launch", "assignment", "prompt_delivery", "workspace_edit", "test_execution", "permission_denial", "completion_detection", "cleanup", "ordinary_task", "local_cancellation", "local_slot_release", "guarded_fresh_restart", "resume", "recovery", "remote_generation_termination", "billing_settlement", "capacity_accounting"} {
		allowed[name] = true
	}
	if len(requirements) == 0 || len(requirements) > len(allowed) {
		return errors.New("assignment preview requires a nonempty bounded capability list")
	}
	seen := map[string]bool{}
	for _, name := range requirements {
		if !allowed[name] || seen[name] {
			return errors.New("assignment preview contains an unknown or duplicate capability")
		}
		seen[name] = true
	}
	return nil
}

// Selection is an observation, never dispatch authority or automatic fallback.
// Admission and freshness remain mandatory even for a smaller requested subset.
func previewProviderAssignment(lane providerReadinessLane, requirements []string) providerAssignmentPreview {
	out := providerAssignmentPreview{Requirements: append([]string{}, requirements...), Reasons: append([]string{}, lane.Blockers...)}
	if err := validateProviderPreviewRequirements(requirements); err != nil {
		out.Reasons = append(out.Reasons, "invalid_requirements")
	}
	if lane.AdmissionState != "ready_for_dispatch_checks" || !lane.DurationFits {
		out.Reasons = append(out.Reasons, "admission_or_duration_blocked")
	}
	if lane.EvidenceTruncated || len(lane.EvidenceErrors) > 0 {
		out.Reasons = append(out.Reasons, "incomplete_task_history")
	}
	states := map[string]string{}
	requested := map[string]bool{}
	for _, name := range requirements {
		requested[name] = true
	}
	for _, capability := range lane.CapabilitySummary {
		states[capability.Operation] = capability.State
		if capability.Operation == "ordinary_task" || requested[capability.Operation] {
			for _, latest := range capability.LatestDatedStates {
				if latest == "failed" {
					out.Reasons = append(out.Reasons, "latest_failure_requires_review:"+capability.Operation)
				}
			}
		}
	}
	for _, name := range requirements {
		if states[name] != "passed" {
			out.Reasons = append(out.Reasons, "capability_not_proven:"+name)
		}
	}
	out.Eligible = len(out.Reasons) == 0
	return out
}

// Comparisons use only exact verified operations in the inspected history.
// Cancellations and uncertain outcomes are not successful coding assignments.
func summarizeProviderTasks(operations []providerAssignmentStatus) providerTaskStatistics {
	out := providerTaskStatistics{BillingCost: "unavailable", HumanInterventions: "not_recorded"}
	var elapsed float64
	for _, operation := range operations {
		measurable := false
		switch {
		case providerTaskRequirementPassed(operation, providerAssignmentStatus{}, "completion", ""):
			out.Completed++
			measurable = true
		case providerTaskRequirementPassed(operation, providerAssignmentStatus{}, "local-cancellation", ""):
			out.Cancelled++
		case operation.IdentityBindingVerified && operation.OutcomeSHA256 != "" && operation.ControllerFinalized && operation.State == "failed":
			out.Failed++
			measurable = true
		default:
			out.Unresolved++
		}
		if measurable && operation.ElapsedSeconds != nil && *operation.ElapsedSeconds >= 0 {
			elapsed += *operation.ElapsedSeconds
			out.MeasuredDurations++
		}
	}
	if out.MeasuredDurations > 0 {
		mean := elapsed / float64(out.MeasuredDurations)
		out.MeanLocalElapsedSeconds = &mean
	}
	return out
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
		if observation.State == "failed" {
			entry.FailedObservations++
		}
		// Explicit task selection can precede automatic discovery. Compare signed
		// observation times, never slice order, and retain conflicting time ties.
		if observation.ObservedAt != nil && !observation.ObservedAt.IsZero() {
			if entry.LatestObservedAt == nil || observation.ObservedAt.After(*entry.LatestObservedAt) {
				observed := *observation.ObservedAt
				entry.LatestObservedAt = &observed
				entry.LatestDatedStates = []string{observation.State}
			} else if observation.ObservedAt.Equal(*entry.LatestObservedAt) {
				found := false
				for _, value := range entry.LatestDatedStates {
					found = found || value == observation.State
				}
				if !found {
					entry.LatestDatedStates = append(entry.LatestDatedStates, observation.State)
					sort.Strings(entry.LatestDatedStates)
				}
			}
		}
		if rank[observation.State] > rank[entry.State] {
			entry.State = observation.State
		}
	}
	return result
}

func providerReadinessCapabilityText(check providerReadinessCapability) string {
	latest := "unknown"
	if check.LatestObservedAt != nil {
		latest = strings.Join(check.LatestDatedStates, ", ") + " at " + check.LatestObservedAt.UTC().Format(time.RFC3339Nano)
	}
	return fmt.Sprintf("  %s: %s historically (%d retained observations, %d failed); latest dated observation: %s", check.Operation, check.State, len(check.ObservationIndexes), check.FailedObservations, latest)
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
		observations["ordinary_task"] = providerTaskRequirementPassed(op, providerAssignmentStatus{}, "completion", "")
		observations["local_cancellation"] = providerTaskRequirementPassed(op, providerAssignmentStatus{}, "local-cancellation", "")
		observations["guarded_fresh_restart"] = false
		observations["resume"] = false
		for _, parent := range operations {
			if op.ParentOperationSHA256 != "" && parent.OperationIDSHA256 == op.ParentOperationSHA256 {
				observations["resume"] = providerTaskRequirementPassed(op, parent, "session-resume", op.ParentOperationSHA256)
			}
			if op.RestartOfSHA256 != "" && parent.OperationIDSHA256 == op.RestartOfSHA256 {
				observations["guarded_fresh_restart"] = providerTaskRequirementPassed(op, parent, "guarded-restart", op.RestartOfSHA256)
			}
		}
		for _, name := range []string{"launch", "assignment", "prompt_delivery", "workspace_edit", "test_execution", "completion_detection", "cleanup", "ordinary_task", "local_cancellation", "local_slot_release", "guarded_fresh_restart", "resume"} {
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
