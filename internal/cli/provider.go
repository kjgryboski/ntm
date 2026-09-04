package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/agent"
	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/grok"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providercredential"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

const (
	providerDoctorSchema = "ntm.provider-doctor.v2"

	providerPromotionNoGo             = "NO_GO"
	providerPromotionObserveOnly      = "OBSERVE_ONLY"
	providerPromotionReviewGo         = "REVIEW_GO"
	providerPromotionWorkspaceWriteGo = "WORKSPACE_WRITE_GO"
	providerPromotionLifecycleGo      = "LIFECYCLE_GO"

	providerOperationObserve        = "observe"
	providerOperationReview         = "review"
	providerOperationWorkspaceWrite = "workspace-write"
	providerOperationLifecycle      = "lifecycle"
)

type providerCommandOptions struct {
	profile          string
	online           bool
	timeout          time.Duration
	qualificationAge time.Duration
	qualificationDir string
	requireOperation string
}

type providerQualificationOptions struct {
	profile                         string
	live                            bool
	identityOnly                    bool
	grokHeadlessLineage             bool
	exerciseUnknownOutcomeLifecycle bool
	acceptFullWeekReservation       bool
	timeout                         time.Duration
	suiteTimeout                    time.Duration
	qualificationDir                string
}

type providerDoctorStatus string

const (
	providerDoctorPass        providerDoctorStatus = "pass"
	providerDoctorWarn        providerDoctorStatus = "warn"
	providerDoctorFail        providerDoctorStatus = "fail"
	providerDoctorUnavailable providerDoctorStatus = "unavailable"
)

type providerDoctorCheck struct {
	ID          string               `json:"id"`
	Status      providerDoctorStatus `json:"status"`
	Provenance  string               `json:"provenance"`
	Summary     string               `json:"summary"`
	Evidence    string               `json:"evidence,omitempty"`
	Remediation string               `json:"remediation,omitempty"`
}

type providerDoctorIdentity struct {
	SHA256          string                         `json:"sha256"`
	Provider        string                         `json:"provider"`
	Model           string                         `json:"model"`
	Runtime         string                         `json:"runtime"`
	CredentialClass string                         `json:"credential_class"`
	BillingClass    string                         `json:"billing_class"`
	Entitlement     string                         `json:"entitlement"`
	Evidence        provider.IdentityEvidenceGrade `json:"evidence"`
}

type providerDoctorPolicy struct {
	Name                      string `json:"name"`
	SHA256                    string `json:"sha256"`
	Sandbox                   string `json:"sandbox,omitempty"`
	PermissionMode            string `json:"permission_mode,omitempty"`
	ManagedRequirementsSHA256 string `json:"managed_requirements_sha256,omitempty"`
	ManagedRequirementsState  string `json:"managed_requirements_state"`
	RuntimeInspectionState    string `json:"runtime_inspection_state"`
	RuntimeInspectionSHA256   string `json:"runtime_inspection_sha256,omitempty"`
	BypassLockProbeState      string `json:"bypass_lock_probe_state"`
	BypassLockProbeSHA256     string `json:"bypass_lock_probe_sha256,omitempty"`
	BypassLockAuthoritative   bool   `json:"bypass_lock_authoritative"`
}

type providerGrokInspection struct {
	GrokVersion                    string
	PermissionsLoaded              bool
	PermissionSources              []string
	SystemRequirementsLayerPresent bool
	BypassLockWarning              bool
	MCPServerCount                 int
	HookCount                      int
	PluginCount                    int
	MarketplaceCount               int
	ConfigSources                  []providerGrokConfigSource
	UnsafeCompatibilityEnabled     bool
	UnexpectedConfigWarning        bool
	SHA256                         string
}

type providerGrokConfigSource struct {
	Role string
	Path string
	Note string
}

type providerGrokBypassProbe struct {
	Refused             bool
	NetworkIsolated     bool
	CredentialsIsolated bool
	ExitCode            int
	SHA256              string
}

type providerCappedOutput struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (w *providerCappedOutput) Write(value []byte) (int, error) {
	original := len(value)
	remaining := w.limit - w.Buffer.Len()
	if remaining > 0 {
		if remaining < len(value) {
			_, _ = w.Buffer.Write(value[:remaining])
		} else {
			_, _ = w.Buffer.Write(value)
		}
	}
	if original > remaining {
		w.exceeded = true
	}
	return original, nil
}

type providerDoctorRuntime struct {
	Installed       bool   `json:"installed"`
	Version         string `json:"version,omitempty"`
	ExpectedVersion string `json:"expected_version,omitempty"`
	Drift           string `json:"drift"`
}

type providerDoctorQualification struct {
	State                 string          `json:"state"`
	Passed                bool            `json:"passed"`
	TrustedCurrent        bool            `json:"trusted_current"`
	ModelIdentityVerified bool            `json:"model_identity_verified"`
	PolicySHA256          string          `json:"policy_sha256,omitempty"`
	CompletedAt           time.Time       `json:"completed_at,omitempty"`
	AgeSeconds            int64           `json:"age_seconds,omitempty"`
	ReceiptSHA256         string          `json:"receipt_sha256,omitempty"`
	ChecksPassed          int             `json:"checks_passed"`
	ChecksTotal           int             `json:"checks_total"`
	CheckStates           map[string]bool `json:"check_states,omitempty"`
}

type providerDoctorOperationScope struct {
	Operation string `json:"operation"`
	Admitted  bool   `json:"admitted"`
	Evidence  string `json:"evidence"`
}

type providerDoctorPromotion struct {
	Level                     string                         `json:"level"`
	RequiredOperation         string                         `json:"required_operation"`
	RequiredOperationAdmitted bool                           `json:"required_operation_admitted"`
	Scopes                    []providerDoctorOperationScope `json:"scopes"`
}

type providerQualificationRunOutput struct {
	SchemaVersion  string                        `json:"schema_version"`
	Profile        string                        `json:"profile"`
	Transport      string                        `json:"transport"`
	IdentitySHA256 string                        `json:"identity_sha256"`
	RuntimeVersion string                        `json:"runtime_version"`
	PolicySHA256   string                        `json:"policy_sha256"`
	ReceiptPath    string                        `json:"receipt_path"`
	Receipt        providerqualification.Receipt `json:"receipt"`
}

type providerDoctorCapacity struct {
	Scope               provider.CapacityControlScope `json:"scope"`
	StoreSHA256         string                        `json:"store_sha256,omitempty"`
	FallbackReason      string                        `json:"fallback_reason,omitempty"`
	CircuitState        string                        `json:"circuit_state"`
	Running             int                           `json:"running"`
	Tokens              float64                       `json:"tokens"`
	ConsecutiveFailures int                           `json:"consecutive_failures"`
	NextRetry           *time.Time                    `json:"next_retry,omitempty"`
	CircuitOpenUntil    *time.Time                    `json:"circuit_open_until,omitempty"`
	TerminalReason      provider.ErrorClass           `json:"terminal_reason,omitempty"`
	HalfOpenInFlight    bool                          `json:"half_open_in_flight"`
	// Subscription is populated only for the structured Z.ai Coding Plan
	// Codex lane. The top-level fields remain that lane's exact-identity
	// circuit snapshot; this nested view describes the shared plan budget.
	Subscription *providerDoctorSubscriptionCapacity `json:"subscription,omitempty"`
}

// providerDoctorSubscriptionCapacity is intentionally limited to non-secret,
// controller-local estimates. It never serializes endpoint, account alias,
// credential material, store paths, or raw provider output.
type providerDoctorSubscriptionCapacity struct {
	ScopeSHA256          string     `json:"scope_sha256"`
	PlanRunning          int        `json:"plan_running"`
	PlanMaxConcurrent    int        `json:"plan_max_concurrent"`
	AdmissionReservation float64    `json:"admission_reservation"`
	FiveHourCreditsUsed  float64    `json:"five_hour_credits_used"`
	FiveHourCreditsLimit float64    `json:"five_hour_credits_limit"`
	FiveHourResetsAt     *time.Time `json:"five_hour_resets_at,omitempty"`
	WeeklyCreditsUsed    float64    `json:"weekly_credits_used"`
	WeeklyCreditsLimit   float64    `json:"weekly_credits_limit"`
	WeeklyResetsAt       *time.Time `json:"weekly_resets_at,omitempty"`
	UnknownUsageReserved bool       `json:"unknown_usage_reserved"`
	ConservativeUsage    bool       `json:"conservative_usage_recorded"`
	LegacyRecovery       bool       `json:"legacy_owner_authorized_recovery"`
	LimitEvidence        string     `json:"limit_evidence,omitempty"`
	ResetEvidence        string     `json:"reset_evidence,omitempty"`
}

type providerDoctorReport struct {
	SchemaVersion string                         `json:"schema_version"`
	GeneratedAt   time.Time                      `json:"generated_at"`
	DurationMS    int64                          `json:"duration_ms"`
	Mode          string                         `json:"mode"`
	Profile       string                         `json:"profile"`
	Transport     string                         `json:"transport"`
	Promotion     providerDoctorPromotion        `json:"promotion"`
	Identity      providerDoctorIdentity         `json:"identity"`
	Policy        providerDoctorPolicy           `json:"policy"`
	Runtime       providerDoctorRuntime          `json:"runtime"`
	Qualification providerDoctorQualification    `json:"qualification"`
	Capacity      providerDoctorCapacity         `json:"capacity"`
	Capabilities  provider.OperationCapabilities `json:"capabilities"`
	Checks        []providerDoctorCheck          `json:"checks"`
}

type providerDoctorLiveEvidence struct {
	ModelVerified         bool
	AuthVerified          bool
	RuntimeContractPassed bool
	SHA256                string
}

type providerDoctorAdmission interface {
	Acquire(provider.Identity) ratelimit.Decision
	Release(provider.Identity, ratelimit.Decision)
	RecordSuccess(provider.Identity)
	CapacityStatus() ratelimit.CapacityStatus
}

type providerDoctorDependencies struct {
	now       func() time.Time
	lookPath  func(string) (string, error)
	version   func(context.Context, string) (string, error)
	lookupEnv func(string) (string, bool)
	readFile  func(string) ([]byte, error)
	stat      func(string) (os.FileInfo, error)
	rootOwned func(os.FileInfo) bool
	// trustExecutable returns a canonical system-authoritative executable path.
	// The file and every parent directory must be root-owned and non-writable
	// by unprivileged users so the path cannot be swapped between attestation
	// and dispatch.
	trustExecutable func(string) (string, error)
	// readRequirements securely binds content and metadata to the same open
	// file descriptor. Production sets it; unit tests may inject the older
	// readFile/stat pair to exercise report assembly without privileged files.
	readRequirements               func(string) ([]byte, os.FileInfo, error)
	inspectGrok                    func(context.Context, string, string, string) (providerGrokInspection, error)
	probeGrokBypassLock            func(context.Context, string) (providerGrokBypassProbe, error)
	onlineProbe                    func(context.Context, config.ProviderProfileConfig, provider.Identity) (providerDoctorLiveEvidence, error)
	qualificationStore             func(string, string) (providerqualification.Receipt, string, error)
	qualificationStoreForTransport func(string, string, string) (providerqualification.Receipt, string, error)
	capacityStatus                 func() ratelimit.CapacityStatus
	capacitySnapshot               func(provider.Identity) ratelimit.AdmissionSnapshot
	// codexSubscription* are intentionally separate from the generic doctor
	// admission: Z.ai Codex billing is governed by the same singleton paired
	// identity/subscription controller used by `provider codex run`.
	codexSubscriptionStatus   func() ratelimit.CapacityStatus
	codexSubscriptionSnapshot func(provider.Identity) ratelimit.SubscriptionCapacitySnapshot
	credentialStatus          func(context.Context, string) (providercredential.Status, error)
	attestationPreflight      func(context.Context) (providerattestation.SignatureMetadata, error)
	grokAttestationPreflight  func(context.Context, config.ProviderProfileConfig) (providerattestation.SignatureMetadata, error)
	codexCredentialStatus     func(context.Context, config.ProviderProfileConfig) (providercredential.Status, error)
	codexAttestationPreflight func(context.Context, config.ProviderProfileConfig) (providerattestation.SignatureMetadata, error)
	admission                 providerDoctorAdmission
}

type providerQualificationDependencies struct {
	loadConfig func() *config.Config
	lookPath   func(string) (string, error)
	version    func(context.Context, string) (string, error)
	lookupEnv  func(string) (string, bool)
	run        func(context.Context, providerqualification.Options) providerqualification.Receipt
	store      func(string, providerqualification.Receipt) (string, error)
	sign       func(context.Context, *providerqualification.Receipt) error
	preflight  func(context.Context) error
	admission  providerDoctorAdmission
}

func defaultProviderDoctorDependencies() providerDoctorDependencies {
	admission := ratelimit.DefaultAdmissionController()
	codexAdmission := defaultProviderCodexSubscriptionAdmission()
	return providerDoctorDependencies{
		now:                            time.Now,
		lookPath:                       exec.LookPath,
		version:                        providerRuntimeVersion,
		lookupEnv:                      os.LookupEnv,
		readFile:                       os.ReadFile,
		stat:                           os.Stat,
		rootOwned:                      providerRequirementsRootOwned,
		trustExecutable:                providerSystemAuthoritativeExecutable,
		readRequirements:               providerRequirementsReadForDoctor,
		inspectGrok:                    providerRuntimeInspectGrok,
		probeGrokBypassLock:            providerRuntimeProbeGrokBypassLock,
		onlineProbe:                    runProviderDoctorOnlineProbe,
		qualificationStore:             providerqualification.LoadLatest,
		qualificationStoreForTransport: providerqualification.LoadLatestForTransport,
		capacityStatus: func() ratelimit.CapacityStatus {
			return admission.CapacityStatus()
		},
		capacitySnapshot: func(identity provider.Identity) ratelimit.AdmissionSnapshot {
			return admission.Snapshot(identity)
		},
		codexSubscriptionStatus: func() ratelimit.CapacityStatus {
			return codexAdmission.CapacityStatus()
		},
		codexSubscriptionSnapshot: func(identity provider.Identity) ratelimit.SubscriptionCapacitySnapshot {
			return codexAdmission.Snapshot(identity)
		},
		credentialStatus: providerCredentialDeps.store.Status,
		attestationPreflight: func(ctx context.Context) (providerattestation.SignatureMetadata, error) {
			return preflightProviderReceiptSignerMetadata(ctx, signProviderReceiptPayload)
		},
		grokAttestationPreflight: func(ctx context.Context, profile config.ProviderProfileConfig) (providerattestation.SignatureMetadata, error) {
			sign, err := providerGrokPinnedSigner(profile)
			if err != nil {
				return providerattestation.SignatureMetadata{}, err
			}
			return preflightProviderGrokReceiptSignerMetadata(ctx, sign)
		},
		codexCredentialStatus: func(ctx context.Context, profile config.ProviderProfileConfig) (providercredential.Status, error) {
			return zai.CodexCredentialStatus(ctx, profile.CredentialBridgeCommand, profile.CredentialBridgeCommandSHA256, profile.BrokerCredentialID)
		},
		codexAttestationPreflight: func(ctx context.Context, profile config.ProviderProfileConfig) (providerattestation.SignatureMetadata, error) {
			sign, err := providerCodexPinnedSigner(profile)
			if err != nil {
				return providerattestation.SignatureMetadata{}, err
			}
			return preflightProviderReceiptSignerMetadata(ctx, sign)
		},
		admission: admission,
	}
}

var providerDoctorDeps = defaultProviderDoctorDependencies()

var providerQualificationDeps = providerQualificationDependencies{
	loadConfig: loadSelectedConfigOrDefault,
	lookPath:   exec.LookPath,
	version:    providerRuntimeVersion,
	lookupEnv:  os.LookupEnv,
	run:        providerqualification.Run,
	store:      providerqualification.Store,
	sign:       signProviderQualificationReceipt,
	preflight: func(ctx context.Context) error {
		return preflightProviderReceiptSigner(ctx, signProviderReceiptPayload)
	},
	admission: ratelimit.DefaultAdmissionController(),
}

func newProviderCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "provider",
		Short: "Inspect and qualify exact AI provider lanes",
	}
	cmd.AddCommand(newProviderDoctorCmd(), newProviderBaselineCmd(), newProviderQualifyCmd(), newProviderSessionCmd(), newProviderNativeRunCmd(), newProviderCodexCmd(), newProviderVerifyCmd(), newProviderCredentialCmd(), newProviderAttestationCmd(), newProviderCapabilitiesCmd(), newProviderPolicyCmd(), newProviderTelemetryCmd(), newProviderBrokerCmd(), newProviderRoutingCmd())
	return cmd
}

func newProviderQualifyCmd() *cobra.Command {
	opts := providerQualificationOptions{timeout: 90 * time.Second, suiteTimeout: 12 * time.Minute}
	cmd := &cobra.Command{
		Use:   "qualify",
		Short: "Run a live qualification for one exact provider lane",
		Long: `Run the applicable live qualification checks against one exact provider profile.

This command is intentionally live-only. Full coding suites use and remove a
disposable repository after recording controller-owned cleanup evidence. The
default Grok ACP producer is deliberately observe-only. A profile selecting the
exact grok-workspace-write-ci policy runs one bounded ACP turn in a disposable
linked worktree through NTM's typed broker. It proves edit, isolated tests,
protected-path denial, push-surface denial, and cleanup without claiming crash,
cancellation, or resume. The explicit
--grok-headless-lineage mode bootstraps a strict ACP session inside a disposable
linked worktree, then proves native fork/resume lineage without authorizing
review, writes, cancellation, or general lifecycle dispatch.
Coding Plan and native API credentials remain separate; native tool qualification
requires the controller-owned tools policy and OS-protected credential broker.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProviderQualification(cmd, opts, providerQualificationDeps)
		},
	}
	cmd.Flags().StringVar(&opts.profile, "profile", "", "Exact configured provider profile (required)")
	cmd.Flags().BoolVar(&opts.live, "live", false, "Explicitly authorize real provider calls in a disposable repository")
	cmd.Flags().BoolVar(&opts.identityOnly, "identity-only", false, "Run exactly one signed read-only Codex identity/model preflight and stop")
	cmd.Flags().BoolVar(&opts.grokHeadlessLineage, "grok-headless-lineage", false, "Run the isolated ACP bootstrap plus headless fork/resume lineage qualification")
	cmd.Flags().BoolVar(&opts.exerciseUnknownOutcomeLifecycle, "exercise-unknown-outcome-lifecycle", false, "Exercise Codex cancellation and resume despite unavailable provider-final usage acknowledgement")
	cmd.Flags().BoolVar(&opts.acceptFullWeekReservation, "accept-full-week-reservation", false, "Accept that an interrupted Codex turn can reserve the remaining local weekly plan budget")
	cmd.Flags().DurationVar(&opts.timeout, "timeout", opts.timeout, "Timeout for each provider scenario")
	cmd.Flags().DurationVar(&opts.suiteTimeout, "suite-timeout", opts.suiteTimeout, "Overall qualification timeout")
	cmd.Flags().StringVar(&opts.qualificationDir, "qualification-store", "", "Override qualification receipt directory")
	return cmd
}

func runProviderQualification(cmd *cobra.Command, opts providerQualificationOptions, deps providerQualificationDependencies) error {
	if strings.TrimSpace(opts.profile) == "" {
		return errors.New("provider qualification requires an exact --profile")
	}
	if !opts.live {
		return errors.New("provider qualification makes real provider calls; pass --live to authorize it")
	}
	if opts.timeout <= 0 || opts.suiteTimeout <= 0 {
		return errors.New("provider qualification timeouts must be positive")
	}
	if opts.exerciseUnknownOutcomeLifecycle != opts.acceptFullWeekReservation {
		return errors.New("Codex lifecycle qualification requires both --exercise-unknown-outcome-lifecycle and --accept-full-week-reservation")
	}
	if deps.loadConfig == nil {
		return errors.New("provider qualification requires a configuration loader")
	}

	cfg := deps.loadConfig()
	if cfg == nil {
		return errors.New("provider qualification requires loaded configuration")
	}
	profile, err := cfg.ProviderProfile(opts.profile)
	if err != nil {
		return err
	}
	identity, err := profile.Identity()
	if err != nil {
		return err
	}
	transport, err := providerTransportForIdentity(identity)
	if err != nil {
		return err
	}
	if transport != "zai_codex_runtime" && (opts.exerciseUnknownOutcomeLifecycle || opts.acceptFullWeekReservation) {
		return errors.New("the Codex lifecycle-risk flags apply only to zai_codex_runtime profiles")
	}
	if opts.identityOnly && transport != "zai_codex_runtime" {
		return errors.New("the identity-only preflight applies only to zai_codex_runtime profiles")
	}
	if opts.identityOnly && (opts.exerciseUnknownOutcomeLifecycle || opts.acceptFullWeekReservation) {
		return errors.New("the identity-only preflight cannot exercise lifecycle scenarios")
	}
	if opts.grokHeadlessLineage && transport != "xai_acp" {
		return errors.New("the Grok headless lineage qualification applies only to an exact native Grok profile")
	}
	if opts.grokHeadlessLineage && (opts.identityOnly || opts.exerciseUnknownOutcomeLifecycle || opts.acceptFullWeekReservation) {
		return errors.New("the Grok headless lineage qualification cannot be combined with Codex qualification modes")
	}
	if transport == "xai_acp" {
		return runProviderGrokQualification(cmd, opts, profile, identity, providerGrokQualificationDeps)
	}
	if transport == "zai_native_api" {
		return runProviderNativeQualification(cmd, opts, profile, identity, providerNativeQualificationDeps)
	}
	if transport == "zai_codex_runtime" {
		return runProviderCodexQualification(cmd, opts, profile, identity, providerCodexQualificationDeps)
	}
	if transport != "zai_claude_runtime" {
		return errors.New("the live qualification suite accepts only exact Z.ai, native API, or Grok ACP profiles")
	}
	if deps.lookPath == nil || deps.version == nil || deps.lookupEnv == nil || deps.run == nil || deps.store == nil || deps.sign == nil || deps.preflight == nil || deps.admission == nil {
		return errors.New("provider qualification dependencies are incomplete")
	}
	if err := deps.preflight(providerCommandContext(cmd)); err != nil {
		return fmt.Errorf("provider qualification requires an initialized receipt signing key before dispatch: %w", err)
	}
	credential, credentialPresent := deps.lookupEnv("ZAI_API_KEY")
	credentialPresent = credentialPresent && strings.TrimSpace(credential) != ""
	if !credentialPresent {
		return errors.New("no deliberately scoped Z.ai Coding Plan credential is present")
	}
	binary, err := deps.lookPath(profile.Command)
	if err != nil {
		return fmt.Errorf("locate configured Z.ai runtime: %w", err)
	}
	commandCtx := providerCommandContext(cmd)
	versionCtx, versionCancel := context.WithTimeout(commandCtx, 5*time.Second)
	runtimeVersion, err := deps.version(versionCtx, binary)
	versionCancel()
	if err != nil {
		return fmt.Errorf("read configured Z.ai runtime version: %w", err)
	}
	if strings.TrimSpace(profile.RuntimeVersion) == "" {
		return errors.New("provider qualification requires a reviewed runtime_version pin")
	}
	if !versionMatches(runtimeVersion, profile.RuntimeVersion) {
		return fmt.Errorf("provider runtime drift detected: installed version does not match pin %q", profile.RuntimeVersion)
	}
	policySHA := providerqualification.QualificationPolicySHA256()
	if policySHA == "" {
		return errors.New("compiled Z.ai qualification policy could not be hashed")
	}
	if deps.admission.CapacityStatus().Scope != provider.CapacityControlScopeLocalShared {
		return errors.New("provider qualification requires the cross-process local shared capacity store")
	}
	decision := deps.admission.Acquire(identity)
	if !decision.Allowed || !decision.NoFailover {
		if decision.Allowed {
			deps.admission.Release(identity, decision)
		}
		return errors.New("provider qualification admission was denied for the exact Z.ai identity; failover is prohibited")
	}
	defer deps.admission.Release(identity, decision)

	suiteCtx, suiteCancel := context.WithTimeout(commandCtx, opts.suiteTimeout)
	receipt := deps.run(suiteCtx, providerqualification.Options{
		Live: true, Identity: identity, Binary: binary, Timeout: opts.timeout,
		RuntimeVersion: runtimeVersion, PolicySHA256: policySHA,
	})
	suiteCancel()
	if err := receipt.Validate(); err != nil {
		return fmt.Errorf("live qualification produced an invalid receipt: %w", err)
	}
	if err := deps.sign(commandCtx, &receipt); err != nil {
		return fmt.Errorf("sign live qualification receipt: %w", err)
	}
	path, err := deps.store(opts.qualificationDir, receipt)
	if err != nil {
		return fmt.Errorf("store create-only qualification receipt: %w", err)
	}
	output := providerQualificationRunOutput{
		SchemaVersion: providerqualification.SchemaVersion,
		Profile:       opts.profile, Transport: transport, IdentitySHA256: identity.Hash(),
		RuntimeVersion: runtimeVersion, PolicySHA256: policySHA, ReceiptPath: path, Receipt: receipt,
	}
	if IsJSONOutput() {
		if err := encodeIndentedJSON(cmd.OutOrStdout(), output); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Z.ai qualification: %s (%d/%d checks)\n", qualificationResult(receipt), countPassedQualificationChecks(receipt), len(receipt.Checks))
		fmt.Fprintf(cmd.OutOrStdout(), "Receipt: %s\n", path)
		for _, check := range receipt.Checks {
			fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\n", qualificationCheckStatus(check.Passed), check.Name, check.Detail)
		}
	}
	if !receipt.Passed {
		if IsJSONOutput() {
			return errJSONFailure
		}
		return &providerQualificationExitError{}
	}
	deps.admission.RecordSuccess(identity)
	return nil
}

type providerQualificationExitError struct{}

func (*providerQualificationExitError) Error() string {
	return "provider qualification did not pass every mandatory live check"
}
func (*providerQualificationExitError) ExitCode() int { return 1 }

func qualificationResult(receipt providerqualification.Receipt) string {
	if receipt.Passed {
		return "PASS"
	}
	return "NO-GO"
}

func qualificationCheckStatus(passed bool) string {
	if passed {
		return "PASS"
	}
	return "FAIL"
}

func countPassedQualificationChecks(receipt providerqualification.Receipt) int {
	count := 0
	for _, check := range receipt.Checks {
		if check.Passed {
			count++
		}
	}
	return count
}

type providerPolicyOptions struct {
	name           string
	install        bool
	confirm        bool
	replaceManaged bool
}

func newProviderPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "Render or install managed provider policy"}
	opts := providerPolicyOptions{name: agent.GrokWorkspaceWritePolicyName}
	requirements := &cobra.Command{
		Use:   "requirements",
		Short: "Render the root-owned Grok requirements policy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.replaceManaged && !opts.install {
				return errors.New("--replace-managed requires --install")
			}
			document, ok := agent.GrokSystemRequirementsForPolicy(opts.name)
			if !ok {
				return fmt.Errorf("unknown Grok automation policy %q", opts.name)
			}
			state := "rendered"
			if opts.install {
				if !opts.confirm {
					return errors.New("managed requirements installation requires --confirm")
				}
				if err := installProviderRequirements(providerRequirementsPath(), document.Contents, opts.replaceManaged); err != nil {
					return err
				}
				state = "installed_verified"
			}
			if IsJSONOutput() {
				return encodeIndentedJSON(cmd.OutOrStdout(), struct {
					Policy   string `json:"policy"`
					SHA256   string `json:"sha256"`
					State    string `json:"state"`
					Contents string `json:"contents,omitempty"`
				}{Policy: document.PolicyName, SHA256: document.SHA256, State: state, Contents: document.Contents})
			}
			if opts.install {
				fmt.Fprintf(cmd.OutOrStdout(), "Installed %s at the system Grok requirements path (sha256 %s).\n", document.PolicyName, document.SHA256)
				return nil
			}
			_, err := io.WriteString(cmd.OutOrStdout(), document.Contents)
			return err
		},
	}
	requirements.Flags().StringVar(&opts.name, "policy", opts.name, "Built-in Grok automation policy")
	requirements.Flags().BoolVar(&opts.install, "install", false, "Create the system Grok requirements file")
	requirements.Flags().BoolVar(&opts.confirm, "confirm", false, "Confirm system-level policy installation")
	requirements.Flags().BoolVar(&opts.replaceManaged, "replace-managed", false, "Atomically migrate an existing root-owned NTM-managed policy after preserving a digest-named backup")
	cmd.AddCommand(requirements)
	return cmd
}

func installProviderRequirements(path, contents string, replaceManaged bool) error {
	if !providerRequirementsCanInstall() {
		return errors.New("system Grok requirements installation requires an administrator/root process")
	}
	if filepath.Clean(path) != filepath.Clean(providerRequirementsPath()) {
		return errors.New("managed requirements installation is restricted to the system Grok requirements path")
	}
	if existingFile, err := providerRequirementsOpenExisting(path); err == nil {
		existing, readErr := io.ReadAll(io.LimitReader(existingFile, 1<<20))
		info, statErr := existingFile.Stat()
		closeErr := existingFile.Close()
		if readErr != nil || statErr != nil || closeErr != nil {
			return errors.New("inspect existing Grok requirements securely")
		}
		if sha256TextCLI(existing) == sha256StringCLI(contents) {
			if providerRequirementsRootOwned(info) {
				return nil
			}
			return errors.New("existing Grok requirements match but ownership is not system-authoritative")
		}
		if !replaceManaged {
			return errors.New("existing Grok requirements differ; refusing to overwrite without --replace-managed and an owner-reviewed migration")
		}
		if !bytes.HasPrefix(existing, []byte("# NTM-managed ")) {
			return errors.New("existing Grok requirements are not marked as NTM-managed; refusing migration")
		}
		return migrateProviderRequirements(path, existing, contents)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect existing Grok requirements: %w", err)
	}
	if err := providerRequirementsPrepareParent(path); err != nil {
		return err
	}
	if err := writeProviderRequirementsExclusive(path, []byte(contents)); err != nil {
		return fmt.Errorf("create Grok requirements: %w", err)
	}
	return verifyProviderRequirements(path, contents, "created")
}

func migrateProviderRequirements(path string, existing []byte, contents string) error {
	existingSHA := sha256TextCLI(existing)
	nextSHA := sha256StringCLI(contents)
	backupPath := path + ".bak-" + existingSHA[:16]
	if err := ensureProviderRequirementsCopy(backupPath, existing); err != nil {
		return fmt.Errorf("preserve previous Grok requirements: %w", err)
	}
	nextPath := path + ".next-" + nextSHA[:16]
	if err := ensureProviderRequirementsCopy(nextPath, []byte(contents)); err != nil {
		return fmt.Errorf("stage replacement Grok requirements: %w", err)
	}
	if err := os.Rename(nextPath, path); err != nil {
		return fmt.Errorf("atomically replace Grok requirements: %w", err)
	}
	if err := syncProviderRequirementsDirectory(path); err != nil {
		return err
	}
	return verifyProviderRequirements(path, contents, "migrated")
}

func ensureProviderRequirementsCopy(path string, contents []byte) error {
	if existingFile, err := providerRequirementsOpenExisting(path); err == nil {
		existing, readErr := io.ReadAll(io.LimitReader(existingFile, 1<<20))
		closeErr := existingFile.Close()
		if readErr != nil || closeErr != nil || sha256TextCLI(existing) != sha256TextCLI(contents) {
			return errors.New("existing migration artifact does not match the required digest")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeProviderRequirementsExclusive(path, contents)
}

func writeProviderRequirementsExclusive(path string, contents []byte) error {
	f, err := providerRequirementsOpenCreate(path)
	if err != nil {
		return err
	}
	if _, err := f.Write(contents); err != nil {
		_ = f.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	return nil
}

func verifyProviderRequirements(path, contents, action string) error {
	installedFile, err := providerRequirementsOpenExisting(path)
	if err != nil {
		return fmt.Errorf("%s Grok requirements but secure reopen failed", action)
	}
	installed, readErr := io.ReadAll(io.LimitReader(installedFile, 1<<20))
	info, statErr := installedFile.Stat()
	closeErr := installedFile.Close()
	if readErr != nil || statErr != nil || closeErr != nil || !providerRequirementsRootOwned(info) {
		return fmt.Errorf("%s Grok requirements but could not verify system-authoritative ownership", action)
	}
	if sha256TextCLI(installed) != sha256StringCLI(contents) {
		return fmt.Errorf("%s Grok requirements but digest verification failed", action)
	}
	return nil
}

func syncProviderRequirementsDirectory(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open Grok requirements directory for sync: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync Grok requirements directory: %w", err)
	}
	return nil
}

func newProviderDoctorCmd() *cobra.Command {
	opts := providerCommandOptions{timeout: 60 * time.Second, qualificationAge: 24 * time.Hour, requireOperation: providerOperationLifecycle}
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Report provider identity, policy, entitlement, and evidence",
		Long: `Diagnose one exact configured provider profile.

The command is read-only and offline by default. --online performs one bounded,
no-tool identity/model probe. It does not turn a probe or synthetic conformance
result into a live coding qualification receipt.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProviderDoctor(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.profile, "profile", "", "Exact configured provider profile (required)")
	cmd.Flags().BoolVar(&opts.online, "online", false, "Perform a bounded live no-tool identity/model probe")
	cmd.Flags().DurationVar(&opts.timeout, "timeout", opts.timeout, "Online probe timeout")
	cmd.Flags().DurationVar(&opts.qualificationAge, "max-qualification-age", opts.qualificationAge, "Maximum age of a live qualification receipt")
	cmd.Flags().StringVar(&opts.qualificationDir, "qualification-store", "", "Override qualification receipt directory")
	cmd.Flags().StringVar(&opts.requireOperation, "require-operation", opts.requireOperation, "Operation that must be admitted: observe|review|workspace-write|lifecycle")
	return cmd
}

func newProviderCapabilitiesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "capabilities",
		Short: "Print the static provider transport capability matrix",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			matrix := provider.CapabilityMatrix()
			if IsJSONOutput() {
				return encodeIndentedJSON(cmd.OutOrStdout(), matrix)
			}
			keys := make([]string, 0, len(matrix))
			for key := range matrix {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			fmt.Fprintln(cmd.OutOrStdout(), "TRANSPORT\tCOMPLETION\tCOMPLETION_SCOPE\tCANCEL\tCANCEL_SCOPE\tRESUME\tCLEANUP\tCLEANUP_SCOPE\tCAPACITY\tLAUNCH_CAPACITY\tREQUEST_CAPACITY\tLIVE_ERROR_FEEDBACK")
			for _, key := range keys {
				capability := matrix[key]
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", key, capability.Completion, capability.CompletionAuthorityScope, capability.Cancellation, capability.CancellationAuthorityScope, capability.Resume, capability.Cleanup, capability.CleanupAuthorityScope, capability.CapacityControlScope, capability.LaunchCapacityControl, capability.RequestCapacityControl, capability.LiveErrorFeedback)
			}
			return nil
		},
	}
}

type providerBaselineCheck struct {
	Operation      string `json:"operation"`
	State          string `json:"state"`
	EvidenceSHA256 string `json:"evidence_sha256,omitempty"`
}

type providerBaselineLane struct {
	Provider           string                          `json:"provider"`
	Profile            string                          `json:"profile,omitempty"`
	Identity           providerDoctorIdentity          `json:"identity"`
	Transport          string                          `json:"transport,omitempty"`
	QualificationState string                          `json:"qualification_state"`
	CapacityBlock      string                          `json:"capacity_block,omitempty"`
	CancellationScope  provider.EvidenceAuthorityScope `json:"cancellation_scope,omitempty"`
	CleanupScope       provider.EvidenceAuthorityScope `json:"cleanup_scope,omitempty"`
	Checks             []providerBaselineCheck         `json:"checks"`
}

// baseline is an offline evidence inventory, not a new qualification engine.
// Ordinary pane usability never substitutes for the common signed scenarios.
func newProviderBaselineCmd() *cobra.Command {
	var profiles []string
	cmd := &cobra.Command{Use: "baseline", Short: "Compare common provider evidence without making provider calls", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			lanes := []providerBaselineLane{}
			seen := map[string]bool{}
			loaded := loadSelectedConfigOrDefault()
			for _, profile := range profiles {
				report, err := buildProviderDoctorReport(providerCommandContext(cmd), loaded, providerCommandOptions{
					profile: profile, timeout: 60 * time.Second, qualificationAge: 24 * time.Hour, requireOperation: providerOperationWorkspaceWrite,
				}, providerDoctorDeps)
				if err != nil {
					return err
				}
				lanes = append(lanes, providerBaselineForReport(report))
				seen[report.Identity.Provider] = true
			}
			for _, name := range []string{"openai", "anthropic", "xai", "zai"} {
				if !seen[name] {
					lanes = append(lanes, providerBaselineForReport(providerDoctorReport{Identity: providerDoctorIdentity{Provider: name}}))
				}
			}
			if IsJSONOutput() {
				return encodeIndentedJSON(cmd.OutOrStdout(), struct {
					Schema string                 `json:"schema_version"`
					Note   string                 `json:"note"`
					Lanes  []providerBaselineLane `json:"lanes"`
				}{"ntm.provider-baseline.v1", "Offline inventory only. Unproven means a signed check is negative or lacks evidence; it does not assert whether the scenario was attempted. Untested means no trusted current evidence is available. No readiness is granted.", lanes})
			}
			fmt.Fprintln(cmd.OutOrStdout(), "PROVIDER\tPROFILE\tOPERATION\tEVIDENCE_STATE")
			for _, lane := range lanes {
				for _, check := range lane.Checks {
					fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\n", lane.Provider, lane.Profile, check.Operation, check.State)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&profiles, "profile", nil, "Exact profiles to inspect offline; may be repeated")
	return cmd
}

func providerBaselineForReport(report providerDoctorReport) providerBaselineLane {
	lane := providerBaselineLane{Provider: report.Identity.Provider, Profile: report.Profile, Identity: report.Identity,
		Transport: report.Transport, QualificationState: report.Qualification.State,
		CancellationScope: report.Capabilities.CancellationAuthorityScope, CleanupScope: report.Capabilities.CleanupAuthorityScope}
	if report.Profile == "" {
		lane.QualificationState = "identity_not_bound"
	} else {
		lane.CapacityBlock = providerDoctorCapacityAdmissionBlock(report.Capacity)
	}
	current := report.Qualification.TrustedCurrent && report.Runtime.Drift == "none"
	for _, scenario := range []struct {
		name        string
		checks      []string
		unsupported bool
	}{
		{"launch", nil, false}, {"assignment", nil, false}, {"prompt_delivery", nil, false},
		{"model_identity", []string{providerqualification.CheckIdentity}, false},
		{"workspace_edit", []string{providerqualification.CheckWorkspaceEdit}, false},
		{"test_execution", []string{providerqualification.CheckTestCommand}, false},
		{"permission_denial", []string{providerqualification.CheckSecretDenied, providerqualification.CheckPushDenied}, false},
		{"completion_detection", nil, report.Capabilities.Completion == provider.EvidenceUnavailable},
		{"cancellation", []string{providerqualification.CheckCancellation}, report.Capabilities.Cancellation == provider.EvidenceUnavailable},
		{"recovery", []string{providerqualification.CheckCrashRecovery}, false},
		{"resume", []string{providerqualification.CheckResume}, report.Capabilities.Resume == provider.EvidenceUnavailable},
		{"cleanup", []string{providerqualification.CheckProcessCleanup}, report.Capabilities.Cleanup == provider.EvidenceUnavailable},
		{"capacity_accounting", []string{"capacity_accounting"}, false},
	} {
		check := providerBaselineCheck{Operation: scenario.name, State: "untested"}
		if scenario.unsupported {
			check.State = "unsupported"
		} else if current && len(scenario.checks) > 0 {
			present := true
			for _, name := range scenario.checks {
				if _, ok := report.Qualification.CheckStates[name]; !ok {
					present = false
				}
			}
			if present {
				check.State = "unproven"
				check.EvidenceSHA256 = report.Qualification.ReceiptSHA256
				if qualificationChecksPassed(report.Qualification, scenario.checks...) {
					check.State = "proven"
				}
				if scenario.name == "model_identity" && !report.Qualification.ModelIdentityVerified {
					check.State = "unproven"
				}
			}
		}
		lane.Checks = append(lane.Checks, check)
	}
	return lane
}

func runProviderDoctor(cmd *cobra.Command, opts providerCommandOptions) error {
	started := providerDoctorDeps.now().UTC()
	if strings.TrimSpace(opts.profile) == "" {
		return errors.New("provider doctor requires an exact --profile")
	}
	if opts.timeout <= 0 || opts.qualificationAge <= 0 {
		return errors.New("provider doctor timeout and maximum qualification age must be positive")
	}
	if !validProviderOperation(opts.requireOperation) {
		return fmt.Errorf("provider doctor --require-operation must be one of: %s, %s, %s, %s", providerOperationObserve, providerOperationReview, providerOperationWorkspaceWrite, providerOperationLifecycle)
	}
	loaded := loadSelectedConfigOrDefault()
	report, err := buildProviderDoctorReport(providerCommandContext(cmd), loaded, opts, providerDoctorDeps)
	if err != nil {
		return err
	}
	report.GeneratedAt = started
	report.DurationMS = providerDoctorDeps.now().UTC().Sub(started).Milliseconds()
	if IsJSONOutput() {
		if err := encodeIndentedJSON(cmd.OutOrStdout(), report); err != nil {
			return err
		}
	} else {
		printProviderDoctorHuman(cmd.OutOrStdout(), report)
	}
	if !report.Promotion.RequiredOperationAdmitted {
		if IsJSONOutput() {
			return errJSONFailure
		}
		return &providerDoctorExitError{report: report}
	}
	return nil
}

type providerDoctorExitError struct{ report providerDoctorReport }

func (e *providerDoctorExitError) Error() string {
	return fmt.Sprintf("provider profile promotion is %s; required operation %q is not admitted", e.report.Promotion.Level, e.report.Promotion.RequiredOperation)
}
func (e *providerDoctorExitError) ExitCode() int { return 1 }

func buildProviderDoctorReport(ctx context.Context, cfg *config.Config, opts providerCommandOptions, deps providerDoctorDependencies) (providerDoctorReport, error) {
	report := providerDoctorReport{
		SchemaVersion: providerDoctorSchema,
		Mode:          "offline",
		Profile:       opts.profile,
		Promotion: providerDoctorPromotion{
			Level:             providerPromotionNoGo,
			RequiredOperation: normalizeProviderOperation(opts.requireOperation),
			Scopes:            []providerDoctorOperationScope{},
		},
		Checks: []providerDoctorCheck{},
	}
	if opts.online {
		report.Mode = "online"
	}
	if cfg == nil {
		return report, errors.New("provider doctor requires loaded configuration")
	}
	profile, err := cfg.ProviderProfile(opts.profile)
	if err != nil {
		return report, err
	}
	identity, err := profile.Identity()
	if err != nil {
		return report, err
	}
	report.Identity = providerDoctorIdentity{
		SHA256: identity.Hash(), Provider: identity.Provider(), Model: identity.Model(), Runtime: identity.Runtime(),
		CredentialClass: identity.CredentialClass(), BillingClass: identity.BillingClass(), Entitlement: identity.Entitlement(), Evidence: identity.EvidenceGrade(),
	}
	report.Transport, err = providerTransportForIdentity(identity)
	if err != nil {
		return report, err
	}
	capability, ok := provider.CapabilityMatrix()[report.Transport]
	if !ok {
		return report, fmt.Errorf("provider transport %q has no declared capability matrix", report.Transport)
	}
	report.Capabilities = capability
	report.Checks = append(report.Checks,
		providerDoctorCheck{ID: "profile", Status: providerDoctorPass, Provenance: "config_validated", Summary: "exact provider profile validated"},
		providerDoctorCheck{ID: "identity", Status: providerDoctorPass, Provenance: "profile_attested", Summary: "immutable provider identity is complete", Evidence: identity.Hash()},
	)

	executionProfile := profile
	executionDeps := deps
	var executionAuthorityErr error
	if identity.Provider() == "xai" {
		switch {
		case deps.lookPath == nil || deps.trustExecutable == nil:
			executionAuthorityErr = errors.New("Grok runtime authority dependencies are incomplete")
		default:
			located, resolveErr := deps.lookPath(profile.Command)
			if resolveErr != nil {
				executionAuthorityErr = fmt.Errorf("locate configured Grok runtime: %w", resolveErr)
				break
			}
			trusted, trustErr := deps.trustExecutable(located)
			if trustErr != nil {
				executionAuthorityErr = fmt.Errorf("configured Grok runtime is not system-authoritative: %w", trustErr)
				break
			}
			executionProfile.Command = trusted
			executionDeps.lookPath = func(string) (string, error) { return trusted, nil }
		}
	}
	var policy providerDoctorPolicy
	var policyCheck providerDoctorCheck
	if executionAuthorityErr != nil {
		report.Runtime = providerDoctorRuntime{ExpectedVersion: profile.RuntimeVersion, Drift: "untrusted"}
		report.Checks = append(report.Checks, providerDoctorCheck{
			ID: "runtime", Status: providerDoctorFail, Provenance: "live_local",
			Summary:     "configured Grok runtime is not system-authoritative",
			Evidence:    safeErrorDigest(executionAuthorityErr),
			Remediation: "Install the pinned Grok executable under a root-owned, non-writable canonical path",
		})
		policy = providerDoctorPolicy{
			Name: profile.AutomationPolicy, ManagedRequirementsState: "not_checked",
			RuntimeInspectionState: "runtime_untrusted", BypassLockProbeState: "blocked",
		}
		if descriptor, ok := agent.GrokAutomationPolicy(profile.AutomationPolicy); ok {
			policy.SHA256 = agent.GrokAutomationPolicySHA256(profile.AutomationPolicy)
			policy.Sandbox, policy.PermissionMode = descriptor.Sandbox, descriptor.PermissionMode
		}
		policyCheck = providerDoctorCheck{
			ID: "policy", Status: providerDoctorFail, Provenance: "preflight",
			Summary:     "managed policy attestation was blocked before executing an untrusted Grok runtime",
			Evidence:    safeErrorDigest(executionAuthorityErr),
			Remediation: "Repair executable ownership and parent-directory authority before policy attestation",
		}
	} else {
		report.Runtime, report.Checks = diagnoseProviderRuntime(ctx, executionProfile, identity, executionDeps, report.Checks)
		policy, policyCheck = diagnoseProviderPolicy(ctx, providerDoctorInspectionCWD(), executionProfile, identity, executionDeps)
	}
	report.Policy = policy
	report.Checks = append(report.Checks, policyCheck)
	authCheck := diagnoseProviderAuthPresence(identity, deps.lookupEnv)
	if identity.Provider() == "zai" && identity.Entitlement() == provider.EntitlementNativeAPI {
		authCheck = diagnoseNativeProviderCredential(ctx, identity, deps.credentialStatus)
	} else if identity.Provider() == "zai" && identity.Entitlement() == provider.EntitlementCodexResponses {
		authCheck = diagnoseCodexProviderCredential(ctx, profile, deps.codexCredentialStatus)
	}
	report.Checks = append(report.Checks, authCheck)
	attestationPreflight := deps.attestationPreflight
	if identity.Provider() == "xai" && identity.Runtime() == "grok" {
		attestationPreflight = func(ctx context.Context) (providerattestation.SignatureMetadata, error) {
			if deps.grokAttestationPreflight == nil {
				return providerattestation.SignatureMetadata{}, providerattestation.ErrProtectionUnavailable
			}
			return deps.grokAttestationPreflight(ctx, profile)
		}
	} else if identity.Provider() == "zai" && identity.Entitlement() == provider.EntitlementCodexResponses {
		attestationPreflight = func(ctx context.Context) (providerattestation.SignatureMetadata, error) {
			if deps.codexAttestationPreflight == nil {
				return providerattestation.SignatureMetadata{}, providerattestation.ErrProtectionUnavailable
			}
			return deps.codexAttestationPreflight(ctx, profile)
		}
	}
	attestationCheck, trustedQualificationSigner := diagnoseProviderReceiptAttestationWithKey(ctx, attestationPreflight)
	report.Checks = append(report.Checks, attestationCheck)
	report.Capacity, report.Checks = diagnoseProviderCapacity(identity, deps, report.Checks)
	qualificationPolicySHA := report.Policy.SHA256
	if report.Transport == "zai_claude_runtime" {
		qualificationPolicySHA = providerqualification.QualificationPolicySHA256()
	}
	report.Qualification, report.Checks = diagnoseQualification(identity, report.Transport, qualificationPolicySHA, trustedQualificationSigner, opts, deps, report.Checks)

	if opts.online {
		if report.Transport == "zai_codex_runtime" {
			if report.Qualification.TrustedCurrent && report.Qualification.ModelIdentityVerified {
				report.Checks = append(report.Checks, providerDoctorCheck{ID: "model_entitlement", Status: providerDoctorPass, Provenance: "signed_live_qualification", Summary: "current signed qualification observed the exact provider-reported model and authenticated Coding Plan lane", Evidence: report.Qualification.ReceiptSHA256})
			} else {
				report.Checks = append(report.Checks, providerDoctorCheck{ID: "model_entitlement", Status: providerDoctorFail, Provenance: "signed_live_qualification", Summary: "a current signed qualification with exact provider-reported model evidence is required; Codex doctor dispatch remains disabled", Evidence: report.Qualification.ReceiptSHA256, Remediation: "Run the explicit provider qualification suite after reviewing the pinned Codex runtime and policy"})
			}
		} else {
			var probePreflightErr error
			switch {
			case deps.onlineProbe == nil || deps.admission == nil:
				probePreflightErr = errors.New("online provider probe dependencies are incomplete")
			case executionAuthorityErr != nil:
				probePreflightErr = executionAuthorityErr
			case report.Capacity.Scope != provider.CapacityControlScopeLocalShared:
				probePreflightErr = errors.New("online provider probe requires the cross-process local shared capacity store")
			case report.Runtime.Drift != "none":
				probePreflightErr = errors.New("online provider probe requires the exact pinned runtime")
			case authCheck.Status == providerDoctorFail:
				probePreflightErr = errors.New("online provider probe requires the exact provider credential lane")
			case identity.Provider() == "xai" && (policyCheck.Status != providerDoctorPass || !policy.BypassLockAuthoritative):
				probePreflightErr = errors.New("online Grok probe requires root-owned managed requirements discovered by the pinned runtime")
			}
			if probePreflightErr != nil {
				report.Checks = append(report.Checks, providerDoctorCheck{ID: "model_entitlement", Status: providerDoctorFail, Provenance: "preflight", Summary: "live no-tool identity/model probe was blocked before provider dispatch", Evidence: safeErrorDigest(probePreflightErr), Remediation: "Repair the failed policy, runtime, credential, or capacity gate before a live probe"})
			} else if decision := deps.admission.Acquire(identity); !decision.Allowed || !decision.NoFailover {
				report.Checks = append(report.Checks, providerDoctorCheck{ID: "model_entitlement", Status: providerDoctorFail, Provenance: "local_shared_admission", Summary: "live no-tool identity/model probe was denied before provider dispatch", Evidence: sha256StringCLI(string(decision.Reason)), Remediation: "Honor the exact identity retry/circuit state; provider failover is prohibited"})
			} else {
				probeCtx, cancel := context.WithTimeout(ctx, opts.timeout)
				live, probeErr := deps.onlineProbe(probeCtx, executionProfile, identity)
				cancel()
				deps.admission.Release(identity, decision)
				if probeErr != nil {
					report.Checks = append(report.Checks, providerDoctorCheck{ID: "model_entitlement", Status: providerDoctorFail, Provenance: "live", Summary: "live no-tool identity/model probe failed", Evidence: safeErrorDigest(probeErr), Remediation: "Check the exact credential entitlement, endpoint, model, and provider CLI diagnostics"})
				} else if !live.ModelVerified || !live.AuthVerified || report.Transport == "xai_acp" && !live.RuntimeContractPassed {
					report.Checks = append(report.Checks, providerDoctorCheck{ID: "model_entitlement", Status: providerDoctorFail, Provenance: "live", Summary: "live probe lacked exact model, authentication, or shared runtime-contract evidence", Evidence: live.SHA256})
				} else {
					deps.admission.RecordSuccess(identity)
					report.Checks = append(report.Checks, providerDoctorCheck{ID: "model_entitlement", Status: providerDoctorPass, Provenance: "live", Summary: "exact model and authentication were observed", Evidence: live.SHA256})
					authCheck = providerDoctorCheck{ID: "auth_presence", Status: providerDoctorPass, Provenance: "live", Summary: "credential was accepted for the exact provider lane", Evidence: live.SHA256}
					replaceProviderDoctorCheck(report.Checks, authCheck)
				}
			}
		}
	} else {
		remediation := "Run provider doctor with --online for a bounded no-tool probe"
		if identity.Provider() == "zai" && identity.Entitlement() == provider.EntitlementCodexResponses {
			remediation = "Use provider codex run or provider qualify; Codex online doctor dispatch is disabled so every paid request stays admission-controlled and receipted"
		}
		report.Checks = append(report.Checks, providerDoctorCheck{ID: "model_entitlement", Status: providerDoctorUnavailable, Provenance: "offline", Summary: "model entitlement was not probed", Remediation: remediation})
	}

	if report.Transport == "zai_claude_runtime" {
		report.Checks = append(report.Checks, diagnoseZAIClaudeRequestAuthority(capability))
	}
	report.Checks = append(report.Checks, diagnoseLifecycleAuthority(capability))

	report.Promotion = providerDoctorPromotionForReport(report, report.Promotion.RequiredOperation)
	return report, nil
}

func diagnoseProviderPolicy(ctx context.Context, inspectionCWD string, profile config.ProviderProfileConfig, identity provider.Identity, deps providerDoctorDependencies) (providerDoctorPolicy, providerDoctorCheck) {
	result := providerDoctorPolicy{Name: profile.AutomationPolicy, ManagedRequirementsState: "not_applicable", RuntimeInspectionState: "not_applicable", BypassLockProbeState: "not_applicable"}
	if identity.Provider() != "xai" {
		switch {
		case identity.Provider() == "zai" && identity.Entitlement() == provider.EntitlementCodexResponses:
			result.SHA256 = providerCodexPolicySHA256()
		case identity.Provider() == "zai" && identity.Entitlement() == provider.EntitlementNativeAPI && profile.AutomationPolicy == provider.NativeZAIToolsPolicyName:
			result.SHA256 = providerNativeToolsPolicySHA256()
		case identity.Provider() == "zai" && identity.Entitlement() == provider.EntitlementNativeAPI:
			result.SHA256 = providerNativeNoToolsPolicySHA256()
		default:
			result.SHA256 = identity.ConfigSHA256()
		}
		return result, providerDoctorCheck{ID: "policy", Status: providerDoctorPass, Provenance: "config_validated", Summary: "provider policy is bound by the reviewed profile manifest", Evidence: result.SHA256}
	}
	binary := profile.Command
	if deps.lookPath != nil {
		resolved, err := deps.lookPath(profile.Command)
		if err != nil {
			result.RuntimeInspectionState = "runtime_unavailable"
			return result, providerDoctorCheck{ID: "policy", Status: providerDoctorFail, Provenance: "live_local", Summary: "configured Grok runtime could not be resolved before policy attestation", Evidence: safeErrorDigest(err), Remediation: "Install and pin the exact Grok runtime before automation"}
		}
		binary = resolved
	}
	descriptor, ok := agent.GrokAutomationPolicy(profile.AutomationPolicy)
	if !ok {
		return result, providerDoctorCheck{ID: "policy", Status: providerDoctorFail, Provenance: "compiled", Summary: "unknown Grok automation policy"}
	}
	result.SHA256 = agent.GrokAutomationPolicySHA256(profile.AutomationPolicy)
	result.Sandbox, result.PermissionMode = descriptor.Sandbox, descriptor.PermissionMode
	requirements, ok := agent.GrokSystemRequirementsForPolicy(profile.AutomationPolicy)
	if !ok {
		return result, providerDoctorCheck{ID: "policy", Status: providerDoctorFail, Provenance: "compiled", Summary: "managed Grok requirements could not be rendered"}
	}
	result.ManagedRequirementsSHA256 = requirements.SHA256
	path := providerRequirementsPath()
	var data []byte
	var info os.FileInfo
	var readErr, statErr error
	if deps.readRequirements != nil {
		data, info, readErr = deps.readRequirements(path)
		statErr = readErr
	} else {
		data, readErr = deps.readFile(path)
		info, statErr = deps.stat(path)
	}
	installedSHA := sha256TextCLI(data)
	acceptedSHA := installedSHA == requirements.SHA256
	// The root-owned workspace envelope is the maximum managed capability.
	// A read-only invocation remains safe beneath it because the per-run deny
	// rules are stricter and Grok deny rules take precedence. This permits both
	// graduated profiles to coexist on one host without weakening observe mode.
	if !acceptedSHA && profile.AutomationPolicy == agent.DefaultGrokAutomationPolicyName {
		if workspaceRequirements, workspaceOK := agent.GrokSystemRequirementsForPolicy(agent.GrokWorkspaceWritePolicyName); workspaceOK && installedSHA == workspaceRequirements.SHA256 {
			acceptedSHA = true
			result.ManagedRequirementsSHA256 = workspaceRequirements.SHA256
		}
	}
	switch {
	case readErr != nil || statErr != nil:
		result.ManagedRequirementsState = "missing"
		return result, providerDoctorCheck{ID: "policy", Status: providerDoctorFail, Provenance: "live_local", Summary: "root-owned Grok managed requirements are not installed", Evidence: requirements.SHA256, Remediation: "Install the generated policy at the system Grok requirements path and verify it with grok inspect"}
	case !acceptedSHA:
		result.ManagedRequirementsState = "digest_mismatch"
		return result, providerDoctorCheck{ID: "policy", Status: providerDoctorFail, Provenance: "live_local", Summary: "installed Grok requirements do not match a compatible managed envelope", Evidence: installedSHA, Remediation: "Review and install the exact generated managed requirements"}
	case !deps.rootOwned(info):
		result.ManagedRequirementsState = "ownership_unverified"
		return result, providerDoctorCheck{ID: "policy", Status: providerDoctorFail, Provenance: "live_local", Summary: "Grok bypass lock is not proven system-authoritative", Evidence: requirements.SHA256, Remediation: "Make the system requirements file administrator/root owned"}
	default:
		result.ManagedRequirementsState = "installed_verified"
	}
	if deps.inspectGrok == nil {
		result.RuntimeInspectionState = "unavailable"
		return result, providerDoctorCheck{ID: "policy", Status: providerDoctorFail, Provenance: "live_local", Summary: "root-owned Grok requirements match, but runtime discovery was not inspected", Evidence: requirements.SHA256, Remediation: "Run the pinned Grok runtime inspection and verify the managed settings path"}
	}
	inspectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	inspection, inspectErr := deps.inspectGrok(inspectCtx, binary, inspectionCWD, profile.RuntimeHome)
	cancel()
	result.RuntimeInspectionSHA256 = inspection.SHA256
	if inspectErr != nil {
		result.RuntimeInspectionState = "failed"
		return result, providerDoctorCheck{ID: "policy", Status: providerDoctorFail, Provenance: "live_runtime_inspection", Summary: "Grok runtime inspection failed", Evidence: safeErrorDigest(inspectErr), Remediation: "Run grok --no-auto-update inspect --json and review managed configuration discovery"}
	}
	if !inspection.PermissionsLoaded || !hasProviderSystemRequirementsSource(inspection.PermissionSources, path) || !inspection.SystemRequirementsLayerPresent {
		result.RuntimeInspectionState = "managed_requirements_not_discovered"
		return result, providerDoctorCheck{ID: "policy", Status: providerDoctorFail, Provenance: "live_runtime_inspection", Summary: "pinned Grok runtime did not report the exact system requirements source and layer as loaded", Evidence: inspection.SHA256, Remediation: "Repair the system requirements installation and re-run Grok inspection"}
	}
	if !providerGrokInspectionIsolated(inspection, profile.RuntimeHome, path) {
		result.RuntimeInspectionState = "ambient_configuration_detected"
		return result, providerDoctorCheck{ID: "policy", Status: providerDoctorFail, Provenance: "live_runtime_inspection", Summary: "Grok inspection detected ambient/project extensions or configuration outside the isolated profile", Evidence: inspection.SHA256, Remediation: "Use a dedicated GROK_HOME and remove project/user MCP, hook, plugin, marketplace, or compatibility inputs before automation"}
	}
	result.RuntimeInspectionState = "managed_requirements_discovered"
	if inspection.BypassLockWarning {
		// Grok 1.0.13 reports the documented key as an inspect-schema warning
		// even while its headless runtime enforces the managed lock. Preserve
		// that discrepancy in the receipt and require an isolated behavioral
		// refusal below; the warning alone is never authority evidence.
		result.RuntimeInspectionState = "managed_requirements_discovered_with_bypass_warning"
	}
	if deps.probeGrokBypassLock == nil {
		result.BypassLockProbeState = "unavailable"
		return result, providerDoctorCheck{ID: "policy", Status: providerDoctorFail, Provenance: "live_behavioral_attestation", Summary: "Grok managed bypass lock was not behaviorally attested", Evidence: inspection.SHA256, Remediation: "Run the isolated no-network Grok bypass-lock refusal probe"}
	}
	probeCtx, probeCancel := context.WithTimeout(ctx, 5*time.Second)
	probe, probeErr := deps.probeGrokBypassLock(probeCtx, binary)
	probeCancel()
	result.BypassLockProbeSHA256 = probe.SHA256
	if probeErr != nil {
		result.BypassLockProbeState = "failed"
		return result, providerDoctorCheck{ID: "policy", Status: providerDoctorFail, Provenance: "live_behavioral_attestation", Summary: "Grok managed bypass-lock refusal probe failed closed", Evidence: safeErrorDigest(probeErr), Remediation: "Restore Linux Bubblewrap isolation and verify the exact pinned Grok runtime refuses always-approve"}
	}
	if !probe.Refused || !probe.NetworkIsolated || !probe.CredentialsIsolated {
		result.BypassLockProbeState = "not_refused"
		return result, providerDoctorCheck{ID: "policy", Status: providerDoctorFail, Provenance: "live_behavioral_attestation", Summary: "Grok did not authoritatively refuse always-approve inside the isolated probe", Evidence: probe.SHA256, Remediation: "Do not automate Grok until the root-owned bypass lock is enforced by the pinned runtime"}
	}
	result.BypassLockProbeState = "always_approve_refused"
	result.BypassLockAuthoritative = true
	evidence := sha256StringCLI(inspection.SHA256 + "\x00" + probe.SHA256)
	return result, providerDoctorCheck{ID: "policy", Status: providerDoctorPass, Provenance: "live_behavioral_attestation", Summary: "compiled policy, root-owned requirements, runtime discovery, and isolated always-approve refusal match", Evidence: evidence}
}

// verifyGrokACPDispatchAuthority is the live, fail-closed gate for the legacy
// robot ACP entry point. Profile validation alone is not authority evidence:
// the exact managed policy must be root-owned and discovered by the pinned
// Grok runtime immediately before the provider process is started.
func verifyGrokACPDispatchAuthority(ctx context.Context, inspectionCWD string, profile config.ProviderProfileConfig, identity provider.Identity, deps providerDoctorDependencies) (string, error) {
	if deps.lookPath == nil || deps.trustExecutable == nil || deps.version == nil || deps.rootOwned == nil || deps.inspectGrok == nil || deps.probeGrokBypassLock == nil || (deps.readRequirements == nil && (deps.readFile == nil || deps.stat == nil)) {
		return "", errors.New("Grok ACP authority verification dependencies are incomplete")
	}
	if identity.Provider() != "xai" || identity.Runtime() != "grok" {
		return "", errors.New("Grok ACP authority verification requires an exact xAI/Grok identity")
	}
	locatedBinary, err := deps.lookPath(profile.Command)
	if err != nil {
		return "", fmt.Errorf("locate configured Grok runtime: %w", err)
	}
	binary, err := deps.trustExecutable(locatedBinary)
	if err != nil {
		return "", fmt.Errorf("configured Grok runtime is not system-authoritative: %w", err)
	}
	versionCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	actualVersion, err := deps.version(versionCtx, binary)
	cancel()
	if err != nil {
		return "", fmt.Errorf("read configured Grok runtime version: %w", err)
	}
	if strings.TrimSpace(profile.RuntimeVersion) == "" || !versionMatches(actualVersion, profile.RuntimeVersion) {
		return "", errors.New("configured Grok runtime is unpinned or has drifted")
	}
	attestedProfile := profile
	attestedProfile.Command = binary
	attestedDeps := deps
	attestedDeps.lookPath = func(string) (string, error) { return binary, nil }
	policy, check := diagnoseProviderPolicy(ctx, inspectionCWD, attestedProfile, identity, attestedDeps)
	if check.Status != providerDoctorPass || !policy.BypassLockAuthoritative {
		return "", errors.New("root-owned Grok managed requirements are missing, mismatched, or not authoritative")
	}
	return binary, nil
}

func diagnoseProviderRuntime(ctx context.Context, profile config.ProviderProfileConfig, identity provider.Identity, deps providerDoctorDependencies, checks []providerDoctorCheck) (providerDoctorRuntime, []providerDoctorCheck) {
	result := providerDoctorRuntime{ExpectedVersion: profile.RuntimeVersion, Drift: "unknown"}
	if identity.Provider() == "zai" && identity.Entitlement() == provider.EntitlementNativeAPI {
		const adapterVersion = "zai-native-http-v1"
		result.Installed, result.Version = true, adapterVersion
		if profile.RuntimeVersion == "" {
			result.Drift = "unpinned"
			checks = append(checks, providerDoctorCheck{ID: "runtime", Status: providerDoctorWarn, Provenance: "compiled", Summary: "native Z.ai adapter is available but its schema version is not pinned", Evidence: sha256StringCLI(adapterVersion), Remediation: "Set runtime_version = \"zai-native-http-v1\" in the reviewed profile"})
		} else if profile.RuntimeVersion != adapterVersion {
			result.Drift = "detected"
			checks = append(checks, providerDoctorCheck{ID: "runtime", Status: providerDoctorFail, Provenance: "compiled", Summary: "native Z.ai adapter schema drift detected", Evidence: sha256StringCLI(adapterVersion)})
		} else {
			result.Drift = "none"
			checks = append(checks, providerDoctorCheck{ID: "runtime", Status: providerDoctorPass, Provenance: "compiled", Summary: "native Z.ai adapter schema matches its pin", Evidence: sha256StringCLI(adapterVersion)})
		}
		return result, checks
	}
	path, err := deps.lookPath(profile.Command)
	if err != nil {
		checks = append(checks, providerDoctorCheck{ID: "runtime", Status: providerDoctorFail, Provenance: "live_local", Summary: "provider runtime executable is not installed", Remediation: "Install the exact provider CLI configured by this profile"})
		return result, checks
	}
	result.Installed = true
	versionCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	version, versionErr := deps.version(versionCtx, path)
	if versionErr != nil {
		checks = append(checks, providerDoctorCheck{ID: "runtime", Status: providerDoctorFail, Provenance: "live_local", Summary: "provider runtime version could not be read", Evidence: safeErrorDigest(versionErr)})
		return result, checks
	}
	result.Version = version
	if profile.RuntimeVersion == "" {
		result.Drift = "unpinned"
		checks = append(checks, providerDoctorCheck{ID: "runtime", Status: providerDoctorWarn, Provenance: "live_local", Summary: "provider runtime is installed but no expected version is pinned", Evidence: sha256StringCLI(version), Remediation: "Set runtime_version in the exact provider profile after review"})
		return result, checks
	}
	if !versionMatches(version, profile.RuntimeVersion) {
		result.Drift = "detected"
		checks = append(checks, providerDoctorCheck{ID: "runtime", Status: providerDoctorFail, Provenance: "live_local", Summary: "provider runtime version drift detected", Evidence: sha256StringCLI(version), Remediation: "Review the installed CLI and update either the binary or the pinned profile version"})
		return result, checks
	}
	result.Drift = "none"
	checks = append(checks, providerDoctorCheck{ID: "runtime", Status: providerDoctorPass, Provenance: "live_local", Summary: "provider runtime version matches its pin", Evidence: sha256StringCLI(version)})
	return result, checks
}

func diagnoseProviderAuthPresence(identity provider.Identity, lookup func(string) (string, bool)) providerDoctorCheck {
	present := func(name string) bool {
		value, ok := lookup(name)
		return ok && strings.TrimSpace(value) != ""
	}
	switch {
	case identity.Provider() == "zai" && identity.Entitlement() == provider.EntitlementNativeAPI:
		return providerDoctorCheck{ID: "auth_presence", Status: providerDoctorFail, Provenance: "os_credential_broker", Summary: "native API credential status requires the OS-protected broker", Remediation: "Run ntm provider credential status for this exact profile"}
	case identity.Provider() == "zai":
		if present("ZAI_API_KEY") {
			return providerDoctorCheck{ID: "auth_presence", Status: providerDoctorPass, Provenance: "live_local", Summary: "Claude-compatible Coding Plan credential is present"}
		}
		return providerDoctorCheck{ID: "auth_presence", Status: providerDoctorFail, Provenance: "live_local", Summary: "Claude-compatible Z.ai credential is absent", Remediation: "Provide ZAI_API_KEY for the Coding Plan lane; generic Anthropic tokens are never forwarded"}
	case identity.Provider() == "xai" && present("XAI_API_KEY"):
		return providerDoctorCheck{ID: "auth_presence", Status: providerDoctorPass, Provenance: "live_local", Summary: "xAI API credential is present"}
	default:
		return providerDoctorCheck{ID: "auth_presence", Status: providerDoctorUnavailable, Provenance: "offline", Summary: "cached provider authentication cannot be proven from environment presence", Remediation: "Run provider doctor with --online to validate cached authentication"}
	}
}

func diagnoseNativeProviderCredential(ctx context.Context, identity provider.Identity, statusFn func(context.Context, string) (providercredential.Status, error)) providerDoctorCheck {
	if statusFn == nil {
		return providerDoctorCheck{ID: "auth_presence", Status: providerDoctorFail, Provenance: "os_credential_broker", Summary: "OS-protected credential broker is unavailable", Remediation: "Install a supported native credential store and provision this exact profile"}
	}
	status, err := statusFn(ctx, providerCredentialID(identity))
	if err != nil || !status.Available {
		return providerDoctorCheck{ID: "auth_presence", Status: providerDoctorFail, Provenance: "os_credential_broker", Summary: "OS-protected credential broker is unavailable", Evidence: safeErrorDigest(err), Remediation: "Install a supported native credential store and run ntm provider credential set --stdin for this exact profile"}
	}
	if !status.Present || status.Evidence != providercredential.EvidenceOSProtectedProcessReadable {
		return providerDoctorCheck{ID: "auth_presence", Status: providerDoctorFail, Provenance: "os_credential_broker", Summary: "exact native API credential is absent or insufficiently protected", Evidence: digestSafeJSON(status), Remediation: "Provision the exact native profile with ntm provider credential set --stdin"}
	}
	return providerDoctorCheck{ID: "auth_presence", Status: providerDoctorPass, Provenance: "os_credential_broker", Summary: "exact native API credential is present in OS-protected storage", Evidence: digestSafeJSON(status)}
}

func diagnoseCodexProviderCredential(ctx context.Context, profile config.ProviderProfileConfig, statusFn func(context.Context, config.ProviderProfileConfig) (providercredential.Status, error)) providerDoctorCheck {
	if statusFn == nil {
		return providerDoctorCheck{ID: "auth_presence", Status: providerDoctorFail, Provenance: "os_credential_broker", Summary: "Z.ai Coding Plan credential status is unavailable", Remediation: "Provision the exact isolated profile with ntm provider credential set --stdin"}
	}
	status, err := statusFn(ctx, profile)
	if err != nil || !status.Available {
		return providerDoctorCheck{ID: "auth_presence", Status: providerDoctorFail, Provenance: "os_credential_broker", Summary: "pinned Z.ai Coding Plan credential bridge is unavailable", Evidence: safeErrorDigest(err), Remediation: "Repair the profile-pinned bridge before provisioning or using the Coding Plan token"}
	}
	if !status.Present || status.Evidence != providercredential.EvidenceOSProtectedProcessReadable {
		return providerDoctorCheck{ID: "auth_presence", Status: providerDoctorFail, Provenance: "os_credential_broker", Summary: "exact Z.ai Coding Plan credential is absent or insufficiently protected", Evidence: digestSafeJSON(status), Remediation: "Provision the Individual GLM Coding Plan key with ntm provider credential set --profile=<exact-profile> --stdin"}
	}
	return providerDoctorCheck{ID: "auth_presence", Status: providerDoctorPass, Provenance: "os_credential_broker", Summary: "exact Z.ai Coding Plan credential is present in OS-protected storage", Evidence: digestSafeJSON(status)}
}

func diagnoseProviderReceiptAttestation(ctx context.Context, preflight func(context.Context) (providerattestation.SignatureMetadata, error)) providerDoctorCheck {
	check, _ := diagnoseProviderReceiptAttestationWithKey(ctx, preflight)
	return check
}

func diagnoseProviderReceiptAttestationWithKey(ctx context.Context, preflight func(context.Context) (providerattestation.SignatureMetadata, error)) (providerDoctorCheck, *providerattestation.KeyMetadata) {
	if preflight == nil {
		return providerDoctorCheck{ID: "receipt_attestation", Status: providerDoctorFail, Provenance: "local_attestation", Summary: "provider receipt signing preflight is unavailable", Remediation: "Run ntm provider attestation init on a supported local attestation backend"}, nil
	}
	signature, err := preflight(ctx)
	if err != nil {
		return providerDoctorCheck{ID: "receipt_attestation", Status: providerDoctorFail, Provenance: "local_attestation", Summary: "provider receipt signing key is absent or unavailable", Evidence: safeErrorDigest(err), Remediation: "Run ntm provider attestation init before live provider execution"}, nil
	}
	provenance := "os_credential_broker"
	summary := "OS-protected process-readable receipt key produced a locally verifiable signature"
	if signature.ProtectionEvidence == providerattestation.ProtectionHardwareNoExportLocalController {
		provenance = "hardware_local_controller"
		summary = "hardware-backed non-exportable local-controller key produced a locally verifiable signature"
	}
	key := signature.KeyMetadata
	return providerDoctorCheck{ID: "receipt_attestation", Status: providerDoctorPass, Provenance: provenance, Summary: summary, Evidence: digestSafeJSON(key)}, &key
}

func diagnoseQualification(identity provider.Identity, transport, policySHA string, trustedSigner *providerattestation.KeyMetadata, opts providerCommandOptions, deps providerDoctorDependencies, checks []providerDoctorCheck) (providerDoctorQualification, []providerDoctorCheck) {
	result := providerDoctorQualification{State: "missing", PolicySHA256: policySHA}
	qualificationRequired := transport == "xai_acp" || transport == "xai_headless_session" || transport == "zai_claude_runtime" || transport == "zai_codex_runtime" || transport == "zai_native_api" && policySHA == providerNativeToolsPolicySHA256()
	if !qualificationRequired {
		result.State = "not_required"
		checks = append(checks, providerDoctorCheck{ID: "qualification", Status: providerDoctorPass, Provenance: "capability_registry", Summary: "the nine-check coding qualification is not applicable to this no-tool/provider-native transport; online identity and capability-specific gates still apply"})
		return result, checks
	}
	var receipt providerqualification.Receipt
	var err error
	if deps.qualificationStoreForTransport != nil {
		receipt, _, err = deps.qualificationStoreForTransport(opts.qualificationDir, identity.Hash(), transport)
	} else if deps.qualificationStore != nil {
		// Retained only for focused legacy unit-test seams. Production always
		// selects by exact transport so one adapter's receipt cannot authorize
		// another adapter for the same provider identity.
		receipt, _, err = deps.qualificationStore(opts.qualificationDir, identity.Hash())
	} else {
		err = errors.New("qualification receipt store is unavailable")
	}
	if err != nil {
		checks = append(checks, providerDoctorCheck{ID: "qualification", Status: providerDoctorFail, Provenance: "unavailable", Summary: "no valid live qualification receipt exists", Remediation: "Run the explicit live provider qualification suite in a disposable repository"})
		return result, checks
	}
	if err := receipt.Validate(); err != nil {
		checks = append(checks, providerDoctorCheck{ID: "qualification", Status: providerDoctorFail, Provenance: "live_receipt", Summary: "qualification receipt failed integrity validation", Evidence: safeErrorDigest(err), Remediation: "Run a fresh live qualification with the pinned receipt signer"})
		return result, checks
	}
	result.Passed = receipt.Passed
	result.CompletedAt = receipt.CompletedAt
	result.ReceiptSHA256 = receipt.ReceiptSHA256
	result.AgeSeconds = int64(deps.now().UTC().Sub(receipt.CompletedAt).Seconds())
	result.ChecksTotal = len(receipt.Checks)
	for _, check := range receipt.Checks {
		if check.Passed {
			result.ChecksPassed++
		}
	}
	markTrustedCurrent := func() {
		result.TrustedCurrent = true
		result.CheckStates = make(map[string]bool, len(receipt.Checks))
		for _, check := range receipt.Checks {
			result.CheckStates[check.Name] = providerqualification.AuthoritativePassedCheck(check)
		}
		result.ModelIdentityVerified = qualificationReceiptModelIdentityVerified(receipt, transport)
	}
	switch {
	case receipt.Attestation == nil:
		result.State = "unsigned"
		checks = append(checks, providerDoctorCheck{ID: "qualification", Status: providerDoctorFail, Provenance: "live_receipt", Summary: "qualification receipt is not cryptographically attested", Evidence: receipt.ReceiptSHA256, Remediation: "Initialize provider receipt signing and run a fresh live qualification"})
	case trustedSigner == nil || receipt.Attestation.KeyMetadata != *trustedSigner:
		result.State = "signer_mismatch"
		checks = append(checks, providerDoctorCheck{ID: "qualification", Status: providerDoctorFail, Provenance: "live_receipt", Summary: "qualification receipt was not signed by the profile-pinned local attestation key", Evidence: receipt.ReceiptSHA256, Remediation: "Run a fresh live qualification with the currently pinned receipt signer"})
	case receipt.Transport != transport || receipt.IdentitySHA256 != identity.Hash() || receipt.PolicySHA256 != policySHA:
		result.State = "identity_or_policy_mismatch"
		checks = append(checks, providerDoctorCheck{ID: "qualification", Status: providerDoctorFail, Provenance: "live_receipt", Summary: "qualification receipt does not bind this exact identity, transport, and policy", Evidence: receipt.ReceiptSHA256})
	case deps.now().UTC().Before(receipt.CompletedAt):
		result.State = "future_dated"
		checks = append(checks, providerDoctorCheck{ID: "qualification", Status: providerDoctorFail, Provenance: "live_receipt", Summary: "qualification receipt is future-dated", Evidence: receipt.ReceiptSHA256})
	case deps.now().UTC().Sub(receipt.CompletedAt) > opts.qualificationAge:
		result.State = "expired"
		checks = append(checks, providerDoctorCheck{ID: "qualification", Status: providerDoctorFail, Provenance: "live_receipt", Summary: "live qualification receipt has expired", Evidence: receipt.ReceiptSHA256, Remediation: "Run a fresh live qualification after reviewing CLI and policy drift"})
	case !receipt.Passed:
		markTrustedCurrent()
		result.State = "current_partial"
		checks = append(checks, providerDoctorCheck{ID: "qualification", Status: providerDoctorWarn, Provenance: "live_receipt", Summary: "current signed qualification is partial; only operations whose exact checks passed may be promoted", Evidence: receipt.ReceiptSHA256})
	case transport == "zai_codex_runtime" && !qualificationModelIdentityVerified(receipt):
		markTrustedCurrent()
		result.State = "model_identity_unverified"
		checks = append(checks, providerDoctorCheck{ID: "qualification", Status: providerDoctorWarn, Provenance: "live_receipt", Summary: "current signed qualification lacks provider-live exact model identity evidence", Evidence: receipt.ReceiptSHA256, Remediation: "Do not spend another qualification request until the runtime exposes the served model"})
	default:
		markTrustedCurrent()
		result.State = "current_pass"
		checks = append(checks, providerDoctorCheck{ID: "qualification", Status: providerDoctorPass, Provenance: "live_receipt", Summary: "all mandatory live qualification checks passed and are current", Evidence: receipt.ReceiptSHA256})
	}
	return result, checks
}

// qualificationModelIdentityVerified requires the signed receipt's dedicated
// model-identity gate. The bound identity includes the configured model; the
// Codex qualification producer only marks this provider-live check passed
// after it observes an exact terminal provider-reported model.
func qualificationModelIdentityVerified(receipt providerqualification.Receipt) bool {
	for _, check := range receipt.Checks {
		if check.Name == providerqualification.CheckIdentity {
			return check.Passed && check.Provenance == "live" && check.EvidenceSHA256 != "" && check.Detail == providerCodexQualificationModelGate
		}
	}
	return false
}

func qualificationReceiptModelIdentityVerified(receipt providerqualification.Receipt, transport string) bool {
	for _, check := range receipt.Checks {
		if check.Name != providerqualification.CheckIdentity || !check.Passed || check.Provenance != "live" || check.EvidenceSHA256 == "" {
			continue
		}
		switch transport {
		case "zai_codex_runtime":
			return check.Detail == providerCodexQualificationModelGate
		case "xai_acp":
			return check.Detail == "terminal_public_and_resolved_model_verified"
		default:
			return true
		}
	}
	return false
}

func diagnoseProviderCapacity(identity provider.Identity, deps providerDoctorDependencies, checks []providerDoctorCheck) (providerDoctorCapacity, []providerDoctorCheck) {
	var status ratelimit.CapacityStatus
	var snapshot ratelimit.AdmissionSnapshot
	var subscription *providerDoctorSubscriptionCapacity
	if identity.Provider() == "zai" && identity.Entitlement() == provider.EntitlementCodexResponses {
		if deps.codexSubscriptionStatus == nil || deps.codexSubscriptionSnapshot == nil {
			result := providerDoctorCapacity{Scope: provider.CapacityControlScopeProcessLocal, CircuitState: "unknown", FallbackReason: "Z.ai Codex subscription capacity dependencies are unavailable"}
			checks = append(checks, providerDoctorCheck{ID: "capacity", Status: providerDoctorFail, Provenance: "compiled", Summary: "Z.ai Codex subscription capacity snapshot is unavailable", Remediation: "Restore the paired local shared Z.ai Coding Plan admission controller"})
			return result, checks
		}
		status = deps.codexSubscriptionStatus()
		codexSnapshot := deps.codexSubscriptionSnapshot(identity)
		snapshot = codexSnapshot.Exact
		subscription = &providerDoctorSubscriptionCapacity{
			ScopeSHA256:          codexSnapshot.SubscriptionScopeSHA256,
			PlanRunning:          codexSnapshot.PlanRunning,
			PlanMaxConcurrent:    codexSnapshot.PlanMaxConcurrent,
			AdmissionReservation: codexSnapshot.AdmissionReservation,
			FiveHourCreditsUsed:  codexSnapshot.FiveHourCreditsUsed,
			FiveHourCreditsLimit: codexSnapshot.FiveHourCreditsLimit,
			FiveHourResetsAt:     codexSnapshot.FiveHourResetsAt,
			WeeklyCreditsUsed:    codexSnapshot.WeeklyCreditsUsed,
			WeeklyCreditsLimit:   codexSnapshot.WeeklyCreditsLimit,
			WeeklyResetsAt:       codexSnapshot.WeeklyResetsAt,
			UnknownUsageReserved: codexSnapshot.UnknownUsageReserved,
			ConservativeUsage:    codexSnapshot.ConservativeUsage,
			LegacyRecovery:       codexSnapshot.LegacyRecoveryAuthorized,
			LimitEvidence:        codexSnapshot.LimitEvidence,
			ResetEvidence:        codexSnapshot.ResetEvidence,
		}
	} else {
		status = deps.capacityStatus()
		snapshot = deps.capacitySnapshot(identity)
	}
	result := providerDoctorCapacity{
		Scope: status.Scope, FallbackReason: status.FallbackReason, CircuitState: "closed",
		Running: snapshot.Running, Tokens: snapshot.Tokens, ConsecutiveFailures: snapshot.ConsecutiveFailures,
		NextRetry: snapshot.NextRetry, CircuitOpenUntil: snapshot.CircuitOpenUntil, TerminalReason: snapshot.TerminalReason,
		HalfOpenInFlight: snapshot.HalfOpenInFlight, Subscription: subscription,
	}
	if status.SharedStorePath != "" {
		result.StoreSHA256 = sha256StringCLI(filepath.Clean(status.SharedStorePath))
	}
	if status.Scope != provider.CapacityControlScopeLocalShared {
		checks = append(checks, providerDoctorCheck{ID: "capacity", Status: providerDoctorFail, Provenance: "live_local", Summary: "capacity/circuit state is not shared across local NTM processes", Evidence: safeErrorDigest(errors.New(status.FallbackReason)), Remediation: "Restore the identity-keyed local shared capacity store"})
		return result, checks
	}
	now := deps.now().UTC()
	switch {
	case snapshot.TerminalReason != "":
		result.CircuitState = "terminal_block"
	case snapshot.HalfOpenInFlight:
		result.CircuitState = "half_open"
	case snapshot.CircuitOpenUntil != nil && snapshot.CircuitOpenUntil.After(now):
		result.CircuitState = "open"
	case snapshot.NextRetry != nil && snapshot.NextRetry.After(now):
		result.CircuitState = "backoff"
	}
	statusValue := providerDoctorPass
	remediation := ""
	summary := "identity-keyed local shared capacity store is active; circuit=" + result.CircuitState
	if block := providerDoctorCapacityAdmissionBlock(result); block != "" {
		statusValue = providerDoctorFail
		summary += "; admission_block=" + block
		remediation = "Wait for active leases or quota reset, or complete the explicit owner-authorized capacity recovery; do not dispatch or fail over while admission is blocked"
	}
	checks = append(checks, providerDoctorCheck{ID: "capacity", Status: statusValue, Provenance: "live_local_shared", Summary: summary, Evidence: sha256StringCLI(identity.CapacityScope().String()), Remediation: remediation})
	return result, checks
}

func providerDoctorCapacityAdmissionBlock(capacity providerDoctorCapacity) string {
	if capacity.CircuitState != "closed" {
		return "identity_" + capacity.CircuitState
	}
	if capacity.Running > 0 {
		return "identity_concurrency_busy"
	}
	subscription := capacity.Subscription
	if subscription == nil {
		return ""
	}
	if subscription.PlanMaxConcurrent < 1 || subscription.AdmissionReservation <= 0 || subscription.FiveHourCreditsLimit <= 0 || subscription.WeeklyCreditsLimit <= 0 || subscription.FiveHourCreditsUsed < 0 || subscription.WeeklyCreditsUsed < 0 {
		return "subscription_snapshot_invalid"
	}
	if subscription.UnknownUsageReserved {
		return "subscription_unknown_usage_reserved"
	}
	if subscription.PlanRunning >= subscription.PlanMaxConcurrent {
		return "subscription_concurrency_busy"
	}
	if subscription.FiveHourCreditsUsed+subscription.AdmissionReservation > subscription.FiveHourCreditsLimit {
		return "subscription_five_hour_quota"
	}
	if subscription.WeeklyCreditsUsed+subscription.AdmissionReservation > subscription.WeeklyCreditsLimit {
		return "subscription_weekly_quota"
	}
	return ""
}

func diagnoseLifecycleAuthority(capability provider.OperationCapabilities) providerDoctorCheck {
	if providerLifecycleFullyAuthoritative(capability) {
		return providerDoctorCheck{ID: "lifecycle_authority", Status: providerDoctorPass, Provenance: "capability_registry", Summary: "cancellation and cleanup are provider-authoritative"}
	}
	return providerDoctorCheck{ID: "lifecycle_authority", Status: providerDoctorWarn, Provenance: "capability_registry", Summary: fmt.Sprintf("cancellation=%s/%s cleanup=%s/%s; evidence is not fully provider-authoritative", capability.Cancellation, capability.CancellationAuthorityScope, capability.Cleanup, capability.CleanupAuthorityScope), Remediation: "Treat local process-tree control and client submission receipts as narrower than provider acknowledgement"}
}

func providerLifecycleFullyAuthoritative(capability provider.OperationCapabilities) bool {
	return capability.Cancellation == provider.EvidenceAuthoritative &&
		capability.CancellationAuthorityScope == provider.EvidenceAuthorityScopeProvider &&
		capability.Cleanup == provider.EvidenceAuthoritative &&
		capability.CleanupAuthorityScope == provider.EvidenceAuthorityScopeProvider
}

func normalizeProviderOperation(operation string) string {
	operation = strings.ToLower(strings.TrimSpace(operation))
	if operation == "" {
		return providerOperationLifecycle
	}
	return operation
}

func validProviderOperation(operation string) bool {
	switch normalizeProviderOperation(operation) {
	case providerOperationObserve, providerOperationReview, providerOperationWorkspaceWrite, providerOperationLifecycle:
		return true
	default:
		return false
	}
}

func providerDoctorPromotionForReport(report providerDoctorReport, requiredOperation string) providerDoctorPromotion {
	requiredOperation = normalizeProviderOperation(requiredOperation)
	promotion := providerDoctorPromotion{
		Level:             providerPromotionNoGo,
		RequiredOperation: requiredOperation,
		Scopes: []providerDoctorOperationScope{
			{Operation: providerOperationObserve, Evidence: "live exact-identity completion"},
			{Operation: providerOperationReview, Evidence: "bounded no-write provider operation"},
			{Operation: providerOperationWorkspaceWrite, Evidence: "signed edit/test/denial/cleanup qualification; Z.ai Codex also requires capacity accounting"},
			{Operation: providerOperationLifecycle, Evidence: "signed local crash/cancel/resume/cleanup qualification; remote inference stop is separately reported"},
		},
	}

	observe := providerDoctorFoundationReady(report) &&
		report.Capabilities.Launch == provider.EvidenceAuthoritative &&
		report.Capabilities.Delivery == provider.EvidenceAuthoritative &&
		report.Capabilities.Completion == provider.EvidenceAuthoritative
	review := observe && providerDoctorReviewEvidence(report)
	workspaceWrite := review && providerDoctorWorkspaceEvidence(report)
	lifecycle := workspaceWrite && providerDoctorLifecycleEvidence(report)
	admitted := []bool{observe, review, workspaceWrite, lifecycle}
	levels := []string{providerPromotionObserveOnly, providerPromotionReviewGo, providerPromotionWorkspaceWriteGo, providerPromotionLifecycleGo}
	for index := range promotion.Scopes {
		promotion.Scopes[index].Admitted = admitted[index]
		if admitted[index] {
			promotion.Level = levels[index]
		}
		if promotion.Scopes[index].Operation == requiredOperation {
			promotion.RequiredOperationAdmitted = admitted[index]
		}
	}
	return promotion
}

func providerDoctorFoundationReady(report providerDoctorReport) bool {
	if report.Mode != "online" || report.Runtime.Drift != "none" || report.Capacity.Scope != provider.CapacityControlScopeLocalShared {
		return false
	}
	if report.Transport == "zai_codex_runtime" && !report.Qualification.ModelIdentityVerified {
		return false
	}
	if providerDoctorCapacityAdmissionBlock(report.Capacity) != "" {
		return false
	}
	for _, id := range []string{"profile", "identity", "runtime", "policy", "auth_presence", "receipt_attestation", "capacity", "model_entitlement"} {
		if providerDoctorCheckStatus(report.Checks, id) != providerDoctorPass {
			return false
		}
	}
	// Qualification and lifecycle checks are operation-specific. A failure in
	// either must not suppress a lower, independently evidenced operation.
	for _, check := range report.Checks {
		if check.Status == providerDoctorFail && check.ID != "qualification" && check.ID != "lifecycle_authority" {
			return false
		}
	}
	return true
}

func providerDoctorCheckStatus(checks []providerDoctorCheck, id string) providerDoctorStatus {
	for _, check := range checks {
		if check.ID == id {
			return check.Status
		}
	}
	return ""
}

func providerDoctorReviewEvidence(report providerDoctorReport) bool {
	switch report.Transport {
	case "xai_acp", "xai_headless_session":
		return qualificationChecksPassed(report.Qualification,
			providerqualification.CheckIdentity, providerqualification.CheckSecretDenied, providerqualification.CheckPushDenied)
	case "zai_native_api":
		if report.Policy.Name == provider.NativeZAIToolsPolicyName {
			return qualificationChecksPassed(report.Qualification, "exact_model_request_id", "protected_path_denial", "shell_and_push_absent")
		}
		return false
	case "zai_codex_runtime":
		return report.Qualification.ModelIdentityVerified && qualificationChecksPassed(report.Qualification,
			providerqualification.CheckIdentity, providerqualification.CheckSecretDenied, providerqualification.CheckPushDenied)
	default:
		return false
	}
}

func providerDoctorWorkspaceEvidence(report providerDoctorReport) bool {
	switch report.Transport {
	case "xai_acp", "xai_headless_session":
		return qualificationChecksPassed(report.Qualification, providerOperationRequiredChecks(report.Transport, providerOperationWorkspaceWrite)...)
	case "zai_codex_runtime":
		return qualificationChecksPassed(report.Qualification, providerOperationRequiredChecks(report.Transport, providerOperationWorkspaceWrite)...)
	case "zai_native_api":
		return report.Policy.Name == provider.NativeZAIToolsPolicyName && qualificationChecksPassed(report.Qualification,
			"exact_model_request_id", "controller_tool_loop", "workspace_edit", "isolated_verification", "protected_path_denial", "shell_and_push_absent")
	default:
		// Unknown transports have no workspace-evidence contract.
		return false
	}
}

func providerDoctorLifecycleEvidence(report providerDoctorReport) bool {
	if !report.Capabilities.LocalLifecycleSupported() {
		return false
	}
	switch report.Transport {
	case "xai_acp", "xai_headless_session", "zai_codex_runtime":
		return qualificationChecksPassed(report.Qualification,
			providerqualification.CheckCrashRecovery, providerqualification.CheckCancellation,
			providerqualification.CheckResume, providerqualification.CheckProcessCleanup)
	default:
		return false
	}
}

func qualificationChecksPassed(qualification providerDoctorQualification, names ...string) bool {
	if !qualification.TrustedCurrent || len(qualification.CheckStates) == 0 {
		return false
	}
	for _, name := range names {
		if !qualification.CheckStates[name] {
			return false
		}
	}
	return true
}

func providerDoctorReady(report providerDoctorReport) bool {
	return providerDoctorPromotionForReport(report, providerOperationLifecycle).RequiredOperationAdmitted
}

func diagnoseZAIClaudeRequestAuthority(capability provider.OperationCapabilities) providerDoctorCheck {
	if capability.RequestCapacityControl == provider.EvidenceAuthoritative && capability.LiveErrorFeedback == provider.EvidenceAuthoritative {
		return providerDoctorCheck{ID: "request_authority", Status: providerDoctorPass, Provenance: "capability_registry", Summary: "per-request capacity/circuit control and live provider error feedback are authoritative"}
	}
	return providerDoctorCheck{
		ID: "request_authority", Status: providerDoctorFail, Provenance: "capability_registry",
		Summary:     fmt.Sprintf("request capacity=%s live error feedback=%s; the Claude-compatible pane runtime is opaque per request", capability.RequestCapacityControl, capability.LiveErrorFeedback),
		Remediation: "Do not treat pane launch admission or a qualification receipt as per-request concurrency/circuit authority; use a provider-native structured transport when one is authorized and qualified",
	}
}

func providerTransportForIdentity(identity provider.Identity) (string, error) {
	switch {
	case identity.Provider() == "xai" && identity.Runtime() == "grok":
		return "xai_acp", nil
	case identity.Provider() == "zai" && identity.Entitlement() == provider.EntitlementClaudeCompat:
		return "zai_claude_runtime", nil
	case identity.Provider() == "zai" && identity.Entitlement() == provider.EntitlementCodexResponses:
		return "zai_codex_runtime", nil
	case identity.Provider() == "zai" && identity.Entitlement() == provider.EntitlementNativeAPI:
		return "zai_native_api", nil
	default:
		return "", fmt.Errorf("unsupported provider/runtime/entitlement combination %s/%s/%s", identity.Provider(), identity.Runtime(), identity.Entitlement())
	}
}

func runProviderDoctorOnlineProbe(ctx context.Context, profile config.ProviderProfileConfig, identity provider.Identity) (providerDoctorLiveEvidence, error) {
	nonce, err := providerDoctorNonce()
	if err != nil {
		return providerDoctorLiveEvidence{}, err
	}
	switch {
	case identity.Provider() == "xai":
		cwd, err := os.Getwd()
		if err != nil {
			return providerDoctorLiveEvidence{}, err
		}
		result, runErr := grok.Run(ctx, grok.OSRunner{}, grok.Request{
			Prompt: "Reply with this exact nonce and no other text: " + nonce, CWD: cwd, Binary: profile.Command,
			RuntimeHome: profile.RuntimeHome, Model: identity.Model(), RuntimeVersion: profile.RuntimeVersion, ExpectedNonce: nonce, AutomationPolicyArgs: agent.GrokAutomationACPPolicyArgs(profile.AutomationPolicy),
		})
		digest := digestSafeJSON(result)
		if runErr != nil {
			return providerDoctorLiveEvidence{SHA256: digest}, runErr
		}
		return providerDoctorLiveEvidence{
			ModelVerified:         result.Model == identity.Model() && grokDoctorModelEvidenceConfirmed(result.ModelEvidence),
			AuthVerified:          result.Success && result.AcknowledgementVerified && result.Authenticated && result.AuthenticationEvidence == "cached_token_authenticate_plus_completed_session",
			RuntimeContractPassed: result.RuntimeEventContract.Passed,
			SHA256:                digest,
		}, nil
	case identity.Provider() == "zai" && identity.Entitlement() == provider.EntitlementClaudeCompat:
		receipt, probeErr := zai.Probe(ctx, zai.ProbeSpec{Binary: profile.Command, Endpoint: identity.Endpoint(), Model: identity.Model()})
		digest := digestSafeJSON(receipt)
		if probeErr != nil {
			return providerDoctorLiveEvidence{SHA256: digest}, probeErr
		}
		return providerDoctorLiveEvidence{ModelVerified: receipt.ModelSessionEvidence && receipt.Model == identity.Model(), AuthVerified: receipt.ModelSessionEvidence, SHA256: digest}, nil
	case identity.Provider() == "zai" && identity.Entitlement() == provider.EntitlementCodexResponses:
		return providerDoctorLiveEvidence{}, errors.New("Z.ai Codex online doctor dispatch is disabled; use provider codex run or provider qualify for admission-controlled, durable, signed execution")
	case identity.Provider() == "zai" && identity.Entitlement() == provider.EntitlementNativeAPI:
		keyBytes, credentialErr := providerCredentialDeps.store.Get(ctx, providerCredentialID(identity))
		if credentialErr != nil || len(keyBytes) == 0 {
			return providerDoctorLiveEvidence{}, errors.New("native Z.ai credential is unavailable from OS-protected storage")
		}
		defer zeroProviderSecret(keyBytes)
		receipt, probeErr := zai.RunNative(ctx, zai.DefaultNativeHTTPClient(), zai.NativeRequest{
			Endpoint: identity.Endpoint(), Model: identity.Model(), Prompt: "Reply with this exact nonce and no other text: " + nonce,
			ExpectedNonce: nonce, ExpectedRequestID: providerDoctorNativeProbeRequestID(identity, nonce), NativeAPIKey: string(keyBytes), ExplicitOptIn: true, AllowTools: false,
		})
		digest := digestSafeJSON(receipt)
		if probeErr != nil {
			return providerDoctorLiveEvidence{SHA256: digest}, probeErr
		}
		return providerDoctorLiveEvidence{ModelVerified: receipt.Model == identity.Model() && receipt.NonceVerified, AuthVerified: receipt.HTTPStatus >= 200 && receipt.HTTPStatus < 300, SHA256: digest}, nil
	default:
		return providerDoctorLiveEvidence{}, errors.New("provider has no online doctor probe")
	}
}

// grokDoctorModelEvidenceConfirmed accepts only model metadata on the terminal
// ACP completion. Session selection and catalog state cannot rule out a
// provider-side remap and therefore cannot establish the served model.
func grokDoctorModelEvidenceConfirmed(evidence string) bool {
	return strings.TrimSpace(evidence) == "completion_metadata"
}

// providerDoctorNativeProbeRequestID uses the same bounded native request-ID
// derivation as a durable operation. The doctor probe has no operation ledger,
// so its random acknowledgement nonce supplies per-probe uniqueness without
// retaining a raw correlation ID.
func providerDoctorNativeProbeRequestID(identity provider.Identity, nonce string) string {
	return providerNativeRequestID(providerNativeBindingHash(identity, "ntm.provider-doctor-native-probe.v1:"+nonce), "doctor:"+nonce)
}

func providerDoctorInspectionCWD() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return cwd
}

func sameProviderRequirementsPath(actual, expected string) bool {
	actual, expected = filepath.Clean(strings.TrimSpace(actual)), filepath.Clean(strings.TrimSpace(expected))
	if actual == "." || expected == "." {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(actual, expected)
	}
	return actual == expected
}

func providerRuntimeInspectGrok(ctx context.Context, binary, cwd, runtimeHome string) (providerGrokInspection, error) {
	if ctx == nil || strings.TrimSpace(binary) == "" {
		return providerGrokInspection{}, errors.New("Grok runtime inspection requires a context and binary")
	}
	cmd := exec.CommandContext(ctx, binary, "--no-auto-update", "inspect", "--json")
	env, err := grok.IsolatedProcessEnvironment(os.Environ(), runtimeHome, false)
	if err != nil {
		return providerGrokInspection{}, err
	}
	cmd.Env = env
	if strings.TrimSpace(cwd) != "" {
		cmd.Dir = cwd
	}
	const maxInspectBytes = 1 << 20
	capture := &providerCappedOutput{limit: maxInspectBytes}
	cmd.Stdout = capture
	cmd.Stderr = io.Discard
	err = cmd.Run()
	if err != nil {
		return providerGrokInspection{}, err
	}
	output := capture.Bytes()
	if len(output) == 0 || capture.exceeded {
		return providerGrokInspection{}, errors.New("Grok runtime inspection output was empty or exceeded its limit")
	}
	return parseProviderRuntimeInspectGrok(output)
}

func parseProviderRuntimeInspectGrok(output []byte) (providerGrokInspection, error) {
	var envelope struct {
		GrokVersion string `json:"grokVersion"`
		Permissions struct {
			Loaded  json.RawMessage `json:"loaded"`
			Sources []string        `json:"sources"`
		} `json:"permissions"`
		ConfigSources struct {
			Layers []struct {
				Role string `json:"role"`
				Path string `json:"path"`
				Note string `json:"note"`
			} `json:"layers"`
		} `json:"configSources"`
		Hooks          []json.RawMessage `json:"hooks"`
		Plugins        []json.RawMessage `json:"plugins"`
		Marketplaces   []json.RawMessage `json:"marketplaces"`
		MCPServers     []json.RawMessage `json:"mcpServers"`
		ExternalCompat struct {
			Cells []struct {
				Vendor  string `json:"vendor"`
				Surface string `json:"surface"`
				Enabled bool   `json:"enabled"`
			} `json:"cells"`
		} `json:"externalCompat"`
		ConfigWarnings []json.RawMessage `json:"configWarnings"`
	}
	if err := json.Unmarshal(output, &envelope); err != nil {
		return providerGrokInspection{}, errors.New("Grok runtime inspection returned invalid JSON")
	}
	if strings.TrimSpace(envelope.GrokVersion) == "" {
		return providerGrokInspection{}, errors.New("Grok runtime inspection omitted its version")
	}
	loaded, err := providerGrokPermissionsLoaded(envelope.Permissions.Loaded)
	if err != nil {
		return providerGrokInspection{}, err
	}
	inspection := providerGrokInspection{
		GrokVersion:       strings.TrimSpace(envelope.GrokVersion),
		PermissionsLoaded: loaded,
		PermissionSources: append([]string(nil), envelope.Permissions.Sources...),
		MCPServerCount:    len(envelope.MCPServers),
		HookCount:         len(envelope.Hooks),
		PluginCount:       len(envelope.Plugins),
		MarketplaceCount:  len(envelope.Marketplaces),
		SHA256:            sha256TextCLI(output),
	}
	for _, layer := range envelope.ConfigSources.Layers {
		inspection.ConfigSources = append(inspection.ConfigSources, providerGrokConfigSource{Role: strings.TrimSpace(layer.Role), Path: filepath.Clean(strings.TrimSpace(layer.Path)), Note: strings.TrimSpace(layer.Note)})
		if strings.TrimSpace(layer.Role) == "system-requirements" {
			inspection.SystemRequirementsLayerPresent = true
		}
	}
	for _, cell := range envelope.ExternalCompat.Cells {
		vendor := strings.ToLower(strings.TrimSpace(cell.Vendor))
		surface := strings.ToLower(strings.TrimSpace(cell.Surface))
		if cell.Enabled && (vendor == "claude" || vendor == "cursor") && surface != "sessions" {
			inspection.UnsafeCompatibilityEnabled = true
		}
	}
	for _, warning := range envelope.ConfigWarnings {
		text := strings.ToLower(string(warning))
		if strings.Contains(text, "ui.disable_bypass_permissions_mode") && (strings.Contains(text, "unknown") || strings.Contains(text, "unrecognized")) {
			inspection.BypassLockWarning = true
			continue
		}
		inspection.UnexpectedConfigWarning = true
	}
	return inspection, nil
}

func providerGrokInspectionIsolated(inspection providerGrokInspection, runtimeHome, requirementsPath string) bool {
	runtimeHome = filepath.Clean(strings.TrimSpace(runtimeHome))
	requirementsPath = filepath.Clean(strings.TrimSpace(requirementsPath))
	if !filepath.IsAbs(runtimeHome) || runtimeHome == "." || inspection.MCPServerCount != 0 || inspection.HookCount != 0 || inspection.PluginCount != 0 || inspection.MarketplaceCount != 0 || inspection.UnsafeCompatibilityEnabled || inspection.UnexpectedConfigWarning {
		return false
	}
	seenSystemRequirements := false
	for _, source := range inspection.ConfigSources {
		role, path, note := strings.TrimSpace(source.Role), filepath.Clean(strings.TrimSpace(source.Path)), strings.TrimSpace(source.Note)
		switch role {
		case "system-requirements":
			if !sameProviderRequirementsPath(path, requirementsPath) {
				return false
			}
			seenSystemRequirements = true
		case "managed", "user", "requirements":
			// Grok 1.0.13 enumerates these three absent lower-priority files with
			// note="empty". Accept only those exact empty slots below the isolated
			// GROK_HOME; any loaded or differently located mutable config fails.
			expectedName := map[string]string{"managed": "managed_config.toml", "user": "config.toml", "requirements": "requirements.toml"}[role]
			if note != "empty" || path != filepath.Join(runtimeHome, expectedName) {
				return false
			}
		default:
			// In particular, a project .grok/config.toml may add MCP servers,
			// plugins, and permission rules after profile review.
			return false
		}
	}
	return seenSystemRequirements
}

// providerGrokPermissionsLoaded accepts the pre-1.0.13 boolean shape and the
// current count shape. A positive count is required: a present but empty
// permission source list is never authority evidence.
func providerGrokPermissionsLoaded(raw json.RawMessage) (bool, error) {
	var boolean bool
	if err := json.Unmarshal(raw, &boolean); err == nil {
		return boolean, nil
	}
	var count int
	if err := json.Unmarshal(raw, &count); err == nil && count >= 0 {
		return count > 0, nil
	}
	return false, errors.New("Grok runtime inspection returned an invalid permissions.loaded value")
}

func hasProviderSystemRequirementsSource(sources []string, path string) bool {
	want := filepath.Clean(path) + " (system requirements)"
	for _, source := range sources {
		if strings.TrimSpace(source) == want {
			return true
		}
	}
	return false
}

func providerRuntimeVersion(ctx context.Context, binary string) (string, error) {
	cmd := exec.CommandContext(ctx, binary, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	if len(output) > 4096 {
		return "", errors.New("provider runtime version output exceeded limit")
	}
	line := strings.TrimSpace(strings.SplitN(string(output), "\n", 2)[0])
	if line == "" || strings.IndexFunc(line, func(r rune) bool { return r < 0x20 && r != '\t' }) >= 0 {
		return "", errors.New("provider runtime returned an invalid version line")
	}
	if len(line) > 256 {
		line = line[:256]
	}
	return line, nil
}

func versionMatches(actual, expected string) bool {
	actual, expected = strings.TrimSpace(actual), strings.TrimSpace(expected)
	if actual == expected {
		return true
	}
	for _, token := range strings.Fields(actual) {
		if token == expected {
			return true
		}
	}
	return false
}

func providerDoctorNonce() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	// Grok's native acknowledgement validator requires the NTM_ACK_ prefix;
	// the same high-entropy token is also valid for the Z.ai probes.
	return "NTM_ACK_" + hex.EncodeToString(raw), nil
}

func providerRequirementsPath() string {
	if runtime.GOOS == "windows" {
		base := strings.TrimSpace(os.Getenv("ProgramData"))
		if base == "" {
			base = `C:\\ProgramData`
		}
		return filepath.Join(base, "grok", "requirements.toml")
	}
	return "/etc/grok/requirements.toml"
}

func replaceProviderDoctorCheck(checks []providerDoctorCheck, replacement providerDoctorCheck) {
	for i := range checks {
		if checks[i].ID == replacement.ID {
			checks[i] = replacement
			return
		}
	}
}

func encodeIndentedJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func printProviderDoctorHuman(w io.Writer, report providerDoctorReport) {
	fmt.Fprintf(w, "Provider promotion: %s\n", report.Promotion.Level)
	fmt.Fprintf(w, "Required operation: %s (admitted=%t)\n", report.Promotion.RequiredOperation, report.Promotion.RequiredOperationAdmitted)
	for _, scope := range report.Promotion.Scopes {
		fmt.Fprintf(w, "  %-15s admitted=%t (%s)\n", scope.Operation, scope.Admitted, scope.Evidence)
	}
	fmt.Fprintf(w, "Profile: %s (%s)\n", report.Profile, report.Transport)
	fmt.Fprintf(w, "Identity: %s\n", report.Identity.SHA256)
	fmt.Fprintf(w, "Policy: %s (%s)\n", report.Policy.Name, report.Policy.SHA256)
	fmt.Fprintf(w, "Qualification: %s (%d/%d checks)\n", report.Qualification.State, report.Qualification.ChecksPassed, report.Qualification.ChecksTotal)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "STATUS\tCHECK\tEVIDENCE\tSUMMARY")
	for _, check := range report.Checks {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", strings.ToUpper(string(check.Status)), check.ID, check.Provenance, check.Summary)
		if check.Remediation != "" {
			fmt.Fprintf(w, "  next: %s\n", check.Remediation)
		}
	}
}

func digestSafeJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return safeErrorDigest(err)
	}
	return sha256TextCLI(data)
}

func sha256TextCLI(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func sha256StringCLI(value string) string { return sha256TextCLI([]byte(value)) }

func safeErrorDigest(err error) string {
	if err == nil {
		return ""
	}
	return sha256StringCLI(err.Error())
}

func providerCommandContext(cmd *cobra.Command) context.Context {
	if cmd != nil && cmd.Context() != nil {
		return cmd.Context()
	}
	return context.Background()
}
