package cli

import (
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
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/agent"
	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/grok"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providertelemetry"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
)

const providerSessionSchema = "ntm.provider-session.v2"

type providerSessionOptions struct {
	profile   string
	sessionID string
	cwd       string
	prompt    string
	timeout   time.Duration
}

type providerSessionAdmission interface {
	Acquire(provider.Identity) ratelimit.Decision
	Release(provider.Identity, ratelimit.Decision)
	RecordSuccess(provider.Identity)
	CapacityStatus() ratelimit.CapacityStatus
}

type providerSessionDependencies struct {
	loadConfig           func() *config.Config
	lookPath             func(string) (string, error)
	version              func(context.Context, string) (string, error)
	readFile             func(string) ([]byte, error)
	stat                 func(string) (os.FileInfo, error)
	rootOwned            func(os.FileInfo) bool
	trustExecutable      func(string) (string, error)
	readRequirements     func(string) ([]byte, os.FileInfo, error)
	inspectGrok          func(context.Context, string, string) (providerGrokInspection, error)
	probeGrokBypassLock  func(context.Context, string) (providerGrokBypassProbe, error)
	isLinkedWorktree     func(context.Context, string) (bool, error)
	attestationPreflight func(context.Context) error
	sign                 func(context.Context, []byte) (providerattestation.SignatureMetadata, error)
	hashBinary           func(string) (string, error)
	recordTelemetry      func(context.Context, providertelemetry.Observation) (providertelemetry.Observation, error)
	run                  func(context.Context, grok.LifecycleRunner, grok.SessionRequest) (grok.SessionReceipt, error)
	runner               grok.LifecycleRunner
	admission            providerSessionAdmission
	now                  func() time.Time
}

var providerSessionDeps = providerSessionDependencies{
	loadConfig:           loadSelectedConfigOrDefault,
	lookPath:             exec.LookPath,
	version:              providerRuntimeVersion,
	readFile:             os.ReadFile,
	stat:                 os.Stat,
	rootOwned:            providerRequirementsRootOwned,
	trustExecutable:      providerSystemAuthoritativeExecutable,
	readRequirements:     providerRequirementsReadForDoctor,
	inspectGrok:          providerRuntimeInspectGrok,
	probeGrokBypassLock:  providerRuntimeProbeGrokBypassLock,
	isLinkedWorktree:     providerIsLinkedGitWorktree,
	attestationPreflight: providerSessionAttestationPreflight,
	sign:                 signProviderReceiptPayload,
	hashBinary:           hashProviderSessionExecutable,
	recordTelemetry:      recordProviderTelemetryDefault,
	run:                  grok.ExecuteSession,
	runner:               grok.HeadlessOSRunner{},
	admission:            ratelimit.DefaultAdmissionController(),
	now:                  func() time.Time { return time.Now().UTC() },
}

type providerSessionAdmissionEvidence struct {
	Allowed              bool                          `json:"allowed"`
	Reason               ratelimit.ErrorClass          `json:"reason,omitempty"`
	RetryAt              *time.Time                    `json:"retry_at,omitempty"`
	NoFailover           bool                          `json:"no_failover"`
	CapacityControlScope provider.CapacityControlScope `json:"capacity_control_scope"`
}

type providerSessionOutput struct {
	SchemaVersion  string                                 `json:"schema_version"`
	Success        bool                                   `json:"success"`
	Profile        string                                 `json:"profile"`
	Transport      string                                 `json:"transport"`
	IdentitySHA256 string                                 `json:"identity_sha256"`
	Policy         string                                 `json:"policy"`
	PolicySHA256   string                                 `json:"policy_sha256"`
	ConfigSHA256   string                                 `json:"config_sha256"`
	BinarySHA256   string                                 `json:"binary_sha256"`
	CWD_SHA256     string                                 `json:"cwd_sha256"`
	WorktreeSHA256 string                                 `json:"worktree_sha256"`
	Dispatched     bool                                   `json:"dispatched"`
	Admission      providerSessionAdmissionEvidence       `json:"admission"`
	Receipt        grok.SessionReceipt                    `json:"receipt"`
	FailureCode    grok.ErrorCode                         `json:"failure_code,omitempty"`
	ErrorSHA256    string                                 `json:"error_sha256,omitempty"`
	Telemetry      providerTelemetryEvidence              `json:"telemetry"`
	Attestation    *providerattestation.SignatureMetadata `json:"attestation,omitempty"`
}

func newProviderSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Resume or fork an exact native Grok headless session",
	}
	cmd.AddCommand(newProviderSessionActionCmd(grok.SessionResume), newProviderSessionActionCmd(grok.SessionFork))
	return cmd
}

func newProviderSessionActionCmd(action grok.SessionAction) *cobra.Command {
	opts := providerSessionOptions{cwd: ".", timeout: 10 * time.Minute}
	actionName := string(action)
	actionTitle := strings.ToUpper(actionName[:1]) + actionName[1:]
	cmd := &cobra.Command{
		Use:   actionName,
		Short: fmt.Sprintf("%s a native Grok headless session with a nonce-bound receipt", actionTitle),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProviderSession(cmd, action, opts, providerSessionDeps)
		},
	}
	cmd.Flags().StringVar(&opts.profile, "profile", "", "Exact configured Grok provider profile (required)")
	cmd.Flags().StringVar(&opts.sessionID, "session-id", "", "Provider session identifier to resume (required; never echoed)")
	cmd.Flags().StringVar(&opts.cwd, "cwd", opts.cwd, "Working directory for the provider session")
	cmd.Flags().StringVar(&opts.prompt, "prompt", "", "Prompt to execute (required; never retained)")
	cmd.Flags().DurationVar(&opts.timeout, "timeout", opts.timeout, "Bounded provider operation timeout")
	return cmd
}

func runProviderSession(cmd *cobra.Command, action grok.SessionAction, opts providerSessionOptions, deps providerSessionDependencies) error {
	if strings.TrimSpace(opts.profile) == "" || strings.TrimSpace(opts.sessionID) == "" || strings.TrimSpace(opts.prompt) == "" {
		return errors.New("provider session requires exact --profile, --session-id, and --prompt values")
	}
	if opts.timeout <= 0 {
		return errors.New("provider session timeout must be positive")
	}
	if deps.loadConfig == nil || deps.lookPath == nil || deps.trustExecutable == nil || deps.version == nil || (deps.readRequirements == nil && (deps.readFile == nil || deps.stat == nil)) || deps.rootOwned == nil || deps.inspectGrok == nil || deps.probeGrokBypassLock == nil || deps.isLinkedWorktree == nil || deps.attestationPreflight == nil || deps.sign == nil || deps.hashBinary == nil || deps.recordTelemetry == nil || deps.run == nil || deps.runner == nil || deps.admission == nil || deps.now == nil {
		return errors.New("provider session dependencies are incomplete")
	}

	cfg := deps.loadConfig()
	if cfg == nil {
		return errors.New("provider session requires loaded configuration")
	}
	profile, err := cfg.ProviderProfile(opts.profile)
	if err != nil {
		return err
	}
	identity, err := profile.Identity()
	if err != nil {
		return err
	}
	if identity.Provider() != "xai" || identity.Runtime() != "grok" {
		return errors.New("provider session resume/fork requires an exact native Grok profile")
	}
	policy, ok := agent.GrokAutomationPolicy(profile.AutomationPolicy)
	if !ok {
		return errors.New("provider session profile names an unsupported Grok policy")
	}
	cwd, err := filepath.Abs(opts.cwd)
	if err != nil {
		return fmt.Errorf("resolve provider session working directory: %w", err)
	}
	info, err := os.Stat(cwd)
	if err != nil || !info.IsDir() {
		return errors.New("provider session working directory must be an existing directory")
	}
	if profile.AutomationPolicy == agent.GrokWorkspaceWritePolicyName {
		checkCtx, cancel := context.WithTimeout(providerCommandContext(cmd), 5*time.Second)
		linked, checkErr := deps.isLinkedWorktree(checkCtx, cwd)
		cancel()
		if checkErr != nil || !linked {
			return errors.New("workspace-write Grok sessions require a linked disposable Git worktree")
		}
	}
	locatedBinary, err := deps.lookPath(profile.Command)
	if err != nil {
		return fmt.Errorf("locate configured Grok runtime: %w", err)
	}
	binary, err := deps.trustExecutable(locatedBinary)
	if err != nil {
		return fmt.Errorf("configured Grok runtime is not system-authoritative: %w", err)
	}
	commandCtx := providerCommandContext(cmd)
	versionCtx, versionCancel := context.WithTimeout(commandCtx, 5*time.Second)
	actualVersion, err := deps.version(versionCtx, binary)
	versionCancel()
	if err != nil {
		return fmt.Errorf("read configured Grok runtime version: %w", err)
	}
	if profile.RuntimeVersion == "" || !versionMatches(actualVersion, profile.RuntimeVersion) {
		return errors.New("configured Grok runtime is unpinned or has drifted")
	}
	binarySHA256, err := deps.hashBinary(binary)
	if err != nil {
		return fmt.Errorf("hash configured Grok runtime: %w", err)
	}
	attestedProfile := profile
	attestedProfile.Command = binary
	policyResult, policyCheck := diagnoseProviderPolicy(commandCtx, cwd, attestedProfile, identity, providerDoctorDependencies{
		lookPath: func(string) (string, error) { return binary, nil },
		readFile: deps.readFile, stat: deps.stat, rootOwned: deps.rootOwned, readRequirements: deps.readRequirements,
		inspectGrok: deps.inspectGrok, probeGrokBypassLock: deps.probeGrokBypassLock,
	})
	if policyCheck.Status != providerDoctorPass || !policyResult.BypassLockAuthoritative {
		return errors.New("root-owned Grok managed requirements are missing, mismatched, or not authoritative")
	}
	status := deps.admission.CapacityStatus()
	if status.Scope != provider.CapacityControlScopeLocalShared {
		return errors.New("provider session requires the cross-process local shared capacity store")
	}
	output := providerSessionOutput{
		SchemaVersion: providerSessionSchema, Profile: opts.profile, Transport: "xai_headless_session",
		IdentitySHA256: identity.Hash(), Policy: policy.Name, PolicySHA256: agent.GrokAutomationPolicySHA256(policy.Name),
		ConfigSHA256: identity.ConfigSHA256(), BinarySHA256: binarySHA256,
		CWD_SHA256: sha256StringCLI(filepath.Clean(cwd)), WorktreeSHA256: sha256StringCLI(filepath.Clean(cwd)),
	}
	// Signing capability must be available before the provider can receive a
	// prompt. Attestation keys are initialized only by `provider attestation
	// init`; this preflight never creates a key during a live session run.
	if err := deps.attestationPreflight(commandCtx); err != nil {
		output.FailureCode = grok.ErrProvider
		output.ErrorSHA256 = safeErrorDigest(err)
		return finishProviderSession(cmd, output, errors.New("provider session requires a ready OS-protected receipt attestation key before dispatch"))
	}
	decision := deps.admission.Acquire(identity)
	output.Admission = providerSessionAdmissionEvidence{
		Allowed: decision.Allowed, Reason: decision.Reason, RetryAt: decision.RetryAt,
		NoFailover: decision.NoFailover, CapacityControlScope: status.Scope,
	}
	if !decision.Allowed || !decision.NoFailover {
		output.FailureCode = grok.ErrProvider
		output.ErrorSHA256 = sha256StringCLI(string(decision.Reason) + fmt.Sprint(decision.NoFailover))
		if decision.Allowed {
			deps.admission.Release(identity, decision)
		}
		return finishProviderSession(cmd, output, errors.New("provider capacity admission denied for the exact Grok identity"))
	}
	defer deps.admission.Release(identity, decision)

	nonce, err := providerSessionNonce()
	if err != nil {
		return err
	}
	transmittedPrompt := strings.TrimSpace(opts.prompt) + "\n\nWhen finished, return this exact acknowledgement token as the final result and no other final text: " + nonce
	runCtx, runCancel := context.WithTimeout(commandCtx, opts.timeout)
	startedAt := deps.now()
	output.Dispatched = true
	receipt, runErr := deps.run(runCtx, deps.runner, grok.SessionRequest{
		Action: action, SessionID: opts.sessionID, Prompt: transmittedPrompt, CWD: cwd,
		Worktree: cwd, Binary: binary, Model: identity.Model(), RuntimeVersion: profile.RuntimeVersion, ExpectedNonce: nonce,
		PolicySHA256: output.PolicySHA256, ConfigSHA256: output.ConfigSHA256, BinarySHA256: output.BinarySHA256,
		// Grok binds sessions to their original sandbox. The root-owned managed
		// requirements above remain authoritative; lifecycle invocations retain
		// every reviewed permission rule but let Grok inherit that bound sandbox.
		PolicyArgs: agent.GrokAutomationLifecyclePolicyArgs(policy.Name),
	})
	runCancel()
	completedAt := deps.now()
	output.Receipt = receipt
	if runErr != nil {
		var typed *grok.Error
		if errors.As(runErr, &typed) {
			output.FailureCode = typed.Code
		}
		if output.FailureCode == "" {
			output.FailureCode = grok.ErrProvider
		}
		output.ErrorSHA256 = safeErrorDigest(runErr)
		output.Telemetry = recordProviderTelemetryEvidence(commandCtx, deps.recordTelemetry, providerSessionTelemetryObservation(identity, output.PolicySHA256, profile.RuntimeVersion, receipt, provider.ErrorUnknown, "unchanged", startedAt, completedAt))
		if err := sealProviderSessionOutput(commandCtx, &output, deps.sign); err != nil {
			output.ErrorSHA256 = safeErrorDigest(err)
			return finishProviderSession(cmd, output, errors.New("Grok session failed and its execution receipt could not be attested"))
		}
		return finishProviderSession(cmd, output, runErr)
	}
	output.Success = true
	output.Telemetry = recordProviderTelemetryEvidence(commandCtx, deps.recordTelemetry, providerSessionTelemetryObservation(identity, output.PolicySHA256, profile.RuntimeVersion, receipt, "", "closed", startedAt, completedAt))
	if err := sealProviderSessionOutput(commandCtx, &output, deps.sign); err != nil {
		output.Success = false
		output.FailureCode = grok.ErrProvider
		output.ErrorSHA256 = safeErrorDigest(err)
		return finishProviderSession(cmd, output, errors.New("Grok session completed but its receipt could not be attested"))
	}
	deps.admission.RecordSuccess(identity)
	return finishProviderSession(cmd, output, nil)
}

func finishProviderSession(cmd *cobra.Command, output providerSessionOutput, runErr error) error {
	if (output.Attestation != nil && !validProviderSessionOutput(output)) || (output.Success && output.Attestation == nil) {
		return errors.New("Grok session receipt attestation is invalid")
	}
	if IsJSONOutput() {
		if err := encodeIndentedJSON(cmd.OutOrStdout(), output); err != nil {
			return err
		}
		if runErr != nil {
			return errJSONFailure
		}
		return nil
	}
	if output.Success {
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Grok session %s completed with nonce-bound lineage.\n", output.Receipt.Action); err != nil {
			return err
		}
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "Identity: %s\nChild session hash: %s\n", output.IdentitySHA256, output.Receipt.ChildSessionSHA256)
		return err
	}
	code := output.FailureCode
	if code == "" {
		code = grok.ErrProvider
	}
	return &providerSessionExitError{code: code}
}

// providerSessionAttestationPreflight proves that the explicitly initialized
// OS-protected signing key is readable and produces verifiable signatures
// before any provider process receives a prompt. The fixed payload contains no
// session data and the probe signature is discarded.
func providerSessionAttestationPreflight(ctx context.Context) error {
	return providerSessionAttestationPreflightWithSigner(ctx, signProviderReceiptPayload)
}

func providerSessionAttestationPreflightWithSigner(ctx context.Context, sign func(context.Context, []byte) (providerattestation.SignatureMetadata, error)) error {
	if sign == nil {
		return errors.New("provider session receipt attestor is unavailable")
	}
	payload := []byte(providerattestation.ProviderAttestationPreflight)
	signature, err := sign(ctx, payload)
	if err != nil {
		return err
	}
	if err := providerattestation.Verify(payload, signature); err != nil {
		return errors.New("provider session attestation preflight verification failed")
	}
	return nil
}

func sealProviderSessionOutput(ctx context.Context, output *providerSessionOutput, sign func(context.Context, []byte) (providerattestation.SignatureMetadata, error)) error {
	if output == nil || sign == nil || !output.Dispatched {
		return errors.New("Grok session receipt attestor is unavailable")
	}
	payload, err := canonicalProviderSessionOutput(*output)
	if err != nil {
		return err
	}
	signature, err := sign(ctx, payload)
	if err != nil {
		return err
	}
	if err := providerattestation.Verify(payload, signature); err != nil {
		return errors.New("Grok session receipt attestation verification failed")
	}
	output.Attestation = &signature
	return nil
}

// validProviderSessionOutput is the read-side verification boundary for a
// completed JSON receipt. There is no durable session replay store yet, so it
// is applied immediately before output and remains available to a future
// reader without trusting a decoded receipt by default.
func validProviderSessionOutput(output providerSessionOutput) bool {
	if output.Attestation == nil || !output.Dispatched || output.SchemaVersion != providerSessionSchema || output.Transport != "xai_headless_session" || !validProviderTelemetryEvidence(output.Telemetry) {
		return false
	}
	if output.Success {
		if output.FailureCode != "" || output.ErrorSHA256 != "" {
			return false
		}
	} else if output.FailureCode == "" || output.ErrorSHA256 == "" {
		return false
	}
	if output.Receipt.CWDSHA256 != output.CWD_SHA256 || output.Receipt.WorktreeSHA256 != output.WorktreeSHA256 || output.Receipt.PolicySHA256 != output.PolicySHA256 || output.Receipt.ConfigSHA256 != output.ConfigSHA256 || output.Receipt.BinarySHA256 != output.BinarySHA256 {
		return false
	}
	payload, err := canonicalProviderSessionOutput(output)
	return err == nil && providerattestation.Verify(payload, *output.Attestation) == nil
}

func providerSessionTelemetryObservation(identity provider.Identity, policySHA256, runtimeVersion string, receipt grok.SessionReceipt, class provider.ErrorClass, circuitState string, startedAt, completedAt time.Time) providertelemetry.Observation {
	inputTokens, outputTokens := int64(0), int64(0)
	if receipt.Usage != nil {
		inputTokens = nativeUsageValue(receipt.Usage.InputTokens)
		outputTokens = nativeUsageValue(receipt.Usage.OutputTokens)
	}
	return providerTelemetryObservation(providerTelemetryObservationInput{
		Identity: identity, Model: identity.Model(), Transport: "xai_headless_session", Adapter: "grok-headless-v1", Runtime: runtimeVersion,
		PolicySHA256: policySHA256, FixtureVersion: "grok-headless-1.0.13-v1", StartedAt: startedAt, CompletedAt: completedAt,
		InputTokens: inputTokens, OutputTokens: outputTokens, ProviderError: class, QuotaState: "unknown", CircuitState: circuitState, NoFailover: true,
	})
}

func hashProviderSessionExecutable(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func canonicalProviderSessionOutput(output providerSessionOutput) ([]byte, error) {
	output.Attestation = nil
	return json.Marshal(output)
}

type providerSessionExitError struct{ code grok.ErrorCode }

func (e *providerSessionExitError) Error() string {
	return "Grok session operation failed: " + string(e.code)
}
func (*providerSessionExitError) ExitCode() int { return 1 }

func providerSessionNonce() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate provider session nonce: %w", err)
	}
	return "NTM_ACK_" + hex.EncodeToString(raw), nil
}

func providerIsLinkedGitWorktree(ctx context.Context, cwd string) (bool, error) {
	if ctx == nil || strings.TrimSpace(cwd) == "" {
		return false, errors.New("context and working directory are required")
	}
	gitDir, err := providerGitPath(ctx, cwd, "--absolute-git-dir")
	if err != nil {
		return false, err
	}
	commonDir, err := providerGitPath(ctx, cwd, "--git-common-dir")
	if err != nil {
		return false, err
	}
	if !filepath.IsAbs(commonDir) {
		commonDir, err = filepath.Abs(filepath.Join(cwd, commonDir))
		if err != nil {
			return false, err
		}
	}
	return filepath.Clean(gitDir) != filepath.Clean(commonDir), nil
}

func providerGitPath(ctx context.Context, cwd, flag string) (string, error) {
	command := exec.CommandContext(ctx, "git", "-C", cwd, "rev-parse", flag)
	output, err := command.Output()
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(output))
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("git returned an invalid worktree path")
	}
	return value, nil
}
