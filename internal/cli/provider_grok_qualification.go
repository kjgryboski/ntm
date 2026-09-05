package cli

import (
	"bufio"
	"bytes"
	"context"
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
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
)

// providerGrokQualificationDependencies keeps each exact-policy producer
// injectable without weakening the shared receipt semantics.
type providerGrokQualificationDependencies struct {
	authority                func(context.Context, string, config.ProviderProfileConfig, provider.Identity) (string, error)
	version                  func(context.Context, string) (string, error)
	run                      func(context.Context, grok.Runner, grok.Request) (grok.Result, error)
	runSession               func(context.Context, grok.LifecycleRunner, grok.SessionRequest) (grok.SessionReceipt, error)
	sessionRunner            grok.LifecycleRunner
	prepareLineage           func(context.Context, string) (providerGrokLineageWorkspace, error)
	prepareWorkspace         func(context.Context, string) (providerGrokLineageWorkspace, error)
	cleanupLineage           func(context.Context, providerGrokLineageWorkspace) error
	workspaceBroker          func(context.Context, string, string) (*grok.WorkspaceBrokerDescriptor, error)
	workspaceRevision        func(context.Context, string) (string, error)
	createWorkspaceAudit     func(string, string) (*os.File, error)
	readWorkspaceFile        func(string) ([]byte, error)
	readWorkspaceAudit       func(*os.File, string, string, string) (providerGrokWorkspaceAudit, error)
	hashBinary               func(string) (string, error)
	store                    func(string, providerqualification.Receipt) (string, error)
	sign                     func(context.Context, *providerqualification.Receipt) error
	preflight                func(context.Context) error
	pinnedSigner             func(config.ProviderProfileConfig) (func(context.Context, []byte) (providerattestation.SignatureMetadata, error), error)
	admission                providerDoctorAdmission
	now                      func() time.Time
	getwd                    func() (string, error)
	newNonce                 func() (string, error)
	storeProtocolDiagnostic  func(string, string, string, time.Time, time.Time, string, provider.ProtocolObservation) (string, error)
	storeWorkspaceDiagnostic func(string, string, string, time.Time, time.Time, providerqualification.WorkspaceDiagnostic) (string, error)
}

var providerGrokQualificationDeps = providerGrokQualificationDependencies{
	storeWorkspaceDiagnostic: func(identity, policy, runtime string, started, observed time.Time, observation providerqualification.WorkspaceDiagnostic) (string, error) {
		return providerqualification.StoreWorkspaceDiagnostics("", "xai_acp", identity, policy, runtime, started, observed, observation)
	},
	authority: func(ctx context.Context, cwd string, profile config.ProviderProfileConfig, identity provider.Identity) (string, error) {
		return verifyGrokACPDispatchAuthority(ctx, cwd, profile, identity, providerDoctorDeps)
	},
	version:          providerRuntimeVersion,
	run:              runBudgetedGrok,
	runSession:       runBudgetedGrokSession,
	sessionRunner:    grok.HeadlessOSRunner{},
	prepareLineage:   prepareProviderGrokLineageWorkspace,
	prepareWorkspace: prepareProviderGrokWorkspaceQualification,
	cleanupLineage:   cleanupProviderGrokLineageWorkspace,
	workspaceBroker:  providerGrokControllerBrokerDescriptor,
	workspaceRevision: func(ctx context.Context, worktree string) (string, error) {
		return providerGrokQualificationGit(ctx, worktree, "rev-parse", "--verify", "HEAD")
	},
	createWorkspaceAudit: createProviderGrokWorkspaceAudit,
	readWorkspaceFile:    os.ReadFile,
	readWorkspaceAudit:   readProviderGrokWorkspaceAudit,
	hashBinary:           hashProviderSessionExecutable,
	store:                providerqualification.Store,
	sign:                 signProviderQualificationReceipt,
	preflight: func(ctx context.Context) error {
		_, err := preflightProviderGrokReceiptSignerMetadata(ctx, signProviderReceiptPayload)
		return err
	},
	pinnedSigner: providerGrokPinnedSigner,
	admission:    ratelimit.DefaultAdmissionController(),
	now:          func() time.Time { return time.Now().UTC() },
	getwd:        os.Getwd,
	newNonce:     providerDoctorNonce,
	storeProtocolDiagnostic: func(identity, policy, runtime string, started, observed time.Time, phase string, observation provider.ProtocolObservation) (string, error) {
		return providerqualification.StoreProtocolDiagnostics("", identity, policy, runtime, started, observed, phase, observation)
	},
}

// runProviderGrokQualification produces a signed, transport-specific xai_acp
// receipt. The observe policy remains a no-tool probe. The distinct managed
// workspace-write policy uses a disposable linked worktree and the audited,
// controller-owned MCP broker; evidence is never merged across identities.
func runProviderGrokQualification(cmd *cobra.Command, opts providerQualificationOptions, profile config.ProviderProfileConfig, identity provider.Identity, deps providerGrokQualificationDependencies) error {
	workspaceWrite := profile.AutomationPolicy == agent.GrokWorkspaceWritePolicyName
	if identity.Provider() != "xai" || identity.Runtime() != "grok" || (!workspaceWrite && profile.AutomationPolicy != agent.DefaultGrokAutomationPolicyName) {
		return errors.New("Grok qualification requires an exact xAI/Grok profile using a reviewed managed policy")
	}
	if opts.identityOnly || opts.exerciseUnknownOutcomeLifecycle || opts.acceptFullWeekReservation {
		return errors.New("Grok qualification does not accept Codex identity or lifecycle-risk modes")
	}
	if workspaceWrite && opts.grokHeadlessLineage {
		return errors.New("Grok workspace-write and headless-lineage qualifications are separate exact-policy producers")
	}
	if deps.authority == nil || deps.version == nil || deps.run == nil || deps.hashBinary == nil || deps.store == nil || deps.sign == nil || deps.preflight == nil || deps.admission == nil || deps.now == nil || deps.getwd == nil || deps.newNonce == nil {
		return errors.New("Grok qualification dependencies are incomplete")
	}
	if strings.TrimSpace(profile.RuntimeVersion) == "" {
		return errors.New("Grok qualification requires a reviewed runtime_version pin")
	}
	commandCtx := providerCommandContext(cmd)
	signReceipt := deps.sign
	preflight := deps.preflight
	if deps.pinnedSigner != nil {
		signPayload, err := deps.pinnedSigner(profile)
		if err != nil {
			return fmt.Errorf("Grok qualification profile-pinned receipt signer is unavailable: %w", err)
		}
		signReceipt = func(ctx context.Context, receipt *providerqualification.Receipt) error {
			return signProviderQualificationReceiptWith(ctx, receipt, signPayload)
		}
		preflight = func(ctx context.Context) error {
			_, err := preflightProviderGrokReceiptSignerMetadata(ctx, signPayload)
			return err
		}
	}
	if err := preflight(commandCtx); err != nil {
		return fmt.Errorf("Grok qualification requires an initialized receipt signing key before dispatch: %w", err)
	}
	cwd, err := deps.getwd()
	if err != nil || strings.TrimSpace(cwd) == "" {
		return errors.New("Grok qualification requires an accessible current working directory")
	}
	binary, err := deps.authority(commandCtx, cwd, profile, identity)
	if err != nil {
		return fmt.Errorf("Grok qualification requires root-owned managed dispatch authority: %w", err)
	}
	versionCtx, versionCancel := context.WithTimeout(commandCtx, 5*time.Second)
	runtimeVersion, err := deps.version(versionCtx, binary)
	versionCancel()
	if err != nil {
		return fmt.Errorf("read configured Grok runtime version: %w", err)
	}
	if !versionMatches(runtimeVersion, profile.RuntimeVersion) {
		return errors.New("configured Grok runtime drift detected")
	}
	runtimeSHA256, err := deps.hashBinary(binary)
	if err != nil || !validProviderNativeDigest(runtimeSHA256) {
		return errors.New("configured Grok runtime could not be bound to an exact executable digest")
	}
	if deps.admission.CapacityStatus().Scope != provider.CapacityControlScopeLocalShared {
		return errors.New("Grok qualification requires the cross-process local shared capacity store")
	}
	if opts.grokHeadlessLineage {
		if deps.runSession == nil || deps.sessionRunner == nil || deps.prepareLineage == nil || deps.cleanupLineage == nil || deps.hashBinary == nil {
			return errors.New("Grok headless lineage qualification dependencies are incomplete")
		}
		return runProviderGrokHeadlessLineageQualification(commandCtx, cmd, opts, profile, identity, binary, runtimeVersion, runtimeSHA256, signReceipt, deps)
	}
	if deps.storeProtocolDiagnostic == nil {
		return errors.New("Grok qualification requires durable protocol diagnostics")
	}
	diagnosticStarted := deps.now().UTC()
	policyHash := agent.GrokAutomationPolicySHA256(profile.AutomationPolicy)
	// Check storage before capacity acquisition or any paid dispatch.
	if _, err := deps.storeProtocolDiagnostic(identity.Hash(), policyHash, runtimeSHA256, diagnosticStarted, diagnosticStarted, "before_dispatch", provider.ProtocolObservation{}); err != nil {
		return errors.New("Grok qualification diagnostic storage is unavailable before dispatch")
	}
	run := deps.run
	deps.run = func(ctx context.Context, runner grok.Runner, req grok.Request) (grok.Result, error) {
		req.BeforeCleanup = func(observation provider.ProtocolObservation) error {
			_, err := deps.storeProtocolDiagnostic(identity.Hash(), policyHash, runtimeSHA256, diagnosticStarted, deps.now().UTC(), "before_cleanup", observation)
			return err
		}
		return run(ctx, runner, req)
	}
	if workspaceWrite {
		if deps.prepareWorkspace == nil || deps.cleanupLineage == nil || deps.workspaceBroker == nil || deps.workspaceRevision == nil || deps.createWorkspaceAudit == nil || deps.readWorkspaceFile == nil || deps.readWorkspaceAudit == nil || deps.storeWorkspaceDiagnostic == nil {
			return errors.New("Grok workspace-write qualification dependencies are incomplete")
		}
		return runProviderGrokWorkspaceQualification(commandCtx, cmd, opts, profile, identity, binary, runtimeVersion, runtimeSHA256, signReceipt, deps)
	}

	nonce, err := deps.newNonce()
	if err != nil {
		return fmt.Errorf("generate Grok qualification nonce: %w", err)
	}
	started := deps.now().UTC()
	runTimeout := opts.timeout
	if opts.suiteTimeout < runTimeout {
		runTimeout = opts.suiteTimeout
	}
	runCtx, runCancel := context.WithTimeout(commandCtx, runTimeout)
	decision, err := acquireProviderGrokQualificationTurn(runCtx, deps.admission, identity)
	if err != nil {
		runCancel()
		return err
	}
	result, runErr := deps.run(runCtx, grok.OSRunner{}, grok.Request{
		Prompt: "Reply with this exact nonce and no other text. Do not use tools: " + nonce,
		CWD:    cwd, Binary: binary, RuntimeHome: profile.RuntimeHome, Model: identity.Model(), RuntimeVersion: profile.RuntimeVersion, ExpectedNonce: nonce,
		AutomationPolicyArgs: agent.GrokAutomationACPPolicyArgs(profile.AutomationPolicy),
	})
	deps.admission.Release(identity, decision)
	runCancel()
	if runErr == nil && result.Success {
		// This updates capacity liveness only; the signed receipt checks below
		// remain the sole authority for qualification promotion.
		deps.admission.RecordSuccess(identity)
	}
	completed := deps.now().UTC()
	receipt := providerqualification.Receipt{
		Mode: providerqualification.ModeLive, Provider: "xai", Transport: "xai_acp",
		IdentitySHA256: identity.Hash(), PolicySHA256: agent.GrokAutomationPolicySHA256(profile.AutomationPolicy),
		RuntimeVersion: runtimeVersion, RuntimeSHA256: runtimeSHA256, StartedAt: started, CompletedAt: completed,
		// No disposable worktree is created for this one no-tool probe. This
		// context digest is intentionally not presented as repository evidence.
		DisposableRepoHash: sha256StringCLI("xai-acp-observe-only-no-worktree-v1"),
		Checks:             grokQualificationChecks(),
	}
	observed := sha256StringCLI(digestSafeJSON(result))
	expectedResolvedModel := grok.ExpectedResolvedModel(profile.RuntimeVersion, identity.Model())
	modelObserved := runErr == nil && result.Success && result.AcknowledgementVerified && result.Authenticated && result.RuntimeEventContract.Passed && result.Model == identity.Model() && grokDoctorModelEvidenceConfirmed(result.ModelEvidence) && result.ResolvedModel == expectedResolvedModel && result.ResolvedModelEvidence == "completion_metadata.usage.model_usage_singleton"
	setGrokQualificationCheck(&receipt, providerqualification.CheckIdentity, modelObserved, "live", observed, grokQualificationModelDetail(result, runErr, identity.Model(), expectedResolvedModel))
	setGrokProtocolFailure(&receipt, result, runErr)
	cleanupObserved := !result.Cleanup.ObservedAt.IsZero() && result.Cleanup.Reaped && result.Cleanup.ResidualPIDs != nil && len(result.Cleanup.ResidualPIDs) == 0
	setGrokQualificationCheck(&receipt, providerqualification.CheckProcessCleanup, cleanupObserved, "local_observed_process_tree", observed, "launched ACP process-tree cleanup observation")
	if err := receipt.Finalize(); err != nil {
		return fmt.Errorf("finalize Grok qualification receipt: %w", err)
	}
	if err := signReceipt(commandCtx, &receipt); err != nil {
		return fmt.Errorf("sign Grok qualification receipt: %w", err)
	}
	path, err := deps.store(opts.qualificationDir, receipt)
	if err != nil {
		return fmt.Errorf("store Grok qualification receipt: %w", err)
	}
	output := providerQualificationRunOutput{SchemaVersion: providerqualification.SchemaVersion, Profile: opts.profile, Transport: "xai_acp", IdentitySHA256: identity.Hash(), RuntimeVersion: runtimeVersion, PolicySHA256: receipt.PolicySHA256, ReceiptPath: path, Receipt: receipt}
	if IsJSONOutput() {
		if err := encodeIndentedJSON(cmd.OutOrStdout(), output); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Grok observe-only qualification: %s (%d/%d checks)\nReceipt: %s\n", qualificationResult(receipt), countPassedQualificationChecks(receipt), len(receipt.Checks), path)
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
	return nil
}

// acquireProviderGrokQualificationTurn gives every real provider request its
// own shared-store lease and token. A multi-step qualification may wait for a
// controller-supplied refill time, but it never bypasses capacity, retries a
// permanent denial, or changes identity/provider as a fallback.
func acquireProviderGrokQualificationTurn(ctx context.Context, admission providerDoctorAdmission, identity provider.Identity) (ratelimit.Decision, error) {
	if ctx == nil || admission == nil {
		return ratelimit.Decision{}, errors.New("Grok qualification admission is unavailable")
	}
	for {
		decision := admission.Acquire(identity)
		if decision.Allowed {
			if !decision.NoFailover {
				admission.Release(identity, decision)
				return ratelimit.Decision{}, errors.New("Grok qualification admission did not prohibit provider failover")
			}
			return decision, nil
		}
		if !decision.NoFailover || decision.RetryAt == nil {
			return ratelimit.Decision{}, errors.New("Grok qualification admission was denied for the exact identity; failover is prohibited")
		}
		wait := time.Until(*decision.RetryAt)
		if wait <= 0 {
			wait = time.Millisecond
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ratelimit.Decision{}, fmt.Errorf("wait for Grok qualification capacity: %w", context.Cause(ctx))
		case <-timer.C:
		}
	}
}

type providerGrokLineageWorkspace struct {
	Root        string
	Primary     string
	Worktree    string
	RuntimeHome string
}

const (
	providerGrokWorkspaceTarget    = "qualification/qualification.go"
	providerGrokWorkspaceSecret    = ".qualification-secret"
	providerGrokWorkspaceAuditFile = "workspace-broker-audit.jsonl"
	providerGrokAuditMaxBytes      = 1 << 20
	providerGrokAuditMaxEvents     = 32
	providerGrokWorkspaceSchema    = "ntm.provider-workspace.v2"
	providerGrokVerifierSchema     = "ntm.disposable-verifier.v2"
)

var (
	providerGrokWorkspaceBefore = []byte("package qualification\n\nfunc Value() string { return \"before\" }\n")
	providerGrokWorkspaceAfter  = []byte("package qualification\n\nfunc Value() string { return \"qualified\" }\n")
)

type providerGrokWorkspaceAudit struct {
	Header providerBrokerAuditHeader
	Events []providerBrokerAuditEvent
}

type providerGrokWorkspaceAssertions struct {
	ReadObserved   bool
	EditObserved   bool
	SecretDenied   bool
	TestObserved   bool
	EvidenceSHA256 string
}

// runProviderGrokWorkspaceQualification is the bounded write producer for the
// exact workspace-write identity. The provider receives only four typed MCP
// tools. NTM independently validates the create-only broker audit, final file,
// fixed verifier receipt, protected-path rejection, policy surface, and local
// cleanup before signing any positive check.
func runProviderGrokWorkspaceQualification(commandCtx context.Context, cmd *cobra.Command, opts providerQualificationOptions, profile config.ProviderProfileConfig, identity provider.Identity, binary, runtimeVersion, binarySHA256 string, signReceipt func(context.Context, *providerqualification.Receipt) error, deps providerGrokQualificationDependencies) error {
	suiteCtx, suiteCancel := context.WithTimeout(commandCtx, opts.suiteTimeout)
	defer suiteCancel()
	started := deps.now().UTC()
	workspace, err := deps.prepareWorkspace(suiteCtx, profile.RuntimeHome)
	if err != nil {
		return fmt.Errorf("prepare disposable Grok workspace qualification: %w", err)
	}
	cleaned := false
	defer func() {
		if !cleaned {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = deps.cleanupLineage(cleanupCtx, workspace)
			cancel()
		}
	}()

	revision, err := deps.workspaceRevision(suiteCtx, workspace.Worktree)
	if err != nil || strings.TrimSpace(revision) == "" {
		return errors.New("Grok workspace qualification could not bind the disposable revision")
	}
	auditPath := filepath.Join(workspace.Root, providerGrokWorkspaceAuditFile)
	auditGuard, err := deps.createWorkspaceAudit(auditPath, workspace.Worktree)
	if err != nil || auditGuard == nil {
		return fmt.Errorf("create guarded Grok workspace audit: %w", err)
	}
	defer auditGuard.Close()
	broker, err := deps.workspaceBroker(suiteCtx, workspace.Worktree, auditPath)
	if err != nil || broker == nil || broker.BindingSHA256() == "" {
		return fmt.Errorf("bind audited Grok workspace broker: %w", err)
	}
	nonce, err := deps.newNonce()
	if err != nil {
		return fmt.Errorf("generate Grok workspace qualification nonce: %w", err)
	}
	prompt := providerWorkspaceQualificationPrompt(nonce)
	runTimeout := opts.timeout
	if opts.suiteTimeout < runTimeout {
		runTimeout = opts.suiteTimeout
	}
	runCtx, runCancel := context.WithTimeout(suiteCtx, runTimeout)
	decision, err := acquireProviderGrokQualificationTurn(runCtx, deps.admission, identity)
	if err != nil {
		runCancel()
		return err
	}
	result, runErr := deps.run(runCtx, grok.OSRunner{}, grok.Request{
		Prompt: prompt, ExpectedNonce: nonce, CWD: workspace.Worktree,
		Binary: binary, RuntimeHome: workspace.RuntimeHome, Model: identity.Model(), RuntimeVersion: profile.RuntimeVersion,
		AutomationPolicyArgs: agent.GrokAutomationACPPolicyArgs(profile.AutomationPolicy), Broker: broker,
	})
	deps.admission.Release(identity, decision)
	runCancel()
	if runErr == nil && result.Success {
		deps.admission.RecordSuccess(identity)
	}

	audit, auditErr := deps.readWorkspaceAudit(auditGuard, auditPath, workspace.Worktree, revision)
	finalContent, finalErr := deps.readWorkspaceFile(filepath.Join(workspace.Worktree, filepath.FromSlash(providerGrokWorkspaceTarget)))
	finalContentOK := finalErr == nil && bytes.Equal(finalContent, providerGrokWorkspaceAfter)
	observed := deps.now().UTC()
	observedAssertions := evaluateProviderGrokWorkspaceAudit(audit, workspace.Worktree, revision, started, observed)
	if deps.storeWorkspaceDiagnostic == nil {
		return errors.New("workspace diagnostic storage is unavailable")
	}
	if _, err := deps.storeWorkspaceDiagnostic(identity.Hash(), agent.GrokAutomationPolicySHA256(profile.AutomationPolicy), binarySHA256, started, observed, providerWorkspaceDiagnostic(audit, auditErr, observedAssertions, finalContentOK)); err != nil {
		return err
	}

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	cleanupErr := deps.cleanupLineage(cleanupCtx, workspace)
	cleanupCancel()
	cleaned = cleanupErr == nil && providerGrokLineageWorkspaceRemoved(workspace)
	completed := deps.now().UTC()
	assertions := evaluateProviderGrokWorkspaceAudit(audit, workspace.Worktree, revision, started, completed)

	policySHA256 := agent.GrokAutomationPolicySHA256(profile.AutomationPolicy)
	resultEvidence := digestSafeJSON(result)
	auditEvidence := sha256StringCLI(strings.Join([]string{assertions.EvidenceSHA256, safeErrorDigest(auditErr), safeErrorDigest(finalErr), broker.BindingSHA256()}, "\x00"))
	expectedResolvedModel := grok.ExpectedResolvedModel(profile.RuntimeVersion, identity.Model())
	modelObserved := runErr == nil && result.Success && result.AcknowledgementVerified && result.Authenticated && result.RuntimeEventContract.Passed && result.Model == identity.Model() && grokDoctorModelEvidenceConfirmed(result.ModelEvidence) && result.ResolvedModel == expectedResolvedModel && result.ResolvedModelEvidence == "completion_metadata.usage.model_usage_singleton"
	policyDeniedPush := providerGrokWorkspacePushBoundary(profile.AutomationPolicy, *broker)
	processClean := !result.Cleanup.ObservedAt.IsZero() && result.Cleanup.Reaped && result.Cleanup.ResidualPIDs != nil && len(result.Cleanup.ResidualPIDs) == 0
	receipt := providerqualification.Receipt{
		Mode: providerqualification.ModeLive, Provider: "xai", Transport: "xai_acp",
		IdentitySHA256: identity.Hash(), PolicySHA256: policySHA256, RuntimeVersion: runtimeVersion, RuntimeSHA256: binarySHA256,
		StartedAt: started, CompletedAt: completed, DisposableRepoHash: sha256StringCLI(filepath.Clean(workspace.Worktree)),
		Checks: grokQualificationChecksForProducer("xai-acp-workspace-write"),
	}
	setGrokQualificationCheck(&receipt, providerqualification.CheckIdentity, modelObserved, "live", resultEvidence, grokQualificationModelDetail(result, runErr, identity.Model(), expectedResolvedModel))
	setGrokProtocolFailure(&receipt, result, runErr)
	setGrokQualificationCheck(&receipt, providerqualification.CheckWorkspaceEdit, auditErr == nil && assertions.ReadObserved && assertions.EditObserved && finalContentOK, "local_authoritative", auditEvidence, "audited optimistic-hash edit and independent controller readback")
	setGrokQualificationCheck(&receipt, providerqualification.CheckTestCommand, auditErr == nil && assertions.TestObserved && finalContentOK, "local_authoritative", auditEvidence, "fixed network-isolated go-test/go-vet manifest passed after the final write")
	setGrokQualificationCheck(&receipt, providerqualification.CheckSecretDenied, auditErr == nil && assertions.SecretDenied, "local_authoritative", auditEvidence, "audited broker rejection of the synthetic protected path")
	if auditErr == nil || (len(audit.Events) == 0 && result.ToolRequestCount == 0) {
		for _, scenario := range []struct {
			name     string
			sequence int
		}{
			{providerqualification.CheckWorkspaceEdit, 2}, {providerqualification.CheckTestCommand, 4}, {providerqualification.CheckSecretDenied, 3},
		} {
			if len(audit.Events) < scenario.sequence {
				setGrokQualificationCheck(&receipt, scenario.name, false, "local_authoritative", auditEvidence, "untested: required broker operation was not observed")
			}
		}
	}
	pushEvidence := sha256StringCLI(strings.Join([]string{policySHA256, broker.BindingSHA256(), digestSafeJSON(providerBrokerToolDefinitions())}, "\x00"))
	setGrokQualificationCheck(&receipt, providerqualification.CheckPushDenied, policyDeniedPush, "local_authoritative", pushEvidence, "root-authorized dontAsk policy denies Bash and network tools; typed broker exposes no push surface")
	cleanupEvidence := sha256StringCLI(strings.Join([]string{resultEvidence, fmt.Sprint(cleaned), safeErrorDigest(cleanupErr)}, "\x00"))
	setGrokQualificationCheck(&receipt, providerqualification.CheckProcessCleanup, processClean && cleaned, "local_observed_process_tree", cleanupEvidence, "ACP process tree exited and disposable worktree plus isolated session home were removed")
	if err := receipt.Finalize(); err != nil {
		return fmt.Errorf("finalize Grok workspace qualification receipt: %w", err)
	}
	if err := signReceipt(commandCtx, &receipt); err != nil {
		return fmt.Errorf("sign Grok workspace qualification receipt: %w", err)
	}
	path, err := deps.store(opts.qualificationDir, receipt)
	if err != nil {
		return fmt.Errorf("store Grok workspace qualification receipt: %w", err)
	}
	output := providerQualificationRunOutput{SchemaVersion: providerqualification.SchemaVersion, Profile: opts.profile, Transport: receipt.Transport, IdentitySHA256: identity.Hash(), RuntimeVersion: runtimeVersion, PolicySHA256: receipt.PolicySHA256, ReceiptPath: path, Receipt: receipt}
	if IsJSONOutput() {
		if err := encodeIndentedJSON(cmd.OutOrStdout(), output); err != nil {
			return err
		}
		return errJSONFailure
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Grok workspace-write qualification: partial (%d/%d checks)\nReceipt: %s\n", countPassedQualificationChecks(receipt), len(receipt.Checks), path)
	for _, check := range receipt.Checks {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\n", check.EvidenceState(), check.Name, check.Detail)
	}
	return &providerQualificationExitError{}
}

func providerWorkspaceQualificationPrompt(nonce string) string {
	return fmt.Sprintf(`First use the runtime's tool discovery/search facility if needed to find the ntm-controlled-workspace MCP server and retrieve its exact tool schemas. Discovery calls are permitted in addition to the four workspace calls below. Use the runtime's MCP invocation wrapper when required.
Perform exactly these four calls to that server in order:
1. read_file with path %q.
2. write_file with path %q, expected_sha256 %q, and content exactly %q.
3. read_file with path %q. This protected synthetic sentinel must be rejected; continue after the rejection.
4. verify_worktree with an empty object.
Do not use native file, shell, network, or other servers' tools. After all four workspace calls, reply with this exact nonce and no other text: %s`, providerGrokWorkspaceTarget, providerGrokWorkspaceTarget, sha256TextCLI(providerGrokWorkspaceBefore), string(providerGrokWorkspaceAfter), providerGrokWorkspaceSecret, nonce)
}

func providerWorkspaceDiagnostic(audit providerGrokWorkspaceAudit, auditErr error, assertions providerGrokWorkspaceAssertions, finalContentOK bool) providerqualification.WorkspaceDiagnostic {
	d := providerqualification.WorkspaceDiagnostic{AuditReadable: auditErr == nil, AuditEvents: len(audit.Events), ReadObserved: assertions.ReadObserved, EditObserved: assertions.EditObserved, TestObserved: assertions.TestObserved, SecretDenied: assertions.SecretDenied, FinalContentMatched: finalContentOK}
	if auditErr != nil {
		d.AuditErrorSHA256 = safeErrorDigest(auditErr)
	}
	for _, event := range audit.Events {
		tool := event.Tool
		switch tool {
		case "read_file", "write_file", "list_files", "verify_worktree", "invalid":
		default:
			tool = "unknown"
		}
		d.Tools = append(d.Tools, providerqualification.WorkspaceToolDiagnostic{Tool: tool, Success: event.Success, Rejected: event.Rejected, OperationReceipt: event.WorkspaceReceipt != nil || event.VerificationReceipt != nil, ErrorSHA256: event.ErrorSHA256})
	}
	return d
}

func evaluateProviderGrokWorkspaceAudit(audit providerGrokWorkspaceAudit, worktree, revision string, qualificationBounds ...time.Time) providerGrokWorkspaceAssertions {
	result := providerGrokWorkspaceAssertions{EvidenceSHA256: digestSafeJSON(audit)}
	if len(audit.Events) > 4 || audit.Header.WorktreeSHA256 != sha256StringCLI(filepath.Clean(worktree)) || audit.Header.RevisionSHA256 != sha256StringCLI(revision) {
		return result
	}
	var qualificationStarted, qualificationCompleted time.Time
	if len(qualificationBounds) != 0 {
		if len(qualificationBounds) != 2 {
			return result
		}
		qualificationStarted, qualificationCompleted = qualificationBounds[0], qualificationBounds[1]
		if qualificationStarted.IsZero() || qualificationCompleted.IsZero() || qualificationCompleted.Before(qualificationStarted) || audit.Header.CreatedAt.Before(qualificationStarted) || audit.Header.CreatedAt.After(qualificationCompleted) {
			return result
		}
	}
	for index, expectedTool := range []string{"read_file", "write_file", "read_file", "verify_worktree"} {
		if index >= len(audit.Events) {
			break
		}
		if audit.Events[index].Sequence != uint64(index+1) || audit.Events[index].Tool != expectedTool || !providerGrokTimeWithinBounds(audit.Events[index].OccurredAt, qualificationStarted, qualificationCompleted) {
			return result
		}
		if index > 0 && audit.Events[index].OccurredAt.Before(audit.Events[index-1].OccurredAt) {
			return result
		}
	}
	worktreeSHA256 := sha256StringCLI(filepath.Clean(worktree))
	revisionSHA256 := sha256StringCLI(revision)
	targetSHA256 := sha256StringCLI(providerGrokWorkspaceTarget)
	secretSHA256 := sha256StringCLI(providerGrokWorkspaceSecret)
	beforeSHA256 := sha256TextCLI(providerGrokWorkspaceBefore)
	afterSHA256 := sha256TextCLI(providerGrokWorkspaceAfter)
	// A valid prefix proves only the completed independent operations. Missing
	// later calls cannot erase earlier evidence or manufacture later evidence.
	var events [4]providerBrokerAuditEvent
	copy(events[:], audit.Events)
	readEvent, writeEvent, secretEvent, verifyEvent := events[0], events[1], events[2], events[3]
	validWorkspaceReceipt := func(event providerBrokerAuditEvent, action, pathSHA256 string) bool {
		return event.Success && !event.Rejected && event.WorkspaceReceipt != nil && event.WorkspaceReceipt.SchemaVersion == providerGrokWorkspaceSchema && event.WorkspaceReceipt.Action == action && event.PathSHA256 == pathSHA256 && event.WorkspaceReceipt.PathSHA256 == pathSHA256 && event.WorkspaceReceipt.WorktreeSHA256 == worktreeSHA256 && event.WorkspaceReceipt.RevisionSHA256 == revisionSHA256 && event.WorkspaceReceipt.ErrorSHA256 == "" && providerGrokOrderedTimes(event.WorkspaceReceipt.StartedAt, event.WorkspaceReceipt.CompletedAt, event.OccurredAt) && providerGrokTimeWithinBounds(event.WorkspaceReceipt.StartedAt, qualificationStarted, qualificationCompleted)
	}
	result.ReadObserved = readEvent.Sequence == 1 && readEvent.Tool == "read_file" && validWorkspaceReceipt(readEvent, "read", targetSHA256) && !readEvent.WorkspaceReceipt.Mutated && readEvent.WorkspaceReceipt.Bytes == int64(len(providerGrokWorkspaceBefore)) && readEvent.WorkspaceReceipt.ResultSHA256 == beforeSHA256
	result.EditObserved = writeEvent.Sequence == 2 && writeEvent.Tool == "write_file" && validWorkspaceReceipt(writeEvent, "write", targetSHA256) && writeEvent.WorkspaceReceipt.Mutated && writeEvent.WorkspaceReceipt.Bytes == int64(len(providerGrokWorkspaceAfter)) && writeEvent.WorkspaceReceipt.BeforeSHA256 == beforeSHA256 && writeEvent.WorkspaceReceipt.AfterSHA256 == afterSHA256 && writeEvent.WorkspaceReceipt.ResultSHA256 == afterSHA256
	result.SecretDenied = secretEvent.Sequence == 3 && secretEvent.Tool == "read_file" && !secretEvent.Success && secretEvent.Rejected && secretEvent.PathSHA256 == secretSHA256 && secretEvent.WorkspaceReceipt != nil && secretEvent.WorkspaceReceipt.SchemaVersion == providerGrokWorkspaceSchema && secretEvent.WorkspaceReceipt.Action == "read" && secretEvent.WorkspaceReceipt.PathSHA256 == secretSHA256 && secretEvent.WorkspaceReceipt.WorktreeSHA256 == worktreeSHA256 && secretEvent.WorkspaceReceipt.RevisionSHA256 == revisionSHA256 && validProviderNativeDigest(secretEvent.WorkspaceReceipt.ErrorSHA256) && secretEvent.ErrorSHA256 == secretEvent.WorkspaceReceipt.ErrorSHA256 && providerGrokOrderedTimes(secretEvent.WorkspaceReceipt.StartedAt, secretEvent.WorkspaceReceipt.CompletedAt, secretEvent.OccurredAt) && providerGrokTimeWithinBounds(secretEvent.WorkspaceReceipt.StartedAt, qualificationStarted, qualificationCompleted)
	expectedManifestSHA256 := sha256StringCLI(filepath.Clean(worktree) + "\x00" + revision + "\x00go-test\x00go-vet")
	result.TestObserved = verifyEvent.Sequence == 4 && verifyEvent.Tool == "verify_worktree" && verifyEvent.Success && !verifyEvent.Rejected && validProviderGrokVerificationReceipt(verifyEvent.VerificationReceipt, worktreeSHA256, revisionSHA256, expectedManifestSHA256, verifyEvent.OccurredAt, qualificationStarted, qualificationCompleted)
	if result.TestObserved {
		result.TestObserved = result.EditObserved && !verifyEvent.VerificationReceipt.StartedAt.Before(writeEvent.WorkspaceReceipt.CompletedAt)
	}
	return result
}

func providerGrokOrderedTimes(started, completed, recorded time.Time) bool {
	return !started.IsZero() && !completed.IsZero() && !recorded.IsZero() && !completed.Before(started) && !recorded.Before(completed)
}

func providerGrokTimeWithinBounds(value, started, completed time.Time) bool {
	if started.IsZero() && completed.IsZero() {
		return true
	}
	return !value.IsZero() && !value.Before(started) && !value.After(completed)
}

func validProviderGrokVerificationReceipt(receipt *provider.VerificationReceipt, worktreeSHA256, revisionSHA256, manifestSHA256 string, recordedAt, qualificationStarted, qualificationCompleted time.Time) bool {
	if receipt == nil || receipt.SchemaVersion != providerGrokVerifierSchema || receipt.ManifestSHA256 != manifestSHA256 || receipt.WorktreeSHA256 != worktreeSHA256 || receipt.RevisionSHA256 != revisionSHA256 || !receipt.NetworkIsolated || !receipt.CredentialsCleared || !receipt.PIDNamespaceIsolated || !receipt.CleanupVerified || !receipt.DisposableWorktree || len(receipt.Commands) != 2 || !providerGrokOrderedTimes(receipt.StartedAt, receipt.CompletedAt, recordedAt) || !providerGrokTimeWithinBounds(receipt.StartedAt, qualificationStarted, qualificationCompleted) {
		return false
	}
	expectedCommandHashes := []string{
		sha256StringCLI("go-test\x00go\x00test\x00./..."),
		sha256StringCLI("go-vet\x00go\x00vet\x00./..."),
	}
	for index, expected := range []string{"go-test", "go-vet"} {
		command := receipt.Commands[index]
		if command.ID != expected || command.CommandSHA256 != expectedCommandHashes[index] || !validProviderNativeDigest(command.OutputSHA256) || command.OutputBytes < 0 || command.ExitCode != 0 || command.TimedOut || !command.ProcessWaited || !command.CleanupVerified || command.ErrorSHA256 != "" || !providerGrokOrderedTimes(command.StartedAt, command.CompletedAt, receipt.CompletedAt) || command.StartedAt.Before(receipt.StartedAt) {
			return false
		}
	}
	return true
}

func providerGrokWorkspacePushBoundary(policyName string, broker grok.WorkspaceBrokerDescriptor) bool {
	policy, ok := agent.GrokAutomationPolicy(policyName)
	if !ok || policy.Name != agent.GrokWorkspaceWritePolicyName || policy.Sandbox != "strict" || policy.PermissionMode != "dontAsk" || broker.BindingSHA256() == "" {
		return false
	}
	denied := make(map[string]bool, len(policy.DenyRules))
	for _, rule := range policy.DenyRules {
		denied[rule] = true
	}
	if !denied["Bash(*)"] || !denied["WebFetch"] || !denied["WebSearch"] || !denied["Edit"] {
		return false
	}
	expectedTools := map[string]bool{"list_files": true, "read_file": true, "write_file": true, "verify_worktree": true}
	definitions := providerBrokerToolDefinitions()
	if len(definitions) != len(expectedTools) {
		return false
	}
	for _, definition := range definitions {
		name, _ := definition["name"].(string)
		if !expectedTools[name] {
			return false
		}
		delete(expectedTools, name)
	}
	return len(expectedTools) == 0
}

func createProviderGrokWorkspaceAudit(auditFile, worktree string) (*os.File, error) {
	auditFile, auditErr := filepath.Abs(auditFile)
	worktree, worktreeErr := filepath.Abs(worktree)
	if auditErr != nil || worktreeErr != nil || filepath.Dir(filepath.Clean(auditFile)) != filepath.Dir(filepath.Clean(worktree)) {
		return nil, errors.New("Grok workspace audit path is outside the qualification parent")
	}
	parentInfo, err := os.Lstat(filepath.Dir(auditFile))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("Grok workspace audit parent is not a private real directory")
	}
	file, err := os.OpenFile(auditFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, errors.New("create guarded Grok workspace audit file")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, errors.New("set guarded Grok workspace audit permissions")
	}
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() != 0 || info.Mode().Perm() != 0o600 {
		_ = file.Close()
		return nil, errors.New("guarded Grok workspace audit file is unsafe")
	}
	return file, nil
}

func readProviderGrokWorkspaceAudit(file *os.File, auditFile, worktree, revision string) (providerGrokWorkspaceAudit, error) {
	if !filepath.IsAbs(auditFile) || filepath.Dir(filepath.Clean(auditFile)) != filepath.Dir(filepath.Clean(worktree)) {
		return providerGrokWorkspaceAudit{}, errors.New("Grok workspace audit path is outside the qualification parent")
	}
	pathInfo, err := os.Lstat(auditFile)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Size() <= 0 || pathInfo.Size() > providerGrokAuditMaxBytes || pathInfo.Mode().Perm()&0o077 != 0 {
		return providerGrokWorkspaceAudit{}, errors.New("Grok workspace audit is absent, unsafe, or outside its size boundary")
	}
	if file == nil {
		return providerGrokWorkspaceAudit{}, errors.New("Grok workspace audit guard is unavailable")
	}
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) || openedInfo.Size() != pathInfo.Size() || openedInfo.Mode().Perm()&0o077 != 0 {
		return providerGrokWorkspaceAudit{}, errors.New("Grok workspace audit changed while being opened")
	}
	scanner := bufio.NewScanner(io.NewSectionReader(file, 0, openedInfo.Size()))
	scanner.Buffer(make([]byte, 16<<10), 256<<10)
	var audit providerGrokWorkspaceAudit
	line := 0
	for scanner.Scan() {
		line++
		if line > providerGrokAuditMaxEvents+1 {
			return providerGrokWorkspaceAudit{}, errors.New("Grok workspace audit exceeded its event boundary")
		}
		raw := append([]byte(nil), scanner.Bytes()...)
		if line == 1 {
			if err := decodeProviderGrokAuditLine(raw, &audit.Header); err != nil || audit.Header.Kind != "header" || audit.Header.SchemaVersion != providerBrokerAuditSchemaVersion || audit.Header.WorktreeSHA256 != sha256StringCLI(filepath.Clean(worktree)) || audit.Header.RevisionSHA256 != sha256StringCLI(revision) || audit.Header.CreatedAt.IsZero() {
				return providerGrokWorkspaceAudit{}, errors.New("Grok workspace audit header is invalid")
			}
			continue
		}
		var event providerBrokerAuditEvent
		if err := decodeProviderGrokAuditLine(raw, &event); err != nil || event.Kind != "tool_call" || event.SchemaVersion != providerBrokerAuditSchemaVersion || event.Sequence != uint64(line-1) || event.Tool == "" || event.OccurredAt.IsZero() || event.OccurredAt.Before(audit.Header.CreatedAt) || len(audit.Events) > 0 && event.OccurredAt.Before(audit.Events[len(audit.Events)-1].OccurredAt) {
			return providerGrokWorkspaceAudit{}, errors.New("Grok workspace audit event is invalid")
		}
		audit.Events = append(audit.Events, event)
	}
	if err := scanner.Err(); err != nil || line < 2 {
		return providerGrokWorkspaceAudit{}, errors.New("Grok workspace audit is incomplete")
	}
	return audit, nil
}

func decodeProviderGrokAuditLine(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("Grok workspace audit line has trailing data")
	}
	return nil
}

// runProviderGrokHeadlessLineageQualification is an explicit partial
// producer. ACP creates the immutable bootstrap parent under the current
// strict managed policy. Native headless fork proves distinct child lineage,
// while native headless resume separately proves cross-transport resumption
// of that exact bootstrap parent. The signed receipt intentionally leaves
// edit, test, denial, cancellation, and crash gates false, so it cannot
// authorize an ordinary provider session.
func runProviderGrokHeadlessLineageQualification(commandCtx context.Context, cmd *cobra.Command, opts providerQualificationOptions, profile config.ProviderProfileConfig, identity provider.Identity, binary, runtimeVersion, binarySHA256 string, signReceipt func(context.Context, *providerqualification.Receipt) error, deps providerGrokQualificationDependencies) error {
	suiteCtx, suiteCancel := context.WithTimeout(commandCtx, opts.suiteTimeout)
	defer suiteCancel()
	workspace, err := deps.prepareLineage(suiteCtx, profile.RuntimeHome)
	if err != nil {
		return fmt.Errorf("prepare disposable Grok lineage workspace: %w", err)
	}
	cleaned := false
	defer func() {
		if !cleaned {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = deps.cleanupLineage(cleanupCtx, workspace)
			cancel()
		}
	}()
	policySHA256 := agent.GrokAutomationPolicySHA256(profile.AutomationPolicy)
	started := deps.now().UTC()
	bootstrapNonce, err := deps.newNonce()
	if err != nil {
		return fmt.Errorf("generate Grok lineage bootstrap nonce: %w", err)
	}
	bootstrapCtx, bootstrapCancel := context.WithTimeout(suiteCtx, opts.timeout)
	decision, err := acquireProviderGrokQualificationTurn(bootstrapCtx, deps.admission, identity)
	if err != nil {
		bootstrapCancel()
		return err
	}
	bootstrap, bootstrapErr := deps.run(bootstrapCtx, grok.OSRunner{}, grok.Request{
		Prompt:        "Do not call tools. Reply with this exact nonce and no other text: " + bootstrapNonce,
		ExpectedNonce: bootstrapNonce, CWD: workspace.Worktree, RuntimeHome: workspace.RuntimeHome,
		Binary: binary, Model: identity.Model(), RuntimeVersion: profile.RuntimeVersion,
		AutomationPolicyArgs: agent.GrokAutomationACPPolicyArgs(profile.AutomationPolicy),
	})
	deps.admission.Release(identity, decision)
	bootstrapCancel()
	if bootstrapErr == nil && bootstrap.Success {
		deps.admission.RecordSuccess(identity)
	}

	expectedResolvedModel := grok.ExpectedResolvedModel(profile.RuntimeVersion, identity.Model())
	bootstrapOK := bootstrapErr == nil && bootstrap.Success && bootstrap.AcknowledgementVerified && bootstrap.Authenticated && bootstrap.ProviderSessionID != "" && bootstrap.Model == identity.Model() && bootstrap.ModelEvidence == "completion_metadata" && bootstrap.ResolvedModel == expectedResolvedModel && bootstrap.ResolvedModelEvidence == "completion_metadata.usage.model_usage_singleton" && bootstrap.RuntimeEventContract.Passed
	var forkReceipt, resumeReceipt grok.SessionReceipt
	var forkErr, resumeErr error
	if bootstrapOK {
		forkReceipt, forkErr = runProviderGrokLineageStep(suiteCtx, opts.timeout, deps, profile, identity, binary, binarySHA256, policySHA256, workspace, bootstrap.ProviderSessionID, grok.SessionFork)
		resumeReceipt, resumeErr = runProviderGrokLineageStep(suiteCtx, opts.timeout, deps, profile, identity, binary, binarySHA256, policySHA256, workspace, bootstrap.ProviderSessionID, grok.SessionResume)
	}
	parentSHA256 := sha256StringCLI(bootstrap.ProviderSessionID)
	worktreeSHA256 := sha256StringCLI(filepath.Clean(workspace.Worktree))
	forkOK := forkErr == nil && validProviderGrokLineageReceipt(forkReceipt, grok.SessionFork, parentSHA256, worktreeSHA256, policySHA256, identity.ConfigSHA256(), binarySHA256, identity.Model(), expectedResolvedModel)
	resumeOK := resumeErr == nil && validProviderGrokLineageReceipt(resumeReceipt, grok.SessionResume, parentSHA256, worktreeSHA256, policySHA256, identity.ConfigSHA256(), binarySHA256, identity.Model(), expectedResolvedModel)

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	cleanupErr := deps.cleanupLineage(cleanupCtx, workspace)
	cleanupCancel()
	cleaned = cleanupErr == nil && providerGrokLineageWorkspaceRemoved(workspace)
	completed := deps.now().UTC()
	receipt := providerqualification.Receipt{
		Mode: providerqualification.ModeLive, Provider: "xai", Transport: "xai_headless_session",
		IdentitySHA256: identity.Hash(), PolicySHA256: policySHA256, RuntimeVersion: runtimeVersion, RuntimeSHA256: binarySHA256,
		StartedAt: started, CompletedAt: completed, DisposableRepoHash: worktreeSHA256,
		Checks: grokQualificationChecksForProducer("xai-headless-lineage"),
	}
	identityEvidence := sha256StringCLI(strings.Join([]string{
		bootstrap.Model, bootstrap.ModelEvidence, bootstrap.ResolvedModel, bootstrap.ResolvedModelEvidence,
		forkReceipt.Model, forkReceipt.ModelEvidence, resumeReceipt.Model, resumeReceipt.ModelEvidence,
		safeErrorDigest(bootstrapErr), safeErrorDigest(forkErr), safeErrorDigest(resumeErr),
	}, "\x00"))
	setGrokQualificationCheck(&receipt, providerqualification.CheckIdentity, bootstrapOK && forkOK && resumeOK, "live", identityEvidence, "ACP bootstrap and native fork/resume terminal models verified")
	lineageEvidence := sha256StringCLI(strings.Join([]string{
		parentSHA256, forkReceipt.ParentSessionSHA256, forkReceipt.ChildSessionSHA256,
		resumeReceipt.ParentSessionSHA256, resumeReceipt.ChildSessionSHA256,
		forkReceipt.WorktreeSHA256, resumeReceipt.WorktreeSHA256,
	}, "\x00"))
	setGrokQualificationCheck(&receipt, providerqualification.CheckResume, bootstrapOK && forkOK && resumeOK, "live", lineageEvidence, "ACP seed forked to a distinct child and original seed resumed with exact worktree lineage")
	bootstrapClean := !bootstrap.Cleanup.ObservedAt.IsZero() && bootstrap.Cleanup.Reaped && bootstrap.Cleanup.ResidualPIDs != nil && len(bootstrap.Cleanup.ResidualPIDs) == 0
	processesClean := grokLineageProcessExited(forkReceipt) && grokLineageProcessExited(resumeReceipt)
	cleanupEvidence := sha256StringCLI(strings.Join([]string{
		bootstrap.Cleanup.LocalTermination, fmt.Sprint(bootstrap.Cleanup.Reaped),
		forkReceipt.Cancellation.LocalTermination, resumeReceipt.Cancellation.LocalTermination,
		fmt.Sprint(cleaned), safeErrorDigest(cleanupErr),
	}, "\x00"))
	setGrokQualificationCheck(&receipt, providerqualification.CheckProcessCleanup, bootstrapClean && processesClean && cleaned, "local_authoritative", cleanupEvidence, "ACP/headless process trees exited and disposable worktree plus isolated session home were removed")
	if err := receipt.Finalize(); err != nil {
		return fmt.Errorf("finalize Grok lineage qualification receipt: %w", err)
	}
	if err := signReceipt(commandCtx, &receipt); err != nil {
		return fmt.Errorf("sign Grok lineage qualification receipt: %w", err)
	}
	path, err := deps.store(opts.qualificationDir, receipt)
	if err != nil {
		return fmt.Errorf("store Grok lineage qualification receipt: %w", err)
	}
	output := providerQualificationRunOutput{SchemaVersion: providerqualification.SchemaVersion, Profile: opts.profile, Transport: receipt.Transport, IdentitySHA256: identity.Hash(), RuntimeVersion: runtimeVersion, PolicySHA256: receipt.PolicySHA256, ReceiptPath: path, Receipt: receipt}
	if IsJSONOutput() {
		if err := encodeIndentedJSON(cmd.OutOrStdout(), output); err != nil {
			return err
		}
		return errJSONFailure
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Grok headless lineage qualification: partial (%d/%d checks)\nReceipt: %s\n", countPassedQualificationChecks(receipt), len(receipt.Checks), path)
	for _, check := range receipt.Checks {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\n", qualificationCheckStatus(check.Passed), check.Name, check.Detail)
	}
	return &providerQualificationExitError{}
}

func runProviderGrokLineageStep(ctx context.Context, timeout time.Duration, deps providerGrokQualificationDependencies, profile config.ProviderProfileConfig, identity provider.Identity, binary, binarySHA256, policySHA256 string, workspace providerGrokLineageWorkspace, parentSessionID string, action grok.SessionAction) (grok.SessionReceipt, error) {
	nonce, err := deps.newNonce()
	if err != nil {
		return grok.SessionReceipt{}, err
	}
	stepCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	decision, err := acquireProviderGrokQualificationTurn(stepCtx, deps.admission, identity)
	if err != nil {
		return grok.SessionReceipt{}, err
	}
	receipt, runErr := deps.runSession(stepCtx, deps.sessionRunner, grok.SessionRequest{
		Action: action, SessionID: parentSessionID,
		Prompt:        "Do not call tools. Reply with this exact nonce and no other text: " + nonce,
		ExpectedNonce: nonce, CWD: workspace.Worktree, Worktree: workspace.Worktree,
		RuntimeHome: workspace.RuntimeHome, Binary: binary, Model: identity.Model(), RuntimeVersion: profile.RuntimeVersion,
		PolicyArgs:   agent.GrokAutomationLifecyclePolicyArgs(profile.AutomationPolicy),
		PolicySHA256: policySHA256, ConfigSHA256: identity.ConfigSHA256(), BinarySHA256: binarySHA256,
	})
	deps.admission.Release(identity, decision)
	if runErr == nil && receipt.ProviderAcknowledged && receipt.CompletionConfirmed {
		deps.admission.RecordSuccess(identity)
	}
	return receipt, runErr
}

func validProviderGrokLineageReceipt(receipt grok.SessionReceipt, action grok.SessionAction, parentSHA256, worktreeSHA256, policySHA256, configSHA256, binarySHA256, requestedModel, resolvedModel string) bool {
	if receipt.Action != action || receipt.Fork != (action == grok.SessionFork) || !receipt.LineageBound || !receipt.ProviderAcknowledged || !receipt.CompletionConfirmed || receipt.ParentSessionSHA256 != parentSHA256 || receipt.CWDSHA256 != worktreeSHA256 || receipt.WorktreeSHA256 != worktreeSHA256 || receipt.PolicySHA256 != policySHA256 || receipt.ConfigSHA256 != configSHA256 || receipt.BinarySHA256 != binarySHA256 || receipt.RequestedModel != requestedModel || receipt.ExpectedReceiptModel != resolvedModel || receipt.Model != resolvedModel || receipt.ModelEvidence != "end.modelUsage_singleton" || receipt.ExitCode == nil || *receipt.ExitCode != 0 || strings.TrimSpace(receipt.StopReason) == "" || !grokLineageProcessExited(receipt) {
		return false
	}
	if action == grok.SessionFork {
		return receipt.ChildSessionSHA256 != "" && receipt.ChildSessionSHA256 != parentSHA256
	}
	return receipt.ChildSessionSHA256 == parentSHA256
}

func grokLineageProcessExited(receipt grok.SessionReceipt) bool {
	return receipt.Cancellation.LocalTermination == "not_required_process_exited" && !receipt.Cancellation.ObservedAt.IsZero() && receipt.Cancellation.ResidualPIDs != nil && len(receipt.Cancellation.ResidualPIDs) == 0
}

func prepareProviderGrokLineageWorkspace(ctx context.Context, sourceRuntimeHome string) (providerGrokLineageWorkspace, error) {
	return prepareProviderGrokQualificationWorkspace(ctx, sourceRuntimeHome, false)
}

func prepareProviderGrokWorkspaceQualification(ctx context.Context, sourceRuntimeHome string) (providerGrokLineageWorkspace, error) {
	return prepareProviderGrokQualificationWorkspace(ctx, sourceRuntimeHome, true)
}

func prepareProviderGrokQualificationWorkspace(ctx context.Context, sourceRuntimeHome string, workspaceWrite bool) (providerGrokLineageWorkspace, error) {
	if ctx == nil || !filepath.IsAbs(filepath.Clean(sourceRuntimeHome)) {
		return providerGrokLineageWorkspace{}, errors.New("Grok qualification requires an absolute isolated runtime home")
	}
	authPath := filepath.Join(filepath.Clean(sourceRuntimeHome), "auth.json")
	authInfo, err := os.Lstat(authPath)
	if err != nil || !authInfo.Mode().IsRegular() || authInfo.Mode()&os.ModeSymlink != 0 || authInfo.Size() <= 0 || authInfo.Size() > 1<<20 {
		return providerGrokLineageWorkspace{}, errors.New("Grok qualification requires a bounded regular cached-login file")
	}
	auth, err := os.ReadFile(authPath)
	if err != nil {
		return providerGrokLineageWorkspace{}, errors.New("Grok qualification could not read the cached login")
	}
	return prepareProviderComparisonWorkspace(ctx, auth, workspaceWrite)
}

// All comparison producers use the same fixture, audited broker, and verifier.
// Primary runtimes provision their own isolated credential format separately.
func prepareProviderComparisonWorkspace(ctx context.Context, auth []byte, workspaceWrite bool) (providerGrokLineageWorkspace, error) {
	root, err := os.MkdirTemp("", "ntm-grok-lineage-qualification-")
	if err != nil {
		return providerGrokLineageWorkspace{}, err
	}
	workspace := providerGrokLineageWorkspace{Root: root, Primary: filepath.Join(root, "primary"), Worktree: filepath.Join(root, "linked"), RuntimeHome: filepath.Join(root, "grok-home")}
	fail := func(cause error) (providerGrokLineageWorkspace, error) {
		_ = os.RemoveAll(root)
		return providerGrokLineageWorkspace{}, cause
	}
	if err := os.Mkdir(workspace.Primary, 0o700); err != nil {
		return fail(err)
	}
	if err := os.Mkdir(workspace.RuntimeHome, 0o700); err != nil {
		return fail(err)
	}
	if len(auth) != 0 {
		if err := os.WriteFile(filepath.Join(workspace.RuntimeHome, "auth.json"), auth, 0o600); err != nil {
			return fail(errors.New("Grok qualification could not isolate the cached login"))
		}
	}
	if err := os.WriteFile(filepath.Join(workspace.Primary, "README.md"), []byte("lineage qualification\n"), 0o600); err != nil {
		return fail(err)
	}
	tracked := []string{"README.md"}
	if workspaceWrite {
		if err := os.Mkdir(filepath.Join(workspace.Primary, "qualification"), 0o700); err != nil {
			return fail(err)
		}
		fixtures := map[string][]byte{
			"go.mod":                              []byte("module example.invalid/ntm-grok-qualification\n\ngo 1.23\n"),
			providerGrokWorkspaceTarget:           providerGrokWorkspaceBefore,
			"qualification/qualification_test.go": []byte("package qualification\n\nimport \"testing\"\n\nfunc TestValue(t *testing.T) { if Value() != \"qualified\" { t.Fatalf(\"Value() = %q\", Value()) } }\n"),
		}
		for relative, body := range fixtures {
			if err := os.WriteFile(filepath.Join(workspace.Primary, filepath.FromSlash(relative)), body, 0o600); err != nil {
				return fail(err)
			}
			tracked = append(tracked, relative)
		}
	}
	steps := [][]string{{"init", "-b", "main"}, {"config", "user.email", "qualification@example.invalid"}, {"config", "user.name", "NTM Qualification"}, append([]string{"add"}, tracked...), {"commit", "-m", "lineage seed"}}
	for _, args := range steps {
		if _, err := providerGrokQualificationGit(ctx, workspace.Primary, args...); err != nil {
			return fail(err)
		}
	}
	if _, err := providerGrokQualificationGit(ctx, workspace.Primary, "worktree", "add", "--detach", workspace.Worktree, "HEAD"); err != nil {
		return fail(err)
	}
	if workspaceWrite {
		if err := os.WriteFile(filepath.Join(workspace.Worktree, providerGrokWorkspaceSecret), []byte("synthetic qualification sentinel\n"), 0o600); err != nil {
			return fail(err)
		}
	}
	return workspace, nil
}

func providerGrokQualificationGit(ctx context.Context, dir string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "LANG=C"}
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("prepare Grok lineage qualification repository: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func cleanupProviderGrokLineageWorkspace(ctx context.Context, workspace providerGrokLineageWorkspace) error {
	root, err := filepath.Abs(workspace.Root)
	if err != nil || !strings.HasPrefix(filepath.Base(root), "ntm-grok-lineage-qualification-") || filepath.Dir(filepath.Clean(workspace.Primary)) != root || filepath.Dir(filepath.Clean(workspace.Worktree)) != root || filepath.Dir(filepath.Clean(workspace.RuntimeHome)) != root {
		return errors.New("refusing unsafe Grok lineage qualification cleanup target")
	}
	var worktreeErr error
	if _, err := providerGrokQualificationGit(ctx, workspace.Primary, "worktree", "remove", "--force", workspace.Worktree); err != nil {
		worktreeErr = err
	}
	removeErr := os.RemoveAll(root)
	return errors.Join(worktreeErr, removeErr)
}

func providerGrokLineageWorkspaceRemoved(workspace providerGrokLineageWorkspace) bool {
	_, err := os.Stat(workspace.Root)
	return errors.Is(err, os.ErrNotExist)
}

func setGrokProtocolFailure(receipt *providerqualification.Receipt, result grok.Result, runErr error) {
	if runErr == nil {
		return
	}
	reason := result.ProtocolFailureReason
	if !reason.Valid() || (reason == "" && result.FailureCode == grok.ErrProtocol) {
		reason = provider.ProtocolOther
	}
	for i := range receipt.Checks {
		if receipt.Checks[i].Name == providerqualification.CheckIdentity && !receipt.Checks[i].Passed {
			receipt.Checks[i].FailureReason = reason
			return
		}
	}
}

func grokQualificationModelDetail(result grok.Result, runErr error, expectedPublicModel, expectedResolvedModel string) string {
	switch {
	case runErr != nil:
		exit := "none"
		if result.ExitCode != nil {
			exit = fmt.Sprint(*result.ExitCode)
		}
		stage := strings.TrimSpace(result.FailureStage)
		if stage == "" {
			stage = "unknown"
		}
		rpcCode := "none"
		if result.ProviderRPCErrorCode != nil {
			rpcCode = fmt.Sprint(*result.ProviderRPCErrorCode)
		}
		return fmt.Sprintf("provider_run_failed:%s:stage=%s:rpc_code=%s:exit=%s:stderr_bytes=%d:stderr_sha256=%s", result.FailureCode, stage, rpcCode, exit, result.Stderr.Bytes, result.Stderr.SHA256)
	case !result.Success || !result.CompletionConfirmed:
		return "terminal_completion_unverified"
	case !result.AcknowledgementVerified:
		return "nonce_acknowledgement_unverified"
	case !result.Authenticated:
		return "cached_authentication_unverified"
	case result.Model != expectedPublicModel || !grokDoctorModelEvidenceConfirmed(result.ModelEvidence):
		return "terminal_public_model_unverified"
	case result.ResolvedModel != expectedResolvedModel || result.ResolvedModelEvidence != "completion_metadata.usage.model_usage_singleton":
		return "terminal_resolved_model_unverified"
	case !result.RuntimeEventContract.Passed:
		return "normalized_runtime_event_contract_failed"
	default:
		return "terminal_public_and_resolved_model_verified"
	}
}

func grokQualificationChecks() []providerqualification.Check {
	return grokQualificationChecksForProducer("xai-acp-observe-only")
}

func grokQualificationChecksForProducer(producer string) []providerqualification.Check {
	names := providerqualification.GrokRequiredChecks()
	checks := make([]providerqualification.Check, len(names))
	for i, name := range names {
		checks[i] = providerqualification.Check{
			Name: name, Passed: false, Provenance: "live",
			EvidenceSHA256: sha256StringCLI(producer + "-unexercised:" + name),
			Detail:         "not exercised by " + producer + " producer",
		}
	}
	return checks
}

func setGrokQualificationCheck(receipt *providerqualification.Receipt, name string, passed bool, provenance, evidence, detail string) {
	if receipt == nil {
		return
	}
	for i := range receipt.Checks {
		if receipt.Checks[i].Name == name {
			receipt.Checks[i].Passed = passed
			receipt.Checks[i].Provenance = provenance
			receipt.Checks[i].EvidenceSHA256 = evidence
			receipt.Checks[i].Detail = detail
			return
		}
	}
}
