package cli

import (
	"context"
	"errors"
	"fmt"
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

// providerGrokQualificationDependencies keeps the observe-only producer
// separately injectable. Later scenario-specific runners can add evidence to
// the same xai_acp receipt matrix without changing receipt semantics.
type providerGrokQualificationDependencies struct {
	authority      func(context.Context, string, config.ProviderProfileConfig, provider.Identity) (string, error)
	version        func(context.Context, string) (string, error)
	run            func(context.Context, grok.Runner, grok.Request) (grok.Result, error)
	runSession     func(context.Context, grok.LifecycleRunner, grok.SessionRequest) (grok.SessionReceipt, error)
	sessionRunner  grok.LifecycleRunner
	prepareLineage func(context.Context, string) (providerGrokLineageWorkspace, error)
	cleanupLineage func(context.Context, providerGrokLineageWorkspace) error
	hashBinary     func(string) (string, error)
	store          func(string, providerqualification.Receipt) (string, error)
	sign           func(context.Context, *providerqualification.Receipt) error
	preflight      func(context.Context) error
	pinnedSigner   func(config.ProviderProfileConfig) (func(context.Context, []byte) (providerattestation.SignatureMetadata, error), error)
	admission      providerDoctorAdmission
	now            func() time.Time
	getwd          func() (string, error)
	newNonce       func() (string, error)
}

var providerGrokQualificationDeps = providerGrokQualificationDependencies{
	authority: func(ctx context.Context, cwd string, profile config.ProviderProfileConfig, identity provider.Identity) (string, error) {
		return verifyGrokACPDispatchAuthority(ctx, cwd, profile, identity, providerDoctorDeps)
	},
	version:        providerRuntimeVersion,
	run:            grok.Run,
	runSession:     grok.ExecuteSession,
	sessionRunner:  grok.HeadlessOSRunner{},
	prepareLineage: prepareProviderGrokLineageWorkspace,
	cleanupLineage: cleanupProviderGrokLineageWorkspace,
	hashBinary:     hashProviderSessionExecutable,
	store:          providerqualification.Store,
	sign:           signProviderQualificationReceipt,
	preflight: func(ctx context.Context) error {
		return preflightProviderReceiptSigner(ctx, signProviderReceiptPayload)
	},
	pinnedSigner: providerGrokPinnedSigner,
	admission:    ratelimit.DefaultAdmissionController(),
	now:          func() time.Time { return time.Now().UTC() },
	getwd:        os.Getwd,
	newNonce:     providerDoctorNonce,
}

// runProviderGrokQualification produces a signed, transport-specific xai_acp
// receipt using one observe-only request. It is deliberately not a promotion
// shortcut: it can pass only structured served-model identity and locally
// observed zero-residual cleanup. Every tool, edit, denial, cancellation, and
// resume gate remains explicitly false until a dedicated scenario runner has
// observed that behavior.
func runProviderGrokQualification(cmd *cobra.Command, opts providerQualificationOptions, profile config.ProviderProfileConfig, identity provider.Identity, deps providerGrokQualificationDependencies) error {
	if identity.Provider() != "xai" || identity.Runtime() != "grok" || profile.AutomationPolicy != agent.DefaultGrokAutomationPolicyName {
		return errors.New("Grok qualification requires an exact xAI/Grok profile using the observe-only managed policy")
	}
	if opts.identityOnly || opts.exerciseUnknownOutcomeLifecycle || opts.acceptFullWeekReservation {
		return errors.New("Grok qualification currently supports only the observe-only producer; no lifecycle or identity-only variant exists")
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
			return preflightProviderReceiptSigner(ctx, signPayload)
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
	decision := deps.admission.Acquire(identity)
	if !decision.Allowed || !decision.NoFailover {
		if decision.Allowed {
			deps.admission.Release(identity, decision)
		}
		return errors.New("Grok qualification admission was denied for the exact identity; failover is prohibited")
	}
	defer deps.admission.Release(identity, decision)
	if opts.grokHeadlessLineage {
		if deps.runSession == nil || deps.sessionRunner == nil || deps.prepareLineage == nil || deps.cleanupLineage == nil || deps.hashBinary == nil {
			return errors.New("Grok headless lineage qualification dependencies are incomplete")
		}
		return runProviderGrokHeadlessLineageQualification(commandCtx, cmd, opts, profile, identity, binary, runtimeVersion, runtimeSHA256, signReceipt, deps)
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
	result, runErr := deps.run(runCtx, grok.OSRunner{}, grok.Request{
		Prompt: "Reply with this exact nonce and no other text. Do not use tools: " + nonce,
		CWD:    cwd, Binary: binary, RuntimeHome: profile.RuntimeHome, Model: identity.Model(), RuntimeVersion: profile.RuntimeVersion, ExpectedNonce: nonce,
		AutomationPolicyArgs: agent.GrokAutomationACPPolicyArgs(profile.AutomationPolicy),
	})
	runCancel()
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
	// This cannot be reached by the current observe-only producer because its
	// unexercised gates are intentionally false. Keep the success accounting
	// correct if a future complete scenario runner replaces it.
	deps.admission.RecordSuccess(identity)
	return nil
}

type providerGrokLineageWorkspace struct {
	Root        string
	Primary     string
	Worktree    string
	RuntimeHome string
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
	bootstrap, bootstrapErr := deps.run(bootstrapCtx, grok.OSRunner{}, grok.Request{
		Prompt:        "Do not call tools. Reply with this exact nonce and no other text: " + bootstrapNonce,
		ExpectedNonce: bootstrapNonce, CWD: workspace.Worktree, RuntimeHome: workspace.RuntimeHome,
		Binary: binary, Model: identity.Model(), RuntimeVersion: profile.RuntimeVersion,
		AutomationPolicyArgs: agent.GrokAutomationACPPolicyArgs(profile.AutomationPolicy),
	})
	bootstrapCancel()

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
	return deps.runSession(stepCtx, deps.sessionRunner, grok.SessionRequest{
		Action: action, SessionID: parentSessionID,
		Prompt:        "Do not call tools. Reply with this exact nonce and no other text: " + nonce,
		ExpectedNonce: nonce, CWD: workspace.Worktree, Worktree: workspace.Worktree,
		RuntimeHome: workspace.RuntimeHome, Binary: binary, Model: identity.Model(), RuntimeVersion: profile.RuntimeVersion,
		PolicyArgs:   agent.GrokAutomationLifecyclePolicyArgs(profile.AutomationPolicy),
		PolicySHA256: policySHA256, ConfigSHA256: identity.ConfigSHA256(), BinarySHA256: binarySHA256,
	})
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
	if ctx == nil || !filepath.IsAbs(filepath.Clean(sourceRuntimeHome)) {
		return providerGrokLineageWorkspace{}, errors.New("Grok lineage qualification requires an absolute isolated runtime home")
	}
	authPath := filepath.Join(filepath.Clean(sourceRuntimeHome), "auth.json")
	authInfo, err := os.Lstat(authPath)
	if err != nil || !authInfo.Mode().IsRegular() || authInfo.Mode()&os.ModeSymlink != 0 || authInfo.Size() <= 0 || authInfo.Size() > 1<<20 {
		return providerGrokLineageWorkspace{}, errors.New("Grok lineage qualification requires a bounded regular cached-login file")
	}
	auth, err := os.ReadFile(authPath)
	if err != nil {
		return providerGrokLineageWorkspace{}, errors.New("Grok lineage qualification could not read the cached login")
	}
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
	if err := os.WriteFile(filepath.Join(workspace.RuntimeHome, "auth.json"), auth, 0o600); err != nil {
		return fail(errors.New("Grok lineage qualification could not isolate the cached login"))
	}
	if err := os.WriteFile(filepath.Join(workspace.Primary, "README.md"), []byte("lineage qualification\n"), 0o600); err != nil {
		return fail(err)
	}
	for _, args := range [][]string{{"init", "-b", "main"}, {"config", "user.email", "qualification@example.invalid"}, {"config", "user.name", "NTM Qualification"}, {"add", "README.md"}, {"commit", "-m", "lineage seed"}} {
		if _, err := providerGrokQualificationGit(ctx, workspace.Primary, args...); err != nil {
			return fail(err)
		}
	}
	if _, err := providerGrokQualificationGit(ctx, workspace.Primary, "worktree", "add", "--detach", workspace.Worktree, "HEAD"); err != nil {
		return fail(err)
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

func grokQualificationModelDetail(result grok.Result, runErr error, expectedPublicModel, expectedResolvedModel string) string {
	switch {
	case runErr != nil:
		return "provider_run_failed"
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
