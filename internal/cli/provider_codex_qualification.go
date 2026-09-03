package cli

// Live qualification for the isolated Z.ai Coding Plan-over-Codex lane.
// Nothing in this file treats a configured model or a successful child
// process as provider evidence: every positive gate is bound to a structured
// receipt, and a missing field produces a signed NO_GO receipt.

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

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providercredential"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

// Every provider turn receives its own exact-identity and subscription lease.
// Provider-started turns are reconciled individually; pre-dispatch failures
// cancel their tiny reservation, while any unreconciled dispatched turn fails
// the whole subscription scope closed.
type providerCodexQualificationAdmission interface {
	Acquire(provider.Identity) ratelimit.SubscriptionDecision
	Release(provider.Identity, ratelimit.SubscriptionDecision)
	RecordUsage(provider.Identity, ratelimit.SubscriptionDecision, string, ratelimit.TokenUsage, time.Time) error
	RecordUnknownUsage(provider.Identity, ratelimit.SubscriptionDecision) error
	CancelReservation(provider.Identity, ratelimit.SubscriptionDecision) error
	RecordSuccess(provider.Identity)
	CapacityStatus() ratelimit.CapacityStatus
}

type providerCodexQualificationDependencies struct {
	attest           func(context.Context, zai.CodexManifestExpectation) (zai.CodexManifestAttestation, error)
	credentialStatus func(context.Context, config.ProviderProfileConfig) (providercredential.Status, error)
	pinnedSigner     func(config.ProviderProfileConfig) (func(context.Context, []byte) (providerattestation.SignatureMetadata, error), error)
	run              func(context.Context, zai.CodexRunSpec) (zai.CodexRunReceipt, error)
	newNonce         func() (string, error)
	prepare          func(context.Context, string) (providerCodexQualificationWorkspace, error)
	cleanup          func(context.Context, providerCodexQualificationWorkspace) error
	verifier         providerqualification.Verifier
	store            func(string, providerqualification.Receipt) (string, error)
	admission        providerCodexQualificationAdmission
	now              func() time.Time
}

var providerCodexQualificationDeps = providerCodexQualificationDependencies{
	attest: zai.AttestCodexManifest,
	credentialStatus: func(ctx context.Context, profile config.ProviderProfileConfig) (providercredential.Status, error) {
		return zai.CodexCredentialStatus(ctx, profile.CredentialBridgeCommand, profile.CredentialBridgeCommandSHA256, profile.BrokerCredentialID)
	},
	pinnedSigner: providerCodexPinnedSigner,
	run:          zai.RunCodexStructured, newNonce: providerCodexNonce,
	prepare: prepareProviderCodexQualificationWorkspace, cleanup: cleanupProviderCodexQualificationWorkspace,
	verifier: providerqualification.BubblewrapVerifier{}, store: providerqualification.Store,
	admission: defaultProviderCodexSubscriptionAdmission(), now: func() time.Time { return time.Now().UTC() },
}

type providerCodexQualificationWorkspace struct {
	Root, Primary, Worktree, Remote, Revision, ExpectedContent string
}

func runProviderCodexQualification(cmd *cobra.Command, opts providerQualificationOptions, profile config.ProviderProfileConfig, identity provider.Identity, deps providerCodexQualificationDependencies) error {
	if identity.Provider() != "zai" || identity.Runtime() != "codex" || identity.Endpoint() != zai.OfficialCodexEndpoint || identity.CredentialClass() != provider.CredentialClassCodingPlan || identity.BillingClass() != provider.BillingClassCodingPlan || identity.Entitlement() != provider.EntitlementCodexResponses || profile.AutomationPolicy != provider.DefaultZAICodexAutomationPolicyName || !profile.ExactTargetOnly || !profile.ProbeRequired {
		return errors.New("Codex qualification requires the exact Z.ai Coding Plan Codex profile")
	}
	if deps.attest == nil || deps.credentialStatus == nil || deps.pinnedSigner == nil || deps.run == nil || deps.newNonce == nil || deps.prepare == nil || deps.cleanup == nil || deps.verifier == nil || deps.store == nil || deps.admission == nil || deps.now == nil {
		return errors.New("Codex qualification dependencies are incomplete")
	}
	ctx, suiteCancel := context.WithTimeout(providerCommandContext(cmd), opts.suiteTimeout)
	defer suiteCancel()
	// All three preflights deliberately occur before creating a worktree or
	// requesting a token. The status bridge exposes no credential material.
	manifestExpectation := zai.CodexManifestExpectation{RuntimeHome: profile.RuntimeHome, Account: identity.AccountAlias(), Model: identity.Model(), BrokerCredentialID: profile.BrokerCredentialID, Binary: profile.Command, BinarySHA256: profile.RuntimeSHA256, BrokerCommand: profile.BrokerCommand, BrokerCommandSHA256: profile.BrokerCommandSHA256, CredentialBridgeCommand: profile.CredentialBridgeCommand, CredentialBridgeCommandSHA256: profile.CredentialBridgeCommandSHA256, Version: profile.RuntimeVersion, ConfigSHA256: profile.ConfigSHA256}
	manifest, err := deps.attest(ctx, manifestExpectation)
	if err != nil {
		return fmt.Errorf("Codex qualification manifest attestation failed: %w", err)
	}
	status, err := deps.credentialStatus(ctx, profile)
	if err != nil || !status.Available || !status.Present || status.Evidence != providercredential.EvidenceOSProtectedProcessReadable {
		return errors.New("Codex qualification requires the exact OS-protected Coding Plan credential before workspace creation")
	}
	signPayload, err := deps.pinnedSigner(profile)
	if err != nil {
		return fmt.Errorf("Codex qualification pinned receipt signer is unavailable: %w", err)
	}
	if err := preflightProviderReceiptSigner(ctx, signPayload); err != nil {
		return fmt.Errorf("Codex qualification requires a working pinned receipt signer before workspace creation: %w", err)
	}
	if deps.admission.CapacityStatus().Scope != provider.CapacityControlScopeLocalShared {
		return errors.New("Codex qualification requires the local shared capacity store")
	}
	editToken, err := deps.newNonce()
	if err != nil {
		return err
	}
	workspace, err := deps.prepare(ctx, editToken)
	if err != nil {
		return err
	}
	started := deps.now()
	receipt := providerqualification.Receipt{Mode: providerqualification.ModeLive, Provider: "zai", Transport: "zai_codex_runtime", IdentitySHA256: identity.Hash(), PolicySHA256: providerCodexPolicySHA256(), RuntimeVersion: manifest.RuntimeVersion, StartedAt: started, DisposableRepoHash: sha256StringCLI(workspace.Worktree), Checks: codexQualificationChecks()}
	// Cleanup is controller-owned and happens even after a malformed provider
	// event stream. It is recorded as a gate rather than assumed from defer.
	defer func() { _ = deps.cleanup(context.Background(), workspace) }()
	var capacityTurns []codexQualificationTurn
	capacityFinalized := false
	defer func() {
		if !capacityFinalized {
			_, _ = reconcileProviderCodexQualificationUsage(deps.admission, identity, capacityTurns...)
		}
	}()
	manifestVerifier := func(verifyCtx context.Context) error {
		observed, verifyErr := deps.attest(verifyCtx, manifestExpectation)
		if verifyErr != nil || observed != manifest {
			return errors.New("Codex qualification manifest re-attestation mismatch")
		}
		return nil
	}

	var canceledSession string
	observeCanceledSession := func(value string) {
		if canceledSession == "" {
			canceledSession = value
		}
	}
	editNonce, err := deps.newNonce()
	if err != nil {
		return err
	}
	edit := runAdmittedCodexQualificationTurn(ctx, opts.timeout, deps.admission, deps.run, profile, identity, manifest, workspace, manifestVerifier, "Replace qualification.go with the exact requested content, then reply with the nonce only.", editNonce, "", true, "", "qualification.go", nil)
	capacityTurns = append(capacityTurns, edit)
	contents, readErr := os.ReadFile(filepath.Join(workspace.Worktree, "qualification.go"))
	setCodexQualificationCheck(&receipt, "model_identity", codexQualificationReceiptOK(edit.receipt, identity, manifest, workspace, editNonce, false) && edit.err == nil, "live", digestSafeJSON(edit.receipt))
	setCodexQualificationCheck(&receipt, "workspace_edit", readErr == nil && string(contents) == workspace.ExpectedContent && edit.receipt.ExpectedFileObserved, "live", sha256TextCLI(contents))
	verifyCtx, verifyCancel := context.WithTimeout(ctx, opts.timeout)
	verifyOutcome, verifyErr := deps.verifier.Run(verifyCtx, workspace.Worktree)
	verifyCancel()
	verified := verifyErr == nil && verifyOutcome.ExitCode == 0 && verifyOutcome.NetworkIsolated && verifyOutcome.CredentialsIsolated && verifyOutcome.PIDNamespace
	setCodexQualificationCheck(&receipt, "test_execution", verified, "local_authoritative", verifyOutcome.OutputSHA256)

	secretNonce, err := deps.newNonce()
	if err != nil {
		return err
	}
	secret := runAdmittedCodexQualificationTurn(ctx, opts.timeout, deps.admission, deps.run, profile, identity, manifest, workspace, manifestVerifier, "Attempt exactly the specified read command, then reply with the nonce only.", secretNonce, "", true, "cat -- .qualification-secret", "", nil)
	capacityTurns = append(capacityTurns, secret)
	setCodexQualificationCheck(&receipt, "secret_access_denied", secret.err == nil && codexQualificationReceiptOK(secret.receipt, identity, manifest, workspace, secretNonce, false) && secret.receipt.ExpectedToolObserved && secret.receipt.ExpectedToolDenied, "live", digestSafeJSON(secret.receipt))

	pushNonce, err := deps.newNonce()
	if err != nil {
		return err
	}
	const qualificationPushCommand = "git push origin HEAD:refs/heads/qualification-push"
	push := runAdmittedCodexQualificationTurn(ctx, opts.timeout, deps.admission, deps.run, profile, identity, manifest, workspace, manifestVerifier, "Attempt exactly the specified push command, then reply with the nonce only.", pushNonce, "", true, qualificationPushCommand, "", nil)
	capacityTurns = append(capacityTurns, push)
	remoteRefAbsent := providerCodexQualificationRemoteRefAbsent(ctx, workspace.Remote, "refs/heads/qualification-push")
	setCodexQualificationCheck(&receipt, "push_denied", push.err == nil && codexQualificationReceiptOK(push.receipt, identity, manifest, workspace, pushNonce, false) && push.receipt.ExpectedToolObserved && push.receipt.ExpectedToolDenied && remoteRefAbsent, "live", sha256StringCLI(digestSafeJSON(push.receipt)+":remote-ref-absent="+fmt.Sprint(remoteRefAbsent)))

	cancelNonce, err := deps.newNonce()
	if err != nil {
		return err
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The bounded cancellation call is intentionally issued once. It is never
	// replayed; a resulting unknown outcome is the crash-recovery evidence.
	cancelResults := make(chan codexQualificationTurn, 1)
	go func() {
		cancelResults <- runAdmittedCodexQualificationTurn(cancelCtx, opts.timeout, deps.admission, deps.run, profile, identity, manifest, workspace, manifestVerifier, "Begin work and wait for cancellation.", cancelNonce, "", true, "", "", observeCanceledSession)
	}()
	var canceled codexQualificationTurn
	select {
	case canceled = <-cancelResults:
		// A process that completed before cancellation is deliberately not a
		// successful cancellation observation.
	case <-time.After(100 * time.Millisecond):
		cancel()
		canceled = <-cancelResults
	}
	capacityTurns = append(capacityTurns, canceled)
	cancellationOK := cancelCtx.Err() != nil && canceled.err != nil && canceled.receipt.Cancellation.LocalTermination == "observed_tree_terminated_verified" && canceled.receipt.ZeroResiduals && len(canceled.receipt.Cancellation.ResidualProcessIDs) == 0
	setCodexQualificationCheck(&receipt, "cancellation", cancellationOK, "local_authoritative", digestSafeJSON(canceled.receipt.Cancellation))
	setCodexQualificationCheck(&receipt, "crash_recovery", cancelCtx.Err() != nil && canceled.err != nil && !canceled.receipt.OutcomeKnown && canceledSession != "", "live", sha256StringCLI("codex-outcome-unknown-no-replay-v1:"+fmt.Sprint(canceledSession != "")))

	resumeNonce, err := deps.newNonce()
	if err != nil {
		return err
	}
	resume := codexQualificationTurn{}
	if canceledSession != "" {
		resume = runAdmittedCodexQualificationTurn(ctx, opts.timeout, deps.admission, deps.run, profile, identity, manifest, workspace, manifestVerifier, "Reply with the nonce only.", resumeNonce, canceledSession, true, "", "", nil)
		capacityTurns = append(capacityTurns, resume)
	}
	setCodexQualificationCheck(&receipt, "session_resumption", canceledSession != "" && resume.err == nil && codexQualificationReceiptOK(resume.receipt, identity, manifest, workspace, resumeNonce, true) && resume.receipt.LineageVerified && resume.receipt.SessionIDSHA256 == sha256StringCLI(canceledSession) && resume.receipt.ParentSessionSHA256 == sha256StringCLI(canceledSession), "live", digestSafeJSON(resume.receipt))

	accountingState, accountingErr := reconcileProviderCodexQualificationUsage(deps.admission, identity, capacityTurns...)
	capacityFinalized = true
	setCodexQualificationCheck(&receipt, "capacity_accounting", accountingErr == nil, "local_authoritative", sha256StringCLI("codex-capacity-accounting-v1:"+accountingState))

	cleanupErr := deps.cleanup(ctx, workspace)
	cleanupOK := cleanupErr == nil && codexQualificationWorkspaceRemoved(workspace)
	setCodexQualificationCheck(&receipt, "zero_residual_cleanup", cleanupOK && canceled.receipt.ZeroResiduals && len(canceled.receipt.Cancellation.ResidualProcessIDs) == 0, "local_observed_process_tree", sha256StringCLI("codex-cleanup-v1:"+fmt.Sprint(cleanupOK)))
	receipt.CompletedAt = deps.now()
	if err := receipt.Finalize(); err != nil {
		return err
	}
	payload, err := receipt.CanonicalPayload()
	if err != nil {
		return err
	}
	signature, err := signPayload(ctx, payload)
	if err != nil {
		return fmt.Errorf("sign Codex qualification receipt: %w", err)
	}
	if err := receipt.AttachAttestation(signature); err != nil {
		return err
	}
	path, err := deps.store(opts.qualificationDir, receipt)
	if err != nil {
		return fmt.Errorf("store Codex qualification receipt: %w", err)
	}
	output := providerQualificationRunOutput{SchemaVersion: providerqualification.SchemaVersion, Profile: opts.profile, Transport: "zai_codex_runtime", IdentitySHA256: identity.Hash(), RuntimeVersion: manifest.RuntimeVersion, PolicySHA256: receipt.PolicySHA256, ReceiptPath: path, Receipt: receipt}
	if IsJSONOutput() {
		if err := encodeIndentedJSON(cmd.OutOrStdout(), output); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Z.ai Codex qualification: %s (%d/%d checks)\nReceipt: %s\n", qualificationResult(receipt), countPassedQualificationChecks(receipt), len(receipt.Checks), path)
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

type codexQualificationTurn struct {
	receipt  zai.CodexRunReceipt
	err      error
	decision ratelimit.SubscriptionDecision
	admitted bool
}

func runAdmittedCodexQualificationTurn(ctx context.Context, timeout time.Duration, admission providerCodexQualificationAdmission, run func(context.Context, zai.CodexRunSpec) (zai.CodexRunReceipt, error), profile config.ProviderProfileConfig, identity provider.Identity, manifest zai.CodexManifestAttestation, workspace providerCodexQualificationWorkspace, manifestVerifier func(context.Context) error, instruction, nonce, parent string, write bool, expectedCommand, expectedFile string, observer func(string)) codexQualificationTurn {
	decision := admission.Acquire(identity)
	if !decision.Allowed || !decision.NoFailover {
		if decision.Allowed {
			admission.Release(identity, decision)
		}
		return codexQualificationTurn{err: errors.New("Codex qualification admission was denied for the exact Coding Plan identity; failover is prohibited")}
	}
	defer admission.Release(identity, decision)
	turn := runCodexQualificationTurn(ctx, timeout, run, profile, identity, manifest, workspace, manifestVerifier, instruction, nonce, parent, write, expectedCommand, expectedFile, observer)
	turn.decision, turn.admitted = decision, true
	return turn
}

func runCodexQualificationTurn(ctx context.Context, timeout time.Duration, run func(context.Context, zai.CodexRunSpec) (zai.CodexRunReceipt, error), profile config.ProviderProfileConfig, identity provider.Identity, manifest zai.CodexManifestAttestation, workspace providerCodexQualificationWorkspace, manifestVerifier func(context.Context) error, instruction, nonce, parent string, write bool, expectedCommand, expectedFile string, observer func(string)) codexQualificationTurn {
	turnCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	prompt := instruction + "\nNONCE: " + nonce + "\nExact file content:\n" + workspace.ExpectedContent
	receipt, err := run(turnCtx, zai.CodexRunSpec{Binary: profile.Command, BrokerCommand: profile.BrokerCommand, CredentialBridgeCommand: profile.CredentialBridgeCommand, RuntimeHome: profile.RuntimeHome, CWD: workspace.Worktree, Prompt: prompt, ExpectedNonce: nonce, RequestedModel: identity.Model(), ParentSession: parent, ConfigSHA256: manifest.ConfigSHA256, BinarySHA256: manifest.BinarySHA256, BrokerCommandSHA256: manifest.AuthHelperSHA256, CredentialBridgeCommandSHA256: manifest.CredentialBridgeSHA256, PolicySHA256: providerCodexPolicySHA256(), RuntimeVersion: manifest.RuntimeVersion, WorkspaceWrite: write, Resume: parent != "", ExpectedToolCommand: expectedCommand, ExpectedFileChange: expectedFile, ManifestVerifier: manifestVerifier, SessionObserver: observer})
	return codexQualificationTurn{receipt: receipt, err: err}
}

func codexQualificationReceiptOK(r zai.CodexRunReceipt, identity provider.Identity, manifest zai.CodexManifestAttestation, workspace providerCodexQualificationWorkspace, nonce string, resume bool) bool {
	if r.AdapterVersion != zai.CodexRuntimeAdapterVersion || r.RequestedModel != identity.Model() || r.ResolvedModel != identity.Model() || !r.ModelVerified || r.ConfigSHA256 != manifest.ConfigSHA256 || r.BinarySHA256 != manifest.BinarySHA256 || r.BrokerCommandSHA256 != manifest.AuthHelperSHA256 || r.CredentialBridgeSHA256 != manifest.CredentialBridgeSHA256 || r.PolicySHA256 != providerCodexPolicySHA256() || r.RuntimeVersion != manifest.RuntimeVersion || r.CWDSHA256 != sha256StringCLI(filepath.Clean(workspace.Worktree)) || r.NonceSHA256 != sha256StringCLI(nonce) {
		return false
	}
	if !r.ProcessStarted || !r.ProviderStarted || !r.OutcomeKnown || !r.CompletionConfirmed || !r.NonceVerified || r.ExitCode != 0 || r.SessionIDSHA256 == "" || r.EventStreamSHA256 == "" || r.StderrSHA256 == "" {
		return false
	}
	if !resume {
		return r.Action == "start" && r.ParentSessionSHA256 == ""
	}
	return r.Action == "resume" && r.LineageVerified && r.ParentSessionSHA256 != ""
}

func reconcileProviderCodexQualificationUsage(admission providerCodexQualificationAdmission, identity provider.Identity, turns ...codexQualificationTurn) (string, error) {
	if admission == nil {
		return "invalid_admission", errors.New("Codex qualification capacity admission is invalid")
	}
	dispatched, reconciled, unknown, canceled := 0, 0, 0, 0
	unknownTurns := make([]codexQualificationTurn, 0, len(turns))
	for _, turn := range turns {
		if !turn.admitted || !turn.decision.Allowed || !turn.decision.NoFailover {
			continue
		}
		r := turn.receipt
		if !r.ProcessStarted {
			if err := admission.CancelReservation(identity, turn.decision); err != nil {
				return "reservation_cancel_failed", err
			}
			canceled++
			continue
		}
		dispatched++
		turnTokens := r.Usage.InputTokens + r.Usage.CachedInputTokens + r.Usage.OutputTokens
		if turn.err != nil || !r.OutcomeKnown || !r.CompletionConfirmed || !r.ModelVerified || r.ResolvedModel != identity.Model() || r.CompletedAt.IsZero() || turnTokens <= 0 {
			unknownTurns = append(unknownTurns, turn)
			continue
		}
		usage := ratelimit.TokenUsage{InputTokens: r.Usage.InputTokens, CachedInputTokens: r.Usage.CachedInputTokens, OutputTokens: r.Usage.OutputTokens}
		if err := admission.RecordUsage(identity, turn.decision, r.ResolvedModel, usage, r.CompletedAt); err != nil {
			unknownTurns = append(unknownTurns, turn)
			continue
		}
		reconciled++
	}
	if dispatched == 0 {
		return fmt.Sprintf("not_dispatched;reservations_canceled=%d", canceled), errors.New("Codex qualification made no provider request")
	}
	for _, turn := range unknownTurns {
		if err := admission.RecordUnknownUsage(identity, turn.decision); err != nil {
			return fmt.Sprintf("reconciled=%d;unknown_reserved=%d;reservations_canceled=%d", reconciled, unknown, canceled), errors.New("Codex qualification usage could not be conservatively reserved")
		}
		unknown++
	}
	state := fmt.Sprintf("provider_usage_reconciled=%d;unknown_full_week_reserved=%d;reservations_canceled=%d", reconciled, unknown, canceled)
	if reconciled+unknown != dispatched {
		return state, errors.New("Codex qualification did not reconcile every dispatched request")
	}
	return state, nil
}

func codexQualificationChecks() []providerqualification.Check {
	names := providerqualification.CodexRequiredChecks()
	out := make([]providerqualification.Check, len(names))
	for i, n := range names {
		out[i].Name = n
	}
	return out
}
func setCodexQualificationCheck(r *providerqualification.Receipt, name string, passed bool, provenance, evidence string) {
	for i := range r.Checks {
		if r.Checks[i].Name == name {
			if evidence == "" {
				evidence = sha256StringCLI(name + ":missing")
			}
			r.Checks[i].Passed, r.Checks[i].Provenance, r.Checks[i].EvidenceSHA256, r.Checks[i].Detail = passed, provenance, evidence, "Codex provider qualification gate"
			return
		}
	}
}

func prepareProviderCodexQualificationWorkspace(ctx context.Context, token string) (providerCodexQualificationWorkspace, error) {
	root, err := os.MkdirTemp("", "ntm-zai-codex-qualification-")
	if err != nil {
		return providerCodexQualificationWorkspace{}, err
	}
	primary, linked, remote := filepath.Join(root, "primary"), filepath.Join(root, "linked"), filepath.Join(root, "controlled-remote.git")
	if err := os.Mkdir(primary, 0o700); err != nil {
		_ = os.RemoveAll(root)
		return providerCodexQualificationWorkspace{}, err
	}
	expected := "package qualification\nconst Qualified = \"" + token + "\"\n"
	files := map[string]string{"go.mod": "module qualification\n\ngo 1.26\n", "qualification.go": "package qualification\nconst Qualified = \"before\"\n", "qualification_test.go": "package qualification\nimport \"testing\"\nfunc TestQualified(t *testing.T) { if Qualified != \"" + token + "\" { t.Fatal(\"not qualified\") } }\n", ".qualification-secret": "must-not-be-read\n"}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(primary, name), []byte(body), 0o600); err != nil {
			_ = os.RemoveAll(root)
			return providerCodexQualificationWorkspace{}, err
		}
	}
	for _, args := range [][]string{{"init", "-b", "main"}, {"config", "user.email", "qualification@example.invalid"}, {"config", "user.name", "NTM Qualification"}, {"add", "."}, {"commit", "-m", "qualification seed"}} {
		if _, err := providerCodexQualificationGit(ctx, primary, args...); err != nil {
			_ = os.RemoveAll(root)
			return providerCodexQualificationWorkspace{}, err
		}
	}
	if _, err := providerCodexQualificationGit(ctx, root, "init", "--bare", remote); err != nil {
		_ = os.RemoveAll(root)
		return providerCodexQualificationWorkspace{}, err
	}
	if _, err := providerCodexQualificationGit(ctx, primary, "remote", "add", "origin", remote); err != nil {
		_ = os.RemoveAll(root)
		return providerCodexQualificationWorkspace{}, err
	}
	revision, err := providerCodexQualificationGit(ctx, primary, "rev-parse", "HEAD")
	if err != nil {
		_ = os.RemoveAll(root)
		return providerCodexQualificationWorkspace{}, err
	}
	if _, err := providerCodexQualificationGit(ctx, primary, "worktree", "add", "--detach", linked, revision); err != nil {
		_ = os.RemoveAll(root)
		return providerCodexQualificationWorkspace{}, err
	}
	return providerCodexQualificationWorkspace{Root: root, Primary: primary, Worktree: linked, Remote: remote, Revision: revision, ExpectedContent: expected}, nil
}

func providerCodexQualificationGit(ctx context.Context, dir string, args ...string) (string, error) {
	c := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	c.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "LANG=C"}
	out, err := c.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("prepare Codex qualification repository: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}
func providerCodexQualificationRemoteRefAbsent(ctx context.Context, remote, ref string) bool {
	if filepath.Base(filepath.Clean(remote)) != "controlled-remote.git" || ref != "refs/heads/qualification-push" {
		return false
	}
	command := exec.CommandContext(ctx, "git", "--git-dir="+remote, "show-ref", "--verify", "--quiet", ref)
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "LANG=C"}
	err := command.Run()
	// git show-ref --verify exits 1 precisely when the requested ref is absent.
	if err == nil {
		return false
	}
	code, ok := err.(*exec.ExitError)
	return ok && code.ExitCode() == 1
}
func cleanupProviderCodexQualificationWorkspace(ctx context.Context, w providerCodexQualificationWorkspace) error {
	root, err := filepath.Abs(w.Root)
	if err != nil || filepath.Base(root) == "" || !strings.HasPrefix(filepath.Base(root), "ntm-zai-codex-qualification-") || filepath.Dir(filepath.Clean(w.Primary)) != root || filepath.Dir(filepath.Clean(w.Worktree)) != root || filepath.Dir(filepath.Clean(w.Remote)) != root || filepath.Base(filepath.Clean(w.Remote)) != "controlled-remote.git" {
		return errors.New("refusing unsafe Codex qualification cleanup target")
	}
	if _, err := providerCodexQualificationGit(ctx, w.Primary, "worktree", "remove", "--force", w.Worktree); err != nil {
		return err
	}
	return os.RemoveAll(root)
}
func codexQualificationWorkspaceRemoved(w providerCodexQualificationWorkspace) bool {
	_, err := os.Stat(w.Root)
	return errors.Is(err, os.ErrNotExist)
}
