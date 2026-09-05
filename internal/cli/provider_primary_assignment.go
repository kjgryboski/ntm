package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/grok"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/state"
	"github.com/spf13/cobra"
)

const primaryAssignmentScope = "provider:primary-assignment"

func newProviderAcceptanceCmd() *cobra.Command {
	var directory string
	cmd := &cobra.Command{Use: "acceptance", Short: "Prepare the common isolated coding acceptance fixture without calling a provider", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&directory, "directory", "", "New absolute fixture directory (must not already exist)")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if !filepath.IsAbs(directory) {
			return errors.New("acceptance fixture requires a new absolute directory")
		}
		if err := os.Mkdir(directory, 0700); err != nil {
			return err
		}
		base, worktree := filepath.Join(directory, "base"), filepath.Join(directory, "workspace")
		if err := os.Mkdir(base, 0700); err != nil {
			return err
		}
		ctx := providerCommandContext(cmd)
		if _, err := providerGrokQualificationGit(ctx, base, "init", "--initial-branch=main"); err != nil {
			return err
		}
		files := map[string]string{"go.mod": "module providerparityfixture\n\ngo 1.26.3\n", "calc.go": "package fixture\n\nfunc Add(a, b int) int { return a - b }\n", "calc_test.go": "package fixture\n\nimport \"testing\"\n\nfunc TestAdd(t *testing.T) { for _, tc := range [][3]int{{2,3,5},{-4,7,3},{0,0,0}} { if got := Add(tc[0],tc[1]); got != tc[2] { t.Fatalf(\"Add(%d,%d) = %d, want %d\",tc[0],tc[1],got,tc[2]) } } }\n"}
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(base, name), []byte(content), 0600); err != nil {
				return err
			}
		}
		if _, err := providerGrokQualificationGit(ctx, base, "add", "go.mod", "calc.go", "calc_test.go"); err != nil {
			return err
		}
		if _, err := providerGrokQualificationGit(ctx, base, "-c", "user.name=NTM Acceptance", "-c", "user.email=fixture@localhost", "-c", "commit.gpgsign=false", "commit", "-m", "Initialize provider acceptance fixture"); err != nil {
			return err
		}
		if _, err := providerGrokQualificationGit(ctx, base, "worktree", "add", "--detach", worktree, "HEAD"); err != nil {
			return err
		}
		revision, err := providerGrokQualificationGit(ctx, base, "rev-parse", "HEAD")
		if err != nil {
			return err
		}
		manifest := map[string]any{"schema_version": "ntm.provider-acceptance.v1", "worktree": worktree, "base_revision": revision, "prompt": "Fix Add in calc.go so the existing tests pass. Keep the tests unchanged. Read the current file, use its SHA-256 when writing, and run verify_worktree after the final edit.", "tests_sha256": sha256StringCLI(files["calc_test.go"]), "scenario_sha256": digestSafeJSON(files), "expected_evidence": []string{"exact_identity", "workspace_edit", "passing_verification", "completion", "local_cleanup", "capacity_release"}, "lifecycle_evidence": []string{"local_cancellation", "guarded_restart"}, "remote_generation_termination": "unverified", "retry_rule": "Another paid attempt requires a relevant fix or new diagnostic evidence. Compare permits one attempt per durable experiment ID; ordinary tasks use distinct durable operation IDs. Unknown outcomes must not be replayed.", "provider_calls": 0}
		encoded, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(directory, "acceptance.json"), encoded, 0600); err != nil {
			return err
		}
		return encodeIndentedJSON(cmd.OutOrStdout(), manifest)
	}
	return cmd
}

type primaryAssignmentOutput struct {
	Schema             string                       `json:"schema_version"`
	Profile            string                       `json:"profile"`
	IdentitySHA256     string                       `json:"identity_sha256"`
	OperationIDSHA256  string                       `json:"operation_id_sha256"`
	BindingSHA256      string                       `json:"binding_sha256"`
	RuntimeSHA256      string                       `json:"runtime_sha256"`
	RequestedModel     string                       `json:"requested_model"`
	Observation        primaryComparisonObservation `json:"observation"`
	State              string                       `json:"state"`
	CleanupVerified    bool                         `json:"local_cleanup_verified"`
	WorkspaceVerified  bool                         `json:"workspace_verified"`
	CompletionEvidence string                       `json:"completion_evidence,omitempty"`
	AuditSHA256        string                       `json:"audit_sha256"`
	StartedAt          time.Time                    `json:"started_at"`
	CompletedAt        time.Time                    `json:"completed_at"`
	// Reuse the existing digest-only hardware signing envelope. This contains
	// only an operation_binding check, cannot pass qualification, and is kept
	// solely in the operation ledger, never in the qualification store.
	Envelope *providerqualification.Receipt `json:"attestation_envelope,omitempty"`
}

func primaryAssignmentDigest(out primaryAssignmentOutput) string {
	out.Envelope = nil
	return digestSafeJSON(out)
}

// Qualification retains its nonce-bound identity probe. Ordinary completion
// instead requires the pinned runtime's successful terminal event and the
// controller's independent verifier. An assistant's prose alone grants nothing.
func primaryAssignmentCompleted(out primaryAssignmentOutput) bool {
	return out.CompletionEvidence == "runtime_terminal_and_controller_verifier" &&
		out.Observation.terminalModelVerified(out.RequestedModel) && out.WorkspaceVerified && out.CleanupVerified
}

func primaryAssignmentEnvelope(out primaryAssignmentOutput, identity provider.Identity, version, cwd string) providerqualification.Receipt {
	transport := "anthropic_claude_comparison"
	if identity.Provider() == "openai" {
		transport = "openai_codex_comparison"
	}
	return providerqualification.Receipt{Mode: providerqualification.ModeLive, Provider: identity.Provider(), Transport: transport, IdentitySHA256: identity.Hash(), PolicySHA256: sha256StringCLI(primaryComparisonPolicy + "\x00" + transport), RuntimeVersion: version, RuntimeSHA256: out.RuntimeSHA256, StartedAt: out.StartedAt, CompletedAt: out.CompletedAt, DisposableRepoHash: sha256StringCLI(cwd), Checks: []providerqualification.Check{{Name: "operation_binding", Passed: true, Provenance: "local_authoritative", EvidenceSHA256: primaryAssignmentDigest(out), Detail: "ordinary assignment evidence only; not a qualification"}}}
}

func validPrimaryAssignment(out primaryAssignmentOutput, row *state.SendOperation, identity provider.Identity, trusted providerattestation.KeyMetadata) bool {
	if row == nil || out.Schema != "ntm.primary-assignment.v1" || out.IdentitySHA256 != identity.Hash() || out.BindingSHA256 != row.BindingHash || out.OperationIDSHA256 != sha256StringCLI(row.OperationID) || out.RequestedModel != identity.Model() || out.Envelope == nil || out.Envelope.Passed || out.Envelope.Validate() != nil || out.Envelope.IdentitySHA256 != identity.Hash() || out.Envelope.Attestation == nil || out.Envelope.Attestation.KeyMetadata != trusted || len(out.Envelope.Checks) != 1 {
		return false
	}
	check := out.Envelope.Checks[0]
	return check.Name == "operation_binding" && check.EvidenceSHA256 == primaryAssignmentDigest(out) && providerqualification.AuthoritativePassedCheck(check)
}

func primaryClaudeArguments(home, model, prompt, nonce string, descriptor *grok.WorkspaceBrokerDescriptor) ([]string, error) {
	if !grok.ValidNonce(nonce) {
		return nil, errors.New("Claude completion contract requires a controller nonce")
	}
	encoded, err := json.Marshal(descriptor)
	if err != nil {
		return nil, err
	}
	var broker struct {
		Command string
		Args    []string
	}
	if err = json.Unmarshal(encoded, &broker); err != nil {
		return nil, err
	}
	mcp := map[string]any{"mcpServers": map[string]any{grok.WorkspaceBrokerMCPName: map[string]any{"command": broker.Command, "args": broker.Args, "env": map[string]string{}}}}
	data, err := json.Marshal(mcp)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, "mcp.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		return nil, err
	}
	return []string{"--print", "--verbose", "--output-format", "stream-json", "--tools", "", "--permission-mode", "dontAsk", "--setting-sources", "", "--settings", `{"disableAllHooks":true}`, "--strict-mcp-config", "--mcp-config", path, "--allowedTools", "mcp__ntm-controlled-workspace__read_file,mcp__ntm-controlled-workspace__write_file,mcp__ntm-controlled-workspace__verify_worktree", "--append-system-prompt", primaryClaudeCompletionInstruction(nonce), "--model", model, prompt}, nil
}

func primaryClaudeCompletionInstruction(nonce string) string {
	return "This is a controller-managed coding assignment. Use only the controlled workspace tools. After the final edit, verify_worktree must succeed. If verification fails, report failure and do not emit the nonce. On success your final response must contain exactly the completion nonce on the next line, with no explanation, formatting, or other text:\n" + nonce
}

func primaryWorkspaceArguments(home, model, runtime, prompt, nonce string, descriptor *grok.WorkspaceBrokerDescriptor) ([]string, error) {
	if runtime == "claude" {
		return primaryClaudeArguments(home, model, prompt, nonce, descriptor)
	}
	if runtime != "codex" {
		return nil, errors.New("unsupported primary runtime")
	}
	encoded, err := json.Marshal(descriptor)
	if err != nil {
		return nil, err
	}
	var broker struct {
		Command string
		Args    []string
	}
	if err = json.Unmarshal(encoded, &broker); err != nil {
		return nil, err
	}
	settings := primaryCodexComparisonSettings(model, broker.Command, broker.Args)
	path, err := writePrimaryCodexToolCatalog(home, model)
	if err != nil {
		return nil, err
	}
	settings["model_catalog_json"] = path
	var b bytes.Buffer
	if err = toml.NewEncoder(&b).Encode(settings); err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(home, "config.toml"), b.Bytes(), 0600); err != nil {
		return nil, err
	}
	return []string{"exec", "--json", "--sandbox", "read-only", "--model", model, prompt}, nil
}

func copyPrimaryCredential(profile config.ProviderProfileConfig, destination string) error {
	name := "auth.json"
	if profile.Runtime == "claude" {
		name = ".credentials.json"
	}
	source := filepath.Join(profile.RuntimeHome, name)
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 {
		return errors.New("primary runtime requires a bounded regular account credential file")
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return errors.New("primary credential file could not be read")
	}
	defer func() {
		for i := range data {
			data[i] = 0
		}
	}()
	if !primaryComparisonCredentialValid(data, profile.Runtime) {
		return errors.New("primary runtime requires subscription OAuth credentials; API-key substitution is prohibited")
	}
	if !primaryCredentialSnapshotFresh(data, profile.Runtime, time.Now()) {
		return errors.New("primary Claude credential snapshot is expired or expires within five minutes; refresh the exact account snapshot before dispatch")
	}
	return os.WriteFile(filepath.Join(destination, name), data, 0600)
}

// Disposable runtime homes do not own the account's refresh-token lifecycle.
// Require a currently usable Claude snapshot instead of attempting generation
// with an expired copy whose refresh token may already have rotated elsewhere.
func primaryCredentialSnapshotFresh(data []byte, runtime string, now time.Time) bool {
	if runtime != "claude" {
		return true
	}
	var credential struct {
		OAuth struct {
			ExpiresAt int64 `json:"expiresAt"`
		} `json:"claudeAiOauth"`
	}
	return json.Unmarshal(data, &credential) == nil && credential.OAuth.ExpiresAt > now.Add(5*time.Minute).UnixMilli()
}

// An ordinary completion requires a final controller-owned verification,
// not merely a provider's acknowledgement. Any later successful write revokes it.
func primaryWorkspaceVerified(audit providerGrokWorkspaceAudit, cwd, revision string, started, completed time.Time) bool {
	verified := false
	for _, event := range audit.Events {
		if event.Tool == "write_file" && event.Success {
			verified = false
		}
		if event.Tool == "verify_worktree" {
			verified = event.Success && !event.Rejected && validProviderGrokVerificationReceipt(event.VerificationReceipt, sha256StringCLI(cwd), sha256StringCLI(revision), sha256StringCLI(cwd+"\x00"+revision+"\x00go-test\x00go-vet"), event.OccurredAt, started, completed)
		}
	}
	return verified
}

func createPrimaryAssignmentAudit(cwd, operationID string) (string, *os.File, error) {
	path := filepath.Join(filepath.Dir(cwd), ".ntm-primary-"+sha256StringCLI(operationID)+".jsonl")
	guard, err := createProviderGrokWorkspaceAudit(path, cwd)
	return path, guard, err
}

func runPrimaryAssignment(cmd *cobra.Command, request providerAssignmentRequest, profile config.ProviderProfileConfig, ledger providerNativeOperationLedger) (returnErr error) {
	id, transport, err := validatePrimaryComparisonProfile(profile)
	if err != nil {
		return err
	}
	if runtime.GOOS != "linux" || request.ParentSession != "" || request.Timeout > 5*time.Minute {
		return errors.New("primary assignment requires bounded native workspace work; resume is unsupported")
	}
	ctx, cancel := context.WithTimeout(providerCommandContext(cmd), request.Timeout)
	defer cancel()
	digest, err := hashProviderSessionExecutable(profile.Command)
	if err != nil || digest != profile.RuntimeSHA256 {
		return errors.New("primary executable pin mismatch")
	}
	version, err := providerRuntimeVersion(ctx, profile.Command)
	if err != nil || !versionMatches(version, profile.RuntimeVersion) {
		return errors.New("primary runtime version mismatch")
	}
	sign, err := providerProfilePinnedSigner(profile)
	if err != nil {
		return err
	}
	preflight, err := preflightProviderReceiptSignerMetadata(ctx, sign)
	if err != nil {
		return err
	}
	companion := ""
	if id.Runtime() == "codex" {
		companion, err = hashProviderSessionExecutable(filepath.Join(filepath.Dir(profile.Command), "codex-code-mode-host"))
		if err != nil {
			return err
		}
		if _, err = primaryCodexCompanionDigest(profile.Command, companion); err != nil {
			return err
		}
	}
	policy := primaryWorkspacePolicySHA(transport, companion)
	if _, err = authorizeProviderOperation(providerOperationAuthorization{Identity: id, Transport: transport, PolicySHA256: policy, RuntimeVersion: version, RuntimeSHA256: digest, Operation: providerOperationWorkspaceWrite, MaxQualificationAge: 24 * time.Hour, TrustedSigner: preflight.KeyMetadata}); err != nil {
		return err
	}
	cwd, err := filepath.Abs(request.CWD)
	if err != nil {
		return err
	}
	binding := sha256StringCLI(id.Hash() + "\x00" + request.OperationID + "\x00" + sha256StringCLI(request.Prompt) + "\x00" + cwd + "\x00" + request.RestartOf)
	row, won, err := ledger.ClaimSendOperation(&state.SendOperation{OperationID: request.OperationID, SessionName: primaryAssignmentScope, BindingHash: binding, PayloadSHA256: id.Hash(), CreatedAt: time.Now().UTC()})
	if err != nil {
		return err
	}
	if !won {
		var out primaryAssignmentOutput
		if row.Status != state.SendOperationCompleted || row.BindingHash != binding || json.Unmarshal([]byte(row.OutcomeJSON), &out) != nil || !validPrimaryAssignment(out, row, id, preflight.KeyMetadata) {
			return errors.New("primary assignment is active, uncertain, or has an invalid receipt; do not replay")
		}
		return printPrimaryAssignment(cmd, out)
	}
	root, err := os.MkdirTemp("", "ntm-primary-operation-")
	if err != nil {
		return err
	}
	// Only the redacted audit survives. Remove the freshly owned runtime home,
	// which may contain credential copies or runtime transcripts.
	home := filepath.Join(root, "home")
	if err = os.Mkdir(home, 0700); err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, os.RemoveAll(home)) }()
	if err = copyPrimaryCredential(profile, home); err != nil {
		return err
	}
	revision, err := providerGrokQualificationGit(ctx, cwd, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	auditPath, guard, err := createPrimaryAssignmentAudit(cwd, request.OperationID)
	if err != nil {
		return err
	}
	defer guard.Close()
	broker, err := providerWorkspaceBrokerDescriptorWithAudit(ctx, cwd, auditPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(cwd, "go.mod")); err != nil {
		return errors.New("primary workspace adapter currently requires the qualified Go verifier")
	}
	nonce, err := providerDoctorNonce()
	if err != nil {
		return err
	}
	prompt := request.Prompt + "\nUse only the ntm-controlled-workspace tools. Finish with verify_worktree after your final write. On successful verification reply with exactly: " + nonce
	args, err := primaryWorkspaceArguments(home, id.Model(), id.Runtime(), prompt, nonce, broker)
	if err != nil {
		return err
	}
	out := primaryAssignmentOutput{Schema: "ntm.primary-assignment.v1", Profile: request.Profile, IdentitySHA256: id.Hash(), OperationIDSHA256: sha256StringCLI(request.OperationID), BindingSHA256: binding, RuntimeSHA256: digest, RequestedModel: id.Model(), State: "failed", StartedAt: time.Now().UTC()}
	// Exercise the exact operation envelope before acquiring capacity.
	probe := out
	probe.CompletedAt = probe.StartedAt
	envelope := primaryAssignmentEnvelope(probe, id, version, cwd)
	if err = envelope.Finalize(); err != nil {
		return err
	}
	if err = signProviderQualificationReceiptWith(ctx, &envelope, sign); err != nil {
		return err
	}
	if _, err = providerqualification.StorePrimaryComparisonDiagnostics("", transport, id.Hash(), policy, digest, out.StartedAt, out.StartedAt, "before_dispatch", providerqualification.PrimaryComparisonDiagnostic{}); err != nil {
		return err
	}
	admission := ratelimit.DefaultAdmissionController()
	if admission.CapacityStatus().Scope != provider.CapacityControlScopeLocalShared {
		return errors.New("shared local capacity is unavailable")
	}
	if err := reserveProviderExperiment(request.OperationID, id.Hash(), binding); err != nil {
		return err
	}
	decision, err := acquireProviderGrokQualificationTurn(ctx, admission, id)
	if err != nil {
		return err
	}
	result, runErr := (providerqualification.LocalRunner{}).Run(ctx, providerqualification.Invocation{Binary: profile.Command, Args: args, Dir: cwd, Env: primaryComparisonEnvironment(home, id.Runtime()), OutputLimit: 8 << 20})
	capacity := admission.ReleaseObserved(id, decision)
	capacityErr := provider.ObserveCapacityRelease(ctx, capacity)
	scanner := bufio.NewScanner(bytes.NewReader(result.Stdout))
	scanner.Buffer(make([]byte, 4096), 2<<20)
	for scanner.Scan() {
		out.Observation.observe(scanner.Bytes(), id.Runtime(), nonce)
	}
	out.Observation.Malformed = out.Observation.Malformed || scanner.Err() != nil || result.OutputTruncated
	if scanner.Err() != nil || result.OutputTruncated {
		out.Observation.FailureCategory = "output_incomplete"
	}
	out.Observation.ExitOK = runErr == nil && result.ExitCode == 0
	out.Observation.observeWarnings(result.Stderr)
	for i := range result.Stdout {
		result.Stdout[i] = 0
	}
	for i := range result.Stderr {
		result.Stderr[i] = 0
	}
	out.CompletedAt = time.Now().UTC()
	out.CleanupVerified = result.ProcessStarted && result.ResidualCheckPerformed && result.ProcessTreeTerminated && len(result.ResidualProcessIDs) == 0
	audit, auditErr := readProviderGrokWorkspaceAudit(guard, auditPath, cwd, revision)
	out.AuditSHA256 = digestSafeJSON(audit)
	out.WorkspaceVerified = auditErr == nil && primaryWorkspaceVerified(audit, cwd, revision, out.StartedAt, out.CompletedAt)
	out.CompletionEvidence = "runtime_terminal_and_controller_verifier"
	if primaryAssignmentCompleted(out) {
		out.State = "completed"
	}
	if errors.Is(ctx.Err(), context.Canceled) && out.CleanupVerified {
		out.State = "cancelled_local"
	}
	diagnostic := providerqualification.PrimaryComparisonDiagnostic{Completed: out.Observation.Completed, NonceVerified: out.Observation.NonceVerified, ModelMatched: out.Observation.ServedModel == id.Model(), Malformed: out.Observation.Malformed, UnexpectedTool: out.Observation.UnexpectedTool, EventCount: out.Observation.EventCount, ExitOK: out.Observation.ExitOK, TerminalCategory: out.Observation.TerminalCategory}
	diagnostic.FailureCategory = out.Observation.FailureCategory
	_, diagErr := providerqualification.StorePrimaryComparisonDiagnostics("", transport, id.Hash(), policy, digest, out.StartedAt, out.CompletedAt, "before_cleanup", diagnostic)
	if err = os.RemoveAll(home); err != nil {
		out.CleanupVerified = false
		out.State = "failed"
	}
	if capacityErr != nil || diagErr != nil {
		out.State = "failed"
	}
	sealed := primaryAssignmentEnvelope(out, id, version, cwd)
	if err = sealed.Finalize(); err != nil {
		return err
	}
	signCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer stop()
	if err = signProviderQualificationReceiptWith(signCtx, &sealed, sign); err != nil {
		return err
	}
	out.Envelope = &sealed
	if !validPrimaryAssignment(out, row, id, preflight.KeyMetadata) {
		return errors.New("primary terminal signature verification failed")
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return err
	}
	if err = ledger.CompleteSendOperation(request.OperationID, primaryAssignmentScope, string(encoded), out.CompletedAt); err != nil {
		return err
	}
	return printPrimaryAssignment(cmd, out)
}

func printPrimaryAssignment(cmd *cobra.Command, out primaryAssignmentOutput) error {
	if IsJSONOutput() {
		if err := encodeIndentedJSON(cmd.OutOrStdout(), out); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Provider assignment: %s; model: %s; local cleanup: %t; remote termination: unverified\n", out.State, out.Observation.ServedModel, out.CleanupVerified)
	}
	if out.State != "completed" {
		return errJSONFailure
	}
	return nil
}
