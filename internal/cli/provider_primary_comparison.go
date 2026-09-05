package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/grok"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/state"
	"github.com/spf13/cobra"
)

const primaryComparisonPolicy = "primary-controlled-workspace-comparison-v1"

// Comparison is evidence production, never an alternative dispatch admission.
// Unavailable account/remote-lifecycle authority remains explicit even if a
// primary runtime is already usable through its ordinary pane workflow.
func newProviderPrimaryComparisonCmd() *cobra.Command {
	var profileName, signerName, codeModeHostSHA256, experimentID, changeEvidence string
	var live bool
	var timeout time.Duration
	cmd := &cobra.Command{Use: "compare", Short: "Compare a pinned primary runtime using the common workspace scenario", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&profileName, "profile", "", "Exact primary runtime profile")
	cmd.Flags().StringVar(&signerName, "signer-profile", "", "Profile supplying only the pinned local receipt signer")
	cmd.Flags().StringVar(&codeModeHostSHA256, "code-mode-host-sha256", "", "Reviewed companion executable SHA-256 (required for Codex comparison)")
	cmd.Flags().StringVar(&experimentID, "experiment-id", "", "Unique durable experiment ID; at most one live attempt")
	cmd.Flags().StringVar(&changeEvidence, "change-evidence-sha256", "", "Digest of the relevant fix or new diagnostic evidence permitting this attempt")
	cmd.Flags().BoolVar(&live, "live", false, "Authorize one bounded primary provider call")
	cmd.Flags().DurationVar(&timeout, "timeout", 90*time.Second, "Maximum provider run duration (at most five minutes)")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if !live || profileName == "" || signerName == "" || timeout <= 0 || timeout > 5*time.Minute || !validProviderNativeOperationID(experimentID) || !validProviderNativeDigest(changeEvidence) {
			return errors.New("comparison requires --live, exact profiles, --experiment-id, --change-evidence-sha256, and a timeout between zero and five minutes")
		}
		loaded := loadSelectedConfigOrDefault()
		if loaded == nil {
			return errors.New("comparison configuration is unavailable")
		}
		profile, err := loaded.ProviderProfile(profileName)
		if err != nil {
			return err
		}
		signer, err := loaded.ProviderProfile(signerName)
		if err != nil {
			return err
		}
		return runProviderPrimaryComparison(cmd, profileName, profile, signer, timeout, codeModeHostSHA256, experimentID, changeEvidence)
	}
	return cmd
}

func validatePrimaryComparisonProfile(p config.ProviderProfileConfig) (provider.Identity, string, error) {
	id, err := p.Identity()
	if err != nil {
		return id, "", err
	}
	transport := ""
	if id.Provider() == "openai" && id.Runtime() == "codex" && id.Endpoint() == "https://chatgpt.com/backend-api/codex" {
		transport = "openai_codex_comparison"
	}
	if id.Provider() == "anthropic" && id.Runtime() == "claude" && id.Endpoint() == "https://api.anthropic.com/" {
		transport = "anthropic_claude_comparison"
	}
	if transport == "" || p.CredentialClass != "oauth" || p.BillingClass != "subscription" || p.Entitlement != "primary_cli" || p.AutomationPolicy != primaryComparisonPolicy || !p.ExactTargetOnly || p.ConfigSHA256 != p.CanonicalManifestSHA256() || !filepath.IsAbs(p.Command) || !filepath.IsAbs(p.RuntimeHome) || p.RuntimeVersion == "" || !validProviderNativeDigest(p.RuntimeSHA256) {
		return id, "", errors.New("primary comparison requires a canonical exact-account/model manifest, absolute runtime and credential home, executable/version pins, and the managed comparison policy")
	}
	return id, transport, nil
}

type primaryComparisonObservation struct {
	TerminalSeen        bool   `json:"terminal_seen,omitempty"`
	FailureCategory     string `json:"failure_category,omitempty"`
	CodeModeUnavailable bool   `json:"code_mode_unavailable,omitempty"`
	MetadataFallback    bool   `json:"model_metadata_fallback,omitempty"`
	MCPStarted          int    `json:"mcp_calls_started,omitempty"`
	MCPCompleted        int    `json:"mcp_calls_completed,omitempty"`
	MCPFailed           int    `json:"mcp_calls_failed,omitempty"`
	TerminalCategory    string `json:"terminal_category,omitempty"`
	Completed           bool   `json:"completed"`
	NonceVerified       bool   `json:"nonce_verified"`
	ServedModel         string `json:"served_model,omitempty"`
	ModelConflict       bool   `json:"model_conflict"`
	Malformed           bool   `json:"malformed"`
	UnexpectedTool      bool   `json:"unexpected_tool"`
	EventCount          int    `json:"event_count"`
	ExitOK              bool   `json:"exit_ok"`
}

func (o primaryComparisonObservation) exactModelVerified(requested string) bool {
	return o.terminalModelVerified(requested) && o.NonceVerified
}

func (o primaryComparisonObservation) terminalModelVerified(requested string) bool {
	return requested != "" && o.ServedModel == requested && o.Completed &&
		o.ExitOK && !o.ModelConflict && !o.Malformed && !o.UnexpectedTool && !o.CodeModeUnavailable
}

// Only terminal assistant output can acknowledge work. Tool content, init
// configuration, and echoed requests cannot prove completion or served model.
func (o *primaryComparisonObservation) observe(line []byte, runtime, nonce string) {
	var e struct {
		Type        string          `json:"type"`
		Subtype     string          `json:"subtype"`
		IsError     bool            `json:"is_error"`
		Result      string          `json:"result"`
		ServerModel string          `json:"server_model"`
		Message     json.RawMessage `json:"message"`
		Item        struct {
			Type   string `json:"type"`
			Text   string `json:"text"`
			Status string `json:"status"`
			Server string `json:"server"`
			Tool   string `json:"tool"`
		} `json:"item"`
	}
	o.EventCount++
	if json.Unmarshal(line, &e) != nil {
		o.Malformed = true
		o.FailureCategory = "invalid_event_envelope"
		return
	}
	model := ""
	if o.TerminalSeen && (e.Type == "assistant" || e.Type == "item.started" || e.Type == "item.completed") {
		o.Malformed = true
		o.FailureCategory = "event_after_terminal"
	}
	if runtime == "claude" {
		if e.Type == "assistant" {
			// SDKMessage is a tagged union. User and system message fields
			// need not have the assistant's BetaMessage shape.
			var message struct {
				Model   string `json:"model"`
				Content []struct {
					Type string `json:"type"`
					Name string `json:"name"`
				} `json:"content"`
			}
			if json.Unmarshal(e.Message, &message) != nil {
				o.Malformed = true
				o.FailureCategory = "invalid_assistant_envelope"
				return
			}
			model = message.Model
			for _, c := range message.Content {
				if c.Type == "tool_use" && !strings.HasPrefix(c.Name, "mcp__ntm-controlled-workspace__") {
					o.UnexpectedTool = true
				}
			}
		}
		if e.Type == "result" {
			if o.TerminalSeen {
				o.Malformed = true
				o.FailureCategory = "duplicate_terminal"
			}
			o.TerminalSeen = true
			o.Completed = !e.IsError && e.Subtype == "success"
			o.NonceVerified = o.Completed && strings.TrimSpace(e.Result) == nonce
			o.TerminalCategory = primaryTerminalCategory(e.Result, nonce)
		}
	} else {
		if e.Item.Type == "mcp_tool_call" {
			if e.Type == "item.started" {
				o.MCPStarted++
			}
			if e.Type == "item.completed" {
				o.MCPCompleted++
				if e.Item.Status != "completed" {
					o.MCPFailed++
				}
			}
			if e.Item.Server != "" && e.Item.Server != grok.WorkspaceBrokerMCPName {
				o.UnexpectedTool = true
			}
		}
		if e.Type == "item.completed" {
			switch e.Item.Type {
			case "agent_message":
				o.NonceVerified = strings.TrimSpace(e.Item.Text) == nonce
				o.TerminalCategory = primaryTerminalCategory(e.Item.Text, nonce)
			case "command_execution", "file_change", "web_search":
				o.UnexpectedTool = true
			}
		}
		if e.Type == "turn.completed" {
			if o.TerminalSeen {
				o.Malformed = true
				o.FailureCategory = "duplicate_terminal"
			}
			o.TerminalSeen = true
			o.Completed = true
			model = e.ServerModel
		}
		if e.Type == "turn.failed" || e.Type == "error" {
			o.TerminalSeen = true
			o.Malformed = true
			o.FailureCategory = "runtime_error"
		}
	}
	if model != "" {
		prefix := "gpt-"
		if runtime == "claude" {
			prefix = "claude-"
		}
		if len(model) > 120 || !strings.HasPrefix(model, prefix) || strings.IndexFunc(model, func(r rune) bool {
			return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_')
		}) >= 0 {
			o.Malformed = true
			o.FailureCategory = "invalid_model_label"
			return
		}
		if o.ServedModel != "" && o.ServedModel != model {
			o.ModelConflict = true
		}
		o.ServedModel = model
	}
}

// Match only source-defined runtime warning categories. Never retain stderr,
// provider explanations, paths, arbitrary tool names, or error payloads.
func (o *primaryComparisonObservation) observeWarnings(data []byte) {
	o.CodeModeUnavailable = bytes.Contains(data, []byte("Code Mode is unavailable because"))
	o.MetadataFallback = bytes.Contains(data, []byte("Defaulting to fallback metadata"))
}

// The reviewed 0.153.0 standalone install resolves this companion beside the
// main executable. MCP inventory alone does not check Code Mode execution.
func primaryCodexCompanionDigest(binary, expected string) (string, error) {
	if !filepath.IsAbs(binary) || !validProviderNativeDigest(expected) {
		return "", errors.New("Codex comparison requires a reviewed code-mode-host SHA-256 before dispatch")
	}
	path := filepath.Join(filepath.Dir(binary), "codex-code-mode-host")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return "", errors.New("Codex code-mode companion is missing or not a regular executable; tool inventory is insufficient")
	}
	digest, err := hashProviderSessionExecutable(path)
	if err != nil || digest != expected {
		return "", errors.New("Codex code-mode companion digest differs from the reviewed pin")
	}
	return digest, nil
}

// These are prose hints, not failure authority or readiness evidence. Only the
// closed category survives; the explanation itself is never stored.
func primaryTerminalCategory(text, nonce string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return "empty"
	}
	if text == nonce {
		return "acknowledged"
	}
	text = strings.ToLower(text)
	switch {
	case strings.Contains(text, "read-only") || strings.Contains(text, "read only"):
		return "read_only_mentioned"
	case strings.Contains(text, "tool") && (strings.Contains(text, "unavailable") || strings.Contains(text, "not available") || strings.Contains(text, "no access") || strings.Contains(text, "not exposed") || strings.Contains(text, "don't have") || strings.Contains(text, "do not have")):
		return "tools_unavailable_mentioned"
	case strings.Contains(text, "permission") || strings.Contains(text, "not allowed") || strings.Contains(text, "cannot write"):
		return "permission_mentioned"
	default:
		return "other_text"
	}
}

func primaryComparisonEnvironment(home, runtime string) []string {
	// Both runtime and broker commands are absolute and pinned. A WSL host's
	// inherited PATH may resolve a Windows helper back through interop instead
	// of the native executable, so primary comparisons use only system paths.
	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + home, "LANG=C", "TERM=dumb"}
	if runtime == "codex" {
		env = append(env, "CODEX_HOME="+home)
	} else {
		env = append(env, "CLAUDE_CONFIG_DIR="+home, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1", "CLAUDE_CODE_DISABLE_AGENT_VIEW=1")
	}
	return env
}

func primaryComparisonCredentialValid(data []byte, runtime string) bool {
	var credential struct {
		AuthMode string `json:"auth_mode"`
		APIKey   string `json:"OPENAI_API_KEY"`
		Tokens   struct {
			AccessToken string `json:"access_token"`
		} `json:"tokens"`
		ClaudeOAuth struct {
			AccessToken string `json:"accessToken"`
		} `json:"claudeAiOauth"`
	}
	if json.Unmarshal(data, &credential) != nil || credential.APIKey != "" {
		return false
	}
	if runtime == "codex" {
		return credential.AuthMode == "chatgpt" && credential.Tokens.AccessToken != ""
	}
	return runtime == "claude" && credential.ClaudeOAuth.AccessToken != ""
}

func runProviderPrimaryComparison(cmd *cobra.Command, profileName string, profile, signer config.ProviderProfileConfig, timeout time.Duration, codeModeHostSHA256, experimentID, changeEvidence string) error {
	id, transport, err := validatePrimaryComparisonProfile(profile)
	if err != nil {
		return err
	}
	// The broker and verifier use Linux paths. In particular, a Windows CLI
	// exposed through WSL interop must not inherit an uncontrolled Windows home.
	if runtime.GOOS != "linux" {
		return errors.New("primary workspace comparison requires native Linux execution")
	}
	binaryFile, err := os.Open(profile.Command)
	if err != nil {
		return errors.New("primary runtime is unavailable")
	}
	var magic [4]byte
	n, readErr := binaryFile.Read(magic[:])
	closeErr := binaryFile.Close()
	if readErr != nil || closeErr != nil || n != 4 || string(magic[:]) != "\x7fELF" {
		return errors.New("primary comparison requires a pinned native Linux executable, not a wrapper or Windows interop command")
	}
	ctx := providerCommandContext(cmd)
	versionCtx, versionCancel := context.WithTimeout(ctx, 5*time.Second)
	version, versionErr := primaryPinnedRuntimeVersion(versionCtx, profile)
	versionCancel()
	digest, hashErr := hashProviderSessionExecutable(profile.Command)
	if versionErr != nil || hashErr != nil || !versionMatches(version, profile.RuntimeVersion) || digest != profile.RuntimeSHA256 {
		return errors.New("primary runtime version or executable pin mismatch")
	}
	if id.Runtime() == "codex" {
		if _, err := primaryCodexCompanionDigest(profile.Command, codeModeHostSHA256); err != nil {
			return err
		}
	} else if codeModeHostSHA256 != "" {
		return errors.New("code-mode companion pin is only valid for Codex")
	}
	sign, err := providerProfilePinnedSigner(signer)
	if err != nil {
		return err
	}
	if _, err := preflightProviderReceiptSignerMetadataFor(ctx, sign, signer.Provider == "xai"); err != nil {
		return err
	}
	admission := ratelimit.DefaultAdmissionController()
	if admission.CapacityStatus().Scope != provider.CapacityControlScopeLocalShared {
		return errors.New("primary comparison requires shared local capacity admission")
	}
	started := time.Now().UTC()
	policy := primaryWorkspacePolicySHA(transport, codeModeHostSHA256)
	if _, err := providerqualification.StorePrimaryComparisonDiagnostics("", transport, id.Hash(), policy, digest, started, started, "before_dispatch", providerqualification.PrimaryComparisonDiagnostic{}); err != nil {
		return err
	}
	workspace, err := prepareProviderComparisonWorkspace(ctx, nil, true)
	if err != nil {
		return err
	}
	defer func() {
		if providerGrokLineageWorkspaceRemoved(workspace) {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = cleanupProviderGrokLineageWorkspace(cleanupCtx, workspace)
	}()
	if err = copyPrimaryCredential(profile, workspace.RuntimeHome); err != nil {
		return err
	}
	revision, err := providerGrokQualificationGit(ctx, workspace.Worktree, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	auditPath := filepath.Join(workspace.Root, providerGrokWorkspaceAuditFile)
	guard, err := createProviderGrokWorkspaceAudit(auditPath, workspace.Worktree)
	if err != nil {
		return err
	}
	defer guard.Close()
	broker, err := providerWorkspaceBrokerDescriptorWithAudit(ctx, workspace.Worktree, auditPath)
	if err != nil {
		return err
	}
	nonce, err := providerDoctorNonce()
	if err != nil {
		return err
	}
	prompt := providerWorkspaceQualificationPrompt(nonce)
	args, err := primaryWorkspaceArguments(workspace.RuntimeHome, id.Model(), id.Runtime(), prompt, nonce, broker)
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ledger, closeLedger, err := openProviderNativeLedger()
	if err != nil {
		return err
	}
	defer closeLedger()
	if err := claimPrimaryComparisonExperiment(ledger, experimentID, id.Hash(), changeEvidence); err != nil {
		return err
	}
	if err := reserveProviderExperiment(experimentID, id.Hash(), changeEvidence); err != nil {
		return err
	}
	decision, err := acquireProviderGrokQualificationTurn(runCtx, admission, id)
	if err != nil {
		return err
	}
	var observation primaryComparisonObservation
	outcome, runErr := (providerqualification.LocalRunner{}).Run(runCtx, providerqualification.Invocation{Binary: profile.Command, Args: args, Dir: workspace.Worktree, Env: primaryComparisonEnvironment(workspace.RuntimeHome, id.Runtime()), OutputLimit: 8 << 20})
	scanner := bufio.NewScanner(bytes.NewReader(outcome.Stdout))
	scanner.Buffer(make([]byte, 4096), 2<<20)
	for scanner.Scan() {
		observation.observe(scanner.Bytes(), id.Runtime(), nonce)
	}
	observation.Malformed = observation.Malformed || scanner.Err() != nil || outcome.OutputTruncated
	if scanner.Err() != nil || outcome.OutputTruncated {
		observation.FailureCategory = "output_incomplete"
	}
	observation.ExitOK = runErr == nil && outcome.ExitCode == 0
	observation.observeWarnings(outcome.Stderr)
	// Raw streams remain memory-only and are never embedded in diagnostic or
	// signed evidence. Reuse the common continuously observed process runner.
	for i := range outcome.Stdout {
		outcome.Stdout[i] = 0
	}
	for i := range outcome.Stderr {
		outcome.Stderr[i] = 0
	}
	outcome.Stdout = nil
	outcome.Stderr = nil
	capacity := admission.ReleaseObserved(id, decision)
	completed := time.Now().UTC()
	diagnostic := providerqualification.PrimaryComparisonDiagnostic{Completed: observation.Completed, NonceVerified: observation.NonceVerified, ModelMatched: observation.ServedModel != "" && observation.ServedModel == id.Model(), ModelConflict: observation.ModelConflict, Malformed: observation.Malformed, UnexpectedTool: observation.UnexpectedTool, EventCount: observation.EventCount, ExitOK: observation.ExitOK}
	diagnostic.FailureCategory = observation.FailureCategory
	diagnostic.TerminalCategory = observation.TerminalCategory
	diagnostic.CodeModeUnavailable, diagnostic.MetadataFallback = observation.CodeModeUnavailable, observation.MetadataFallback
	diagnostic.MCPStarted, diagnostic.MCPCompleted, diagnostic.MCPFailed = observation.MCPStarted, observation.MCPCompleted, observation.MCPFailed
	if observation.ServedModel != "" {
		diagnostic.ModelSHA256 = sha256StringCLI(observation.ServedModel)
	}
	if _, err = providerqualification.StorePrimaryComparisonDiagnostics("", transport, id.Hash(), policy, digest, started, completed, "before_cleanup", diagnostic); err != nil {
		return err
	}
	audit, auditErr := readProviderGrokWorkspaceAudit(guard, auditPath, workspace.Worktree, revision)
	assertions := evaluateProviderGrokWorkspaceAudit(audit, workspace.Worktree, revision, started, completed)
	content, contentErr := os.ReadFile(filepath.Join(workspace.Worktree, providerGrokWorkspaceTarget))
	edit := contentErr == nil && bytes.Equal(content, providerGrokWorkspaceAfter)
	if _, err = providerqualification.StoreWorkspaceDiagnostics("", transport, id.Hash(), policy, digest, started, completed, providerWorkspaceDiagnostic(audit, auditErr, assertions, edit)); err != nil {
		return err
	}
	receipt := providerqualification.Receipt{Mode: providerqualification.ModeLive, Provider: id.Provider(), Transport: transport, IdentitySHA256: id.Hash(), PolicySHA256: policy, RuntimeVersion: version, RuntimeSHA256: digest, StartedAt: started, CompletedAt: completed, DisposableRepoHash: sha256StringCLI(filepath.Clean(workspace.Worktree)), Checks: grokQualificationChecksForProducer("primary-comparison")}
	for i := range receipt.Checks {
		receipt.Checks[i].Detail = "untested: not exercised by this workspace comparison"
	}
	evidence := digestSafeJSON(observation)
	// The shared gate proves the served model, as it does for Grok. Account
	// authority remains separately profile-attested; no runtime stream upgrades it.
	setGrokQualificationCheck(&receipt, providerqualification.CheckIdentity, observation.exactModelVerified(id.Model()), "live", evidence, "exact served model, terminal acknowledgement and successful stream; account binding remains profile-attested")
	setGrokQualificationCheck(&receipt, providerqualification.CheckWorkspaceEdit, auditErr == nil && assertions.EditObserved && assertions.ReadObserved && edit, "local_authoritative", assertions.EvidenceSHA256, "common broker edit audit and independent readback")
	setGrokQualificationCheck(&receipt, providerqualification.CheckTestCommand, auditErr == nil && assertions.TestObserved && edit, "local_authoritative", assertions.EvidenceSHA256, "common isolated go-test/go-vet verifier")
	boundary := outcome.ProcessStarted && !observation.UnexpectedTool && !observation.Malformed && (id.Runtime() == "claude" || codeModeHostSHA256 != "")
	setGrokQualificationCheck(&receipt, providerqualification.CheckSecretDenied, boundary && auditErr == nil && assertions.SecretDenied, "local_authoritative", assertions.EvidenceSHA256, "common protected-path broker rejection with built-in tools disabled")
	setGrokQualificationCheck(&receipt, providerqualification.CheckPushDenied, boundary, "local_authoritative", broker.BindingSHA256(), "managed CLI disables built-in tools and exposes only the three bounded broker tools")
	if !boundary {
		for _, name := range []string{providerqualification.CheckSecretDenied, providerqualification.CheckPushDenied} {
			setGrokQualificationCheck(&receipt, name, false, "local_authoritative", evidence, "unsupported: complete runtime tool boundary is not verified")
		}
	}
	setGrokQualificationCheck(&receipt, providerqualification.CheckProcessCleanup, false, "local_observed_process_tree", digestSafeJSON(outcome), "untested: disposable workspace cleanup has not completed")
	if err = receipt.Finalize(); err != nil {
		return err
	}
	if _, err = providerqualification.StoreDiagnostics("", receipt); err != nil {
		return err
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	cleanupErr := cleanupProviderGrokLineageWorkspace(cleanupCtx, workspace)
	cleanupCancel()
	cleaned := cleanupErr == nil && providerGrokLineageWorkspaceRemoved(workspace)
	setGrokQualificationCheck(&receipt, providerqualification.CheckProcessCleanup, outcome.ProcessStarted && outcome.ResidualCheckPerformed && outcome.ProcessTreeTerminated && len(outcome.ResidualProcessIDs) == 0 && cleaned, "local_observed_process_tree", digestSafeJSON(outcome), "continuously observed local process tree and owned disposable workspace cleanup")
	receipt.CompletedAt = time.Now().UTC()
	if err = receipt.Finalize(); err != nil {
		return err
	}
	if _, err = providerqualification.StoreDiagnostics("", receipt); err != nil {
		return err
	}
	if err = signProviderQualificationReceiptWith(ctx, &receipt, sign); err != nil {
		return err
	}
	path, err := providerqualification.Store("", receipt)
	if err != nil {
		return err
	}
	if err = encodeIndentedJSON(cmd.OutOrStdout(), map[string]any{"profile": profileName, "provider": id.Provider(), "runtime": id.Runtime(), "account_sha256": sha256StringCLI(id.AccountAlias()), "account_identity_evidence": provider.IdentityEvidenceProfileAttested, "billing_class": id.BillingClass(), "requested_model": id.Model(), "receipt_path": path, "receipt": receipt, "runtime_observation": observation, "local_capacity_observation": capacity}); err != nil {
		return err
	}
	return &providerQualificationExitError{}
}

// Hash before invoking even --version: readiness must not execute a replacement
// binary merely to discover that it no longer matches its profile pin.
func primaryPinnedRuntimeVersion(ctx context.Context, profile config.ProviderProfileConfig) (string, error) {
	digest, err := hashProviderSessionExecutable(profile.Command)
	if err != nil || digest != profile.RuntimeSHA256 {
		return "", errors.New("primary executable pin mismatch")
	}
	version, err := providerRuntimeVersion(ctx, profile.Command)
	if err != nil || !versionMatches(version, profile.RuntimeVersion) {
		return "", errors.New("primary runtime version mismatch")
	}
	return version, nil
}

func claimPrimaryComparisonExperiment(ledger providerNativeOperationLedger, experimentID, identity, evidence string) error {
	if ledger == nil || !validProviderNativeOperationID(experimentID) || !validProviderNativeDigest(identity) || !validProviderNativeDigest(evidence) {
		return errors.New("comparison experiment binding is incomplete")
	}
	_, won, err := ledger.ClaimSendOperation(&state.SendOperation{OperationID: experimentID, SessionName: "provider:comparison-experiment", BindingHash: sha256StringCLI(identity + "\x00" + evidence), PayloadSHA256: evidence, CreatedAt: time.Now().UTC()})
	if err != nil {
		return err
	}
	if !won {
		return errors.New("comparison experiment already attempted; a new attempt requires a relevant change or new diagnostic evidence and a distinct experiment ID")
	}
	return nil
}

func primaryCodexComparisonSettings(model, command string, args []string) map[string]any {
	// Codex's Auto MCP policy requests approval when safety annotations are
	// absent. Explicit approval applies only to this controller-bound broker's
	// three exposed tools; their file and execution boundaries remain in NTM.
	return map[string]any{
		"model": model, "model_provider": "openai", "approval_policy": "never",
		"sandbox_mode": "read-only", "check_for_update_on_startup": false,
		"web_search": "disabled",
		"history":    map[string]any{"persistence": "none"},
		"features":   map[string]any{"shell_tool": false, "multi_agent": false, "apps": false, "plugins": false, "view_image": false, "image_generation": false, "request_permissions_tool": false},
		"mcp_servers": map[string]any{grok.WorkspaceBrokerMCPName: map[string]any{
			"command": command, "args": append([]string(nil), args...), "required": true,
			"default_tools_approval_mode": "approve",
			"enabled_tools":               []string{"read_file", "write_file", "verify_worktree"},
		}},
	}
}

func primaryWorkspacePolicySHA(transport, companion string) string {
	if transport == "openai_codex_comparison" {
		return sha256StringCLI(primaryComparisonPolicy + "\x00" + transport + "\x00codex-controlled-tools-v1\x00" + companion)
	}
	return sha256StringCLI(primaryComparisonPolicy + "\x00" + transport)
}

// Pinned Codex b194851: core/tools/spec_plan.rs registers apply_patch from
// model metadata regardless of the shell flag. A static catalog takes precedence
// over remote tool metadata; it is a local restriction, never served-model proof.
// ServerModel from the terminal event remains mandatory for qualification.
func writePrimaryCodexToolCatalog(home, model string) (string, error) {
	entry := map[string]any{"slug": model, "display_name": model, "description": nil, "supported_reasoning_levels": []any{}, "shell_type": "disabled", "visibility": "none", "supported_in_api": false, "priority": 99, "support_verbosity": false, "default_verbosity": nil, "apply_patch_tool_type": nil, "truncation_policy": map[string]any{"mode": "bytes", "limit": 10000}, "experimental_supported_tools": []string{}, "include_apps_usage_instructions": false, "include_skills_usage_instructions": false, "include_plugin_usage_instructions": false, "tool_mode": "code_mode", "multi_agent_version": "disabled"}
	entry["base_instructions"] = "Complete the user's isolated coding assignment using the available controlled workspace tools. Respect tool denials. Verify changes through verify_worktree before reporting completion. Report failure honestly when a required step cannot be completed."
	data, err := json.Marshal(map[string]any{"models": []any{entry}})
	if err != nil {
		return "", err
	}
	path := filepath.Join(home, "controlled-tool-catalog.json")
	return path, os.WriteFile(path, data, 0600)
}
