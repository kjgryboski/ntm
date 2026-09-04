package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/grok"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/spf13/cobra"
)

const primaryComparisonPolicy = "primary-controlled-workspace-comparison-v1"

// Comparison is evidence production, never an alternative dispatch admission.
// Unavailable account/remote-lifecycle authority remains explicit even if a
// primary runtime is already usable through its ordinary pane workflow.
func newProviderPrimaryComparisonCmd() *cobra.Command {
	var profileName, signerName string
	var live bool
	var timeout time.Duration
	cmd := &cobra.Command{Use: "compare", Short: "Compare a pinned primary runtime using the common workspace scenario", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&profileName, "profile", "", "Exact primary runtime profile")
	cmd.Flags().StringVar(&signerName, "signer-profile", "", "Profile supplying only the pinned local receipt signer")
	cmd.Flags().BoolVar(&live, "live", false, "Authorize one bounded primary provider call")
	cmd.Flags().DurationVar(&timeout, "timeout", 90*time.Second, "Maximum provider run duration (at most five minutes)")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if !live || profileName == "" || signerName == "" || timeout <= 0 || timeout > 5*time.Minute {
			return errors.New("comparison requires --live, exact --profile and --signer-profile, and a timeout between zero and five minutes")
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
		return runProviderPrimaryComparison(cmd, profileName, profile, signer, timeout)
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
	Completed      bool   `json:"completed"`
	NonceVerified  bool   `json:"nonce_verified"`
	ServedModel    string `json:"served_model,omitempty"`
	ModelConflict  bool   `json:"model_conflict"`
	Malformed      bool   `json:"malformed"`
	UnexpectedTool bool   `json:"unexpected_tool"`
	EventCount     int    `json:"event_count"`
	ExitOK         bool   `json:"exit_ok"`
}

// Only terminal assistant output can acknowledge work. Tool content, init
// configuration, and echoed requests cannot prove completion or served model.
func (o *primaryComparisonObservation) observe(line []byte, runtime, nonce string) {
	var e struct {
		Type        string `json:"type"`
		Subtype     string `json:"subtype"`
		IsError     bool   `json:"is_error"`
		Result      string `json:"result"`
		ServerModel string `json:"server_model"`
		Message     struct {
			Model   string `json:"model"`
			Content []struct {
				Type string `json:"type"`
				Name string `json:"name"`
			} `json:"content"`
		} `json:"message"`
		Item struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"item"`
	}
	o.EventCount++
	if json.Unmarshal(line, &e) != nil {
		o.Malformed = true
		return
	}
	model := ""
	if runtime == "claude" {
		if e.Type == "assistant" {
			model = e.Message.Model
			for _, c := range e.Message.Content {
				if c.Type == "tool_use" && !strings.HasPrefix(c.Name, "mcp__ntm-controlled-workspace__") {
					o.UnexpectedTool = true
				}
			}
		}
		if e.Type == "result" {
			if o.Completed {
				o.Malformed = true
			}
			o.Completed = !e.IsError && e.Subtype == "success"
			o.NonceVerified = o.Completed && strings.TrimSpace(e.Result) == nonce
		}
	} else {
		if e.Type == "item.completed" {
			switch e.Item.Type {
			case "agent_message":
				o.NonceVerified = strings.TrimSpace(e.Item.Text) == nonce
			case "command_execution", "file_change", "web_search":
				o.UnexpectedTool = true
			}
		}
		if e.Type == "turn.completed" {
			if o.Completed {
				o.Malformed = true
			}
			o.Completed = true
			model = e.ServerModel
		}
		if e.Type == "turn.failed" || e.Type == "error" {
			o.Malformed = true
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
			return
		}
		if o.ServedModel != "" && o.ServedModel != model {
			o.ModelConflict = true
		}
		o.ServedModel = model
	}
}

func primaryComparisonEnvironment(home, runtime string) []string {
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "LANG=C", "TERM=dumb"}
	if runtime == "codex" {
		env = append(env, "CODEX_HOME="+home)
	} else {
		env = append(env, "CLAUDE_CONFIG_DIR="+home, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1")
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

func runProviderPrimaryComparison(cmd *cobra.Command, profileName string, profile, signer config.ProviderProfileConfig, timeout time.Duration) error {
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
	version, versionErr := providerRuntimeVersion(versionCtx, profile.Command)
	versionCancel()
	digest, hashErr := hashProviderSessionExecutable(profile.Command)
	if versionErr != nil || hashErr != nil || !versionMatches(version, profile.RuntimeVersion) || digest != profile.RuntimeSHA256 {
		return errors.New("primary runtime version or executable pin mismatch")
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
	policy := sha256StringCLI(primaryComparisonPolicy + "\x00" + transport)
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
	// Copy only one bounded cached credential file from the explicitly selected
	// account home. No global configuration, hooks, MCP servers, or API-key env.
	authName := "auth.json"
	if id.Runtime() == "claude" {
		authName = ".credentials.json"
	}
	source := filepath.Join(profile.RuntimeHome, authName)
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 {
		return errors.New("primary comparison requires a bounded regular account credential file")
	}
	auth, err := os.ReadFile(source)
	if err != nil {
		return errors.New("primary credential file could not be read")
	}
	if !primaryComparisonCredentialValid(auth, id.Runtime()) {
		for i := range auth {
			auth[i] = 0
		}
		return errors.New("primary comparison requires subscription OAuth credentials; API-key substitution is prohibited")
	}
	err = os.WriteFile(filepath.Join(workspace.RuntimeHome, authName), auth, 0600)
	for i := range auth {
		auth[i] = 0
	}
	if err != nil {
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
	encoded, err := json.Marshal(broker)
	if err != nil {
		return err
	}
	var descriptor struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	if err = json.Unmarshal(encoded, &descriptor); err != nil {
		return err
	}
	nonce, err := providerDoctorNonce()
	if err != nil {
		return err
	}
	prompt := fmt.Sprintf("Use only ntm-controlled-workspace MCP tools. Perform exactly four calls in order: read_file path %q; write_file path %q expected_sha256 %q content %q; read_file path %q (expect protected synthetic sentinel rejection and continue); verify_worktree {}. Then reply with exactly %s and no other text.", providerGrokWorkspaceTarget, providerGrokWorkspaceTarget, sha256TextCLI(providerGrokWorkspaceBefore), string(providerGrokWorkspaceAfter), providerGrokWorkspaceSecret, nonce)
	var args []string
	if id.Runtime() == "claude" {
		mcp := map[string]any{"mcpServers": map[string]any{grok.WorkspaceBrokerMCPName: map[string]any{"command": descriptor.Command, "args": descriptor.Args, "env": map[string]string{}}}}
		data, _ := json.Marshal(mcp)
		mcpPath := filepath.Join(workspace.RuntimeHome, "mcp.json")
		if err = os.WriteFile(mcpPath, data, 0600); err != nil {
			return err
		}
		args = []string{"--print", "--verbose", "--output-format", "stream-json", "--tools", "", "--permission-mode", "dontAsk", "--setting-sources", "", "--settings", `{"disableAllHooks":true}`, "--strict-mcp-config", "--mcp-config", mcpPath, "--allowedTools", "mcp__ntm-controlled-workspace__read_file,mcp__ntm-controlled-workspace__write_file,mcp__ntm-controlled-workspace__verify_worktree", "--model", id.Model(), prompt}
	} else {
		settings := map[string]any{"model": id.Model(), "model_provider": "openai", "approval_policy": "never", "sandbox_mode": "read-only", "check_for_update_on_startup": false, "history": map[string]any{"persistence": "none"}, "features": map[string]any{"shell_tool": false, "multi_agent": false, "apps": false}, "mcp_servers": map[string]any{grok.WorkspaceBrokerMCPName: map[string]any{"command": descriptor.Command, "args": descriptor.Args, "enabled_tools": []string{"read_file", "write_file", "verify_worktree"}}}}
		var b bytes.Buffer
		if err = toml.NewEncoder(&b).Encode(settings); err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(workspace.RuntimeHome, "config.toml"), b.Bytes(), 0600); err != nil {
			return err
		}
		args = []string{"exec", "--json", "--sandbox", "read-only", "--model", id.Model(), prompt}
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
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
	observation.ExitOK = runErr == nil && outcome.ExitCode == 0
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
	receipt := providerqualification.Receipt{Mode: providerqualification.ModeLive, Provider: id.Provider(), Transport: transport, IdentitySHA256: id.Hash(), PolicySHA256: policy, RuntimeVersion: version, RuntimeSHA256: digest, StartedAt: started, CompletedAt: completed, DisposableRepoHash: sha256StringCLI(filepath.Clean(workspace.Worktree)), Checks: grokQualificationChecksForProducer("primary-comparison")}
	for i := range receipt.Checks {
		receipt.Checks[i].Detail = "untested: not exercised by this workspace comparison"
	}
	evidence := digestSafeJSON(observation)
	// Configured account labels are not provider-authoritative account evidence.
	// Even an exact terminal model must not silently promote that missing gate.
	setGrokQualificationCheck(&receipt, providerqualification.CheckIdentity, false, "live", evidence, "unsupported: primary stream does not authenticate the selected account binding")
	setGrokQualificationCheck(&receipt, providerqualification.CheckWorkspaceEdit, auditErr == nil && assertions.EditObserved && assertions.ReadObserved && edit, "local_authoritative", assertions.EvidenceSHA256, "common broker edit audit and independent readback")
	setGrokQualificationCheck(&receipt, providerqualification.CheckTestCommand, auditErr == nil && assertions.TestObserved && edit, "local_authoritative", assertions.EvidenceSHA256, "common isolated go-test/go-vet verifier")
	boundary := id.Runtime() == "claude" && outcome.ProcessStarted && !observation.UnexpectedTool && !observation.Malformed
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
	if err = encodeIndentedJSON(cmd.OutOrStdout(), map[string]any{"profile": profileName, "provider": id.Provider(), "runtime": id.Runtime(), "account_sha256": sha256StringCLI(id.AccountAlias()), "billing_class": id.BillingClass(), "requested_model": id.Model(), "receipt_path": path, "receipt": receipt, "runtime_observation": observation, "local_capacity_observation": capacity}); err != nil {
		return err
	}
	return &providerQualificationExitError{}
}
