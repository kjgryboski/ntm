package zai

// Verification for the non-secret CAAM-owned Codex profile. It deliberately
// returns only hashes; configuration contents and broker metadata stay local.

import (
	"context"
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

	"github.com/BurntSushi/toml"
)

const (
	// CodexManifestVersion is CAAM's current descriptor/metadata contract.
	// NTM must not accept the earlier v1 descriptor: it did not bind the
	// trusted credential-bridge path.
	CodexManifestVersion                 = "caam.zai-codex.v2"
	CodexObservePermissionProfile        = "zai_observe"
	CodexWorkspaceWritePermissionProfile = "zai_workspace_write"
	codexPermissionGlobScanMaxDepth      = 8
)

type CodexManifestExpectation struct {
	RuntimeHome                   string
	Account                       string
	Endpoint                      string
	Model                         string
	BrokerCredentialID            string
	Binary                        string
	BinarySHA256                  string
	BrokerCommand                 string
	BrokerCommandSHA256           string
	CredentialBridgeCommand       string
	CredentialBridgeCommandSHA256 string
	Version                       string
	ConfigSHA256                  string
}

type CodexManifestAttestation struct {
	ConfigSHA256           string `json:"config_sha256"`
	BinarySHA256           string `json:"binary_sha256"`
	AuthHelperSHA256       string `json:"auth_helper_sha256"`
	CredentialBridgeSHA256 string `json:"credential_bridge_sha256"`
	RuntimeVersion         string `json:"runtime_version"`
}

type codexModels struct {
	Models []codexModelCatalogEntry `json:"models"`
}

// codexModelCatalogEntry mirrors the bounded Codex 0.149 model catalog that
// CAAM writes for one selected Z.ai Coding Plan model. Provider identity is
// deliberately not accepted here; it belongs to zai-codex.json.
type codexModelCatalogEntry struct {
	Slug                          string                     `json:"slug"`
	DisplayName                   string                     `json:"display_name"`
	Description                   string                     `json:"description"`
	DefaultReasoningLevel         string                     `json:"default_reasoning_level"`
	SupportedReasoningLevels      []codexReasoningLevel      `json:"supported_reasoning_levels"`
	ShellType                     string                     `json:"shell_type"`
	Visibility                    string                     `json:"visibility"`
	SupportedInAPI                bool                       `json:"supported_in_api"`
	Priority                      int                        `json:"priority"`
	SupportVerbosity              bool                       `json:"support_verbosity"`
	ApplyPatchToolType            string                     `json:"apply_patch_tool_type"`
	TruncationPolicy              codexModelTruncationPolicy `json:"truncation_policy"`
	ContextWindow                 int                        `json:"context_window"`
	MaxContextWindow              int                        `json:"max_context_window"`
	EffectiveContextWindowPercent int                        `json:"effective_context_window_percent"`
	SupportsReasoningSummaries    bool                       `json:"supports_reasoning_summaries"`
	DefaultReasoningSummary       string                     `json:"default_reasoning_summary"`
	SupportsParallelToolCalls     bool                       `json:"supports_parallel_tool_calls"`
	ExperimentalSupportedTools    []string                   `json:"experimental_supported_tools"`
	InputModalities               []string                   `json:"input_modalities"`
	BaseInstructions              string                     `json:"base_instructions"`
}

type codexReasoningLevel struct {
	Effort      string `json:"effort"`
	Description string `json:"description"`
}

type codexModelTruncationPolicy struct {
	Mode  string `json:"mode"`
	Limit int    `json:"limit"`
}

type codexDescriptor struct {
	ManifestVersion string `json:"manifest_version"`
	Provider        string `json:"provider"`
	AccountAlias    string `json:"account_alias"`
	CredentialClass string `json:"credential_class"`
	BillingClass    string `json:"billing_class"`
	Entitlement     string `json:"entitlement"`
	Runtime         string `json:"runtime"`
	Model           string `json:"model"`
	Endpoint        string `json:"endpoint"`
	CredentialID    string `json:"credential_id"`
	BrokerProtocol  string `json:"broker_protocol"`
	BridgePath      string `json:"bridge_path"`
	BridgeSHA256    string `json:"bridge_sha256"`
	SyncPolicy      string `json:"sync_policy"`
}

type codexConfig struct {
	CLIAuthCredentialsStore string                         `toml:"cli_auth_credentials_store"`
	ModelProvider           string                         `toml:"model_provider"`
	Model                   string                         `toml:"model"`
	ModelCatalogJSON        string                         `toml:"model_catalog_json"`
	ModelReasoningEffort    string                         `toml:"model_reasoning_effort"`
	ApprovalPolicy          string                         `toml:"approval_policy"`
	AllowLoginShell         *bool                          `toml:"allow_login_shell"`
	CheckForUpdateOnStartup *bool                          `toml:"check_for_update_on_startup"`
	DefaultPermissions      string                         `toml:"default_permissions"`
	History                 codexHistoryConfig             `toml:"history"`
	ShellEnvironmentPolicy  codexShellEnvironmentPolicy    `toml:"shell_environment_policy"`
	Permissions             codexPermissions               `toml:"permissions"`
	Providers               map[string]codexProviderConfig `toml:"model_providers"`
}

type codexHistoryConfig struct {
	Persistence string `toml:"persistence"`
}

type codexShellEnvironmentPolicy struct {
	Inherit               string   `toml:"inherit"`
	IgnoreDefaultExcludes *bool    `toml:"ignore_default_excludes"`
	Exclude               []string `toml:"exclude"`
}

type codexPermissions struct {
	Observe        codexPermissionProfile `toml:"zai_observe"`
	WorkspaceWrite codexPermissionProfile `toml:"zai_workspace_write"`
}

type codexPermissionProfile struct {
	Filesystem codexFilesystemPermissions `toml:"filesystem"`
	Network    codexNetworkPermission     `toml:"network"`
}

type codexFilesystemPermissions struct {
	Minimal          string            `toml:":minimal"`
	WorkspaceRoots   map[string]string `toml:":workspace_roots"`
	GlobScanMaxDepth int               `toml:"glob_scan_max_depth"`
}

type codexNetworkPermission struct {
	Enabled *bool `toml:"enabled"`
}

type codexProviderConfig struct {
	Name    string `toml:"name"`
	BaseURL string `toml:"base_url"`
	EnvKey  string `toml:"env_key"`
	WireAPI string `toml:"wire_api"`
}

func AttestCodexManifest(ctx context.Context, e CodexManifestExpectation) (CodexManifestAttestation, error) {
	var out CodexManifestAttestation
	if ctx == nil || !filepath.IsAbs(e.RuntimeHome) || !filepath.IsAbs(e.Binary) || !filepath.IsAbs(e.BrokerCommand) || !filepath.IsAbs(e.CredentialBridgeCommand) || !validManifestDigest(e.ConfigSHA256) || !validManifestDigest(e.BinarySHA256) || !validManifestDigest(e.BrokerCommandSHA256) || !validManifestDigest(e.CredentialBridgeCommandSHA256) || !canonicalCodexAccount(e.Account) || strings.TrimSpace(e.Endpoint) != OfficialCodexEndpoint || strings.TrimSpace(e.Model) == "" || strings.TrimSpace(e.BrokerCredentialID) == "" || strings.TrimSpace(e.Version) == "" {
		return out, errors.New("invalid Codex manifest expectation")
	}
	if err := validateIsolatedCodexHome(e.RuntimeHome); err != nil {
		return out, err
	}
	if err := validateCodexAuthBoundary(e.RuntimeHome); err != nil {
		return out, err
	}
	files, configSHA256, err := caamCodexManifestFilesAndSHA256(e)
	if err != nil {
		return out, err
	}
	if err := validateCAAMCodexManifestFiles(files, e); err != nil {
		return out, err
	}
	out.ConfigSHA256 = configSHA256
	if out.ConfigSHA256 != e.ConfigSHA256 {
		return out, errors.New("Codex manifest digest mismatch")
	}
	helper, err := regularExecutable(e.BrokerCommand)
	if err != nil {
		return out, errors.New("invalid Codex auth helper")
	}
	helperDigest := sha256.Sum256(helper)
	out.AuthHelperSHA256 = hex.EncodeToString(helperDigest[:])
	if out.AuthHelperSHA256 != e.BrokerCommandSHA256 {
		return out, errors.New("Codex broker executable digest mismatch")
	}
	bridge, err := regularExecutable(e.CredentialBridgeCommand)
	if err != nil {
		return out, errors.New("invalid Codex credential bridge executable")
	}
	bridgeDigest := sha256.Sum256(bridge)
	out.CredentialBridgeSHA256 = hex.EncodeToString(bridgeDigest[:])
	if out.CredentialBridgeSHA256 != e.CredentialBridgeCommandSHA256 {
		return out, errors.New("Codex credential bridge executable digest mismatch")
	}
	binary, err := regularExecutable(e.Binary)
	if err != nil {
		return out, err
	}
	s := sha256.Sum256(binary)
	out.BinarySHA256 = hex.EncodeToString(s[:])
	if out.BinarySHA256 != e.BinarySHA256 {
		return out, errors.New("Codex runtime executable digest mismatch")
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(cctx, e.Binary, "--version")
	command.Env = minimalStructuredCodexEnvironment(nil, e.RuntimeHome)
	versionOutput, err := command.Output()
	if err != nil || len(versionOutput) > 4096 {
		return out, errors.New("Codex binary version mismatch")
	}
	versionLine := strings.TrimSpace(strings.SplitN(string(versionOutput), "\n", 2)[0])
	if versionLine != "codex-cli "+e.Version {
		return out, errors.New("Codex binary version mismatch")
	}
	out.RuntimeVersion = e.Version
	return out, nil
}

func validateCAAMCodexManifestFiles(files map[string][]byte, e CodexManifestExpectation) error {
	var models codexModels
	if err := decodeStrictJSON(files["models.json"], &models); err != nil || !validCodexModelCatalog(models, e.Model) {
		return errors.New("invalid Codex models manifest")
	}
	var descriptor codexDescriptor
	if err := decodeStrictJSON(files["zai-codex.json"], &descriptor); err != nil || descriptor.ManifestVersion != CodexManifestVersion || descriptor.Provider != "zai" || descriptor.AccountAlias != e.Account || descriptor.CredentialClass != "coding_plan" || descriptor.BillingClass != "coding_plan" || descriptor.Entitlement != "codex_responses" || descriptor.Runtime != "codex" || descriptor.Model != e.Model || descriptor.Endpoint != e.Endpoint || descriptor.CredentialID != e.BrokerCredentialID || descriptor.BrokerProtocol != "ntm-provider-bridge-v1" || descriptor.BridgePath != e.CredentialBridgeCommand || descriptor.BridgeSHA256 != e.CredentialBridgeCommandSHA256 || descriptor.SyncPolicy != "host-local-metadata-only" {
		return errors.New("invalid Codex broker descriptor")
	}
	var cfg codexConfig
	metadata, err := toml.Decode(string(files["config.toml"]), &cfg)
	if err != nil || len(metadata.Undecoded()) != 0 {
		return errors.New("invalid Codex config")
	}
	p, ok := cfg.Providers["zai"]
	wantExclude := []string{"ZAI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_*", "XAI_*", "*TOKEN*", "*SECRET*", "*PASSWORD*", "*KEY*", "CODEX_HOME"}
	if !ok || len(cfg.Providers) != 1 || cfg.CLIAuthCredentialsStore != "ephemeral" || cfg.ModelProvider != "zai" || cfg.Model != e.Model || cfg.ModelCatalogJSON != "~/.codex/models.json" || cfg.ModelReasoningEffort != "max" || cfg.ApprovalPolicy != "never" || cfg.AllowLoginShell == nil || *cfg.AllowLoginShell || cfg.CheckForUpdateOnStartup == nil || *cfg.CheckForUpdateOnStartup || cfg.DefaultPermissions != CodexObservePermissionProfile || cfg.History.Persistence != "none" || cfg.ShellEnvironmentPolicy.Inherit != "core" || cfg.ShellEnvironmentPolicy.IgnoreDefaultExcludes == nil || *cfg.ShellEnvironmentPolicy.IgnoreDefaultExcludes || !equalCodexStrings(cfg.ShellEnvironmentPolicy.Exclude, wantExclude) || !validCodexPermissionProfiles(cfg.Permissions) || p.Name != "Z.ai Coding Plan" || p.BaseURL != e.Endpoint || p.EnvKey != "ZAI_API_KEY" || p.WireAPI != "responses" {
		return errors.New("invalid Codex provider config")
	}
	return nil
}

func validCodexModelCatalog(catalog codexModels, model string) bool {
	if len(catalog.Models) != 1 {
		return false
	}
	entry := catalog.Models[0]
	displayName, description := "glm-5.3", "Z.ai's latest flagship model"
	if model == "glm-5.3-flash" {
		displayName = "GLM-5.3-Flash"
		description = "CAAM compatibility profile for Z.ai GLM-5.3-Flash Coding Plan model."
	} else if model != "glm-5.3" {
		return false
	}
	wantReasoning := []codexReasoningLevel{
		{Effort: "low", Description: "Light reasoning"},
		{Effort: "high", Description: "Enhanced reasoning"},
		{Effort: "max", Description: "Deep reasoning"},
	}
	if entry.Slug != model || entry.DisplayName != displayName || entry.Description != description || entry.DefaultReasoningLevel != "max" ||
		entry.ShellType != "shell_command" || entry.Visibility != "list" || !entry.SupportedInAPI || entry.Priority != 0 ||
		entry.SupportVerbosity ||
		entry.ApplyPatchToolType != "freeform" || entry.TruncationPolicy.Mode != "bytes" || entry.TruncationPolicy.Limit != 10000 ||
		entry.ContextWindow != 1048576 || entry.MaxContextWindow != 1048576 || entry.EffectiveContextWindowPercent != 95 ||
		!entry.SupportsReasoningSummaries || entry.DefaultReasoningSummary != "none" || !entry.SupportsParallelToolCalls ||
		len(entry.ExperimentalSupportedTools) != 0 || len(entry.InputModalities) != 1 || entry.InputModalities[0] != "text" || entry.BaseInstructions != "" ||
		len(entry.SupportedReasoningLevels) != len(wantReasoning) {
		return false
	}
	for index := range wantReasoning {
		if entry.SupportedReasoningLevels[index] != wantReasoning[index] {
			return false
		}
	}
	return true
}

func validCodexPermissionProfiles(permissions codexPermissions) bool {
	if !validCodexNetworkDeny(permissions.Observe.Network) || !validCodexNetworkDeny(permissions.WorkspaceWrite.Network) {
		return false
	}
	observe := permissions.Observe.Filesystem
	workspace := permissions.WorkspaceWrite.Filesystem
	if observe.Minimal != "read" || workspace.Minimal != "read" || observe.GlobScanMaxDepth != codexPermissionGlobScanMaxDepth || workspace.GlobScanMaxDepth != codexPermissionGlobScanMaxDepth {
		return false
	}
	wantObserve := codexScopedWorkspacePermissions("read", false)
	wantWorkspace := codexScopedWorkspacePermissions("write", true)
	return equalCodexStringMap(observe.WorkspaceRoots, wantObserve) && equalCodexStringMap(workspace.WorkspaceRoots, wantWorkspace)
}

func validCodexNetworkDeny(network codexNetworkPermission) bool {
	return network.Enabled != nil && !*network.Enabled
}

func codexScopedWorkspacePermissions(rootAccess string, gitReadOnly bool) map[string]string {
	permissions := map[string]string{
		".":                        rootAccess,
		".qualification-secret":    "deny",
		"**/.qualification-secret": "deny",
		".env*":                    "deny",
		"**/.env*":                 "deny",
		".ssh":                     "deny",
		"**/.ssh/**":               "deny",
		".aws":                     "deny",
		"**/.aws/**":               "deny",
		".config":                  "deny",
		"**/.config/**":            "deny",
	}
	if gitReadOnly {
		permissions[".git"] = "read"
	}
	return permissions
}

func equalCodexStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range right {
		if left[key] != value {
			return false
		}
	}
	return true
}

func equalCodexStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

// CAAMCodexManifestSHA256 computes CAAM's v2 Z.ai Codex manifest over the
// exact profile metadata and the three private runtime files. It is the one
// digest contract used by both configuration admission and live attestation.
// It also validates every structured managed file against the expectation so
// callers cannot bless a self-consistent digest for conflicting identity data.
func CAAMCodexManifestSHA256(e CodexManifestExpectation) (string, error) {
	files, digest, err := caamCodexManifestFilesAndSHA256(e)
	if err != nil {
		return "", err
	}
	if err := validateCAAMCodexManifestFiles(files, e); err != nil {
		return "", err
	}
	return digest, nil
}

func caamCodexManifestFilesAndSHA256(e CodexManifestExpectation) (map[string][]byte, string, error) {
	if !filepath.IsAbs(e.RuntimeHome) || filepath.Base(filepath.Clean(e.RuntimeHome)) != ".codex" || !canonicalCodexAccount(e.Account) || strings.TrimSpace(e.Endpoint) != OfficialCodexEndpoint || strings.TrimSpace(e.Model) == "" || strings.TrimSpace(e.BrokerCredentialID) == "" || !filepath.IsAbs(e.CredentialBridgeCommand) || !validManifestDigest(e.CredentialBridgeCommandSHA256) {
		return nil, "", errors.New("invalid CAAM v2 Codex manifest binding")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(e.Endpoint), "/")
	capacity := sha256.New()
	for _, field := range []string{"zai", e.Account, endpoint, "coding_plan", "coding_plan", "codex_responses"} {
		_, _ = capacity.Write([]byte(field))
		_, _ = capacity.Write([]byte{0})
	}
	fields := []string{
		"caam.zai-codex.manifest.v2", "zai-codex", CodexManifestVersion, "zai",
		e.Account, "coding_plan", "coding_plan", "codex_responses", "codex", endpoint,
		strings.TrimSpace(e.Model), strings.TrimSpace(e.BrokerCredentialID),
		"subscription:" + hex.EncodeToString(capacity.Sum(nil)), "host-local-metadata-only",
		e.CredentialBridgeCommand, e.CredentialBridgeCommandSHA256,
	}
	hasher := sha256.New()
	for _, field := range fields {
		_, _ = hasher.Write([]byte(field))
		_, _ = hasher.Write([]byte{0})
	}
	files := make(map[string][]byte, 3)
	for _, name := range []string{"config.toml", "models.json", "zai-codex.json"} {
		path := filepath.Join(e.RuntimeHome, name)
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, "", fmt.Errorf("CAAM v2 Codex manifest file %s is not a private regular file", name)
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return nil, "", fmt.Errorf("read CAAM v2 Codex manifest file %s: %w", name, err)
		}
		files[name] = contents
		_, _ = hasher.Write([]byte(name))
		_, _ = hasher.Write([]byte{0})
		_, _ = hasher.Write(contents)
		_, _ = hasher.Write([]byte{0})
	}
	return files, hex.EncodeToString(hasher.Sum(nil)), nil
}

func canonicalCodexAccount(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && strings.ToLower(value) == value
}

func validManifestDigest(value string) bool {
	if len(value) != 64 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func validateIsolatedCodexHome(runtimeHome string) error {
	if filepath.Base(filepath.Clean(runtimeHome)) != ".codex" {
		return errors.New("Codex runtime home must be a dedicated .codex directory")
	}
	profileDir := filepath.Dir(filepath.Clean(runtimeHome))
	baseDir := filepath.Dir(profileDir)
	if profileDir == baseDir || baseDir == filepath.Dir(baseDir) {
		return errors.New("Codex runtime home has no isolated profile boundary")
	}
	for _, path := range []string{baseDir, profileDir, runtimeHome} {
		if err := regularPrivateDir(path); err != nil {
			return err
		}
	}
	return nil
}

func validateCodexAuthBoundary(runtimeHome string) error {
	path := filepath.Join(runtimeHome, "auth.json")
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != 0 {
		return errors.New("Codex auth file must be empty, private, and profile-local")
	}
	return nil
}

func regularPrivateDir(p string) error {
	i, e := os.Lstat(p)
	if e != nil || i.Mode()&os.ModeSymlink != 0 || !i.IsDir() || i.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("unsafe directory %s", p)
	}
	return nil
}
func regularDir(p string) error {
	i, e := os.Lstat(p)
	if e != nil || i.Mode()&os.ModeSymlink != 0 || !i.IsDir() {
		return fmt.Errorf("unsafe directory %s", p)
	}
	return nil
}
func regularFile(p string) ([]byte, error) {
	i, e := os.Lstat(p)
	if e != nil || i.Mode()&os.ModeSymlink != 0 || !i.Mode().IsRegular() {
		return nil, fmt.Errorf("unsafe file %s", p)
	}
	return os.ReadFile(p)
}

func regularExecutable(path string) ([]byte, error) {
	contents, err := regularFile(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("unsafe executable %s", path)
	}
	return contents, nil
}
