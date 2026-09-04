package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// DefaultGrokAutomationPolicyName is the named least-privilege policy used by
// unattended Grok Build panes. Keeping the name stable lets robot capability
// output and execution receipts identify the policy without copying rules.
const DefaultGrokAutomationPolicyName = "grok-readonly-ci"

// GrokWorkspaceWritePolicyName is the narrowly scoped policy for an
// explicitly disposable worktree. It is not a general-purpose approval mode.
// The provider may edit, but executable verification stays controller-owned:
// source code which the model can edit is not safe to execute in a process
// that can also reach provider credentials.
const GrokWorkspaceWritePolicyName = "grok-workspace-write-ci"

// DefaultGrokAutomationCommand is the fully rendered compatibility launch
// when no model or reasoning override is requested. Restart/restore paths use
// this value directly and must never receive Go template syntax.
//
// Rules intentionally allow only provider-native read/search operations.
// Bash is denied entirely: an allowlist of test commands cannot honestly
// guarantee a credential-isolated process. NTM itself performs test/verification
// outside the provider process until a non-exportable credential broker and
// kernel-enforced sandbox are available. Writes, pushes, destructive commands,
// package installation, privilege escalation, and common credential paths
// remain denied. --no-auto-update is mandatory for every NTM-managed automated
// launch.
const DefaultGrokAutomationCommand = `grok --no-auto-update --sandbox strict --permission-mode dontAsk` +
	` --allow 'Read' --allow 'Grep' --allow 'WebFetch' --allow 'WebSearch'` +
	` --deny 'Edit' --deny 'Bash(*)'` +
	` --deny 'Read(**/.env*)' --deny 'Read(**/.ssh/**)' --deny 'Read(**/.aws/**)'` +
	` --deny 'Read(**/.config/gcloud/**)' --deny 'Read(**/.config/gh/**)' --deny 'Read(**/.grok/**)'` +
	` --deny 'Read(**/.azure/**)' --deny 'Read(**/.kube/**)' --deny 'Read(**/.docker/**)'` +
	` --deny 'Read(**/.netrc)' --deny 'Read(**/.npmrc)' --deny 'Read(**/.pypirc)' --deny 'Read(**/*.pem)' --deny 'Read(**/*.key)'` +
	` --deny 'Read(**/*credential*)' --deny 'Read(**/*secret*)'` +
	` --deny 'Grep(**/.env*)' --deny 'Grep(**/.ssh/**)' --deny 'Grep(**/.aws/**)'` +
	` --deny 'Grep(**/.config/gcloud/**)' --deny 'Grep(**/.config/gh/**)' --deny 'Grep(**/.grok/**)'` +
	` --deny 'Grep(**/.azure/**)' --deny 'Grep(**/.kube/**)' --deny 'Grep(**/.docker/**)'` +
	` --deny 'Grep(**/.netrc)' --deny 'Grep(**/.npmrc)' --deny 'Grep(**/.pypirc)' --deny 'Grep(**/*.pem)' --deny 'Grep(**/*.key)'` +
	` --deny 'Grep(**/*credential*)' --deny 'Grep(**/*secret*)'`

// DefaultGrokAutomationCommandTemplate is the model-aware interactive
// compatibility launch. Provider-native automation should use ACP; this TUI
// command remains available for humans and older workflows. dontAsk silently
// denies anything not explicitly allowed, while explicit deny rules take
// precedence over allows.
const DefaultGrokAutomationCommandTemplate = DefaultGrokAutomationCommand +
	`{{if .Model}} --model {{shellQuote .Model}}{{end}}` +
	`{{if .ReasoningEffort}} --effort {{shellQuote .ReasoningEffort}}{{end}}`

// GrokAutomationPolicyDescriptor is safe capability metadata. It deliberately
// contains rule names rather than credentials, paths, or provider output.
type GrokAutomationPolicyDescriptor struct {
	Name           string
	Sandbox        string
	PermissionMode string
	AllowRules     []string
	DenyRules      []string
}

// DefaultGrokAutomationPolicy returns a copy of the built-in policy metadata.
func DefaultGrokAutomationPolicy() GrokAutomationPolicyDescriptor {
	return GrokAutomationPolicyDescriptor{
		Name: DefaultGrokAutomationPolicyName,
		// The root-owned requirements file is global, not profile-scoped. Both
		// unattended invocation profiles therefore use its strict sandbox
		// baseline; this observe profile is narrowed by its own no-MCP, no-Edit,
		// no-Bash permission vector.
		Sandbox:        "strict",
		PermissionMode: "dontAsk",
		AllowRules: []string{
			"Read", "Grep", "WebFetch", "WebSearch",
		},
		DenyRules: []string{
			"Edit", "Bash(*)",
			"Read(**/.env*)", "Read(**/.ssh/**)", "Read(**/.aws/**)",
			"Read(**/.config/gcloud/**)", "Read(**/.config/gh/**)", "Read(**/.grok/**)",
			"Read(**/.azure/**)", "Read(**/.kube/**)", "Read(**/.docker/**)",
			"Read(**/.netrc)", "Read(**/.npmrc)", "Read(**/.pypirc)", "Read(**/*.pem)", "Read(**/*.key)",
			"Read(**/*credential*)", "Read(**/*secret*)",
			"Grep(**/.env*)", "Grep(**/.ssh/**)", "Grep(**/.aws/**)",
			"Grep(**/.config/gcloud/**)", "Grep(**/.config/gh/**)", "Grep(**/.grok/**)",
			"Grep(**/.azure/**)", "Grep(**/.kube/**)", "Grep(**/.docker/**)",
			"Grep(**/.netrc)", "Grep(**/.npmrc)", "Grep(**/.pypirc)", "Grep(**/*.pem)", "Grep(**/*.key)",
			"Grep(**/*credential*)", "Grep(**/*secret*)",
		},
	}
}

// GrokSystemRequirements is the deterministic, non-secret system-layer
// requirements document that an owner may install at /etc/grok/requirements.toml.
// Installation is an explicit owner action: creation is non-overwriting, while
// a separately confirmed managed replacement accepts only an existing
// root-owned NTM-marked document and preserves a digest-named backup.
type GrokSystemRequirements struct {
	PolicyName string
	Contents   string
	SHA256     string
}

// GrokSystemRequirementsForPolicy renders the one global, system-authoritative
// baseline accepted for either named built-in invocation policy. /etc/grok/
// requirements.toml cannot be profile-specific, so the returned content and
// digest intentionally remain identical for both selectors. PolicyName records
// the caller's compatible profile for diagnostics only; it does not claim that
// a distinct root-owned document exists for that profile.
func GrokSystemRequirementsForPolicy(name string) (GrokSystemRequirements, bool) {
	if _, ok := GrokAutomationPolicy(name); !ok {
		return GrokSystemRequirements{}, false
	}
	policy := grokSystemRequirementsBaseline()
	var builder strings.Builder
	builder.WriteString("# NTM-managed global Grok baseline. Install as a root-owned system requirement.\n")
	builder.WriteString("# Per-invocation policy arguments may only narrow this baseline.\n")
	builder.WriteString("[sandbox]\nprofile = \"")
	builder.WriteString(policy.Sandbox)
	builder.WriteString("\"\n\n[ui]\npermission_mode = \"")
	builder.WriteString(policy.PermissionMode)
	builder.WriteString("\"\ndisable_bypass_permissions_mode = true\n\n[permission]\nrules = [\n")
	for _, rule := range policy.AllowRules {
		writeGrokRequirementRule(&builder, "allow", rule)
	}
	for _, rule := range policy.DenyRules {
		writeGrokRequirementRule(&builder, "deny", rule)
	}
	builder.WriteString("]\n\n")
	// These extension and built-in tool controls are compliance-critical. The
	// system requirements layer outranks project/user configuration, so a
	// repository cannot reconnect host extensions or re-enable Grok's native
	// writer around the NTM-owned MCP broker.
	// Grok 1.0.13 reports features.tool_search as unknown even though newer
	// documentation lists it. Do not install a silently ignored root setting:
	// the isolated profile and exact MCP descriptor constrain discovery, while
	// built-in writing and LSP remain explicitly disabled here.
	builder.WriteString("[features]\nwrite_file = false\nlsp_tools = false\n\n")
	builder.WriteString("[subagents]\nenabled = false\n\n[memory]\nenabled = false\n\n")
	builder.WriteString("[plugins]\npaths = []\nenabled = []\n\n")
	builder.WriteString("[compat.claude]\nskills = false\nrules = false\nagents = false\nmcps = false\nhooks = false\n\n")
	builder.WriteString("[compat.cursor]\nskills = false\nrules = false\nagents = false\nmcps = false\nhooks = false\n")
	contents := builder.String()
	sum := sha256.Sum256([]byte(contents))
	return GrokSystemRequirements{PolicyName: name, Contents: contents, SHA256: hex.EncodeToString(sum[:])}, true
}

// grokSystemRequirementsBaseline is deliberately the maximum reviewed common
// envelope. It permits only read/search/web and the exact NTM workspace MCP
// names. Observe launches install no MCP server at all; workspace launches
// explicitly deny web and expose only the typed local broker. Built-in Edit
// and Bash, and every credential/config read, grep, or edit path remain a
// root-owned denial for both profiles.
func grokSystemRequirementsBaseline() GrokAutomationPolicyDescriptor {
	observe := DefaultGrokAutomationPolicy()
	denyRules := append([]string(nil), observe.DenyRules...)
	for _, rule := range observe.DenyRules {
		if strings.HasPrefix(rule, "Read(") {
			denyRules = append(denyRules, "Edit("+strings.TrimPrefix(rule, "Read("))
		}
	}
	return GrokAutomationPolicyDescriptor{
		Name:           "grok-system-baseline",
		Sandbox:        "strict",
		PermissionMode: "dontAsk",
		AllowRules: append(append([]string(nil), observe.AllowRules...),
			"MCPTool(ntm-controlled-workspace__list_files)",
			"MCPTool(ntm-controlled-workspace__read_file)",
			"MCPTool(ntm-controlled-workspace__write_file)",
			"MCPTool(ntm-controlled-workspace__verify_worktree)",
		),
		DenyRules: denyRules,
	}
}

// writeGrokRequirementRule converts the CLI's Tool(pattern) notation to the
// documented requirements.toml schema. Keeping this conversion explicit
// prevents a syntactically valid but ignored `rule = ...` field from creating
// a false policy-installation receipt.
func writeGrokRequirementRule(builder *strings.Builder, action, rule string) {
	tool, pattern := rule, ""
	if open := strings.IndexByte(rule, '('); open > 0 && strings.HasSuffix(rule, ")") {
		tool, pattern = rule[:open], rule[open+1:len(rule)-1]
	}
	// CLI selectors use MCPTool(...), while the documented verbose TOML
	// schema names that tool family "mcp". Grok 1.0.13 silently drops the
	// entire permission source when it receives tool = "mcptool", so keep
	// this wire-format mapping explicit and covered by a live parse probe.
	configTool := strings.ToLower(tool)
	if strings.EqualFold(tool, "MCPTool") {
		configTool = "mcp"
	}
	builder.WriteString("  { action = \"")
	builder.WriteString(tomlEscape(action))
	builder.WriteString("\", tool = \"")
	builder.WriteString(tomlEscape(configTool))
	builder.WriteString("\"")
	if pattern != "" {
		builder.WriteString(", pattern = \"")
		builder.WriteString(tomlEscape(pattern))
		builder.WriteString("\"")
	}
	builder.WriteString(" },\n")
}

func tomlEscape(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

// GrokWorkspaceWritePolicy returns the reviewed disposable-worktree policy.
// The strict sandbox blocks child-process network access on Linux and narrows
// filesystem reads to the workspace and system paths. Bash remains entirely
// denied: an exact-looking test command can execute model-edited code, which
// can read a parent process or credential store unless a separate OS-isolated
// verifier owns that execution.
func GrokWorkspaceWritePolicy() GrokAutomationPolicyDescriptor {
	base := DefaultGrokAutomationPolicy()
	denyRules := append([]string{}, base.DenyRules[2:]...)
	// strict intentionally keeps ~/.grok and temp writable for the runtime.
	// Mirror every sensitive Read path as an Edit denial so the model cannot
	// mutate credential/config material merely because Edit itself is allowed.
	for _, rule := range base.DenyRules {
		if strings.HasPrefix(rule, "Read(") {
			denyRules = append(denyRules, "Edit("+strings.TrimPrefix(rule, "Read("))
		}
	}
	// Workspace writes are controller-owned. The model may request an exact
	// broker tool, but Grok's built-in Edit and Bash surfaces remain denied so
	// it cannot bypass the optimistic-hash writer or isolated verifier.
	denyRules = append(denyRules, "Edit", "WebFetch", "WebSearch", "Bash(*)")
	return GrokAutomationPolicyDescriptor{
		Name:           GrokWorkspaceWritePolicyName,
		Sandbox:        "strict",
		PermissionMode: "dontAsk",
		AllowRules: []string{
			"Read", "Grep",
			"MCPTool(ntm-controlled-workspace__list_files)",
			"MCPTool(ntm-controlled-workspace__read_file)",
			"MCPTool(ntm-controlled-workspace__write_file)",
			"MCPTool(ntm-controlled-workspace__verify_worktree)",
		},
		DenyRules: denyRules,
	}
}

// GrokAutomationPolicy resolves the only built-in unattended Grok policies.
// It returns a copy so callers cannot mutate the reviewed rule set.
func GrokAutomationPolicy(name string) (GrokAutomationPolicyDescriptor, bool) {
	switch name {
	case DefaultGrokAutomationPolicyName:
		return DefaultGrokAutomationPolicy(), true
	case GrokWorkspaceWritePolicyName:
		return GrokWorkspaceWritePolicy(), true
	default:
		return GrokAutomationPolicyDescriptor{}, false
	}
}

// DefaultGrokAutomationPermissionArgs returns exec-ready permission arguments.
// Values are not shell-quoted because native adapters pass this vector directly
// to execve rather than joining it into a shell command.
func DefaultGrokAutomationPermissionArgs() []string {
	return GrokAutomationPermissionArgs(DefaultGrokAutomationPolicyName)
}

// GrokAutomationPermissionArgs returns exec-ready permission arguments for a
// named built-in policy. Unknown policy names return nil so callers fail closed.
func GrokAutomationPermissionArgs(name string) []string {
	policy, ok := GrokAutomationPolicy(name)
	if !ok {
		return nil
	}
	args := []string{"--permission-mode", policy.PermissionMode}
	for _, rule := range policy.AllowRules {
		args = append(args, "--allow", rule)
	}
	for _, rule := range policy.DenyRules {
		args = append(args, "--deny", rule)
	}
	return args
}

// DefaultGrokAutomationACPPolicyArgs returns the same named policy in the
// single-argument form accepted by the ACP adapter's narrow launch validator.
// Keeping the permission mode explicit prevents CLI-default drift.
func DefaultGrokAutomationACPPolicyArgs() []string {
	return GrokAutomationACPPolicyArgs(DefaultGrokAutomationPolicyName)
}

// GrokAutomationACPPolicyArgs returns ACP-ready arguments for a named policy.
func GrokAutomationACPPolicyArgs(name string) []string {
	policy, ok := GrokAutomationPolicy(name)
	if !ok {
		return nil
	}
	args := []string{"--sandbox=" + policy.Sandbox, "--permission-mode=" + policy.PermissionMode}
	for _, rule := range policy.AllowRules {
		args = append(args, "--allow="+rule)
	}
	for _, rule := range policy.DenyRules {
		args = append(args, "--deny="+rule)
	}
	return args
}

// GrokAutomationLifecyclePolicyArgs returns the explicit permission rules for
// a resume or fork without forcing a sandbox profile. Grok 1.0.13 binds a
// session to its original sandbox and refuses a resume that supplies a
// different profile. The root-owned managed requirements remain the authority
// for the named policy; omitting only this session-bound selector lets Grok
// retain its provider-recorded sandbox while preserving every permission rule.
func GrokAutomationLifecyclePolicyArgs(name string) []string {
	args := GrokAutomationACPPolicyArgs(name)
	if len(args) == 0 {
		return nil
	}
	result := make([]string, 0, len(args)-1)
	for _, arg := range args {
		if strings.HasPrefix(arg, "--sandbox=") {
			continue
		}
		result = append(result, arg)
	}
	return result
}

// DefaultGrokAutomationPolicySHA256 is a stable, non-secret authorization
// digest for receipts. Length-prefix-free ambiguity is avoided with NUL
// separators because policy names and rules cannot contain control bytes.
func DefaultGrokAutomationPolicySHA256() string {
	return GrokAutomationPolicySHA256(DefaultGrokAutomationPolicyName)
}

// GrokAutomationPolicySHA256 returns the receipt-safe digest for a policy.
func GrokAutomationPolicySHA256(name string) string {
	policy, ok := GrokAutomationPolicy(name)
	if !ok {
		return ""
	}
	fields := []string{policy.Name, policy.Sandbox, policy.PermissionMode}
	fields = append(fields, policy.AllowRules...)
	fields = append(fields, policy.DenyRules...)
	sum := sha256.Sum256([]byte(strings.Join(fields, "\x00")))
	return hex.EncodeToString(sum[:])
}

// DefaultGrokAutomationShellArgs returns shell-ready static arguments for
// launchers that keep the binary and argument vector separately. Rule values
// containing spaces are single-quoted because those launchers join the vector
// into a shell command rather than invoking execve directly.
func DefaultGrokAutomationShellArgs() []string {
	return GrokAutomationShellArgs(DefaultGrokAutomationPolicyName)
}

// GrokAutomationShellArgs returns shell-ready static args for a named policy.
func GrokAutomationShellArgs(name string) []string {
	policy, ok := GrokAutomationPolicy(name)
	if !ok {
		return nil
	}
	args := []string{"--no-auto-update", "--sandbox", policy.Sandbox, "--permission-mode", policy.PermissionMode}
	for _, rule := range policy.AllowRules {
		args = append(args, "--allow", "'"+rule+"'")
	}
	for _, rule := range policy.DenyRules {
		args = append(args, "--deny", "'"+rule+"'")
	}
	return args
}
