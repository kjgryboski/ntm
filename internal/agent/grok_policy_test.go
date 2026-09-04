package agent

import (
	"slices"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestDefaultGrokAutomationPolicyIsLeastPrivilege(t *testing.T) {
	policy := DefaultGrokAutomationPolicy()
	if policy.Name != DefaultGrokAutomationPolicyName || policy.Sandbox != "strict" || policy.PermissionMode != "dontAsk" {
		t.Fatalf("policy = %+v", policy)
	}
	command := DefaultGrokAutomationCommandTemplate
	for _, required := range []string{
		"--no-auto-update", "--sandbox strict", "--permission-mode dontAsk", "--allow 'Read'",
		"--deny 'Edit'", "--deny 'Bash(*)'", "--deny 'Read(**/.grok/**)'",
		"--deny 'Read(**/.config/gh/**)'", "--deny 'Read(**/.azure/**)'", "--deny 'Read(**/*.key)'",
		"--deny 'Grep(**/.grok/**)'", "--deny 'Grep(**/.config/gh/**)'", "--deny 'Grep(**/.azure/**)'", "--deny 'Grep(**/*.key)'",
	} {
		if !strings.Contains(command, required) {
			t.Errorf("default Grok command omits %q", required)
		}
	}
	if strings.Contains(command, "--always-approve") || strings.Contains(command, "--yolo") {
		t.Fatalf("default Grok command grants broad approval: %q", command)
	}
}

func TestDefaultGrokAutomationPolicyReturnsCopies(t *testing.T) {
	first := DefaultGrokAutomationPolicy()
	first.AllowRules[0] = "mutated"
	second := DefaultGrokAutomationPolicy()
	if second.AllowRules[0] != "Read" {
		t.Fatalf("policy metadata shared mutable backing storage: %+v", second.AllowRules)
	}
}

func TestDefaultGrokAutomationACPPolicyIsExplicitAndDigestStable(t *testing.T) {
	args := DefaultGrokAutomationACPPolicyArgs()
	if len(args) < 2 || args[0] != "--sandbox=strict" || args[1] != "--permission-mode=dontAsk" {
		t.Fatalf("ACP policy args = %#v", args)
	}
	joined := strings.Join(args, "\n")
	for _, required := range []string{"--allow=Read", "--deny=Edit", "--deny=Bash(*)", "--deny=Read(**/.grok/**)", "--deny=Read(**/.config/gh/**)", "--deny=Read(**/.azure/**)", "--deny=Read(**/*.key)", "--deny=Grep(**/.grok/**)", "--deny=Grep(**/.config/gh/**)", "--deny=Grep(**/.azure/**)", "--deny=Grep(**/*.key)"} {
		if !strings.Contains(joined, required) {
			t.Errorf("ACP policy omits %q", required)
		}
	}
	if digest := DefaultGrokAutomationPolicySHA256(); len(digest) != 64 || digest != DefaultGrokAutomationPolicySHA256() {
		t.Fatalf("policy digest = %q", digest)
	}
}

func TestGrokAutomationLifecyclePolicyArgsOmitOnlySessionBoundSandbox(t *testing.T) {
	for _, name := range []string{DefaultGrokAutomationPolicyName, GrokWorkspaceWritePolicyName} {
		full := GrokAutomationACPPolicyArgs(name)
		lifecycle := GrokAutomationLifecyclePolicyArgs(name)
		want := make([]string, 0, len(full)-1)
		for _, arg := range full {
			if strings.HasPrefix(arg, "--sandbox=") {
				continue
			}
			want = append(want, arg)
		}
		if !slices.Equal(lifecycle, want) {
			t.Fatalf("policy %q lifecycle args changed more than sandbox: got=%#v want=%#v", name, lifecycle, want)
		}
		if strings.Contains(strings.Join(lifecycle, "\n"), "--sandbox=") {
			t.Fatalf("policy %q lifecycle args still force a sandbox: %#v", name, lifecycle)
		}
	}
	if args := GrokAutomationLifecyclePolicyArgs("unknown"); args != nil {
		t.Fatalf("unknown lifecycle policy args = %#v, want nil", args)
	}
}

func TestGrokWorkspaceWritePolicyIsNarrowAndPinned(t *testing.T) {
	policy, ok := GrokAutomationPolicy(GrokWorkspaceWritePolicyName)
	if !ok || policy.Sandbox != "strict" || policy.PermissionMode != "dontAsk" {
		t.Fatalf("workspace policy = %+v, ok=%v", policy, ok)
	}
	joinedAllow := strings.Join(policy.AllowRules, "\n")
	joinedDeny := strings.Join(policy.DenyRules, "\n")
	for _, required := range []string{
		"MCPTool(ntm-controlled-workspace__list_files)",
		"MCPTool(ntm-controlled-workspace__read_file)",
		"MCPTool(ntm-controlled-workspace__write_file)",
		"MCPTool(ntm-controlled-workspace__verify_worktree)",
	} {
		if !strings.Contains(joinedAllow, required) {
			t.Errorf("workspace allow rules omit %q", required)
		}
	}
	if strings.Contains(joinedAllow, "\nEdit\n") || joinedAllow == "Edit" || strings.HasPrefix(joinedAllow, "Edit\n") || strings.HasSuffix(joinedAllow, "\nEdit") {
		t.Fatal("workspace policy exposes Grok's built-in Edit surface")
	}
	for _, required := range []string{"Edit", "Bash(*)", "WebFetch", "WebSearch", "Read(**/.ssh/**)", "Read(**/*secret*)", "Edit(**/.grok/**)", "Edit(**/.ssh/**)", "Edit(**/*secret*)"} {
		if !strings.Contains(joinedDeny, required) {
			t.Errorf("workspace deny rules omit %q", required)
		}
	}
	if got := GrokAutomationPolicySHA256(GrokWorkspaceWritePolicyName); len(got) != 64 || got == DefaultGrokAutomationPolicySHA256() {
		t.Fatalf("workspace policy digest = %q", got)
	}
	if args := GrokAutomationACPPolicyArgs("unknown"); args != nil {
		t.Fatalf("unknown policy args = %#v, want nil", args)
	}
}

func TestGrokSystemRequirementsAreDeterministicAndLockBypass(t *testing.T) {
	observe, ok := GrokSystemRequirementsForPolicy(DefaultGrokAutomationPolicyName)
	if !ok || observe.PolicyName != DefaultGrokAutomationPolicyName || len(observe.SHA256) != 64 {
		t.Fatalf("observe requirements = %+v, ok=%v", observe, ok)
	}
	workspace, ok := GrokSystemRequirementsForPolicy(GrokWorkspaceWritePolicyName)
	if !ok || workspace.PolicyName != GrokWorkspaceWritePolicyName || len(workspace.SHA256) != 64 {
		t.Fatalf("workspace requirements = %+v, ok=%v", workspace, ok)
	}
	if observe.SHA256 != workspace.SHA256 || observe.Contents != workspace.Contents {
		t.Fatalf("global requirements differ by invocation policy: observe=%+v workspace=%+v", observe, workspace)
	}
	for _, want := range []string{
		"[sandbox]", "profile = \"strict\"",
		"[ui]", "permission_mode = \"dontAsk\"", "disable_bypass_permissions_mode = true",
		"[features]", "write_file = false", "lsp_tools = false",
		"[subagents]", "enabled = false",
		"[memory]",
		"[plugins]", "paths = []",
		"[compat.claude]", "skills = false", "rules = false", "agents = false", "mcps = false", "hooks = false",
		"[compat.cursor]", "skills = false", "rules = false", "agents = false", "mcps = false", "hooks = false",
		"[permission]",
		`action = "deny", tool = "bash", pattern = "*"`,
		`action = "deny", tool = "edit", pattern = "**/.grok/**"`,
		`action = "allow", tool = "mcp", pattern = "ntm-controlled-workspace__write_file"`,
	} {
		if !strings.Contains(observe.Contents, want) {
			t.Errorf("requirements omit %q", want)
		}
	}
	if strings.Contains(observe.Contents, `tool = "mcptool"`) {
		t.Fatal("requirements used the CLI MCPTool spelling instead of the documented verbose TOML mcp tool name")
	}
	if strings.Contains(observe.Contents, "tool_search") {
		t.Fatal("requirements emitted a setting that pinned Grok 1.0.13 reports as unsupported")
	}
	again, _ := GrokSystemRequirementsForPolicy(DefaultGrokAutomationPolicyName)
	if observe.SHA256 != again.SHA256 || observe.Contents != again.Contents {
		t.Fatal("requirements rendering is not deterministic")
	}
	var decoded map[string]any
	if _, err := toml.Decode(observe.Contents, &decoded); err != nil {
		t.Fatalf("requirements TOML is invalid: %v\n%s", err, observe.Contents)
	}
}
