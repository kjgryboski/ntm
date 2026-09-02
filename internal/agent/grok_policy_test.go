package agent

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestDefaultGrokAutomationPolicyIsLeastPrivilege(t *testing.T) {
	policy := DefaultGrokAutomationPolicy()
	if policy.Name != DefaultGrokAutomationPolicyName || policy.Sandbox != "read-only" || policy.PermissionMode != "dontAsk" {
		t.Fatalf("policy = %+v", policy)
	}
	command := DefaultGrokAutomationCommandTemplate
	for _, required := range []string{
		"--no-auto-update", "--sandbox read-only", "--permission-mode dontAsk", "--allow 'Read'",
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
	if len(args) < 2 || args[0] != "--sandbox=read-only" || args[1] != "--permission-mode=dontAsk" {
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

func TestGrokWorkspaceWritePolicyIsNarrowAndPinned(t *testing.T) {
	policy, ok := GrokAutomationPolicy(GrokWorkspaceWritePolicyName)
	if !ok || policy.Sandbox != "strict" || policy.PermissionMode != "dontAsk" {
		t.Fatalf("workspace policy = %+v, ok=%v", policy, ok)
	}
	joinedAllow := strings.Join(policy.AllowRules, "\n")
	joinedDeny := strings.Join(policy.DenyRules, "\n")
	for _, required := range []string{"Edit"} {
		if !strings.Contains(joinedAllow, required) {
			t.Errorf("workspace allow rules omit %q", required)
		}
	}
	for _, required := range []string{"Bash(*)", "WebFetch", "WebSearch", "Read(**/.ssh/**)", "Read(**/*secret*)", "Edit(**/.grok/**)", "Edit(**/.ssh/**)", "Edit(**/*secret*)"} {
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
	requirements, ok := GrokSystemRequirementsForPolicy(GrokWorkspaceWritePolicyName)
	if !ok || requirements.PolicyName != GrokWorkspaceWritePolicyName || len(requirements.SHA256) != 64 {
		t.Fatalf("requirements = %+v, ok=%v", requirements, ok)
	}
	for _, want := range []string{"[sandbox]", "profile = \"strict\"", "[ui]", "permission_mode = \"dontAsk\"", "disable_bypass_permissions_mode = true", "[permission]", `action = "deny", tool = "bash", pattern = "*"`} {
		if !strings.Contains(requirements.Contents, want) {
			t.Errorf("requirements omit %q", want)
		}
	}
	again, _ := GrokSystemRequirementsForPolicy(GrokWorkspaceWritePolicyName)
	if requirements.SHA256 != again.SHA256 || requirements.Contents != again.Contents {
		t.Fatal("requirements rendering is not deterministic")
	}
	var decoded map[string]any
	if _, err := toml.Decode(requirements.Contents, &decoded); err != nil {
		t.Fatalf("requirements TOML is invalid: %v\n%s", err, requirements.Contents)
	}
}
