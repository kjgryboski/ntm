package zai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeCodexManifestFixture(t *testing.T) CodexManifestExpectation {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a POSIX executable script")
	}
	base := t.TempDir()
	profile := "zai-codex-kevin"
	runtimeHome := filepath.Join(base, profile, ".codex")
	if err := os.MkdirAll(runtimeHome, 0o700); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(base, "caam-zai-codex")
	binary := filepath.Join(base, "codex-0.149.0")
	bridge := filepath.Join(base, "ntm-provider-bridge.exe")
	for path, contents := range map[string]string{
		helper: "#!/bin/sh\nexit 1\n",
		binary: "#!/bin/sh\nprintf 'codex-cli 0.149.0\\n'\n",
		bridge: "#!/bin/sh\nexit 1\n",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	config := fmt.Sprintf("cli_auth_credentials_store = \"ephemeral\"\nmodel_provider = \"zai\"\nmodel = \"glm-5.3\"\nmodel_catalog_json = \"models.json\"\nmodel_reasoning_effort = \"max\"\napproval_policy = \"never\"\nallow_login_shell = false\ncheck_for_update_on_startup = false\ndefault_permissions = \"zai_observe\"\n\n[history]\npersistence = \"none\"\n\n[shell_environment_policy]\ninherit = \"core\"\nignore_default_excludes = false\nexclude = [\"ZAI_API_KEY\", \"OPENAI_API_KEY\", \"ANTHROPIC_*\", \"XAI_*\", \"*TOKEN*\", \"*SECRET*\", \"*PASSWORD*\", \"*KEY*\", \"CODEX_HOME\"]\n\n[permissions.zai_observe.filesystem]\n\":minimal\" = \"read\"\nglob_scan_max_depth = 8\n\n[permissions.zai_observe.filesystem.\":workspace_roots\"]\n\".\" = \"read\"\n\".qualification-secret\" = \"deny\"\n\"**/.qualification-secret\" = \"deny\"\n\".env*\" = \"deny\"\n\"**/.env*\" = \"deny\"\n\".ssh\" = \"deny\"\n\"**/.ssh/**\" = \"deny\"\n\".aws\" = \"deny\"\n\"**/.aws/**\" = \"deny\"\n\".config\" = \"deny\"\n\"**/.config/**\" = \"deny\"\n\n[permissions.zai_observe.network]\nenabled = false\n\n[permissions.zai_workspace_write.filesystem]\n\":minimal\" = \"read\"\nglob_scan_max_depth = 8\n\n[permissions.zai_workspace_write.filesystem.\":workspace_roots\"]\n\".\" = \"write\"\n\".git\" = \"read\"\n\".qualification-secret\" = \"deny\"\n\"**/.qualification-secret\" = \"deny\"\n\".env*\" = \"deny\"\n\"**/.env*\" = \"deny\"\n\".ssh\" = \"deny\"\n\"**/.ssh/**\" = \"deny\"\n\".aws\" = \"deny\"\n\"**/.aws/**\" = \"deny\"\n\".config\" = \"deny\"\n\"**/.config/**\" = \"deny\"\n\n[permissions.zai_workspace_write.network]\nenabled = false\n\n[model_providers.zai]\nname = \"Z.ai Coding Plan\"\nbase_url = \"%s\"\nenv_key = \"ZAI_API_KEY\"\nwire_api = \"responses\"\n", OfficialCodexEndpoint)
	config = strings.Replace(config, `model_catalog_json = "models.json"`, `model_catalog_json = "~/.codex/models.json"`, 1)
	models := "{\n  \"models\": [\n    {\n      \"slug\": \"glm-5.3\",\n      \"display_name\": \"GLM-5.3\",\n      \"description\": \"Z.ai GLM-5.3 Coding Plan model.\",\n      \"default_reasoning_level\": \"max\",\n      \"supported_reasoning_levels\": [\n        {\"effort\": \"low\", \"description\": \"Fast responses for straightforward tasks.\"},\n        {\"effort\": \"high\", \"description\": \"More reasoning for complex coding tasks.\"},\n        {\"effort\": \"max\", \"description\": \"Maximum reasoning depth for the hardest tasks.\"}\n      ],\n      \"shell_type\": \"shell_command\",\n      \"visibility\": \"list\",\n      \"supported_in_api\": true,\n      \"priority\": 0,\n      \"availability_nux\": null,\n      \"upgrade\": null,\n      \"support_verbosity\": false,\n      \"default_verbosity\": null,\n      \"apply_patch_tool_type\": \"freeform\",\n      \"truncation_policy\": {\"mode\": \"bytes\", \"limit\": 10000},\n      \"context_window\": 1048576,\n      \"max_context_window\": 1048576,\n      \"effective_context_window_percent\": 95,\n      \"supports_reasoning_summaries\": true,\n      \"default_reasoning_summary\": \"none\",\n      \"supports_parallel_tool_calls\": true,\n      \"experimental_supported_tools\": [],\n      \"input_modalities\": [\"text\"],\n      \"base_instructions\": \"\"\n    }\n  ]\n}\n"
	models = strings.Replace(models, `"display_name": "GLM-5.3"`, `"display_name": "glm-5.3"`, 1)
	models = strings.Replace(models, `"description": "Z.ai GLM-5.3 Coding Plan model."`, `"description": "Z.ai's latest flagship model"`, 1)
	models = strings.ReplaceAll(models, "Fast responses for straightforward tasks.", "Light reasoning")
	models = strings.ReplaceAll(models, "More reasoning for complex coding tasks.", "Enhanced reasoning")
	models = strings.ReplaceAll(models, "Maximum reasoning depth for the hardest tasks.", "Deep reasoning")
	models = strings.Replace(models, "      \"availability_nux\": null,\n      \"upgrade\": null,\n", "", 1)
	models = strings.Replace(models, "      \"default_verbosity\": null,\n", "", 1)
	helperHash := sha256.Sum256([]byte("#!/bin/sh\nexit 1\n"))
	binaryHash := sha256.Sum256([]byte("#!/bin/sh\nprintf 'codex-cli 0.149.0\\n'\n"))
	descriptor := fmt.Sprintf("{\n  \"manifest_version\": %q,\n  \"provider\": \"zai\",\n  \"account_alias\": \"kevin\",\n  \"credential_class\": \"coding_plan\",\n  \"billing_class\": \"coding_plan\",\n  \"entitlement\": \"codex_responses\",\n  \"runtime\": \"codex\",\n  \"model\": \"glm-5.3\",\n  \"endpoint\": %q,\n  \"credential_id\": \"ntm.zai.coding_plan.kevin\",\n  \"broker_protocol\": \"ntm-provider-bridge-v1\",\n  \"bridge_path\": %q,\n  \"bridge_sha256\": %q,\n  \"sync_policy\": \"host-local-metadata-only\"\n}\n", CodexManifestVersion, OfficialCodexEndpoint, bridge, hex.EncodeToString(helperHash[:]))
	files := map[string][]byte{
		"auth.json":      {},
		"config.toml":    []byte(config),
		"models.json":    []byte(models),
		"zai-codex.json": []byte(descriptor),
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(runtimeHome, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	expectation := CodexManifestExpectation{
		RuntimeHome: runtimeHome, Account: "kevin", Endpoint: OfficialCodexEndpoint, Model: "glm-5.3",
		BrokerCredentialID: "ntm.zai.coding_plan.kevin", Binary: binary, BinarySHA256: hex.EncodeToString(binaryHash[:]),
		BrokerCommand: helper, BrokerCommandSHA256: hex.EncodeToString(helperHash[:]),
		CredentialBridgeCommand: bridge, CredentialBridgeCommandSHA256: hex.EncodeToString(helperHash[:]),
		Version: "0.149.0",
	}
	digest, err := CAAMCodexManifestSHA256(expectation)
	if err != nil {
		t.Fatal(err)
	}
	expectation.ConfigSHA256 = digest
	return expectation
}

func TestAttestCodexManifestRejectsNonemptyAuthFile(t *testing.T) {
	expectation := writeCodexManifestFixture(t)
	if err := os.WriteFile(filepath.Join(expectation.RuntimeHome, "auth.json"), []byte(`{"token":"must-not-be-used"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AttestCodexManifest(context.Background(), expectation); err == nil {
		t.Fatal("nonempty profile auth file was accepted")
	}
}

func TestAttestCodexManifestBindsFilesHelperAndBinary(t *testing.T) {
	expectation := writeCodexManifestFixture(t)
	attestation, err := AttestCodexManifest(context.Background(), expectation)
	if err != nil {
		t.Fatal(err)
	}
	if attestation.ConfigSHA256 != expectation.ConfigSHA256 || len(attestation.BinarySHA256) != 64 || len(attestation.AuthHelperSHA256) != 64 || attestation.CredentialBridgeSHA256 != expectation.CredentialBridgeCommandSHA256 || attestation.RuntimeVersion != expectation.Version {
		t.Fatalf("attestation = %+v", attestation)
	}
}

func TestAttestCodexManifestRejectsTamperAndWrongIdentity(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*CodexManifestExpectation)
	}{
		{name: "digest", mutate: func(e *CodexManifestExpectation) { e.ConfigSHA256 = strings.Repeat("0", 64) }},
		{name: "account", mutate: func(e *CodexManifestExpectation) { e.Account = "other" }},
		{name: "model", mutate: func(e *CodexManifestExpectation) { e.Model = "glm-5.3-flash" }},
		{name: "credential", mutate: func(e *CodexManifestExpectation) { e.BrokerCredentialID = "ntm.zai.coding_plan.other" }},
		{name: "version", mutate: func(e *CodexManifestExpectation) { e.Version = "0.150.0" }},
		{name: "binary hash", mutate: func(e *CodexManifestExpectation) { e.BinarySHA256 = strings.Repeat("0", 64) }},
		{name: "broker hash", mutate: func(e *CodexManifestExpectation) { e.BrokerCommandSHA256 = strings.Repeat("0", 64) }},
		{name: "bridge hash", mutate: func(e *CodexManifestExpectation) { e.CredentialBridgeCommandSHA256 = strings.Repeat("0", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			expectation := writeCodexManifestFixture(t)
			test.mutate(&expectation)
			if _, err := AttestCodexManifest(context.Background(), expectation); err == nil {
				t.Fatal("tampered manifest was accepted")
			}
		})
	}
}

func TestAttestCodexManifestRejectsDescriptorBridgePathAfterDigestRefresh(t *testing.T) {
	expectation := writeCodexManifestFixture(t)
	descriptorPath := filepath.Join(expectation.RuntimeHome, "zai-codex.json")
	contents, err := os.ReadFile(descriptorPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(descriptorPath, []byte(strings.Replace(string(contents), expectation.CredentialBridgeCommand, "/usr/local/libexec/ntm/substituted-bridge", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CAAMCodexManifestSHA256(expectation); err == nil {
		t.Fatal("canonical manifest verification accepted substituted bridge path")
	}
	if _, err := AttestCodexManifest(context.Background(), expectation); err == nil {
		t.Fatal("descriptor bridge-path substitution retained manifest authority")
	}
}

func TestAttestCodexManifestRejectsSymlinkedManagedFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not generally available to unprivileged Windows tests")
	}
	expectation := writeCodexManifestFixture(t)
	target := filepath.Join(filepath.Dir(expectation.RuntimeHome), "outside-models.json")
	managed := filepath.Join(expectation.RuntimeHome, "models.json")
	if err := os.Rename(managed, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, managed); err != nil {
		t.Fatal(err)
	}
	if _, err := AttestCodexManifest(context.Background(), expectation); err == nil {
		t.Fatal("symlinked managed file was accepted")
	}
}
