package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dicklesworthstone/ntm/internal/provider"
)

type providerBrokerVerifierFake struct {
	manifests []provider.VerificationManifest
}

func (f *providerBrokerVerifierFake) Verify(_ context.Context, manifest provider.VerificationManifest) (provider.VerificationReceipt, error) {
	f.manifests = append(f.manifests, manifest)
	return provider.VerificationReceipt{
		SchemaVersion:      "ntm.provider-verification.v2",
		NetworkIsolated:    true,
		CredentialsCleared: true,
		CleanupVerified:    true,
		DisposableWorktree: true,
	}, nil
}

func TestProviderBrokerExposesOnlyFixedWorkspaceToolSet(t *testing.T) {
	broker := &providerBroker{}
	response := broker.handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	if response.Error != nil {
		t.Fatalf("tools/list error = %+v", response.Error)
	}
	encoded, err := json.Marshal(response.Result)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"list_files", "read_file", "write_file", "verify_worktree"} {
		if !strings.Contains(string(encoded), `"name":"`+name+`"`) {
			t.Fatalf("tools/list omitted %q: %s", name, encoded)
		}
	}
	for _, forbidden := range []string{"shell", "exec", "network", "credential"} {
		if strings.Contains(string(encoded), `"name":"`+forbidden+`"`) {
			t.Fatalf("tools/list exposed forbidden tool %q: %s", forbidden, encoded)
		}
	}
}

func TestProviderBrokerRejectsUnknownMethodAndToolWithoutExecuting(t *testing.T) {
	broker := &providerBroker{}
	unknownMethod := broker.handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"shell/exec","params":{}}`))
	if unknownMethod.Error == nil || unknownMethod.Error.Code != -32601 {
		t.Fatalf("unknown method response = %+v", unknownMethod)
	}
	unknownTool := broker.handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shell","arguments":{}}}`))
	if unknownTool.Error == nil || unknownTool.Error.Code != -32602 {
		t.Fatalf("unknown tool response = %+v", unknownTool)
	}
}

func TestProviderBrokerRejectsUnboundedAndMalformedRequests(t *testing.T) {
	broker := &providerBroker{}
	malformed := broker.handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","extra":true}`))
	if malformed.Error == nil || malformed.Error.Code != -32700 {
		t.Fatalf("malformed response = %+v", malformed)
	}
	tooLarge := broker.handle(context.Background(), []byte(strings.Repeat("x", providerBrokerMaxMessageBytes+1)))
	if tooLarge.Error == nil || tooLarge.Error.Code != -32700 {
		t.Fatalf("oversized response = %+v", tooLarge)
	}
}

func TestProviderBrokerConsumesOnlyStandardInitializedNotification(t *testing.T) {
	// The classifier is kept separate from serve because a real server may be
	// initialized only after the worktree and isolated verifier are bound.
	if !providerBrokerNotification([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`)) {
		t.Fatal("standard initialized notification was not recognized")
	}
	if providerBrokerNotification([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":{}}`)) {
		t.Fatal("tool notification was accepted")
	}
}

func TestProviderBrokerServeBindsLinkedWorktreeAndVerifier(t *testing.T) {
	repository := t.TempDir()
	runProviderToolsGit(t, repository, "init")
	runProviderToolsGit(t, repository, "config", "user.name", "NTM Provider Test")
	runProviderToolsGit(t, repository, "config", "user.email", "ntm-provider@example.invalid")
	initial := []byte("package main\n")
	if err := os.WriteFile(filepath.Join(repository, "main.go"), initial, 0o600); err != nil {
		t.Fatal(err)
	}
	runProviderToolsGit(t, repository, "add", "main.go")
	runProviderToolsGit(t, repository, "commit", "-m", "fixture")
	revision := runProviderToolsGit(t, repository, "rev-parse", "HEAD")
	linked := filepath.Join(t.TempDir(), "worktree")
	runProviderToolsGit(t, repository, "worktree", "add", "-b", "broker-test", linked, revision)

	workspace, err := provider.NewWorkspaceBroker(t.Context(), linked, revision)
	if err != nil {
		t.Fatal(err)
	}
	verifier := &providerBrokerVerifierFake{}
	broker := &providerBroker{
		workspace: workspace,
		verifier:  verifier,
		manifest: provider.VerificationManifest{
			Worktree: linked, Revision: revision, CommandIDs: []string{"go-test"},
		},
	}
	initialSHA256 := sha256.Sum256(initial)
	updated := "package main\n\nfunc main() {}\n"
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"main.go"}}}`,
		fmt.Sprintf(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"main.go","expected_sha256":"%x","content":%q}}}`, initialSHA256, updated),
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"verify_worktree","arguments":{}}}`,
	}
	var output strings.Builder
	if err := broker.serve(t.Context(), strings.NewReader(strings.Join(requests, "\n")+"\n"), &output); err != nil {
		t.Fatal(err)
	}
	responses := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(responses) != 5 {
		t.Fatalf("responses = %d, want 5 (initialized notification must be silent): %s", len(responses), output.String())
	}
	for index, raw := range responses {
		var response providerBrokerResponse
		if err := json.Unmarshal([]byte(raw), &response); err != nil {
			t.Fatalf("response %d is invalid JSON: %v", index, err)
		}
		if response.Error != nil {
			t.Fatalf("response %d failed: %+v", index, response.Error)
		}
	}
	contents, err := os.ReadFile(filepath.Join(linked, "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != updated {
		t.Fatalf("workspace content = %q, want %q", contents, updated)
	}
	if len(verifier.manifests) != 1 || verifier.manifests[0].Worktree != linked || verifier.manifests[0].Revision != revision || len(verifier.manifests[0].CommandIDs) != 1 || verifier.manifests[0].CommandIDs[0] != "go-test" {
		t.Fatalf("verifier manifests = %+v", verifier.manifests)
	}
}
