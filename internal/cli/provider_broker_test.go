package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Dicklesworthstone/ntm/internal/grok"
	"github.com/Dicklesworthstone/ntm/internal/provider"
)

type providerBrokerVerifierFake struct {
	manifests []provider.VerificationManifest
}

func TestProviderBrokerControllerUsesRealWorkspaceAndIsolatedVerifier(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux verifier")
	}
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "auth.json"), []byte(`{"token":"synthetic-controller-test"}`), 0600); err != nil {
		t.Fatal(err)
	}
	workspace, err := prepareProviderGrokWorkspaceQualification(t.Context(), home)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupProviderGrokLineageWorkspace(context.Background(), workspace)
	revision, err := providerGrokQualificationGit(t.Context(), workspace.Worktree, "rev-parse", "--verify", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(workspace.Root, providerGrokWorkspaceAuditFile)
	guard, err := createProviderGrokWorkspaceAudit(auditPath, workspace.Worktree)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	descriptor, err := providerGrokControllerBrokerDescriptor(t.Context(), workspace.Worktree, auditPath)
	if err != nil {
		t.Fatal(err)
	}
	servers, err := (grok.Request{Broker: descriptor}).SessionMCPServers()
	if err != nil || len(servers) != 0 {
		t.Fatal("Grok controller descriptor still launches a child broker")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := hashProviderSessionExecutable(executable)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := openProviderBroker(t.Context(), providerBrokerOptions{worktree: workspace.Worktree, revision: revision, commands: []string{"go-test", "go-vet"}, auditFile: auditPath, ntmSHA256: digest}, providerBrokerDeps)
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	requests := []string{
		fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":%q}}}`, providerGrokWorkspaceTarget),
		fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":%q,"expected_sha256":%q,"content":%q}}}`, providerGrokWorkspaceTarget, sha256TextCLI(providerGrokWorkspaceBefore), string(providerGrokWorkspaceAfter)),
		fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":%q}}}`, providerGrokWorkspaceSecret),
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"verify_worktree","arguments":{}}}`,
	}
	for index, request := range requests {
		raw, err := broker.Call(t.Context(), json.RawMessage(request))
		if err != nil {
			t.Fatal(err)
		}
		var response providerBrokerResponse
		if json.Unmarshal(raw, &response) != nil || (response.Error != nil) != (index == 2) {
			t.Fatalf("unexpected controller operation result at %d", index)
		}
	}
	audit, err := readProviderGrokWorkspaceAudit(guard, auditPath, workspace.Worktree, revision)
	if err != nil {
		t.Fatal(err)
	}
	checks := evaluateProviderGrokWorkspaceAudit(audit, workspace.Worktree, revision)
	if !checks.ReadObserved || !checks.EditObserved || !checks.SecretDenied || !checks.TestObserved {
		t.Fatalf("controller evidence incomplete: %+v", checks)
	}
	if err := broker.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Call(t.Context(), json.RawMessage(requests[0])); err == nil {
		t.Fatal("closed broker executed a request")
	}
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
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"main.go"},"_meta":{"progressToken":3,"private-extension":"PRIVATE_METADATA_CANARY"}}}`,
		fmt.Sprintf(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"main.go","expected_sha256":"%x","content":%q}}}`, initialSHA256, updated),
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"verify_worktree","arguments":{}}}`,
	}
	var output strings.Builder
	if err := broker.serve(t.Context(), strings.NewReader(strings.Join(requests, "\n")+"\n"), &output); err != nil {
		t.Fatal(err)
	}
	responses := strings.Split(strings.TrimSpace(output.String()), "\n")
	if strings.Contains(output.String(), "PRIVATE_METADATA_CANARY") {
		t.Fatal("MCP metadata leaked into tool result")
	}
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

func TestProviderBrokerAuditIsPrivateRedactedAndEnforcesWriteThenVerify(t *testing.T) {
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
	parent := t.TempDir()
	linked := filepath.Join(parent, "worktree")
	runProviderToolsGit(t, repository, "worktree", "add", "-b", "broker-audit-test", linked, revision)
	workspace, err := provider.NewWorkspaceBroker(t.Context(), linked, revision)
	if err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(parent, "broker-audit.jsonl")
	holder, err := os.OpenFile(auditPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	audit, err := openProviderBrokerAudit(linked, revision, auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.file.Close()
	if _, err := openProviderBrokerAudit(linked, revision, auditPath); err == nil {
		t.Fatal("nonempty audit file was admitted more than once")
	}
	verifier := &providerBrokerVerifierFake{}
	broker := &providerBroker{workspace: workspace, verifier: verifier, audit: audit, manifest: provider.VerificationManifest{
		Worktree: linked, Revision: revision, CommandIDs: []string{"go-test"},
	}}
	initialSHA256 := sha256.Sum256(initial)
	secretContent := "do-not-persist-this-content"
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"verify_worktree","arguments":{}}}`,
		fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"main.go","expected_sha256":"%x","content":%q}}}`, initialSHA256, secretContent),
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"verify_worktree","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"verify_worktree","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"shell","arguments":{}}}`,
	}
	var output strings.Builder
	if err := broker.serve(t.Context(), strings.NewReader(strings.Join(requests, "\n")+"\n"), &output); err != nil {
		t.Fatal(err)
	}
	responses := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(responses) != len(requests) {
		t.Fatalf("response count = %d, want %d", len(responses), len(requests))
	}
	for _, index := range []int{0, 3, 4} {
		var response providerBrokerResponse
		if err := json.Unmarshal([]byte(responses[index]), &response); err != nil {
			t.Fatal(err)
		}
		if response.Error == nil {
			t.Fatalf("response %d unexpectedly succeeded: %+v", index, response)
		}
	}
	if len(verifier.manifests) != 1 {
		t.Fatalf("verification calls = %d, want 1", len(verifier.manifests))
	}
	info, err := os.Stat(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("audit mode = %o, want 600", info.Mode().Perm())
	}
	encoded, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secretContent) || strings.Contains(string(encoded), "main.go") || strings.Contains(string(encoded), linked) {
		t.Fatalf("audit retained raw sensitive input: %s", encoded)
	}
	lines := strings.Split(strings.TrimSpace(string(encoded)), "\n")
	if len(lines) != len(requests)+1 {
		t.Fatalf("audit line count = %d, want %d: %s", len(lines), len(requests)+1, encoded)
	}
	var header providerBrokerAuditHeader
	if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
		t.Fatal(err)
	}
	if header.SchemaVersion != providerBrokerAuditSchemaVersion || header.Kind != "header" || header.WorktreeSHA256 == "" || header.RevisionSHA256 == "" {
		t.Fatalf("audit header = %+v", header)
	}
	for index, raw := range lines[1:] {
		var event providerBrokerAuditEvent
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			t.Fatal(err)
		}
		if event.Sequence != uint64(index+1) || event.SchemaVersion != providerBrokerAuditSchemaVersion || event.Kind != "tool_call" {
			t.Fatalf("audit event %d = %+v", index, event)
		}
	}
	var writeEvent, verifiedEvent, staleEvent providerBrokerAuditEvent
	_ = json.Unmarshal([]byte(lines[2]), &writeEvent)
	_ = json.Unmarshal([]byte(lines[3]), &verifiedEvent)
	_ = json.Unmarshal([]byte(lines[4]), &staleEvent)
	if !writeEvent.Success || writeEvent.WorkspaceReceipt == nil || writeEvent.PathSHA256 == "" {
		t.Fatalf("write audit event = %+v", writeEvent)
	}
	if !verifiedEvent.Success || verifiedEvent.VerificationReceipt == nil {
		t.Fatalf("verification audit event = %+v", verifiedEvent)
	}
	if staleEvent.Success || !staleEvent.Rejected || staleEvent.ErrorSHA256 == "" {
		t.Fatalf("stale verification audit event = %+v", staleEvent)
	}
}

func TestProviderBrokerAuditRequiresPrecreatedPrivateFileAndExecutableDigest(t *testing.T) {
	parent := t.TempDir()
	linked := filepath.Join(parent, "linked")
	if err := os.Mkdir(linked, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]struct {
		contents string
		mode     os.FileMode
	}{
		"missing.jsonl":  {"", 0o600},
		"nonempty.jsonl": {"unexpected", 0o600},
		"wide.jsonl":     {"", 0o644},
	} {
		path := filepath.Join(parent, name)
		if name != "missing.jsonl" {
			if err := os.WriteFile(path, []byte(contents.contents), contents.mode); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := openProviderBrokerAudit(linked, strings.Repeat("a", 40), path); err == nil {
			t.Fatalf("invalid audit file %q was admitted", name)
		}
	}
	if verifyProviderBrokerExecutableDigest(strings.Repeat("0", sha256.Size*2)) {
		t.Fatal("mismatched broker executable digest was accepted")
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if !verifyProviderBrokerExecutableDigest(fmt.Sprintf("%x", hasher.Sum(nil))) {
		t.Fatal("current broker executable digest was rejected")
	}
}
