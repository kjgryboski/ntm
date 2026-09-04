package cli

// The provider broker is the only MCP service NTM offers to a coding
// provider. It deliberately has no generic command, environment, URL, or
// credential capability: a provider may read/write bounded workspace files
// and ask NTM to run the already-selected isolated verifier.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/agent"
	"github.com/Dicklesworthstone/ntm/internal/grok"
	"github.com/Dicklesworthstone/ntm/internal/provider"
)

const (
	providerBrokerProtocolVersion = "2025-03-26"
	providerBrokerName            = "ntm-controlled-workspace"
	providerBrokerMaxMessageBytes = 1 << 20
)

type providerBrokerOptions struct {
	worktree string
	revision string
	commands []string
}

type providerBrokerVerifier interface {
	Verify(context.Context, provider.VerificationManifest) (provider.VerificationReceipt, error)
}

type providerBrokerDependencies struct {
	newWorkspace func(context.Context, string, string) (*provider.WorkspaceBroker, error)
	newVerifier  func() (providerBrokerVerifier, error)
}

var providerBrokerDeps = providerBrokerDependencies{
	newWorkspace: provider.NewWorkspaceBroker,
	newVerifier: func() (providerBrokerVerifier, error) {
		catalog, err := provider.DefaultDisposableCommandCatalog()
		if err != nil {
			return nil, err
		}
		return provider.NewIsolatedVerifier(catalog)
	},
}

// providerWorkspaceBrokerDescriptor binds a workspace-write ACP turn to the
// current NTM binary, exact linked worktree revision, and a fixed verifier
// manifest inferred from the repository type. It performs no provider call.
func providerWorkspaceBrokerDescriptor(ctx context.Context, worktree string) (*grok.WorkspaceBrokerDescriptor, error) {
	worktree, err := filepath.Abs(worktree)
	if err != nil {
		return nil, fmt.Errorf("resolve provider broker worktree: %w", err)
	}
	git := exec.CommandContext(ctx, "git", "-C", worktree, "rev-parse", "--verify", "HEAD")
	revisionBytes, err := git.Output()
	if err != nil {
		return nil, errors.New("provider broker requires an exact Git HEAD revision")
	}
	revision := strings.TrimSpace(string(revisionBytes))
	// Reuse the broker's own admission logic before the provider receives a
	// prompt. This proves that the path is a linked disposable worktree and
	// that HEAD still matches the immutable manifest.
	if _, err := provider.NewWorkspaceBroker(ctx, worktree, revision); err != nil {
		return nil, fmt.Errorf("bind provider broker to disposable worktree: %w", err)
	}
	commands := make([]string, 0, 3)
	if info, statErr := os.Stat(filepath.Join(worktree, "go.mod")); statErr == nil && !info.IsDir() {
		commands = append(commands, "go-test", "go-vet")
	}
	if info, statErr := os.Stat(filepath.Join(worktree, "Cargo.toml")); statErr == nil && !info.IsDir() {
		commands = append(commands, "cargo-test")
	}
	if len(commands) == 0 {
		return nil, errors.New("provider broker has no approved verifier manifest for this repository type")
	}
	return grok.NewWorkspaceBrokerDescriptor(worktree, revision, commands)
}

func providerWorkspaceBrokerForPolicy(ctx context.Context, worktree, policy string) (*grok.WorkspaceBrokerDescriptor, error) {
	if policy != agent.GrokWorkspaceWritePolicyName {
		return nil, nil
	}
	return providerWorkspaceBrokerDescriptor(ctx, worktree)
}

type providerBroker struct {
	workspace *provider.WorkspaceBroker
	verifier  providerBrokerVerifier
	manifest  provider.VerificationManifest
}

type providerBrokerRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type providerBrokerResponse struct {
	JSONRPC string                  `json:"jsonrpc"`
	ID      json.RawMessage         `json:"id"`
	Result  any                     `json:"result,omitempty"`
	Error   *providerBrokerRPCError `json:"error,omitempty"`
}

type providerBrokerRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func newProviderBrokerCmd() *cobra.Command {
	opts := providerBrokerOptions{}
	cmd := &cobra.Command{
		Use:   "broker",
		Short: "Run NTM's constrained workspace MCP broker",
	}
	stdio := &cobra.Command{
		Use:   "stdio",
		Short: "Serve only bounded workspace tools on stdin/stdout",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProviderBrokerStdio(cmd, opts, providerBrokerDeps)
		},
	}
	stdio.Flags().StringVar(&opts.worktree, "worktree", "", "Exact linked disposable worktree path (required)")
	stdio.Flags().StringVar(&opts.revision, "revision", "", "Exact current 40-64 character Git revision (required)")
	stdio.Flags().StringSliceVar(&opts.commands, "commands", nil, "Approved verifier IDs: go-test, go-vet, cargo-test")
	cmd.AddCommand(stdio)
	return cmd
}

func runProviderBrokerStdio(cmd *cobra.Command, opts providerBrokerOptions, deps providerBrokerDependencies) error {
	if strings.TrimSpace(opts.worktree) == "" || strings.TrimSpace(opts.revision) == "" || len(opts.commands) == 0 {
		return errors.New("provider broker stdio requires --worktree, --revision, and at least one --commands ID")
	}
	if deps.newWorkspace == nil || deps.newVerifier == nil {
		return errors.New("provider broker dependencies are incomplete")
	}
	ctx := providerCommandContext(cmd)
	workspace, err := deps.newWorkspace(ctx, opts.worktree, opts.revision)
	if err != nil || workspace == nil {
		return fmt.Errorf("initialize constrained workspace broker: %w", err)
	}
	verifier, err := deps.newVerifier()
	if err != nil || verifier == nil {
		return fmt.Errorf("initialize isolated verifier: %w", err)
	}
	broker := &providerBroker{workspace: workspace, verifier: verifier, manifest: provider.VerificationManifest{
		Worktree: opts.worktree, Revision: opts.revision, CommandIDs: append([]string(nil), opts.commands...),
	}}
	return broker.serve(ctx, cmd.InOrStdin(), cmd.OutOrStdout())
}

func (b *providerBroker) serve(ctx context.Context, input io.Reader, output io.Writer) error {
	if b == nil || b.workspace == nil || b.verifier == nil || input == nil || output == nil {
		return errors.New("provider broker is not initialized")
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 32<<10), providerBrokerMaxMessageBytes)
	encoder := json.NewEncoder(output)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if providerBrokerNotification(scanner.Bytes()) {
			// MCP notifications intentionally have no JSON-RPC response. The
			// broker accepts only the standard post-initialize marker and does
			// not let notifications invoke tools or state changes.
			continue
		}
		response := b.handle(ctx, scanner.Bytes())
		if err := encoder.Encode(response); err != nil {
			return fmt.Errorf("write provider broker response: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return errors.New("provider broker input exceeded its protocol limit")
	}
	return nil
}

func providerBrokerNotification(raw []byte) bool {
	request, err := decodeProviderBrokerRequest(raw)
	return err == nil && request.JSONRPC == "2.0" && len(request.ID) == 0 && request.Method == "notifications/initialized"
}

func (b *providerBroker) handle(ctx context.Context, raw []byte) providerBrokerResponse {
	request, err := decodeProviderBrokerRequest(raw)
	if err != nil {
		return providerBrokerError(nil, -32700, "invalid JSON-RPC request")
	}
	if request.JSONRPC != "2.0" || len(request.ID) == 0 || string(request.ID) == "null" || strings.TrimSpace(request.Method) == "" {
		return providerBrokerError(request.ID, -32600, "invalid JSON-RPC envelope")
	}
	var result any
	switch request.Method {
	case "initialize":
		result = map[string]any{
			"protocolVersion": providerBrokerProtocolVersion,
			"serverInfo":      map[string]string{"name": providerBrokerName, "version": "v1"},
			"capabilities":    map[string]any{"tools": map[string]any{}},
		}
	case "notifications/initialized":
		result = map[string]any{}
	case "tools/list":
		result = map[string]any{"tools": providerBrokerToolDefinitions()}
	case "tools/call":
		result, err = b.call(ctx, request.Params)
	default:
		return providerBrokerError(request.ID, -32601, "method is not available from the constrained provider broker")
	}
	if err != nil {
		return providerBrokerError(request.ID, -32602, "tool arguments or controller operation were rejected")
	}
	return providerBrokerResponse{JSONRPC: "2.0", ID: request.ID, Result: result}
}

func decodeProviderBrokerRequest(raw []byte) (providerBrokerRequest, error) {
	if len(raw) == 0 || len(raw) > providerBrokerMaxMessageBytes {
		return providerBrokerRequest{}, errors.New("invalid request size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request providerBrokerRequest
	if err := decoder.Decode(&request); err != nil {
		return providerBrokerRequest{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return providerBrokerRequest{}, errors.New("trailing request data")
	}
	return request, nil
}

func providerBrokerError(id json.RawMessage, code int, message string) providerBrokerResponse {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return providerBrokerResponse{JSONRPC: "2.0", ID: id, Error: &providerBrokerRPCError{Code: code, Message: message}}
}

func providerBrokerToolDefinitions() []map[string]any {
	return []map[string]any{
		{"name": "list_files", "description": "List bounded source files below a relative directory in the linked disposable worktree.", "inputSchema": json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}`)},
		{"name": "read_file", "description": "Read one bounded UTF-8 source file from the linked disposable worktree.", "inputSchema": json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}`)},
		{"name": "write_file", "description": "Atomically write one bounded UTF-8 source file when its expected SHA-256 matches.", "inputSchema": json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"},"expected_sha256":{"type":"string"},"content":{"type":"string"}},"required":["path","expected_sha256","content"],"additionalProperties":false}`)},
		{"name": "verify_worktree", "description": "Run only NTM's fixed, network-isolated verification manifest after the final write.", "inputSchema": json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)},
	}
}

func (b *providerBroker) call(ctx context.Context, raw json.RawMessage) (any, error) {
	var request struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := decodeProviderNativeToolArgs(raw, &request); err != nil {
		return nil, err
	}
	var payload any
	switch request.Name {
	case "list_files":
		var args struct {
			Path string `json:"path"`
		}
		if err := decodeProviderNativeToolArgs(request.Arguments, &args); err != nil {
			return nil, err
		}
		files, receipt, err := b.workspace.ListFiles(ctx, args.Path)
		if err != nil {
			return nil, err
		}
		payload = struct {
			Files   []string                           `json:"files"`
			Receipt provider.WorkspaceOperationReceipt `json:"receipt"`
		}{files, receipt}
	case "read_file":
		var args struct {
			Path string `json:"path"`
		}
		if err := decodeProviderNativeToolArgs(request.Arguments, &args); err != nil {
			return nil, err
		}
		content, receipt, err := b.workspace.ReadFile(ctx, args.Path)
		if err != nil {
			return nil, err
		}
		payload = struct {
			Content string                             `json:"content"`
			SHA256  string                             `json:"sha256"`
			Receipt provider.WorkspaceOperationReceipt `json:"receipt"`
		}{string(content), receipt.ResultSHA256, receipt}
	case "write_file":
		var args struct {
			Path           string `json:"path"`
			ExpectedSHA256 string `json:"expected_sha256"`
			Content        string `json:"content"`
		}
		if err := decodeProviderNativeToolArgs(request.Arguments, &args); err != nil {
			return nil, err
		}
		receipt, err := b.workspace.WriteFile(ctx, args.Path, args.ExpectedSHA256, []byte(args.Content))
		if err != nil {
			return nil, err
		}
		payload = struct {
			Written bool                               `json:"written"`
			SHA256  string                             `json:"sha256"`
			Receipt provider.WorkspaceOperationReceipt `json:"receipt"`
		}{true, receipt.AfterSHA256, receipt}
	case "verify_worktree":
		var args struct{}
		if err := decodeProviderNativeToolArgs(request.Arguments, &args); err != nil {
			return nil, err
		}
		receipt, err := b.verifier.Verify(ctx, b.manifest)
		if err != nil {
			return nil, err
		}
		payload = struct {
			Passed  bool                         `json:"passed"`
			Receipt provider.VerificationReceipt `json:"receipt"`
		}{true, receipt}
	default:
		return nil, errors.New("unknown constrained broker tool")
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return map[string]any{"content": []map[string]string{{"type": "text", "text": string(encoded)}}, "isError": false}, nil
}
