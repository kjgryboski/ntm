package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

type providerNativeToolController interface {
	zai.NativeToolExecutor
	Receipt() providerNativeControllerReceipt
	CompletedVerification() bool
}

type providerNativeControllerReceipt struct {
	SchemaVersion       string                               `json:"schema_version"`
	ManifestSHA256      string                               `json:"manifest_sha256"`
	WorkspaceOperations []provider.WorkspaceOperationReceipt `json:"workspace_operations"`
	Verification        *provider.VerificationReceipt        `json:"verification,omitempty"`
	VerificationSHA256  string                               `json:"verification_sha256,omitempty"`
	Dirty               bool                                 `json:"dirty"`
	Verified            bool                                 `json:"verified"`
}

type providerNativeController struct {
	workspace *provider.WorkspaceBroker
	verifier  providerVerificationRunner
	manifest  provider.VerificationManifest
	receipt   providerNativeControllerReceipt
}

func newProviderNativeController(ctx context.Context, opts providerNativeRunOptions) (providerNativeToolController, error) {
	workspace, err := provider.NewWorkspaceBroker(ctx, opts.worktree, opts.revision)
	if err != nil {
		return nil, err
	}
	catalog, err := provider.DefaultDisposableCommandCatalog()
	if err != nil {
		return nil, err
	}
	verifier, err := provider.NewIsolatedVerifier(catalog)
	if err != nil {
		return nil, err
	}
	manifest := provider.VerificationManifest{Worktree: opts.worktree, Revision: opts.revision, CommandIDs: append([]string(nil), opts.commands...)}
	return &providerNativeController{
		workspace: workspace, verifier: verifier, manifest: manifest,
		receipt: providerNativeControllerReceipt{SchemaVersion: "ntm.provider-native-controller.v1", ManifestSHA256: providerNativeToolManifestBinding(opts), WorkspaceOperations: []provider.WorkspaceOperationReceipt{}},
	}, nil
}

func (c *providerNativeController) ExecuteNativeTool(ctx context.Context, call zai.NativeToolCall) (zai.NativeToolResult, error) {
	if c == nil || c.workspace == nil || c.verifier == nil {
		return zai.NativeToolResult{}, errors.New("native provider controller is unavailable")
	}
	switch call.Name {
	case "list_files":
		var args struct {
			Path string `json:"path"`
		}
		if err := decodeProviderNativeToolArgs(call.Arguments, &args); err != nil {
			return zai.NativeToolResult{}, err
		}
		files, receipt, err := c.workspace.ListFiles(ctx, args.Path)
		c.receipt.WorkspaceOperations = append(c.receipt.WorkspaceOperations, receipt)
		if err != nil {
			return zai.NativeToolResult{}, err
		}
		content, err := json.Marshal(struct {
			Files []string `json:"files"`
		}{Files: files})
		if err != nil {
			return zai.NativeToolResult{}, err
		}
		return zai.NativeToolResult{Content: string(content), EvidenceSHA256: digestSafeJSON(receipt)}, nil
	case "read_file":
		var args struct {
			Path string `json:"path"`
		}
		if err := decodeProviderNativeToolArgs(call.Arguments, &args); err != nil {
			return zai.NativeToolResult{}, err
		}
		content, receipt, err := c.workspace.ReadFile(ctx, args.Path)
		c.receipt.WorkspaceOperations = append(c.receipt.WorkspaceOperations, receipt)
		if err != nil {
			return zai.NativeToolResult{}, err
		}
		result, err := json.Marshal(struct {
			Content string `json:"content"`
			SHA256  string `json:"sha256"`
		}{Content: string(content), SHA256: receipt.ResultSHA256})
		if err != nil {
			return zai.NativeToolResult{}, err
		}
		return zai.NativeToolResult{Content: string(result), EvidenceSHA256: digestSafeJSON(receipt)}, nil
	case "write_file":
		var args struct {
			Path           string `json:"path"`
			ExpectedSHA256 string `json:"expected_sha256"`
			Content        string `json:"content"`
		}
		if err := decodeProviderNativeToolArgs(call.Arguments, &args); err != nil {
			return zai.NativeToolResult{}, err
		}
		receipt, err := c.workspace.WriteFile(ctx, args.Path, args.ExpectedSHA256, []byte(args.Content))
		c.receipt.WorkspaceOperations = append(c.receipt.WorkspaceOperations, receipt)
		if err != nil {
			return zai.NativeToolResult{}, err
		}
		c.receipt.Dirty, c.receipt.Verified, c.receipt.Verification, c.receipt.VerificationSHA256 = true, false, nil, ""
		result, _ := json.Marshal(struct {
			Written bool   `json:"written"`
			SHA256  string `json:"sha256"`
		}{Written: true, SHA256: receipt.AfterSHA256})
		return zai.NativeToolResult{Content: string(result), EvidenceSHA256: digestSafeJSON(receipt)}, nil
	case "verify_worktree":
		var args struct{}
		if err := decodeProviderNativeToolArgs(call.Arguments, &args); err != nil {
			return zai.NativeToolResult{}, err
		}
		receipt, err := c.verifier.Verify(ctx, c.manifest)
		c.receipt.Verification = &receipt
		c.receipt.VerificationSHA256 = digestSafeJSON(receipt)
		if err != nil {
			c.receipt.Verified = false
			return zai.NativeToolResult{}, err
		}
		c.receipt.Dirty, c.receipt.Verified = false, true
		result, _ := json.Marshal(struct {
			Passed        bool   `json:"passed"`
			ReceiptSHA256 string `json:"receipt_sha256"`
		}{Passed: true, ReceiptSHA256: c.receipt.VerificationSHA256})
		return zai.NativeToolResult{Content: string(result), EvidenceSHA256: c.receipt.VerificationSHA256}, nil
	default:
		return zai.NativeToolResult{}, fmt.Errorf("native provider controller rejected unknown tool %q", call.Name)
	}
}

func (c *providerNativeController) Receipt() providerNativeControllerReceipt {
	if c == nil {
		return providerNativeControllerReceipt{}
	}
	result := c.receipt
	result.WorkspaceOperations = append([]provider.WorkspaceOperationReceipt(nil), c.receipt.WorkspaceOperations...)
	if c.receipt.Verification != nil {
		copyReceipt := *c.receipt.Verification
		copyReceipt.Commands = append([]provider.CommandVerification(nil), c.receipt.Verification.Commands...)
		result.Verification = &copyReceipt
	}
	return result
}

func (c *providerNativeController) CompletedVerification() bool {
	return c != nil && c.receipt.Verified && !c.receipt.Dirty && c.receipt.Verification != nil && c.receipt.VerificationSHA256 != ""
}

func providerNativeToolDefinitions() []zai.NativeFunctionDefinition {
	return []zai.NativeFunctionDefinition{
		{Name: "list_files", Description: "List bounded source files below a relative directory in the disposable worktree.", Parameters: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}`)},
		{Name: "read_file", Description: "Read one bounded UTF-8 source file from the disposable worktree.", Parameters: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}`)},
		{Name: "write_file", Description: "Atomically write one bounded UTF-8 source file when its current SHA-256 matches.", Parameters: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"},"expected_sha256":{"type":"string"},"content":{"type":"string"}},"required":["path","expected_sha256","content"],"additionalProperties":false}`)},
		{Name: "verify_worktree", Description: "Run the controller-selected isolated verification manifest after the final write.", Parameters: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)},
	}
}

func decodeProviderNativeToolArgs(raw json.RawMessage, output any) error {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return errors.New("native provider tool arguments are missing or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errors.New("native provider tool arguments do not match the compiled schema")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("native provider tool arguments contain trailing data")
	}
	return nil
}

func providerNativeToolManifestBinding(opts providerNativeRunOptions) string {
	if !opts.tools {
		return ""
	}
	fields := []string{
		"ntm.zai-native.tool-manifest.v1",
		sha256StringCLI(strings.TrimSpace(opts.worktree)),
		strings.TrimSpace(opts.revision),
		strings.Join(opts.commands, "\x00"),
	}
	return sha256StringCLI(strings.Join(fields, "\x00"))
}
