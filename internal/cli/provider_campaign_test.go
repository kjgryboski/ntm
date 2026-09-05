package cli

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/zai"
	"github.com/spf13/cobra"
)

// Fail when a new direct provider sink appears outside the reviewed managed
// dispatch boundaries. Behavioral tests above also exercise the budget store.
func TestProviderDispatchSourceAudit(t *testing.T) {
	allowed := map[string]map[string]bool{
		"providerqualification.Run":               {"runAccountedLegacyQualification": true},
		"grok.Run":                                {"runBudgetedGrok": true, "runProviderDoctorOnlineProbe": true},
		"grok.ExecuteSession":                     {"runBudgetedGrokSession": true},
		"zai.RunCodexStructured":                  {"runBudgetedCodexStructured": true},
		"zai.RunNative":                           {"runBudgetedNative": true, "runProviderDoctorOnlineProbe": true},
		"zai.RunNativeTools":                      {"runBudgetedNativeTools": true, "nativeQualificationInFlightHTTPCancel": true},
		"zai.Probe":                               {"runProviderDoctorOnlineProbe": true},
		"robot.ExecuteGrokACPOperationAuthorized": {"runProviderAssignment": true},
		"robot.PrintGrokACPOperationAuthorized":   {"root.go:initializer": true},
	}
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range files {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			owner := entry.Name() + ":initializer"
			if function, ok := declaration.(*ast.FuncDecl); ok {
				owner = function.Name.Name
			}
			ast.Inspect(declaration, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := selector.X.(*ast.Ident)
				if !ok {
					return true
				}
				name := pkg.Name + "." + selector.Sel.Name
				if owners, tracked := allowed[name]; tracked && !owners[owner] {
					t.Errorf("unreviewed provider sink %s in %s/%s", name, entry.Name(), owner)
				}
				return true
			})
		}
	}
}

func TestProviderCampaignRejectsUnmanagedPaneRoutes(t *testing.T) {
	prior := providerCampaignID
	defer func() { providerCampaignID = prior }()
	providerCampaignID = "bound-campaign"
	root := &cobra.Command{Use: "ntm"}
	for _, name := range []string{"spawn", "send", "assign", "respawn", "interrupt"} {
		cmd := &cobra.Command{Use: name}
		root.AddCommand(cmd)
		cmd.Flags().String("provider-profile", "", "")
		if validateProviderCampaignRoute(cmd) == nil {
			t.Fatalf("%s raw route accepted", name)
		}
		_ = cmd.Flags().Set("provider-profile", "exact-profile")
		if err := validateProviderCampaignRoute(cmd); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProviderCampaignSurfaceDoesNotResetWithSelectedConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	prior := providerCampaignID
	defer func() { providerCampaignID = prior }()
	cmd := newProviderCampaignCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--id", "parity", "--limit", "1", "--authorization-sha256", strings.Repeat("a", 64)})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	providerCampaignID = "parity"
	if err := reserveProviderExperiment("first", strings.Repeat("a", 64), strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NTM_CONFIG", filepath.Join(t.TempDir(), "other.toml"))
	if err := reserveProviderExperiment("second", strings.Repeat("a", 64), strings.Repeat("b", 64)); err == nil {
		t.Fatal("changing config reset campaign budget")
	}
}

type campaignCountingClient struct{ calls int }

func (c *campaignCountingClient) Do(*http.Request) (*http.Response, error) {
	c.calls++
	return nil, errors.New("offline transport failure")
}

func TestProviderNativeCampaignCountsEveryRoundAndNeverRefunds(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	prior := providerCampaignID
	defer func() { providerCampaignID = prior }()
	providerCampaignID = "native-rounds"
	store, err := openProviderCampaignStore()
	if err != nil {
		t.Fatal(err)
	}
	if err = store.ConfigureProviderCampaign(providerCampaignID, 1, 0, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	store.Close()
	transport := &campaignCountingClient{}
	request := zai.NativeRequest{Endpoint: "https://api.z.ai/api/paas/v4", Model: "fixture", ExpectedRequestID: "bound-operation", Prompt: "fixture"}
	client := budgetedNativeClient(transport, request)
	httpRequest, _ := http.NewRequest("POST", "https://api.z.ai/api/paas/v4/chat/completions", nil)
	_, _ = client.Do(httpRequest)
	_, _ = client.Do(httpRequest)
	// A new wrapper simulates controller restart; the first round cannot replay.
	_, _ = budgetedNativeClient(transport, request).Do(httpRequest)
	if transport.calls != 1 {
		t.Fatalf("transport calls=%d, want 1", transport.calls)
	}
}

func TestProviderDoctorCampaignBlocksBeforeAnyRuntimeOrCredentialAccess(t *testing.T) {
	prior := providerCampaignID
	defer func() { providerCampaignID = prior }()
	providerCampaignID = ""
	id, err := provider.NewIdentity("xai", "fixture", "grok-4.6", "https://api.x.ai", "grok", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	_, err = runProviderDoctorOnlineProbe(context.Background(), config.ProviderProfileConfig{Command: "/must-not-execute"}, id)
	if err == nil || !strings.Contains(err.Error(), "campaign-id") {
		t.Fatalf("unexpected boundary result: %v", err)
	}
}

func TestProviderOpaqueLegacyQualificationNeverStartsRuntime(t *testing.T) {
	out, err := (unaccountedQualificationRunner{}).Run(t.Context(), providerqualification.Invocation{Binary: "/must-not-run"})
	if err == nil || out.ProcessStarted || out.ExitCode != -1 {
		t.Fatal("opaque qualification dispatched without request accounting")
	}
	id, err := provider.NewIdentity("zai", "fixture", "glm-5.3", "https://api.z.ai/api/anthropic", "claude", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	_, err = runProviderDoctorOnlineProbe(t.Context(), config.ProviderProfileConfig{Command: "/must-not-run"}, id)
	if err == nil || !strings.Contains(err.Error(), "request accounting") {
		t.Fatal("opaque doctor bypassed structured admission")
	}
}

func TestProviderProductionDependenciesUseBudgetedDispatch(t *testing.T) {
	for name, functions := range map[string][2]any{
		"opaque-qualification": {providerQualificationDeps.run, runAccountedLegacyQualification},
		"session":              {providerSessionDeps.run, runBudgetedGrokSession},
		"grok-qualification":   {providerGrokQualificationDeps.run, runBudgetedGrok},
		"native":               {providerNativeRunDeps.run, runBudgetedNative},
		"native-tools":         {providerNativeRunDeps.runTools, runBudgetedNativeTools},
		"native-qualification": {providerNativeQualificationDeps.runTools, runBudgetedNativeTools},
		"codex":                {providerCodexRunDeps.run, runBudgetedCodexStructured},
	} {
		a := runtime.FuncForPC(reflect.ValueOf(functions[0]).Pointer()).Name()
		b := runtime.FuncForPC(reflect.ValueOf(functions[1]).Pointer()).Name()
		if a != b {
			t.Fatalf("%s bypasses budget: %s", name, a)
		}
	}
}
