package cli

import (
	"fmt"
	"os"
	"testing"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/tests/testutil"
)

const (
	// These fixtures accept input like a TUI. Expose both supported composers
	// so production delivery guards can observe readiness without being bypassed.
	testAgentCatCommandTemplate    = `{{if .Model}}: {{shellQuote .Model}} >/dev/null && {{end}}printf '\n› \n❯ \n'; /bin/cat`
	testAgentBinCatCommandTemplate = testAgentCatCommandTemplate
)

func newTmuxIntegrationTestConfig(projectsBase string) *config.Config {
	testCfg := config.Default()
	testCfg.ProjectsBase = projectsBase

	// Generic tmux integration tests should stay focused on pane/session behavior
	// instead of shelling out to optional memory and coordination helpers.
	testCfg.AgentMail.Enabled = false
	testCfg.CASS.Context.Enabled = false
	testCfg.SessionRecovery.Enabled = false
	testCfg.SessionRecovery.AutoInjectOnSpawn = false
	testCfg.SessionRecovery.IncludeAgentMail = false
	testCfg.SessionRecovery.IncludeBeadsContext = false
	testCfg.SessionRecovery.IncludeCMMemories = false
	testCfg.GeminiSetup.AutoSelectProModel = false

	return testCfg
}

func TestMain(m *testing.M) {
	if os.Getenv("NTM_PROVIDER_BROKER_TEST_HELPER") == "1" {
		root := &cobra.Command{Use: "ntm", SilenceErrors: true, SilenceUsage: true}
		providerCmd := &cobra.Command{Use: "provider"}
		providerCmd.AddCommand(newProviderBrokerCmd())
		root.AddCommand(providerCmd)
		root.SetArgs(os.Args[1:])
		root.SetIn(os.Stdin)
		root.SetOut(os.Stdout)
		root.SetErr(os.Stderr)
		if err := root.Execute(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	cleanupTmux, err := testutil.IsolateTmuxTestProcess()
	if err != nil {
		fmt.Fprintf(os.Stderr, "isolate CLI tmux tests: %v\n", err)
		os.Exit(1)
	}

	// CLI tests exercise git-touching paths (hooks install via `ntm init`,
	// worktrees, ...); never let them read or write the developer's real git
	// configuration (#225).
	cleanupGit, err := testutil.IsolateGitConfigProcess()
	if err != nil {
		fmt.Fprintf(os.Stderr, "isolate CLI git config: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	if err := cleanupGit(); err != nil {
		fmt.Fprintf(os.Stderr, "clean up isolated CLI git config: %v\n", err)
		code = 1
	}
	if err := cleanupTmux(); err != nil {
		fmt.Fprintf(os.Stderr, "clean up isolated CLI tmux: %v\n", err)
		code = 1
	}

	os.Exit(code)
}
