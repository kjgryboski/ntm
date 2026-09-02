package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsBridgeConfigPathIgnoresInheritedConfigOverrides(t *testing.T) {
	t.Setenv("NTM_CONFIG", "/attacker/config.toml")
	t.Setenv("XDG_CONFIG_HOME", "/attacker/xdg")
	if got, want := windowsBridgeConfigPath(filepath.Join(string(filepath.Separator), "owner")), filepath.Join(string(filepath.Separator), "owner", ".config", "ntm", "config.toml"); got != want {
		t.Fatalf("path=%q want=%q env=%q", got, want, os.Getenv("NTM_CONFIG"))
	}
}
