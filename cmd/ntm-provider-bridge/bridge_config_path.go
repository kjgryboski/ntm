package main

import (
	"errors"
	"path/filepath"
	"strings"
)

// windowsBridgeConfigPath derives the owner configuration location without
// consulting NTM_CONFIG or XDG_CONFIG_HOME inherited by a WSL caller.
func windowsBridgeConfigPath(home string) string {
	return filepath.Join(home, ".config", "ntm", "config.toml")
}

// resolvedWindowsBridgeConfigPath rejects a config symlink/reparse point that
// resolves outside the Windows owner's home directory.
func resolvedWindowsBridgeConfigPath(home string) (string, error) {
	resolvedHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		return "", err
	}
	resolvedConfig, err := filepath.EvalSymlinks(windowsBridgeConfigPath(home))
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(resolvedHome, resolvedConfig)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", errors.New("Windows bridge config resolves outside owner home")
	}
	return resolvedConfig, nil
}
