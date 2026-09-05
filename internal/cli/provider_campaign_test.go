package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

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
