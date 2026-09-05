package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProviderScanReviewRejectsNewFindingsChangedSourceAndSummaryOnly(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "fixture.go")
	if err := os.WriteFile(source, []byte("package fixture\nfunc run(){ panic(1) }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`[{"ruleId":"panic","file":"fixture.go","severity":"warning","text":"panic(1)","range":{"start":{"line":1}}}]`)
	original, err := providerScanFindings(raw, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(providerNewScanFindings(original, original)) != 0 {
		t.Fatal("stable scan changed")
	}
	duplicate := append(append([]providerScanFinding{}, original...), original...)
	if len(providerNewScanFindings(original, duplicate)) != 1 {
		t.Fatal("duplicate new occurrence hidden")
	}
	if err := os.WriteFile(source, []byte("package fixture\nfunc run(){ panic(1) }; var changed = true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := providerScanFindings(raw, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(providerNewScanFindings(original, changed)) != 1 {
		t.Fatal("changed source retained stale review")
	}
	for _, invalid := range [][]byte{[]byte(`{"critical":0}`), []byte(`null`), []byte(` `), []byte(`[{"ruleId":"panic","file":"../outside.go","severity":"warning","text":"panic(1)"}]`)} {
		if _, err := providerScanFindings(invalid, root); err == nil {
			t.Fatal("invalid scan accepted")
		}
	}
	input := filepath.Join(root, "scan.json")
	if err := os.WriteFile(input, raw, 0600); err != nil {
		t.Fatal(err)
	}
	baseline := filepath.Join(root, "baseline.json")
	args := []string{"--input", input, "--root", root, "--scanner-sha256", strings.Repeat("a", 64), "--rules-sha256", strings.Repeat("b", 64)}
	cmd := newProviderScanReviewCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs(append(append([]string{}, args...), "--write-baseline", baseline))
	if cmd.Execute() == nil {
		t.Fatal("unreviewed baseline created")
	}
	cmd = newProviderScanReviewCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs(append(append([]string{}, args...), "--write-baseline", baseline, "--reviewed-input-sha256", sha256TextCLI(raw)))
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var stored providerScanBaseline
	data, _ := os.ReadFile(baseline)
	if json.Unmarshal(data, &stored) != nil || len(stored.Findings) != 1 {
		t.Fatal("review not bound")
	}
	cmd = newProviderScanReviewCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs(append(append([]string{}, args...), "--baseline", baseline))
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}
