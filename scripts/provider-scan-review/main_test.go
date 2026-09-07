package main

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"testing"
)

func TestReviewRejectsNewChangedAndUnreviewedFindings(t *testing.T) {
	root := t.TempDir()
	source := []byte("package fixture\n")
	if err := os.WriteFile(filepath.Join(root, "fixture.go"), source, 0600); err != nil {
		t.Fatal(err)
	}
	f := finding{"warning", "test.rule", "fixture.go", "1", digest(source), "false_positive", "Reviewed synthetic fixture"}
	if check(root, []finding{f}, nil).ReviewMatched {
		t.Fatal("empty inventory hid findings")
	}
	for _, scenario := range []string{"same", "new-rule", "new-line", "changed-source", "unreviewed", "extra-duplicate", "outside"} {
		t.Run(scenario, func(t *testing.T) {
			review := []finding{f}
			current := []finding{f}
			switch scenario {
			case "new-rule":
				current[0].Rule = "new.rule"
			case "new-line":
				current[0].Line = "2"
			case "changed-source":
				current[0].SHA = digest([]byte("changed"))
			case "unreviewed":
				review[0].Reason = ""
			case "extra-duplicate":
				current = append(current, f)
			case "outside":
				current[0].File = "../fixture.go"
			}
			out := check(root, review, current)
			if out.ReviewMatched != (scenario == "same") || out.RawScannerPassed {
				t.Fatalf("incorrect verdict: %+v", out)
			}
		})
	}
}
func TestCommandPinsRawReportAndReview(t *testing.T) {
	root := t.TempDir()
	source := []byte("package fixture\n")
	if err := os.WriteFile(filepath.Join(root, "fixture.go"), source, 0600); err != nil {
		t.Fatal(err)
	}
	var data bytes.Buffer
	w := csv.NewWriter(&data)
	if err := w.WriteAll([][]string{{"severity", "rule", "file", "line", "source_sha256", "disposition", "reason"}, {"warning", "test.rule", "fixture.go", "1", digest(source), "false_positive", "Reviewed fixture"}}); err != nil {
		t.Fatal(err)
	}
	csvPath, rawPath := filepath.Join(root, "review.csv"), filepath.Join(root, "raw.txt")
	if err := os.WriteFile(csvPath, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	raw := []byte("raw finding, warning\n")
	if err := os.WriteFile(rawPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--root", root, "--review", csvPath, "--review-sha256", digest(data.Bytes()), "--findings", csvPath, "--findings-sha256", digest(data.Bytes()), "--raw", rawPath, "--raw-sha256", digest(raw)}
	var out bytes.Buffer
	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rawPath, []byte("changed report"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(args, &out); err == nil {
		t.Fatal("changed raw report accepted")
	}
}
