package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

type providerScanFinding struct {
	Rule         string `json:"rule"`
	File         string `json:"file"`
	Severity     string `json:"severity"`
	Line         int    `json:"line"`
	SourceSHA256 string `json:"source_sha256"`
	MatchSHA256  string `json:"match_sha256"`
}

type providerScanBaseline struct {
	Schema              string                `json:"schema_version"`
	ScannerSHA256       string                `json:"scanner_sha256"`
	RulesSHA256         string                `json:"rules_sha256"`
	ReviewedInputSHA256 string                `json:"reviewed_input_sha256"`
	Findings            []providerScanFinding `json:"findings"`
}

// This baseline reports changes in reviewed findings. It never changes scanner
// severity or suppresses its raw output. A source edit invalidates that file's
// dispositions, even when a rule still matches the same text and line.
func newProviderScanReviewCmd() *cobra.Command {
	var input, root, baselinePath, writePath, reviewed, scanner, rules string
	cmd := &cobra.Command{Use: "scan-review", Short: "Compare complete AST findings against an explicitly reviewed, source-bound baseline", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&input, "input", "", "Complete ast-grep JSON array from a successful scan")
	cmd.Flags().StringVar(&root, "root", "", "Absolute scanned source root")
	cmd.Flags().StringVar(&baselinePath, "baseline", "", "Previously reviewed baseline to compare")
	cmd.Flags().StringVar(&writePath, "write-baseline", "", "New baseline path; requires explicit review digest")
	cmd.Flags().StringVar(&reviewed, "reviewed-input-sha256", "", "SHA-256 of the exact scan whose findings were individually reviewed")
	cmd.Flags().StringVar(&scanner, "scanner-sha256", "", "Exact scanner executable digest")
	cmd.Flags().StringVar(&rules, "rules-sha256", "", "Exact rulepack manifest digest")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if !filepath.IsAbs(root) || !validProviderNativeDigest(scanner) || !validProviderNativeDigest(rules) || (baselinePath == "") == (writePath == "") {
			return errors.New("scan review requires an absolute root, scanner/rule digests, and exactly one baseline action")
		}
		data, err := readProviderScanInput(input)
		if err != nil {
			return err
		}
		findings, err := providerScanFindings(data, root)
		if err != nil {
			return err
		}
		current := providerScanBaseline{Schema: "ntm.provider-scan-review.v1", ScannerSHA256: scanner, RulesSHA256: rules, ReviewedInputSHA256: sha256TextCLI(data), Findings: findings}
		if writePath != "" {
			if reviewed != current.ReviewedInputSHA256 {
				return errors.New("baseline creation requires the exact individually reviewed scan digest")
			}
			f, err := os.OpenFile(writePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			writeErr := encodeIndentedJSON(f, current)
			closeErr := f.Close()
			if err = errors.Join(writeErr, closeErr); err != nil {
				return err
			}
			return encodeIndentedJSON(cmd.OutOrStdout(), map[string]any{"baseline_written": true, "reviewed_findings": len(findings), "scanner_severity_changed": false})
		}
		previousData, err := readProviderScanInput(baselinePath)
		if err != nil {
			return err
		}
		var previous providerScanBaseline
		if json.Unmarshal(previousData, &previous) != nil || previous.Schema != current.Schema || previous.ScannerSHA256 != scanner || previous.RulesSHA256 != rules || !validProviderNativeDigest(previous.ReviewedInputSHA256) {
			return errors.New("baseline schema, scanner, rulepack or review binding differs")
		}
		added := providerNewScanFindings(previous.Findings, findings)
		if err = encodeIndentedJSON(cmd.OutOrStdout(), map[string]any{"new_findings": added, "current_findings": len(findings), "passed": len(added) == 0, "scanner_severity_changed": false}); err != nil {
			return err
		}
		if len(added) > 0 {
			return errors.New("new or changed-source scanner findings require individual review")
		}
		return nil
	}
	return cmd
}

func readProviderScanInput(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 2 || info.Size() > 32<<20 {
		return nil, errors.New("scan input must be a bounded regular JSON file")
	}
	return os.ReadFile(path)
}

func providerScanFindings(data []byte, root string) ([]providerScanFinding, error) {
	var matches []struct {
		Rule     string `json:"ruleId"`
		File     string `json:"file"`
		Severity string `json:"severity"`
		Text     string `json:"text"`
		Range    struct {
			Start struct {
				Line int `json:"line"`
			} `json:"start"`
		} `json:"range"`
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed[0] != '[' || json.Unmarshal(data, &matches) != nil {
		return nil, errors.New("complete AST JSON array required; summary-only or failed scan is not a baseline")
	}
	findings := make([]providerScanFinding, 0, len(matches))
	for _, m := range matches {
		path := m.File
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || m.Rule == "" || m.Text == "" || m.Severity == "" || m.Range.Start.Line < 0 {
			return nil, errors.New("finding is outside the scanned root or lacks exact rule/location evidence")
		}
		actual, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, err
		}
		actualRelative, err := filepath.Rel(root, actual)
		if err != nil || actualRelative == ".." || strings.HasPrefix(actualRelative, ".."+string(filepath.Separator)) {
			return nil, errors.New("finding source escapes root through a symlink")
		}
		info, err := os.Stat(actual)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 8<<20 {
			return nil, errors.New("finding source must be a bounded regular file")
		}
		source, err := os.ReadFile(actual)
		if err != nil {
			return nil, err
		}
		if !strings.Contains(string(source), m.Text) {
			return nil, fmt.Errorf("finding source changed since scan: %s", relative)
		}
		findings = append(findings, providerScanFinding{Rule: m.Rule, File: filepath.ToSlash(relative), Severity: m.Severity, Line: m.Range.Start.Line + 1, SourceSHA256: sha256TextCLI(source), MatchSHA256: sha256StringCLI(m.Text)})
	}
	return findings, nil
}

func providerNewScanFindings(previous, current []providerScanFinding) []providerScanFinding {
	counts := map[providerScanFinding]int{}
	for _, finding := range previous {
		counts[finding]++
	}
	added := []providerScanFinding{}
	for _, finding := range current {
		if counts[finding] > 0 {
			counts[finding]--
		} else {
			added = append(added, finding)
		}
	}
	return added
}
