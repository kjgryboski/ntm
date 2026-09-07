// Command provider-scan-review checks source-bound dispositions against a new
// complete finding inventory. It never rewrites source or scanner reports.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type finding struct {
	Severity, Rule, File, Line, SHA, Disposition, Reason string
}
type result struct {
	InventoryScope   string   `json:"inventory_scope"`
	ReviewMatched    bool     `json:"review_matched"`
	RawScannerPassed bool     `json:"raw_scanner_passed"`
	Findings         int      `json:"findings"`
	Matched          int      `json:"matched"`
	Problems         []string `json:"problems"`
}

// Normalize the complete machine report, not a manually transcribed subset.
// UBS summaries and capped text samples cannot prove extraction completeness
// and deliberately fail closed. This supports ast-grep's raw JSON array only.
func normalizeRaw(root string, raw []byte) ([]finding, error) {
	var records []struct {
		Rule     string `json:"ruleId"`
		Severity string `json:"severity"`
		File     string `json:"file"`
		Range    struct {
			Start struct {
				Line *int `json:"line"`
			} `json:"start"`
		} `json:"range"`
	}
	if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '[' || json.Unmarshal(raw, &records) != nil {
		return nil, errors.New("complete ast-grep JSON report required; summary or sampled text cannot grant review completeness")
	}
	out := make([]finding, 0, len(records))
	for _, r := range records {
		if r.Rule == "" || r.Severity == "" || r.File == "" || r.Range.Start.Line == nil || *r.Range.Start.Line < 0 {
			return nil, errors.New("raw finding missing required producer fields")
		}
		path := r.File
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, path)
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(root, resolved)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, errors.New("raw finding outside source root")
		}
		b, err := os.ReadFile(resolved)
		if err != nil {
			return nil, err
		}
		out = append(out, finding{Severity: r.Severity, Rule: r.Rule, File: filepath.ToSlash(rel), Line: strconv.Itoa(*r.Range.Start.Line + 1), SHA: digest(b)})
	}
	return out, nil
}

func sameInventory(a, b []finding) bool {
	if len(a) != len(b) {
		return false
	}
	counts := map[string]int{}
	for _, f := range a {
		counts[key(f)]++
	}
	for _, f := range b {
		k := key(f)
		if counts[k] <= 0 {
			return false
		}
		counts[k]--
	}
	return true
}

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func readPinned(path, pin string) ([]byte, error) {
	if len(pin) != 64 {
		return nil, errors.New("exact SHA-256 pin required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if digest(b) != pin {
		return nil, errors.New("artifact digest mismatch")
	}
	return b, nil
}
func inventory(data []byte) ([]finding, error) {
	r := csv.NewReader(strings.NewReader(string(data)))
	r.FieldsPerRecord = 7
	header, err := r.Read()
	if err != nil {
		return nil, err
	}
	if strings.Join(header, ",") != "severity,rule,file,line,source_sha256,disposition,reason" {
		return nil, errors.New("unexpected inventory schema")
	}
	out := []finding{}
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		line, e := strconv.Atoi(row[3])
		if e != nil || line < 1 || row[0] == "" || row[1] == "" || row[2] == "" || len(row[4]) != 64 {
			return nil, errors.New("malformed finding")
		}
		out = append(out, finding{row[0], row[1], row[2], row[3], row[4], row[5], row[6]})
	}
	return out, nil
}
func key(f finding) string {
	return strings.Join([]string{f.Severity, f.Rule, f.File, f.Line, f.SHA}, "\x00")
}
func check(root string, reviewed, current []finding) result {
	out := result{InventoryScope: "complete_raw_ast_grep_report_only", Findings: len(current), Problems: []string{}}
	if len(current) == 0 {
		out.Problems = append(out.Problems, "empty_inventory_requires_raw_scanner_review")
	}
	counts := map[string]int{}
	for _, f := range reviewed {
		if (f.Disposition != "false_positive" && f.Disposition != "reviewed_information") || strings.TrimSpace(f.Reason) == "" {
			out.Problems = append(out.Problems, "invalid_review:"+f.File+":"+f.Line)
			continue
		}
		counts[key(f)]++
	}
	cache := map[string]string{}
	for _, f := range current {
		// Resolve symlinks before the containment check; a path inside the tree
		// must not read a target outside it. Inputs are project-relative only.
		clean := filepath.Clean(f.File)
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			out.Problems = append(out.Problems, "unsafe_path:"+f.File)
			continue
		}
		actual, ok := cache[f.File]
		if !ok {
			resolved, err := filepath.EvalSymlinks(filepath.Join(root, clean))
			if err != nil {
				out.Problems = append(out.Problems, "missing_source:"+f.File)
				continue
			}
			rel, err := filepath.Rel(root, resolved)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				out.Problems = append(out.Problems, "outside_source_root:"+f.File)
				continue
			}
			b, err := os.ReadFile(resolved)
			if err != nil {
				out.Problems = append(out.Problems, "unreadable_source:"+f.File)
				continue
			}
			actual = digest(b)
			cache[f.File] = actual
		}
		if actual != f.SHA {
			out.Problems = append(out.Problems, "changed_source:"+f.File+":"+f.Line)
			continue
		}
		k := key(f)
		if counts[k] <= 0 {
			out.Problems = append(out.Problems, "new_or_changed_finding:"+f.File+":"+f.Line+":"+f.Rule)
			continue
		}
		counts[k]--
		out.Matched++
	}
	out.ReviewMatched = len(out.Problems) == 0
	return out
}
func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("provider-scan-review", flag.ContinueOnError)
	root := fs.String("root", "", "Exact source root")
	review := fs.String("review", "", "Reviewed CSV inventory")
	reviewSHA := fs.String("review-sha256", "", "Pinned review digest")
	current := fs.String("findings", "", "Complete current CSV finding inventory")
	currentSHA := fs.String("findings-sha256", "", "Pinned current inventory digest")
	raw := fs.String("raw", "", "Retained raw scanner report")
	rawSHA := fs.String("raw-sha256", "", "Pinned raw report digest")
	normalize := fs.Bool("normalize", false, "Emit all raw ast-grep findings as CSV; no review verdict")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || !filepath.IsAbs(*root) {
		return errors.New("absolute source root and no positional arguments required")
	}
	resolved, err := filepath.EvalSymlinks(*root)
	if err != nil {
		return err
	}
	rawBytes, err := readPinned(*raw, *rawSHA)
	if err != nil {
		return fmt.Errorf("raw report: %w", err)
	}
	findings, err := normalizeRaw(resolved, rawBytes)
	if err != nil {
		return err
	}
	if *normalize {
		w := csv.NewWriter(stdout)
		if err = w.Write([]string{"severity", "rule", "file", "line", "source_sha256", "disposition", "reason"}); err != nil {
			return err
		}
		for _, f := range findings {
			if err = w.Write([]string{f.Severity, f.Rule, f.File, f.Line, f.SHA, "", ""}); err != nil {
				return err
			}
		}
		w.Flush()
		return w.Error()
	}
	b, err := readPinned(*review, *reviewSHA)
	if err != nil {
		return err
	}
	reviewed, err := inventory(b)
	if err != nil {
		return err
	}
	if *current != "" {
		b, err = readPinned(*current, *currentSHA)
		if err != nil {
			return err
		}
		supplied, err := inventory(b)
		if err != nil {
			return err
		}
		if !sameInventory(supplied, findings) {
			return errors.New("supplied inventory omits, duplicates, or changes raw scanner findings")
		}
	}
	out := check(resolved, reviewed, findings)
	if err = json.NewEncoder(stdout).Encode(out); err != nil {
		return err
	}
	if !out.ReviewMatched {
		return errors.New("review requires attention; raw report preserved")
	}
	return nil
}
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
