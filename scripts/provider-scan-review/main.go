// Command provider-scan-review checks source-bound dispositions against a new
// complete finding inventory. It never rewrites source or scanner reports.
package main

import (
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
	ReviewMatched    bool     `json:"review_matched"`
	RawScannerPassed bool     `json:"raw_scanner_passed"`
	Findings         int      `json:"findings"`
	Matched          int      `json:"matched"`
	Problems         []string `json:"problems"`
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
	out := result{Findings: len(current), Problems: []string{}}
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
	if _, err = readPinned(*raw, *rawSHA); err != nil {
		return fmt.Errorf("raw report: %w", err)
	}
	b, err := readPinned(*review, *reviewSHA)
	if err != nil {
		return err
	}
	reviewed, err := inventory(b)
	if err != nil {
		return err
	}
	b, err = readPinned(*current, *currentSHA)
	if err != nil {
		return err
	}
	findings, err := inventory(b)
	if err != nil {
		return err
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
