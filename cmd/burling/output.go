package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/goweft/burling/internal/report"
)

// render writes r to stdout in the requested format and returns the
// appropriate exit code.
//
// Format dispatch:
//   - json: r.MarshalIndent output, newline terminated.
//   - text: a section per severity (ERROR/WARNING/INFO), one finding
//     per line within each section, followed by a summary.
//
// Unknown formats produce a usage error on stderr and exit 2.
func render(stdout, stderr *os.File, r *report.Report, cf *commonFlags) int {
	switch cf.format {
	case "json":
		if err := renderJSON(stdout, r); err != nil {
			fmt.Fprintf(stderr, "burling: render json: %v\n", err)
			return 2
		}
	case "text", "":
		renderText(stdout, r)
	default:
		fmt.Fprintf(stderr, "burling: unknown --format %q (want text or json)\n", cf.format)
		return 2
	}
	return r.ExitCode(cf.strict)
}

func renderJSON(w *os.File, r *report.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// renderText emits a deliberately plain, grep-friendly format:
//
//	ERROR   [ID-06] §2.3  document_signature did not verify ...
//	WARNING [CM-08] §3.1  ttl 2h exceeds standard cap of 1h
//	INFO    [CH-00] §3.2  chained-mode validation deferred to v0.2
//	
//	Summary: 1 ERROR, 1 WARNING, 1 INFO — FAIL
//
// Findings are sorted by severity (ERROR first, then WARNING, then
// INFO) with original order preserved within a severity. This means
// the most important findings appear first even if the check
// dispatcher ran them later.
func renderText(w *os.File, r *report.Report) {
	// Header
	if r.Target != "" {
		fmt.Fprintf(w, "Target:  %s\n", r.Target)
	}
	if r.SpecVersion != "" {
		fmt.Fprintf(w, "Spec:    %s\n", r.SpecVersion)
	}
	if r.BurlingVersion != "" {
		fmt.Fprintf(w, "burling: %s\n", r.BurlingVersion)
	}
	if r.Target != "" || r.SpecVersion != "" || r.BurlingVersion != "" {
		fmt.Fprintln(w)
	}

	// Sort by severity (ERROR=2 > WARNING=1 > INFO=0, so descending).
	// We make a copy so we don't mutate the caller's slice ordering —
	// JSON callers need the natural order preserved.
	findings := make([]report.Finding, len(r.Findings))
	copy(findings, r.Findings)
	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].Severity > findings[j].Severity
	})

	for _, f := range findings {
		fmt.Fprintf(w, "%-7s [%s] %-5s %s\n",
			f.Severity.String(),
			f.CheckID,
			f.SpecRef,
			f.Message,
		)
	}

	if len(findings) == 0 {
		fmt.Fprintln(w, "No findings — all checks passed.")
		return
	}

	// Summary line.
	var errs, warns, infos int
	for _, f := range findings {
		switch f.Severity {
		case report.SeverityError:
			errs++
		case report.SeverityWarning:
			warns++
		case report.SeverityInfo:
			infos++
		}
	}
	var parts []string
	if errs > 0 {
		parts = append(parts, fmt.Sprintf("%d ERROR", errs))
	}
	if warns > 0 {
		parts = append(parts, fmt.Sprintf("%d WARNING", warns))
	}
	if infos > 0 {
		parts = append(parts, fmt.Sprintf("%d INFO", infos))
	}
	verdict := "PASS"
	if errs > 0 {
		verdict = "FAIL"
	}
	fmt.Fprintf(w, "\nSummary: %s — %s\n", strings.Join(parts, ", "), verdict)
}
