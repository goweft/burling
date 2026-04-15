// Package report defines the Finding type and severity enum used by
// every burling validation module. All checks produce Findings; the
// CLI aggregates them into a Report and emits either human-readable
// text or JSON for CI consumption.
package report

import (
	"encoding/json"
	"fmt"
)

// Severity classifies the impact of a Finding.
//
// ERROR findings always fail the exit code.
// WARNING findings fail the exit code only when --strict is set.
// INFO findings are never fatal.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityError
)

// String returns the uppercase label used in conformance matrix output.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityError:
		return "ERROR"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(s))
	}
}

// MarshalJSON encodes Severity as its string label so JSON output is
// stable across releases even if iota ordering changes.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// Finding is a single conformance check result. Every check in the
// conformance matrix produces zero or more Findings. A successful check
// produces no Finding.
type Finding struct {
	// CheckID is the matrix identifier, e.g. "ID-01", "SA-03".
	CheckID string `json:"check_id"`
	// SpecRef is the AIP draft section the check enforces, e.g. "§3.3".
	SpecRef string `json:"spec_ref"`
	// Severity is the classification (ERROR/WARNING/INFO).
	Severity Severity `json:"severity"`
	// Message is a human-readable description of the failure.
	Message string `json:"message"`
	// Context is optional structured detail (claim values, hashes, etc.).
	Context map[string]any `json:"context,omitempty"`
}

// Report is the aggregate result of running all requested checks against
// a single token or identity document.
//
// Report is the stable JSON schema consumed by CI integrations; changes
// to field names are breaking and require a CHANGELOG entry.
type Report struct {
	// Target is the input identifier (path, URL, or synthetic name).
	Target string `json:"target"`
	// BurlingVersion is the version of the validator that produced the report.
	BurlingVersion string `json:"burling_version"`
	// SpecVersion is the AIP draft identifier the checks were derived from.
	SpecVersion string `json:"spec_version"`
	// Findings is the ordered list of check failures. Empty means pass.
	Findings []Finding `json:"findings"`
}

// HasErrors reports whether any finding is of ERROR severity.
func (r *Report) HasErrors() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityError {
			return true
		}
	}
	return false
}

// HasWarnings reports whether any finding is of WARNING severity.
func (r *Report) HasWarnings() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityWarning {
			return true
		}
	}
	return false
}

// ExitCode returns the process exit code for the report. If strict is
// true, WARNING findings also fail (exit 1). ERROR always fails.
func (r *Report) ExitCode(strict bool) int {
	if r.HasErrors() {
		return 1
	}
	if strict && r.HasWarnings() {
		return 1
	}
	return 0
}
