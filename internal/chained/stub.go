// Package chained is a v0.1 stub for AIP §3.2 chained-mode (Biscuit)
// IBCT validation.
//
// Checks CH-01..CH-05 are deferred to v0.2 pending the Biscuit
// vendor-vs-implement decision. Validate emits a single INFO finding
// so the CLI dispatch layer can call into this package without
// special-casing — stubs look like real modules to the outside.
package chained

import (
	"context"

	"github.com/goweft/burling/internal/report"
)

// DeferredMessage is the INFO message emitted by this stub. Exported
// so the CLI can grep for it when rendering "module not implemented"
// sections, and so the test here and any future integration test can
// assert on the same string.
const DeferredMessage = "chained-mode validation deferred to v0.2"

// Validate returns a report containing a single INFO finding noting
// that this module is not yet implemented. The ctx argument is
// accepted for signature symmetry with real validation packages and
// is otherwise unused.
func Validate(_ context.Context) *report.Report {
	return &report.Report{
		Findings: []report.Finding{{
			CheckID:  "CH-00",
			SpecRef:  "§3.2",
			Severity: report.SeverityInfo,
			Message:  DeferredMessage,
			Context:  map[string]any{"checks_deferred": []string{"CH-01", "CH-02", "CH-03", "CH-04", "CH-05"}},
		}},
	}
}
