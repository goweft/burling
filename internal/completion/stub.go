// Package completion is a v0.1 stub for AIP §3.6 completion-block
// checks (CB-01..CB-04). Deferred to v0.2 — completion blocks are
// appended to chains, meaningful only once chained mode is supported.
package completion

import (
	"context"

	"github.com/goweft/burling/internal/report"
)

const DeferredMessage = "completion-block validation deferred to v0.2 (depends on chained mode)"

func Validate(_ context.Context) *report.Report {
	return &report.Report{
		Findings: []report.Finding{{
			CheckID:  "CB-00",
			SpecRef:  "§3.6",
			Severity: report.SeverityInfo,
			Message:  DeferredMessage,
			Context:  map[string]any{"checks_deferred": []string{"CB-01", "CB-02", "CB-03", "CB-04"}},
		}},
	}
}
