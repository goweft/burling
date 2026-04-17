// Package delegation is a v0.1 stub for AIP §3.5 delegation-context
// checks (DC-01..DC-04: delegation_reason, on_behalf_of, budget
// coherence). Deferred to v0.2 — these fields live on chain blocks,
// meaningful only once chained mode is supported.
//
// Directory was formerly internal/context. Renamed to avoid stdlib
// package-name collision; see commit history.
package delegation

import (
	"context"

	"github.com/goweft/burling/internal/report"
)

const DeferredMessage = "delegation-context validation deferred to v0.2 (depends on chained mode)"

func Validate(_ context.Context) *report.Report {
	return &report.Report{
		Findings: []report.Finding{{
			CheckID:  "DC-00",
			SpecRef:  "§3.5",
			Severity: report.SeverityInfo,
			Message:  DeferredMessage,
			Context:  map[string]any{"checks_deferred": []string{"DC-01", "DC-02", "DC-03", "DC-04"}},
		}},
	}
}
