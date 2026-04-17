// Package depth is a v0.1 stub for AIP §3.4 bounded delegation-depth
// checks (BD-01..BD-03). Deferred to v0.2 because depth is a property
// of the full chain; meaningful only once chained mode is supported.
package depth

import (
	"context"

	"github.com/goweft/burling/internal/report"
)

const DeferredMessage = "delegation-depth validation deferred to v0.2 (depends on chained mode)"

func Validate(_ context.Context) *report.Report {
	return &report.Report{
		Findings: []report.Finding{{
			CheckID:  "BD-00",
			SpecRef:  "§3.4",
			Severity: report.SeverityInfo,
			Message:  DeferredMessage,
			Context:  map[string]any{"checks_deferred": []string{"BD-01", "BD-02", "BD-03"}},
		}},
	}
}
