// Package scope is a v0.1 stub for AIP §3.3 scope attenuation checks.
//
// Checks SA-01..SA-06 (scope attenuation across tool, resource,
// action, and temporal dimensions, plus transitivity) are deferred
// to v0.2. Scope attenuation is the highest-priority security
// property of the protocol and its implementation is gated on
// chained-mode support landing first — attenuation is meaningful
// only across a chain of blocks.
package scope

import (
	"context"

	"github.com/goweft/burling/internal/report"
)

const DeferredMessage = "scope-attenuation validation deferred to v0.2 (depends on chained mode)"

func Validate(_ context.Context) *report.Report {
	return &report.Report{
		Findings: []report.Finding{{
			CheckID:  "SA-00",
			SpecRef:  "§3.3",
			Severity: report.SeverityInfo,
			Message:  DeferredMessage,
			Context:  map[string]any{"checks_deferred": []string{"SA-01", "SA-02", "SA-03", "SA-04", "SA-05", "SA-06"}},
		}},
	}
}
