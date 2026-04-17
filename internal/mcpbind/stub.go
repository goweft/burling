// Package mcpbind is a v0.1 stub for AIP §4.1 MCP-binding checks
// (MB-01..MB-03). Deferred to v0.2 — these are transport-level
// checks that gate on a real MCP test target, not on chained-mode
// support. Stubbed for symmetry with the other modules so the CLI
// dispatch layer calls every module the same way.
package mcpbind

import (
	"context"

	"github.com/goweft/burling/internal/report"
)

const DeferredMessage = "MCP-binding validation deferred to v0.2 (transport-level, needs MCP test target)"

func Validate(_ context.Context) *report.Report {
	return &report.Report{
		Findings: []report.Finding{{
			CheckID:  "MB-00",
			SpecRef:  "§4.1",
			Severity: report.SeverityInfo,
			Message:  DeferredMessage,
			Context:  map[string]any{"checks_deferred": []string{"MB-01", "MB-02", "MB-03"}},
		}},
	}
}
