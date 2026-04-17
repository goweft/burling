package chained

import (
	"context"
	"testing"

	"github.com/goweft/burling/internal/report"
)

func TestValidate_EmitsSingleInfo(t *testing.T) {
	r := Validate(context.Background())
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(r.Findings), r.Findings)
	}
	f := r.Findings[0]
	if f.Severity != report.SeverityInfo {
		t.Errorf("severity = %v, want INFO", f.Severity)
	}
	if f.Message != DeferredMessage {
		t.Errorf("message = %q, want %q", f.Message, DeferredMessage)
	}
	if r.HasErrors() {
		t.Error("stub should not produce errors")
	}
	if r.ExitCode(true) != 0 {
		t.Error("stub should not fail --strict exit code")
	}
}
