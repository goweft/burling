package depth

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
	if r.Findings[0].Severity != report.SeverityInfo {
		t.Errorf("severity = %v, want INFO", r.Findings[0].Severity)
	}
	if got := r.Findings[0].SpecRef; got != "§5.1" {
		t.Errorf("SpecRef = %q, want §5.1", got)
	}
	if r.HasErrors() {
		t.Error("stub should not produce errors")
	}
}
