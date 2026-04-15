package report

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSeverityString(t *testing.T) {
	tests := []struct {
		name string
		s    Severity
		want string
	}{
		{"info", SeverityInfo, "INFO"},
		{"warning", SeverityWarning, "WARNING"},
		{"error", SeverityError, "ERROR"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.String(); got != tc.want {
				t.Errorf("Severity.String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSeverityMarshalJSON(t *testing.T) {
	f := Finding{CheckID: "SA-01", Severity: SeverityError, Message: "oops"}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"severity":"ERROR"`) {
		t.Errorf("expected severity as string label, got: %s", b)
	}
}

func TestReportHasErrors(t *testing.T) {
	r := &Report{Findings: []Finding{
		{Severity: SeverityWarning},
		{Severity: SeverityError},
	}}
	if !r.HasErrors() {
		t.Error("HasErrors() = false, want true")
	}
	if !r.HasWarnings() {
		t.Error("HasWarnings() = false, want true")
	}
}

func TestReportExitCode(t *testing.T) {
	tests := []struct {
		name   string
		finds  []Finding
		strict bool
		want   int
	}{
		{"clean", nil, false, 0},
		{"clean strict", nil, true, 0},
		{"warn non-strict", []Finding{{Severity: SeverityWarning}}, false, 0},
		{"warn strict", []Finding{{Severity: SeverityWarning}}, true, 1},
		{"error non-strict", []Finding{{Severity: SeverityError}}, false, 1},
		{"error strict", []Finding{{Severity: SeverityError}}, true, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &Report{Findings: tc.finds}
			if got := r.ExitCode(tc.strict); got != tc.want {
				t.Errorf("ExitCode(%v) = %d, want %d", tc.strict, got, tc.want)
			}
		})
	}
}
