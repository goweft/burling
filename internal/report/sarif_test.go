package report

import (
	"encoding/json"
	"testing"
)

// sarifDecode renders r to SARIF and unmarshals it into a generic map so
// tests can assert on structure without exporting the SARIF types.
func sarifDecode(t *testing.T, r *Report) map[string]any {
	t.Helper()
	b, err := r.SARIF()
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v\n%s", err, b)
	}
	return m
}

func firstRun(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	runs, ok := m["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected exactly 1 run; got %v", m["runs"])
	}
	return runs[0].(map[string]any)
}

func TestSARIF_TopLevelShape(t *testing.T) {
	r := &Report{
		Target:         "token.jwt",
		BurlingVersion: "1.2.3",
		SpecVersion:    "draft-prakash-aip-00",
		Findings: []Finding{
			{CheckID: "CM-02", SpecRef: "§3.1", Severity: SeverityError, Message: `expected typ "aip+jwt"`},
		},
	}
	m := sarifDecode(t, r)
	if m["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", m["version"])
	}
	if _, ok := m["$schema"]; !ok {
		t.Error("missing $schema")
	}
	driver := firstRun(t, m)["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "burling" {
		t.Errorf("driver.name = %v, want burling", driver["name"])
	}
	if driver["version"] != "1.2.3" {
		t.Errorf("driver.version = %v, want 1.2.3", driver["version"])
	}
	if driver["informationUri"] != "https://github.com/goweft/burling" {
		t.Errorf("driver.informationUri = %v", driver["informationUri"])
	}
}

func TestSARIF_ResultPerFinding_LevelMapping(t *testing.T) {
	r := &Report{
		Target: "t.jwt",
		Findings: []Finding{
			{CheckID: "CM-02", SpecRef: "§3.1", Severity: SeverityError, Message: "e"},
			{CheckID: "CM-08", SpecRef: "§3.1", Severity: SeverityWarning, Message: "w"},
			{CheckID: "CH-00", SpecRef: "§3.2", Severity: SeverityInfo, Message: "i"},
		},
	}
	results := firstRun(t, sarifDecode(t, r))["results"].([]any)
	if len(results) != 3 {
		t.Fatalf("want 3 results, got %d", len(results))
	}
	want := map[string]string{"CM-02": "error", "CM-08": "warning", "CH-00": "note"}
	for _, ri := range results {
		res := ri.(map[string]any)
		id := res["ruleId"].(string)
		if res["level"] != want[id] {
			t.Errorf("%s level = %v, want %v", id, res["level"], want[id])
		}
	}
}

func TestSARIF_RulesDedupedAndMostSevereLevel(t *testing.T) {
	// CM-03 appears INFO then ERROR: rules dedupe to one entry, and the
	// rule's default level takes the most severe (error).
	r := &Report{
		Target: "t.jwt",
		Findings: []Finding{
			{CheckID: "CM-03", SpecRef: "§3.1", Severity: SeverityInfo, Message: "no resolver"},
			{CheckID: "CM-03", SpecRef: "§3.1", Severity: SeverityError, Message: "kid missing"},
		},
	}
	m := sarifDecode(t, r)
	run := firstRun(t, m)
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("expected 1 deduped rule, got %d", len(rules))
	}
	cfg := rules[0].(map[string]any)["defaultConfiguration"].(map[string]any)
	if cfg["level"] != "error" {
		t.Errorf("rule default level = %v, want error", cfg["level"])
	}
	if got := len(run["results"].([]any)); got != 2 {
		t.Errorf("want 2 results, got %d", got)
	}
}

func TestSARIF_LocationFromTarget(t *testing.T) {
	r := &Report{Target: "path/to/token.jwt", Findings: []Finding{
		{CheckID: "CM-02", SpecRef: "§3.1", Severity: SeverityError, Message: "e"},
	}}
	res := firstRun(t, sarifDecode(t, r))["results"].([]any)[0].(map[string]any)
	loc := res["locations"].([]any)[0].(map[string]any)
	art := loc["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)
	if art["uri"] != "path/to/token.jwt" {
		t.Errorf("artifact uri = %v", art["uri"])
	}
}

func TestSARIF_NoTarget_OmitsLocation(t *testing.T) {
	r := &Report{Findings: []Finding{
		{CheckID: "CM-02", Severity: SeverityError, Message: "e"},
	}}
	res := firstRun(t, sarifDecode(t, r))["results"].([]any)[0].(map[string]any)
	if _, ok := res["locations"]; ok {
		t.Error("expected no locations when Target is empty")
	}
}

func TestSARIF_HelpURIFromSpecRef(t *testing.T) {
	r := &Report{Target: "t", Findings: []Finding{
		{CheckID: "ID-06", SpecRef: "§2.3", Severity: SeverityError, Message: "e"},
		{CheckID: "X-00", SpecRef: "", Severity: SeverityInfo, Message: "i"},
	}}
	rules := firstRun(t, sarifDecode(t, r))["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	byID := map[string]map[string]any{}
	for _, ru := range rules {
		rr := ru.(map[string]any)
		byID[rr["id"].(string)] = rr
	}
	if got := byID["ID-06"]["helpUri"]; got != "https://www.ietf.org/archive/id/draft-prakash-aip-00.html#section-2.3" {
		t.Errorf("ID-06 helpUri = %v", got)
	}
	if got := byID["X-00"]["helpUri"]; got != "https://github.com/goweft/burling" {
		t.Errorf("empty-specRef helpUri = %v, want repo fallback", got)
	}
}

func TestSARIF_EmptyReport_HasEmptyArrays(t *testing.T) {
	r := &Report{Target: "t.jwt", BurlingVersion: "1.0.0"}
	run := firstRun(t, sarifDecode(t, r))
	if got := len(run["results"].([]any)); got != 0 {
		t.Errorf("want empty results, got %d", got)
	}
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	if len(rules) != 0 {
		t.Errorf("want empty rules, got %d", len(rules))
	}
}

func TestSARIF_SpecVersionInRunProperties(t *testing.T) {
	r := &Report{Target: "t", SpecVersion: "draft-prakash-aip-00", Findings: []Finding{
		{CheckID: "CM-02", SpecRef: "§3.1", Severity: SeverityError, Message: "e"},
	}}
	props, ok := firstRun(t, sarifDecode(t, r))["properties"].(map[string]any)
	if !ok {
		t.Fatal("expected run.properties")
	}
	if props["specVersion"] != "draft-prakash-aip-00" {
		t.Errorf("specVersion = %v", props["specVersion"])
	}
}
