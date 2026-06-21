package report

import (
	"bytes"
	"encoding/json"
	"strings"
)

// SARIF 2.1.0 output, for upload to GitHub code scanning via
// github/codeql-action/upload-sarif. The shape is deliberately minimal:
// a single run whose driver advertises one rule per distinct check ID
// present in the report, plus one result per finding. Severities map to
// SARIF levels (ERROR->error, WARNING->warning, INFO->note), and the
// report Target becomes each result's artifact location so alerts attach
// to the validated file in the pull-request view.
//
// The types below are unexported; callers use (*Report).SARIF, which
// returns indented JSON bytes. Building from the Report alone keeps this
// package a leaf — it needs no knowledge of the 45-check matrix beyond
// what each Finding already carries (CheckID, SpecRef, Severity).

const (
	sarifVersion   = "2.1.0"
	sarifSchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"
	toolInfoURI    = "https://github.com/goweft/burling"
	draftHTMLBase  = "https://www.ietf.org/archive/id/draft-prakash-aip-00.html"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string       `json:"id"`
	Name                 string       `json:"name,omitempty"`
	HelpURI              string       `json:"helpUri,omitempty"`
	DefaultConfiguration *sarifConfig `json:"defaultConfiguration,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// SARIF renders the report as SARIF 2.1.0 (indented JSON, newline
// terminated). A report with no findings yields empty rules/results
// arrays, which code scanning reads as "no alerts" and uses to clear any
// prior ones.
func (r *Report) SARIF() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r.toSARIF()); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (r *Report) toSARIF() sarifLog {
	// First-seen order keeps rule output deterministic. The same check ID
	// can appear with mixed severities in one run (e.g. CM-03 emits INFO
	// when no resolver is configured but ERROR when a kid is missing); the
	// rule's defaultConfiguration takes the most severe level seen, while
	// every result carries its own exact level.
	order := make([]string, 0)
	maxSev := make(map[string]Severity)
	specRef := make(map[string]string)
	results := make([]sarifResult, 0, len(r.Findings))

	for _, f := range r.Findings {
		if _, ok := maxSev[f.CheckID]; !ok {
			order = append(order, f.CheckID)
			maxSev[f.CheckID] = f.Severity
			specRef[f.CheckID] = f.SpecRef
		} else if f.Severity > maxSev[f.CheckID] {
			maxSev[f.CheckID] = f.Severity
		}

		res := sarifResult{
			RuleID:  f.CheckID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Message},
		}
		if r.Target != "" {
			res.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: r.Target},
					Region:           &sarifRegion{StartLine: 1},
				},
			}}
		}
		props := make(map[string]any)
		if f.SpecRef != "" {
			props["specRef"] = f.SpecRef
		}
		if len(f.Context) > 0 {
			props["context"] = f.Context
		}
		if len(props) > 0 {
			res.Properties = props
		}
		results = append(results, res)
	}

	rules := make([]sarifRule, 0, len(order))
	for _, id := range order {
		rules = append(rules, sarifRule{
			ID:                   id,
			Name:                 id,
			HelpURI:              specRefToHelpURI(specRef[id]),
			DefaultConfiguration: &sarifConfig{Level: sarifLevel(maxSev[id])},
		})
	}

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "burling",
			InformationURI: toolInfoURI,
			Version:        r.BurlingVersion,
			Rules:          rules,
		}},
		Results: results,
	}
	if r.SpecVersion != "" {
		run.Properties = map[string]any{"specVersion": r.SpecVersion}
	}

	return sarifLog{
		Schema:  sarifSchemaURI,
		Version: sarifVersion,
		Runs:    []sarifRun{run},
	}
}

// sarifLevel maps a burling Severity to a SARIF result level. SARIF
// defines error, warning, note, and none; burling uses the first three.
func sarifLevel(s Severity) string {
	switch s {
	case SeverityError:
		return "error"
	case SeverityWarning:
		return "warning"
	default:
		return "note"
	}
}

// specRefToHelpURI turns a SpecRef like "§3.1" into a deep link to that
// section of the published draft. A ref that isn't a bare section number
// (empty, or anything unexpected) falls back to the repository URL.
func specRefToHelpURI(specRef string) string {
	s := strings.TrimSpace(specRef)
	s = strings.TrimPrefix(s, "§")
	if s == "" {
		return toolInfoURI
	}
	for _, c := range s {
		if (c < '0' || c > '9') && c != '.' {
			return toolInfoURI
		}
	}
	return draftHTMLBase + "#section-" + s
}
