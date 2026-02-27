package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/V3idt/lattice-cli/internal/model"
)

func Render(result model.ScanResult, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		return renderJSON(result)
	case "sarif":
		return renderSARIF(result)
	case "table", "":
		return renderTable(result)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

func renderJSON(result model.ScanResult) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func renderTable(result model.ScanResult) error {
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ENGINE\tSEVERITY\tACTION\tRULE\tLOCATION\tMESSAGE")
	for _, finding := range result.Findings {
		action := extractActionTag(finding.Tags)
		location := fmt.Sprintf("%s:%d:%d", finding.Location.File, finding.Location.Line, finding.Location.Column)
		_, _ = fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\t%s\n",
			finding.Engine,
			finding.Severity,
			action,
			finding.RuleID,
			location,
			truncate(finding.Message, 120),
		)
	}
	if err := w.Flush(); err != nil {
		return err
	}

	_, _ = fmt.Fprintln(os.Stdout)
	_, _ = fmt.Fprintf(
		os.Stdout,
		"Summary: total=%d critical=%d high=%d medium=%d low=%d info=%d blocked=%d warnings=%d errors=%d\n",
		result.Summary.Total,
		result.Summary.Critical,
		result.Summary.High,
		result.Summary.Medium,
		result.Summary.Low,
		result.Summary.Info,
		result.BlockedCount,
		result.WarningCount,
		len(result.Errors),
	)
	return nil
}

type sarifRoot struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string                  `json:"id"`
	Name             string                  `json:"name,omitempty"`
	ShortDescription sarifMultiformatMessage `json:"shortDescription,omitempty"`
	Properties       map[string]string       `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string                  `json:"ruleId"`
	Level     string                  `json:"level"`
	Message   sarifMultiformatMessage `json:"message"`
	Locations []sarifLocation         `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

type sarifMultiformatMessage struct {
	Text string `json:"text"`
}

func renderSARIF(result model.ScanResult) error {
	rulesByID := map[string]sarifRule{}
	sarifResults := make([]sarifResult, 0, len(result.Findings))

	for _, finding := range result.Findings {
		if _, ok := rulesByID[finding.RuleID]; !ok {
			rulesByID[finding.RuleID] = sarifRule{
				ID:   finding.RuleID,
				Name: finding.RuleID,
				ShortDescription: sarifMultiformatMessage{
					Text: finding.Message,
				},
				Properties: map[string]string{
					"engine":     finding.Engine,
					"severity":   string(finding.Severity),
					"confidence": string(finding.Confidence),
				},
			}
		}

		sarifResults = append(sarifResults, sarifResult{
			RuleID:  finding.RuleID,
			Level:   sarifLevel(finding.Severity),
			Message: sarifMultiformatMessage{Text: finding.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: finding.Location.File},
					Region:           sarifRegion{StartLine: finding.Location.Line, StartColumn: finding.Location.Column},
				},
			}},
		})
	}

	rules := make([]sarifRule, 0, len(rulesByID))
	for _, rule := range rulesByID {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	doc := sarifRoot{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "lattice-cli", Version: result.ToolVersion, Rules: rules}},
			Results: sarifResults,
		}},
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifLevel(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func extractActionTag(tags []string) string {
	for _, tag := range tags {
		if strings.HasPrefix(tag, "action:") {
			return strings.TrimPrefix(tag, "action:")
		}
	}
	return "warn"
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	if limit < 4 {
		return value[:limit]
	}
	return value[:limit-3] + "..."
}
