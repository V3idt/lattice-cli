package engines

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/V3idt/lattice-cli/internal/model"
)

type gitleaksFinding struct {
	RuleID      string   `json:"RuleID"`
	Description string   `json:"Description"`
	File        string   `json:"File"`
	StartLine   int      `json:"StartLine"`
	StartColumn int      `json:"StartColumn"`
	Match       string   `json:"Match"`
	Tags        []string `json:"Tags"`
}

func RunGitleaks(repoRoot string) ([]model.Finding, []model.ScanError) {
	if _, err := exec.LookPath("gitleaks"); err != nil {
		return nil, []model.ScanError{{
			Code:    "ENGINE_NOT_INSTALLED",
			Message: "gitleaks binary not found in PATH",
			Engine:  "gitleaks",
		}}
	}

	tmpFile, err := os.CreateTemp("", "lattice-gitleaks-*.json")
	if err != nil {
		return nil, []model.ScanError{{
			Code:    "ENGINE_EXECUTION_FAILED",
			Message: fmt.Sprintf("failed creating temp file: %v", err),
			Engine:  "gitleaks",
		}}
	}
	reportPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(reportPath)

	cmd := exec.Command(
		"gitleaks",
		"detect",
		"--no-git",
		"--source", repoRoot,
		"--report-format", "json",
		"--report-path", reportPath,
		"--redact",
		"--exit-code", "0",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, []model.ScanError{{
			Code:    "ENGINE_EXECUTION_FAILED",
			Message: fmt.Sprintf("failed running gitleaks: %v (%s)", err, strings.TrimSpace(string(out))),
			Engine:  "gitleaks",
		}}
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, []model.ScanError{{
			Code:    "ENGINE_PARSE_FAILED",
			Message: fmt.Sprintf("failed reading gitleaks report: %v", err),
			Engine:  "gitleaks",
		}}
	}

	var parsed []gitleaksFinding
	if len(strings.TrimSpace(string(data))) == 0 {
		parsed = []gitleaksFinding{}
	} else if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, []model.ScanError{{
			Code:    "ENGINE_PARSE_FAILED",
			Message: fmt.Sprintf("failed parsing gitleaks report json: %v", err),
			Engine:  "gitleaks",
		}}
	}

	findings := make([]model.Finding, 0, len(parsed))
	for _, result := range parsed {
		relPath := result.File
		if filepath.IsAbs(relPath) {
			if relative, err := filepath.Rel(repoRoot, relPath); err == nil {
				relPath = relative
			}
		}
		relPath = filepath.Clean(relPath)
		snippet := strings.TrimSpace(result.Match)
		fingerprint := model.Fingerprint(result.RuleID, relPath, max(result.StartLine, 1), snippet)

		message := strings.TrimSpace(result.Description)
		if message == "" {
			message = "Potential hardcoded secret detected"
		}

		finding := model.Finding{
			ID:          model.FindingID(fingerprint),
			RuleID:      strings.TrimSpace(result.RuleID),
			Engine:      "gitleaks",
			Severity:    model.SeverityHigh,
			Confidence:  model.ConfidenceHigh,
			CWE:         "CWE-798",
			Message:     message,
			FixHint:     "Remove hardcoded secret and load from secure secret manager or environment variable.",
			Location:    model.Location{File: relPath, Line: max(result.StartLine, 1), Column: max(result.StartColumn, 1)},
			Evidence:    model.Evidence{Snippet: snippet},
			Fingerprint: fingerprint,
			Tags:        append([]string{}, result.Tags...),
		}
		findings = append(findings, finding)
	}

	return findings, nil
}
