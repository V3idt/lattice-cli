package engines

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/V3idt/lattice-cli/internal/model"
)

type semgrepResult struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
			Col  int `json:"col"`
		} `json:"start"`
		Extra struct {
			Message  string         `json:"message"`
			Severity string         `json:"severity"`
			Metadata map[string]any `json:"metadata"`
			Lines    string         `json:"lines"`
		} `json:"extra"`
	} `json:"results"`
}

func RunSemgrep(repoRoot, rulesPath string) ([]model.Finding, []model.ScanError) {
	if _, err := exec.LookPath("semgrep"); err != nil {
		return nil, []model.ScanError{{
			Code:    "ENGINE_NOT_INSTALLED",
			Message: "semgrep binary not found in PATH",
			Engine:  "semgrep",
		}}
	}

	args := []string{
		"--quiet",
		"--json",
		"--no-git-ignore",
		"--config", rulesPath,
		repoRoot,
	}
	cmd := exec.Command("semgrep", args...)
	cmd.Env = append(os.Environ(), "HOME=/tmp", "XDG_CONFIG_HOME=/tmp")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return nil, []model.ScanError{{
				Code:    "ENGINE_EXECUTION_FAILED",
				Message: fmt.Sprintf("failed running semgrep: %v", err),
				Engine:  "semgrep",
			}}
		}
	}

	var parsed semgrepResult
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, []model.ScanError{{
			Code:    "ENGINE_PARSE_FAILED",
			Message: fmt.Sprintf("failed parsing semgrep json: %v", err),
			Engine:  "semgrep",
		}}
	}

	findings := make([]model.Finding, 0, len(parsed.Results))
	for _, result := range parsed.Results {
		relPath := toRelativePath(repoRoot, result.Path)
		snippet := strings.TrimSpace(result.Extra.Lines)
		if snippet == "requires login" {
			snippet = ""
		}

		severity := model.NormalizeSeverity(result.Extra.Severity)
		confidence := model.ConfidenceMedium
		cwe := ""
		fixHint := ""
		if result.Extra.Metadata != nil {
			confidence = parseConfidence(result.Extra.Metadata["confidence"])
			cwe = parseCWE(result.Extra.Metadata["cwe"])
			if rawFix, ok := result.Extra.Metadata["fix"]; ok {
				fixHint = strings.TrimSpace(fmt.Sprintf("%v", rawFix))
			}
		}

		fingerprint := model.Fingerprint(result.CheckID, relPath, result.Start.Line, snippet)
		finding := model.Finding{
			ID:          model.FindingID(fingerprint),
			RuleID:      result.CheckID,
			Engine:      "semgrep",
			Severity:    severity,
			Confidence:  confidence,
			CWE:         cwe,
			Message:     strings.TrimSpace(result.Extra.Message),
			FixHint:     fixHint,
			Location:    model.Location{File: relPath, Line: max(result.Start.Line, 1), Column: max(result.Start.Col, 1)},
			Evidence:    model.Evidence{Snippet: snippet},
			Fingerprint: fingerprint,
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

func toRelativePath(root, value string) string {
	if value == "" {
		return value
	}
	if !filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	rel, err := filepath.Rel(root, value)
	if err != nil {
		return filepath.Clean(value)
	}
	return filepath.Clean(rel)
}

func parseConfidence(value any) model.Confidence {
	if value == nil {
		return model.ConfidenceMedium
	}
	return model.NormalizeConfidence(fmt.Sprintf("%v", value))
}

func parseCWE(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, strings.TrimSpace(fmt.Sprintf("%v", item)))
		}
		return strings.Join(parts, ",")
	case float64:
		return "CWE-" + strconv.Itoa(int(typed))
	default:
		return ""
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
