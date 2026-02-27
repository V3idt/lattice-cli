package scan

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/V3idt/lattice-cli/internal/engines"
	"github.com/V3idt/lattice-cli/internal/model"
	"github.com/V3idt/lattice-cli/internal/policy"
)

const ToolVersion = "0.1.0"

type Options struct {
	Path         string
	Format       string
	Engine       string
	Diff         bool
	PolicyPath   string
	SemgrepRules string
}

func Run(opts Options) (model.ScanResult, int, error) {
	if opts.Diff {
		return model.ScanResult{}, 2, fmt.Errorf("--diff is not implemented yet")
	}

	repoRoot, err := filepath.Abs(strings.TrimSpace(opts.Path))
	if err != nil {
		return model.ScanResult{}, 2, fmt.Errorf("resolve scan path: %w", err)
	}

	policyConfig, err := policy.Load(opts.PolicyPath)
	if err != nil {
		return model.ScanResult{}, 2, err
	}

	started := time.Now().UTC()
	result := model.ScanResult{
		SchemaVersion: "0.1.0",
		ScanID:        model.NewScanID(),
		ToolVersion:   ToolVersion,
		StartedAt:     started.Format(time.RFC3339),
		Target:        model.ScanTarget{RepoRoot: repoRoot, Mode: "full"},
		Findings:      []model.Finding{},
		Errors:        []model.ScanError{},
	}

	runSemgrep := opts.Engine == "all" || opts.Engine == "semgrep"
	runGitleaks := opts.Engine == "all" || opts.Engine == "gitleaks"
	if !runSemgrep && !runGitleaks {
		return model.ScanResult{}, 2, fmt.Errorf("unsupported engine: %s", opts.Engine)
	}

	if runSemgrep {
		findings, errs := engines.RunSemgrep(repoRoot, opts.SemgrepRules)
		result.Findings = append(result.Findings, findings...)
		result.Errors = append(result.Errors, errs...)
	}

	if runGitleaks {
		findings, errs := engines.RunGitleaks(repoRoot)
		result.Findings = append(result.Findings, findings...)
		result.Errors = append(result.Errors, errs...)
	}

	sort.Slice(result.Findings, func(i, j int) bool {
		if result.Findings[i].Location.File == result.Findings[j].Location.File {
			if result.Findings[i].Location.Line == result.Findings[j].Location.Line {
				return result.Findings[i].RuleID < result.Findings[j].RuleID
			}
			return result.Findings[i].Location.Line < result.Findings[j].Location.Line
		}
		return result.Findings[i].Location.File < result.Findings[j].Location.File
	})

	for i := range result.Findings {
		action := policyConfig.ActionForFinding(result.Findings[i])
		result.Findings[i].Tags = append(result.Findings[i].Tags, "action:"+string(action))
		switch action {
		case model.ActionBlock:
			result.BlockedCount++
		case model.ActionWarn:
			result.WarningCount++
		}
	}

	result.Summary = buildSummary(result.Findings)
	result.FinishedAt = time.Now().UTC().Format(time.RFC3339)

	if len(result.Errors) > 0 {
		return result, 2, nil
	}
	if result.BlockedCount > 0 {
		return result, 1, nil
	}
	return result, 0, nil
}

func buildSummary(findings []model.Finding) model.ScanSummary {
	summary := model.ScanSummary{Total: len(findings)}
	for _, finding := range findings {
		switch finding.Severity {
		case model.SeverityCritical:
			summary.Critical++
		case model.SeverityHigh:
			summary.High++
		case model.SeverityMedium:
			summary.Medium++
		case model.SeverityLow:
			summary.Low++
		default:
			summary.Info++
		}
	}
	return summary
}
