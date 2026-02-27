package model

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type Action string

const (
	ActionBlock  Action = "block"
	ActionWarn   Action = "warn"
	ActionIgnore Action = "ignore"
)

type Location struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

type Evidence struct {
	Snippet string `json:"snippet,omitempty"`
	Source  string `json:"source,omitempty"`
	Sink    string `json:"sink,omitempty"`
}

type Finding struct {
	ID          string     `json:"id"`
	RuleID      string     `json:"rule_id"`
	Engine      string     `json:"engine"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	CWE         string     `json:"cwe,omitempty"`
	Message     string     `json:"message"`
	FixHint     string     `json:"fix_hint,omitempty"`
	Location    Location   `json:"location"`
	Evidence    Evidence   `json:"evidence,omitempty"`
	Fingerprint string     `json:"fingerprint"`
	Tags        []string   `json:"tags,omitempty"`
}

type ScanError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Engine  string `json:"engine,omitempty"`
}

type ScanSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type ScanTarget struct {
	RepoRoot string   `json:"repo_root"`
	Mode     string   `json:"mode"`
	Paths    []string `json:"paths,omitempty"`
}

type ScanResult struct {
	SchemaVersion string      `json:"schema_version"`
	ScanID        string      `json:"scan_id"`
	ToolVersion   string      `json:"tool_version"`
	StartedAt     string      `json:"started_at,omitempty"`
	FinishedAt    string      `json:"finished_at,omitempty"`
	Target        ScanTarget  `json:"target"`
	Summary       ScanSummary `json:"summary"`
	Findings      []Finding   `json:"findings"`
	Errors        []ScanError `json:"errors"`

	BlockedCount int `json:"-"`
	WarningCount int `json:"-"`
}

func NewScanID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "scan-unknown"
	}
	return "scan-" + hex.EncodeToString(buf)
}

var wsPattern = regexp.MustCompile(`\s+`)

func Fingerprint(ruleID, file string, line int, snippet string) string {
	normalizedSnippet := wsPattern.ReplaceAllString(strings.TrimSpace(snippet), " ")
	if len(normalizedSnippet) > 240 {
		normalizedSnippet = normalizedSnippet[:240]
	}
	raw := fmt.Sprintf("%s|%s|%d|%s", ruleID, file, line, normalizedSnippet)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func FindingID(fingerprint string) string {
	if len(fingerprint) < 16 {
		return "finding-" + fingerprint
	}
	return "finding-" + fingerprint[:16]
}

func NormalizeSeverity(raw string) Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return SeverityCritical
	case "high", "error":
		return SeverityHigh
	case "medium", "warning", "warn":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func NormalizeConfidence(raw string) Confidence {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "high":
		return ConfidenceHigh
	case "low":
		return ConfidenceLow
	default:
		return ConfidenceMedium
	}
}
