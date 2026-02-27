package main

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestScanJSONSmoke(t *testing.T) {
	if _, err := exec.LookPath("semgrep"); err != nil {
		t.Skip("semgrep not installed")
	}
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not installed")
	}

	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	binaryPath := filepath.Join(t.TempDir(), "lattice")
	buildCmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/lattice")
	buildCmd.Dir = repoRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build lattice binary: %v\noutput: %s", err, string(out))
	}

	cmd := exec.Command(
		binaryPath,
		"scan",
		"--path",
		"test/fixtures",
		"--engine",
		"all",
		"--format",
		"json",
	)
	cmd.Dir = repoRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit code 1 is expected because fixtures contain block-level findings.
			if exitErr.ExitCode() != 1 {
				t.Fatalf("scan command failed unexpectedly: %v\noutput: %s", err, string(output))
			}
		} else {
			t.Fatalf("scan command failed: %v", err)
		}
	}

	var payload map[string]any
	if err := json.Unmarshal(output, &payload); err != nil {
		t.Fatalf("invalid json output: %v\noutput: %s", err, string(output))
	}

	required := []string{"schema_version", "scan_id", "tool_version", "target", "summary", "findings", "errors"}
	for _, key := range required {
		if _, ok := payload[key]; !ok {
			t.Fatalf("missing required key %q in output", key)
		}
	}
}
