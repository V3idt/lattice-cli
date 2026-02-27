package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/V3idt/lattice-cli/internal/output"
	"github.com/V3idt/lattice-cli/internal/scan"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 2
	}

	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "scan":
		return runScan(args[1:])
	case "version":
		fmt.Println(scan.ToolVersion)
		return 0
	case "help", "-h", "--help":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
		printUsage()
		return 2
	}
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	path := fs.String("path", ".", "Path to repository or directory to scan")
	format := fs.String("format", "table", "Output format: table|json|sarif")
	engine := fs.String("engine", "all", "Engine to run: semgrep|gitleaks|all")
	diff := fs.Bool("diff", false, "Scan only changed files (not implemented yet)")
	policyPath := fs.String("policy", "policy.yml", "Path to policy yaml file")
	semgrepRules := fs.String("semgrep-rules", "semgrep-rules/ai-mvp.yml", "Path to Semgrep rules yaml")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	result, exitCode, err := scan.Run(scan.Options{
		Path:         *path,
		Format:       *format,
		Engine:       strings.ToLower(strings.TrimSpace(*engine)),
		Diff:         *diff,
		PolicyPath:   *policyPath,
		SemgrepRules: *semgrepRules,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitCode
	}

	if err := output.Render(result, *format); err != nil {
		fmt.Fprintf(os.Stderr, "render output: %v\n", err)
		return 2
	}
	return exitCode
}

func printUsage() {
	fmt.Print(`lattice-cli v0.1

Usage:
  lattice scan [flags]
  lattice version

Scan flags:
  --path            Path to repository or directory to scan (default: .)
  --format          table|json|sarif (default: table)
  --engine          semgrep|gitleaks|all (default: all)
  --policy          Path to policy yaml (default: policy.yml)
  --semgrep-rules   Path to Semgrep rules yaml (default: semgrep-rules/ai-mvp.yml)
  --diff            Reserved for diff-only scanning (currently not implemented)
`)
}
