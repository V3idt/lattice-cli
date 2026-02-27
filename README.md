# lattice-cli

Security scanning CLI focused on codebases built with AI coding tools.

## Prerequisites

- `go` 1.23+
- `semgrep`
- `gitleaks`

## Quickstart

```bash
go run ./cmd/lattice scan --path . --engine all --format table
```

JSON output for agents:

```bash
go run ./cmd/lattice scan --path . --engine all --format json
```

SARIF output:

```bash
go run ./cmd/lattice scan --path . --engine all --format sarif
```

## Policy

Default policy file is `policy.yml`.

- `block` findings return exit code `1`
- engine/tool errors return exit code `2`
- clean or warn-only scans return `0`

## Exit Codes

- `0`: success (clean or warnings only)
- `1`: policy-blocking findings detected
- `2`: invalid args or engine/tool errors
