.PHONY: test-fixtures test-fixtures-all test build scan-json

test-fixtures:
	python3 scripts/run_fixture_checks.py --strict-tools

test-fixtures-all:
	python3 scripts/run_fixture_checks.py --strict-tools --engine semgrep --engine gitleaks --engine osv

test:
	go test ./...

build:
	go build -o ./bin/lattice ./cmd/lattice

scan-json:
	go run ./cmd/lattice scan --path . --engine all --format json
