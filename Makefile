.PHONY: test-fixtures test-fixtures-all

test-fixtures:
	python3 scripts/run_fixture_checks.py --strict-tools

test-fixtures-all:
	python3 scripts/run_fixture_checks.py --strict-tools --engine semgrep --engine gitleaks --engine osv
