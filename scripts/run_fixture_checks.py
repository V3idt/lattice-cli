#!/usr/bin/env python3
"""Starter fixture runner for Semgrep, Gitleaks, and optionally OSV-Scanner."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List, Set


ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = ROOT / "test" / "fixtures"
EXPECTED_DIR = FIXTURES_DIR / "expected"


class CheckFailure(Exception):
    pass


def _load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _to_rel(path_value: str) -> str:
    path = Path(path_value).resolve()
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return path_value


def _ensure_tool(tool: str, strict_tools: bool) -> bool:
    if shutil.which(tool):
        return True
    message = f"SKIP: '{tool}' is not installed."
    if strict_tools:
        raise CheckFailure(message)
    print(message)
    return False


def _run(cmd: List[str], allow_exit_codes: Iterable[int]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if cmd and cmd[0] == "semgrep":
        # Semgrep writes logs in HOME/XDG config dirs. Force writable paths in sandboxed runs.
        env["HOME"] = "/tmp"
        env["XDG_CONFIG_HOME"] = "/tmp"
    result = subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)
    if result.returncode not in set(allow_exit_codes):
        joined = " ".join(cmd)
        raise CheckFailure(
            f"Command failed ({result.returncode}): {joined}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def _extract_vuln_count(payload) -> int:
    if isinstance(payload, dict):
        count = 0
        for key, value in payload.items():
            if key == "vulnerabilities" and isinstance(value, list):
                count += len(value)
            else:
                count += _extract_vuln_count(value)
        return count
    if isinstance(payload, list):
        return sum(_extract_vuln_count(item) for item in payload)
    return 0


def run_semgrep(strict_tools: bool) -> None:
    if not _ensure_tool("semgrep", strict_tools):
        return

    config = ROOT / "semgrep-rules" / "ai-mvp.yml"
    fixture_root = FIXTURES_DIR / "semgrep"
    fixture_files = sorted(str(path) for path in fixture_root.rglob("*.ts"))
    if not fixture_files:
        raise CheckFailure("Semgrep fixtures are missing (*.ts files not found).")

    result = _run(
        [
            "semgrep",
            "--quiet",
            "--json",
            "--config",
            str(config),
            *fixture_files,
        ],
        allow_exit_codes=(0, 1),
    )
    payload = json.loads(result.stdout or "{}")

    found_by_file: Dict[str, Set[str]] = {}
    for finding in payload.get("results", []):
        rel_path = _to_rel(finding.get("path", ""))
        rule_id = finding.get("check_id", "")
        if not rel_path or not rule_id:
            continue
        found_by_file.setdefault(rel_path, set()).add(rule_id)

    vuln_expect = _load_json(EXPECTED_DIR / "semgrep_vuln.json")
    for expected in vuln_expect.get("must_find", []):
        path = expected["path"]
        required = set(expected["rule_ids"])
        actual = found_by_file.get(path, set())
        missing = []
        for required_rule in required:
            if required_rule in actual:
                continue
            if any(found_rule.endswith(f".{required_rule}") for found_rule in actual):
                continue
            missing.append(required_rule)
        if missing:
            raise CheckFailure(f"Semgrep missing expected rules for {path}: {missing}")

    safe_expect = _load_json(EXPECTED_DIR / "semgrep_safe.json")
    for safe_path in safe_expect.get("must_be_clean", []):
        if safe_path in found_by_file and found_by_file[safe_path]:
            raise CheckFailure(
                f"Semgrep produced unexpected findings for safe fixture {safe_path}: "
                f"{sorted(found_by_file[safe_path])}"
            )

    print("PASS: semgrep fixtures")


def run_gitleaks(strict_tools: bool) -> None:
    if not _ensure_tool("gitleaks", strict_tools):
        return

    source = FIXTURES_DIR / "gitleaks"
    with tempfile.NamedTemporaryFile(prefix="gitleaks-report-", suffix=".json", delete=False) as temp:
        report_path = Path(temp.name)

    _run(
        [
            "gitleaks",
            "detect",
            "--no-git",
            "--source",
            str(source),
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--redact",
            "--exit-code",
            "0",
        ],
        allow_exit_codes=(0,),
    )

    leaks_payload = _load_json(report_path) if report_path.exists() else []
    found_files: Set[str] = set()
    for finding in leaks_payload:
        found_files.add(_to_rel(finding.get("File", "")))

    vuln_expect = _load_json(EXPECTED_DIR / "gitleaks_vuln.json")
    required = set(vuln_expect.get("must_find_files", []))
    if not required.issubset(found_files):
        missing = sorted(required - found_files)
        raise CheckFailure(f"Gitleaks missing expected leaked file detections: {missing}")

    safe_expect = _load_json(EXPECTED_DIR / "gitleaks_safe.json")
    for safe_path in safe_expect.get("must_be_clean", []):
        if safe_path in found_files:
            raise CheckFailure(f"Gitleaks flagged safe fixture unexpectedly: {safe_path}")

    print("PASS: gitleaks fixtures")


def run_osv(strict_tools: bool) -> None:
    if not _ensure_tool("osv-scanner", strict_tools):
        return

    vuln_expect = _load_json(EXPECTED_DIR / "osv_vuln.json")
    safe_expect = _load_json(EXPECTED_DIR / "osv_safe.json")
    cases = vuln_expect.get("cases", []) + safe_expect.get("cases", [])

    for case in cases:
        path = ROOT / case["path"]
        result = _run(
            [
                "osv-scanner",
                "--lockfile",
                str(path),
                "--format",
                "json",
            ],
            allow_exit_codes=(0,),
        )
        payload = json.loads(result.stdout or "{}")
        vuln_count = _extract_vuln_count(payload)

        minimum = case.get("min_vulnerabilities")
        maximum = case.get("max_vulnerabilities")
        if minimum is not None and vuln_count < minimum:
            raise CheckFailure(
                f"OSV expected at least {minimum} vulnerabilities in {case['path']}, got {vuln_count}"
            )
        if maximum is not None and vuln_count > maximum:
            raise CheckFailure(
                f"OSV expected at most {maximum} vulnerabilities in {case['path']}, got {vuln_count}"
            )

    print("PASS: osv fixtures")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run scanner fixture checks.")
    parser.add_argument(
        "--engine",
        action="append",
        choices=("semgrep", "gitleaks", "osv"),
        help="Specify engine(s) to run. Defaults to semgrep + gitleaks.",
    )
    parser.add_argument(
        "--strict-tools",
        action="store_true",
        help="Fail if any requested tool is not installed.",
    )
    args = parser.parse_args()

    engines = args.engine or ["semgrep", "gitleaks"]

    runners = {
        "semgrep": run_semgrep,
        "gitleaks": run_gitleaks,
        "osv": run_osv,
    }

    try:
        for engine in engines:
            runners[engine](args.strict_tools)
    except CheckFailure as failure:
        print(f"FAIL: {failure}")
        return 1

    print("PASS: fixture checks complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
