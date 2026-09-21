"""Command-line entry point for the crypto misuse scanner."""

import argparse
import json
import sys
from pathlib import Path

from .scanner import scan_path

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        prog="crypto-misuse-scan",
        description="Static scanner for common cryptographic misuse patterns in Python code.",
    )
    parser.add_argument("target", help="Python file or directory to scan")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON")
    parser.add_argument(
        "--min-severity", choices=["LOW", "MEDIUM", "HIGH"], default="LOW",
        help="Only show findings at or above this severity (default: LOW)",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color in output")
    args = parser.parse_args(argv)

    target = Path(args.target)
    if not target.exists():
        parser.error(f"{target} does not exist")

    findings = [
        f for f in scan_path(target)
        if SEVERITY_ORDER[f.rule.severity] >= SEVERITY_ORDER[args.min_severity]
    ]

    if args.json:
        print(json.dumps(
            [
                {
                    "file": f.file, "line": f.line, "rule_id": f.rule.rule_id,
                    "title": f.rule.title, "severity": f.rule.severity,
                    "detail": f.detail, "remediation": f.rule.remediation,
                }
                for f in findings
            ],
            indent=2,
        ))
    else:
        if not findings:
            print("No issues found.")
        for f in findings:
            print(f.format(use_color=not args.no_color))
        high = sum(1 for f in findings if f.rule.severity == "HIGH")
        med = sum(1 for f in findings if f.rule.severity == "MEDIUM")
        low = sum(1 for f in findings if f.rule.severity == "LOW")
        print(f"Summary: {high} HIGH, {med} MEDIUM, {low} LOW  ({len(findings)} total)")

    sys.exit(1 if any(f.rule.severity == "HIGH" for f in findings) else 0)


if __name__ == "__main__":
    main()
