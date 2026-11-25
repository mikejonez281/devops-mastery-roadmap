#!/usr/bin/env python3
"""
Automated Build Log Parser
Parses CI/CD build logs to extract warnings, errors, and execution metrics.
"""

import argparse
import json
import re
import sys
from pathlib import Path

# Regex patterns to detect log levels and build metadata
PATTERNS = {
    "error": re.compile(r"\[(ERROR|FATAL|CRITICAL)\]\s*(.*)", re.IGNORECASE),
    "warning": re.compile(r"\[(WARN|WARNING)\]\s*(.*)", re.IGNORECASE),
    "duration": re.compile(r"Total (?:build )?duration:\s*([0-9.]+s?)", re.IGNORECASE),
}


def parse_log_file(file_path: Path) -> dict:
    """Reads a log file and extracts warnings, errors, and metrics."""
    if not file_path.exists():
        raise FileNotFoundError(f"Log file not found at: {file_path}")

    summary = {
        "file": str(file_path),
        "status": "SUCCESS",
        "duration": "unknown",
        "error_count": 0,
        "warning_count": 0,
        "errors": [],
        "warnings": [],
    }

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, start=1):
            line_str = line.strip()

            # Check for errors
            error_match = PATTERNS["error"].search(line_str)
            if error_match:
                level, msg = error_match.groups()
                summary["errors"].append(
                    {"line": line_num, "level": level.upper(), "message": msg}
                )
                continue

            # Check for warnings
            warn_match = PATTERNS["warning"].search(line_str)
            if warn_match:
                level, msg = warn_match.groups()
                summary["warnings"].append(
                    {"line": line_num, "level": level.upper(), "message": msg}
                )
                continue

            # Check for duration
            duration_match = PATTERNS["duration"].search(line_str)
            if duration_match:
                summary["duration"] = duration_match.group(1)

    summary["error_count"] = len(summary["errors"])
    summary["warning_count"] = len(summary["warnings"])

    if summary["error_count"] > 0:
        summary["status"] = "FAILED"

    return summary


def main():
    parser = argparse.ArgumentParser(
        description="Parse CI/CD build logs and extract errors, warnings, and summary metrics."
    )
    parser.add_argument(
        "--file", "-f", required=True, type=Path, help="Path to raw build log file"
    )
    parser.add_argument(
        "--output", "-o", type=Path, default=None, help="Path to write JSON summary"
    )

    args = parser.parse_args()

    try:
        report = parse_log_file(args.file)
    except FileNotFoundError as err:
        print(f"[!] Error: {err}", file=sys.stderr)
        sys.exit(2)

    # Pretty-print summary to console
    print("\n" + "=" * 50)
    print(f" BUILD LOG ANALYSIS: {report['status']}")
    print("=" * 50)
    print(f" File Analyzed:    {report['file']}")
    print(f" Build Duration:   {report['duration']}")
    print(f" Errors Found:     {report['error_count']}")
    print(f" Warnings Found:   {report['warning_count']}")

    if report["errors"]:
        print("\n--- Errors ---")
        for err in report["errors"]:
            print(f"  [Line {err['line']}] [{err['level']}] {err['message']}")

    if report["warnings"]:
        print("\n--- Warnings ---")
        for w in report["warnings"]:
            print(f"  [Line {w['line']}] [{w['level']}] {w['message']}")

    print("=" * 50 + "\n")

    # Save to JSON file if requested
    if args.output:
        with open(args.output, "w", encoding="utf-8") as out:
            json.dump(report, out, indent=2)
        print(f"[+] Report exported to: {args.output}")

    # Return exit code 1 if build had errors (standard CI/CD fail behavior)
    sys.exit(1 if report["status"] == "FAILED" else 0)


if __name__ == "__main__":
    main()
