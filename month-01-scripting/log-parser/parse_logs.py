#!/usr/bin/env python3
"""
Production Build & Diagnostics Log Parser
Combines CI/CD build log metrics, multi-format log parsing (Standard, Historical, PIX, SAS, Unity),
and rule-based anomaly detection into a unified CLI tool.
"""

import argparse
from collections import defaultdict
from datetime import datetime, timedelta
import itertools
import json
import os
from pathlib import Path
import re
import sys
import yaml

# ==============================================================================
# 1. LOG REGEX PATTERNS & PROTOCOL DEFINITIONS
# ==============================================================================

LOG_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\|(.*?)\|(.*?)\|(.*)$")
HISTORICAL_LOG_PATTERN = re.compile(r"^(\d{2}/\d{2}/\d{4}) - (\d{2}:\d{2}:\d{2}\.\d{3}) - (.*)$")
PIX_LOG_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s*\[(.*?)\]\s*\[\s*(.*?)\s*\]\s*\[(.*?)\]\s*-\s*(.*)$")
SAS_LOG_PATTERN = re.compile(r"^(?P<direction>IN|OUT)\s*:\s*(?P<hex_data>[\da-fA-F\s]+?)\s+(?P<timestamp>\d+)$")
UNITY_LOG_PATTERN = re.compile(r"^(?P<domain>[\w\._]+)\.(?P<subsystem>[\w_]+)\s*\(\)\s*(?P<message>\(at\s.*)$")
GENERIC_LEVEL_PATTERN = re.compile(r"\[(ERROR|FATAL|CRITICAL|WARN|WARNING|INFO|DEBUG)\]\s*(.*)", re.IGNORECASE)
DURATION_PATTERN = re.compile(r"Total (?:build )?duration:\s*([0-9.]+s?)", re.IGNORECASE)

SAS_COMMANDS = {
    "01": "General Poll",
    "02": "Send Bill Denominations",
    "0E": "Send Game Played",
    "13": "Send Ticket Data",
    "17": "Send Date and Time",
    "1A": "Send Game ID",
    "1B": "Send Denomination",
    "1C": "Send Game Configuration",
    "1F": "Send Gaming Machine ID",
    "2D": "Send Date/Time",
    "2F": "Send Game N Configuration",
    "51": "Send Ticket Status",
    "53": "Send Ticket Validation Data",
    "54": "Send SAS Version, Game Serial",
    "55": "Send Selected Game Number",
    "56": "Send Enabled Game Numbers",
    "72": "Send Ticket In-Progress Data",
    "74": "Send Cash Out Limit",
    "03": "Send Bill Denominations (Extended)",
    "04": "Send Game Start",
    "05": "Send Game End",
    "06": "Send Hand Pay",
    "07": "Send Jackpot",
    "08": "Send Credit Transfer",
    "09": "Send Bonus Pay",
    "0A": "Send Progressive Hit",
    "0B": "Send Meter Change",
    "0C": "Send Event Log",
    "0D": "Send Machine Status",
    "10": "Send Game N Configuration (Extended)",
    "11": "Send Game N Denomination (Extended)",
    "12": "Send Game N ID (Extended)",
    "14": "Send Ticket Data (Extended)",
    "15": "Send Ticket In-Progress Data (Extended)",
}

SAS_EVENTS = {
    "11": "Slot Door Open",
    "12": "Slot Door Closed",
    "13": "Drop Door Open",
    "14": "Drop Door Closed",
    "15": "Card Cage Open",
    "16": "Card Cage Closed",
    "17": "Power Up",
    "18": "Power Down",
    "19": "Cash Door Open",
    "1A": "Cash Door Closed",
    "1B": "Cash Box Removed",
    "1C": "Cash Box Replaced",
    "1D": "Belly Door Open",
    "1E": "Belly Door Closed",
    "20": "General Tilt",
    "21": "Coin In Jam",
    "22": "Hopper Jam",
    "23": "Hopper Empty",
    "27": "Cashbox Full",
    "28": "Bill Jam",
    "29": "Bill Acceptor Fault",
    "2B": "Bill Rejected",
    "31": "CMOS Data Recovered",
    "32": "CMOS Data Not Recovered",
    "33": "CMOS RAM Error",
    "34": "EPROM Data Error",
    "35": "EPROM Bad Device",
    "36": "Version Change",
    "37": "Checksum Mismatch",
    "3A": "Memory Reset by Operator",
    "3B": "Low Battery",
    "3C": "Option Change",
    "3D": "Cash Ticket Printed",
    "41": "Tilt on Reel 1",
    "42": "Tilt on Reel 2",
    "43": "Tilt on Reel 3",
    "44": "Tilt on Reel 4",
    "45": "Tilt on Reel 5",
    "46": "Reel Disconnected",
    "47": "$1 Bill In",
    "48": "$5 Bill In",
    "49": "$10 Bill In",
    "4A": "$20 Bill In",
    "4B": "$50 Bill In",
    "4C": "$100 Bill In",
    "4F": "General Bill Accepted",
    "51": "Hand Pay Request Started",
    "52": "Hand Pay Complete",
    "54": "Progressive Win",
    "60": "Printer Communication Error",
    "61": "Printer Paper Out",
    "66": "Payout Button Pressed",
    "67": "Ticket Inserted",
    "6F": "AFT Locked",
    "70": "Exception Queue Full",
    "74": "Printer Paper Low",
    "75": "Printer Powered Down",
    "76": "Printer Powered Up",
    "7A": "Soft Meters Reset",
    "7E": "Game Start",
    "7F": "Game End",
    "80": "Hopper Full",
    "81": "Hopper Low",
    "84": "Service Menu Entered",
    "85": "Service Menu Exited",
    "86": "Out of Service",
    "8C": "Game Selected",
    "8F": "Game Auth Complete",
    "98": "Power Off Card Cage Access",
    "99": "Power Off Slot Door Access",
    "9A": "Power Off Cashbox Access",
}

DEFAULT_ANOMALY_RULES = {
    "system_issues": [
        {"keyword": "DISABLE REASON: Location not open", "component": None},
        {"keyword": "outofmemory", "component": None},
    ],
    "hardware_issues": [
        {"keyword": "Error", "component": "HARDWARE_CONTROL"},
        {"keyword": "Failure", "component": "HARDWARE_CONTROL"},
    ],
    "game_state_issues": [
        {"keyword": "unexpected state transition", "component": "FSM`2"}
    ],
    "io_event_issues": [
        {"keyword": "error", "component": "IO_EVENT"},
        {"keyword": "failure", "component": "IO_EVENT"},
    ],
    "network_issues": [
        {"keyword": "timeout", "component": None},
        {"keyword": "connection refused", "component": None},
        {"keyword": "status: 5", "component": None},
    ],
}


# ==============================================================================
# 2. LOG ENTRY PARSER
# ==============================================================================

def parse_log_line(line: str, line_num: int = 1) -> dict:
    """Parses a single log line across multiple supported formats."""
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None

    # Format 1: Timestamp | Level | Component | Message
    match = LOG_PATTERN.match(raw)
    if match:
        ts_str, level, component, message = match.groups()
        try:
            timestamp = datetime.strptime(ts_str.strip(), "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            timestamp = ts_str.strip()
        return {
            "line": line_num,
            "timestamp": timestamp,
            "level": level.strip().upper(),
            "component": component.strip(),
            "message": message.strip(),
        }

    # Format 2: Historical (MM/DD/YYYY - HH:MM:SS.mmm)
    match_hist = HISTORICAL_LOG_PATTERN.match(raw)
    if match_hist:
        d_str, t_str, message = match_hist.groups()
        try:
            timestamp = datetime.strptime(f"{d_str} {t_str}", "%m/%d/%Y %H:%M:%S.%f")
        except ValueError:
            timestamp = f"{d_str} {t_str}"
        return {
            "line": line_num,
            "timestamp": timestamp,
            "level": "INFO",
            "component": "System",
            "message": message.strip(),
        }

    # Format 3: PIX Logs
    match_pix = PIX_LOG_PATTERN.match(raw)
    if match_pix:
        ts_str, thread, level, component, message = match_pix.groups()
        try:
            timestamp = datetime.strptime(ts_str.strip(), "%Y-%m-%d %H:%M:%S,%f")
        except ValueError:
            timestamp = ts_str.strip()
        return {
            "line": line_num,
            "timestamp": timestamp,
            "level": level.strip().upper(),
            "component": component.strip(),
            "thread": thread.strip(),
            "message": message.strip(),
        }

    # Format 4: SAS Protocol Hex Logs
    match_sas = SAS_LOG_PATTERN.match(raw)
    if match_sas:
        direction = match_sas.group("direction")
        hex_data = match_sas.group("hex_data").strip()
        parts = hex_data.split()
        cmd = SAS_COMMANDS.get(parts[0].upper(), f"Unknown Cmd: {parts[0]}")
        events = [SAS_EVENTS.get(p.upper()) for p in parts[1:] if p.upper() in SAS_EVENTS]
        msg = hex_data + (f" => [{', '.join(events)}]" if events else "")
        try:
            timestamp = datetime.fromtimestamp(int(match_sas.group("timestamp")) / 1000.0)
        except Exception:
            timestamp = match_sas.group("timestamp")
        return {
            "line": line_num,
            "timestamp": timestamp,
            "level": direction.upper(),
            "component": cmd,
            "message": msg,
        }

    # Format 5: Unity Unstructured Logs
    match_unity = UNITY_LOG_PATTERN.match(raw)
    if match_unity:
        parts = match_unity.groupdict()
        return {
            "line": line_num,
            "timestamp": datetime.min,
            "level": "INFO",
            "component": "Unity",
            "domain": parts.get("domain", ""),
            "subsystem": parts.get("subsystem", ""),
            "message": parts.get("message", ""),
        }

    # Format 6: Standard CI/CD Build Logs (e.g., [ERROR], [WARN])
    match_generic = GENERIC_LEVEL_PATTERN.search(raw)
    if match_generic:
        level, msg = match_generic.groups()
        lvl = level.upper()
        if "WARN" in lvl:
            lvl = "WARNING"
        return {
            "line": line_num,
            "timestamp": datetime.min,
            "level": lvl,
            "component": "BuildSystem",
            "message": msg.strip(),
        }

    # Fallback raw line
    return {
        "line": line_num,
        "timestamp": datetime.min,
        "level": "INFO",
        "component": "Generic",
        "message": raw,
    }


# ==============================================================================
# 3. ANOMALY ENGINE & PATTERN RECOGNITION
# ==============================================================================

def analyze_anomalies(entries: list, rules: dict = None) -> dict:
    """Detects memory leaks, time gaps, repeated error chains, and rule triggers."""
    rules = rules or DEFAULT_ANOMALY_RULES
    analysis = {
        "hardware_issues": [],
        "system_issues": [],
        "game_state_issues": [],
        "io_event_issues": [],
        "network_issues": [],
        "memory_issues": [],
        "time_gaps": [],
        "error_patterns": [],
        "component_breakdown": defaultdict(lambda: {"errors": 0, "warnings": 0, "total": 0}),
    }

    dt_entries = [e for e in entries if isinstance(e.get("timestamp"), datetime) and e.get("timestamp") != datetime.min]
    dt_entries.sort(key=lambda x: x["timestamp"])

    memory_readings = []
    mem_pattern = re.compile(r"mem(ory)?(?: usage)?:?\s*(\d+\.?\d*)\s*(mb|gb|kb)", re.IGNORECASE)

    for entry in entries:
        msg = str(entry.get("message", ""))
        comp = entry.get("component", "Unknown")
        lvl = entry.get("level", "INFO")
        ts = entry.get("timestamp")

        # Track Component Breakdown
        analysis["component_breakdown"][comp]["total"] += 1
        if lvl in ["ERROR", "CRITICAL", "FATAL", "EXCEP"]:
            analysis["component_breakdown"][comp]["errors"] += 1
        elif lvl in ["WARN", "WARNING"]:
            analysis["component_breakdown"][comp]["warnings"] += 1

        # Check YAML Rules
        for category, cat_rules in rules.items():
            for r in cat_rules:
                kw = r.get("keyword")
                filter_comp = r.get("component")
                if kw and kw.lower() in msg.lower() and (not filter_comp or filter_comp == comp):
                    if category in analysis:
                        analysis[category].append({"line": entry.get("line"), "component": comp, "message": msg})

        # Check Memory Leak
        m_match = mem_pattern.search(msg)
        if m_match and isinstance(ts, datetime):
            val = float(m_match.group(2))
            unit = m_match.group(3).lower()
            if unit == "gb":
                val *= 1024
            elif unit == "kb":
                val /= 1024
            memory_readings.append({"timestamp": ts, "usage_mb": val})

    # Time Gap Detection (>10s pause)
    for i in range(1, len(dt_entries)):
        gap = (dt_entries[i]["timestamp"] - dt_entries[i - 1]["timestamp"]).total_seconds()
        if gap > 10.0:
            analysis["time_gaps"].append({
                "start": str(dt_entries[i - 1]["timestamp"]),
                "end": str(dt_entries[i]["timestamp"]),
                "gap_seconds": gap,
            })

    # Memory Trend
    if len(memory_readings) >= 5:
        start_u = memory_readings[0]["usage_mb"]
        end_u = memory_readings[-1]["usage_mb"]
        hours = max(0.01, (memory_readings[-1]["timestamp"] - memory_readings[0]["timestamp"]).total_seconds() / 3600.0)
        increase = end_u - start_u
        if increase > 50 and hours > 0.1:
            analysis["memory_issues"].append({
                "message": f"Memory leak trend detected: +{increase:.2f} MB over {hours:.2f} hours",
                "start_mb": start_u,
                "end_mb": end_u,
            })

    # Error Pattern Chains
    critical_levels = {"ERROR", "FATAL", "CRITICAL", "EXCEP"}
    sequences = []
    for is_crit, group in itertools.groupby(entries, key=lambda e: e.get("level") in critical_levels):
        if is_crit:
            seq = list(group)
            if len(seq) > 1:
                sequences.append(seq)

    pattern_counts = defaultdict(int)
    for seq in sequences:
        sig = " -> ".join([f"{e.get('component')}:{e.get('level')}" for e in seq])
        pattern_counts[sig] += 1

    for sig, count in pattern_counts.items():
        if count > 1:
            analysis["error_patterns"].append(f"Chain occurred {count} times: {sig}")

    analysis["component_breakdown"] = dict(analysis["component_breakdown"])
    return analysis


# ==============================================================================
# 4. MAIN PARSE WORKFLOW & CLI INTERFACE
# ==============================================================================

def parse_log_file(file_path: Path, rules_path: Path = None) -> dict:
    """Complete log parse pipeline."""
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    rules = DEFAULT_ANOMALY_RULES
    if rules_path and rules_path.exists():
        with open(rules_path, "r", encoding="utf-8") as rf:
            rules = yaml.safe_load(rf)

    entries = []
    duration = "unknown"

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for idx, line in enumerate(f, start=1):
            dur_match = DURATION_PATTERN.search(line)
            if dur_match:
                duration = dur_match.group(1)
            parsed = parse_log_line(line, idx)
            if parsed:
                entries.append(parsed)

    errors = [e for e in entries if e.get("level") in ["ERROR", "FATAL", "CRITICAL", "EXCEP"]]
    warnings = [e for e in entries if e.get("level") in ["WARN", "WARNING"]]

    anomalies = analyze_anomalies(entries, rules)

    summary = {
        "file": str(file_path),
        "status": "FAILED" if errors else "SUCCESS",
        "duration": duration,
        "total_lines_analyzed": len(entries),
        "error_count": len(errors),
        "warning_count": len(warnings),
        "errors": [{"line": e["line"], "component": e.get("component"), "message": e["message"]} for e in errors],
        "warnings": [{"line": e["line"], "component": e.get("component"), "message": e["message"]} for e in warnings],
        "anomalies": anomalies,
    }
    return summary


def main():
    parser = argparse.ArgumentParser(
        description="Unified Diagnostics & Build Log Parser (CLI & DevOps Engine)"
    )
    parser.add_argument("--file", "-f", required=True, type=Path, help="Path to raw log file")
    parser.add_argument("--output", "-o", type=Path, default=None, help="Path to output JSON summary")
    parser.add_argument("--rules", "-r", type=Path, default=None, help="Custom anomaly_rules.yaml path")

    args = parser.parse_args()

    # CLI Execution
    try:
        report = parse_log_file(args.file, args.rules)
    except FileNotFoundError as err:
        print(f"[!] Error: {err}", file=sys.stderr)
        sys.exit(2)

    # Print Clean Dashboard Summary
    print("\n" + "=" * 60)
    print(f" LOG ANALYSIS REPORT: {report['status']}")
    print("=" * 60)
    print(f" Target File:         {report['file']}")
    print(f" Total Entries:       {report['total_lines_analyzed']}")
    print(f" Build Duration:      {report['duration']}")
    print(f" Errors:              {report['error_count']}")
    print(f" Warnings:            {report['warning_count']}")

    if report["errors"]:
        print("\n--- Errors ---")
        for err in report["errors"][:10]:
            print(f"  [L{err['line']}] [{err['component']}] {err['message']}")
        if len(report["errors"]) > 10:
            print(f"  ... and {len(report['errors']) - 10} more errors.")

    if report["warnings"]:
        print("\n--- Warnings ---")
        for w in report["warnings"][:5]:
            print(f"  [L{w['line']}] [{w['component']}] {w['message']}")

    anom = report["anomalies"]
    total_anom = len(anom["hardware_issues"]) + len(anom["network_issues"]) + len(anom["system_issues"]) + len(anom["time_gaps"])
    if total_anom > 0:
        print(f"\n--- Detected Anomalies ({total_anom}) ---")
        for k in ["hardware_issues", "network_issues", "system_issues", "memory_issues"]:
            if anom.get(k):
                print(f"  [{k.upper()}] {len(anom[k])} incident(s)")
        if anom.get("time_gaps"):
            print(f"  [TIME GAPS] {len(anom['time_gaps'])} freeze gap(s) > 10s")
        if anom.get("error_patterns"):
            for ep in anom["error_patterns"]:
                print(f"  [PATTERN] {ep}")

    print("=" * 60 + "\n")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as out:
            json.dump(report, out, indent=2, default=str)
        print(f"[+] Full JSON report exported to: {args.output}")

    sys.exit(1 if report["status"] == "FAILED" else 0)


if __name__ == "__main__":
    main()
