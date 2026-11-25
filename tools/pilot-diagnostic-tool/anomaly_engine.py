import re
from datetime import datetime, timedelta
import yaml
import os
import sys


def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller."""
    try:
        base_path = sys._MEIPASS
        return os.path.join(base_path, "src", relative_path)
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


# Load anomaly detection rules from a YAML file
try:
    with open(resource_path("anomaly_rules.yaml"), "r") as f:
        anomaly_rules = yaml.safe_load(f)
except FileNotFoundError:
    print("Anomaly rules file not found. Using default rules.")
    anomaly_rules = {
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


def _analyze_memory_trend(memory_readings):
    """Post-analysis for memory trend."""
    if len(memory_readings) < 10:
        return None

    memory_readings.sort(key=lambda r: r["timestamp"])

    first_reading = memory_readings[0]
    last_reading = memory_readings[-1]

    duration_hours = (last_reading["timestamp"] - first_reading["timestamp"]).total_seconds() / 3600
    usage_increase = last_reading["usage_mb"] - first_reading["usage_mb"]

    if duration_hours > 1 and usage_increase > 100:
        return {
            "message": f"Potential memory leak detected. Usage increased by {usage_increase:.2f} MB over {duration_hours:.2f} hours.",
            "start_usage": first_reading["usage_mb"],
            "end_usage": last_reading["usage_mb"],
        }
    return None


def _find_error_patterns(sorted_entries):
    """Identify sequences of consecutive critical errors."""
    from collections import defaultdict
    import itertools

    error_patterns = []
    critical_levels = {"ERROR", "CRITICAL", "EXCEP"}

    sequences = []
    for is_critical, group in itertools.groupby(
        sorted_entries, key=lambda e: e.get("level", "").upper() in critical_levels
    ):
        if is_critical:
            sequence = list(group)
            if len(sequence) > 1:
                sequences.append(sequence)

    if not sequences:
        return error_patterns

    pattern_counts = defaultdict(list)
    for seq in sequences:
        pattern_parts = []
        for e in seq:
            component = e.get("component", "N/A")
            message = str(e.get("message", ""))
            if ")" in message:
                simple_message = message.split(")")[0] + ")"
            else:
                simple_message = (message[:72] + "...") if len(message) > 75 else message
            pattern_parts.append(f"{component}: {simple_message}")
        pattern_signature = " -> ".join(pattern_parts)
        pattern_counts[pattern_signature].append(seq[0]["timestamp"])

    for signature, timestamps in pattern_counts.items():
        if len(timestamps) > 1:
            error_patterns.append({
                "message": f"Repeated {len(timestamps)} times: {signature.replace('->', ' -> ')}",
                "timestamp": timestamps[0],
            })

    return error_patterns


def _perform_entry_analysis(entry, last_timestamp, analysis, memory_readings):
    """Analyzes a single log entry."""
    level = str(entry.get("level", "")).strip().upper()
    message = str(entry.get("message", ""))
    component = entry.get("component", "unknown")
    timestamp = entry.get("timestamp")

    memory_pattern = re.compile(r"mem(ory)?(?: usage)?:?\s*(\d+\.?\d*)\s*(mb|gb|kb)", re.IGNORECASE)
    mem_match = memory_pattern.search(message)
    if mem_match and timestamp:
        value = float(mem_match.group(2))
        unit = mem_match.group(3).lower()
        if unit == "gb":
            value *= 1024
        elif unit == "kb":
            value /= 1024
        memory_readings.append({"timestamp": timestamp, "usage_mb": value})

    for issue_type, rules in anomaly_rules.items():
        for rule in rules:
            keyword = rule["keyword"].lower() if rule["keyword"] else None
            component_filter = rule["component"]
            if keyword and keyword in message.lower() and (not component_filter or component_filter == component):
                analysis[issue_type].append({
                    "message": entry.get("message", ""),
                    "timestamp": timestamp,
                    "component": component,
                })

    time_gap_threshold = timedelta(seconds=10)
    if last_timestamp and timestamp and (timestamp - last_timestamp) > time_gap_threshold:
        analysis["time_gaps"].append({
            "start": last_timestamp,
            "end": timestamp,
            "duration": f"{(timestamp - last_timestamp).total_seconds():.2f} seconds",
        })

    if component not in analysis["component_issues"]:
        analysis["component_issues"][component] = {"errors": 0, "warnings": 0, "criticals": 0, "total": 0}
    if level == "ERROR":
        analysis["component_issues"][component]["errors"] += 1
    elif level == "WARNING":
        analysis["component_issues"][component]["warnings"] += 1
    elif level in ["CRITICAL", "EXCEP"]:
        analysis["component_issues"][component]["criticals"] += 1
    analysis["component_issues"][component]["total"] += 1


def analyze_log_anomalies(entries):
    """Analyzes a list of log entries for patterns and anomalies."""
    analysis = {
        "hardware_issues": [],
        "game_state_issues": [],
        "io_event_issues": [],
        "system_issues": [],
        "memory_issues": [],
        "network_issues": [],
        "time_gaps": [],
        "component_issues": {},
        "error_patterns": [],
    }

    sorted_entries = sorted(
        [e for e in entries if isinstance(e.get("timestamp"), datetime)],
        key=lambda x: x["timestamp"],
    )

    if not sorted_entries:
        return analysis

    last_timestamp = None
    memory_readings = []

    for entry in sorted_entries:
        try:
            _perform_entry_analysis(entry, last_timestamp, analysis, memory_readings)
            last_timestamp = entry.get("timestamp")
        except Exception as e:
            print(f"[Anomaly Engine] Skipped malformed entry: {entry} | Error: {e}")
            continue

    analysis["error_patterns"] = _find_error_patterns(sorted_entries)
    memory_issue = _analyze_memory_trend(memory_readings)
    if memory_issue:
        analysis["memory_issues"].append(memory_issue)

    return analysis
