import re
import glob
import os
from datetime import datetime
import json

# Correct pattern to match four-field log format: timestamp|level|component|message
LOG_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\|(.*?)\|(.*?)\|(.*)$")
# Historical logs pattern
HISTORICAL_LOG_PATTERN = re.compile(r"^(\d{2}/\d{2}/\d{4}) - (\d{2}:\d{2}:\d{2}\.\d{3}) - (.*)$")
# PIX logs: 2025-10-18 00:00:01,175 [thread] [ INFO] [component] - message
PIX_LOG_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s*\[(.*?)\]\s*\[\s*(.*?)\s*\]\s*\[(.*?)\]\s*-\s*(.*)$")
# SAS logs: IN :01 1a  480783796
SAS_LOG_PATTERN = re.compile(r"^(?P<direction>IN|OUT)\s*:\s*(?P<hex_data>[\da-fA-F\s]+?)\s+(?P<timestamp>\d+)$")

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

UNITY_LOG_PATTERN = re.compile(r"^(?P<domain>[\w\._]+)\.(?P<subsystem>[\w_]+)\s*\(\)\s*(?P<message>\(at\s.*)$")


def parse_log_line(line):
    """Parses a single log line into a dictionary."""
    if line.strip().startswith("#"):
        return None

    match = LOG_PATTERN.match(line)
    if match:
        try:
            timestamp_str, level, component, message = match.groups()
            timestamp = datetime.strptime(timestamp_str.strip(), "%Y-%m-%d %H:%M:%S.%f")
            try:
                if message.strip().startswith("{"):
                    message_data = json.loads(message.strip())
                else:
                    message_data = message.strip()
            except json.JSONDecodeError:
                message_data = message.strip()

            return {
                "timestamp": timestamp,
                "level": level.strip(),
                "component": component.strip(),
                "message": message_data,
            }
        except Exception as e:
            return {"error": f"Failed to parse line: {e}", "original_line": line}

    match_historical = HISTORICAL_LOG_PATTERN.match(line)
    if match_historical:
        try:
            date_str, time_str, message = match_historical.groups()
            timestamp = datetime.strptime(f"{date_str} {time_str}", "%m/%d/%Y %H:%M:%S.%f")
            return {
                "timestamp": timestamp,
                "level": "INFO",
                "component": "System",
                "message": message.strip(),
            }
        except Exception as e:
            return {"error": f"Failed to parse historical log line: {e}", "original_line": line}

    match_pix = PIX_LOG_PATTERN.match(line)
    if match_pix:
        try:
            timestamp_str, thread_name, level, component, message = match_pix.groups()
            timestamp = datetime.strptime(timestamp_str.strip(), "%Y-%m-%d %H:%M:%S,%f")
            try:
                if message.strip().startswith("{"):
                    message_data = json.loads(message.strip())
                else:
                    message_data = message.strip()
            except json.JSONDecodeError:
                message_data = message.strip()

            return {
                "timestamp": timestamp,
                "level": level.strip(),
                "component": component.strip(),
                "thread_name": thread_name.strip(),
                "message": message_data,
            }
        except Exception as e:
            return {"error": f"Failed to parse PIX log line: {e}", "original_line": line}

    match_sas = SAS_LOG_PATTERN.match(line.strip())
    if match_sas:
        try:
            hex_parts = match_sas.group("hex_data").strip().split()
            command_hex = hex_parts[0].upper()
            command_desc = SAS_COMMANDS.get(command_hex, f"Unknown Cmd: {command_hex}")

            event_descriptions = []
            if len(hex_parts) > 1:
                for part in hex_parts[1:]:
                    event_desc = SAS_EVENTS.get(part.upper())
                    if event_desc:
                        event_descriptions.append(event_desc)

            message = match_sas.group("hex_data").strip()
            if event_descriptions:
                message += f"  =>  [{', '.join(event_descriptions)}]"

            return {
                "timestamp": datetime.fromtimestamp(int(match_sas.group("timestamp")) / 1000.0),
                "level": match_sas.group("direction"),
                "component": command_desc,
                "message": message,
            }
        except Exception as e:
            return {"error": f"Failed to parse SAS log line: {e}", "original_line": line}

    if line:
        level = "INFO"
        line_lower = line.lower()
        if "exception:" in line_lower or line.strip().endswith("exception"):
            level = "EXCEP"
        elif "error cs" in line_lower or "shader error" in line_lower:
            level = "ERROR"
        elif "crash" in line_lower:
            level = "CRITICAL"
        elif line_lower.startswith("warning:"):
            level = "WARNING"
        elif line.strip().startswith("(Filename:"):
            return None

        match_unity = UNITY_LOG_PATTERN.match(line)
        if match_unity:
            parts = match_unity.groupdict()
            return {
                "timestamp": datetime.min,
                "level": level,
                "component": "Unity",
                "domain": parts.get("domain", "").strip(),
                "subsystem": parts.get("subsystem", "").strip(),
                "message": parts.get("message", "").strip(),
            }

        return {
            "timestamp": datetime.min,
            "level": level,
            "component": "Unity",
            "message": line,
        }

    return None


def parse_log_file(file_path, filter_levels=None, progress_callback=None):
    """Parses a log file and returns a list of entry dictionaries."""
    parsed_entries = []
    normalized_filter_levels = [level.upper() for level in filter_levels] if filter_levels else None

    try:
        total_lines = 0
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f_count:
            total_lines = sum(1 for _ in f_count)

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            line_iterator = iter(f)
            i = 0
            for line in line_iterator:
                if progress_callback and (i % 5000 == 0 or i == total_lines - 1):
                    progress = int(((i + 1) * 100) / total_lines) if total_lines > 0 else 100
                    progress_callback(progress, f"Parsing: {progress}% complete...")

                entry = parse_log_line(line)
                if entry:
                    if "exception" in str(entry.get("message", "")).lower():
                        try:
                            next_line = next(line_iterator).strip()
                            i += 1
                            if not (LOG_PATTERN.match(next_line) or HISTORICAL_LOG_PATTERN.match(next_line) or PIX_LOG_PATTERN.match(next_line)):
                                entry["message"] = f"{entry['message'].strip()}\n{next_line}"
                            else:
                                next_entry = parse_log_line(next_line)
                                if next_entry and (not normalized_filter_levels or next_entry.get("level", "").upper() in normalized_filter_levels):
                                    parsed_entries.append(next_entry)
                        except StopIteration:
                            pass

                    if not normalized_filter_levels or entry.get("level", "").upper() in normalized_filter_levels:
                        parsed_entries.append(entry)
                i += 1

    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        if progress_callback:
            progress_callback(-1, "Error: File not found.")
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        if progress_callback:
            progress_callback(-1, f"Error: {e}")

    return parsed_entries


def detect_time_gaps(logs, threshold_seconds=10):
    gaps = []
    logs_sorted = sorted(logs, key=lambda x: x["timestamp"])

    for i in range(1, len(logs_sorted)):
        prev = logs_sorted[i - 1]["timestamp"]
        curr = logs_sorted[i]["timestamp"]
        gap = (curr - prev).total_seconds()

        if gap > threshold_seconds:
            gaps.append({"start": prev, "end": curr, "duration": f"{gap:.2f} seconds"})

    return gaps
