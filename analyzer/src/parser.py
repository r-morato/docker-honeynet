"""
parser.py

Reads a Cowrie-style JSON Lines honeypot log and groups events by session
into structured records ready for classification and clustering.
"""

import json
from datetime import datetime


def _parse_ts(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def load_sessions(log_path):
    """Parse a Cowrie JSONL log file into a list of session dicts."""
    sessions = {}

    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            sid = event.get("session")
            if not sid:
                continue

            s = sessions.setdefault(sid, {
                "session_id": sid,
                "src_ip": None,
                "start": None,
                "end": None,
                "duration": None,
                "commands": [],
                "logins": [],
            })

            eid = event.get("eventid", "")

            if eid == "cowrie.session.connect":
                s["src_ip"] = event.get("src_ip")
                s["start"] = event.get("timestamp")

            elif eid in ("cowrie.login.success", "cowrie.login.failed"):
                s["logins"].append({
                    "username": event.get("username", ""),
                    "password": event.get("password", ""),
                    "success": eid == "cowrie.login.success",
                })

            elif eid == "cowrie.command.input":
                cmd = event.get("input", "")
                if cmd:
                    s["commands"].append(cmd)

            elif eid == "cowrie.session.closed":
                s["end"] = event.get("timestamp")
                s["duration"] = event.get("duration")

    result = []
    for s in sessions.values():
        if s["duration"] is None and s["start"] and s["end"]:
            try:
                s["duration"] = (_parse_ts(s["end"]) - _parse_ts(s["start"])).total_seconds()
            except Exception:
                s["duration"] = 0.0
        s["duration"] = s["duration"] or 0.0
        s["num_commands"] = len(s["commands"])
        s["num_unique_commands"] = len(set(s["commands"]))
        s["num_logins"] = len(s["logins"])
        s["num_failed_logins"] = sum(1 for l in s["logins"] if not l["success"])
        s["login_success"] = any(l["success"] for l in s["logins"])
        s["commands_text"] = " ".join(s["commands"])
        result.append(s)

    result.sort(key=lambda s: s["start"] or "")
    return result
