"""
alerts.py

Optional webhook alerting for high-severity sessions, so the analyzer can run
from cron and tell you when something worth reading happens, instead of you
having to open the report to find out.

- select_alerts() picks sessions at or above a severity (and, optionally,
  anything the Isolation Forest flagged) that haven't been alerted on before.
- A small JSON state file remembers which session IDs were already sent, so
  re-running over the same growing Cowrie log doesn't repeat old alerts.
- The payload carries both "text" (Slack, Mattermost, most generic receivers)
  and "content" (Discord) plus a structured "sessions" list, so one URL works
  with the common chat webhooks and with your own tooling.

Everything in a session was typed by an attacker. Values are truncated and
wrapped in backticks in the message text, but treat the payload as untrusted
wherever it ends up.
"""

import json
import os
import urllib.request
from urllib.parse import urlparse

MAX_SESSIONS_IN_TEXT = 10
MAX_FIELD = 120
DISCORD_LIMIT = 2000


def load_state(path):
    """Return the set of session IDs already alerted on."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return set(data.get("alerted", []))
    except FileNotFoundError:
        return set()
    except (OSError, ValueError, AttributeError):
        # A corrupt state file shouldn't stop alerting; worst case is a repeat.
        print(f"[!] Ignoring unreadable alert state file: {path}")
        return set()


def save_state(path, alerted):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"alerted": sorted(alerted)}, f)
    os.replace(tmp, path)


def select_alerts(sessions, min_severity=4, include_anomalies=False, already_alerted=()):
    """Sessions worth alerting on that haven't been sent before, worst first."""
    already = set(already_alerted)
    picked = [
        s for s in sessions
        if s["session_id"] not in already
        and (s.get("severity", 0) >= min_severity or (include_anomalies and s.get("is_anomaly")))
    ]
    picked.sort(key=lambda s: (-s.get("severity", 0), s.get("start") or ""))
    return picked


def _clip(value, limit=MAX_FIELD):
    value = " ".join(str(value or "").split())  # no newlines from attacker input
    value = value.replace("`", "'")
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _session_line(s):
    reason = s.get("category", "?")
    if s.get("is_anomaly") and s.get("severity", 0) < 4:
        reason += ", anomalous"
    cmds = _clip("; ".join(s.get("commands", [])[:5])) or "(no commands)"
    return f"[sev {s.get('severity', '?')}] {reason} from `{_clip(s.get('src_ip') or 'unknown', 45)}`: `{cmds}`"


def build_payload(alerts, log_path=None):
    lines = [f"Honeypot: {len(alerts)} new session(s) worth a look"]
    lines += [f"- {_session_line(s)}" for s in alerts[:MAX_SESSIONS_IN_TEXT]]
    if len(alerts) > MAX_SESSIONS_IN_TEXT:
        lines.append(f"- ...and {len(alerts) - MAX_SESSIONS_IN_TEXT} more, see the report")
    text = "\n".join(lines)
    if len(text) > DISCORD_LIMIT:
        text = text[: DISCORD_LIMIT - 1] + "…"
    return {
        "text": text,
        "content": text,
        "source_log": log_path,
        "sessions": [
            {
                "session_id": s["session_id"],
                "src_ip": s.get("src_ip"),
                "start": s.get("start"),
                "category": s.get("category"),
                "severity": s.get("severity"),
                "is_anomaly": bool(s.get("is_anomaly")),
                "commands": [_clip(c, 500) for c in s.get("commands", [])[:20]],
            }
            for s in alerts
        ],
    }


def validate_url(url):
    parsed = urlparse(url or "")
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("webhook URL must be an http(s) URL")
    return url


def post_json(url, payload, timeout=10):
    """POST the payload as JSON. Raises on network errors or a non-2xx reply."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        validate_url(url), data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "honeypot-intel-analyzer"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status


def send_alerts(sessions, url, state_path, min_severity=4, include_anomalies=False,
                log_path=None, dry_run=False, sender=post_json):
    """
    Select, send and record alerts. Returns how many sessions were alerted on.
    The state file is only updated after the webhook accepted the message, so a
    failed delivery is retried on the next run.
    """
    already = load_state(state_path)
    alerts = select_alerts(sessions, min_severity, include_anomalies, already)
    if not alerts:
        return 0
    payload = build_payload(alerts, log_path)
    if dry_run:
        print(payload["text"])
        return len(alerts)
    sender(url, payload)
    save_state(state_path, already | {s["session_id"] for s in alerts})
    return len(alerts)
