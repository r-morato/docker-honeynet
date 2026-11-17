#!/usr/bin/env python3
"""
Honeypot Intel Analyzer
------------------------
Turns raw Cowrie honeypot logs into a triaged, human-readable intelligence
report. Runs entirely locally: no cloud APIs, no accounts, no telemetry.

Usage:
    python analyze.py --log sample_data/cowrie_sample.jsonl --out output/report.html
    python analyze.py --log /path/to/cowrie.json --out output/report.html
    python analyze.py --log /path/to/cowrie.json --alert-webhook https://...   # alert on new high-severity sessions
"""

import argparse
import os
import sys

from src.parser import load_sessions
from src.classifier import analyze
from src.report import generate_html_report
from src.alerts import send_alerts, validate_url


def main():
    ap = argparse.ArgumentParser(description="Analyze Cowrie honeypot logs and generate an HTML intel report.")
    ap.add_argument("--log", required=True, help="Path to a Cowrie JSON Lines log file.")
    ap.add_argument("--out", default="output/report.html", help="Path to write the HTML report to.")
    alert = ap.add_argument_group("alerting (optional)")
    alert.add_argument("--alert-webhook", default=os.environ.get("HONEYPOT_WEBHOOK_URL"),
                       help="POST new high-severity sessions to this webhook (Slack, Discord, ntfy or any JSON "
                            "receiver). Defaults to $HONEYPOT_WEBHOOK_URL, which keeps the URL out of your shell history.")
    alert.add_argument("--alert-min-severity", type=int, default=4, choices=range(1, 6), metavar="1-5",
                       help="Alert on sessions at or above this severity (default: 4, persistence/exfiltration and up).")
    alert.add_argument("--alert-anomalies", action="store_true",
                       help="Also alert on sessions the anomaly detector flagged, whatever their severity.")
    alert.add_argument("--alert-state", default=None,
                       help="File that remembers which sessions were already sent "
                            "(default: alerted_sessions.json next to --out).")
    alert.add_argument("--alert-dry-run", action="store_true",
                       help="Print the alert instead of sending it, and don't record it as sent.")
    args = ap.parse_args()

    if args.alert_webhook and not args.alert_dry_run:
        try:
            validate_url(args.alert_webhook)
        except ValueError as e:
            print(f"error: --alert-webhook: {e}", file=sys.stderr)
            sys.exit(1)

    if not os.path.exists(args.log):
        print(f"error: log file not found: {args.log}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsing sessions from {args.log} ...")
    sessions = load_sessions(args.log)
    print(f"[*] Found {len(sessions)} sessions.")

    if not sessions:
        print("error: no sessions parsed — is this a valid Cowrie JSONL log?", file=sys.stderr)
        sys.exit(1)

    print("[*] Tagging attack categories, clustering campaigns, scoring anomalies ...")
    sessions, clusters = analyze(sessions)
    print(f"[*] {len(clusters)} correlated campaign(s) identified.")
    print(f"[*] {sum(1 for s in sessions if s['is_anomaly'])} anomalous session(s) flagged.")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    html_doc = generate_html_report(sessions, clusters, args.log)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html_doc)

    print(f"[*] Report written to {args.out}")
    print("[*] Open it directly in a browser — no server required.")

    if args.alert_webhook or args.alert_dry_run:
        state = args.alert_state or os.path.join(os.path.dirname(args.out) or ".", "alerted_sessions.json")
        try:
            sent = send_alerts(sessions, args.alert_webhook, state,
                               min_severity=args.alert_min_severity, include_anomalies=args.alert_anomalies,
                               log_path=args.log, dry_run=args.alert_dry_run)
        except Exception as e:  # network errors, non-2xx replies
            print(f"error: alert delivery failed, will retry next run: {e}", file=sys.stderr)
            sys.exit(2)
        verb = "would alert" if args.alert_dry_run else "alerted"
        print(f"[*] {verb} on {sent} new session(s)." if sent else "[*] No new sessions to alert on.")


if __name__ == "__main__":
    main()
