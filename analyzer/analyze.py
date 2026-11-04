#!/usr/bin/env python3
"""
Honeypot Intel Analyzer
------------------------
Turns raw Cowrie honeypot logs into a triaged, human-readable intelligence
report. Runs entirely locally: no cloud APIs, no accounts, no telemetry.

Usage:
    python analyze.py --log sample_data/cowrie_sample.jsonl --out output/report.html
    python analyze.py --log /path/to/cowrie.json --out output/report.html
"""

import argparse
import os
import sys

from src.parser import load_sessions
from src.classifier import analyze
from src.report import generate_html_report


def main():
    ap = argparse.ArgumentParser(description="Analyze Cowrie honeypot logs and generate an HTML intel report.")
    ap.add_argument("--log", required=True, help="Path to a Cowrie JSON Lines log file.")
    ap.add_argument("--out", default="output/report.html", help="Path to write the HTML report to.")
    args = ap.parse_args()

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


if __name__ == "__main__":
    main()
