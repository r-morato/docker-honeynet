"""Alerting tests. Run from analyzer/: python -m unittest discover tests"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from src.alerts import build_payload, load_state, post_json, select_alerts, send_alerts, validate_url

ANALYZER = os.path.join(os.path.dirname(__file__), "..")
SAMPLE = os.path.join(ANALYZER, "sample_data", "cowrie_sample.jsonl")


def _s(sid, severity, anomaly=False, commands=("uname -a",), ip="203.0.113.7", start="2026-08-18T00:00:00Z"):
    return {"session_id": sid, "severity": severity, "is_anomaly": anomaly, "commands": list(commands),
            "src_ip": ip, "start": start, "category": f"cat{severity}"}


class Receiver:
    """A real local webhook endpoint that records what it was sent."""

    def __init__(self, status=200):
        received = self.received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                received.append((self.headers["Content-Type"], json.loads(body)))
                self.send_response(status)
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/hook"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class SelectAlertsTest(unittest.TestCase):
    def test_threshold_order_and_history(self):
        sessions = [_s("a", 2), _s("b", 5, start="2026-08-18T02:00:00Z"), _s("c", 4), _s("d", 5)]
        self.assertEqual([s["session_id"] for s in select_alerts(sessions)], ["d", "b", "c"])
        self.assertEqual([s["session_id"] for s in select_alerts(sessions, already_alerted={"d"})], ["b", "c"])
        self.assertEqual([s["session_id"] for s in select_alerts(sessions, min_severity=5)], ["d", "b"])

    def test_anomalies_are_opt_in(self):
        sessions = [_s("a", 1, anomaly=True), _s("b", 5)]
        self.assertEqual([s["session_id"] for s in select_alerts(sessions)], ["b"])
        self.assertEqual([s["session_id"] for s in select_alerts(sessions, include_anomalies=True)], ["b", "a"])


class PayloadTest(unittest.TestCase):
    def test_attacker_text_cannot_break_the_message(self):
        evil = "echo `id`\n@everyone <script>x</script> " + "A" * 500
        text = build_payload([_s("a", 5, commands=[evil])])["text"]
        line = text.splitlines()[1]
        self.assertEqual(len(text.splitlines()), 2)  # no injected newlines
        self.assertNotIn("`id`", line)  # backticks can't close our code span
        self.assertLess(len(line), 250)

    def test_long_runs_are_summarised_and_fit_discord(self):
        payload = build_payload([_s(str(i), 5, commands=["x" * 300]) for i in range(40)])
        self.assertIn("and 30 more", payload["text"])
        self.assertLessEqual(len(payload["content"]), 2000)
        self.assertEqual(len(payload["sessions"]), 40)

    def test_url_must_be_http(self):
        for bad in ("file:///etc/passwd", "ftp://x", "hooks.slack.com/x", ""):
            with self.assertRaises(ValueError):
                validate_url(bad)
        validate_url("https://hooks.slack.com/services/x")


class SendAlertsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = os.path.join(self.tmp.name, "state", "alerted.json")

    def test_sends_once_then_remembers(self):
        rx = Receiver()
        self.addCleanup(rx.close)
        sessions = [_s("a", 5), _s("b", 1)]
        self.assertEqual(send_alerts(sessions, rx.url, self.state), 1)
        self.assertEqual(send_alerts(sessions, rx.url, self.state), 0)
        sessions.append(_s("c", 4))
        self.assertEqual(send_alerts(sessions, rx.url, self.state), 1)
        self.assertEqual(len(rx.received), 2)
        content_type, body = rx.received[0]
        self.assertEqual(content_type, "application/json")
        self.assertEqual(body["sessions"][0]["session_id"], "a")
        self.assertEqual(load_state(self.state), {"a", "c"})

    def test_failed_delivery_is_retried_next_run(self):
        rx = Receiver(status=500)
        self.addCleanup(rx.close)
        with self.assertRaises(Exception):
            send_alerts([_s("a", 5)], rx.url, self.state)
        self.assertEqual(load_state(self.state), set())

    def test_dry_run_sends_and_records_nothing(self):
        def boom(*_):
            raise AssertionError("dry run must not send")
        self.assertEqual(send_alerts([_s("a", 5)], None, self.state, dry_run=True, sender=boom), 1)
        self.assertFalse(os.path.exists(self.state))

    def test_corrupt_state_file_does_not_stop_alerting(self):
        os.makedirs(os.path.dirname(self.state))
        with open(self.state, "w") as f:
            f.write("not json")
        sent = []
        self.assertEqual(send_alerts([_s("a", 5)], "http://x", self.state, sender=lambda u, p: sent.append(p)), 1)
        self.assertEqual(load_state(self.state), {"a"})

    def test_post_json_raises_on_error_status(self):
        rx = Receiver(status=404)
        self.addCleanup(rx.close)
        with self.assertRaises(Exception):
            post_json(rx.url, {"text": "hi"})


class CliTest(unittest.TestCase):
    """Runs analyze.py end to end on the sample log against a local receiver."""

    def run_cli(self, *args, env=None):
        return subprocess.run([sys.executable, "analyze.py", "--log", SAMPLE, *args], cwd=ANALYZER,
                              capture_output=True, text=True, env={**os.environ, **(env or {})})

    def test_alerts_from_env_url_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "report.html")
            rx = Receiver()
            self.addCleanup(rx.close)
            first = self.run_cli("--out", out, env={"HONEYPOT_WEBHOOK_URL": rx.url})
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertIn("alerted on", first.stdout)
            second = self.run_cli("--out", out, env={"HONEYPOT_WEBHOOK_URL": rx.url})
            self.assertIn("No new sessions", second.stdout)
            self.assertEqual(len(rx.received), 1)
            self.assertTrue(os.path.exists(os.path.join(tmp, "alerted_sessions.json")))

            bad = Receiver(status=500)
            self.addCleanup(bad.close)
            failed = self.run_cli("--out", os.path.join(tmp, "b", "r.html"), "--alert-webhook", bad.url)
            self.assertEqual(failed.returncode, 2)
            self.assertTrue(os.path.exists(os.path.join(tmp, "b", "r.html")))  # report still written

            refused = self.run_cli("--out", out, "--alert-webhook", "file:///etc/passwd")
            self.assertEqual(refused.returncode, 1)

    def test_no_webhook_means_no_alerting(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {k: v for k, v in os.environ.items() if k != "HONEYPOT_WEBHOOK_URL"}
            r = subprocess.run([sys.executable, "analyze.py", "--log", SAMPLE, "--out", os.path.join(tmp, "r.html")],
                               cwd=ANALYZER, capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 0)
            self.assertNotIn("alert", r.stdout.lower())
            self.assertFalse(os.path.exists(os.path.join(tmp, "alerted_sessions.json")))


if __name__ == "__main__":
    unittest.main()
