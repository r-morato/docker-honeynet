"""Parser tests. Run from analyzer/: python -m unittest discover tests"""

import json
import os
import tempfile
import unittest

from src.parser import load_sessions

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "sample_data", "cowrie_sample.jsonl")


def _session(sid="abc123", duration=3.5):
    return [
        {"eventid": "cowrie.session.connect", "session": sid, "src_ip": "203.0.113.7",
         "timestamp": "2026-08-18T00:15:35Z"},
        {"eventid": "cowrie.login.failed", "session": sid, "username": "root", "password": "root"},
        {"eventid": "cowrie.login.success", "session": sid, "username": "pi", "password": "raspberry"},
        {"eventid": "cowrie.command.input", "session": sid, "input": "uname -a"},
        {"eventid": "cowrie.session.closed", "session": sid, "duration": duration,
         "timestamp": "2026-08-18T00:15:39Z"},
    ]


class LoadSessionsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, data):
        path = os.path.join(self.tmp.name, "log.jsonl")
        mode = "wb" if isinstance(data, bytes) else "w"
        with open(path, mode) as f:
            f.write(data)
        return path

    def write_events(self, events, extra=""):
        return self.write("\n".join(json.dumps(e) for e in events) + "\n" + extra)

    def test_basic_session(self):
        [s] = load_sessions(self.write_events(_session()))
        self.assertEqual(s["src_ip"], "203.0.113.7")
        self.assertEqual(s["commands"], ["uname -a"])
        self.assertEqual(s["num_logins"], 2)
        self.assertEqual(s["num_failed_logins"], 1)
        self.assertTrue(s["login_success"])
        self.assertEqual(s["duration"], 3.5)

    def test_string_duration_is_converted(self):
        [s] = load_sessions(self.write_events(_session(duration="2.1")))
        self.assertEqual(s["duration"], 2.1)

    def test_unparseable_duration_falls_back_to_timestamps(self):
        [s] = load_sessions(self.write_events(_session(duration="n/a")))
        self.assertEqual(s["duration"], 4.0)

    def test_invalid_utf8_does_not_abort(self):
        good = "\n".join(json.dumps(e) for e in _session()).encode()
        bad = b'\n{"eventid":"cowrie.command.input","session":"abc123","input":"echo \xff\xfe"}\n'
        [s] = load_sessions(self.write(good + bad))
        self.assertEqual(len(s["commands"]), 2)

    def test_skips_malformed_and_non_object_lines(self):
        extra = 'not json\n[1, 2]\n42\n"str"\n{"eventid": "x", "session": ["list"]}\n'
        sessions = load_sessions(self.write_events(_session(), extra))
        self.assertEqual([s["session_id"] for s in sessions], ["abc123"])

    def test_sample_data_parses(self):
        sessions = load_sessions(SAMPLE)
        self.assertGreater(len(sessions), 0)
        self.assertTrue(all(isinstance(s["duration"], float) for s in sessions))


if __name__ == "__main__":
    unittest.main()
