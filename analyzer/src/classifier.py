"""
classifier.py

Three layers of analysis applied to parsed honeypot sessions:

1. Rule-based tagging   -- deterministic keyword/regex matching against
                            executed commands, assigns a primary attack
                            category + severity score to every session.
2. Behavioral clustering -- TF-IDF over command text + KMeans groups
                            sessions that "look alike" into campaigns,
                            even across different source IPs.
3. Anomaly detection    -- Isolation Forest over numeric session features
                            flags statistical outliers worth a human look,
                            independent of the rule-based tags above.
"""

import re
from collections import Counter

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest

# ---------------------------------------------------------------------------
# Layer 1: rule-based tagging
# ---------------------------------------------------------------------------

# Ordered most-specific-first: a session is tagged with the first category
# whose pattern matches. Severity is on a 1-5 scale used for sorting/color.
CATEGORY_RULES = [
    ("Cryptomining", 5, re.compile(r"xmrig|minerd|stratum\+tcp|monero|nicehash|cryptonight", re.I)),
    ("Malware Download", 5, re.compile(r"(wget|curl|tftp|busybox\s+wget).*(http|ftp)|chmod\s+\+?7*x", re.I)),
    ("Data Exfiltration", 4, re.compile(r"\bscp\b|nc\s+-e|/etc/shadow|tar\s+cz|base64\s+-d", re.I)),
    ("Persistence", 4, re.compile(r"authorized_keys|crontab|useradd|chpasswd|usermod", re.I)),
    ("Reconnaissance", 2, re.compile(r"uname\s+-a|whoami|/etc/passwd|ifconfig|ps\s+aux|netstat|cat\s+/proc", re.I)),
    ("Credential Brute-Force", 3, re.compile(r".^"), ),  # placeholder, handled by login heuristics below
]

DEFAULT_CATEGORY = ("Unclassified / Low Activity", 1)


def tag_session(session):
    """Return (category, severity) for a single parsed session."""
    text = session["commands_text"]

    # Command-based rules first (most specific signal available).
    for name, severity, pattern in CATEGORY_RULES:
        if name == "Credential Brute-Force":
            continue
        if text and pattern.search(text):
            return name, severity

    # Brute-force heuristic: many failed logins relative to activity,
    # regardless of whether commands were ever run.
    if session["num_failed_logins"] >= 4:
        return "Credential Brute-Force", 3

    if session["num_commands"] == 0 and session["num_logins"] > 0:
        return "Unclassified / Low Activity", 1

    return DEFAULT_CATEGORY


def tag_all(sessions):
    for s in sessions:
        category, severity = tag_session(s)
        s["category"] = category
        s["severity"] = severity
    return sessions


# ---------------------------------------------------------------------------
# Layer 2: behavioral clustering (campaign correlation)
# ---------------------------------------------------------------------------

def cluster_sessions(sessions, max_clusters=6):
    """
    Groups sessions with similar command behavior using TF-IDF + KMeans,
    so that e.g. the same botnet script run from 5 different IPs gets
    correlated into one "campaign" instead of 5 unrelated events.

    Sessions with no commands are excluded from clustering and left
    unclustered (cluster_id = -1).
    """
    active = [s for s in sessions if s["num_commands"] > 0]
    for s in sessions:
        s["cluster_id"] = -1

    if len(active) < 4:
        return []

    texts = [s["commands_text"] for s in active]
    vectorizer = TfidfVectorizer(token_pattern=r"[^\s]+", max_features=500)
    X = vectorizer.fit_transform(texts)

    k = max(2, min(max_clusters, len(active) // 4))
    km = KMeans(n_clusters=k, n_init=10, random_state=42)
    labels = km.fit_predict(X)

    for s, label in zip(active, labels):
        s["cluster_id"] = int(label)

    # Describe each cluster by its top TF-IDF terms + dominant category.
    terms = np.array(vectorizer.get_feature_names_out())
    clusters = []
    for cluster_id in range(k):
        members = [s for s in active if s["cluster_id"] == cluster_id]
        if not members:
            continue
        center = km.cluster_centers_[cluster_id]
        top_idx = center.argsort()[::-1][:6]
        signature_terms = [t for t in terms[top_idx] if center[terms.tolist().index(t)] > 0]
        dominant_category = Counter(m["category"] for m in members).most_common(1)[0][0]
        src_ips = sorted(set(m["src_ip"] for m in members if m["src_ip"]))
        clusters.append({
            "cluster_id": cluster_id,
            "size": len(members),
            "dominant_category": dominant_category,
            "signature_terms": signature_terms[:5],
            "src_ip_count": len(src_ips),
            "src_ips": src_ips[:8],
            "session_ids": [m["session_id"] for m in members],
        })

    clusters.sort(key=lambda c: c["size"], reverse=True)
    return clusters


# ---------------------------------------------------------------------------
# Layer 3: anomaly detection over numeric features
# ---------------------------------------------------------------------------

FEATURE_NAMES = ["duration", "num_commands", "num_unique_commands", "num_logins", "num_failed_logins"]


def detect_anomalies(sessions, contamination=0.08):
    """Flags statistically unusual sessions with Isolation Forest."""
    if len(sessions) < 10:
        for s in sessions:
            s["is_anomaly"] = False
            s["anomaly_score"] = 0.0
        return sessions

    X = np.array([[s[f] for f in FEATURE_NAMES] for s in sessions], dtype=float)
    clf = IsolationForest(contamination=contamination, random_state=42, n_estimators=200)
    preds = clf.fit_predict(X)
    scores = clf.decision_function(X)

    for s, pred, score in zip(sessions, preds, scores):
        s["is_anomaly"] = bool(pred == -1)
        s["anomaly_score"] = float(score)

    return sessions


def analyze(sessions):
    """Runs all three layers and returns (sessions, clusters)."""
    tag_all(sessions)
    clusters = cluster_sessions(sessions)
    detect_anomalies(sessions)
    return sessions, clusters
