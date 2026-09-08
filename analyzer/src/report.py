"""
report.py

Renders analysis results as a single self-contained HTML file: no server,
no external network requests, no build step. Double-click it and it opens.

Every string that originated from attacker-controlled honeypot input
(commands, usernames, session ids, source IPs) is HTML-escaped before
being embedded — never trust bytes an attacker typed into your honeypot.
"""

import html
from collections import Counter
from datetime import datetime, timezone

SEVERITY_STYLE = {
    5: ("critical", "#FF5C5C"),
    4: ("high", "#F5A623"),
    3: ("medium", "#4FD1C5"),
    2: ("medium", "#4FD1C5"),
    1: ("low", "#5A6B7D"),
}

CSS = """
:root {
  --bg: #0B0F14;
  --panel: #121821;
  --panel-border: #1F2A36;
  --text: #E7ECF2;
  --text-muted: #8291A3;
  --critical: #FF5C5C;
  --high: #F5A623;
  --medium: #4FD1C5;
  --low: #5A6B7D;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
* { box-sizing: border-box; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  margin: 0;
  padding: 0 0 64px 0;
}
.wrap { max-width: 1080px; margin: 0 auto; padding: 0 24px; }

header.cover {
  border-bottom: 1px solid var(--panel-border);
  padding: 48px 0 32px 0;
  margin-bottom: 32px;
}
.eyebrow {
  font-family: var(--mono);
  font-size: 12px;
  letter-spacing: 0.18em;
  color: var(--medium);
  text-transform: uppercase;
  margin-bottom: 12px;
}
h1 {
  font-size: 34px;
  letter-spacing: -0.01em;
  margin: 0 0 12px 0;
  font-weight: 700;
}
.meta {
  font-family: var(--mono);
  font-size: 13px;
  color: var(--text-muted);
  display: flex;
  gap: 24px;
  flex-wrap: wrap;
}

.stat-row {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 1px;
  background: var(--panel-border);
  border: 1px solid var(--panel-border);
  margin-bottom: 40px;
}
.stat {
  background: var(--panel);
  padding: 20px 16px;
}
.stat .n {
  font-family: var(--mono);
  font-size: 28px;
  font-weight: 700;
  line-height: 1;
}
.stat .l {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-top: 8px;
}

section { margin-bottom: 48px; }
h2 {
  font-family: var(--mono);
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  color: var(--text-muted);
  border-bottom: 1px solid var(--panel-border);
  padding-bottom: 10px;
  margin-bottom: 20px;
}

.bar-row { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; font-family: var(--mono); font-size: 13px; }
.bar-label { width: 210px; flex-shrink: 0; color: var(--text); }
.bar-track { flex: 1; background: var(--panel); border: 1px solid var(--panel-border); height: 18px; position: relative; }
.bar-fill { height: 100%; }
.bar-count { width: 40px; text-align: right; color: var(--text-muted); flex-shrink: 0; }

.timeline {
  display: flex;
  flex-wrap: wrap;
  gap: 2px;
  background: var(--panel);
  border: 1px solid var(--panel-border);
  padding: 12px;
}
.tick { width: 8px; height: 20px; flex-shrink: 0; }

.cluster-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 16px;
}
.case-file {
  background: var(--panel);
  border: 1px solid var(--panel-border);
  padding: 16px;
  position: relative;
}
.case-file .stamp {
  font-family: var(--mono);
  font-size: 10px;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  border: 1px solid currentColor;
  display: inline-block;
  padding: 2px 8px;
  margin-bottom: 10px;
}
.case-file .id {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text-muted);
  float: right;
}
.case-file .cat { font-weight: 700; margin-bottom: 8px; font-size: 15px; }
.case-file .terms { display: flex; flex-wrap: wrap; gap: 6px; margin: 10px 0; }
.chip {
  font-family: var(--mono);
  font-size: 11px;
  background: rgba(255,255,255,0.05);
  border: 1px solid var(--panel-border);
  padding: 2px 7px;
  color: var(--text-muted);
}
.case-file .footline { font-family: var(--mono); font-size: 12px; color: var(--text-muted); margin-top: 10px; }

table { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 13px; }
th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--panel-border); }
th { color: var(--text-muted); text-transform: uppercase; font-size: 11px; letter-spacing: 0.08em; font-weight: 500; }
tr:hover td { background: rgba(255,255,255,0.02); }
.pill { display: inline-block; padding: 1px 8px; font-size: 11px; border-radius: 2px; font-family: var(--mono); }

footer {
  font-family: var(--mono);
  font-size: 12px;
  color: var(--text-muted);
  border-top: 1px solid var(--panel-border);
  padding-top: 20px;
  margin-top: 32px;
}
"""


def _sev_color(severity):
    return SEVERITY_STYLE.get(severity, ("low", "#5A6B7D"))[1]


def _esc(x):
    return html.escape(str(x)) if x is not None else ""


def _stat(n, label):
    return f'<div class="stat"><div class="n">{_esc(n)}</div><div class="l">{_esc(label)}</div></div>'


def _category_breakdown_html(sessions):
    counts = Counter(s["category"] for s in sessions)
    sev_by_cat = {s["category"]: s["severity"] for s in sessions}
    total = len(sessions) or 1
    rows = []
    for cat, count in counts.most_common():
        pct = round(100 * count / total)
        color = _sev_color(sev_by_cat.get(cat, 1))
        rows.append(f"""
        <div class="bar-row">
          <div class="bar-label">{_esc(cat)}</div>
          <div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{color};"></div></div>
          <div class="bar-count">{count}</div>
        </div>""")
    return "\n".join(rows)


def _timeline_html(sessions):
    ticks = []
    for s in sessions:
        color = _sev_color(s["severity"])
        title = f'{s["start"] or "unknown time"} · {s["category"]} · {s["src_ip"]} · session {s["session_id"]}'
        ticks.append(f'<div class="tick" style="background:{color};" title="{_esc(title)}"></div>')
    return "\n".join(ticks)


def _clusters_html(clusters):
    if not clusters:
        return '<p style="color:var(--text-muted);font-family:var(--mono);font-size:13px;">Not enough command activity to correlate campaigns from this log.</p>'
    cards = []
    for c in clusters:
        terms = "".join(f'<span class="chip">{_esc(t)}</span>' for t in c["signature_terms"])
        ip_preview = ", ".join(_esc(ip) for ip in c["src_ips"][:5])
        more = f' +{c["src_ip_count"] - 5} more' if c["src_ip_count"] > 5 else ""
        cards.append(f"""
        <div class="case-file">
          <span class="id">CASE #{c['cluster_id']+1:02d}</span>
          <div class="stamp">{c['size']} sessions correlated</div>
          <div class="cat">{_esc(c['dominant_category'])}</div>
          <div class="terms">{terms}</div>
          <div class="footline">{c['src_ip_count']} source IP(s): {ip_preview}{more}</div>
        </div>""")
    return f'<div class="cluster-grid">{"".join(cards)}</div>'


def _anomalies_html(sessions):
    anomalies = sorted([s for s in sessions if s["is_anomaly"]], key=lambda s: s["anomaly_score"])
    if not anomalies:
        return '<p style="color:var(--text-muted);font-family:var(--mono);font-size:13px;">No statistical outliers flagged in this log.</p>'
    rows = []
    for s in anomalies:
        color = _sev_color(s["severity"])
        rows.append(f"""
        <tr>
          <td>{_esc(s['session_id'])}</td>
          <td>{_esc(s['src_ip'])}</td>
          <td><span class="pill" style="background:{color}22;color:{color};">{_esc(s['category'])}</span></td>
          <td>{s['duration']:.1f}s</td>
          <td>{s['num_commands']}</td>
          <td>{s['num_failed_logins']}</td>
        </tr>""")
    return f"""
    <table>
      <thead><tr><th>Session</th><th>Source IP</th><th>Category</th><th>Duration</th><th>Commands</th><th>Failed logins</th></tr></thead>
      <tbody>{"".join(rows)}</tbody>
    </table>"""


def _top_ips_html(sessions, limit=10):
    by_ip = Counter(s["src_ip"] for s in sessions if s["src_ip"])
    rows = []
    for ip, count in by_ip.most_common(limit):
        cats = Counter(s["category"] for s in sessions if s["src_ip"] == ip)
        top_cat = cats.most_common(1)[0][0]
        color = _sev_color(next((s["severity"] for s in sessions if s["src_ip"] == ip and s["category"] == top_cat), 1))
        rows.append(f"""
        <tr>
          <td>{_esc(ip)}</td>
          <td>{count}</td>
          <td><span class="pill" style="background:{color}22;color:{color};">{_esc(top_cat)}</span></td>
        </tr>""")
    return f"""
    <table>
      <thead><tr><th>Source IP</th><th>Sessions</th><th>Dominant behavior</th></tr></thead>
      <tbody>{"".join(rows)}</tbody>
    </table>"""


def generate_html_report(sessions, clusters, log_path):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = len(sessions)
    unique_ips = len(set(s["src_ip"] for s in sessions if s["src_ip"]))
    successful_logins = sum(1 for s in sessions if s["login_success"])
    anomalies = sum(1 for s in sessions if s["is_anomaly"])
    top_category = Counter(s["category"] for s in sessions).most_common(1)
    top_category = top_category[0][0] if top_category else "n/a"

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Honeypot Intelligence Report</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">

  <header class="cover">
    <div class="eyebrow">Honeypot Intel Analyzer &mdash; Case Report</div>
    <h1>Attack Session Intelligence Report</h1>
    <div class="meta">
      <span>Source log: {_esc(log_path)}</span>
      <span>Generated: {now}</span>
      <span>Sessions analyzed: {total}</span>
    </div>
  </header>

  <div class="stat-row">
    {_stat(total, "Sessions")}
    {_stat(unique_ips, "Unique Source IPs")}
    {_stat(successful_logins, "Successful Logins")}
    {_stat(anomalies, "Anomalies Flagged")}
    {_stat(top_category, "Top Category")}
  </div>

  <section>
    <h2>Threat Category Breakdown</h2>
    {_category_breakdown_html(sessions)}
  </section>

  <section>
    <h2>Session Timeline &mdash; hover a tick for details</h2>
    <div class="timeline">{_timeline_html(sessions)}</div>
  </section>

  <section>
    <h2>Correlated Campaigns (behavioral clustering)</h2>
    {_clusters_html(clusters)}
  </section>

  <section>
    <h2>Anomalies Flagged for Review</h2>
    {_anomalies_html(sessions)}
  </section>

  <section>
    <h2>Top Source IPs</h2>
    {_top_ips_html(sessions)}
  </section>

  <footer>
    Generated locally by honeypot-intel-analyst. No cloud services, external APIs, or telemetry involved &mdash;
    this file is self-contained and safe to open offline.
  </footer>

</div>
</body>
</html>"""
    return html_doc
