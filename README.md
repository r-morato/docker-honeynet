# docker-honeynet

A small SSH/Telnet honeypot for my homelab, plus the tool I use to make sense of what it catches.

Two parts, one repo:

| Path | What it is |
|---|---|
| `docker-compose.yml`, `cowrie/`, `logio/` | the honeypot stack: [Cowrie](https://github.com/cowrie/cowrie) behind a [log.io](https://github.com/NarrativeScience/log.io) live log viewer, all in Docker |
| [`analyzer/`](analyzer/) | [Honeypot Intel Analyzer](analyzer/README.md), a local Python tool that reads the Cowrie logs and turns them into a triaged HTML report (attack types, correlated campaigns, anomalies) |

The stack collects the logs; the analyzer is what I actually read.

## The honeypot stack

Cowrie emulates SSH on `2222` and Telnet on `2223`, records every session (login attempts, commands run, files fetched), and log.io tails those logs in a browser at `:28778`.

```bash
git clone https://github.com/r-morato/docker-honeynet.git
cd docker-honeynet
docker compose up -d
```

That gives you:

- SSH honeypot on `2222`
- Telnet honeypot on `2223`
- Live log viewer at `http://<lab-ip>:28778`

Ports are set in `cowrie/cowrie.cfg` and `docker-compose.yml`. Cowrie's session logs (`cowrie/var/log/`) are gitignored.

### Running it safely

- Put this on a **dedicated VM or an isolated VLAN**, never on a trusted segment. The point is to attract hostile traffic.
- Only forward the honeypot ports to it. Nothing else.
- Everything in the logs (usernames, commands, IPs) was typed by an attacker. Treat it as untrusted input, which is also why the analyzer HTML-escapes all of it.

In my setup a firewall rule forwards external `2222`/`2223` to the honeypot VM and drops everything else inbound to it.

## The analyzer

Cowrie generates far more log noise than is worth reading by hand, mostly bots retrying the same credentials and dropping the same scripts. [`analyzer/`](analyzer/) reads the JSONL log and produces one self-contained HTML report: rule-based attack tagging, TF-IDF + KMeans clustering to collapse a single campaign hitting from many IPs into one entry, and an Isolation Forest pass to flag the odd sessions. Runs locally in under a second, no cloud, no API keys.

```bash
cd analyzer
pip install -r requirements.txt
python analyze.py --log sample_data/cowrie_sample.jsonl --out output/report.html
# or point --log at a real Cowrie JSON log from the honeypot
```

There is synthetic sample data in `analyzer/sample_data/` and a pre-built [example report](https://htmlpreview.github.io/?https://github.com/r-morato/docker-honeynet/blob/main/analyzer/docs/example-report.html) if you want to see the output without running anything. Full detail in [`analyzer/README.md`](analyzer/README.md).

## Ideas I haven't gotten to

- Ship logs off the VM with Filebeat or Fluentd
- Webhook alert on a high-severity session
- GeoIP / reverse-DNS enrichment on source IPs
- Auto-block repeat offenders upstream of the honeypot

## License

[MIT](LICENSE)
