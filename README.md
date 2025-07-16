# Docker-Honeynet

This repository contains a lightweight honeypot and log monitoring stack for my homelab, all deployed using Docker Compose. It uses [Cowrie](https://github.com/cowrie/cowrie) to emulate SSH and Telnet services and capture unauthorized access attempts, paired with a live web dashboard for real-time log monitoring.

---

## Purpose

The main goal of this setup is to **experiment with network security**, **monitor inbound connections**, and **detect scanning or brute-force attempts** in a controlled environment.

Some key benefits:

- Helps identify bad actors scanning or probing exposed ports.
- Learn how honeypots work and integrate with log tools.
- Visualize access attempts in real time through a lightweight dashboard.
- Runs entirely in Docker for easy cleanup and redeployment.
- Isolated environment means attackers never reach your real services.

---

## What’s Covered

This setup currently includes:

- **Cowrie Honeypot**: Emulates SSH and Telnet on custom ports (2222/2223).
- **Log.io Dashboard**: Web-based real-time viewer for Cowrie logs.
- **Docker Compose Orchestration**: Easy to deploy and tear down.

---

## Repository Layout

```
Docker-Honeynet/
├── docker-compose.yml        # Defines services and network
├── cowrie/                   # Honeypot configuration
│   └── cowrie.cfg            # Custom Cowrie settings (ports, interfaces)
├── logio/                    # Custom Dockerfile for log viewer
│   └── Dockerfile
└── .gitignore                # Ignores log and temp files
```

---

## Getting Started

To use this project locally:

```bash
git clone https://github.com/YourGitHubUsername/Docker-Honeynet.git
cd Docker-Honeynet
docker compose up -d
```

You’ll now have:
- SSH honeypot running on `port 2222`
- Telnet honeypot on `port 2223`
- Web dashboard accessible at `http://<your-lab-ip>:28778`

**Note:** You can change the ports in `cowrie.cfg` and `docker-compose.yml` if needed.

---

## Automation Integration

This setup can be plugged into broader homelab automation:

- Use **Proxmox + Terraform** to deploy a dedicated honeypot VM.
- Configure **Ansible** to pull the repo and start the stack.
- Add alerting with tools like **Prometheus**, **ELK**, or **Grafana Loki**.

---

## Security Notes

- **Run in a sandboxed environment**. Do not expose this honeypot to your internal trusted network.
- It is highly recommended to deploy this on a **dedicated VM** or VLAN.
- You can monitor log files under `cowrie/var/log` or through the log.io interface.
- While Cowrie is passive by design, never trust traffic from unknown sources.

---

## Future Plans

- Add Filebeat or Fluentd for log shipping
- Optional webhook integration for Discord/Slack alerts
- Tag and enrich data with GeoIP or reverse DNS
- Auto-block repeat offenders using fail2ban or Suricata


