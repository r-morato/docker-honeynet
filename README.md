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

Docker-Honeynet/
├── docker-compose.yml # Defines services and network
├── cowrie/ # Honeypot configuration
│ └── cowrie.cfg # Custom Cowrie settings (ports, interfaces)
├── logio/ # Custom Dockerfile for log viewer
│ └── Dockerfile
└── .gitignore # Ignores log and temp files


---

## Getting Started

To use this project locally:

```bash
git clone https://github.com/YourGitHubUsername/Docker-Honeynet.git
cd Docker-Honeynet
docker compose up -d
