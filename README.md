<div align="center">

# 🛡️ SSH Honeypot v2.0

[![Stars](https://img.shields.io/github/stars/Dev9269/ssh-honeypot?style=flat-square&logo=github&color=gold)](https://github.com/Dev9269/ssh-honeypot)
[![Forks](https://img.shields.io/github/forks/Dev9269/ssh-honeypot?style=flat-square&logo=github&color=blue)](https://github.com/Dev9269/ssh-honeypot/forks)
[![License](https://img.shields.io/github/license/Dev9269/ssh-honeypot?style=flat-square&color=brightgreen)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)](https://attack.mitre.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen?style=flat-square)](https://github.com/Dev9269/ssh-honeypot/pulls)

A modern, production-ready SSH honeypot platform for cybersecurity research, threat intelligence collection, and attack pattern analysis.

**Created by** [Jainam Maru](https://github.com/Dev9269)

</div>

---

## What's New in v2.0

- **Fake Shell Interaction** — Captures attacker commands in a realistic Linux shell environment
- **IP Geolocation** — Maps attacker IPs to city/country/ASN (GeoIP2 or ip-api.com fallback)
- **Threat Intelligence** — AbuseIPDB, AlienVault OTX, VirusTotal integration
- **Real-time Alerts** — Webhook, Slack, Discord, and email notifications
- **Web Dashboard** — FastAPI-based live monitoring UI with auth
- **SQLite Database** — Structured storage for querying and analysis
- **MITRE ATT&CK Mapping** — Auto-tags attacks with TTP IDs
- **Rate Limiting** — Per-IP connection throttling with auto-ban
- **Dynamic Fingerprinting** — Randomized SSH banners to avoid detection
- **Log Rotation** — Automatic rotation with size/backup limits
- **YAML Configuration** — Full config via `honeypot.yaml`
- **Docker Support** — Containerized deployment with docker-compose
- **SFTP Simulation** — Fake file transfer environment
- **Prometheus Metrics** — /metrics endpoint for monitoring

## Features

| Feature | Description |
|---------|-------------|
| SSH Simulation | Realistic OpenSSH banner spoofing with dynamic fingerprint rotation |
| Auth Logging | Captures username, password, key fingerprint, method, timestamp |
| Command Capture | Fake shell records every command attackers execute |
| Geolocation | IP → location mapping (offline GeoIP2 or free ip-api.com API) |
| Threat Scoring | Multi-source threat intelligence scoring (0-10) |
| MITRE ATT&CK | Auto-classifies attacks to TTP framework (T1110, T1059, T1098, etc.) |
| Alerts | Webhook, Slack, Discord, SMTP email notifications |
| Dashboard | Real-time web UI with stats, top IPs, recent attacks |
| Rate Limiting | Per-IP connection limit with automatic temp bans |
| IP Filtering | Whitelist/blacklist by IP or CIDR range |
| Database | SQLite for structured querying and analytics |
| Docker | Containerized via Dockerfile + docker-compose |
| macOS .app | Native macOS application support |

## Quick Start

### Installation

```bash
git clone https://github.com/Dev9269/ssh-honeypot.git
cd ssh-honeypot
pip install -r requirements.txt
```

### Basic Usage

```bash
python main.py
```

### With Dashboard

```bash
python main.py --dashboard
# Open http://127.0.0.1:8080 (user: admin, pass: admin)
```

### With YAML Config

```bash
python main.py --config honeypot.yaml
```

## Command Line Options

```
python main.py --help

Options:
  --host HOST           Host interface (default: 0.0.0.0)
  --port PORT           Port (default: 2222)
  --config CONFIG       Path to YAML config file
  --dashboard           Enable web dashboard
  --no-shell            Disable fake shell
  --no-geo              Disable geolocation
  --no-db               Disable database logging
  --blacklist BLACKLIST Comma separated IPs/CIDRs to block
  --whitelist WHITELIST Comma separated IPs/CIDRs to allow
  --version             Show version
```

## Console Output

```
[*] SSH Honeypot v2.0.0 listening on 0.0.0.0:2222
[*] Fake banner: SSH-2.0-OpenSSH_7.9p1 Debian-10
[*] Logs: logs/attacks.log, logs/attacks.json
[*] Database: logs/honeypot.db
[*] Geolocation: enabled
[*] Threat Intelligence: enabled
[*] Alerts: enabled
[*] Fake Shell: enabled (ubuntu-server)
[*] Dashboard: http://127.0.0.1:8080
[*] Press Ctrl+C to stop
[+] Connection from 192.168.1.100:54321 [New York, US] [threat: 6/10]
[+] Connection from 10.0.0.5:12345 [London, GB] [threat: 0/10]
[!] Rate limit exceeded for 203.0.113.5
[-] Connection closed from 192.168.1.100 (duration: 12.5s)
```

## Fake Shell Example

When an attacker connects (the honeypot rejects auth but still serves a shell):

```
Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2025 x86_64 GNU/Linux

root@ubuntu-server:/root$ whoami
root
root@ubuntu-server:/root$ id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu-server:/root$ uname -a
Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP...
root@ubuntu-server:/root$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
root@ubuntu-server:/root$ exit
logout
```

All commands are logged to `attacks.log`, `attacks.json`, and the SQLite database with MITRE ATT&CK classifications.

## Docker Deployment

```bash
# Build and run
docker-compose up --build

# Or build manually
docker build -t ssh-honeypot .
docker run -d -p 2222:2222 -p 8080:8080 ssh-honeypot
```

## Project Structure

```
ssh-honeypot/
├── honeypot/
│   ├── __init__.py
│   ├── server.py       # SSH server + client handler
│   ├── shell.py        # Fake shell with command responses
│   ├── config.py       # Configuration (YAML + defaults)
│   ├── logger.py       # Logging (.log, .json, rotation)
│   ├── db.py           # SQLite database backend
│   ├── geo.py          # IP geolocation (GeoIP2 + ip-api.com)
│   ├── intel.py        # Threat intelligence (AbuseIPDB, OTX, VT)
│   ├── alerts.py       # Alerting (webhook, Slack, Discord, email)
│   ├── ratelimiter.py  # Per-IP rate limiter with auto-ban
│   ├── analyzer.py     # MITRE ATT&CK framework mapping
│   ├── dashboard.py    # FastAPI web dashboard
│   └── sftp_server.py  # SFTP simulation
├── logs/               # Attack logs + database
├── main.py             # Entry point
├── honeypot.yaml       # YAML configuration
├── Dockerfile          # Docker build
├── docker-compose.yml  # Docker compose
├── requirements.txt    # Python dependencies
└── README.md
```

## Configuration (YAML)

All settings can be configured via `honeypot.yaml`:

```yaml
server:
  host: 0.0.0.0
  port: 2222

rate_limit:
  max_connections: 10
  window: 60
  ban_duration: 300

alerts:
  enabled: true
  slack_webhook: "https://hooks.slack.com/services/..."
  discord_webhook: "https://discord.com/api/webhooks/..."
  min_severity: medium
```

See the full `honeypot.yaml` file for all options.

## Log Files

### attacks.log (Human-readable)
```
2026-06-24 14:30:22,123 - IP: 192.168.1.100 | Username: root | Password: password123 | Method: password | MITRE: T1110:Brute Force
2026-06-24 14:30:45,678 - Activity | IP: 10.0.0.5 | command: whoami
```

### attacks.json (Structured)
```json
[
  {
    "event": "auth_attempt",
    "timestamp": "2026-06-24T14:30:22.123456",
    "ip": "192.168.1.100",
    "username": "root",
    "password": "password123",
    "method": "password",
    "mitre": "T1110:Brute Force"
  }
]
```

### SQLite Database
Query attack data directly:
```bash
sqlite3 logs/honeypot.db "SELECT ip, username, password FROM auth_attempts ORDER BY timestamp DESC LIMIT 10;"
```

## MITRE ATT&CK Coverage

| Technique | ID | Detected By |
|-----------|----|-------------|
| Brute Force | T1110 | Password auth attempts |
| Account Manipulation | T1098 | SSH key auth attempts |
| Command & Scripting | T1059 | Shell command execution |
| Network Discovery | T1046 | Recon commands (nmap, etc.) |
| Remote Services | T1021 | Lateral movement commands |
| Privilege Escalation | T1068 | sudo/chown commands |
| Defense Evasion | T1562 | rm -rf, shutdown, etc. |
| Data Collection | T1005 | tar, zip, find commands |

## Security Notice

**This tool is for authorized security research and education only.**

- Deploy only on networks you own or have permission to monitor
- Comply with all applicable laws
- The author assumes no liability for misuse

## License

MIT License — see [LICENSE](LICENSE)

## Acknowledgments

- [Paramiko](https://www.paramiko.org/) — SSH protocol library
- [MaxMind GeoIP2](https://www.maxmind.com/) — Geolocation data
- [AbuseIPDB](https://www.abuseipdb.com/) — Threat intelligence
- [MITRE ATT&CK](https://attack.mitre.org/) — TTP framework
