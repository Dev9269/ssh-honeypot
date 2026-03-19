# SSH Honeypot

A production-ready SSH honeypot implemented in Python using Paramiko. This tool is designed for cybersecurity professionals, researchers, and enthusiasts to study SSH attack patterns in a controlled environment.

## Created by: jainam maru

## What is a Honeypot?

A honeypot is a security mechanism designed to detect, deflect, or study attempts at unauthorized use of information systems. By appearing to be a legitimate target, honeypots attract attackers and allow security teams to monitor and analyze their tactics, techniques, and procedures (TTPs) without putting actual production systems at risk.

## Features

- **Realistic SSH Simulation**: Spoofs OpenSSH banner to appear legitimate
- **Comprehensive Logging**: Records all login attempts (username, password, IP, timestamp, method) in both `.log` and `.json` formats
- **Structured Events**: JSON log entries include event types (`auth_attempt`, `session_activity`) to make analysis easier
- **Safe by Design**: Always rejects authentication attempts - no real access is ever granted
- **Multi-threaded Architecture**: Handles multiple simultaneous connections efficiently
- **Configurable**: Customizable host, port, whitelist/blacklist, and authentication delay via command line arguments
- **Host Key Management**: Automatically generates or loads RSA host keys (stored in `logs/host_key.pem`)
- **Colored Console Output**: Optional colored terminal output (via `colorama`) for improved readability
- **Professional Structure**: Clean, modular code following Python best practices

## Technologies Used

- **Python 3.6+**: Core programming language
- **Paramiko**: SSH protocol implementation for Python
- **Standard Library**: Socket, threading, json, logging, argparse

## Installation

### Prerequisites
- Python 3.6 or higher
- pip (Python package installer)

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/ssh-honeypot.git
   cd ssh-honeypot
   ```
nmap -p 2222 127.0.0.1nmap -p 2222 127.0.0.1
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage
```bash
python main.py
```
This starts the honeypot on the default port 2222, listening on all interfaces (0.0.0.0).

### Custom Configuration
```bash
# Run on a specific port
python main.py --port 2222

# Bind to a specific interface
python main.py --host 192.168.1.100

# Combine options
python main.py --host 0.0.0.0 --port 2222

# Block a specific IP or CIDR range
python main.py --blacklist 203.0.113.5,192.0.2.0/24

# Allow only a specific IP range (whitelist overrides blacklist)
python main.py --whitelist 10.0.0.0/8
```

### Help
```bash
python main.py --help
```

## Example Output

When an attacker attempts to connect, you'll see console output like:
```
[*] SSH Honeypot listening on 0.0.0.0:2222
[*] Fake banner: SSH-2.0-OpenSSH_7.9p1 Debian-10
[*] Logs will be saved to logs/attacks.log and logs/attacks.json
[*] Press Ctrl+C to stop
[+] Connection from 192.168.1.100:54321
[-] Connection closed from 192.168.1.100
[+] Connection from 10.0.0.5:12345
[-] Connection closed from 10.0.0.5
```

### Log Files

#### attacks.log (Human-readable)
```
2026-03-19 14:30:22,123 - IP: 192.168.1.100 | Username: root | Password: password123
2026-03-19 14:30:45,678 - IP: 10.0.0.5 | Username: admin | Password: admin
2026-03-19 14:31:10,045 - IP: 192.168.1.100 | Username: root | Password: [SSH Key: a1b2c3d4e5f6...]
```

#### attacks.json (Structured)
```json
[
  {
    "event": "auth_attempt",
    "timestamp": "2026-03-19T14:30:22.123456",
    "ip": "192.168.1.100",
    "username": "root",
    "password": "password123",
    "method": "password"
  },
  {
    "event": "auth_attempt",
    "timestamp": "2026-03-19T14:30:45.678901",
    "ip": "10.0.0.5",
    "username": "admin",
    "password": "admin",
    "method": "password"
  }
]
```

## Project Structure

```
ssh-honeypot/
│
├── honeypot/
│   ├── __init__.py
│   ├── server.py       # Main SSH server implementation
│   ├── logger.py       # Logging functionality
│   └── config.py       # Configuration settings
│
├── logs/               # Directory for log files
│   ├── attacks.log     # Human-readable log
│   └── attacks.json    # Structured JSON log
│
├── main.py             # Entry point with CLI argument parsing
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

## Security Notice & Ethical Use

⚠️ **WARNING**: This tool is intended for **educational and ethical security research purposes only**. 

- Deploy this honeypot only on networks and systems you own or have explicit permission to monitor
- Do not use this tool to entrap or target individuals without consent
- Ensure compliance with all applicable laws and regulations in your jurisdiction
- The developers assume no liability for misuse of this software

## Future Improvements

Potential enhancements for future versions:

1. **Session Interaction**: Implement a fake shell to capture attacker commands
2. **Geolocation**: Add IP geolocation to attack logs
3. **Threat Intelligence Integration**: Auto-block known malicious IPs
4. **Real-time Alerts**: Email/SMS notifications for attacks
5. **Web Dashboard**: Visual interface for analyzing attack patterns
6. **Additional Protocols**: FTP, HTTP, or database honeypots
7. **Docker Support**: Containerized deployment for easier setup
8. **Advanced Fingerprinting**: More sophisticated OS/service simulation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Paramiko](https://www.paramiko.org/) for the excellent SSH library
- Open-source honeypot projects that inspired this implementation
- The cybersecurity community for sharing knowledge and techniques