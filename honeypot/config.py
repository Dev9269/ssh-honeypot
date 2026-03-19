# Configuration settings for the SSH Honeypot
"""
Owner: Jainammaru_
GitHub: https://github.com/Dev9269
Instagram: https://www.instagram.com/jainammaru_/
LinkedIn: https://www.linkedin.com/in/jainam-maru-007803386/
"""
# Created by: jainam maru

import os

# NOTE: Paths are resolved relative to the project root so the honeypot behaves consistently
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Server configuration
HOST = '0.0.0.0'  # Listen on all available interfaces
PORT = 2222       # Default port for the honeypot

# Logging configuration
LOG_DIR = os.path.join(ROOT_DIR, 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'attacks.log')
JSON_LOG_FILE = os.path.join(LOG_DIR, 'attacks.json')

# Host key configuration
# This is used to generate or load the SSH host key for the honeypot
HOST_KEY_PATH = os.path.join(LOG_DIR, 'host_key.pem')

# SSH Banner (fake OpenSSH version)
SSH_BANNER = 'SSH-2.0-OpenSSH_7.9p1 Debian-10'

# Authentication delay (in seconds) to simulate real server
AUTH_DELAY = 2

# Maximum number of pending connections
BACKLOG = 5

# Maximum size of data to receive at once
BUFFER_SIZE = 1024

# Encoding for communication
ENCODING = 'utf-8'

# Optional IP filtering (leave empty to disable)
BLACKLIST = []  # Example: ['192.0.2.1']
WHITELIST = []  # Example: ['10.0.0.0/8']
