import json
import logging
import os
import threading
from datetime import datetime
from typing import Optional
from . import config

"""
Owner: Jainammaru_
GitHub: https://github.com/Dev9269
Instagram: https://www.instagram.com/jainammaru_/
LinkedIn: https://www.linkedin.com/in/jainam-maru-007803386/
"""
# Created by: jainam maru

_LOCK = threading.Lock()

class HoneypotLogger:
    def __init__(self):
        # Ensure log directory exists
        os.makedirs(config.LOG_DIR, exist_ok=True)

        # Setup file logger for attacks.log
        self.file_logger = logging.getLogger('honeypot_file_logger')
        self.file_logger.setLevel(logging.INFO)
        if not self.file_logger.handlers:
            fh = logging.FileHandler(config.LOG_FILE, encoding='utf-8')
            fh.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(message)s')
            fh.setFormatter(formatter)
            self.file_logger.addHandler(fh)

        # Ensure JSON log file exists and is a valid JSON array
        self.json_log_file = config.JSON_LOG_FILE
        try:
            with open(self.json_log_file, 'r', encoding='utf-8') as f:
                json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            with open(self.json_log_file, 'w', encoding='utf-8') as f:
                json.dump([], f, indent=4)

    def log_attempt(self, ip: str, username: str, password: str, method: str = 'password', timestamp: str = None):
        """Log an authentication attempt to both .log and .json files."""
        if timestamp is None:
            timestamp = datetime.now().isoformat()

        username = username or ''
        password = password or ''

        log_entry = {
            'event': 'auth_attempt',
            'timestamp': timestamp,
            'ip': ip,
            'username': username,
            'password': password,
            'method': method,
        }

        # Log to the human-readable file
        message = f"IP: {ip} | Username: {username} | Password: {password} | Method: {method}"
        self.file_logger.info(message)

        # Log to the structured JSON file in a thread-safe way
        with _LOCK:
            try:
                with open(self.json_log_file, 'r+', encoding='utf-8') as f:
                    data = json.load(f)
                    data.append(log_entry)
                    f.seek(0)
                    json.dump(data, f, indent=4)
                    f.truncate()
            except (json.JSONDecodeError, FileNotFoundError):
                with open(self.json_log_file, 'w', encoding='utf-8') as f:
                    json.dump([log_entry], f, indent=4)

    def log_session_activity(self, ip: str, activity: str, username: str = None, timestamp: str = None):
        """Log session activity (e.g., command attempts)."""
        if timestamp is None:
            timestamp = datetime.now().isoformat()

        entry = {
            'event': 'session_activity',
            'timestamp': timestamp,
            'ip': ip,
            'username': username or '',
            'activity': activity,
        }

        self.file_logger.info(f"Activity | IP: {ip} | {activity}")
        with _LOCK:
            try:
                with open(self.json_log_file, 'r+', encoding='utf-8') as f:
                    data = json.load(f)
                    data.append(entry)
                    f.seek(0)
                    json.dump(data, f, indent=4)
                    f.truncate()
            except (json.JSONDecodeError, FileNotFoundError):
                with open(self.json_log_file, 'w', encoding='utf-8') as f:
                    json.dump([entry], f, indent=4)


_default_logger: Optional[HoneypotLogger] = None


def get_logger() -> HoneypotLogger:
    global _default_logger
    if _default_logger is None:
        _default_logger = HoneypotLogger()
    return _default_logger