import json
import logging
import os
import threading
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Optional
from . import config
_LOCK = threading.Lock()


class HoneypotLogger:

    def __init__(self):
        os.makedirs(config.LOG_DIR, exist_ok=True)
        self.file_logger = logging.getLogger('honeypot_file_logger')
        self.file_logger.setLevel(logging.INFO)
        if not self.file_logger.handlers:
            if config.LOG_ROTATION_ENABLED:
                fh = RotatingFileHandler(
                    config.LOG_FILE, maxBytes=config.LOG_MAX_SIZE_MB * 1024 * 1024,
                    backupCount=config.LOG_BACKUP_COUNT, encoding='utf-8'
                )
            else:
                fh = logging.FileHandler(config.LOG_FILE, encoding='utf-8')
            fh.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(message)s')
            fh.setFormatter(formatter)
            self.file_logger.addHandler(fh)
        self.json_log_file = config.JSON_LOG_FILE
        try:
            with open(self.json_log_file, 'r', encoding='utf-8') as f:
                json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            with open(self.json_log_file, 'w', encoding='utf-8') as f:
                json.dump([], f, indent=4)

    def log_attempt(self, ip: str, username: str, password: str, method: str = 'password',
                    timestamp: str = None, mitre: str = ''):
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
        if mitre:
            log_entry['mitre'] = mitre
        msg = f"IP: {ip} | Username: {username} | Password: {password} | Method: {method}"
        if mitre:
            msg += f" | MITRE: {mitre}"
        self.file_logger.info(msg)
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
    def log_session_activity(self, ip: str, activity: str, username: str = None,
                             timestamp: str = None, mitre: str = ''):
        if timestamp is None:
            timestamp = datetime.now().isoformat()
        entry = {
            'event': 'session_activity',
            'timestamp': timestamp,
            'ip': ip,
            'username': username or '',
            'activity': activity,
        }
        if mitre:
            entry['mitre'] = mitre
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


    def close(self):
        for handler in self.file_logger.handlers[:]:
            handler.close()
            self.file_logger.removeHandler(handler)


_default_logger: Optional[HoneypotLogger] = None


def get_logger() -> HoneypotLogger:
    global _default_logger
    if _default_logger is None:
        _default_logger = HoneypotLogger()
    return _default_logger


def reset_logger():
    global _default_logger
    if _default_logger is not None:
        _default_logger.close()
        _default_logger = None
    named = logging.getLogger('honeypot_file_logger')
    for h in named.handlers[:]:
        h.close()
        named.removeHandler(h)
