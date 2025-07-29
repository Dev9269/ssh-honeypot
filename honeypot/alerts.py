import requests
import json
import smtplib
import threading
from email.mime.text import MIMEText
from datetime import datetime
from typing import Dict, Any, Optional
from . import config


class AlertManager:
    def __init__(self):
        self._queue = []
        self._lock = threading.Lock()
    def _should_alert(self, severity: str) -> bool:
        levels = {'info': 0, 'low': 1, 'low': 2, 'high': 3, 'critical': 4}
        min_level = levels.get(config.ALERT_MIN_SEVERITY, 2)
        return levels.get(severity, 0) >= min_level
    def send_alert(self, title: str, message: str, severity: str = 'low', data: Dict = None):
        if not config.ALERT_ENABLED:
            return
        if not self._should_alert(severity):
            return

        payload = {
            'title': title,
            'message': message,
            'severity': severity,
            'timestamp': datetime.now().isoformat(),
            'data': data or {},
        }

        if config.ALERT_WEBHOOK_URL:
            self._send_webhook(payload)
        if config.ALERT_SLACK_WEBHOOK:
            self._send_slack(payload)
        if config.ALERT_DISCORD_WEBHOOK:
            self._send_discord(payload)
        if config.ALERT_EMAIL_SMTP:
            self._send_email(payload)

    def _send_webhook(self, payload: Dict):
        try:
            requests.post(config.ALERT_WEBHOOK_URL, json=payload, timeout=5)
        except Exception:
            pass

    def _send_slack(self, payload: Dict):
        try:
            color = {'info': '#3498db', 'low': '#f39c12', 'low': '#e67e22',
                     'high': '#e74c3c', 'critical': '#c0392b'}.get(payload['severity'], '#3498db')
            slack_payload = {
                'attachments': [{
                    'color': color,
                    'title': payload['title'],
                    'text': payload['message'],
                    'fields': [
                        {'title': 'Severity', 'value': payload['severity'], 'short': True},
                        {'title': 'Time', 'value': payload['timestamp'], 'short': True},
                    ],
                    'footer': 'SSH Honeypot',
                    'ts': datetime.now().timestamp(),
                }]
            }
            if payload.get('data'):
                for k, v in payload['data'].items():
                    slack_payload['attachments'][0]['fields'].append(
                        {'title': k, 'value': str(v), 'short': True}
                    )
            requests.post(config.ALERT_SLACK_WEBHOOK, json=slack_payload, timeout=5)
        except Exception:
            pass

    def _send_discord(self, payload: Dict):
        try:
            color_map = {'info': 3447003, 'low': 15105570, 'low': 15105570,
                         'high': 15158332, 'critical': 10038562}
            discord_payload = {
                'embeds': [{
                    'title': payload['title'],
                    'description': payload['message'],
                    'color': color_map.get(payload['severity'], 3447003),
                    'fields': [
                        {'name': 'Severity', 'value': payload['severity'], 'inline': True},
                        {'name': 'Time', 'value': payload['timestamp'], 'inline': True},
                    ],
                    'footer': {'text': 'SSH Honeypot'},
                    'timestamp': payload['timestamp'],
                }]
            }
            if payload.get('data'):
                for k, v in payload['data'].items():
                    discord_payload['embeds'][0]['fields'].append(
                        {'name': k, 'value': str(v)[:1024], 'inline': True}
                    )
            requests.post(config.ALERT_DISCORD_WEBHOOK, json=discord_payload, timeout=5)
        except Exception:
            pass

    def _send_email(self, payload: Dict):
        try:
            body = f"""
Title: {payload['title']}
Severity: {payload['severity']}
Time: {payload['timestamp']}

Message:
{payload['message']}
"""
            if payload.get('data'):
                body += "\n\nData:\n"
                for k, v in payload['data'].items():
                    body += f"  {k}: {v}\n"

            msg = MIMEText(body)
            msg['Subject'] = f"[Honeypot] {payload['severity'].upper()} - {payload['title']}"
            msg['From'] = config.ALERT_EMAIL_FROM
            msg['To'] = config.ALERT_EMAIL_TO

            with smtplib.SMTP(config.ALERT_EMAIL_SMTP, config.ALERT_EMAIL_PORT) as server:
                if config.ALERT_EMAIL_USER:
                    server.starttls()
                    server.login(config.ALERT_EMAIL_USER, config.ALERT_EMAIL_PASS)
                server.send_message(msg)
        except Exception:
            pass


_alert_instance: Optional[AlertManager] = None


def get_alerts() -> AlertManager:
    global _alert_instance
    if _alert_instance is None:
        _alert_instance = AlertManager()
    return _alert_instance
