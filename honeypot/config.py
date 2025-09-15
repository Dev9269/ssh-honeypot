import os
import yaml
from typing import List, Optional
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST = '0.0.0.0'
PORT = 2222
LOG_DIR = os.path.join(ROOT_DIR, 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'attacks.log')
JSON_LOG_FILE = os.path.join(LOG_DIR, 'attacks.json')
HOST_KEY_PATH = os.path.join(LOG_DIR, 'host_key.pem')
SSH_BANNER = 'SSH-2.0-OpenSSH_7.9p1 Debian-10'
AUTH_DELAY = 2
BACKLOG = 5
BUFFER_SIZE = 1024
ENCODING = 'utf-8'
BLACKLIST = []
WHITELIST = []
RATE_LIMIT_MAX_CONNECTIONS = 10
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_BAN_DURATION = 300
SHELL_ENABLED = True
SHELL_HOSTNAME = 'ubuntu-server'
SHELL_PROMPT = '$ '
SHELL_BANNER = 'Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux\r\n'
SFTP_ENABLED = True
SFTP_ROOT = os.path.join(ROOT_DIR, 'sftp_root')
GEO_ENABLED = True
GEO_DB_PATH = os.path.join(ROOT_DIR, 'data', 'GeoLite2-City.mmdb')
INTEL_ENABLED = False
INTEL_ABUSEIPDB_KEY = ''
INTEL_OTX_KEY = ''
INTEL_CACHE_TTL = 3600

ALERT_ENABLED = False
ALERT_WEBHOOK_URL = ''
ALERT_SLACK_WEBHOOK = ''
ALERT_DISCORD_WEBHOOK = ''
ALERT_EMAIL_SMTP = ''
ALERT_EMAIL_PORT = 587
ALERT_EMAIL_USER = ''
ALERT_EMAIL_PASS = ''
ALERT_EMAIL_TO = ''
ALERT_EMAIL_FROM = 'honeypot@localhost'
ALERT_MIN_SEVERITY = 'low'

DB_ENABLED = True
DB_PATH = os.path.join(LOG_DIR, 'honeypot.db')

DASHBOARD_ENABLED = False
DASHBOARD_HOST = '127.0.0.1'
DASHBOARD_PORT = 8080
DASHBOARD_USER = 'admin'
DASHBOARD_PASSWORD = 'admin'

METRICS_ENABLED = False
METRICS_PORT = 9090

LOG_ROTATION_ENABLED = True
LOG_MAX_SIZE_MB = 50
LOG_BACKUP_COUNT = 5

MITRE_ENABLED = True

AI_ENABLED = False
AI_MODE = 'ollama'
AI_OLLAMA_ENDPOINT = 'http://127.0.0.1:11434'
AI_MODEL = 'llama3.1:8b'
AI_TIMEOUT = 10
AI_STREAM = True
AI_MAX_HISTORY = 5
AI_ACCEPT_ANY_AUTH = True
AI_FALLBACK_TO_STATIC = True
AI_SYSTEM_PROMPT = (
    'You are a real, vulnerable Linux terminal running Debian 12. '
    'Simulate a live OS shell environment perfectly. '
    'Act as an SSH honeypot. '
    'Respond ONLY with raw terminal output. '
    'Do not include markdown code blocks, pleasantries, explanations, or conversational AI filler. '
    'If an attacker types an invalid command, output the exact standard Linux error '
    '(e.g., "bash: command not found"). '
    'Keep responses short, blunt, and authentic to a bash shell.'
)

FINGERPRINT_BANNERS = [
    'SSH-2.0-OpenSSH_7.9p1 Debian-10',
    'SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2',
    'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3',
    'SSH-2.0-OpenSSH_6.6.1',
    'SSH-2.0-OpenSSH_5.3',
    'SSH-2.0-OpenSSH_9.3p1 FreeBSD-20231021',
]


def load_yaml_config(config_path: Optional[str] = None) -> bool:
    if config_path is None:
        config_path = os.path.join(ROOT_DIR, 'honeypot.yaml')
    if not os.path.exists(config_path):
        return False

    with open(config_path, 'r') as f:
        cfg = yaml.safe_load(f)

    if not cfg:
        return False

    g = globals()
    server = cfg.get('server', {})
    g['HOST'] = server.get('host', HOST)
    g['PORT'] = server.get('port', PORT)

    auth = cfg.get('auth', {})
    g['AUTH_DELAY'] = auth.get('delay', AUTH_DELAY)

    ip_filter = cfg.get('ip_filter', {})
    g['WHITELIST'] = ip_filter.get('whitelist', WHITELIST)
    g['BLACKLIST'] = ip_filter.get('blacklist', BLACKLIST)

    rate = cfg.get('rate_limit', {})
    g['RATE_LIMIT_MAX_CONNECTIONS'] = rate.get('max_connections', RATE_LIMIT_MAX_CONNECTIONS)
    g['RATE_LIMIT_WINDOW'] = rate.get('window', RATE_LIMIT_WINDOW)
    g['RATE_LIMIT_BAN_DURATION'] = rate.get('ban_duration', RATE_LIMIT_BAN_DURATION)

    shell = cfg.get('shell', {})
    g['SHELL_ENABLED'] = shell.get('enabled', SHELL_ENABLED)
    g['SHELL_HOSTNAME'] = shell.get('hostname', SHELL_HOSTNAME)
    g['SHELL_PROMPT'] = shell.get('prompt', SHELL_PROMPT)
    g['SHELL_BANNER'] = shell.get('banner', SHELL_BANNER)

    sftp_cfg = cfg.get('sftp', {})
    g['SFTP_ENABLED'] = sftp_cfg.get('enabled', SFTP_ENABLED)
    g['SFTP_ROOT'] = sftp_cfg.get('root', SFTP_ROOT)

    geo = cfg.get('geo', {})
    g['GEO_ENABLED'] = geo.get('enabled', GEO_ENABLED)
    g['GEO_DB_PATH'] = geo.get('db_path', GEO_DB_PATH)

    intel = cfg.get('threat_intel', {})
    g['INTEL_ENABLED'] = intel.get('enabled', INTEL_ENABLED)
    g['INTEL_ABUSEIPDB_KEY'] = intel.get('abuseipdb_key', INTEL_ABUSEIPDB_KEY)
    g['INTEL_OTX_KEY'] = intel.get('otx_key', INTEL_OTX_KEY)

    alert = cfg.get('alerts', {})
    g['ALERT_ENABLED'] = alert.get('enabled', ALERT_ENABLED)
    g['ALERT_WEBHOOK_URL'] = alert.get('webhook_url', ALERT_WEBHOOK_URL)
    g['ALERT_SLACK_WEBHOOK'] = alert.get('slack_webhook', ALERT_SLACK_WEBHOOK)
    g['ALERT_DISCORD_WEBHOOK'] = alert.get('discord_webhook', ALERT_DISCORD_WEBHOOK)
    g['ALERT_EMAIL_SMTP'] = alert.get('email_smtp', ALERT_EMAIL_SMTP)
    g['ALERT_EMAIL_PORT'] = alert.get('email_port', ALERT_EMAIL_PORT)
    g['ALERT_EMAIL_USER'] = alert.get('email_user', ALERT_EMAIL_USER)
    g['ALERT_EMAIL_PASS'] = alert.get('email_pass', ALERT_EMAIL_PASS)
    g['ALERT_EMAIL_TO'] = alert.get('email_to', ALERT_EMAIL_TO)
    g['ALERT_EMAIL_FROM'] = alert.get('email_from', ALERT_EMAIL_FROM)
    g['ALERT_MIN_SEVERITY'] = alert.get('min_severity', ALERT_MIN_SEVERITY)

    db = cfg.get('database', {})
    g['DB_ENABLED'] = db.get('enabled', DB_ENABLED)
    g['DB_PATH'] = db.get('path', DB_PATH)

    dash = cfg.get('dashboard', {})
    g['DASHBOARD_ENABLED'] = dash.get('enabled', DASHBOARD_ENABLED)
    g['DASHBOARD_HOST'] = dash.get('host', DASHBOARD_HOST)
    g['DASHBOARD_PORT'] = dash.get('port', DASHBOARD_PORT)
    g['DASHBOARD_USER'] = dash.get('user', DASHBOARD_USER)
    g['DASHBOARD_PASSWORD'] = dash.get('password', DASHBOARD_PASSWORD)

    metrics = cfg.get('metrics', {})
    g['METRICS_ENABLED'] = metrics.get('enabled', METRICS_ENABLED)
    g['METRICS_PORT'] = metrics.get('port', METRICS_PORT)

    log = cfg.get('log_rotation', {})
    g['LOG_ROTATION_ENABLED'] = log.get('enabled', LOG_ROTATION_ENABLED)
    g['LOG_MAX_SIZE_MB'] = log.get('max_size_mb', LOG_MAX_SIZE_MB)
    g['LOG_BACKUP_COUNT'] = log.get('backup_count', LOG_BACKUP_COUNT)

    g['MITRE_ENABLED'] = cfg.get('mitre', {}).get('enabled', MITRE_ENABLED)

    ai = cfg.get('ai', {})
    g['AI_ENABLED'] = ai.get('enabled', AI_ENABLED)
    g['AI_MODE'] = ai.get('mode', AI_MODE)
    g['AI_OLLAMA_ENDPOINT'] = ai.get('ollama_endpoint', AI_OLLAMA_ENDPOINT)
    g['AI_MODEL'] = ai.get('model', AI_MODEL)
    g['AI_TIMEOUT'] = ai.get('timeout', AI_TIMEOUT)
    g['AI_STREAM'] = ai.get('stream', AI_STREAM)
    g['AI_MAX_HISTORY'] = ai.get('max_history', AI_MAX_HISTORY)
    g['AI_ACCEPT_ANY_AUTH'] = ai.get('accept_any_auth', AI_ACCEPT_ANY_AUTH)
    g['AI_FALLBACK_TO_STATIC'] = ai.get('fallback_to_static', AI_FALLBACK_TO_STATIC)
    g['AI_SYSTEM_PROMPT'] = ai.get('system_prompt', AI_SYSTEM_PROMPT)

    banners = cfg.get('fingerprint_banners', {})
    if banners.get('enabled', False):
        g['FINGERPRINT_BANNERS'] = banners.get('banners', FINGERPRINT_BANNERS)

    return True
