import sqlite3
import os
import threading
from datetime import datetime
from typing import Optional, List, Dict, Any
from . import config

_local = threading.local()


def _get_connection() -> sqlite3.Connection:
    if hasattr(_local, 'conn') and _local.conn is not None:
        try:
            _local.conn.execute("SELECT 1")
            return _local.conn
        except (sqlite3.ProgrammingError, sqlite3.OperationalError):
            try:
                _local.conn.close()
            except Exception:
                pass
            _local.conn = None
    db_dir = os.path.dirname(config.DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    _local.conn = sqlite3.connect(config.DB_PATH)
    _local.conn.row_factory = sqlite3.Row
    _local.conn.execute("PRAGMA journal_mode=WAL")
    _local.conn.execute("PRAGMA busy_timeout=5000")
    return _local.conn


def init_db():
    conn = _get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS auth_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT NOT NULL,
            username TEXT,
            password TEXT,
            method TEXT,
            country TEXT,
            city TEXT,
            asn TEXT,
            isp TEXT,
            threat_score INTEGER DEFAULT 0,
            mitre_techniques TEXT,
            severity TEXT,
            raw_data TEXT
        );
        CREATE TABLE IF NOT EXISTS session_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT NOT NULL,
            username TEXT,
            activity TEXT,
            command TEXT,
            mitre_techniques TEXT
        );
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT NOT NULL,
            username TEXT,
            command TEXT NOT NULL,
            response TEXT,
            mitre_techniques TEXT
        );
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            reason TEXT,
            blocked_at TEXT NOT NULL,
            expires_at TEXT,
            permanent INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER,
            session_duration REAL,
            closed_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_auth_ip ON auth_attempts(ip);
        CREATE INDEX IF NOT EXISTS idx_auth_ts ON auth_attempts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_cmd_ip ON commands(ip);
        CREATE INDEX IF NOT EXISTS idx_session_ip ON session_activity(ip);
    """)
    conn.commit()


def insert_auth_attempt(ip: str, username: str, password: str, method: str,
                        country: str = '', city: str = '', asn: str = '',
                        threat_score: int = 0, mitre_techniques: str = '',
                        severity: str = '', raw_data: str = ''):
    try:
        conn = _get_connection()
        conn.execute(
            """INSERT INTO auth_attempts
               (timestamp, ip, username, password, method, country, city, asn, threat_score, mitre_techniques, severity, raw_data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (datetime.now().isoformat(), ip, username, password, method,
             country, city, asn, threat_score, mitre_techniques, severity, raw_data)
        )
        conn.commit()
    except Exception:
        pass


def insert_command(ip: str, username: str, command: str, response: str = '',
                   mitre_techniques: str = ''):
    try:
        conn = _get_connection()
        conn.execute(
            "INSERT INTO commands (timestamp, ip, username, command, response, mitre_techniques) VALUES (?, ?, ?, ?, ?, ?)",
            (datetime.now().isoformat(), ip, username, command, response, mitre_techniques)
        )
        conn.commit()
    except Exception:
        pass


def insert_session_activity(ip: str, username: str, activity: str, mitre_techniques: str = ''):
    try:
        conn = _get_connection()
        conn.execute(
            "INSERT INTO session_activity (timestamp, ip, username, activity, mitre_techniques) VALUES (?, ?, ?, ?, ?)",
            (datetime.now().isoformat(), ip, username, activity, mitre_techniques)
        )
        conn.commit()
    except Exception:
        pass


def insert_connection(ip: str, port: int):
    try:
        conn = _get_connection()
        conn.execute(
            "INSERT INTO connections (timestamp, ip, port) VALUES (?, ?, ?)",
            (datetime.now().isoformat(), ip, port)
        )
        conn.commit()
        return conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    except Exception:
        return None


def update_connection_end(conn_id: int, duration: float):
    try:
        conn = _get_connection()
        conn.execute(
            "UPDATE connections SET closed_at = ?, session_duration = ? WHERE id = ?",
            (datetime.now().isoformat(), duration, conn_id)
        )
        conn.commit()
    except Exception:
        pass


def is_ip_blocked(ip: str) -> bool:
    try:
        conn = _get_connection()
        row = conn.execute(
            "SELECT expires_at, permanent FROM blocked_ips WHERE ip = ?", (ip,)
        ).fetchone()
        if row is None:
            return False
        if row['permanent']:
            return True
        if row['expires_at']:
            expires = datetime.fromisoformat(row['expires_at'])
            if datetime.now() > expires:
                conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
                conn.commit()
                return False
        return True
    except Exception:
        return False


def block_ip(ip: str, reason: str = '', duration: int = 300):
    try:
        conn = _get_connection()
        expires = datetime.now().isoformat() if duration == 0 else \
            datetime.fromtimestamp(datetime.now().timestamp() + duration).isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at, expires_at, permanent) VALUES (?, ?, ?, ?, ?)",
            (ip, reason, datetime.now().isoformat(), expires, 1 if duration == 0 else 0)
        )
        conn.commit()
    except Exception:
        pass


def get_stats() -> Dict[str, Any]:
    try:
        conn = _get_connection()
        total_attempts = conn.execute("SELECT COUNT(*) FROM auth_attempts").fetchone()[0]
        unique_ips = conn.execute("SELECT COUNT(DISTINCT ip) FROM auth_attempts").fetchone()[0]
        top_usernames = [dict(r) for r in conn.execute(
            "SELECT username, COUNT(*) as count FROM auth_attempts WHERE username != '' GROUP BY username ORDER BY count DESC LIMIT 10"
        ).fetchall()]
        top_passwords = [dict(r) for r in conn.execute(
            "SELECT password, COUNT(*) as count FROM auth_attempts WHERE password != '' GROUP BY password ORDER BY count DESC LIMIT 10"
        ).fetchall()]
        top_ips = [dict(r) for r in conn.execute(
            "SELECT ip, COUNT(*) as count FROM auth_attempts GROUP BY ip ORDER BY count DESC LIMIT 10"
        ).fetchall()]
        recent = [dict(r) for r in conn.execute(
            "SELECT * FROM auth_attempts ORDER BY timestamp DESC LIMIT 50"
        ).fetchall()]
        return {
            'total_attempts': total_attempts,
            'unique_ips': unique_ips,
            'top_usernames': top_usernames,
            'top_passwords': top_passwords,
            'top_ips': top_ips,
            'recent': recent,
        }
    except Exception:
        return {}
