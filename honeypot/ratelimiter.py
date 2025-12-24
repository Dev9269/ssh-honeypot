import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from . import config


class RateLimiter:

    def __init__(self):
        self._connections: dict = defaultdict(list)
        self._banned: dict = {}
        self._lock = threading.Lock()

    def is_allowed(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            if ip in self._banned:
                ban_until = self._banned[ip]
                if now < ban_until:
                    return False
                del self._banned[ip]
            timestamps = self._connections[ip]
            timestamps = [t for t in timestamps if now - t < config.RATE_LIMIT_WINDOW]
            if len(timestamps) >= config.RATE_LIMIT_MAX_CONNECTIONS:
                self._banned[ip] = now + config.RATE_LIMIT_BAN_DURATION
                del self._connections[ip]
                return False
            timestamps.append(now)
            self._connections[ip] = timestamps
        return True
    def get_remaining(self, ip: str) -> int:
        now = time.time()
        with self._lock:
            timestamps = [t for t in self._connections.get(ip, [])
                         if now - t < config.RATE_LIMIT_WINDOW]
            return max(0, config.RATE_LIMIT_MAX_CONNECTIONS - len(timestamps))

    def reset(self, ip: str):
        with self._lock:
            self._connections.pop(ip, None)
            self._banned.pop(ip, None)


_limiter_instance = None


def get_limiter() -> RateLimiter:
    global _limiter_instance
    if _limiter_instance is None:
        _limiter_instance = RateLimiter()
    return _limiter_instance
