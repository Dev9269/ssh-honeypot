import requests
import json
import time
from typing import Dict, Any, Optional
from functools import lru_cache
from . import config


class ThreatIntel:

    def __init__(self):
        self._cache = {}
    @lru_cache(maxsize=500)
    def check_abuseipdb(self, ip: str) -> int:
        if not config.INTEL_ENABLED or not config.INTEL_ABUSEIPDB_KEY:
            return 0
        try:
            resp = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                params={'ipAddress': ip, 'maxAgeInDays': 90},
                headers={'Key': config.INTEL_ABUSEIPDB_KEY, 'Accept': 'application/json'},
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json().get('data', {})
                return data.get('abuseConfidenceScore', 0)
        except Exception:
            pass
        return 0
    def check_otx(self, ip: str) -> Dict[str, Any]:
        if not config.INTEL_ENABLED or not config.INTEL_OTX_KEY:
            return {}
        try:
            resp = requests.get(
                f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general',
                headers={'X-OTX-API-Key': config.INTEL_OTX_KEY},
                timeout=5
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return {}

    def get_threat_score(self, ip: str) -> int:
        score = 0
        ab = self.check_abuseipdb(ip)
        if ab > 75:
            score += 3
        elif ab > 50:
            score += 2
        elif ab > 25:
            score += 1

        try:
            resp = requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                              headers={'x-apikey': config.INTEL_ABUSEIPDB_KEY},
                              timeout=5)
            if resp.status_code == 200:
                stats = resp.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                if malicious > 5:
                    score += 3
                elif malicious > 2:
                    score += 2
                elif malicious > 0:
                    score += 1
        except Exception:
            pass

        return min(score, 10)

    def get_severity(self, score: int) -> str:
        if score >= 7:
            return 'critical'
        if score >= 5:
            return 'high'
        if score >= 3:
            return 'low'
        if score >= 1:
            return 'low'
        return 'info'


_intel_instance: Optional[ThreatIntel] = None


def get_intel() -> ThreatIntel:
    global _intel_instance
    if _intel_instance is None:
        _intel_instance = ThreatIntel()
    return _intel_instance
