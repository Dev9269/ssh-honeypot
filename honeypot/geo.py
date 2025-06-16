import socket
import struct
import requests
from typing import Optional, Dict, Any
from functools import lru_cache

from . import config


class GeoIP:

    def __init__(self):
        self._reader = None
        self._available = False
        self._init_db()

    def _init_db(self):
        if not config.GEO_ENABLED:
            return
        try:
            if os.path.exists(config.GEO_DB_PATH):
                import geoip2.database
                self._reader = geoip2.database.Reader(config.GEO_DB_PATH)
                self._available = True
                return
        except Exception:
            pass

    @lru_cache(maxsize=1000)

    def lookup(self, ip: str) -> Dict[str, str]:
        result = {'country': '', 'city': '', 'asn': '', 'isp': '', 'lat': 0.0, 'lon': 0.0}
        if not self._available:
            return result
        try:
            response = self._reader.city(ip)
            result['country'] = response.country.name or ''
            result['city'] = response.city.name or ''
            if response.location:
                result['lat'] = response.location.latitude or 0.0
                result['lon'] = response.location.longitude or 0.0
        except Exception:
            pass
        try:
            asn_reader = getattr(self, '_asn_reader', None)
            if asn_reader is None:
                asn_path = config.GEO_DB_PATH.replace('City', 'ASN')
                if os.path.exists(asn_path):
                    import geoip2.database
                    self._asn_reader = geoip2.database.Reader(asn_path)
                    asn_reader = self._asn_reader
            if asn_reader:
                response = asn_reader.asn(ip)
                result['asn'] = f"AS{response.autonomous_system_number}"
                result['isp'] = response.autonomous_system_organization or ''
        except Exception:
            pass
        return result

    def lookup_online(self, ip: str) -> Dict[str, str]:
        result = {'country': '', 'city': '', 'asn': '', 'isp': ''}
        try:
            resp = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success':
                    result['country'] = data.get('country', '')
                    result['city'] = data.get('city', '')
                    result['asn'] = f"AS{data.get('as', '').split()[0]}" if data.get('as') else ''
                    result['isp'] = data.get('isp', '')
        except Exception:
            pass
        return result


import os

_geo_instance: Optional[GeoIP] = None


def get_geo() -> GeoIP:
    global _geo_instance
    if _geo_instance is None:
        _geo_instance = GeoIP()
    return _geo_instance
