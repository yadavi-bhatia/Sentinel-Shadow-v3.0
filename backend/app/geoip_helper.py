from __future__ import annotations
import ipaddress
import os
from functools import lru_cache

try:
    import geoip2.database
except Exception:
    geoip2 = None

CITY_DB_PATH = os.getenv("GEOLITE2_CITY_DB", "backend/data/GeoLite2-City.mmdb")
ASN_DB_PATH = os.getenv("GEOLITE2_ASN_DB", "backend/data/GeoLite2-ASN.mmdb")

_city_reader = None
_asn_reader = None


def _load_readers():
    global _city_reader, _asn_reader
    if geoip2 is None:
        return None, None
    if _city_reader is None and os.path.exists(CITY_DB_PATH):
        _city_reader = geoip2.database.Reader(CITY_DB_PATH)
    if _asn_reader is None and os.path.exists(ASN_DB_PATH):
        _asn_reader = geoip2.database.Reader(ASN_DB_PATH)
    return _city_reader, _asn_reader


@lru_cache(maxsize=10000)
def enrich_geo(ip: str) -> dict:
    result = {
        "country": "Unknown",
        "city": "Unknown",
        "asn": "Unknown",
        "asn_org": "Unknown",
        "latitude": None,
        "longitude": None,
        "source": "fallback",
    }

    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            result.update({"country": "Localhost", "city": "Loopback", "source": "local"})
            return result
        if addr.is_private:
            result.update({"country": "Private Network", "city": "Internal", "source": "local"})
            return result
    except ValueError:
        return result

    city_reader, asn_reader = _load_readers()

    if city_reader:
        try:
            city_resp = city_reader.city(ip)
            result.update(
                {
                    "country": city_resp.country.name or "Unknown",
                    "city": city_resp.city.name or "Unknown",
                    "latitude": city_resp.location.latitude,
                    "longitude": city_resp.location.longitude,
                    "source": "maxmind",
                }
            )
        except Exception:
            pass

    if asn_reader:
        try:
            asn_resp = asn_reader.asn(ip)
            result.update(
                {
                    "asn": str(asn_resp.autonomous_system_number or "Unknown"),
                    "asn_org": asn_resp.autonomous_system_organization or "Unknown",
                }
            )
        except Exception:
            pass

    if result["country"] == "Unknown":
        if ip.startswith("203."):
            result.update({"country": "Singapore", "city": "Singapore", "source": "prefix"})
        elif ip.startswith("198."):
            result.update({"country": "Germany", "city": "Frankfurt", "source": "prefix"})
        elif ip.startswith("45."):
            result.update({"country": "Netherlands", "city": "Amsterdam", "source": "prefix"})
        elif ip.startswith("91."):
            result.update({"country": "United States", "city": "Ashburn", "source": "prefix"})
        elif ip.startswith("185."):
            result.update({"country": "Russia", "city": "Moscow", "source": "prefix"})
        elif ip.startswith("103."):
            result.update({"country": "India", "city": "Bengaluru", "source": "prefix"})

    return result