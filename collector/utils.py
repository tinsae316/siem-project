# collector/utils.py
import socket
import geoip2.database
from datetime import datetime
import os

# Path to your GeoLite2 database (you need to download it separately)
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "./GeoLite2-City.mmdb")

# ---------- Time Helpers ----------
def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO8601 format with 'Z'."""
    return datetime.utcnow().isoformat() + "Z"

# ---------- Network Helpers ----------
def resolve_hostname(ip: str) -> str:
    """Try to resolve an IP to a hostname (reverse DNS)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def geo_lookup(ip: str) -> dict:
    """GeoIP lookup: returns country, region, city if found."""
    if not os.path.exists(GEOIP_DB_PATH):
        return {}
    try:
        reader = geoip2.database.Reader(GEOIP_DB_PATH)
        response = reader.city(ip)
        return {
            "country_name": response.country.name,
            "region_name": response.subdivisions.most_specific.name,
            "city_name": response.city.name
        }
    except Exception:
        return {}
