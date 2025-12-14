import pyshark
import ipaddress
import geoip2.database

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
GEOIP_DB = BASE_DIR / "GeoLite2-Country.mmdb"

def analyze_ips(path: str):
    try:
        capture = pyshark.FileCapture(path, keep_packets=False)
    except Exception as e:
        return {
            "success": False,
            "message": f"Błąd podczas analizy IP: {e}"
        }

    public_ips = set()
    country_stats = {}

    reader = geoip2.database.Reader(GEOIP_DB)

    try:
        for pkt in capture:
            if "ip" in pkt:
                src = pkt.ip.src
                dst = pkt.ip.dst

                for ip in (src, dst):
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if ip_obj.is_private:
                            continue
                    except:
                        continue

                    public_ips.add(ip)

                    try:
                        country = reader.country(ip).country.iso_code or "UNKNOWN"
                    except:
                        country = "UNKNOWN"

                    country_stats[country] = country_stats.get(country, 0) + 1

    except Exception:
        pass

    capture.close()

    return {
        "success": True,
        "public_ips": sorted(list(public_ips)),
        "country_stats": country_stats
    }
