import socket
import requests
from typing import Tuple, Dict, Any

def ftc4_geo(domain: str) -> Tuple[str, str, Dict[str, Any]]:
    """
    Resolve A/AAAA records, then enrich via ipinfo.io + restcountries.com.
    """
    # IPv4
    ipv4 = "None"
    try:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_INET)
        ipv4 = infos[0][4][0]
    except Exception:
        pass

    # IPv6
    ipv6 = "None"
    try:
        infos6 = socket.getaddrinfo(domain, None, family=socket.AF_INET6)
        ipv6 = infos6[0][4][0]
    except Exception:
        pass

    geo = {
        "country":   "None",
        "region":    "None",
        "city":      "None",
        "asn":       "Unavailable",
        "org":       "Unavailable",
    }

    if ipv4 != "None":
        try:
            r = requests.get(f"https://ipinfo.io/{ipv4}/json", timeout=5)
            r.raise_for_status()
            data = r.json()
            org_field = data.get("org", "")
            parts = org_field.split(" ", 1)
            geo["asn"] = parts[0]
            geo["org"] = parts[1] if len(parts) > 1 else geo["org"]
            geo["country"] = data.get("country", geo["country"])
            geo["region"]  = data.get("region",  geo["region"])
            geo["city"]    = data.get("city",    geo["city"])
        except Exception:
            pass


    return ipv4, ipv6, geo
