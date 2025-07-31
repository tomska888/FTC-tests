import re
import shlex
import socket
import subprocess
import requests
from typing import Tuple, Dict, Any

# Regex to validate a single full IPv6 address
_IPV6_PATTERN = re.compile(
    r'((?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|'
    r'(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4})'
)

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

   # 2) IPv6 via nslookup -query=AAAA
    ipv6 = "None"
    try:
        cmd = f"nslookup -query=AAAA {domain}"
        out = subprocess.check_output(
            shlex.split(cmd),
            stderr=subprocess.DEVNULL,
            universal_newlines=True,
            timeout=10
        )
        # find all substrings matching the IPv6 pattern
        found = _IPV6_PATTERN.findall(out)
        if found:
            # de-duplicate while preserving order
            seen = []
            for addr in found:
                if addr not in seen:
                    seen.append(addr)
            ipv6 = ", ".join(seen)
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
