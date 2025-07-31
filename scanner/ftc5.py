import subprocess
import requests
from typing import Tuple, List

def ftc5_dns(domain: str) -> Tuple[str, List[str], str]:
    """
    Get www subdomain CNAME, NS records list, and DNS provider(s).
    """
    # CNAME for www
    subcname = "None"
    try:
        out = subprocess.getoutput(f"nslookup -type=CNAME www.{domain}")
        for line in out.splitlines():
            if "canonical name =" in line.lower():
                subcname = line.split("=",1)[1].strip().rstrip(".")
                break
    except Exception:
        pass

    # NS records
    nss: List[str] = []
    providers = set()
    try:
        out = subprocess.getoutput(f"nslookup -type=NS {domain}")
        for line in out.splitlines():
            if "nameserver =" in line.lower():
                ns = line.split("=",1)[1].strip().rstrip(".")
                nss.append(ns)
                if "." in ns:
                    providers.add(ns.split(".",1)[1])
    except Exception:
        pass

    return subcname, nss, ", ".join(sorted(providers)) or "None"
