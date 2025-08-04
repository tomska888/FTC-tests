import subprocess
from typing import Tuple, List

import dns.resolver


def ftc5_dns(domain: str) -> Tuple[str, List[str], str, str]:
    """
    Get www subdomain CNAME, NS records list, DNS provider(s), and CNAME provider.
    Uses dnspython for authoritative lookups, falls back to subprocess if needed.

    Args:
        domain: The target domain name.

    Returns:
        A tuple of (subcname, nss, ns_providers_str, cname_provider).
    """
    subcname = "None"
    nss: List[str] = []
    ns_providers = set()
    cname_provider = "None"

    # 1) Try library lookup for CNAME www.domain
    try:
        answers = dns.resolver.resolve(f'www.{domain}', 'CNAME')
        for rdata in answers:
            cname = rdata.target.to_text().rstrip('.')
            subcname = cname
            break
    except Exception:
        # fallback to nslookup
        try:
            out = subprocess.getoutput(f"nslookup -type=CNAME www.{domain}")
            for line in out.splitlines():
                if 'canonical name =' in line.lower():
                    subcname = line.split('=', 1)[1].strip().rstrip('.')
                    break
        except Exception:
            pass

    # Determine CNAME provider (second-level domain)
    if subcname != "None":
        parts = subcname.split('.', 1)
        if len(parts) > 1:
            cname_provider = parts[1]

    # 2) Try library lookup for NS records
    try:
        answers_ns = dns.resolver.resolve(domain, 'NS')
        for rdata in answers_ns:
            ns = rdata.target.to_text().rstrip('.')
            nss.append(ns)
            parts = ns.split('.', 1)
            if len(parts) > 1:
                ns_providers.add(parts[1])
    except Exception:
        # fallback to nslookup
        try:
            out = subprocess.getoutput(f"nslookup -type=NS {domain}")
            for line in out.splitlines():
                if 'nameserver =' in line.lower():
                    ns = line.split('=', 1)[1].strip().rstrip('.')
                    nss.append(ns)
                    if '.' in ns:
                        ns_providers.add(ns.split('.', 1)[1])
        except Exception:
            pass

    ns_providers_str = ", ".join(sorted(ns_providers)) or "None"
    return subcname, nss, ns_providers_str, cname_provider
