import socket
import dns.resolver
from typing import Optional, Tuple, Dict, Any
import ipinfo


def ftc4_geo(domain: str, ipinfo_token: Optional[str] = None) -> Tuple[str, str, Dict[str, Any]]:
    """
    Perform Geo-IP & ASN lookup for the given domain.
    Resolves IPv4 and AAAA (IPv6) records via socket and DNS queries, then enriches data using the ipinfo-python package.

    Args:
        domain: The target domain name.
        ipinfo_token: Optional API token for ipinfo.io (if not provided, uses public endpoints).

    Returns:
        A tuple of (ipv4, ipv6, geo_data) where:
          - ipv4: First resolved A record or 'None'.
          - ipv6: Comma-separated AAAA records or 'None'.
          - geo_data: Dict with keys 'asn', 'org', 'country', 'region', 'city'.
    """
    # Initialize default values
    ipv4 = "None"
    ipv6 = "None"
    geo = {
        "asn": "Unavailable",
        "org": "Unavailable",
        "country": "None",
        "region": "None",
        "city": "None",
    }

    # 1) Resolve IPv4 via socket
    try:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_INET)
        if infos:
            ipv4 = infos[0][4][0]
    except Exception:
        pass

    # 2) Resolve IPv6 (AAAA) via DNS query
    try:
        answers6 = dns.resolver.resolve(domain, 'AAAA')
        seen_v6 = []
        for rdata in answers6:
            addr = rdata.address if hasattr(rdata, 'address') else rdata.to_text()
            if addr not in seen_v6:
                seen_v6.append(addr)
        if seen_v6:
            ipv6 = ", ".join(seen_v6)
    except Exception:
        pass

    # 3) Enrich via ipinfo using IPv4
    if ipv4 != 'None':
        try:
            handler = ipinfo.getHandler(ipinfo_token) if ipinfo_token else ipinfo.getHandler()
            details = handler.getDetails(ipv4)
            data = details.all or {}

            org_field = data.get('org', '')
            parts = org_field.split(' ', 1)
            geo['asn'] = parts[0] if parts else geo['asn']
            geo['org'] = parts[1] if len(parts) > 1 else geo['org']

            geo['country'] = data.get('country', geo['country'])
            geo['region'] = data.get('region', geo['region'])
            geo['city'] = data.get('city', geo['city'])

            # Add a note if not US
            if geo['country'] != 'US':
                geo['note'] = (
                    'Note: May reflect nearest endpoint.'
                )
        except Exception:
            pass

    return ipv4, ipv6, geo
