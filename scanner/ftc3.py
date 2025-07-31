# scanner/ftc3.py

import subprocess
import shlex
import json
from typing import Tuple, Optional, Set
from urllib.parse import urlparse

import requests
from scanner.utils import session

def detect_cdn_with_findcdn(domain: str) -> Optional[str]:
    """
    Runs `findcdn list <domain>` and scans its output for the
    "cdns_by_names" line. Returns a de-duped, comma-separated
    string of CDN names, or None on failure / no result.
    """
    try:
        # Invoke the CLI
        cmd = f"findcdn list {domain}"
        output = subprocess.check_output(
            shlex.split(cmd),
            stderr=subprocess.DEVNULL,
            universal_newlines=True,
            timeout=30
        )
        # Scan each line for the cdns_by_names entry
        for line in output.splitlines():
            if "cdns_by_names" in line:
                # e.g. line = '            "cdns_by_names": "'.Fastly', 'Fastly'"'
                # isolate the part after the colon
                _, val = line.split(":", 1)
                val = val.strip().rstrip(",")         # remove leading/trailing whitespace & comma
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]                  # strip the wrapping quotes
                # now val == "'.Fastly', 'Fastly'"
                parts = [p.strip().strip("'\"") for p in val.split(",") if p.strip()]
                # de-dup while preserving order
                seen = []
                for p in parts:
                    if p not in seen:
                        seen.append(p)
                return ", ".join(seen) if seen else None
    except Exception:
        return None

    return None

def detect_waf_with_wafw00f(url: str) -> Optional[str]:
    """
    Invokes `wafw00f <url>` and returns:
      – “None” if no WAF detected
      – e.g. "Cloudflare (Cloudflare Inc.)" if a WAF is identified
      – "Found but unknown – seems to be behind a WAF or some sort of security solution"
        if wafw00f reports that generic “seems to be behind” message
    """
    parsed = urlparse(url)
    target = f"{parsed.scheme}://{parsed.netloc}"
    cmd = f"wafw00f {target}"
    try:
        out = subprocess.check_output(
            shlex.split(cmd),
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            timeout=60
        )
    except Exception:
        return None

    for line in out.splitlines():
        line = line.strip()
        # Exact detection
        if line.startswith("[+] The site") and "is behind" in line:
            behind = line.split("is behind", 1)[1].strip().rstrip(".")
            return behind

        # Generic “seems to be behind” case
        if "seems to be behind a WAF or some sort of security solution" in line:
            return "Found but unknown – seems to be behind a WAF or some sort of security solution"

        # Explicit “no WAF detected”
        if "No WAF detected" in line:
            return None

    return None

def ftc3_headers(url: str, domain: str) -> Tuple[str, str, str, str, str]:
    """
    FTC3: Infrastructure Header Analysis
      1) Fetch final URL + headers
      2) Server via Server header on every hop
      3) CDN via findcdn → fallback to CNAME & cache-header logic
      4) WAF via wafw00f → fallback to header/cookie logic
      5) Antibot via cookies & HTML body
    Returns: (final_url, server, cdn, waf, antibot)
    """
    # 1) Fetch with redirects
    try:
        resp = session.get(url, allow_redirects=True, timeout=10)
        # no raise_for_status so we keep headers even on 4xx/5xx
    except Exception as e:
        err = f"Error fetching headers: {e}"
        return err, "None", "None", "None", "None"

    # leave these untouched:
    final_url = resp.url
    hdrs      = resp.headers

    # 2) Server header across the redirect chain
    server_values = []
    for hop in resp.history + [resp]:
        srv = hop.headers.get("Server")
        if srv and srv not in server_values:
            server_values.append(srv)
    server = ", ".join(server_values) if server_values else "None"

    # 3) CDN detection
    host = urlparse(final_url).hostname or domain
    cdn_display = detect_cdn_with_findcdn(host) or None
    if not cdn_display:
        # fallback to original CNAME + cache-header logic
        cdn_set: Set[str] = set()
        try:
            import dns.resolver
            current = host
            while True:
                ans = dns.resolver.resolve(current, "CNAME")
                current = str(ans[0].target).rstrip(".")
                for patt, vendor in [
                    ("cloudflare",     "Cloudflare"),
                    ("akamaitechnologies", "Akamai"),
                    ("cloudfront",     "CloudFront"),
                    ("fastly",         "Fastly"),
                    ("azureedge",      "Azure CDN"),
                    ("edgesuite.net",  "Akamai"),
                    ("stackpathcdn",   "StackPath"),
                    ("cdn77.net",      "CDN77"),
                    ("incap",          "Imperva Incapsula"),
                ]:
                    if patt in current.lower():
                        cdn_set.add(vendor)
        except Exception:
            pass

        for hdr_key, vendor in [
            ("CF-Cache-Status", "Cloudflare"),
            ("X-Cache",         None),
            ("Via",             None),
            ("X-Served-By",     None),
            ("X-Edge-Location", None),
        ]:
            if hdr_key in hdrs:
                if vendor:
                    cdn_set.add(vendor)
                else:
                    cdn_set.add(f"{hdr_key}: {hdrs[hdr_key]}")
        cdn_display = ", ".join(sorted(cdn_set)) if cdn_set else "None"
    else:
        cdn_display = cdn_display

    # 4) WAF detection
    waf_name = detect_waf_with_wafw00f(final_url)
    if waf_name:
        waf_display = waf_name
    else:
        # fallback to header & cookie heuristics
        waf_set: Set[str] = set()
        for k, v in hdrs.items():
            kl, vl = k.lower(), v.lower()
            if "x-sucuri-id" in kl:
                waf_set.add("Sucuri WAF")
            if "incap" in vl:
                waf_set.add("Imperva Incapsula")
            if "mod_security" in kl or "mod_security" in vl:
                waf_set.add("ModSecurity")
            if "x-waf-policy" in kl or "x-waf" in kl:
                waf_set.add("Generic WAF")
            if "x-cdn" in kl and "akamai" in vl:
                waf_set.add("Akamai WAF")
        for ck in resp.cookies.keys():
            cl = ck.lower()
            if "sucuri" in cl:
                waf_set.add("Sucuri WAF")
            if "incap" in cl:
                waf_set.add("Imperva Incapsula")
        waf_display = ", ".join(sorted(waf_set)) if waf_set else "None"

    # 5) Antibot clues
    antibot_set: Set[str] = set()
    for ck in resp.cookies.keys():
        lc = ck.lower()
        if any(tok in lc for tok in (
            "__cfduid", "__cfruid", "botshield",
            "bm_sv", "visid_incap")):
            antibot_set.add(f"Cookie: {ck}")
    for k in hdrs:
        if any(tok in k.lower() for tok in (
            "cf-chl-bypass", "challenge", "captcha", "bot-score")):
            antibot_set.add(f"{k}: {hdrs[k]}")
    try:
        body = resp.text.lower()
        if "captcha" in body or "please enable javascript" in body:
            antibot_set.add("HTML contains challenge")
    except Exception:
        pass
    antibot_display = ", ".join(sorted(antibot_set)) if antibot_set else "None"

    return final_url, server, cdn_display, waf_display, antibot_display
