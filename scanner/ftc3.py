from typing import Tuple
from urllib.parse import urlparse
import requests

try:
    import dns.resolver  # for CNAME chain lookup
except ImportError:
    dns = None

def ftc3_headers(url: str) -> Tuple[str, str, str, str, str]:
    """
    Fetch final URL + headers and detect:
      – Web server via Server header
      – CDN via CNAME chain + cache headers
      – WAF via headers & cookies
      – Antibot via cookies, headers, and HTML body
    Returns: (final_url, server, cdn, waf, antibot)
    """
    try:
        resp = requests.get(url, allow_redirects=True, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        err = f"Error fetching headers: {e}"
        return err, "None", "None", "None", "None"

    final_url = resp.url
    hdrs = resp.headers

    # Server header
    server = hdrs.get("Server", "None")

    # CDN detection
    cdn_set = set()

    # 1) CNAME chain
    if dns:
        domain = urlparse(final_url).hostname or ""
        current = domain
        while True:
            try:
                ans = dns.resolver.resolve(current, "CNAME")
                current = str(ans[0].target).rstrip(".")
                for patt, name in [
                    ("cloudflare", "Cloudflare"),
                    ("akamai", "Akamai"),
                    ("cloudfront", "CloudFront"),
                    ("fastly", "Fastly"),
                    ("azureedge", "Azure CDN"),
                    ("stackpathcdn", "StackPath"),
                    ("cdn77.net", "CDN77"),
                    ("incap", "Imperva Incapsula"),
                ]:
                    if patt in current.lower():
                        cdn_set.add(name)
            except Exception:
                break

    # 2) Cache headers
    for hdr_key in ("CF-Cache-Status", "X-Cache", "Via", "X-Served-By", "X-Edge-Location"):
        if hdr_key in hdrs:
            val = hdrs[hdr_key]
            cdn_set.add(hdr_key if hdr_key != "X-Cache" else f"X-Cache: {val}")

    cdn = ", ".join(sorted(cdn_set)) if cdn_set else "None"

    # WAF detection
    waf_set = set()
    for k, v in hdrs.items():
        kl, vl = k.lower(), v.lower()
        if "x-sucuri-id" in kl:
            waf_set.add("Sucuri WAF")
        if "incap" in vl:
            waf_set.add("Imperva Incapsula")
        if "mod_security" in kl or "mod_security" in vl:
            waf_set.add("ModSecurity")
        if "x-waf" in kl:
            waf_set.add("Generic WAF")
    for ck in resp.cookies.keys():
        cl = ck.lower()
        if "sucuri" in cl:
            waf_set.add("Sucuri WAF")
        if "incap" in cl:
            waf_set.add("Imperva Incapsula")

    waf = ", ".join(sorted(waf_set)) if waf_set else "None"

    # Antibot clues
    bot_set = set()
    # cookies
    for ck in resp.cookies.keys():
        lc = ck.lower()
        for tok in ("__cfduid", "__cfruid", "botshield", "bm_sv", "visid_incap"):
            if tok in lc:
                bot_set.add(f"Cookie: {ck}")
    # challenge headers
    for k in hdrs:
        if any(tok in k.lower() for tok in ("cf-chl-bypass", "challenge", "captcha", "bot-score")):
            bot_set.add(f"{k}: {hdrs[k]}")
    # HTML body check
    text = resp.text.lower()
    if "captcha" in text or "please enable javascript" in text:
        bot_set.add("HTML contains challenge")

    antibot = ", ".join(sorted(bot_set)) if bot_set else "None"

    return final_url, server, cdn, waf, antibot
