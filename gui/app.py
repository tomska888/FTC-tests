from flask import Flask, render_template, request
from markupsafe import Markup
from urllib.parse import urlparse

from scanner.ftc1      import run_urlscan, run_virustotal
from scanner.ftc3      import ftc3_headers
from scanner.ftc4      import ftc4_geo
from scanner.ftc5      import ftc5_dns
from scanner.utils     import now

app = Flask(__name__)

def format_country(geo: dict) -> Markup:
    """
    Return the country name, with a hover‐tooltip if geo['note'] exists.
    """
    country = geo.get("country", "None")
    note    = geo.get("note", "")
    if note:
        # This will render: <span title="…">US</span>
        return Markup(f'<span title="{note}">{country}</span>')
    return Markup(country)

TESTS = {
    "ftc1": {
        "label": "FTC-0001: URL Reputation Checks",
        "funcs": [
            ("urlscan.io verdict", lambda url, dom: run_urlscan(url)),
            ("VirusTotal detection", lambda url, dom: run_virustotal(url)),
        ],
    },
    "ftc3": {
        "label": "FTC-0003: Infrastructure Header Analysis",
        "funcs": [
            ("Final resolved URL", lambda url, dom: ftc3_headers(url, dom)[0]),
            ("Web server",          lambda url, dom: ftc3_headers(url, dom)[1]),
            ("CDN detected",        lambda url, dom: ftc3_headers(url, dom)[2]),
            ("WAF detected",        lambda url, dom: ftc3_headers(url, dom)[3]),
            ("Antibot clues",       lambda url, dom: ftc3_headers(url, dom)[4]),
        ],
    },
    "ftc4": {
        "label": "FTC-0004: IP & Geolocation",
        "funcs": [
            ("IPv4 address", lambda url, dom: ftc4_geo(dom)[0]),
            ("IPv6 address", lambda url, dom: ftc4_geo(dom)[1]),
            ("ASN number",   lambda url, dom: ftc4_geo(dom)[2]["asn"]),
            ("ASN company",  lambda url, dom: ftc4_geo(dom)[2]["org"]),
            ("Country",      lambda url, dom: format_country(ftc4_geo(dom)[2])),
            ("Region",       lambda url, dom: ftc4_geo(dom)[2]["region"]),
            ("City",         lambda url, dom: ftc4_geo(dom)[2]["city"]),
        ],
    },
    "ftc5": {
        "label": "FTC-0005: DNS Records",
        "funcs": [
            ("Subdomain CNAME", lambda url, dom: ftc5_dns(dom)[0]),
            ("CNAME provider",    lambda url, dom: ftc5_dns(dom)[3]),
            ("Nameserver(s)",   lambda url, dom: ", ".join(ftc5_dns(dom)[1])),
            ("DNS provider",    lambda url, dom: ftc5_dns(dom)[2]),
        ],
    },
}

@app.route("/", methods=["GET", "POST"])
def index():
    error = None
    results = {}
    chosen = []

    if request.method == "POST":
        url = request.form.get("url","").strip()
        chosen = request.form.getlist("tests")
        if not url:
            error = "Please enter a URL"
        else:
            if not url.startswith(("http://","https://")):
                url = "http://" + url
            dom = urlparse(url).netloc or urlparse(url).path

            # Run only selected tests
            for tid in chosen:
                section = TESTS.get(tid)
                if not section: 
                    continue
                rows = []
                for title, fn in section["funcs"]:
                    try:
                        val = fn(url, dom)
                    except Exception as e:
                        val = f"Error: {e}"
                    rows.append((title, val))
                results[tid] = {
                    "label": section["label"],
                    "rows": rows
                }

    return render_template("index.html",
                           timestamp=now(),
                           tests=TESTS,
                           chosen=chosen,
                           results=results,
                           error=error)

if __name__ == "__main__":
    app.run(debug=True)
