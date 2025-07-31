from flask import Flask, render_template, request, redirect, url_for
from urllib.parse import urlparse

from scanner.ftc1      import run_urlscan, run_virustotal
from scanner.ftc3      import ftc3_headers
from scanner.ftc4      import ftc4_geo
from scanner.ftc5      import ftc5_dns
from scanner.utils     import now

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            error = "Please enter a URL"
        else:
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            dom = urlparse(url).netloc or urlparse(url).path

            # run scans (could be slow—consider background task later)
            try:
                vs = run_urlscan(url)
            except Exception as e:
                vs = f"Error: {e}"
            vt = run_virustotal(url)
            final, srv, cdn, waf, bot = ftc3_headers(url)
            ipv4, ipv6, geo = ftc4_geo(dom)
            subcname, ns_list, prov = ftc5_dns(dom)

            result = {
                "url": url,
                "urlscan": vs,
                "virustotal": vt,
                "final_url": final,
                "server": srv,
                "cdn": cdn,
                "waf": waf,
                "antibot": bot,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "asn": geo["asn"],
                "org": geo["org"],
                "country": geo["country"],
                "region": geo["region"],
                "city": geo["city"],
                "subcname": subcname,
                "ns": ns_list,
                "dns_provider": prov,
            }

    return render_template("index.html", result=result, error=error)

if __name__ == "__main__":
    app.run(debug=True)
