import os
import datetime
import webbrowser
from urllib.parse import urlparse

from flask import Flask, render_template, request, jsonify
from markupsafe import Markup

from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

from scanner.ftc1  import run_urlscan, run_virustotal
from scanner.ftc3  import ftc3_headers
from scanner.ftc4  import ftc4_geo
from scanner.ftc5  import ftc5_dns
from scanner.utils import now, print_table
from scanner import config

app = Flask(__name__)

# ── OAuth2 Installed-App Flow ──────────────────────────────────────────
CLIENT_CONFIG = {
    "installed": {
        "client_id":     config.GOOGLE_CLIENT_ID,
        "client_secret": config.GOOGLE_CLIENT_SECRET,
        "auth_uri":      "https://accounts.google.com/o/oauth2/auth",
        "token_uri":     "https://oauth2.googleapis.com/token",
        "redirect_uris":[ "urn:ietf:wg:oauth:2.0:oob", "http://localhost" ]
    }
}
SCOPES = ['https://www.googleapis.com/auth/drive']
DRIVE_FOLDER_ID = config.DRIVE_FOLDER_ID

# Perform OAuth once (disable Flask reloader in __main__ for single prompt)
flow = InstalledAppFlow.from_client_config(CLIENT_CONFIG, SCOPES)
creds = flow.run_local_server(port=0)
# Immediately open the main app in your browser
webbrowser.open('http://localhost:5000/')

drive_svc = build('drive', 'v3', credentials=creds)
# ────────────────────────────────────────────────────────────────────────

def _upload_to_drive(filepath: str, filename: str):
    file_metadata = {'name': filename, 'parents': [DRIVE_FOLDER_ID]}
    media = MediaFileUpload(filepath, mimetype='text/plain')
    drive_svc.files().create(
        body=file_metadata,
        media_body=media,
        fields='id',
        supportsAllDrives=True
    ).execute()

def format_country(geo: dict) -> Markup:
    country = geo.get("country", "None")
    note    = geo.get("note", "")
    if note:
        return Markup(f'<span class="country-cell" title="{note}">{country}</span>')
    return Markup(f'<span class="country-cell">{country}</span>')

TESTS = {
    "ftc1": {
        "label": "FTC-0001: URL Reputation Checks",
        "funcs": [
            ("urlscan.io verdict",   lambda u,d: run_urlscan(u)),
            ("VirusTotal detection", lambda u,d: run_virustotal(u)),
        ],
    },
    "ftc3": {
        "label": "FTC-0003: Infrastructure Header Analysis",
        "funcs": [
            ("Final resolved URL", lambda u,d: ftc3_headers(u, d)[0]),
            ("Web server",        lambda u,d: ftc3_headers(u, d)[1]),
            ("CDN detected",      lambda u,d: ftc3_headers(u, d)[2]),
            ("WAF detected",      lambda u,d: ftc3_headers(u, d)[3]),
            ("Antibot clues",     lambda u,d: ftc3_headers(u, d)[4]),
        ],
    },
    "ftc4": {
        "label": "FTC-0004: IP & Geolocation",
        "funcs": [
            ("IPv4 address", lambda u,d: ftc4_geo(d)[0]),
            ("IPv6 address", lambda u,d: ftc4_geo(d)[1]),
            ("ASN number",   lambda u,d: ftc4_geo(d)[2]["asn"]),
            ("ASN company",  lambda u,d: ftc4_geo(d)[2]["org"]),
            ("Country",      lambda u,d: format_country(ftc4_geo(d)[2])),
            ("Region",       lambda u,d: ftc4_geo(d)[2]["region"]),
            ("City",         lambda u,d: ftc4_geo(d)[2]["city"]),
        ],
    },
    "ftc5": {
        "label": "FTC-0005: DNS Records",
        "funcs": [
            ("Subdomain CNAME", lambda u,d: ftc5_dns(d)[0]),
            ("CNAME provider",  lambda u,d: ftc5_dns(d)[3]),
            ("Nameserver(s)",   lambda u,d: ", ".join(ftc5_dns(d)[1])),
            ("DNS provider",    lambda u,d: ftc5_dns(d)[2]),
        ],
    },
}

@app.route("/", methods=["GET"])
def index():
    return render_template(
        "index.html",
        timestamp=now(),
        tests=TESTS,
        chosen=[],
        results={},
        error=None,
        drive_folder_id=DRIVE_FOLDER_ID,
    )

@app.route("/run_test", methods=["POST"])
def run_test():
    url = request.form["url"]
    tid = request.form["tid"]
    dom = urlparse(url).netloc or urlparse(url).path
    section = TESTS.get(tid)
    if not section:
        return jsonify(error="Unknown test"), 400

    rows = []
    for title, fn in section["funcs"]:
        try:
            val = fn(url, dom)
        except Exception as e:
            val = f"Error: {e}"
        rows.append({"title": title, "val": val})

    return jsonify(tid=tid, label=section["label"], rows=rows)

@app.route("/save_results", methods=["POST"])
def save_results():
    payload = request.get_json(force=True)
    url     = payload.get("url", "")
    results = payload.get("results", {})

    dom      = urlparse(url).netloc or urlparse(url).path
    date_str = datetime.datetime.now().strftime("%Y-%m-%d")
    safe_dom = dom.replace(":", "_").replace("/", "_")
    stem     = f"{date_str}_{safe_dom}_scan"

    results_dir = os.path.join(os.getcwd(), "results")
    os.makedirs(results_dir, exist_ok=True)

    fname = f"{stem}.txt"
    path  = os.path.join(results_dir, fname)
    i = 1
    while os.path.exists(path):
        fname = f"{stem}{i}.txt"
        path  = os.path.join(results_dir, fname)
        i += 1

    with open(path, "w", encoding="utf-8") as fh:
        for tid, section in results.items():
            fh.write(f"{section['label']}\n")
            raw = section.get("rows", [])
            norm_rows = []
            for row in raw:
                if isinstance(row, dict):
                    norm_rows.append((row["title"], row["val"]))
                elif isinstance(row, (list, tuple)) and len(row) >= 2:
                    norm_rows.append((row[0], row[1]))
            print_table(norm_rows, fh)
            fh.write("\n")

    try:
        _upload_to_drive(path, fname)
    except Exception as e:
        app.logger.warning(f"Drive upload failed: {e}")

    return jsonify(status="ok", filename=fname)

if __name__ == "__main__":
    # disable reloader to avoid double OAuth prompt
    app.run(debug=True, use_reloader=False)
