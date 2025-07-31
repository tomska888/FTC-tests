import sys
import os
from datetime import date
from urllib.parse import urlparse

from scanner.ftc1      import run_urlscan, run_virustotal
from scanner.ftc3      import ftc3_headers
from scanner.ftc4      import ftc4_geo
from scanner.ftc5      import ftc5_dns
from scanner.utils     import now, print_table

def make_output_path(domain: str) -> str:
    """
    Ensure a 'results/' folder exists and return a filename of the form:
      YYYY-MM-DD_<domain>_scan.txt,
    or if that exists, YYYY-MM-DD_<domain>_scan1.txt, etc.
    """
    today = date.today().isoformat()
    base = f"{today}_{domain}_scan"
    folder = os.path.join(os.getcwd(), "results")
    os.makedirs(folder, exist_ok=True)

    # find existing files
    existing = [f for f in os.listdir(folder) if f.startswith(base) and f.endswith(".txt")]
    if base + ".txt" not in existing:
        filename = base + ".txt"
    else:
        # extract trailing numbers
        nums = []
        for f in existing:
            stem = f[len(base):-4]  # drop base and ".txt"
            if stem.isdigit():
                nums.append(int(stem))
        next_idx = max(nums, default=0) + 1
        filename = f"{base}{next_idx}.txt"

    return os.path.join(folder, filename)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <website>")
        sys.exit(1)

    site = sys.argv[1]
    if not site.startswith(("http://", "https://")):
        site = "http://" + site
    dom = urlparse(site).netloc or urlparse(site).path

    out_file = make_output_path(dom)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(f"# Scan run at {now()}\n\n")

        f.write("## FTC1: URL Reputation Checks\n\n")
        print_table([
            ("urlscan.io verdict", run_urlscan(site)),
            ("VirusTotal detection", run_virustotal(site)),
        ], f)

        f.write("## FTC3: Infrastructure Header Analysis\n\n")
        final, srv, cdn, waf, bot = ftc3_headers(site)
        print_table([
            ("Final resolved URL", final),
            ("Web server",          srv),
            ("CDN detected",        cdn),
            ("WAF detected",        waf),
            ("Antibot clues",       bot),
        ], f)

        f.write("## FTC4: IP and Geolocation\n\n")
        ipv4, ipv6, geo = ftc4_geo(dom)
        print_table([
            ("IPv4 address", ipv4),
            ("IPv6 address", ipv6),
            ("ASN number",   geo["asn"]),
            ("ASN company",  geo["org"]),
            ("Country",      geo["country"]),
            ("Region",       geo["region"]),
            ("City",         geo["city"]),
        ], f)

        f.write("## FTC5: DNS Records\n\n")
        subcname, ns_list, prov = ftc5_dns(dom)
        print_table([
            ("Subdomain CNAME", subcname),
            ("CNAME provider",  subcname.split(".", 1)[1] if "." in subcname else "None"),
            ("Nameserver(s)",   ", ".join(ns_list) if ns_list else "None"),
            ("DNS provider",    prov),
        ], f)

    print(f"✅ Results written to {out_file}")

if __name__ == "__main__":
    main()
