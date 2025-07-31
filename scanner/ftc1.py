import time
import requests
from typing import List

from scanner.utils import session, poll_json
from scanner.config import URLSCAN_API_KEY, VT_API_KEY

def run_urlscan(url: str) -> str:
    """
    FTC1: submit to urlscan.io, poll the Result API, parse verdicts.urlscan.categories.
    If submission or polling fails, returns a “Skipped” or timeout message.
    """
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}

    # 1) Submit the scan
    try:
        resp = session.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json={"url": url, "visibility": "public"},
            timeout=10,
        )
        resp.raise_for_status()
        scan_id = resp.json().get("uuid")
        if not scan_id:
            return "Skipped (no scan ID returned)"
    except requests.RequestException as e:
        return f"Skipped (submission error: {e})"

    # 2) Poll for result
    try:
        result = poll_json(f"https://urlscan.io/api/v1/result/{scan_id}/", headers)
    except TimeoutError:
        return "Scan timed out"
    except Exception as e:
        return f"Skipped (polling error: {e})"

    # 3) Extract categories
    cats: List[str] = (
        result.get("verdicts", {})
              .get("urlscan", {})
              .get("categories", [])
    )
    return ", ".join(cats) if cats else "No classification"


def run_virustotal(url: str) -> str:
    """
    FTC1: submit to VT v3, wait, fetch analysis stats as "malicious/total".
    """
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    try:
        post = session.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10,
        )
        post.raise_for_status()
        analysis_id = post.json()["data"]["id"]
    except Exception as e:
        return f"Skipped (VT submission error: {e})"

    time.sleep(20)

    try:
        stats = session.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=10,
        ).json()["data"]["attributes"]["stats"]
        mal = stats.get("malicious", 0)
        tot = sum(stats.values())
        return f"{mal}/{tot}"
    except Exception as e:
        return f"Skipped (VT fetch error: {e})"
