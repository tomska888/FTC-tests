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
    Retries up to 2 times if result is "0/0", then skips.
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

    # initial wait before fetching
    time.sleep(20)

    max_retries = 2
    for attempt in range(max_retries + 1):
        try:
            resp = session.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=10,
            )
            resp.raise_for_status()
            stats = resp.json()["data"]["attributes"]["stats"]
            mal = stats.get("malicious", 0)
            tot = sum(stats.values())
            # if we have any results, return immediately
            if tot > 0:
                return f"{mal}/{tot}"
        except Exception as e:
            last_error = e

        # if this was not the last attempt, wait before retrying
        if attempt < max_retries:
            time.sleep(10)

    # after retries, still no data
    return f"Skipped (VT returned 0/0 after {max_retries + 1} attempts)"
