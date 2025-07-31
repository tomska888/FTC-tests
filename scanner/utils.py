import time
import logging
from typing import Any, Dict, Optional
import requests

# initialize a shared session
session = requests.Session()

def now() -> str:
    """Return current local time as YYYY-MM-DD HH:MM:SS."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

def poll_json(
    url: str,
    headers: Dict[str, str],
    interval: int = 5,
    max_attempts: int = 12,
    timeout: int = 10,
) -> Dict[str, Any]:
    """
    Poll a JSON endpoint until HTTP 200 or exhaust attempts.
    Raises TimeoutError on failure.
    """
    for attempt in range(1, max_attempts + 1):
        resp = session.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            return resp.json()
        logging.debug(f"Attempt {attempt}/{max_attempts} for {url} returned {resp.status_code}")
        time.sleep(interval)
    raise TimeoutError(f"Polling {url} timed out after {interval * max_attempts}s")

def print_table(rows: list, fh) -> None:
    """
    Write a simple two-column table to file handle fh.
    """
    width = max(len(k) for k, _ in rows)
    fh.write(f"{'Field'.ljust(width)}   Value\n")
    fh.write(f"{'-'*width}   {'-'*5}\n")
    for k, v in rows:
        fh.write(f"{k.ljust(width)}   {v}\n")
    fh.write("\n")