from datetime import datetime, timezone
import requests

DEFAULT_TIMEOUT = 8
USER_AGENT = "osint_lab/0.1 (+https://example.local/lab)"

def pretty_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def safe_request_head(url, timeout=DEFAULT_TIMEOUT):
    headers = {"User-Agent": USER_AGENT}
    try:
        r = requests.head(url, headers=headers, allow_redirects=True, timeout=timeout)
        return {"status_code": r.status_code, "url": r.url, "ok": r.ok, "headers": dict(r.headers)}
    except requests.RequestException as e:
        return {"error": str(e)}

def safe_request_get(url, timeout=DEFAULT_TIMEOUT):
    headers = {"User-Agent": USER_AGENT}
    try:
        r = requests.get(url, headers=headers, allow_redirects=True, timeout=timeout)
        return {"status_code": r.status_code, "url": r.url, "ok": r.ok, "text": r.text, "headers": dict(r.headers)}
    except requests.RequestException as e:
        return {"error": str(e)}