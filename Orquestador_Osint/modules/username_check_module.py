from utils.helpers import pretty_now
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

SOCIAL_SITES = [
    "https://twitter.com/{username}",
    "https://www.facebook.com/{username}",
    "https://www.instagram.com/{username}/",
    "https://github.com/{username}",
    "https://www.reddit.com/user/{username}",
    "https://www.tiktok.com/@{username}",
    "https://www.linkedin.com/in/{username}",
]

def module_username_check(username, sites=SOCIAL_SITES, concurrency=6, verify_tls=True, compact=False):
    results = {"module": "username_check", "input": username, "ts": pretty_now(), "sites": []}
    def check_site(pattern):
        url = pattern.format(username=username)
        time.sleep(__import__("random").uniform(0.2, 0.5))
        try:
            r = requests.head(url, timeout=8, verify=verify_tls)
            exists = r.status_code == 200
        except Exception:
            exists = None
        return {"url": url, "exists": exists}
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = [ex.submit(check_site, p) for p in sites]
        for f in as_completed(futs):
            results["sites"].append(f.result())
    return results