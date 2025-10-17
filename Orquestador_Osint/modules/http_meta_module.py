from bs4 import BeautifulSoup
from utils.helpers import pretty_now, safe_request_get

def module_http_meta(domain, summary: bool = False):
    out = {"module": "http_meta", "input": domain, "ts": pretty_now()}
    hosts = [domain] if domain.startswith("http") else [
        f"https://{domain}", f"https://www.{domain}",
        f"http://{domain}",  f"http://www.{domain}"
    ]
    for url in hosts:
        r = safe_request_get(url, timeout=15)
        if "error" in r:
            continue
        if r.get("status_code") and r["status_code"] < 400:
            text = r.get("text", "")
            soup = BeautifulSoup(text, "html.parser")
            title = soup.title.string.strip() if soup.title and soup.title.string else None
            metas = {(m.get("name") or m.get("property") or m.get("itemprop")).lower(): m.get("content", "")
                     for m in soup.find_all("meta") if (m.get("name") or m.get("property") or m.get("itemprop"))}
            desc = metas.get("description")
            out["final_url"] = r.get("url")
            out["status_code"] = r.get("status_code")
            out["headers"] = r.get("headers")
            out["title"] = title
            out["meta_tags"] = metas
            out["robots"] = metas.get("robots")
            return out
    out["error"] = "no reachable HTTP(S) endpoint"
    return out