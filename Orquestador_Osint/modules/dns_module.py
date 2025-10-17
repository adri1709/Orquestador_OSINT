import dns.resolver
from utils.helpers import pretty_now

def module_dns(domain, summary: bool = False):
    out = {"module": "dns", "input": domain, "ts": pretty_now(), "records": {}}
    qtypes = ["A", "AAAA", "MX", "NS", "TXT"]
    resolver = dns.resolver.Resolver()
    # AÑADIR ESTAS LÍNEAS para usar DNS públicos (evita problemas con routers/ISP)
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]  
    resolver.timeout = 5
    resolver.lifetime = 10
    for q in qtypes:
        try:
            answers = resolver.resolve(domain, q)
            out["records"][q] = [r.to_text() for r in answers]
        except Exception as e:
            out["records"][q] = {"error": str(e)}
    return out