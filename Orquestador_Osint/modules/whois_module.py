import whois
from utils.helpers import pretty_now

def module_whois(domain, summary: bool = False):
    out = {"module": "whois", "input": domain, "ts": pretty_now()}
    try:
        w = whois.whois(domain)
        
        # Parsear datos estructurados
        parsed = {
            "domain_name": w.domain_name if isinstance(w.domain_name, str) else (w.domain_name[0] if w.domain_name else None),
            "registrar": w.registrar,
            "creation_date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date) if w.expiration_date else None,
            "updated_date": str(w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date) if w.updated_date else None,
            "name_servers": w.name_servers if w.name_servers else [],
            "status": w.status if isinstance(w.status, list) else [w.status] if w.status else [],
            "org": w.org,
            "country": w.country,
            "dnssec": w.dnssec,
            "registrar_abuse_email": w.emails[0] if w.emails else None
        }
        
        out["result"] = parsed
        if not summary:
            out["raw_text"] = w.text if hasattr(w, 'text') else None
    except Exception as e:
        out["error"] = str(e)
    return out