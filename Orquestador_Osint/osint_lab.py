import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.whois_module import module_whois
from modules.dns_module import module_dns
from modules.http_meta_module import module_http_meta
from modules.username_check_module import module_username_check
from modules.phone_module import module_phone_lookup
from utils.helpers import pretty_now

MAX_WORKERS = 6

def run_pipeline(args):
    summary = {"target": {}, "results": [], "started": pretty_now()}
    
    if args.domain:
        domain = args.domain.strip()
        summary["target"]["domain"] = domain
        tasks = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            tasks.append(ex.submit(module_whois, domain, args.summary))
            tasks.append(ex.submit(module_dns, domain, args.summary))
            tasks.append(ex.submit(module_http_meta, domain, args.summary))
            for fut in as_completed(tasks):
                try:
                    summary["results"].append(fut.result())
                except Exception as e:
                    summary["results"].append({"module_error": str(e)})
    
    if args.username:
        summary["target"]["username"] = args.username
        compact = args.compact or args.summary
        ures = module_username_check(args.username, compact=compact)
        summary["results"].append(ures)
    
    if args.phone:
        summary["target"]["phone"] = args.phone
        phone_res = module_phone_lookup(args.phone, args.numverify_key)
        summary["results"].append(phone_res)
    
    
    summary["finished"] = pretty_now()
    return summary

def build_parser():
    p = argparse.ArgumentParser(description="osint_lab - modular OSINT (ethical use only)")
    p.add_argument("--domain", "-d", help="Domain to analyze")
    p.add_argument("--username", "-u", help="Username to check")
    p.add_argument("--phone", help="Número de teléfono")
    p.add_argument("--numverify-key", help="API key de numverify")
    p.add_argument("--out", "-o", help="Output JSON file")
    p.add_argument("--summary", action="store_true", help="Modo resumen")
    p.add_argument("--compact", action="store_true", help="Salida compacta")
    p.add_argument("--quiet", action="store_true", help="Sin mensajes por pantalla")
    p.add_argument("--max-workers", type=int, default=MAX_WORKERS)
    return p

def main():
    global MAX_WORKERS
    args = build_parser().parse_args()

    if not (args.domain or args.username or args.phone):
        print("Debe especificar al menos --domain, --username o --phone")
        return
    
    MAX_WORKERS = args.max_workers
    report = run_pipeline(args)
    
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        if not args.quiet:
            print(f"Reporte guardado en {args.out}")
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()