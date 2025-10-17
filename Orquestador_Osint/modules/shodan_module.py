import requests
from utils.helpers import pretty_now

# API Key de Shodan (reemplazar con la tuya desde https://account.shodan.io)
DEFAULT_SHODAN_KEY = "kDHBboGP9eXWktZd9pUAkFbJNlcVdnJF"

def module_shodan_host(ip, api_key=None):
    """
    Consulta información de un host/IP usando Shodan API
    Documentación: https://developer.shodan.io/api
    """
    out = {"module": "shodan_host", "input": ip, "ts": pretty_now()}
    
    key = api_key or DEFAULT_SHODAN_KEY
    
    # CORREGIDO: Solo validar si NO hay key
    if not key:
        out["error"] = "No Shodan API key provided. Get one at https://account.shodan.io/register"
        return out
    
    url = f"https://api.shodan.io/shodan/host/{ip}"
    params = {"key": key}
    
    try:
        r = requests.get(url, params=params, timeout=10)
        
        if r.status_code == 200:
            data = r.json()
            
            # Extraer información relevante
            out["result"] = {
                "ip": data.get("ip_str"),
                "organization": data.get("org"),
                "isp": data.get("isp"),
                "asn": data.get("asn"),
                "country": data.get("country_name"),
                "city": data.get("city"),
                "hostnames": data.get("hostnames", []),
                "domains": data.get("domains", []),
                "ports": data.get("ports", []),
                "vulns": list(data.get("vulns", {}).keys()) if data.get("vulns") else [],
                "last_update": data.get("last_update"),
                "total_services": len(data.get("data", []))
            }
            
            # Servicios detectados (limitado a primeros 5)
            services = []
            for service in data.get("data", [])[:5]:
                services.append({
                    "port": service.get("port"),
                    "transport": service.get("transport"),
                    "product": service.get("product"),
                    "version": service.get("version"),
                    "banner": service.get("data", "")[:200]
                })
            out["result"]["services"] = services
            
        elif r.status_code == 401:
            out["error"] = "Invalid Shodan API key"
        elif r.status_code == 404:
            out["error"] = "No information available for this IP"
        else:
            out["error"] = f"HTTP {r.status_code}: {r.text[:200]}"
            
    except Exception as e:
        out["error"] = str(e)
    
    return out


def module_shodan_search(query, api_key=None, max_results=10):
    """
    Búsqueda en Shodan usando queries (ej: "apache country:ES")
    """
    out = {"module": "shodan_search", "query": query, "ts": pretty_now()}
    
    key = api_key or DEFAULT_SHODAN_KEY
    
    # CORREGIDO: Solo validar si NO hay key
    if not key:
        out["error"] = "No Shodan API key provided"
        return out
    
    url = "https://api.shodan.io/shodan/host/search"
    params = {"key": key, "query": query}
    
    try:
        r = requests.get(url, params=params, timeout=15)
        
        if r.status_code == 200:
            data = r.json()
            results = []
            
            for match in data.get("matches", [])[:max_results]:
                results.append({
                    "ip": match.get("ip_str"),
                    "port": match.get("port"),
                    "organization": match.get("org"),
                    "hostnames": match.get("hostnames", []),
                    "location": f"{match.get('location', {}).get('city', 'N/A')}, {match.get('location', {}).get('country_name', 'N/A')}",
                    "product": match.get("product"),
                    "banner": match.get("data", "")[:150]
                })
            
            out["result"] = {
                "total_results": data.get("total"),
                "returned": len(results),
                "matches": results
            }
        else:
            out["error"] = f"HTTP {r.status_code}: {r.text[:200]}"
            
    except Exception as e:
        out["error"] = str(e)
    
    return out