import requests
from utils.helpers import pretty_now

# Añade aquí tu API key (solo para uso local/laboratorio — no subir a repos públicos)
DEFAULT_NUMVERIFY_KEY = "554731d4da37219ea6aa98d49717b621"

def module_phone_lookup(phone, api_key=None):
    out = {"module": "phone_lookup", "input": phone, "ts": pretty_now()}
    # Usa la API key pasada por argumento o la fija en este archivo
    key = api_key or DEFAULT_NUMVERIFY_KEY
    if not key:
        out["error"] = "No numverify API key provided"
        return out
    url = "http://apilayer.net/api/validate"
    params = {
        "access_key": key,
        "number": phone,
        "country_code": "",
        "format": 1
    }
    try:
        r = requests.get(url, params=params, timeout=8)
        if r.status_code == 200:
            out["result"] = r.json()
        else:
            out["error"] = f"HTTP {r.status_code} - {r.text[:200]}"
    except Exception as e:
        out["error"] = str(e)
    return out