import os
from utils.helpers import pretty_now

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

def _convert_gps_to_degrees(value):
    """Convierte coordenadas GPS a grados decimales"""
    try:
        d, m, s = value
        return float(d) + float(m) / 60.0 + float(s) / 3600.0
    except:
        return None

def _extract_gps_info(gps_info):
    """Extrae y formatea información GPS"""
    gps_data = {}
    
    for tag_id in gps_info:
        tag = GPSTAGS.get(tag_id, tag_id)
        gps_data[tag] = gps_info[tag_id]
    
    # Convertir coordenadas a formato legible
    if "GPSLatitude" in gps_data and "GPSLatitudeRef" in gps_data:
        lat = _convert_gps_to_degrees(gps_data["GPSLatitude"])
        if lat and gps_data["GPSLatitudeRef"] == "S":
            lat = -lat
        gps_data["Latitude_Decimal"] = lat
    
    if "GPSLongitude" in gps_data and "GPSLongitudeRef" in gps_data:
        lon = _convert_gps_to_degrees(gps_data["GPSLongitude"])
        if lon and gps_data["GPSLongitudeRef"] == "W":
            lon = -lon
        gps_data["Longitude_Decimal"] = lon
    
    return gps_data

def _read_image_metadata(path):
    """Lee metadatos de una imagen usando Pillow"""
    if not PIL_AVAILABLE:
        return None, "Pillow no está instalado. Instala con: pip install Pillow"
    
    if not os.path.exists(path):
        return None, "Archivo no encontrado"
    
    try:
        img = Image.open(path)
        metadata = {
            "file_info": {
                "filename": os.path.basename(path),
                "format": img.format,
                "size_pixels": f"{img.size[0]}x{img.size[1]}",
                "mode": img.mode,
                "file_size_bytes": os.path.getsize(path)
            },
            "exif": {},
            "gps": None
        }
        
        # Extraer EXIF
        exif = img._getexif()
        if exif:
            for tag_id, value in exif.items():
                tag = TAGS.get(tag_id, tag_id)
                
                # Procesar GPS por separado
                if tag == "GPSInfo":
                    metadata["gps"] = _extract_gps_info(value)
                else:
                    # Convertir a tipos serializables
                    if isinstance(value, bytes):
                        try:
                            metadata["exif"][tag] = value.decode('utf-8', errors='ignore')
                        except:
                            metadata["exif"][tag] = str(value)
                    elif isinstance(value, (tuple, list)):
                        metadata["exif"][tag] = str(value)
                    else:
                        metadata["exif"][tag] = value
        
        img.close()
        return metadata, None
        
    except Exception as e:
        return None, f"Error al procesar imagen: {str(e)}"

def module_exif(paths):
    """
    Analiza metadatos de imágenes usando solo Pillow (sin dependencias externas)
    
    Args:
        paths: str o lista de rutas de archivos de imagen
    
    Returns:
        dict con resultados estructurados
    """
    if isinstance(paths, str):
        paths = [paths]
    
    paths = [os.path.abspath(p) for p in paths]
    out = {
        "module": "exif_metadata",
        "inputs": paths,
        "ts": pretty_now(),
        "results": []
    }
    
    for path in paths:
        metadata, error = _read_image_metadata(path)
        
        if metadata:
            out["results"].append({
                "file": path,
                "status": "success",
                "metadata": metadata
            })
        else:
            out["results"].append({
                "file": path,
                "status": "error",
                "error": error
            })
    
    return out