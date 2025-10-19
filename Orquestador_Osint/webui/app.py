import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
import tempfile
import json
import uuid

from modules.whois_module import module_whois
from modules.dns_module import module_dns
from modules.http_meta_module import module_http_meta
from modules.username_check_module import module_username_check
from modules.phone_module import module_phone_lookup
from modules.exif_module import module_exif
from modules.shodan_module import module_shodan_host

from utils.helpers import pretty_now
from utils.pdf_generator import generate_osint_pdf
from utils.correlator import generate_graphviz_visualization, export_to_maltego, generate_correlation_report

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
UPLOAD_DIR = os.path.join(tempfile.gettempdir(), "osint_uploads")
PDF_DIR = os.path.join(tempfile.gettempdir(), "osint_pdfs")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(PDF_DIR, exist_ok=True)

results_cache = {}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def api_scan():
    if request.is_json:
        ty = request.json.get("type")
        value = request.json.get("value")
        numverify_key = request.json.get("numverify_key")
        shodan_key = request.json.get("shodan_key")
    else:
        ty = request.form.get("type")
        value = request.form.get("value")
        numverify_key = request.form.get("numverify_key")
        shodan_key = request.form.get("shodan_key")

    result = {"target": {}, "results": [], "started": pretty_now()}

    try:
        if ty == "domain" and value:
            result["target"]["domain"] = value
            result["results"].append(module_whois(value))
            result["results"].append(module_dns(value))
            result["results"].append(module_http_meta(value))
        elif ty == "username" and value:
            result["target"]["username"] = value
            result["results"].append(module_username_check(value))
        elif ty == "phone" and value:
            result["target"]["phone"] = value
            result["results"].append(module_phone_lookup(value, api_key=numverify_key))
        elif ty == "ip" and value:
            result["target"]["ip"] = value
            result["results"].append(module_shodan_host(value, api_key=shodan_key))
        elif ty == "images":
            files = request.files.getlist("files")
            if not files or len(files) == 0:
                return jsonify({"error":"no files uploaded"}), 400
            saved = []
            for f in files:
                if f.filename == '':
                    continue
                filename = secure_filename(f.filename)
                path = os.path.join(UPLOAD_DIR, filename)
                f.save(path)
                saved.append(path)
            if not saved:
                return jsonify({"error":"no valid files uploaded"}), 400
            result["target"]["images"] = saved
            result["results"].append(module_exif(saved))
        else:
            return jsonify({"error": f"invalid type '{ty}' or missing value"}), 400

    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 500

    result["finished"] = pretty_now()
    
    result_id = str(uuid.uuid4())
    results_cache[result_id] = result
    result["pdf_id"] = result_id
    
    return jsonify(result)

@app.route("/api/download_pdf/<result_id>", methods=["GET"])
def download_pdf(result_id):
    if result_id not in results_cache:
        return jsonify({"error": "Result not found or expired"}), 404
    
    data = results_cache[result_id]
    pdf_filename = f"osint_report_{result_id[:8]}.pdf"
    pdf_path = os.path.join(PDF_DIR, pdf_filename)
    
    try:
        generate_osint_pdf(data, pdf_path)
        return send_file(pdf_path, as_attachment=True, download_name=pdf_filename)
    except Exception as e:
        return jsonify({"error": f"PDF generation failed: {str(e)}"}), 500

@app.route("/api/correlate/<result_id>", methods=["GET"])
def correlate_data(result_id):
    """Genera correlación y visualización de datos"""
    if result_id not in results_cache:
        return jsonify({"error": "Result not found"}), 404
    
    data = results_cache[result_id]
    
    try:
        # Generar grafo visual
        graph_path = os.path.join(PDF_DIR, f"graph_{result_id[:8]}")
        graph_result = generate_graphviz_visualization(data, graph_path)
        
        # Exportar a Maltego
        maltego_path = os.path.join(PDF_DIR, f"maltego_{result_id[:8]}")
        maltego_result = export_to_maltego(data, maltego_path)
        
        # Generar reporte de correlación
        correlation_report = generate_correlation_report(data)
        
        return jsonify({
            "graph": graph_result,
            "maltego": maltego_result,
            "correlation_report": correlation_report
        })
    
    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 500


@app.route("/api/download_graph/<result_id>", methods=["GET"])
def download_graph(result_id):
    """Descarga el grafo generado"""
    graph_file = os.path.join(PDF_DIR, f"graph_{result_id[:8]}.png")
    
    if not os.path.exists(graph_file):
        return jsonify({"error": "Graph not found"}), 404
    
    return send_file(graph_file, as_attachment=True, download_name=f"osint_graph_{result_id[:8]}.png")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)