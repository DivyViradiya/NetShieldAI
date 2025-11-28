from flask import Blueprint, render_template, jsonify, request, Response, send_from_directory
import threading
import json
import time
import os
from queue import Empty

# Import the ssl_scanner module
from Services import ssl_scanner
# Import the PDF generator module
from Services import pdf_generator

ssl_scanner_bp = Blueprint('ssl_scanner_bp', __name__)

# ==========================================
# --- ⚙️ CONFIGURATION: PDF OUTPUT PATH ---
# ==========================================
PDF_FILENAME = r"D:\NetShieldAI\Services\PDFs\ssl_report.pdf" 

# This constructs the full path automatically
# We use the RESULTS_DIR from ssl_scanner to ensure consistency
JSON_REPORT_PATH = ssl_scanner.JSON_REPORT_FILE
PDF_REPORT_PATH = os.path.join(ssl_scanner.RESULTS_DIR, PDF_FILENAME)
# ==========================================

@ssl_scanner_bp.route('/')
def ssl_scanner_page():
    """Renders the SSL scanner page."""
    return render_template('ssl_scanner.html')

@ssl_scanner_bp.route('/scan', methods=['POST'])
def scan_ssl():
    """
    API endpoint to initiate an SSL scan using the local sslscan executable.
    Runs the scan in a separate thread to avoid blocking the Flask app.
    """
    data = request.get_json()
    target_host = data.get('target_host')

    if not target_host:
        ssl_scanner.log("[!] Target host cannot be empty for SSL scan.")
        return jsonify({"status": "error", "message": "Target host is required."}), 400

    if not ssl_scanner.is_sslscan_available():
        ssl_scanner.log("[!] sslscan.exe is not available. Cannot perform scan.")
        return jsonify({
            "status": "error",
            "message": "sslscan.exe not found. Please check server configuration and logs."
        }), 500
    
    # Function to run in a separate thread
    def scan_task():
        ssl_scanner.log(f"[*] Starting SSL scan for {target_host}...")
        
        # 1. Run the Scan (Generates XML)
        report_file = ssl_scanner.run_ssl_scan(target_host)
        
        if report_file:
            # 2. Parse XML and Save JSON
            # This function now automatically saves the JSON to ssl_scanner.JSON_REPORT_FILE
            summary = ssl_scanner.parse_ssl_report(report_file)
            
            if summary:
                ssl_scanner.log(f"[+] SSL scan complete. Generating PDF report...")
                
                # 3. Generate PDF Report
                try:
                    # Create the directory for PDFs if it doesn't exist
                    os.makedirs(os.path.dirname(PDF_REPORT_PATH), exist_ok=True)
                    
                    pdf_generator.create_ssl_report_pdf(str(JSON_REPORT_PATH), str(PDF_REPORT_PATH))
                    
                    if os.path.exists(PDF_REPORT_PATH):
                        ssl_scanner.log(f"[+] PDF report generated successfully: {PDF_REPORT_PATH}")
                    else:
                        ssl_scanner.log("[!] PDF generation ran but file not found.")
                
                except Exception as e:
                    ssl_scanner.log(f"[!] FAILED to generate PDF: {str(e)}")
            else:
                ssl_scanner.log(f"[!] Failed to parse SSL report for {target_host}.")
        else:
            ssl_scanner.log(f"[!] SSL scan failed for {target_host}.")

    threading.Thread(target=scan_task).start()
    return jsonify({"status": "success", "message": f"SSL scan for {target_host} initiated."})

@ssl_scanner_bp.route('/report_files', methods=['GET'])
def get_report_files():
    """Checks availability of reports to enable the download button."""
    json_exists = os.path.exists(JSON_REPORT_PATH)
    pdf_exists = os.path.exists(PDF_REPORT_PATH)

    if not json_exists and not pdf_exists:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    return jsonify({
        "status": "success",
        "json_report": "/ssl_scanner/get_json_report" if json_exists else None,
        "pdf_report": "/ssl_scanner/download_pdf" if pdf_exists else None
    })

@ssl_scanner_bp.route('/download_pdf', methods=['GET'])
def download_pdf_report():
    """Serves the PDF report dynamically."""
    if not os.path.exists(PDF_REPORT_PATH):
        return jsonify({"status": "error", "message": "PDF report file not found."}), 404
    
    directory = os.path.dirname(PDF_REPORT_PATH)
    filename = os.path.basename(PDF_REPORT_PATH)

    return send_from_directory(
        directory=directory,
        path=filename,
        as_attachment=True
    )

@ssl_scanner_bp.route('/get_json_report', methods=['GET'])
def get_json_report_file():
    """Serves the JSON report file."""
    if not os.path.exists(JSON_REPORT_PATH):
        return jsonify({"status": "error", "message": "JSON report file not found."}), 404
    
    directory = os.path.dirname(JSON_REPORT_PATH)
    filename = os.path.basename(JSON_REPORT_PATH)

    return send_from_directory(
        directory=directory,
        path=filename,
        as_attachment=True
    )

@ssl_scanner_bp.route('/report', methods=['GET'])
def get_ssl_report():
    """
    API endpoint to get the content of the parsed SSL scan report (JSON content).
    This is used by the frontend to render the immediate results view.
    """
    if not os.path.exists(JSON_REPORT_PATH):
        return jsonify({
            "status": "error",
            "message": "No SSL scan report available. Please run a scan first."
        }), 404
    
    try:
        with open(JSON_REPORT_PATH, 'r', encoding='utf-8') as f:
            parsed_summary = json.load(f)

        return jsonify({
            "status": "success",
            "content": parsed_summary, 
            "report_file": os.path.basename(JSON_REPORT_PATH)
        })
    except Exception as e:
        ssl_scanner.log(f"[!] Error reading or parsing SSL scan report: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to read or parse SSL scan report: {str(e)}"
        }), 500

@ssl_scanner_bp.route('/clear_log', methods=['POST'])
def clear_ssl_log_route():
    """API endpoint to clear the SSL scanner log file."""
    ssl_scanner.clear_log_file()
    return jsonify({"status": "success", "message": "SSL log cleared."})

@ssl_scanner_bp.route('/log_stream')
def ssl_log_stream():
    """Server-Sent Events (SSE) endpoint to stream SSL scanner log messages."""
    def generate_logs():
        while True:
            try:
                message = ssl_scanner.log_queue.get(timeout=10)
                yield message
            except Empty:
                yield ": keep-alive\n\n"
            except GeneratorExit:
                break

    return Response(generate_logs(), mimetype='text/event-stream')