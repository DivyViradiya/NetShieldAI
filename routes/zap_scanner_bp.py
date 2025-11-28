import os
import threading
import json
import time
from flask import Blueprint, render_template, jsonify, request, Response, send_from_directory

# Import the new zap_scanner module
from Services import zap_scanner
# --- NEW: Import the PDF generator ---
from Services import pdf_generator 

# Assuming you might still have this for other parts of your app
# from Services.api_client import login_required

zap_scanner_bp = Blueprint('zap_scanner_bp', __name__)

# ==========================================
# --- ⚙️ CONFIGURATION: PDF OUTPUT PATH ---
# ==========================================
# 1. To change the FOLDER, edit 'RESULTS_DIR' in 'Services/zap_scanner.py'
# 2. To change the FILENAME, edit the variable below:
PDF_FILENAME = r"D:\NetShieldAI\Services\PDFs\zap_report.pdf" 

# This constructs the full path automatically
JSON_REPORT_PATH = os.path.join(zap_scanner.RESULTS_DIR, "zap_report.json")
XML_REPORT_PATH = os.path.join(zap_scanner.RESULTS_DIR, "zap_report.xml")
PDF_REPORT_PATH = os.path.join(zap_scanner.RESULTS_DIR, PDF_FILENAME)
# ==========================================


@zap_scanner_bp.route('/')
# @login_required  # Uncomment if you want to protect this page
def zap_scanner_page():
    """Renders the ZAP scanner page."""
    return render_template('zap_scanner.html')


@zap_scanner_bp.route('/scan', methods=['POST'])
# @login_required # Uncomment if you want to protect this endpoint
def initiate_zap_scan():
    """
    API endpoint to initiate a ZAP quick scan.
    """
    data = request.get_json()
    target_url = data.get('target_url')

    if not target_url:
        zap_scanner.log("[!] Target URL is required for ZAP scan.")
        return jsonify({"status": "error", "message": "Target URL is required."}), 400
    
    if zap_scanner.model is None:
        zap_scanner.log("[!] FATAL: ML model is not loaded. Cannot start scan.")
        return jsonify({"status": "error", "message": "ML model is not loaded. Check server logs for details."}), 500

    def scan_and_process_task():
        zap_scanner.log(f"[*] Starting ZAP Quick Scan for {target_url}...")
        
        # Ensure we use the XML path defined at the top
        scan_successful = zap_scanner.run_zap_scan(target_url, XML_REPORT_PATH)

        if scan_successful:
            zap_scanner.log("[+] ZAP scan command finished. Now parsing and enriching report...")
            scan_results = zap_scanner.parse_zap_xml_report(XML_REPORT_PATH)
            
            if scan_results:
                scan_results["target_url"] = target_url
                # Assuming zap_scanner.save_json_report writes to zap_scanner.RESULTS_DIR
                json_report_path = zap_scanner.save_json_report(scan_results, zap_scanner.RESULTS_DIR)
                
                if json_report_path:
                    zap_scanner.log(f"[+] JSON report saved: {json_report_path}")
                    
                    # --- NEW: Generate PDF ---
                    try:
                        zap_scanner.log("[*] Starting PDF report generation...")
                        # This now calls your WeasyPrint generator using the global PDF_REPORT_PATH
                        pdf_generator.create_zap_report_pdf(json_report_path, PDF_REPORT_PATH)
                        
                        if os.path.exists(PDF_REPORT_PATH):
                            zap_scanner.log(f"[+] PDF report generated: {PDF_REPORT_PATH}")
                        else:
                             zap_scanner.log("[!] PDF generation ran but file is missing.")
                             
                    except Exception as e:
                        zap_scanner.log(f"[!] FAILED to generate PDF report: {e}")
                    # --- End of new code ---

                else:
                    zap_scanner.log("[!] Failed to save the final JSON report.")
            else:
                zap_scanner.log("[!] Failed to parse the ZAP XML report after the scan.")
        else:
            zap_scanner.log(f"[!] ZAP scan failed for target: {target_url}. Check logs for details.")

    threading.Thread(target=scan_and_process_task).start()
    
    return jsonify({
        "status": "success",
        "message": f"ZAP Quick Scan initiated for {target_url}. Monitor the logs for progress."
    })


@zap_scanner_bp.route('/scan_results', methods=['GET'])
# @login_required # Uncomment if you want to protect this endpoint
def get_zap_scan_results():
    """
    API endpoint to get the final, enriched ZAP scan report (JSON).
    """
    if not os.path.exists(JSON_REPORT_PATH):
        return jsonify({
            "status": "pending",
            "message": "No JSON report available. Please run a scan first or wait for the current one to complete."
        }), 404
    
    try:
        with open(JSON_REPORT_PATH, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        
        return jsonify({
            "status": "success",
            "data": report_data
        })
    except Exception as e:
        zap_scanner.log(f"[!] Error reading or parsing JSON report file: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to read or parse the report file. Check server logs for details."
        }), 500

# --- NEW: Route to provide report file paths ---
@zap_scanner_bp.route('/report_files', methods=['GET'])
def get_report_files():
    """
    Returns the status and paths of the generated report files.
    """
    json_exists = os.path.exists(JSON_REPORT_PATH)
    pdf_exists = os.path.exists(PDF_REPORT_PATH)

    if not json_exists and not pdf_exists:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    # We return the FULL path from the server root
    return jsonify({
        "status": "success",
        "json_report": "/zap_scanner/scan_results" if json_exists else None,
        "pdf_report": "/zap_scanner/download_pdf" if pdf_exists else None
    })

# --- NEW: Route to download the PDF report ---
@zap_scanner_bp.route('/download_pdf', methods=['GET'])
def download_pdf_report():
    """
    Serves the generated PDF report for download.
    Dynamically determines directory and filename to prevent path errors.
    """
    if not os.path.exists(PDF_REPORT_PATH):
        return jsonify({"status": "error", "message": "PDF report file not found."}), 404
    
    try:
        # Dynamically determine directory and filename from the global path
        directory = os.path.dirname(PDF_REPORT_PATH)
        filename = os.path.basename(PDF_REPORT_PATH)

        return send_from_directory(
            directory=directory,
            path=filename,
            as_attachment=True
        )
    except Exception as e:
        zap_scanner.log(f"[!] Error serving PDF file: {e}")
        return jsonify({"status": "error", "message": "Could not serve PDF file."}), 500


@zap_scanner_bp.route('/clear_log', methods=['POST'])
# @login_required # Uncomment if you want to protect this endpoint
def clear_zap_log_route():
    """API endpoint to clear the ZAP scanner log file."""
    zap_scanner.clear_log_file()
    return jsonify({"status": "success", "message": "ZAP log cleared."})


@zap_scanner_bp.route('/log_stream')
# @login_required # Uncomment if you want to protect this endpoint
def zap_log_stream():
    """
    Server-Sent Events (SSE) endpoint to stream the ZAP scanner log file.
    """
    def generate_logs():
        try:
            with open(zap_scanner.LOG_FILE, 'r', encoding='utf-8') as f:
                f.seek(0, 2) # Go to the end of the file
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    yield f"data: {line.strip()}\n\n"
        except FileNotFoundError:
            yield "data: Log file not found. It will be created when the scan starts.\n\n"
        except Exception as e:
            print(f"Error in log stream: {e}")
            yield f"data: An error occurred in the log stream: {e}\n\n"

    return Response(generate_logs(), mimetype='text/event-stream')