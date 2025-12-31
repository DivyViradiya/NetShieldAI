import os
import threading
import json
import time
import queue # Import queue to handle empty exception
from flask import Blueprint, render_template, jsonify, request, Response, send_from_directory
from flask_login import login_required, current_user
import requests
import uuid 
from werkzeug.utils import secure_filename # <--- Added Import

# Import the new zap_scanner module
from Services import zap_scanner
# --- NEW: Import the PDF generator ---
from Services import pdf_generator 

zap_scanner_bp = Blueprint('zap_scanner_bp', __name__)

# --- User-Specific Directory Helper ---
def get_user_results_dir():
    if not current_user.is_authenticated:
        return None
    
    # NEW LOGIC: Composite Identifier
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    user_dir = os.path.join(base_dir, 'Services', 'results', user_identifier, 'zap_scanner')
    
    # FIXED: Added exist_ok=True to prevent race condition crashes
    os.makedirs(user_dir, exist_ok=True)
        
    return user_dir

SERVER_PROXY_URL = "http://localhost:5100" 

# -----------------------------------------------
# ## 🖥️ UI Route
# -----------------------------------------------

@zap_scanner_bp.route('/')
@login_required 
def zap_scanner_page():
    return render_template('zap_scanner.html')


# -----------------------------------------------
# ## 🚀 Scan Initiation & Processing Routes
# -----------------------------------------------

@zap_scanner_bp.route('/scan', methods=['POST'])
@login_required 
def initiate_zap_scan():
    data = request.get_json()
    target_url = data.get('target_url')

    if not target_url:
        return jsonify({"status": "error", "message": "Target URL is required."}), 400
    
    # --- Auto-append Protocol ---
    target_url = target_url.strip() 
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    if zap_scanner.model is None:
        return jsonify({"status": "error", "message": "ML model is not loaded. Check server logs."}), 500

    # Capture User Context for Thread using Composite ID
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_output_dir = get_user_results_dir()

    def scan_and_process_task():
        # Pass composite ID to log function
        zap_scanner.log(f"[*] Starting ZAP Quick Scan for {target_url} (User: {current_user_identifier})...", current_user_identifier)
        
        paths = zap_scanner.get_output_paths(user_output_dir)
        xml_path = paths["xml_report"]
        pdf_path = paths["pdf_report"]
        
        os.makedirs(os.path.dirname(xml_path), exist_ok=True)
        
        # 1. Run Scan (Pass composite ID)
        scan_successful = zap_scanner.run_zap_scan(target_url, str(xml_path), current_user_identifier)

        if scan_successful:
            zap_scanner.log("[+] ZAP scan command finished. Parsing...", current_user_identifier)
            
            # 2. Parse (Pass composite ID)
            scan_results = zap_scanner.parse_zap_xml_report(str(xml_path), current_user_identifier)
            
            if scan_results:
                scan_results["target_url"] = target_url
                # 3. Save JSON (Pass composite ID to logging inside save function if needed, usually directory is enough)
                json_report_path = zap_scanner.save_json_report(scan_results, user_output_dir, current_user_identifier)
                
                if json_report_path:
                    zap_scanner.log(f"[+] JSON report saved.", current_user_identifier)
                    
                    # 4. Generate PDF
                    try:
                        zap_scanner.log("[*] Generating PDF report...", current_user_identifier)
                        pdf_generator.create_zap_report_pdf(json_report_path, str(pdf_path))
                        
                        if pdf_path.exists():
                            zap_scanner.log(f"[+] PDF generated successfully.", current_user_identifier)
                            zap_scanner.log(f"[*] Scan, analysis, and prediction complete.", current_user_identifier)
                        else:
                             zap_scanner.log("[!] PDF generation failed (file missing).", current_user_identifier)
                             
                    except Exception as e:
                        zap_scanner.log(f"[!] FAILED to generate PDF report: {e}", current_user_identifier)

                else:
                    zap_scanner.log("[!] Failed to save JSON report.", current_user_identifier)
            else:
                zap_scanner.log("[!] Failed to parse ZAP XML report.", current_user_identifier)
        else:
            zap_scanner.log(f"[!] ZAP scan failed for target: {target_url}.", current_user_identifier)

    threading.Thread(target=scan_and_process_task).start()
    
    return jsonify({
        "status": "success",
        "message": f"ZAP Quick Scan initiated for {target_url}. Monitor the logs for progress."
    })


@zap_scanner_bp.route('/trigger_ai_analysis', methods=['POST'])
@login_required
def trigger_ai_analysis_route():
    user_dir = get_user_results_dir()
    paths = zap_scanner.get_output_paths(user_dir)
    pdf_path = paths["pdf_report"]

    if not pdf_path.exists():
        return jsonify({
            "status": "error", 
            "message": "PDF report not available. Please run a scan first."
        }), 404

    return jsonify({
        "status": "success",
        "scanner_type": "zap" 
    })


# -----------------------------------------------
# ## 📥 Report Retrieval Routes
# -----------------------------------------------

@zap_scanner_bp.route('/scan_results', methods=['GET'])
@login_required 
def get_zap_scan_results():
    user_dir = get_user_results_dir()
    paths = zap_scanner.get_output_paths(user_dir)
    json_path = paths["json_report"]

    if not json_path.exists():
        return jsonify({
            "status": "pending",
            "message": "No JSON report available."
        }), 404
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        return jsonify({"status": "success", "data": report_data})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@zap_scanner_bp.route('/report_files', methods=['GET'])
@login_required
def get_report_files():
    user_dir = get_user_results_dir()
    paths = zap_scanner.get_output_paths(user_dir)
    
    json_exists = paths["json_report"].exists()
    pdf_exists = paths["pdf_report"].exists()

    if not json_exists and not pdf_exists:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    return jsonify({
        "status": "success",
        "json_report": "/zap_scanner/scan_results" if json_exists else None,
        "pdf_report": "/zap_scanner/download_pdf" if pdf_exists else None
    })


@zap_scanner_bp.route('/download_pdf', methods=['GET'])
@login_required
def download_pdf_report():
    user_dir = get_user_results_dir()
    paths = zap_scanner.get_output_paths(user_dir)
    pdf_path = paths["pdf_report"]

    if not pdf_path.exists():
        return jsonify({"status": "error", "message": "PDF file not found."}), 404
    
    try:
        directory = str(pdf_path.parent)
        filename = pdf_path.name
        return send_from_directory(directory=directory, path=filename, as_attachment=True)
    except Exception as e:
        return jsonify({"status": "error", "message": "Could not serve PDF file."}), 500


# -----------------------------------------------
# ## 📝 Log Streaming Routes (User Isolated)
# -----------------------------------------------

@zap_scanner_bp.route('/clear_log', methods=['POST'])
@login_required 
def clear_zap_log_route():
    """Clears the log for the CURRENT USER only."""
    # Use composite identifier
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    zap_scanner.clear_log_file(current_user_identifier)
    return jsonify({"status": "success", "message": "Log cleared."})


@zap_scanner_bp.route('/log_stream')
@login_required 
def zap_log_stream():
    """
    Streams logs specifically for the logged-in user from their memory queue.
    """
    # Use composite identifier
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    
    def generate_logs():
        # Get the specific queue for this user
        user_queue = zap_scanner.get_user_queue(current_user_identifier)
        
        while True:
            try:
                # Wait for message (blocking to avoid busy loop)
                message = user_queue.get(timeout=5)
                yield f"data: {message}\n\n"
            except queue.Empty:
                # Keep connection alive
                yield ": keep-alive\n\n"
            except Exception as e:
                yield f"data: Error in stream: {str(e)}\n\n"

    return Response(generate_logs(), mimetype='text/event-stream')