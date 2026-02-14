from flask import Blueprint, render_template, jsonify, request, Response, send_from_directory, current_app
from flask_login import login_required, current_user
import threading
import json
import time
import os
from queue import Empty
import requests
import uuid
import logging
from werkzeug.utils import secure_filename 

# --- Logging Setup ---
logger = logging.getLogger(__name__)

# [NEW] Import db to update user stats
from extensions import db

# Import the ssl_scanner module
from Services import ssl_scanner
# Import the PDF generator module
from Services import pdf_generator
# --- Import Scan Logger ---
from Services import scan_logger

ssl_scanner_bp = Blueprint('ssl_scanner_bp', __name__)

# --- PHASE 3: User-Specific Directory Helper ---
def get_user_results_dir():
    """
    Constructs the path: Services/results/<username_id>/ssl_scanner
    """
    if not current_user.is_authenticated:
        return None
    
    # NEW LOGIC: Composite Identifier
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    user_dir = os.path.join(base_dir, 'Services', 'results', user_identifier, 'ssl_scanner')
    
    # FIXED: Added exist_ok=True to prevent race condition crashes
    os.makedirs(user_dir, exist_ok=True)
        
    return user_dir

# ==========================================
# --- ⚙️ CONFIGURATION (Default references)
# ==========================================
SERVER_PROXY_URL = "http://localhost:5100" 
# ==========================================

@ssl_scanner_bp.route('/')
@login_required
def ssl_scanner_page():
    """Renders the SSL scanner page."""
    logger.info(f"\033[32m[*] Accessing SSL Scanner Page (User: {current_user.username})\033[0m")
    return render_template('scanners/ssl_scanner.html')

@ssl_scanner_bp.route('/scan', methods=['POST'])
@login_required
def scan_ssl():
    """
    API endpoint to initiate an SSL scan using the local sslscan executable.
    Runs the scan in a separate thread to avoid blocking the Flask app.
    """
    data = request.get_json()
    target_host = data.get('target_host')
    logger.info(f"\033[32m[*] SSL Scan requested for {target_host} by {current_user.username}\033[0m")

    if not target_host:
        ssl_scanner.log("[!] Target host cannot be empty for SSL scan.", user_identifier)
        return jsonify({"status": "error", "message": "Target host is required."}), 400

    if not ssl_scanner.is_sslscan_available():
        ssl_scanner.log("[!] sslscan.exe is not available. Cannot perform scan.", user_identifier)
        return jsonify({
            "status": "error",
            "message": "sslscan.exe not found. Please check server configuration and logs."
        }), 500
    
    # Determine User Directory for this scan
    user_output_dir = get_user_results_dir()

    # --- Capture Context for Thread ---
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_id = current_user.id
    app = current_app._get_current_object()

    # [NEW] Increment Database Counter for Stats
    try:
        current_user.scan_count_ssl += 1
        db.session.commit()
    except Exception as e:
        ssl_scanner.log(f"[!] Failed to update user stats: {e}", current_user_identifier)

    # Function to run in a separate thread
    def scan_task():
        # Use captured identifier
        ssl_scanner.log(f"[*] Starting SSL scan for {target_host} (User: {current_user_identifier})...", current_user_identifier, to_console=True)
        
        start_time = time.time()
        
        # 1. Run the Scan (Generates XML) - Pass user directory
        report_file = ssl_scanner.run_ssl_scan(target_host, output_dir=user_output_dir)
        
        duration = time.time() - start_time
        status = "Failed"
        finding_count = 0

        if report_file:
            status = "Completed"
            # 2. Parse XML and Save JSON
            # Pass user directory so JSON is saved there
            summary = ssl_scanner.parse_ssl_report(report_file, output_dir=user_output_dir)
            
            if summary:
                # Count "findings" as combined weak protocols + vulnerabilities
                finding_count = len(summary.get('protocols', [])) + len(summary.get('vulnerabilities', []))
                
                ssl_scanner.log(f"[+] SSL scan complete. Generating PDF report...", current_user_identifier, to_console=True)
                
                # 3. Generate PDF Report
                try:
                    # Get user-specific paths
                    user_paths = ssl_scanner.get_output_paths(user_output_dir)
                    json_path = user_paths["json_report"]
                    pdf_path = user_paths["pdf_report"]

                    # Create the directory for PDFs if it doesn't exist
                    os.makedirs(pdf_path.parent, exist_ok=True)
                    
                    # Generate PDF using the JSON file
                    pdf_generator.create_ssl_report_pdf(str(json_path), str(pdf_path))
                    
                    if pdf_path.exists():
                        ssl_scanner.log(f"[+] PDF report generated successfully: {pdf_path}", current_user_identifier, to_console=True)
                    else:
                        ssl_scanner.log("[!] PDF generation ran but file not found.", current_user_identifier, to_console=True)
                
                except Exception as e:
                    ssl_scanner.log(f"[!] FAILED to generate PDF: {str(e)}", current_user_identifier, to_console=True)
            else:
                ssl_scanner.log(f"[!] Failed to parse SSL report for {target_host}.", current_user_identifier, to_console=True)
        else:
            ssl_scanner.log(f"[!] SSL scan failed for {target_host}.", current_user_identifier, to_console=True)

        # Log to Database (Inside App Context)
        with app.app_context():
            scan_logger.create_full_scan_log(
                user_id=user_id,
                tool_name="SSLScan",
                target=target_host,
                duration=duration,
                finding_count=finding_count,
                status=status,
                scan_type="Standard"
            )

    threading.Thread(target=scan_task).start()
    return jsonify({"status": "success", "message": f"SSL scan for {target_host} initiated."})

@ssl_scanner_bp.route('/trigger_ai_analysis', methods=['POST'])
@login_required
def trigger_ai_analysis_route():
    """
    Checks if PDF exists and returns scanner type. 
    """
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_dir = get_user_results_dir()
    paths = ssl_scanner.get_output_paths(user_dir)
    pdf_path = paths["pdf_report"]

    if not pdf_path.exists():
        ssl_scanner.log(f"[!] Analysis failed: PDF report not found at {pdf_path}", user_identifier)
        return jsonify({
            "status": "error", 
            "message": "PDF report not available. Please run a scan first."
        }), 404

    # Returns the scanner type so the chatbot blueprint knows which file to read.
    return jsonify({
        "status": "success",
        "scanner_type": "ssl" 
    })

@ssl_scanner_bp.route('/report_files', methods=['GET'])
@login_required
def get_report_files():
    """Checks availability of reports to enable the download button."""
    user_dir = get_user_results_dir()
    paths = ssl_scanner.get_output_paths(user_dir)
    
    json_exists = paths["json_report"].exists()
    pdf_exists = paths["pdf_report"].exists()

    if not json_exists and not pdf_exists:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    return jsonify({
        "status": "success",
        "json_report": "/ssl_scanner/get_json_report" if json_exists else None,
        "pdf_report": "/ssl_scanner/download_pdf" if pdf_exists else None
    })

@ssl_scanner_bp.route('/download_pdf', methods=['GET'])
@login_required
def download_pdf_report():
    """Serves the PDF report dynamically."""
    user_dir = get_user_results_dir()
    paths = ssl_scanner.get_output_paths(user_dir)
    pdf_path = paths["pdf_report"]

    if not pdf_path.exists():
        return jsonify({"status": "error", "message": "PDF report file not found."}), 404
    
    directory = str(pdf_path.parent)
    filename = pdf_path.name

    return send_from_directory(
        directory=directory,
        path=filename,
        as_attachment=True
    )

@ssl_scanner_bp.route('/get_json_report', methods=['GET'])
@login_required
def get_json_report_file():
    """Serves the JSON report file."""
    user_dir = get_user_results_dir()
    paths = ssl_scanner.get_output_paths(user_dir)
    json_path = paths["json_report"]

    if not json_path.exists():
        return jsonify({"status": "error", "message": "JSON report file not found."}), 404
    
    directory = str(json_path.parent)
    filename = json_path.name

    return send_from_directory(
        directory=directory,
        path=filename,
        as_attachment=True
    )

@ssl_scanner_bp.route('/report', methods=['GET'])
@login_required
def get_ssl_report():
    """
    API endpoint to get the content of the parsed SSL scan report (JSON content).
    This is used by the frontend to render the immediate results view.
    """
    user_dir = get_user_results_dir()
    paths = ssl_scanner.get_output_paths(user_dir)
    json_path = paths["json_report"]

    if not json_path.exists():
        return jsonify({
            "status": "error",
            "message": "No SSL scan report available. Please run a scan first."
        }), 404
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            parsed_summary = json.load(f)

        return jsonify({
            "status": "success",
            "content": parsed_summary, 
            "report_file": json_path.name
        })
    except Exception as e:
        ssl_scanner.log(f"[!] Error reading or parsing SSL scan report: {e}", user_identifier)
        return jsonify({
            "status": "error",
            "message": f"Failed to read or parse SSL scan report: {str(e)}"
        }), 500

@ssl_scanner_bp.route('/clear_log', methods=['POST'])
@login_required
def clear_ssl_log_route():
    """API endpoint to clear the SSL scanner log file."""
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    ssl_scanner.clear_log_file(user_identifier)
    return jsonify({"status": "success", "message": "SSL log cleared."})

@ssl_scanner_bp.route('/log_stream')
@login_required
def ssl_log_stream():
    """Server-Sent Events (SSE) endpoint to stream SSL scanner log messages."""
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    def generate_logs():
        user_queue = ssl_scanner.get_user_queue(user_identifier)
        while True:
            try:
                message = user_queue.get(timeout=10)
                yield message
            except Empty:
                yield ": keep-alive\n\n"
            except GeneratorExit:
                break

    return Response(generate_logs(), mimetype='text/event-stream')