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
from Services import report_manager

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
    logger.info(f"[*] Accessing SSL Scanner Page (User: {current_user.username})")
    
    user_agent = request.headers.get('User-Agent')
    if user_agent and any(word in user_agent for word in ['Mobile', 'Android', 'iPhone', 'iPad']):
        return render_template('mobile_scanners/ssl_scanner.html')
        
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
    logger.info(f"[*] SSL Scan requested for {target_host} by {current_user.username}")

    # Determine User Directory for this scan
    user_output_dir = get_user_results_dir()

    # --- Capture Context for Thread ---
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_id = current_user.id
    app = current_app._get_current_object()

    if not target_host:
        ssl_scanner.log("[!] Target host cannot be empty for SSL scan.", current_user_identifier)
        return jsonify({"status": "error", "message": "Target host is required."}), 400

    if not ssl_scanner.is_sslscan_available(user_id=current_user_identifier):
        ssl_scanner.log("[!] sslscan.exe is not available. Cannot perform scan.", current_user_identifier)
        return jsonify({
            "status": "error",
            "message": "sslscan.exe not found. Please check server configuration and logs."
        }), 500

    # [NEW] Prevent Multiple Concurrent Scans for the same user
    if ssl_scanner.is_scan_running(current_user_identifier):
        logger.warning(f"[!] SSL Scan already in progress for user {current_user_identifier}")
        return jsonify({
            "status": "error", 
            "message": "An SSL scan is already in progress. Please wait for it to complete."
        }), 400

    # [RC-8 FIX] Atomic DB counter increment
    try:
        from sqlalchemy import update as _sa_update
        from models import User as _User
        db.session.execute(
            _sa_update(_User).where(_User.id == current_user.id)
            .values(scan_count_ssl=_User.scan_count_ssl + 1)
        )
        db.session.commit()
    except Exception as e:
        db.session.rollback()  # RC-3 FIX
        ssl_scanner.log(f"[!] Failed to update user stats: {e}", current_user_identifier)

    # [NEW] Reset Log File for this new scan session
    scan_logger.reset_log_file(current_user_identifier, "ssl_scanner")

    # Function to run in a separate thread
    def scan_task():
        # Use DB Logging
        with app.app_context():
            log_id = scan_logger.log_scan_start(
                user_id=user_id,
                tool_name="SSLScan",
                target=target_host,
                scan_type="Standard"
            )

        start_time = time.time()
        
        # 1. Run the Scan (Generates XML) - Pass user directory
        report_file = ssl_scanner.run_ssl_scan(target_host, output_dir=user_output_dir, user_id=current_user_identifier)
        
        duration = time.time() - start_time
        status = "Failed"
        finding_count = 0

        if report_file:
            status = "Completed"
            # 2. Parse XML and Save JSON
            # Pass user directory so JSON is saved there
            summary = ssl_scanner.parse_ssl_report(report_file, output_dir=user_output_dir, user_id=current_user_identifier, target=target_host)
            if summary:
                # Count "findings" as combined weak protocols + vulnerabilities
                finding_count = len(summary.get('protocols', [])) + len(summary.get('vulnerabilities', []))
                
                ssl_scanner.log(f"[+] SSL scan data processed. Generating PDF report for {target_host}...", current_user_identifier, to_console=True)
                
                # 3. Generate PDF Report
                try:
                    # Get user-specific paths
                    user_paths = ssl_scanner.get_output_paths(user_output_dir, target=target_host)
                    json_path = user_paths["json_report"]
                    pdf_path = user_paths["pdf_report"]

                    # Create the directory for PDFs if it doesn't exist
                    os.makedirs(os.path.dirname(pdf_path), exist_ok=True)
                    
                    # Generate PDF using the JSON file
                    pdf_generator.create_ssl_report_pdf(str(json_path), str(pdf_path))
                    
                    if os.path.exists(pdf_path):
                        # Final synchronization wait
                        time.sleep(1.5)
                        ssl_scanner.log(f"[+] SSL_SCAN_FINALIZED_SUCCESSFULLY", current_user_identifier, to_console=True)
                        ssl_scanner.log(f"SYSTEM_EVENT: READY_FOR_ANALYSIS:{target_host}", current_user_identifier, to_console=True)
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
            # [FIXED] Pass error msg on failure
            error_msg = None if status == "Completed" else "SSL scan failed."
            scan_logger.log_scan_end(log_id, status=status, finding_count=finding_count, duration=duration, error_msg=error_msg)

    threading.Thread(target=scan_task, daemon=True).start()  # RC-5 FIX: daemon=True
    return jsonify({"status": "success", "message": f"SSL scan for {target_host} initiated."})


@ssl_scanner_bp.route('/check_active_scan', methods=['GET'])
@login_required
def check_active_scan():
    """
    Checks if there's an active scan running for the current user's session.
    Prioritizes DB state (SSOT).
    """
    # 1. CHECK DB (Primary Source of Truth)
    active_log = scan_logger.get_active_scan_log(current_user.id, "SSLScan")
    
    if active_log:
        return jsonify({
            "status": "active",
            "message": "Active scan found (DB)",
            "target": active_log.target,
            "scan_id": active_log.id
        }), 200

    # 2. Fallback: Check Memory
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    if ssl_scanner.is_scan_running(current_user_identifier):
         return jsonify({
            "status": "active",
            "message": "Active scan found (Memory)"
        }), 200

    return jsonify({"status": "inactive", "message": "No active scan found"}), 200


@ssl_scanner_bp.route('/report_history', methods=['GET'])
@login_required
def get_ssl_report_history():
    user_dir = get_user_results_dir()
    history = report_manager.get_report_history(user_dir, scanner_name="ssl_report")
    return jsonify({"status": "success", "history": history})

@ssl_scanner_bp.route('/trigger_ai_analysis', methods=['POST'])
@login_required
def trigger_ai_analysis_route():
    """Robustly triggers AI analysis by finding the correct PDF report."""
    data = request.get_json() or {}
    target = data.get('target')
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_dir = get_user_results_dir()
    
    # 1. Resolve PDF Path with Fallbacks
    from pathlib import Path
    pdf_path = None
    
    if target:
        paths = ssl_scanner.get_output_paths(user_dir, target=target)
        pdf_path = Path(paths["pdf_report"])
    
    # Fallback 1: History search (Recent for this scanner)
    if not pdf_path or not pdf_path.exists():
        history = report_manager.get_report_history(user_dir, scanner_name="ssl_report", extension="pdf")
        if history:
            pdf_path = Path(history[0]['path'])
    
    # Fallback 2: Any PDF in the results directory
    if not pdf_path or not pdf_path.exists():
        history = report_manager.get_report_history(user_dir, scanner_name=None, extension="pdf")
        if history:
            pdf_path = Path(history[0]['path'])

    if not pdf_path or not pdf_path.exists():
        ssl_scanner.log(f"[!] Analysis failed: PDF report not found in {user_dir}", user_identifier)
        return jsonify({
            "status": "error", 
            "message": "PDF report not available. Please run a scan first."
        }), 404

    return jsonify({
        "status": "success",
        "scanner_type": "ssl",
        "target": target
    })

@ssl_scanner_bp.route('/report_files', methods=['GET'])
@login_required
def get_report_files():
    """Checks availability of reports to enable the download button."""
    target = request.args.get('target')
    user_dir = get_user_results_dir()
    paths = ssl_scanner.get_output_paths(user_dir, target=target)
    
    json_exists = paths["json_report"].exists()
    pdf_exists = paths["pdf_report"].exists()

    if not json_exists and not pdf_exists:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    return jsonify({
        "status": "success",
        "json_report": f"/ssl_scanner/get_json_report?target={target}" if json_exists else None,
        "pdf_report": f"/ssl_scanner/download_pdf?target={target}" if pdf_exists else None
    })

@ssl_scanner_bp.route('/download_pdf', methods=['GET'])
@login_required
def download_pdf_report():
    """Serves the PDF report dynamically."""
    user_dir = get_user_results_dir()
    
    # Check if a specific filename is requested
    requested_filename = request.args.get('filename')
    target = request.args.get('target') # For backward compatibility

    if requested_filename:
        filename = secure_filename(requested_filename)
        pdf_path = os.path.join(user_dir, filename)
        if not os.path.exists(pdf_path):
             return jsonify({"status": "error", "message": f"Report {filename} not found."}), 404
    elif target:
        filename = report_manager.generate_report_filename("ssl_report", target, "pdf")
        pdf_path = os.path.join(user_dir, filename)
    else:
        # Fallback to latest
        history = report_manager.get_report_history(user_dir, scanner_name="ssl_report")
        if not history:
             return jsonify({"status": "error", "message": "No reports found."}), 404
        pdf_path = history[0]['path']
        filename = os.path.basename(pdf_path)

    if not os.path.exists(pdf_path):
        return jsonify({"status": "error", "message": "PDF report file not found."}), 404
    
    directory = os.path.dirname(pdf_path)

    return send_from_directory(
        directory=directory,
        path=filename,
        as_attachment=True
    )

@ssl_scanner_bp.route('/get_json_report', methods=['GET'])
@login_required
def get_json_report_file():
    """Serves the JSON report file."""
    target = request.args.get('target')
    user_dir = get_user_results_dir()
    paths = ssl_scanner.get_output_paths(user_dir, target=target)
    json_path = paths["json_report"]

    if not json_path.exists():
        return jsonify({"status": "error", "message": "JSON report file not found."}), 404
    
    return send_from_directory(
        directory=str(json_path.parent),
        path=json_path.name,
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
    target = request.args.get('target')
    paths = ssl_scanner.get_output_paths(user_dir, target=target)
    json_path = paths["json_report"]

    if not json_path.exists() and not target:
        # Fallback to latest JSON
        history = report_manager.get_report_history(user_dir, scanner_name="ssl_report", extension="json")
        if history:
            json_path = Path(history[0]['path'])

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
    scan_logger.reset_log_file(user_identifier, "ssl_scanner")
    return jsonify({"status": "success", "message": "SSL log cleared."})

@ssl_scanner_bp.route('/log_stream')
@login_required
def ssl_log_stream():
    """Server-Sent Events (SSE) endpoint to stream SSL scanner log messages."""
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    return Response(
        scan_logger.tail_log_file(user_identifier, "ssl_scanner"),
        mimetype='text/event-stream'
    )