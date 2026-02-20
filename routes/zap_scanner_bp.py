import os
import threading
import json
import time
import queue # Import queue to handle empty exception
from flask import Blueprint, render_template, jsonify, request, Response, send_from_directory, current_app
from flask_login import login_required, current_user
import requests
import uuid 
import logging
from werkzeug.utils import secure_filename 

# --- Logging Setup ---
logger = logging.getLogger(__name__)

# [NEW] Import db to update user stats
from extensions import db

# Import the new zap_scanner module
from Services import zap_scanner
# --- NEW: Import the PDF generator ---
from Services import pdf_generator
# --- Import Scan Logger ---
from Services import scan_logger

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
    logger.info(f"[*] Accessing Web App Scanner Page (User: {current_user.username})")
    return render_template('scanners/zap_scanner.html')


# -----------------------------------------------
# ## 🚀 Scan Initiation & Processing Routes
# -----------------------------------------------

@zap_scanner_bp.route('/scan', methods=['POST'])
@login_required 
def initiate_zap_scan():
    data = request.get_json()
    target_url = data.get('target_url')
    scan_mode = data.get('scan_mode', 'Quick Scan')
    use_ajax = data.get('use_ajax', False)
    auth_config = data.get('auth_config') # {login_url, username_field, password_field, username, password}

    auth_status = "Authenticated" if auth_config else "Anonymous"
    logger.info(f"[*] ZAP Scan ({scan_mode}, AJAX: {use_ajax}, Auth: {auth_status}) requested for {target_url} by {current_user.username}")

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

    # [NEW] Prevent Multiple Concurrent Scans for the same user
    if zap_scanner.is_scan_running(current_user_identifier):
        logger.warning(f"[!] ZAP Scan already in progress for user {current_user_identifier}")
        return jsonify({
            "status": "error", 
            "message": "A ZAP scan is already in progress. Please wait for it to complete or use the 'Stop Scan' feature (if available) before starting a new one."
        }), 400

    user_output_dir = get_user_results_dir()
    user_id_for_log = current_user.id
    app = current_app._get_current_object()

    # [NEW] Increment Database Counter for Stats
    # [NEW] Increment Database Counter
    try:
        current_user.scan_count_zap += 1
        db.session.commit()
    except Exception as e:
        zap_scanner.log(f"[!] Failed to update user stats: {e}", current_user_identifier)

    # [NEW] Reset Log File for this new scan session
    scan_logger.reset_log_file(current_user_identifier, "zap")

    # 5. Log Scan Start (Database)
    log_id = scan_logger.log_scan_start(
        user_id=current_user.id,
        tool_name="ZAP",
        target=target_url,
        scan_type="Quick Scan"
    )

    def scan_and_process_task():
        # Pass composite ID to log function
        zap_scanner.log(f"[*] Starting ZAP {scan_mode} (AJAX: {use_ajax}, Auth: {auth_status}) for {target_url} (User: {current_user_identifier})...", current_user_identifier, to_console=True)
        
        sanitized_target = scan_logger.sanitize_filename(target_url)
        target_pdf_filename = f"zap_report_{sanitized_target}.pdf"
        
        paths = zap_scanner.get_output_paths(user_output_dir)
        xml_path = paths["xml_report"]
        pdf_path = os.path.join(user_output_dir, target_pdf_filename)
        
        os.makedirs(os.path.dirname(xml_path), exist_ok=True)
        
        start_time = time.time()
        
        # 1. Run Scan (Pass composite ID and new parameters)
        scan_successful = zap_scanner.run_zap_scan(
            target_url, str(xml_path), current_user_identifier, 
            scan_mode=scan_mode, use_ajax=use_ajax, auth_config=auth_config
        )

        duration = time.time() - start_time
        finding_count = 0
        status = "Failed"

        if scan_successful:
            status = "Completed"
            zap_scanner.log("[+] ZAP scan command finished. Parsing...", current_user_identifier)
            
            # 2. Parse (Pass composite ID)
            scan_results = zap_scanner.parse_zap_xml_report(str(xml_path), current_user_identifier)
            
            if scan_results:
                scan_results["target_url"] = target_url
                scan_results["scan_mode"] = scan_mode
                scan_results["use_ajax"] = use_ajax
                finding_count = len(scan_results.get("findings", []))
                
                # 3. Save JSON (Pass composite ID to logging inside save function if needed, usually directory is enough)
                json_report_path = zap_scanner.save_json_report(scan_results, user_output_dir, current_user_identifier)
                
                if json_report_path:
                    zap_scanner.log(f"[+] JSON report saved.", current_user_identifier, to_console=True)
                    
                    # 4. Generate PDF
                    try:
                        zap_scanner.log(f"[*] Generating PDF report for {target_url}...", current_user_identifier, to_console=True)
                        pdf_generator.create_zap_report_pdf(json_report_path, str(pdf_path))
                        
                        if os.path.exists(pdf_path):
                            # Final synchronization wait to ensure file handles are closed
                            time.sleep(1.5)
                            zap_scanner.log(f"[+] PDF generated successfully.", current_user_identifier, to_console=True)
                            zap_scanner.log(f"SYSTEM_EVENT: READY_FOR_ANALYSIS:{target_url}", current_user_identifier, to_console=True)
                            zap_scanner.log(f"[*] Scan, analysis, and prediction complete.", current_user_identifier, to_console=True)
                        else:
                             zap_scanner.log("[!] PDF generation failed (file missing).", current_user_identifier, to_console=True)
                             
                    except Exception as e:
                        zap_scanner.log(f"[!] FAILED to generate PDF report: {e}", current_user_identifier, to_console=True)

                else:
                    zap_scanner.log("[!] Failed to save JSON report.", current_user_identifier)
            else:
                zap_scanner.log("[!] Failed to parse ZAP XML report.", current_user_identifier)
        else:
            zap_scanner.log(f"[!] ZAP scan failed for target: {target_url}.", current_user_identifier)

        # Log to Database (Inside App Context)
        with app.app_context():
            # [FIXED] Pass correct error message if failed
            error_msg = None if scan_successful else "ZAP scan process failed."
            scan_logger.log_scan_end(log_id, status=status, finding_count=finding_count, duration=duration, error_msg=error_msg)

    threading.Thread(target=scan_and_process_task).start()
    
    return jsonify({
        "status": "success",
        "message": f"ZAP Quick Scan initiated for {target_url}. Monitor the logs for progress."
    })


@zap_scanner_bp.route('/status', methods=['GET'])
@login_required
def get_zap_status():
    """Checks if a ZAP scan is currently running for the user (DB Source of Truth)."""
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    
    # 1. CHECK DB (Primary Source of Truth)
    active_log = scan_logger.get_active_scan_log(current_user.id, "ZAP")
    
    if active_log:
        return jsonify({
            "status": "success",
            "is_running": True,
            "target": active_log.target
        })

    # 2. Fallback: Check Memory
    is_running = zap_scanner.is_scan_running(current_user_identifier)
    
    target = None
    if is_running:
        with zap_scanner.scan_lock:
            target = zap_scanner.active_scans[current_user_identifier].get('target')

    return jsonify({
        "status": "success",
        "is_running": is_running,
        "target": target
    })


@zap_scanner_bp.route('/trigger_ai_analysis', methods=['POST'])
@login_required
def trigger_ai_analysis_route():
    data = request.get_json() or {}
    target = data.get('target')
    user_dir = get_user_results_dir()
    
    if target:
        sanitized = scan_logger.sanitize_filename(target)
        pdf_filename = f"zap_report_{sanitized}.pdf"
    else:
        paths = zap_scanner.get_output_paths(user_dir)
        pdf_filename = os.path.basename(paths["pdf_report"])

    pdf_path = os.path.join(user_dir, pdf_filename)

    if not os.path.exists(pdf_path):
        return jsonify({
            "status": "error", 
            "message": "PDF report not available. Please run a scan first."
        }), 404

    return jsonify({
        "status": "success",
        "scanner_type": "zap",
        "target": target
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
    target = request.args.get('target')
    user_dir = get_user_results_dir()
    paths = zap_scanner.get_output_paths(user_dir)
    
    if target:
        sanitized = scan_logger.sanitize_filename(target)
        pdf_filename = f"zap_report_{sanitized}.pdf"
    else:
        pdf_filename = os.path.basename(paths["pdf_report"])

    json_exists = paths["json_report"].exists()
    pdf_exists = os.path.exists(os.path.join(user_dir, pdf_filename))

    if not json_exists and not pdf_exists:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    return jsonify({
        "status": "success",
        "json_report": "/zap_scanner/scan_results" if json_exists else None,
        "pdf_report": f"/zap_scanner/download_pdf?target={target}" if pdf_exists else None
    })


@zap_scanner_bp.route('/download_pdf', methods=['GET'])
@login_required
def download_pdf_report():
    target = request.args.get('target')
    user_dir = get_user_results_dir()
    
    if target:
        sanitized = scan_logger.sanitize_filename(target)
        pdf_filename = f"zap_report_{sanitized}.pdf"
    else:
        paths = zap_scanner.get_output_paths(user_dir)
        pdf_filename = os.path.basename(paths["pdf_report"])

    pdf_path = os.path.join(user_dir, pdf_filename)

    if not os.path.exists(pdf_path):
        return jsonify({"status": "error", "message": "PDF file not found."}), 404
    
    try:
        directory = user_dir
        filename = pdf_filename
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
    Streams logs specifically for the logged-in user from their active log file.
    """
    # Use composite identifier
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    
    # Use the file tailing generator from scan_logger
    return Response(
        scan_logger.tail_log_file(current_user_identifier, "zap"), 
        mimetype='text/event-stream'
    )