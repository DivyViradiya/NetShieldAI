import os
from pathlib import Path
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
# --- NEW: Import the PDF generator and Report Manager ---
from Services import pdf_generator
from Services import report_manager
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
    logger.info(f"\033[34m[*] Accessing Web App Scanner Page (User: {current_user.username})\033[0m")
    user_agent = request.headers.get('User-Agent')
    if user_agent and any(word in user_agent for word in ['Mobile', 'Android', 'iPhone', 'iPad']):
        return render_template('mobile_scanners/zap_scanner.html')
    return render_template('scanners/zap_scanner.html')


# -----------------------------------------------
# ## 🚀 Scan Initiation & Processing Routes
# -----------------------------------------------

@zap_scanner_bp.route('/scan', methods=['POST'])
@login_required 
def initiate_zap_scan():
    data = request.get_json()
    target_url = data.get('target_url')
    scan_mode = data.get('scan_mode', 'default')
    logger.info(f"\033[34m[*] ZAP Scan requested for {target_url} (Mode: {scan_mode}) by {current_user.username}\033[0m")

    if not target_url:
        return jsonify({"status": "error", "message": "Target URL is required."}), 400
    
    # --- Auto-append Protocol ---
    target_url = target_url.strip() 
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    # [REMOVED] Legacy model check. TCTREngine handles model availability internally.

    # Capture User Context for Thread using Composite ID
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_output_dir = get_user_results_dir()
    user_id_for_log = current_user.id
    app = current_app._get_current_object()

    # RC-12 FIX: Prevent duplicate concurrent ZAP scans for the same user (mirrors Nmap guard)
    if zap_scanner.is_scan_running(current_user_identifier):
        logger.warning(f"[!] ZAP Scan already in progress for user {current_user_identifier}")
        return jsonify({
            "status": "error",
            "message": "A ZAP scan is already in progress. Please wait for it to complete."
        }), 400

    # [RC-8 FIX] Atomic DB counter increment — prevents double-count on concurrent tabs
    try:
        from sqlalchemy import update as _sa_update
        from models import User as _User
        db.session.execute(
            _sa_update(_User).where(_User.id == current_user.id)
            .values(scan_count_zap=_User.scan_count_zap + 1)
        )
        db.session.commit()
    except Exception as e:
        db.session.rollback()  # RC-3 FIX: clean session before thread starts
        zap_scanner.log(f"[!] Failed to update user stats: {e}", current_user_identifier)

    def scan_and_process_task():
        # Pass composite ID to log function
        zap_scanner.log(f"[*] Starting ZAP Quick Scan for {target_url} (User: {current_user_identifier})...", current_user_identifier, to_console=True)
        
        paths = zap_scanner.get_output_paths(user_output_dir, target=target_url)
        xml_path = paths["xml_report"]
        pdf_path = paths["pdf_report"]
        
        os.makedirs(os.path.dirname(xml_path), exist_ok=True)
        
        start_time = time.time()
        
        # 1. Run Scan (Pass composite ID and scan_mode)
        scan_successful = zap_scanner.run_zap_scan(target_url, str(xml_path), current_user_identifier, scan_mode=scan_mode)

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
                finding_count = len(scan_results.get("findings", []))
                
                # 3. Save JSON (Pass composite ID to logging inside save function if needed, usually directory is enough)
                json_report_path = zap_scanner.save_json_report(scan_results, user_output_dir, current_user_identifier, target=target_url)
                
                if json_report_path:
                    zap_scanner.log(f"[+] JSON report saved.", current_user_identifier, to_console=True)
                    
                    # 4. Generate PDF
                    try:
                        zap_scanner.log("[*] Generating PDF report...", current_user_identifier, to_console=True)
                        pdf_generator.create_zap_report_pdf(json_report_path, str(pdf_path))
                        
                        if pdf_path.exists():
                            # Final synchronization wait to ensure file handles are closed
                            time.sleep(1.5)
                            zap_scanner.log(f"[+] PDF generated successfully.", current_user_identifier, to_console=True)
                            zap_scanner.log("SYSTEM_EVENT: READY_FOR_ANALYSIS", current_user_identifier, to_console=True)
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
            scan_logger.create_full_scan_log(
                user_id=user_id_for_log,
                tool_name="ZAP",
                target=target_url,
                duration=duration,
                finding_count=finding_count,
                status=status,
                scan_type="Quick Scan"
            )

    threading.Thread(target=scan_and_process_task, daemon=True).start()  # RC-5 FIX: daemon=True
    
    return jsonify({
        "status": "success",
        "message": f"ZAP Quick Scan initiated for {target_url}. Monitor the logs for progress."
    })


@zap_scanner_bp.route('/status', methods=['GET'])
@login_required
def get_zap_status():
    """Checks if a ZAP scan is currently running for the user."""
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    is_running = zap_scanner.is_scan_running(current_user_identifier)
    
    # Also get the target if running
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
    """Robustly triggers AI analysis by finding the correct PDF report."""
    data = request.get_json() or {}
    target = data.get('target')
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_dir = get_user_results_dir()
    
    # 1. Resolve PDF Path with Fallbacks
    from pathlib import Path
    pdf_path = None
    
    if target:
        paths = zap_scanner.get_output_paths(user_dir, target=target)
        pdf_path = Path(paths["pdf_report"])
    
    # Fallback 1: History search (Recent for this scanner)
    if not pdf_path or not pdf_path.exists():
        history = report_manager.get_report_history(user_dir, scanner_name="zap_scanner", extension="pdf")
        if history:
            pdf_path = Path(history[0]['path'])
    
    # Fallback 2: Any PDF in the results directory
    if not pdf_path or not pdf_path.exists():
        history = report_manager.get_report_history(user_dir, scanner_name=None, extension="pdf")
        if history:
            pdf_path = Path(history[0]['path'])

    if not pdf_path or not pdf_path.exists():
        zap_scanner.log(f"[!] Analysis failed: PDF report not found in {user_dir}", user_identifier)
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
    target = request.args.get('target')

    if not target:
        history = report_manager.get_report_history(user_dir, scanner_name="zap_scanner", extension="json")
        if history:
            json_path = Path(history[0]['path'])
        else:
            json_path = zap_scanner.get_output_paths(user_dir, target=target)["json_report"]
    else:
        paths = zap_scanner.get_output_paths(user_dir, target=target)
        json_path = paths["json_report"]
    
    print(f"[DEBUG] Accessing ZAP results at: {json_path} (exists: {json_path.exists()})")

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


@zap_scanner_bp.route('/report_history', methods=['GET'])
@login_required
def get_zap_report_history():
    user_dir = get_user_results_dir()
    history = report_manager.get_report_history(user_dir, scanner_name="zap_scanner")
    return jsonify({"status": "success", "history": history})


@zap_scanner_bp.route('/report_files', methods=['GET'])
@login_required
def get_report_files():
    target = request.args.get('target')
    user_dir = get_user_results_dir()
    
    if not target:
        history = report_manager.get_report_history(user_dir, scanner_name="zap_scanner")
        if history:
            target = history[0]['filename'].replace('zap_scanner_', '').replace('.pdf', '')
            
    paths = zap_scanner.get_output_paths(user_dir, target=target)
    
    json_exists = paths["json_report"].exists()
    pdf_exists = paths["pdf_report"].exists()

    if not json_exists and not pdf_exists:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    return jsonify({
        "status": "success",
        "json_report": f"/zap_scanner/scan_results?target={target}" if json_exists else None,
        "pdf_report": f"/zap_scanner/download_pdf?target={target}" if pdf_exists else None
    })


@zap_scanner_bp.route('/download_pdf', methods=['GET'])
@login_required
def download_pdf_report():
    user_dir = get_user_results_dir()
    requested_filename = request.args.get('filename')
    target = request.args.get('target')
    
    if requested_filename:
        filename = secure_filename(requested_filename)
        pdf_path = os.path.join(user_dir, filename)
    elif target:
        filename = report_manager.generate_report_filename("zap_scanner", target, "pdf")
        pdf_path = os.path.join(user_dir, filename)
    else:
        history = report_manager.get_report_history(user_dir, scanner_name="zap_scanner")
        if not history:
            return jsonify({"status": "error", "message": "No reports found."}), 404
        pdf_path = history[0]['path']
        filename = os.path.basename(pdf_path)

    if not os.path.exists(pdf_path):
        return jsonify({"status": "error", "message": "PDF report file not found."}), 404
    
    return send_from_directory(
        directory=os.path.dirname(pdf_path),
        path=filename,
        as_attachment=True
    )


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

@zap_scanner_bp.route('/log_history', methods=['GET'])
@login_required
def get_zap_log_history():
    """Retrieves the previously written logs for resilient frontend loading."""
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    log_file = os.path.join(zap_scanner.LOGS_DIR, "users", current_user_identifier, "zap_agent_log.txt")
    logs = []
    if os.path.exists(log_file):
        with open(log_file, 'r', encoding='utf-8') as f:
            logs = f.read().splitlines()
    return jsonify({"status": "success", "logs": logs})


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
                # Ensure correct SSE format: data: <message>\n\n
                if message == ': keep-alive':
                    yield f"{message}\n\n"
                else:
                    yield f"data: {message}\n\n"
            except queue.Empty:
                # Keep connection alive
                yield ": keep-alive\n\n"
            except Exception as e:
                yield f"data: Error in stream: {str(e)}\n\n"

    return Response(generate_logs(), mimetype='text/event-stream')