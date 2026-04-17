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

# [NEW] Import db and get_user_result_dir_name to update user stats
from core.extensions import db
from models.models import get_user_result_dir_name

# Import the new zap_scanner module
from Services import zap_scanner
# --- NEW: Import the PDF generator and Report Manager ---
from Services import pdf_generator
from Services import report_manager
# --- Import Scan Logger ---
from Services import scan_logger
from Services.target_validator import validate_target, TargetBlockedError, AuthorizationRequiredError

zap_scanner_bp = Blueprint('zap_scanner_bp', __name__)

# --- User-Specific Directory Helper ---
def get_user_results_dir():
    """Constructs the path: results/<username_id>/zap_scanner"""
    user_base_dir = report_manager.get_user_results_dir(current_user)
    user_dir = os.path.join(user_base_dir, 'zap_scanner')
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
    user_confirmed_auth = data.get('user_confirmed_auth', False)
    
    logger.info(f"\033[34m[*] ZAP Scan requested for {target_url} (Mode: {scan_mode}) by {current_user.username}\033[0m")

    if not target_url:
        return jsonify({"status": "error", "message": "Target URL is required."}), 400
    
    # --- Auto-append Protocol ---
    target_url = target_url.strip() 
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url

    # ── Target validation gate ──────────────────────────────────────
    try:
        validate_target(target_url, user_confirmed_auth=user_confirmed_auth)
    except TargetBlockedError as e:
        return jsonify({
            "status": "blocked",
            "message": str(e)
        }), 403
    except AuthorizationRequiredError as e:
        return jsonify({
            "status": "auth_required",
            "message": str(e)
        }), 403
    # ── End validation ──────────────────────────────────────────────
    
    # [REMOVED] Legacy model check. TCTREngine handles model availability internally.

    # Capture User Context for Thread using Composite ID
    user_result_dir = get_user_result_dir_name(current_user)
    user_output_dir = get_user_results_dir()
    user_id_for_log = current_user.id
    app = current_app._get_current_object()

    # RC-12 FIX: Prevent duplicate concurrent ZAP scans for the same user (mirrors Nmap guard)
    if zap_scanner.is_scan_running(user_result_dir):
        logger.warning(f"[!] ZAP Scan already in progress for user {user_result_dir}")
        return jsonify({
            "status": "error",
            "message": "A ZAP scan is already in progress. Please wait for it to complete."
        }), 400

    # [RC-8 FIX] Atomic DB counter increment — prevents double-count on concurrent tabs
    try:
        from sqlalchemy import update as _sa_update
        from models.models import User as _User
        db.session.execute(
            _sa_update(_User).where(_User.id == current_user.id)
            .values(scan_count_zap=_User.scan_count_zap + 1)
        )
        db.session.commit()
    except Exception as e:
        db.session.rollback()  # RC-3 FIX: clean session before thread starts
        zap_scanner.log(f"[!] Failed to update user stats: {e}", user_result_dir)

    def scan_and_process_task():
        # [NEW] Log Start in DB
        with app.app_context():
            log_id = scan_logger.log_scan_start(
                user_id=user_id_for_log,
                tool_name="ZAP",
                target=target_url,
                scan_type=f"ZAP {scan_mode.capitalize()}"
            )

        # Pass composite ID to log function
        zap_scanner.log(f"[*] Starting ZAP {scan_mode.capitalize()} Scan for {target_url} (User: {user_result_dir})...", user_result_dir, to_console=True)
        
        paths = zap_scanner.get_output_paths(user_output_dir, target=target_url)
        xml_path = paths["xml_report"]
        pdf_path = paths["pdf_report"]
        
        os.makedirs(os.path.dirname(xml_path), exist_ok=True)
        
        start_time = time.time()
        
        # 1. Run Scan (Pass composite ID and scan_mode)
        scan_successful = zap_scanner.run_zap_scan(target_url, str(xml_path), user_result_dir, scan_mode=scan_mode)

        duration = time.time() - start_time
        finding_count = 0
        status = "Failed"

        if scan_successful:
            status = "Completed"
            zap_scanner.log("[+] ZAP scan command finished. Parsing...", user_result_dir)
            
            # 2. Parse (Pass composite ID)
            scan_results = zap_scanner.parse_zap_xml_report(str(xml_path), user_result_dir)
            
            if scan_results:
                scan_results["target_url"] = target_url
                finding_count = len(scan_results.get("findings", []))
                
                # 3. Save JSON (Pass composite ID to logging inside save function if needed, usually directory is enough)
                json_report_path = zap_scanner.save_json_report(scan_results, user_output_dir, user_result_dir, target=target_url)
                
                if json_report_path:
                    zap_scanner.log(f"[+] JSON report saved.", user_result_dir, to_console=True)
                    
                    # 4. Generate PDF
                    try:
                        zap_scanner.log("[*] Generating PDF report...", user_result_dir, to_console=True)
                        pdf_generator.create_zap_report_pdf(json_report_path, str(pdf_path), user_id=user_result_dir)
                        
                        if pdf_path.exists():
                            # [FIX] Final synchronization wait using centralized helper
                            report_manager.wait_for_file(str(pdf_path))
                            zap_scanner.log(f"[+] PDF generated successfully.", user_result_dir, to_console=True)
                            zap_scanner.log("SYSTEM_EVENT: READY_FOR_ANALYSIS", user_result_dir, to_console=True)
                            zap_scanner.log(f"[*] Scan, analysis, and prediction complete.", user_result_dir, to_console=True)

                            # [NEW] Register the PDF report in the database
                            with app.app_context():
                                from models.models import Report
                                # Use relative path from the user's result directory for storage
                                rel_path = os.path.relpath(str(pdf_path), os.path.dirname(os.path.dirname(user_output_dir)))
                                new_report = Report(
                                    scan_log_id=log_id,
                                    user_id=user_id_for_log,
                                    filename=os.path.basename(str(pdf_path)),
                                    relative_path=rel_path,
                                    file_type="pdf",
                                    category="zap_scanner"
                                )
                                db.session.add(new_report)
                                db.session.commit()
                        else:
                             zap_scanner.log("[!] PDF generation failed (file missing).", user_result_dir, to_console=True)
                             
                    except Exception as e:
                        zap_scanner.log(f"[!] FAILED to generate PDF report: {e}", user_result_dir, to_console=True)

                else:
                    zap_scanner.log("[!] Failed to save JSON report.", user_result_dir)
            else:
                zap_scanner.log("[!] Failed to parse ZAP XML report.", user_result_dir)
        else:
            zap_scanner.log(f"[!] ZAP scan failed for target: {target_url}.", user_result_dir)

        # Log to Database (Inside App Context)
        with app.app_context():
            scan_logger.log_scan_end(
                log_id=log_id,
                status=status,
                finding_count=finding_count,
                duration=duration
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
    user_result_dir = get_user_result_dir_name(current_user)
    is_running = zap_scanner.is_scan_running(user_result_dir)
    
    # Also get the target if running
    target = None
    if is_running:
        with zap_scanner.scan_lock:
            target = zap_scanner.active_scans[user_result_dir].get('target')

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
    user_result_dir = get_user_result_dir_name(current_user)
    user_dir = get_user_results_dir()
    
    # Resolve the latest PDF report for this scanner
    pdf_path_str = report_manager.find_latest_report(user_dir, "zap_scanner", target=target, extension="pdf")
    
    if not pdf_path_str:
        # Fallback to any PDF in the scanner's folder
        pdf_path_str = report_manager.find_latest_report(user_dir, scanner_name=None, extension="pdf")

    if not pdf_path_str or not os.path.exists(pdf_path_str):
        zap_scanner.log(f"[!] Analysis failed: PDF report not found in {user_dir}", user_result_dir)
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
    """Retrieves the latest JSON scan results."""
    user_dir = get_user_results_dir()
    target = request.args.get('target')

    # Resolve latest JSON using helper
    json_path_str = report_manager.find_latest_report(user_dir, "zap_scanner", target=target, extension="json")

    if not json_path_str or not os.path.exists(json_path_str):
        return jsonify({
            "status": "pending",
            "message": "No JSON report available."
        }), 404
    
    try:
        with open(json_path_str, 'r', encoding='utf-8') as f:
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
    """Checks availability of reports."""
    target = request.args.get('target')
    user_dir = get_user_results_dir()
    
    latest_json = report_manager.find_latest_report(user_dir, "zap_scanner", target=target, extension="json")
    latest_pdf = report_manager.find_latest_report(user_dir, "zap_scanner", target=target, extension="pdf")

    if not latest_json and not latest_pdf:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    # [AI BRIEF] Retrieve the latest completed scan log ID and check for existing executive summary
    from models.models import ScanLog
    latest_log = ScanLog.query.filter_by(
        user_id=current_user.id,
        tool_name="ZAP",
        status="Completed"
    ).order_by(ScanLog.start_time.desc()).first()
    
    scan_log_id = latest_log.id if latest_log else None
    
    # Check if executive summary already exists (either in DB or on disk)
    exec_summary_report = None
    if latest_log and latest_log.executive_summary_path:
        if os.path.exists(latest_log.executive_summary_path):
             exec_summary_report = f"/zap_scanner/download_pdf?target={target}&type=executive" if target else "/zap_scanner/download_pdf?type=executive"
    
    # Fallback to disk check if DB is out of sync
    if not exec_summary_report:
        exec_path = report_manager.find_latest_report(user_dir, "zap_scanner", target=target, extension="pdf")
        if exec_path:
            potential_exec = exec_path.replace(".pdf", "_executive.pdf")
            if os.path.exists(potential_exec):
                exec_summary_report = f"/zap_scanner/download_pdf?target={target}&type=executive" if target else "/zap_scanner/download_pdf?type=executive"

    return jsonify({
        "status": "success",
        "json_report": f"/zap_scanner/scan_results?target={target}" if target else "/zap_scanner/scan_results",
        "pdf_report": f"/zap_scanner/download_pdf?target={target}" if target else "/zap_scanner/download_pdf",
        "exec_summary_report": exec_summary_report,
        "scan_log_id": scan_log_id
    })


@zap_scanner_bp.route('/download_pdf', methods=['GET'])
@login_required
def download_pdf_report():
    """Serves the latest PDF report for the target or broad scanner."""
    user_dir = get_user_results_dir()
    requested_filename = request.args.get('filename')
    target = request.args.get('target')
    report_type = request.args.get('type') # 'executive' or None
    
    if requested_filename:
        filename = secure_filename(requested_filename)
        pdf_path = os.path.join(user_dir, filename)
    else:
        pdf_path = report_manager.find_latest_report(user_dir, "zap_scanner", target=target, extension="pdf")
        if not pdf_path:
             return jsonify({"status": "error", "message": "No ZAP PDF report found."}), 404
             
        if report_type == 'executive':
            pdf_path = pdf_path.replace(".pdf", "_executive.pdf")
            if not os.path.exists(pdf_path):
                 return jsonify({"status": "error", "message": "Executive brief not found."}), 404
        
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
    user_result_dir = get_user_result_dir_name(current_user)
    zap_scanner.clear_log_file(user_result_dir)
    return jsonify({"status": "success", "message": "Log cleared."})

@zap_scanner_bp.route('/log_history', methods=['GET'])
@login_required
def get_zap_log_history():
    """Retrieves the previously written logs for resilient frontend loading."""
    user_result_dir = get_user_result_dir_name(current_user)
    log_file = os.path.join(zap_scanner.LOGS_DIR, "users", user_result_dir, "zap_agent_log.txt")
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
    user_result_dir = get_user_result_dir_name(current_user)
    
    def generate_logs():
        # Get the specific queue for this user
        user_queue = zap_scanner.get_user_queue(user_result_dir)
        
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


@zap_scanner_bp.route('/trigger_executive_summary', methods=['POST'])
@login_required
def trigger_executive_summary():
    """Triggers the AI Executive Brief generation for the ZAP report."""
    data = request.get_json() or {}
    log_id = data.get('log_id')
    target = data.get('target')
    
    if not log_id:
        return jsonify({"status": "error", "message": "Missing Scan Log ID"}), 400
        
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_dir = get_user_results_dir()
    
    # 1. Resolve Technical Report Path
    report_path = report_manager.find_latest_report(user_dir, "zap_scanner", target=target, extension="pdf")
    
    if not report_path or not os.path.exists(report_path):
        return jsonify({"status": "error", "message": "Technical report not found. Run a scan first."}), 404

    # 2. Call Centralized AI Service
    from Services.ai_report_service import generate_executive_summary
    success, result = generate_executive_summary(
        log_id=log_id,
        user_identifier=user_identifier,
        report_path=report_path,
        target=target,
        tool_name="Application Security Audit"
    )
    
    if success:
        download_url = f"/zap_scanner/download_pdf?target={target}&type=executive" if target else "/zap_scanner/download_pdf?type=executive"
        return jsonify({
            "status": "success",
            "message": "Executive brief synthesized.",
            "download_url": download_url
        })
    else:
        return jsonify({"status": "error", "message": result}), 500
