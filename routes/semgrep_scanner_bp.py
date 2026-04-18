from flask import Blueprint, render_template, jsonify, request, Response, send_from_directory, current_app
from flask_login import login_required, current_user
import threading
import json
import time
import os
import shutil
from queue import Empty
from werkzeug.utils import secure_filename
from pathlib import Path

# Import db to update user stats
from core.extensions import db

# Import the semgrep_scanner module
from Services import semgrep_scanner
# Import the PDF generator module
from Services import pdf_generator
# --- Import Scan Logger ---
from Services import scan_logger
from Services import report_manager
from Services.target_validator import validate_target, TargetBlockedError, AuthorizationRequiredError
from core.logger_setup import logger

semgrep_scanner_bp = Blueprint('semgrep_scanner_bp', __name__)

# --- CONFIGURATION ---
MAX_UPLOAD_SIZE = 1024 * 1024 * 1024  # 1 GB limit

# --- User-Specific Directory Helper ---
def get_user_results_dir():
    """Constructs the path: results/<username_id>/semgrep_scanner"""
    user_base_dir = report_manager.get_user_results_dir(current_user)
    user_dir = os.path.join(user_base_dir, 'semgrep_scanner')
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

@semgrep_scanner_bp.route('/')
@login_required
def semgrep_scanner_page():
    """Renders the Semgrep scanner page."""
    logger.info(f"[*] Accessing Source Code Scanner Page (User: {current_user.username})")
    user_agent = request.headers.get('User-Agent')
    if user_agent and any(word in user_agent for word in ['Mobile', 'Android', 'iPhone', 'iPad']):
        return render_template('mobile_scanners/semgrep_scanner.html')
    return render_template('scanners/semgrep_scanner.html')

@semgrep_scanner_bp.route('/scan', methods=['POST'])
@login_required
def scan_code():
    """
    API endpoint to initiate a Semgrep scan.
    Handles both File Uploads (Zip) and Git URLs.
    Runs the scan in a separate thread.
    """
    logger.info(f"[*] Semgrep SAST Scan requested by {current_user.username}")
    user_output_dir = get_user_results_dir()
    
    target_input = None
    input_type = None
    
    json_data = request.get_json(silent=True) or {}
    action_id = request.form.get('action_id') or json_data.get('action_id')

    # 1. Handle Input (File vs Git)
    if 'file' in request.files:
        file = request.files['file']
        if file.filename == '':
            return jsonify({"status": "error", "message": "No file selected."}), 400
        
        # Check Size
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        
        if size > MAX_UPLOAD_SIZE:
             return jsonify({"status": "error", "message": "File too large (Max 1GB). Please remove extremely large binary files or datasets if possible."}), 400
        
        # Save temp file securely in the system temp directory so the thread can access it
        temp_filename = f"upload_temp_{secure_filename(file.filename)}"
        temp_path = str(semgrep_scanner.TEMP_DIR / temp_filename)
        file.save(temp_path)
        
        target_input = temp_path
        input_type = "zip"
        target_display = file.filename

    elif 'git_url' in request.form or 'git_url' in json_data:
        target_input = request.form.get('git_url') or json_data.get('git_url')
        if not target_input.strip():
             return jsonify({"status": "error", "message": "Git URL cannot be empty."}), 400
        input_type = "git"
        target_display = target_input

        # --- Target Validation Guardrails ---
        is_auth = request.form.get('user_confirmed_auth') or json_data.get('user_confirmed_auth', False)
        user_confirmed_auth = str(is_auth).lower() == 'true' if isinstance(is_auth, str) else bool(is_auth)
        try:
            validate_target(target_input, user_confirmed_auth=user_confirmed_auth)
        except TargetBlockedError as e:
            logger.warning(f"[BLOCKED] Semgrep Scan rejected for {target_input}: {e}")
            return jsonify({
                "status": "blocked",
                "message": f"Scan Prohibited: {str(e)}"
            }), 403
        except AuthorizationRequiredError as e:
            logger.info(f"[AUTH_REQUIRED] Semgrep Scan requires confirmation for {target_input}")
            return jsonify({
                "status": "auth_required",
                "message": str(e)
            }), 403

    else:
        return jsonify({"status": "error", "message": "Invalid input. Provide a file or git_url."}), 400

    # User Context
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"

    # [NEW] Prevent Multiple Concurrent Scans for the same user
    if semgrep_scanner.is_scan_running(current_user_identifier):
        logger.warning(f"[!] Semgrep Scan already in progress for user {current_user_identifier}")
        return jsonify({
            "status": "error", 
            "message": "A code scan is already in progress. Please wait for it to complete."
        }), 400

    # [RC-8 FIX] Atomic DB counter increment
    try:
        if hasattr(current_user, 'scan_count_semgrep'):
            from sqlalchemy import update as _sa_update
            from models.models import User as _User
            db.session.execute(
                _sa_update(_User).where(_User.id == current_user.id)
                .values(scan_count_semgrep=_User.scan_count_semgrep + 1)
            )
        else:
            pass  # Gracefully skip if column not present yet
        db.session.commit()
    except Exception as e:
        db.session.rollback()  # RC-3 FIX
        semgrep_scanner.log(f"[!] Failed to update user stats: {e}", user_id=current_user_identifier)

    # Capture User ID for thread safety
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_id = current_user.id
    app = current_app._get_current_object()

    # [NEW] Reset Log File for this new scan session
    scan_logger.reset_log_file(current_user_identifier, "semgrep_scanner")

    # 3. Define Background Task
    # 3. Define Background Task
    def scan_task():
        start_time = time.time()
        # Use DB Logging
        with app.app_context():
            log_id = scan_logger.log_scan_start(
                user_id=user_id,
                tool_name="Semgrep SAST",
                target=target_display,
                scan_type="Code Audit",
                correlation_id=action_id
            )

        semgrep_scanner.log(f"[*] Starting Semgrep SAST scan on {target_display} (User: {current_user_identifier})...", user_id=current_user_identifier, to_console=True)
        
        # [FIX] Generate a consistent timestamp for this single scan session in IST
        timestamp = report_manager.get_timestamp()
        
        # Run Scan
        report_file = semgrep_scanner.run_semgrep_scan(
            target_input=target_input, 
            input_type=input_type, 
            output_dir=user_output_dir,
            user_id=current_user_identifier,
            target=target_display,
            timestamp=timestamp
        )

        duration = time.time() - start_time
        status = "Failed"
        finding_count = 0

        # Cleanup Temp Upload File (if zip)
        if input_type == "zip" and os.path.exists(target_input):
            try:
                os.remove(target_input)
            except:
                pass

        if report_file and os.path.exists(report_file):
            status = "Completed"
            semgrep_scanner.log(f"[+] Semgrep scan complete. Generating PDF report for {target_display}...", user_id=current_user_identifier, to_console=True)
            
            # Extract finding count from saved JSON
            try:
                json_path = report_file # This is the absolute path to the parsed JSON
                user_paths = semgrep_scanner.get_output_paths(user_output_dir, target=target_display, timestamp=timestamp)
                pdf_path = user_paths["pdf_report"]
                
                with open(json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    finding_count = data.get('total_findings', 0)

                # Ensure directory exists for PDF
                os.makedirs(os.path.dirname(str(pdf_path)), exist_ok=True)
                
                # Call PDF Generator
                if hasattr(pdf_generator, 'create_semgrep_report_pdf'):
                    pdf_generator.create_semgrep_report_pdf(str(json_path), str(pdf_path), user_id=current_user_identifier)
                    
                    if pdf_path.exists():
                        # Final synchronization wait
                        report_manager.wait_for_file(str(pdf_path))
                        semgrep_scanner.log(f"[+] PDF report generated", user_id=current_user_identifier, to_console=True)
                        semgrep_scanner.log(f"SYSTEM_EVENT: READY_FOR_ANALYSIS:{target_display}", user_id=current_user_identifier, to_console=True)
                    else:
                        semgrep_scanner.log("[!] PDF generation ran but file not found.", user_id=current_user_identifier, to_console=True)
                else:
                    semgrep_scanner.log("[!] PDF Generator function 'create_semgrep_report_pdf' missing.", user_id=current_user_identifier, to_console=True)

            except Exception as e:
                semgrep_scanner.log(f"[!] FAILED to generate PDF: {str(e)}", user_id=current_user_identifier, to_console=True)
        else:
            semgrep_scanner.log(f"[!] Semgrep scan failed for {target_display}.", user_id=current_user_identifier, to_console=True)

        # Log to Database (Inside App Context)
        with app.app_context():
            scan_logger.log_scan_end(log_id, status=status, finding_count=finding_count, duration=duration)

    # 4. Start Thread
    threading.Thread(target=scan_task, daemon=True).start()  # RC-5 FIX: daemon=True
    
    return jsonify({"status": "success", "message": f"Code scan started for {target_display}."})


@semgrep_scanner_bp.route('/status', methods=['GET'])
@login_required
def get_semgrep_status():
    """Checks if a Semgrep scan is currently running for the user."""
    user_id = current_user.id
    current_user_identifier = f"{secure_filename(current_user.username)}_{user_id}"
    
    # 1. CHECK DB (Primary Source of Truth)
    active_log = scan_logger.get_active_scan_log(user_id, "Semgrep SAST")
    
    # 2. Check Memory
    is_running_in_memory = semgrep_scanner.is_scan_running(current_user_identifier)
    
    logger.debug(f"[DEBUG] Semgrep Status check for {current_user.username}: DB={bool(active_log)}, Memory={is_running_in_memory}")

    if active_log:
        if not is_running_in_memory:
            # [STALE SCAN FIX] DB says running, but memory process is gone.
            logger.warning(f"[!] Stale Semgrep Scan detected for {current_user.username} (ID: {active_log.id}). Cleaning up...")
            with current_app.app_context():
                scan_logger.mark_scan_failed(active_log.id, "Scan interrupted (Stale/Restart)")
            
            return jsonify({
                "status": "success",
                "is_running": False,
                "target": None
            })

        return jsonify({
            "status": "success",
            "is_running": True,
            "target": active_log.target
        })

    # 3. Fallback: If memory is running but DB missed it (Rare)
    target = None
    if is_running_in_memory:
        with semgrep_scanner.scan_lock:
            target = semgrep_scanner.active_scans.get(current_user_identifier, {}).get('target')

    return jsonify({
        "status": "success",
        "is_running": is_running_in_memory,
        "target": target
    })

@semgrep_scanner_bp.route('/report_history', methods=['GET'])
@login_required
def get_semgrep_report_history():
    user_dir = get_user_results_dir()
    history = report_manager.get_report_history(user_dir, scanner_name="semgrep_scanner")
    return jsonify({"status": "success", "history": history})

# --- Standard Routes (Replicating SSL Scanner Pattern) ---

@semgrep_scanner_bp.route('/trigger_ai_analysis', methods=['POST'])
@login_required
def trigger_ai_analysis_route():
    """Robustly triggers AI analysis by finding the correct PDF report."""
    data = request.get_json() or {}
    target = data.get('target')
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_dir = get_user_results_dir()
    
    # Resolve the latest PDF report for this scanner
    pdf_path_str = report_manager.find_latest_report(user_dir, "semgrep_scanner", target=target, extension="pdf")
    
    if not pdf_path_str:
        # Fallback to any PDF in the scanner's folder
        pdf_path_str = report_manager.find_latest_report(user_dir, scanner_name=None, extension="pdf")

    if not pdf_path_str or not os.path.exists(pdf_path_str):
        semgrep_scanner.log(f"[!] Analysis failed: PDF report not found in {user_dir}", user_identifier)
        return jsonify({
            "status": "error", 
            "message": "PDF report not available. Please run a scan first."
        }), 404

    return jsonify({
        "status": "success",
        "scanner_type": "semgrep",
        "target": target
    })

@semgrep_scanner_bp.route('/report_files', methods=['GET'])
@login_required
def get_report_files():
    """Checks availability of reports."""
    target = request.args.get('target')
    user_dir = get_user_results_dir()
    
    latest_json = report_manager.find_latest_report(user_dir, "semgrep_scanner", target=target, extension="json")
    latest_pdf = report_manager.find_latest_report(user_dir, "semgrep_scanner", target=target, extension="pdf")

    if not latest_json and not latest_pdf:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    # [AI BRIEF] Retrieve the latest completed scan log ID and check for existing executive summary
    from models.models import ScanLog
    latest_log = ScanLog.query.filter_by(
        user_id=current_user.id,
        tool_name="Semgrep SAST",
        status="Completed"
    ).order_by(ScanLog.start_time.desc()).first()
    
    scan_log_id = latest_log.id if latest_log else None
    
    # Check if executive summary already exists (either in DB or on disk)
    exec_summary_report = None
    if latest_log and latest_log.executive_summary_path:
        if os.path.exists(latest_log.executive_summary_path):
             exec_summary_report = f"/semgrep_scanner/download_pdf?target={target}&type=executive" if target else "/semgrep_scanner/download_pdf?type=executive"
    
    # Fallback to disk check if DB is out of sync
    if not exec_summary_report:
        exec_path = report_manager.find_latest_report(user_dir, "semgrep_scanner", target=target, extension="pdf")
        if exec_path:
            potential_exec = exec_path.replace(".pdf", "_executive.pdf")
            if os.path.exists(potential_exec):
                exec_summary_report = f"/semgrep_scanner/download_pdf?target={target}&type=executive" if target else "/semgrep_scanner/download_pdf?type=executive"

    return jsonify({
        "status": "success",
        "json_report": f"/semgrep_scanner/get_json_report?target={target}" if target else "/semgrep_scanner/get_json_report",
        "pdf_report": f"/semgrep_scanner/download_pdf?target={target}" if target else "/semgrep_scanner/download_pdf",
        "exec_summary_report": exec_summary_report,
        "scan_log_id": scan_log_id
    })

@semgrep_scanner_bp.route('/download_pdf', methods=['GET'])
@login_required
def download_pdf_report():
    """Serves the latest Semgrep PDF report dynamically."""
    user_dir = get_user_results_dir()
    requested_filename = request.args.get('filename')
    target = request.args.get('target')
    report_type = request.args.get('type') # 'executive' or None
    
    if requested_filename:
        filename = secure_filename(requested_filename)
        pdf_path = os.path.join(user_dir, filename)
    else:
        pdf_path = report_manager.find_latest_report(user_dir, "semgrep_scanner", target=target, extension="pdf")
        if not pdf_path:
             return jsonify({"status": "error", "message": "No Semgrep PDF report found."}), 404
             
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

@semgrep_scanner_bp.route('/get_json_report', methods=['GET'])
@login_required
def get_json_report_file():
    """Serves the latest JSON report file for Semgrep scans."""
    target = request.args.get('target')
    user_dir = get_user_results_dir()
    
    json_path_str = report_manager.find_latest_report(user_dir, "semgrep_scanner", target=target, extension="json")

    if not json_path_str or not os.path.exists(json_path_str):
        return jsonify({"status": "error", "message": "JSON report file not found."}), 404
    
    filename = os.path.basename(json_path_str)
    directory = os.path.dirname(json_path_str)

    return send_from_directory(
        directory=directory,
        path=filename,
        as_attachment=True
    )

@semgrep_scanner_bp.route('/report', methods=['GET'])
@login_required
def get_semgrep_report():
    """
    API endpoint to get the content of the parsed scan report (JSON content).
    Used by the frontend to render the results table immediately.
    """
    target = request.args.get('target')
    user_dir = get_user_results_dir()
    
    json_path_str = report_manager.find_latest_report(user_dir, "semgrep_scanner", target=target, extension="json")

    if not json_path_str or not os.path.exists(json_path_str):
        return jsonify({
            "status": "error",
            "message": "No scan report available."
        }), 404
    
    try:
        with open(json_path_str, 'r', encoding='utf-8') as f:
            parsed_summary = json.load(f)

        return jsonify({
            "status": "success",
            "content": parsed_summary, 
            "report_file": os.path.basename(json_path_str)
        })
    except Exception as e:
        current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
        semgrep_scanner.log(f"[!] Error reading Semgrep report: {e}", user_id=current_user_identifier)
        return jsonify({
            "status": "error",
            "message": f"Failed to read report: {str(e)}"
        }), 500

@semgrep_scanner_bp.route('/clear_log', methods=['POST'])
@login_required
def clear_log_route():
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    semgrep_scanner.clear_log_file(current_user_identifier)
    return jsonify({"status": "success", "message": "Log cleared."})

@semgrep_scanner_bp.route('/log_stream')
@login_required
def log_stream():
    """Server-Sent Events (SSE) endpoint."""
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    
    return Response(
        scan_logger.tail_log_file(current_user_identifier, "semgrep_scanner"),
        mimetype='text/event-stream'
    )


@semgrep_scanner_bp.route('/trigger_executive_summary', methods=['POST'])
@login_required
def trigger_executive_summary():
    """Triggers the AI Executive Brief generation for the Semgrep report."""
    data = request.get_json() or {}
    log_id = data.get('log_id')
    target = data.get('target')
    
    if not log_id:
        return jsonify({"status": "error", "message": "Missing Scan Log ID"}), 400
        
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_dir = get_user_results_dir()
    
    # 1. Resolve Technical Report Path
    report_path = report_manager.find_latest_report(user_dir, "semgrep_scanner", target=target, extension="pdf")
    
    if not report_path or not os.path.exists(report_path):
        return jsonify({"status": "error", "message": "Technical report not found. Run a scan first."}), 404

    # 2. Call Centralized AI Service
    from Services.ai_report_service import generate_executive_summary
    success, result = generate_executive_summary(
        log_id=log_id,
        user_identifier=user_identifier,
        report_path=report_path,
        target=target,
        tool_name="Static Analysis Security Audit (Semgrep)"
    )
    
    if success:
        download_url = f"/semgrep_scanner/download_pdf?target={target}&type=executive" if target else "/semgrep_scanner/download_pdf?type=executive"
        return jsonify({
            "status": "success",
            "message": "Executive brief synthesized.",
            "download_url": download_url
        })
    else:
        return jsonify({"status": "error", "message": result}), 500
