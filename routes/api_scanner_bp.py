from flask import Blueprint, render_template, jsonify, request, Response, send_from_directory, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename 
import os
import json
import threading
import time

# Import db to update user stats
from extensions import db
from Services import api_scanner 
from Services import pdf_generator 
# --- Import Scan Logger ---
from Services import scan_logger
from Services import report_manager
from logger_setup import logger

api_scanner_bp = Blueprint('api_scanner_bp', __name__)

# --- User-Specific Directory Helper (Isolated for API) ---
def get_user_results_dir():
    if not current_user.is_authenticated:
        return None
    
    # Composite Identifier
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # NOTE: distinct folder 'api_scanner'
    user_dir = os.path.join(base_dir, 'Services', 'results', user_identifier, 'api_scanner')
    
    os.makedirs(user_dir, exist_ok=True)
        
    return user_dir

# -----------------------------------------------
# ## 🖥️ UI Route
# -----------------------------------------------

@api_scanner_bp.route('/')
@login_required 
def api_scanner_page():
    logger.info(f"[*] Accessing API Security Scanner Page (User: {current_user.username})")
    # You will need a distinct HTML template for this
    return render_template('scanners/api_scanner.html')


# -----------------------------------------------
# ## 🚀 Scan Initiation Route
# -----------------------------------------------

@api_scanner_bp.route('/scan', methods=['POST'])
@login_required 
def initiate_api_scan():
    data = request.get_json()
    target_url = data.get('target_url')
    definition_url = data.get('definition_url') 
    auth_token = data.get('auth_token')

    token_status = "Token Provided" if auth_token else "Anonymous"
    logger.info(f"[*] API Scan requested for {target_url} (Auth: {token_status}) by {current_user.username}")

    if not target_url:
        return jsonify({"status": "error", "message": "Target API URL is required."}), 400
    
    if not definition_url:
        return jsonify({"status": "error", "message": "OpenAPI/Swagger Definition URL is required."}), 400
    
    # --- Auto-append Protocol ---
    target_url = target_url.strip() 
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    # [REMOVED] Legacy model check. TCTREngine handles model availability internally.

    # User Context
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"

    # [NEW] Prevent Multiple Concurrent Scans for the same user
    if api_scanner.is_scan_running(current_user_identifier):
        logger.warning(f"[!] API Scan already in progress for user {current_user_identifier}")
        return jsonify({
            "status": "error", 
            "message": "An API scan is already in progress. Please wait for it to complete."
        }), 400

    user_output_dir = get_user_results_dir()
    user_id_for_log = current_user.id
    app = current_app._get_current_object()

    # [RC-8 FIX] Atomic DB counter increment
    try:
        from sqlalchemy import update as _sa_update
        from models import User as _User
        db.session.execute(
            _sa_update(_User).where(_User.id == current_user.id)
            .values(scan_count_zap=_User.scan_count_zap + 1)  # reuses zap column until scan_count_api is added
        )
        db.session.commit()
    except Exception as e:
        db.session.rollback()  # RC-3 FIX
        api_scanner.log(f"[!] Failed to update user stats: {e}", current_user_identifier)

    # [NEW] Reset Log File for this new scan session
    scan_logger.reset_log_file(current_user_identifier, "api_scanner")

    # 5. Log Scan Start (Database)
    log_id = scan_logger.log_scan_start(
        user_id=user_id_for_log,
        tool_name="API",
        target=target_url,
        scan_type="OpenAPI"
    )

    def scan_and_process_task():
        duration = 0
        finding_count = 0
        status = "Failed"
        scan_successful = False
        error_msg = None

        try:
            api_scanner.log(f"[*] Starting API Scan for {target_url} (Auth: {token_status})...", current_user_identifier, to_console=True)
            api_scanner.log(f"[*] Using Definition: {definition_url}", current_user_identifier, to_console=True)
            
            paths = api_scanner.get_output_paths(user_output_dir, target=target_url)
            xml_path = paths["xml_report"]
            pdf_path = paths["pdf_report"]
            
            os.makedirs(os.path.dirname(xml_path), exist_ok=True)
            
            start_time = time.time()
            
            # 1. Run API Scan
            scan_successful = api_scanner.run_api_scan(target_url, definition_url, str(xml_path), current_user_identifier, auth_token=auth_token)

            duration = time.time() - start_time

            if scan_successful:
                status = "Completed"
                api_scanner.log("[+] API scan command finished. Parsing...", current_user_identifier)
                
                # 2. Parse
                scan_results = api_scanner.parse_xml_report(str(xml_path), current_user_identifier)
                
                if scan_results:
                    scan_results["target_url"] = target_url
                    scan_results["scan_type"] = "API" # Meta-data tag
                    finding_count = len(scan_results.get("findings", []))
                    
                    # 3. Save JSON
                    json_report_path = api_scanner.save_json_report(scan_results, user_output_dir, current_user_identifier, target=target_url)
                    
                    if json_report_path:
                        api_scanner.log(f"[+] JSON report saved.", current_user_identifier, to_console=True)
                        
                        # 4. Generate PDF
                        try:
                            api_scanner.log(f"[*] Generating PDF report for {target_url}...", current_user_identifier, to_console=True)
                            pdf_generator.create_zap_report_pdf(json_report_path, str(pdf_path))
                            
                            if os.path.exists(pdf_path):
                                time.sleep(1.5)
                                api_scanner.log(f"[+] PDF generated successfully.", current_user_identifier, to_console=True)
                                api_scanner.log(f"SYSTEM_EVENT: READY_FOR_ANALYSIS:{target_url}", current_user_identifier, to_console=True)
                                api_scanner.log(f"[*] API Scan complete.", current_user_identifier, to_console=True)
                            else:
                                 api_scanner.log("[!] PDF generation failed (file missing).", current_user_identifier, to_console=True)
                                 
                        except Exception as e:
                            api_scanner.log(f"[!] FAILED to generate PDF report: {e}", current_user_identifier, to_console=True)

                    else:
                        api_scanner.log("[!] Failed to save JSON report.", current_user_identifier, to_console=True)
                else:
                    api_scanner.log("[!] Failed to parse API scan report.", current_user_identifier, to_console=True)
            else:
                api_scanner.log(f"[!] API scan failed for target: {target_url}.", current_user_identifier, to_console=True)
                error_msg = "Scanner process returned failure."

        except Exception as e:
            api_scanner.log(f"[!] Critical thread error: {e}", current_user_identifier, to_console=True)
            error_msg = str(e)

        # ALWAYS log end to Database (Inside App Context)
        with app.app_context():
            final_error = error_msg if not scan_successful else None
            scan_logger.log_scan_end(log_id, status=status, finding_count=finding_count, duration=duration, error_msg=final_error)

    threading.Thread(target=scan_and_process_task, daemon=True).start()  # RC-5 FIX: daemon=True
    
    return jsonify({
        "status": "success",
        "message": f"API Scan initiated for {target_url}."
    })


@api_scanner_bp.route('/status', methods=['GET'])
@login_required
def get_api_status():
    """Checks if an API scan is currently running for the user."""
    user_id = current_user.id
    current_user_identifier = f"{secure_filename(current_user.username)}_{user_id}"
    
    # 1. CHECK DB (Primary Source of Truth)
    active_log = scan_logger.get_active_scan_log(user_id, "API")
    
    # 2. Check Memory
    is_running_in_memory = api_scanner.is_scan_running(current_user_identifier)
    
    logger.debug(f"[DEBUG] API Status check for {current_user.username}: DB={bool(active_log)}, Memory={is_running_in_memory}")

    if active_log:
        if not is_running_in_memory:
            # [STALE SCAN FIX] DB says running, but memory process is gone.
            logger.warning(f"[!] Stale API Scan detected for {current_user.username} (ID: {active_log.id}). Cleaning up...")
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
        with api_scanner.scan_lock:
            target = api_scanner.active_scans.get(current_user_identifier, {}).get('target')

    return jsonify({
        "status": "success",
        "is_running": is_running_in_memory,
        "target": target
    })


@api_scanner_bp.route('/report_history', methods=['GET'])
@login_required
def get_api_report_history():
    user_dir = get_user_results_dir()
    history = report_manager.get_report_history(user_dir, scanner_name="api_scanner")
    return jsonify({"status": "success", "history": history})


@api_scanner_bp.route('/trigger_ai_analysis', methods=['POST'])
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
        paths = api_scanner.get_output_paths(user_dir, target=target)
        pdf_path = Path(paths["pdf_report"])
    
    # Fallback 1: History search (Recent for this scanner)
    if not pdf_path or not pdf_path.exists():
        history = report_manager.get_report_history(user_dir, scanner_name="api_scanner", extension="pdf")
        if history:
            pdf_path = Path(history[0]['path'])
    
    # Fallback 2: Any PDF in the results directory
    if not pdf_path or not pdf_path.exists():
        history = report_manager.get_report_history(user_dir, scanner_name=None, extension="pdf")
        if history:
            pdf_path = Path(history[0]['path'])

    if not pdf_path or not pdf_path.exists():
        api_scanner.log(f"[!] Analysis failed: PDF report not found in {user_dir}", user_identifier)
        return jsonify({
            "status": "error", 
            "message": "PDF report not available. Please run a scan first."
        }), 404

    return jsonify({
        "status": "success",
        "scanner_type": "api",
        "target": target
    })


# -----------------------------------------------
# ## 📥 Report Retrieval Routes
# -----------------------------------------------

@api_scanner_bp.route('/scan_results', methods=['GET'])
@login_required 
def get_api_scan_results():
    target = request.args.get('target')
    user_dir = get_user_results_dir()
    paths = api_scanner.get_output_paths(user_dir, target=target)
    json_path = paths["json_report"]

    if not json_path.exists():
        return jsonify({"status": "pending", "message": "No API report available."}), 404
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        return jsonify({"status": "success", "data": report_data})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@api_scanner_bp.route('/report_files', methods=['GET'])
@login_required
def get_report_files():
    target = request.args.get('target')
    user_dir = get_user_results_dir()
    paths = api_scanner.get_output_paths(user_dir, target=target)
    
    json_exists = paths["json_report"].exists()
    pdf_exists = paths["pdf_report"].exists()

    if not json_exists and not pdf_exists:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    return jsonify({
        "status": "success",
        # Note the prefix change to /api_scanner/
        "json_report": f"/api_scanner/scan_results?target={target}" if json_exists else None,
        "pdf_report": f"/api_scanner/download_pdf?target={target}" if pdf_exists else None
    })


@api_scanner_bp.route('/download_pdf', methods=['GET'])
@login_required
def download_pdf_report():
    user_dir = get_user_results_dir()
    requested_filename = request.args.get('filename')
    target = request.args.get('target')

    if requested_filename:
        filename = secure_filename(requested_filename)
        pdf_path = os.path.join(user_dir, filename)
    elif target:
        filename = report_manager.generate_report_filename("api_scanner", target, "pdf")
        pdf_path = os.path.join(user_dir, filename)
    else:
        history = report_manager.get_report_history(user_dir, scanner_name="api_scanner")
        if not history:
            return jsonify({"status": "error", "message": "No reports found."}), 404
        pdf_path = history[0]['path']
        filename = os.path.basename(pdf_path)

    if not os.path.exists(pdf_path):
        return jsonify({"status": "error", "message": "PDF file not found."}), 404
    
    return send_from_directory(
        directory=os.path.dirname(pdf_path),
        path=filename,
        as_attachment=True
    )


# -----------------------------------------------
# ## 📝 Log Streaming Routes
# -----------------------------------------------

@api_scanner_bp.route('/clear_log', methods=['POST'])
@login_required 
def clear_api_log_route():
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    scan_logger.reset_log_file(current_user_identifier, "api_scanner")
    return jsonify({"status": "success", "message": "Log cleared."})


@api_scanner_bp.route('/log_stream')
@login_required 
def api_log_stream():
    """
    Streams logs specifically for the logged-in user from their active log file.
    """
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    
    # Use the file tailing generator from scan_logger
    return Response(
        scan_logger.tail_log_file(current_user_identifier, "api_scanner"), 
        mimetype='text/event-stream'
    )