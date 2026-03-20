from flask import Blueprint, render_template, jsonify, request, Response, send_from_directory, current_app
from flask_login import login_required, current_user
import threading
import json
import time
import os
import shutil
from datetime import datetime
from queue import Empty
import requests
import uuid
import logging
from werkzeug.utils import secure_filename 
from pathlib import Path

# --- Logging Setup ---
logger = logging.getLogger(__name__)

# Import db to update user stats
from core.extensions import db

# Import the sql_scanner module
from Services import sql_scanner
# Import the PDF generator module
from Services import pdf_generator
# --- Import Scan Logger ---
from Services import scan_logger
from Services import report_manager
from Services.target_validator import validate_target, TargetBlockedError, AuthorizationRequiredError

sql_scanner_bp = Blueprint('sql_scanner_bp', __name__)

# --- User-Specific Directory Helper ---
def get_user_results_dir():
    """Constructs the path: results/<username_id>/sql_scanner"""
    user_base_dir = report_manager.get_user_results_dir(current_user)
    user_dir = os.path.join(user_base_dir, 'sql_scanner')
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

# ==========================================
# --- ⚙️ CONFIGURATION 
# ==========================================
PDF_FILENAME = "sql_report.pdf"
# ==========================================

@sql_scanner_bp.route('/')
@login_required
def sql_scanner_page():
    """Renders the SQL scanner page."""
    logger.info(f"Accessing SQL Scanner Page (User: {current_user.username})")
    user_agent = request.headers.get('User-Agent')
    if user_agent and any(word in user_agent for word in ['Mobile', 'Android', 'iPhone', 'iPad']):
        return render_template('mobile_scanners/sql_scanner.html')
    return render_template('scanners/sql_scanner.html')

@sql_scanner_bp.route('/scan', methods=['POST'])
@login_required
def scan_sql():
    """
    API endpoint to initiate an SQL scan using SQLMap.
    Runs the scan in a separate thread to avoid blocking the Flask app.
    """
    data = request.get_json()
    target_url = data.get('target_url', '').strip()
    user_confirmed_auth = data.get('user_confirmed_auth', False)
    
    logger.info(f"SQL Injection Scan requested for {target_url} by {current_user.username}")
    scan_mode = data.get('scan_mode', 'quick') # Default to 'quick'

    if not target_url:
        sql_scanner.log("[!] Target URL cannot be empty for SQL scan.")
        return jsonify({"status": "error", "message": "Target URL is required."}), 400

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
    
    # Basic URL validation
    if not target_url.startswith(('http://', 'https://')):
        return jsonify({"status": "error", "message": "Invalid URL. Must start with http:// or https://"}), 400

    # Capture User Info for Logging
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_id = current_user.id # Capture ID for the thread
    app = current_app._get_current_object()

    # [NEW] Prevent Multiple Concurrent Scans for the same user
    if sql_scanner.is_scan_running(current_user_identifier):
        logger.warning(f"[!] SQL Scan already in progress for user {current_user_identifier}")
        return jsonify({
            "status": "error", 
            "message": "An SQL injection scan is already in progress. Please wait for it to complete."
        }), 400

    # Check if SQLMap is configured correctly
    if not os.path.exists(sql_scanner.SQLMAP_PATH):
        sql_scanner.log("[!] SQLMap script not found. Cannot perform scan.")
        return jsonify({
            "status": "error",
            "message": "SQLMap not found. Please check server configuration."
        }), 500

    # Determine User Directory for this scan
    user_base_dir = get_user_results_dir()

    # [RC-8 FIX] Atomic DB counter increment
    try:
        if hasattr(current_user, 'scan_count_sql'):
            from sqlalchemy import update as _sa_update
            from models.models import User as _User
            db.session.execute(
                _sa_update(_User).where(_User.id == current_user.id)
                .values(scan_count_sql=_User.scan_count_sql + 1)
            )
            db.session.commit()
    except Exception as e:
        db.session.rollback()  # RC-3 FIX
        sql_scanner.log(f"[!] Failed to update user stats: {e}", current_user_identifier)

    # [NEW] Reset Log File for this new scan session
    scan_logger.reset_log_file(current_user_identifier, "sql_scanner")

    # Function to run in a separate thread
    def scan_task():
        try:
            # Use DB Logging
            with app.app_context():
                log_id = scan_logger.log_scan_start(
                    user_id=user_id,
                    tool_name="SQLMap",
                    target=target_url,
                    scan_type=f"{scan_mode.title()} Mode"
                )

            sql_scanner.log(f"[*] Starting {scan_mode.upper()} SQL scan for {target_url} (User: {current_user_identifier})...", current_user_identifier, to_console=True)
            
            start_time = time.time()
            
            # Generate a consistent timestamp for this single scan session
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # 1. Run the Scan (Returns path to JSON report if successful)
            # We now run it directly in user_base_dir instead of a timestamped subfolder
            json_report_path = sql_scanner.run_sql_scan(
                target_url, 
                output_dir=user_base_dir, 
                scan_mode=scan_mode,
                user_id=current_user_identifier,
                timestamp=timestamp
            )
            
            duration = time.time() - start_time
            finding_count = 0
            status = "Failed"

            if json_report_path and os.path.exists(json_report_path):
                status = "Completed"
                # Try to count findings
                try:
                    with open(json_report_path, 'r', encoding='utf-8') as f:
                        report_data = json.load(f)
                        finding_count = len(report_data.get('vulnerabilities', []))
                except:
                    pass

                sql_scanner.log(f"[+] SQL scan complete. Generating PDF report for {target_url}...", current_user_identifier, to_console=True)
                
                # 2. Generate PDF Report
                try:
                    # Get user-specific paths
                    user_paths = sql_scanner.get_output_paths(user_base_dir, target=target_url, timestamp=timestamp)
                    pdf_path = user_paths["pdf_report"]
                    
                    # Check if the PDF generator has the SQL function implemented
                    if hasattr(pdf_generator, 'create_sql_report_pdf'):
                        success = pdf_generator.create_sql_report_pdf(str(json_report_path), str(pdf_path), user_id=current_user_identifier)
                        
                        if success and os.path.exists(pdf_path):
                            # Final synchronization wait using centralized helper
                            report_manager.wait_for_file(pdf_path)
                            sql_scanner.log(f"[+] PDF report generated and updated in user dashboard", current_user_identifier, to_console=True)
                            sql_scanner.log(f"SYSTEM_EVENT: READY_FOR_ANALYSIS:{target_url}", current_user_identifier, to_console=True)
                        else:
                            # If it returned False or file wasn't created, the error is already logged inside the generator
                            # but we add a final confirmation here.
                            sql_scanner.log("[!] PDF generation failed to produce a valid report file.", current_user_identifier, to_console=True)
                    else:
                        sql_scanner.log("[!] PDF Generator missing 'create_sql_report_pdf' function.", current_user_identifier, to_console=True)
                
                except Exception as e:
                    sql_scanner.log(f"[!] Critical error during PDF generation: {str(e)}", current_user_identifier, to_console=True)
            else:
                sql_scanner.log(f"[!] SQL scan failed or produced no results for {target_url}.", current_user_identifier, to_console=True)
            
            # Log to Database (Inside App Context)
            with app.app_context():
                # [FIXED] Pass error msg on failure
                error_msg = None if status == "Completed" else "SQLMap failed to complete."
                scan_logger.log_scan_end(log_id, status=status, finding_count=finding_count, duration=duration, error_msg=error_msg)
        
        except Exception as e:
             sql_scanner.log(f"[!] Unexpected error in scan thread: {str(e)}", current_user_identifier)

        finally:
            # RELEASE LOCK
            with sql_scanner.scan_lock:
                 if current_user_identifier in sql_scanner.active_scans:
                     del sql_scanner.active_scans[current_user_identifier]

    threading.Thread(target=scan_task, daemon=True).start()  # RC-5 FIX: daemon=True
    return jsonify({"status": "success", "message": f"SQL scan for {target_url} initiated."})

@sql_scanner_bp.route('/check_active_scan', methods=['GET'])
@login_required
def check_active_scan():
    """
    Checks if there's an active scan running for the current user's session.
    Prioritizes DB state (SSOT).
    """
    # 1. CHECK DB (Primary Source of Truth)
    active_log = scan_logger.get_active_scan_log(current_user.id, "SQLMap")
    
    if active_log:
        return jsonify({
            "status": "active",
            "message": "Active scan found (DB)",
            "target": active_log.target,
            "scan_id": active_log.id
        }), 200

    # 2. Fallback: Check Memory
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    if sql_scanner.is_scan_running(current_user_identifier):
         return jsonify({
            "status": "active",
            "message": "Active scan found (Memory)"
        }), 200

    return jsonify({"status": "inactive", "message": "No active scan found"}), 200


@sql_scanner_bp.route('/report_history', methods=['GET'])
@login_required
def get_sql_report_history():
    user_dir = get_user_results_dir()
    history = report_manager.get_report_history(user_dir, scanner_name="sql_scanner")
    return jsonify({"status": "success", "history": history})

@sql_scanner_bp.route('/trigger_ai_analysis', methods=['POST'])
@login_required
def trigger_ai_analysis_route():
    """Robustly triggers AI analysis by finding the correct PDF report."""
    data = request.get_json() or {}
    target = data.get('target')
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_dir = get_user_results_dir()
    
    # Resolve the latest PDF report for this scanner
    pdf_path_str = report_manager.find_latest_report(user_dir, "sql_scanner", target=target, extension="pdf")
    
    if not pdf_path_str:
        # Fallback to any PDF in the scanner's folder
        pdf_path_str = report_manager.find_latest_report(user_dir, scanner_name=None, extension="pdf")

    if not pdf_path_str or not os.path.exists(pdf_path_str):
        sql_scanner.log(f"[!] Analysis failed: PDF report not found in {user_dir}", user_identifier)
        return jsonify({
            "status": "error", 
            "message": "PDF report not available. Please run a scan first."
        }), 404

    return jsonify({
        "status": "success",
        "scanner_type": "sql",
        "target": target
    })

@sql_scanner_bp.route('/report_files', methods=['GET'])
@login_required
def get_report_files():
    """Checks availability of reports to enable the download button."""
    target = request.args.get('target')
    user_dir = get_user_results_dir()
    
    latest_json = report_manager.find_latest_report(user_dir, "sql_scanner", target=target, extension="json")
    latest_pdf = report_manager.find_latest_report(user_dir, "sql_scanner", target=target, extension="pdf")

    if not latest_json and not latest_pdf:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    return jsonify({
        "status": "success",
        "json_report": f"/sql_scanner/get_json_report?target={target}" if target else "/sql_scanner/get_json_report",
        "pdf_report": f"/sql_scanner/download_pdf?target={target}" if target else "/sql_scanner/download_pdf"
    })

@sql_scanner_bp.route('/download_pdf', methods=['GET'])
@login_required
def download_pdf_report():
    """Serves the latest SQL PDF report dynamically."""
    user_dir = get_user_results_dir()
    requested_filename = request.args.get('filename')
    target = request.args.get('target')
    
    if requested_filename:
        filename = secure_filename(requested_filename)
        pdf_path = os.path.join(user_dir, filename)
    else:
        pdf_path = report_manager.find_latest_report(user_dir, "sql_scanner", target=target, extension="pdf")
        if not pdf_path:
             return jsonify({"status": "error", "message": "No SQL PDF report found."}), 404
        filename = os.path.basename(pdf_path)

    if not os.path.exists(pdf_path):
        return jsonify({"status": "error", "message": "PDF report file not found."}), 404
    
    return send_from_directory(
        directory=os.path.dirname(pdf_path),
        path=filename,
        as_attachment=True
    )

@sql_scanner_bp.route('/get_json_report', methods=['GET'])
@login_required
def get_json_report_file():
    """Serves the latest JSON report file for SQL scans."""
    filename = request.args.get('filename')
    target = request.args.get('target')
    user_dir = get_user_results_dir()
    
    if filename:
        filename = secure_filename(filename)
        json_path_str = os.path.join(user_dir, filename)
    else:
        json_path_str = report_manager.find_latest_report(user_dir, "sql_scanner", target=target, extension="json")
        if json_path_str:
            filename = os.path.basename(json_path_str)

    if not json_path_str or not os.path.exists(json_path_str):
        return jsonify({"status": "error", "message": "JSON report file not found."}), 404
    
    return send_from_directory(
        directory=os.path.dirname(json_path_str),
        path=filename,
        as_attachment=True
    )

@sql_scanner_bp.route('/report', methods=['GET'])
@login_required
def get_sql_report_content():
    """
    API endpoint to get the content of the parsed SQL scan report (JSON content).
    Used by frontend to render immediate results.
    """
    target = request.args.get('target')
    user_dir = get_user_results_dir()
    
    json_path_str = report_manager.find_latest_report(user_dir, "sql_scanner", target=target, extension="json")

    if not json_path_str or not os.path.exists(json_path_str):
        return jsonify({
            "status": "error",
            "message": "No SQL scan report available. Please run a scan first."
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
        sql_scanner.log(f"[!] Error reading SQL scan report: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to read SQL scan report: {str(e)}"
        }), 500

@sql_scanner_bp.route('/clear_log', methods=['POST'])
@login_required
def clear_sql_log_route():
    """API endpoint to clear the SQL scanner log file."""
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    scan_logger.reset_log_file(user_identifier, "sql_scanner")
    return jsonify({"status": "success", "message": "SQL log cleared."})

@sql_scanner_bp.route('/log_stream')
@login_required
def sql_log_stream():
    """Server-Sent Events (SSE) endpoint to stream SQL scanner log messages."""
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    return Response(
        scan_logger.tail_log_file(user_identifier, "sql_scanner"),
        mimetype='text/event-stream'
    )
