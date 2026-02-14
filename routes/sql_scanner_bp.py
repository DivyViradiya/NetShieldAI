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
from werkzeug.utils import secure_filename 

# Import db to update user stats
from extensions import db

# Import the sql_scanner module
from Services import sql_scanner
# Import the PDF generator module
from Services import pdf_generator
# --- Import Scan Logger ---
from Services import scan_logger

sql_scanner_bp = Blueprint('sql_scanner_bp', __name__)

# --- GLOBAL LOCK STATE ---
# Track active scans per user to prevent concurrent conflicting processes
active_user_scans = set()
scan_lock = threading.Lock()

# --- PHASE 3: User-Specific Directory Helper ---
def get_user_results_dir():
    """
    Constructs the path: Services/results/<username_id>/sql_scanner
    """
    if not current_user.is_authenticated:
        return None
    
    # Composite Identifier: username_id
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    user_dir = os.path.join(base_dir, 'Services', 'results', user_identifier, 'sql_scanner')
    
    # Create directory if it doesn't exist
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
    return render_template('scanners/sql_scanner.html')

@sql_scanner_bp.route('/scan', methods=['POST'])
@login_required
def scan_sql():
    """
    API endpoint to initiate an SQL scan using SQLMap.
    Runs the scan in a separate thread to avoid blocking the Flask app.
    """
    data = request.get_json()
    target_url = data.get('target_url')
    scan_mode = data.get('scan_mode', 'quick') # Default to 'quick'

    if not target_url:
        sql_scanner.log("[!] Target URL cannot be empty for SQL scan.")
        return jsonify({"status": "error", "message": "Target URL is required."}), 400
    
    # Basic URL validation
    if not target_url.startswith(('http://', 'https://')):
        return jsonify({"status": "error", "message": "Invalid URL. Must start with http:// or https://"}), 400

    # Check if SQLMap is configured correctly
    if not os.path.exists(sql_scanner.SQLMAP_PATH):
        sql_scanner.log("[!] SQLMap script not found. Cannot perform scan.")
        return jsonify({
            "status": "error",
            "message": "SQLMap not found. Please check server configuration."
        }), 500
    
    # --- CONCURRENCY CHECK ---
    with scan_lock:
        if current_user.id in active_user_scans:
            return jsonify({
                "status": "error",
                "message": "A scan is already in progress. Please wait for it to complete."
            }), 429
        active_user_scans.add(current_user.id)

    # Determine User Directory for this scan
    user_base_dir = get_user_results_dir()

    # Capture User Info for Logging
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_id = current_user.id # Capture ID for the thread
    app = current_app._get_current_object()

    # [NEW] Increment Database Counter for Stats
    try:
        # Assuming you will add 'scan_count_sql' to your User model later
        if hasattr(current_user, 'scan_count_sql'):
            current_user.scan_count_sql += 1
            db.session.commit()
    except Exception as e:
        sql_scanner.log(f"[!] Failed to update user stats: {e}", current_user_identifier)

    # Function to run in a separate thread
    def scan_task():
        try:
            sql_scanner.log(f"[*] Starting {scan_mode.upper()} SQL scan for {target_url} (User: {current_user_identifier})...", current_user_identifier)
            
            start_time = time.time()
            
            # 1. Run the Scan (Returns path to JSON report if successful)
            # We now run it directly in user_base_dir instead of a timestamped subfolder
            json_report_path = sql_scanner.run_sql_scan(
                target_url, 
                output_dir=user_base_dir, 
                scan_mode=scan_mode,
                user_id=current_user_identifier
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

                sql_scanner.log(f"[+] SQL scan complete. Generating PDF report...", current_user_identifier)
                
                # 2. Generate PDF Report
                try:
                    # PDF path is now directly in user_base_dir
                    pdf_path = os.path.join(user_base_dir, PDF_FILENAME)
                    
                    # Check if the PDF generator has the SQL function implemented
                    if hasattr(pdf_generator, 'create_sql_report_pdf'):
                        pdf_generator.create_sql_report_pdf(str(json_report_path), str(pdf_path))
                        
                        if os.path.exists(pdf_path):
                            sql_scanner.log(f"[+] PDF report generated and updated in user dashboard: {pdf_path}", current_user_identifier)
                        else:
                            sql_scanner.log("[!] PDF generation ran but file not found.", current_user_identifier)
                    else:
                        sql_scanner.log("[!] PDF Generator missing 'create_sql_report_pdf' function.", current_user_identifier)
                
                except Exception as e:
                    sql_scanner.log(f"[!] FAILED to generate PDF: {str(e)}", current_user_identifier)
            else:
                sql_scanner.log(f"[!] SQL scan failed or produced no results for {target_url}.", current_user_identifier)
            
            # Log to Database (Inside App Context)
            with app.app_context():
                scan_logger.create_full_scan_log(
                    user_id=user_id,
                    tool_name="SQLMap",
                    target=target_url,
                    duration=duration,
                    finding_count=finding_count,
                    status=status,
                    scan_type=f"{scan_mode.title()} Mode"
                )
        
        except Exception as e:
             sql_scanner.log(f"[!] Unexpected error in scan thread: {str(e)}", current_user_identifier)

        finally:
            # RELEASE LOCK
            with scan_lock:
                active_user_scans.discard(user_id)

    threading.Thread(target=scan_task).start()
    return jsonify({"status": "success", "message": f"SQL scan for {target_url} initiated."})

@sql_scanner_bp.route('/trigger_ai_analysis', methods=['POST'])
@login_required
def trigger_ai_analysis_route():
    """
    Checks if PDF exists and returns scanner type for the AI Chatbot.
    """
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_dir = get_user_results_dir()
    pdf_path = os.path.join(user_dir, PDF_FILENAME)

    if not os.path.exists(pdf_path):
        sql_scanner.log(f"[!] Analysis failed: PDF report not found at {pdf_path}", user_identifier)
        return jsonify({
            "status": "error", 
            "message": "PDF report not available. Please run a scan first."
        }), 404

    return jsonify({
        "status": "success",
        "scanner_type": "sql" 
    })

@sql_scanner_bp.route('/report_files', methods=['GET'])
@login_required
def get_report_files():
    """Checks availability of reports to enable the download button."""
    user_dir = get_user_results_dir()
    
    # We use the helper from the service to get standard paths
    paths = sql_scanner.get_output_paths(user_dir)
    json_path = paths["json_report"]
    pdf_path = paths["pdf_report"]

    json_exists = json_path.exists()
    pdf_exists = pdf_path.exists()

    if not json_exists and not pdf_exists:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    return jsonify({
        "status": "success",
        "json_report": "/sql_scanner/get_json_report" if json_exists else None,
        "pdf_report": "/sql_scanner/download_pdf" if pdf_exists else None
    })

@sql_scanner_bp.route('/download_pdf', methods=['GET'])
@login_required
def download_pdf_report():
    """Serves the PDF report dynamically."""
    user_dir = get_user_results_dir()
    paths = sql_scanner.get_output_paths(user_dir)
    pdf_path = paths["pdf_report"]

    if not pdf_path.exists():
        return jsonify({"status": "error", "message": "PDF report file not found."}), 404
    
    return send_from_directory(
        directory=str(pdf_path.parent),
        path=pdf_path.name,
        as_attachment=True
    )

@sql_scanner_bp.route('/get_json_report', methods=['GET'])
@login_required
def get_json_report_file():
    """Serves the JSON report file."""
    user_dir = get_user_results_dir()
    paths = sql_scanner.get_output_paths(user_dir)
    json_path = paths["json_report"]

    if not json_path.exists():
        return jsonify({"status": "error", "message": "JSON report file not found."}), 404
    
    return send_from_directory(
        directory=str(json_path.parent),
        path=json_path.name,
        as_attachment=True
    )

@sql_scanner_bp.route('/report', methods=['GET'])
@login_required
def get_sql_report_content():
    """
    API endpoint to get the content of the parsed SQL scan report (JSON content).
    Used by frontend to render immediate results.
    """
    user_dir = get_user_results_dir()
    paths = sql_scanner.get_output_paths(user_dir)
    json_path = paths["json_report"]

    if not json_path.exists():
        return jsonify({
            "status": "error",
            "message": "No SQL scan report available. Please run a scan first."
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
    sql_scanner.clear_log_file(user_identifier)
    return jsonify({"status": "success", "message": "SQL log cleared."})

@sql_scanner_bp.route('/log_stream')
@login_required
def sql_log_stream():
    """Server-Sent Events (SSE) endpoint to stream SQL scanner log messages."""
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    def generate_logs():
        user_queue = sql_scanner.get_user_queue(user_identifier)
        while True:
            try:
                message = user_queue.get(timeout=10)
                yield message
            except Empty:
                yield ": keep-alive\n\n"
            except GeneratorExit:
                break

    return Response(generate_logs(), mimetype='text/event-stream')