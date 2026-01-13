from flask import Blueprint, render_template, jsonify, request, Response, send_from_directory
from flask_login import login_required, current_user
import threading
import json
import time
import os
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

sql_scanner_bp = Blueprint('sql_scanner_bp', __name__)

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
    # (Assuming the service has a path check, usually handled inside run_sql_scan too)
    if not os.path.exists(sql_scanner.SQLMAP_PATH):
        sql_scanner.log("[!] SQLMap script not found. Cannot perform scan.")
        return jsonify({
            "status": "error",
            "message": "SQLMap not found. Please check server configuration."
        }), 500
    
    # Determine User Directory for this scan
    user_output_dir = get_user_results_dir()

    # Capture User Info for Logging
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"

    # [NEW] Increment Database Counter for Stats
    try:
        # Assuming you will add 'scan_count_sql' to your User model later
        if hasattr(current_user, 'scan_count_sql'):
            current_user.scan_count_sql += 1
            db.session.commit()
    except Exception as e:
        sql_scanner.log(f"[!] Failed to update user stats: {e}")

    # Function to run in a separate thread
    def scan_task():
        sql_scanner.log(f"[*] Starting {scan_mode.upper()} SQL scan for {target_url} (User: {current_user_identifier})...")
        
        # 1. Run the Scan (Returns path to JSON report if successful)
        json_report_path = sql_scanner.run_sql_scan(
            target_url, 
            output_dir=user_output_dir, 
            scan_mode=scan_mode
        )
        
        if json_report_path and os.path.exists(json_report_path):
            sql_scanner.log(f"[+] SQL scan complete. Generating PDF report...")
            
            # 2. Generate PDF Report
            try:
                # Define PDF path
                pdf_path = os.path.join(user_output_dir, PDF_FILENAME)
                
                # Create the directory for PDFs if it doesn't exist (safety check)
                os.makedirs(os.path.dirname(pdf_path), exist_ok=True)
                
                # Check if the PDF generator has the SQL function implemented
                if hasattr(pdf_generator, 'create_sql_report_pdf'):
                    pdf_generator.create_sql_report_pdf(str(json_report_path), str(pdf_path))
                    
                    if os.path.exists(pdf_path):
                        sql_scanner.log(f"[+] PDF report generated successfully: {pdf_path}")
                    else:
                        sql_scanner.log("[!] PDF generation ran but file not found.")
                else:
                    sql_scanner.log("[!] PDF Generator missing 'create_sql_report_pdf' function.")
            
            except Exception as e:
                sql_scanner.log(f"[!] FAILED to generate PDF: {str(e)}")
        else:
            sql_scanner.log(f"[!] SQL scan failed or produced no results for {target_url}.")

    threading.Thread(target=scan_task).start()
    return jsonify({"status": "success", "message": f"SQL scan for {target_url} initiated."})

@sql_scanner_bp.route('/trigger_ai_analysis', methods=['POST'])
@login_required
def trigger_ai_analysis_route():
    """
    Checks if PDF exists and returns scanner type for the AI Chatbot.
    """
    user_dir = get_user_results_dir()
    pdf_path = os.path.join(user_dir, PDF_FILENAME)

    if not os.path.exists(pdf_path):
        sql_scanner.log(f"[!] Analysis failed: PDF report not found at {pdf_path}")
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
    sql_scanner.clear_log_file()
    return jsonify({"status": "success", "message": "SQL log cleared."})

@sql_scanner_bp.route('/log_stream')
@login_required
def sql_log_stream():
    """Server-Sent Events (SSE) endpoint to stream SQL scanner log messages."""
    def generate_logs():
        while True:
            try:
                message = sql_scanner.log_queue.get(timeout=10)
                yield message
            except Empty:
                yield ": keep-alive\n\n"
            except GeneratorExit:
                break

    return Response(generate_logs(), mimetype='text/event-stream')