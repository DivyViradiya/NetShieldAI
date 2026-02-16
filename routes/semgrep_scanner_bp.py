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
from extensions import db

# Import the semgrep_scanner module
from Services import semgrep_scanner
# Import the PDF generator module
from Services import pdf_generator
# --- Import Scan Logger ---
from Services import scan_logger

semgrep_bp = Blueprint('semgrep_bp', __name__)

# --- CONFIGURATION ---
MAX_UPLOAD_SIZE = 1024 * 1024 * 1024  # 1 GB limit

# --- User-Specific Directory Helper ---
def get_user_results_dir():
    """
    Constructs the path: Services/results/<username_id>/semgrep_scanner
    """
    if not current_user.is_authenticated:
        return None
    
    # Composite Identifier
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    user_dir = os.path.join(base_dir, 'Services', 'results', user_identifier, 'semgrep_scanner')
    
    os.makedirs(user_dir, exist_ok=True)
        
    return user_dir

@semgrep_bp.route('/')
@login_required
def semgrep_scanner_page():
    """Renders the Semgrep scanner page."""
    print(f"\033[32m[*] Accessing Source Code Scanner Page (User: {current_user.username})\033[0m")
    return render_template('scanners/semgrep_scanner.html')

@semgrep_bp.route('/scan', methods=['POST'])
@login_required
def scan_code():
    """
    API endpoint to initiate a Semgrep scan.
    Handles both File Uploads (Zip) and Git URLs.
    Runs the scan in a separate thread.
    """
    print(f"\033[32m[*] Semgrep SAST Scan requested by {current_user.username}\033[0m")
    user_output_dir = get_user_results_dir()
    
    target_input = None
    input_type = None

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
        
        # Save temp file securely so the thread can access it
        temp_filename = f"upload_temp_{secure_filename(file.filename)}"
        temp_path = os.path.join(user_output_dir, temp_filename)
        file.save(temp_path)
        
        target_input = temp_path
        input_type = "zip"
        target_display = file.filename

    elif 'git_url' in request.form:
        target_input = request.form['git_url']
        if not target_input.strip():
             return jsonify({"status": "error", "message": "Git URL cannot be empty."}), 400
        input_type = "git"
        target_display = target_input

    else:
        return jsonify({"status": "error", "message": "Invalid input. Provide a file or git_url."}), 400

    # 2. Update Database Stats
    try:
        # Assuming you added 'scan_count_semgrep' to your User model. 
        # If not, add it or use a generic field.
        if hasattr(current_user, 'scan_count_semgrep'):
            current_user.scan_count_semgrep += 1
        else:
            # Fallback if specific field doesn't exist yet
            current_user.scan_count += 1 
        db.session.commit()
    except Exception as e:
        current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
        semgrep_scanner.log(f"[!] Failed to update user stats: {e}", user_id=current_user_identifier)

    # Capture User ID for thread safety
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_id = current_user.id
    app = current_app._get_current_object()

    # 3. Define Background Task
    def scan_task():
        semgrep_scanner.log(f"[*] Starting Semgrep SAST scan on {target_display} (User: {current_user_identifier})...", user_id=current_user_identifier, to_console=True)
        
        start_time = time.time()
        
        # Run Scan
        report_file = semgrep_scanner.run_semgrep_scan(
            target_input=target_input, 
            input_type=input_type, 
            output_dir=user_output_dir,
            user_id=current_user_identifier
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

        if report_file:
            status = "Completed"
            semgrep_scanner.log(f"[+] Semgrep scan complete. Generating PDF report...", user_id=current_user_identifier, to_console=True)
            
            # Extract finding count from saved JSON
            try:
                user_paths = semgrep_scanner.get_output_paths(user_output_dir)
                json_path = user_paths["parsed_json"]
                
                with open(json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    finding_count = data.get('total_findings', 0)
            except:
                pass

            # Generate PDF Report
            try:
                # Create a specific PDF name
                pdf_path = Path(user_output_dir) / "semgrep_report.pdf"

                # Ensure directory exists
                pdf_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Call PDF Generator (Note: You need to add this function to Services/pdf_generator.py)
                if hasattr(pdf_generator, 'create_semgrep_report_pdf'):
                    pdf_generator.create_semgrep_report_pdf(str(json_path), str(pdf_path))
                    
                    if pdf_path.exists():
                        # Final synchronization wait
                        time.sleep(1.5)
                        semgrep_scanner.log(f"[+] PDF report generated: {pdf_path.name}", user_id=current_user_identifier, to_console=True)
                        semgrep_scanner.log("SYSTEM_EVENT: READY_FOR_ANALYSIS", user_id=current_user_identifier, to_console=True)
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
            scan_logger.create_full_scan_log(
                user_id=user_id,
                tool_name="Semgrep SAST",
                target=target_display,
                duration=duration,
                finding_count=finding_count,
                status=status,
                scan_type="Code Audit"
            )

    # 4. Start Thread
    threading.Thread(target=scan_task).start()
    
    return jsonify({"status": "success", "message": f"Code scan started for {target_display}."})

# --- Standard Routes (Replicating SSL Scanner Pattern) ---

@semgrep_bp.route('/trigger_ai_analysis', methods=['POST'])
@login_required
def trigger_ai_analysis_route():
    """Checks if PDF exists and tells Chatbot to use 'semgrep' mode."""
    user_dir = get_user_results_dir()
    # We construct the path manually to match the scan_task logic
    pdf_path = Path(user_dir) / "semgrep_report.pdf"

    if not pdf_path.exists():
        current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
        semgrep_scanner.log(f"[!] Analysis failed: PDF report not found.", user_id=current_user_identifier)
        return jsonify({
            "status": "error", 
            "message": "PDF report not available. Please run a scan first."
        }), 404

    return jsonify({
        "status": "success",
        "scanner_type": "semgrep" 
    })

@semgrep_bp.route('/report_files', methods=['GET'])
@login_required
def get_report_files():
    """Checks availability of reports to enable download buttons."""
    user_dir = get_user_results_dir()
    paths = semgrep_scanner.get_output_paths(user_dir)
    
    json_path = paths["parsed_json"]
    pdf_path = Path(user_dir) / "semgrep_report.pdf"

    json_exists = json_path.exists()
    pdf_exists = pdf_path.exists()

    if not json_exists and not pdf_exists:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    return jsonify({
        "status": "success",
        "json_report": "/semgrep_scanner/get_json_report" if json_exists else None,
        "pdf_report": "/semgrep_scanner/download_pdf" if pdf_exists else None
    })

@semgrep_bp.route('/download_pdf', methods=['GET'])
@login_required
def download_pdf_report():
    """Serves the PDF report."""
    user_dir = get_user_results_dir()
    pdf_path = Path(user_dir) / "semgrep_report.pdf"

    if not pdf_path.exists():
        return jsonify({"status": "error", "message": "PDF report file not found."}), 404
    
    return send_from_directory(
        directory=str(pdf_path.parent),
        path=pdf_path.name,
        as_attachment=True
    )

@semgrep_bp.route('/get_json_report', methods=['GET'])
@login_required
def get_json_report_file():
    """Serves the JSON report."""
    user_dir = get_user_results_dir()
    paths = semgrep_scanner.get_output_paths(user_dir)
    json_path = paths["parsed_json"]

    if not json_path.exists():
        return jsonify({"status": "error", "message": "JSON report file not found."}), 404
    
    return send_from_directory(
        directory=str(json_path.parent),
        path=json_path.name,
        as_attachment=True
    )

@semgrep_bp.route('/report', methods=['GET'])
@login_required
def get_semgrep_report():
    """
    API endpoint to get the content of the parsed scan report (JSON content).
    Used by the frontend to render the results table immediately.
    """
    user_dir = get_user_results_dir()
    paths = semgrep_scanner.get_output_paths(user_dir)
    json_path = paths["parsed_json"]

    if not json_path.exists():
        return jsonify({
            "status": "error",
            "message": "No scan report available."
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
        current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
        semgrep_scanner.log(f"[!] Error reading Semgrep report: {e}", user_id=current_user_identifier)
        return jsonify({
            "status": "error",
            "message": f"Failed to read report: {str(e)}"
        }), 500

@semgrep_bp.route('/clear_log', methods=['POST'])
@login_required
def clear_log_route():
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    semgrep_scanner.clear_log_file(current_user_identifier)
    return jsonify({"status": "success", "message": "Log cleared."})

@semgrep_bp.route('/log_stream')
@login_required
def log_stream():
    """Server-Sent Events (SSE) endpoint."""
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    
    def generate_logs():
        user_queue = semgrep_scanner.get_user_queue(current_user_identifier)
        while True:
            try:
                message = user_queue.get(timeout=10)
                if message == ': keep-alive':
                    yield f"{message}\n\n"
                else:
                    yield f"data: {message}\n\n"
            except Empty:
                yield ": keep-alive\n\n"
            except GeneratorExit:
                break

    return Response(generate_logs(), mimetype='text/event-stream')