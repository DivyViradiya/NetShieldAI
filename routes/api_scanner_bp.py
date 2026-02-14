import os
import threading
import json
import time
import queue 
from flask import Blueprint, render_template, jsonify, request, Response, send_from_directory
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename 

from flask import Blueprint, render_template, jsonify, request, Response, send_from_directory, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename 

# Import db to update user stats
from extensions import db
from Services import api_scanner 
from Services import pdf_generator 
# --- Import Scan Logger ---
from Services import scan_logger

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
    print(f"\033[34m[*] Accessing API Security Scanner Page (User: {current_user.username})\033[0m")
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
    print(f"\033[34m[*] API Scan requested for {target_url} by {current_user.username}\033[0m")
    # [NEW] API Scans require a definition (Swagger/OpenAPI)
    definition_url = data.get('definition_url') 

    if not target_url:
        return jsonify({"status": "error", "message": "Target API URL is required."}), 400
    
    if not definition_url:
        return jsonify({"status": "error", "message": "OpenAPI/Swagger Definition URL is required."}), 400
    
    # --- Auto-append Protocol ---
    target_url = target_url.strip() 
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    # Check if ML model is loaded (if you are using AI for API too)
    if api_scanner.model is None:
        return jsonify({"status": "error", "message": "ML model is not loaded."}), 500

    # User Context
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_output_dir = get_user_results_dir()
    user_id_for_log = current_user.id
    app = current_app._get_current_object()

    # [NEW] Increment Database Counter (assuming you want to track API scans)
    try:
        # You might want to create a specific 'scan_count_api' column later
        current_user.scan_count_zap += 1 
        db.session.commit()
    except Exception as e:
        api_scanner.log(f"[!] Failed to update user stats: {e}", current_user_identifier)

    def scan_and_process_task():
        api_scanner.log(f"[*] Starting API Scan for {target_url}...", current_user_identifier, to_console=True)
        api_scanner.log(f"[*] Using Definition: {definition_url}", current_user_identifier, to_console=True)
        
        paths = api_scanner.get_output_paths(user_output_dir)
        xml_path = paths["xml_report"]
        pdf_path = paths["pdf_report"]
        
        os.makedirs(os.path.dirname(xml_path), exist_ok=True)
        
        start_time = time.time()
        
        # 1. Run API Scan
        # Passing definition_url is the key difference here
        scan_successful = api_scanner.run_api_scan(target_url, definition_url, str(xml_path), current_user_identifier)

        duration = time.time() - start_time
        status = "Failed"
        finding_count = 0

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
                json_report_path = api_scanner.save_json_report(scan_results, user_output_dir, current_user_identifier)
                
                if json_report_path:
                    api_scanner.log(f"[+] JSON report saved.", current_user_identifier, to_console=True)
                    
                    # 4. Generate PDF
                    try:
                        api_scanner.log("[*] Generating PDF report...", current_user_identifier, to_console=True)
                        # Reusing the generator, assuming it handles generic JSON data structure
                        pdf_generator.create_zap_report_pdf(json_report_path, str(pdf_path))
                        
                        if pdf_path.exists():
                            api_scanner.log(f"[+] PDF generated successfully.", current_user_identifier, to_console=True)
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

        # Log to Database (Inside App Context)
        with app.app_context():
            scan_logger.create_full_scan_log(
                user_id=user_id_for_log,
                tool_name="API Scanner",
                target=target_url,
                duration=duration,
                finding_count=finding_count,
                status=status,
                scan_type="OpenAPI"
            )

    threading.Thread(target=scan_and_process_task).start()
    
    return jsonify({
        "status": "success",
        "message": f"API Scan initiated for {target_url}."
    })


# -----------------------------------------------
# ## 📥 Report Retrieval Routes
# -----------------------------------------------

@api_scanner_bp.route('/scan_results', methods=['GET'])
@login_required 
def get_api_scan_results():
    user_dir = get_user_results_dir()
    paths = api_scanner.get_output_paths(user_dir)
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
    user_dir = get_user_results_dir()
    paths = api_scanner.get_output_paths(user_dir)
    
    json_exists = paths["json_report"].exists()
    pdf_exists = paths["pdf_report"].exists()

    if not json_exists and not pdf_exists:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    return jsonify({
        "status": "success",
        # Note the prefix change to /api_scanner/
        "json_report": "/api_scanner/scan_results" if json_exists else None,
        "pdf_report": "/api_scanner/download_pdf" if pdf_exists else None
    })


@api_scanner_bp.route('/download_pdf', methods=['GET'])
@login_required
def download_pdf_report():
    user_dir = get_user_results_dir()
    paths = api_scanner.get_output_paths(user_dir)
    pdf_path = paths["pdf_report"]

    if not pdf_path.exists():
        return jsonify({"status": "error", "message": "PDF file not found."}), 404
    
    try:
        directory = str(pdf_path.parent)
        filename = pdf_path.name
        return send_from_directory(directory=directory, path=filename, as_attachment=True)
    except Exception as e:
        return jsonify({"status": "error", "message": "Could not serve PDF file."}), 500


# -----------------------------------------------
# ## 📝 Log Streaming Routes
# -----------------------------------------------

@api_scanner_bp.route('/clear_log', methods=['POST'])
@login_required 
def clear_api_log_route():
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    api_scanner.clear_log_file(current_user_identifier)
    return jsonify({"status": "success", "message": "Log cleared."})


@api_scanner_bp.route('/log_stream')
@login_required 
def api_log_stream():
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    
    def generate_logs():
        # Get the specific queue for this user from the API service
        user_queue = api_scanner.get_user_queue(current_user_identifier)
        
        while True:
            try:
                message = user_queue.get(timeout=5)
                yield f"data: {message}\n\n"
            except queue.Empty:
                yield ": keep-alive\n\n"
            except Exception as e:
                yield f"data: Error in stream: {str(e)}\n\n"

    return Response(generate_logs(), mimetype='text/event-stream')