import os
import threading
import queue
import time
import uuid
import re
import json
from pathlib import Path
from flask import Blueprint, render_template, jsonify, request, Response, send_from_directory
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
from extensions import db

# [SERVICE] Import the Singleton instance and helpers
from Services.killchain_service import killchain_service, get_scan_queue, cleanup_queue

killchain_bp = Blueprint('killchain_bp', __name__)

# ==========================================
# --- HELPER: Directory Management ---
# ==========================================
def get_user_root_dir():
    """Returns the ROOT result directory for the current user."""
    if not current_user.is_authenticated: return None
    
    # Base user folder: Services/results/Username_ID
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    user_dir = os.path.join(base_dir, 'Services', 'results', user_identifier)
    
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def get_fixed_scan_dir():
    """
    Returns the FIXED directory for the killchain reports.
    Path: Services/results/Username_ID/killchain
    """
    user_root = get_user_root_dir()
    if not user_root: return None
    
    # We use a fixed folder named "killchain" to ensure overwrites
    scan_dir = os.path.join(user_root, "killchain")
    return scan_dir

# ==========================================
# --- ROUTES ---
# ==========================================

@killchain_bp.route('/')
@login_required
def killchain_page():
    return render_template('killchain.html')


@killchain_bp.route('/dispatch', methods=['POST'])
@login_required
def dispatch_scan():
    """
    API endpoint to start the Kill Chain Audit.
    Generates a unique Scan ID for concurrency.
    """
    data = request.get_json()
    target = data.get('target', '').strip()
    profile = data.get('profile', 'full_audit')
    aggression = data.get('aggression', 'normal')

    # --- VALIDATION ---
    if not target:
        return jsonify({"status": "error", "message": "Target is required."}), 400

    # Basic input validation to prevent shell injection characters or invalid formats
    # Allows: domain.com, http://domain.com, 192.168.1.1
    # Disallows: ; | & $ > <
    if not re.match(r'^(?:http(s)?://)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\(\)\*\+,;=.]*$', target):
        return jsonify({"status": "error", "message": "Invalid target format. Please provide a valid URL or Domain."}), 400

    # 1. Generate Unique Scan ID (UUID)
    # We still need this for the Queue ID and frontend tracking, 
    # even though files are stored in a fixed folder.
    scan_id = str(uuid.uuid4())[:8] 
    
    # 2. Setup Directories (FIXED PATH)
    scan_dir = get_fixed_scan_dir()
    os.makedirs(scan_dir, exist_ok=True)

    # 3. Create Unique Queue ID
    # Format: user_id_scan_id
    queue_id = f"{current_user.id}_{scan_id}"

    # 4. Update DB Stats
    try:
        current_user.scan_count_killchain += 1
        db.session.commit()
    except Exception as e:
        print(f"[!] DB Error updating killchain stats: {e}")

    # 5. Launch Background Scan
    # We pass the FIXED scan_dir so the service writes to the same folder every time
    thread = threading.Thread(
        target=killchain_service.run_job,
        args=(target, profile, aggression, queue_id, scan_dir),
        daemon=True
    )
    thread.start()

    return jsonify({
        "status": "success",
        "message": f"Kill Chain Audit started on {target}",
        "scan_id": scan_id,  # Frontend must use this for polling
        "queue_id": queue_id
    })


@killchain_bp.route('/log_stream')
@login_required
def log_stream():
    """
    Streams logs for a specific scan ID via SSE.
    """
    queue_id = request.args.get('queue_id')
    
    if not queue_id:
        return jsonify({"error": "queue_id parameter is required"}), 400

    def generate_logs():
        q = get_scan_queue(queue_id)
        
        # NOTE: We do NOT clean up the queue in a 'finally' block here.
        # This prevents data loss if the client briefly disconnects/reconnects.
        # Cleanup is handled in the service layer when the scan actually finishes.
        
        try:
            while True:
                try:
                    # Blocking get with timeout
                    message = q.get(timeout=5)
                    yield message 
                    
                    # Optional: Check for completion signal to gracefully end local stream
                    if "event: scan_complete" in message:
                         # Wait a moment for frontend to process, then stop yielding
                         time.sleep(1)
                         break
                         
                except queue.Empty:
                    yield ": keep-alive\n\n"
                except Exception as e:
                    yield f"data: [System] Stream Error: {str(e)}\n\n"
                    break
        except GeneratorExit:
            # Standard exception when client disconnects
            pass

    return Response(generate_logs(), mimetype='text/event-stream')


@killchain_bp.route('/report_files', methods=['GET'])
@login_required
def get_report_files():
    """
    Checks if reports exist in the FIXED directory. 
    We ignore the scan_id for file lookup since files are overwritten.
    """
    scan_dir = get_fixed_scan_dir()
    if not scan_dir or not os.path.exists(scan_dir):
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    reports_dir = os.path.join(scan_dir, "reports")
    json_path = os.path.join(reports_dir, "killchain_report.json")
    pdf_path = os.path.join(reports_dir, "killchain_report.pdf")

    json_exists = os.path.exists(json_path)
    pdf_exists = os.path.exists(pdf_path)

    if not json_exists and not pdf_exists:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    # The frontend still expects a scan_id parameter for the download links, 
    # even if we don't strictly use it for looking up the path server-side anymore.
    current_scan_id = request.args.get('scan_id', 'latest')

    return jsonify({
        "status": "success",
        "json_report": f"/killchain/get_json_report?scan_id={current_scan_id}",
        "pdf_report": f"/killchain/download_pdf?scan_id={current_scan_id}"
    })


@killchain_bp.route('/download_pdf', methods=['GET'])
@login_required
def download_pdf_report():
    # We use the fixed dir, ignoring the specific scan_id folder logic
    scan_dir = get_fixed_scan_dir()
    if not scan_dir: return jsonify({"status": "error"}), 404
    
    pdf_path = os.path.join(scan_dir, "reports", "killchain_report.pdf")

    if not os.path.exists(pdf_path):
        return jsonify({"status": "error", "message": "PDF report not found."}), 404

    return send_from_directory(
        directory=os.path.dirname(pdf_path),
        path=os.path.basename(pdf_path),
        as_attachment=True
    )


@killchain_bp.route('/get_json_report', methods=['GET'])
@login_required
def get_json_report():
    # We use the fixed dir, ignoring the specific scan_id folder logic
    scan_dir = get_fixed_scan_dir()
    if not scan_dir: return jsonify({"status": "error"}), 404
    
    json_path = os.path.join(scan_dir, "reports", "killchain_report.json")

    if not os.path.exists(json_path):
        return jsonify({"status": "error", "message": "JSON report not found."}), 404

    return send_from_directory(
        directory=os.path.dirname(json_path),
        path=os.path.basename(json_path),
        as_attachment=True,
        mimetype='application/json'
    )
    
@killchain_bp.route('/trigger_ai_analysis', methods=['POST'])
@login_required
def trigger_ai_analysis():
    """
    Checks if the scan report exists and signals the AI Chatbot to analyze it.
    """
    data = request.get_json()
    scan_id = data.get('scan_id')
    
    # We accept scan_id for validation, but the file is in the fixed location
    scan_dir = get_fixed_scan_dir()
    if not scan_dir:
        return jsonify({"status": "error", "message": "Invalid scan directory."}), 400

    json_report_path = os.path.join(scan_dir, "reports", "killchain_report.json")

    if not os.path.exists(json_report_path):
        return jsonify({
            "status": "error", 
            "message": "Report not found. Please wait for the scan to complete."
        }), 404

    return jsonify({
        "status": "success",
        "scanner_type": "killchain",
        "scan_id": scan_id 
    })
    
    
@killchain_bp.route('/history', methods=['GET'])
@login_required
def get_scan_history():
    """
    Returns the latest scan result from the fixed directory.
    Since we overwrite files, 'history' in terms of files is just the current state.
    """
    scan_dir = get_fixed_scan_dir()
    if not scan_dir or not os.path.exists(scan_dir):
        return jsonify({"status": "success", "scans": []})

    scans = []
    
    # Check for the single report file
    report_path = os.path.join(scan_dir, "reports", "killchain_report.json")
    
    if os.path.exists(report_path):
        try:
            with open(report_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # We can't know the original 'scan_id' from the file name anymore,
                # but we can deduce details from the JSON content.
                scans.append({
                    "scan_id": "latest", # Identifier for the frontend
                    "target": data.get("target", "Unknown"),
                    "date": data.get("scan_date", "Unknown"),
                    "timestamp": os.path.getmtime(report_path)
                })
        except Exception as e:
            print(f"[!] Error reading history: {e}")

    return jsonify({"status": "success", "scans": scans})

