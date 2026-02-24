import os
import threading
import queue
import time
import uuid
import re
import json
import logging
from pathlib import Path

# --- Logging Setup ---
from logger_setup import logger

from flask import Blueprint, render_template, jsonify, request, Response, send_from_directory, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
from extensions import db

# [SERVICE] Import the Singleton instance and helpers
from Services.killchain_service import killchain_service, cleanup_queue
# --- Import Scan Logger ---
from Services import scan_logger

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
    logger.info(f"[*] Accessing Kill Chain Audit Page (User: {current_user.username})")
    return render_template('scanners/killchain.html')


@killchain_bp.route('/dispatch', methods=['POST'])
@login_required
def dispatch_scan():
    """
    API endpoint to start the Kill Chain Audit.
    Generates a unique Scan ID for concurrency.
    """
    data = request.get_json()
    target = data.get('target', '').strip()
    logger.info(f"\033[35m[*] Kill Chain Audit requested for {target} by {current_user.username}\033[0m")
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

    # [NEW] Prevent Multiple Concurrent Scans for the same user
    # We use user_identifier for locking to match queue_id format
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    if killchain_service.is_user_scanning(user_identifier):
        logger.warning(f"[!] Kill Chain Audit already in progress for user {user_identifier}")
        return jsonify({
            "status": "error", 
            "message": "A Kill Chain audit is already in progress. Please wait for it to complete."
        }), 400

    # 1. Generate Unique Scan ID (UUID)
    # We still need this for the Queue ID and frontend tracking, 
    # even though files are stored in a fixed folder.
    scan_id = str(uuid.uuid4())[:8] 
    
    # 2. Setup Directories (FIXED PATH)
    scan_dir = get_fixed_scan_dir()
    os.makedirs(scan_dir, exist_ok=True)

    # 3. Create Unique Queue ID
    # Format: user_identifier::scan_id
    queue_id = f"{user_identifier}::{scan_id}"

    # 4. Update DB Stats
    try:
        current_user.scan_count_killchain += 1
        db.session.commit()
    except Exception as e:
        logger.error(f"[!] DB Error updating killchain stats: {e}")

    # [NEW] Reset Log File for this new scan session
    scan_logger.reset_log_file(user_identifier, "killchain")

    # 5. Log Scan Start (Database)
    log_id = scan_logger.log_scan_start(
        user_id=current_user.id,
        tool_name="Kill Chain",
        target=target,
        scan_type=f"{profile} ({aggression})"
    )

    # Capture App Object
    app = current_app._get_current_object()

    # [NEW] Sanitized target for filename
    sanitized_target = scan_logger.sanitize_filename(target)

    # 6. Launch Background Scan
    # We pass the FIXED scan_dir so the service writes to the same folder every time
    thread = threading.Thread(
        target=killchain_service.run_job,
        args=(target, profile, aggression, queue_id, scan_dir, log_id, app, sanitized_target), # Passed sanitized_target
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

    # Extract user_identifier from queue_id (format: user_identifier::scan_id)
    try:
        user_identifier = queue_id.split('::')[0]
    except:
        user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"

    return Response(
        scan_logger.tail_log_file(user_identifier, "killchain"),
        mimetype='text/event-stream'
    )


@killchain_bp.route('/report_files', methods=['GET'])
@login_required
def get_report_files():
    """
    Checks if reports exist in the FIXED directory. 
    """
    target = request.args.get('target')
    scan_dir = get_fixed_scan_dir()
    if not scan_dir or not os.path.exists(scan_dir):
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    reports_dir = os.path.join(scan_dir, "reports")
    
    if target:
        sanitized = scan_logger.sanitize_filename(target)
        json_filename = f"killchain_report_{sanitized}.json"
        pdf_filename = f"killchain_report_{sanitized}.pdf"
    else:
        json_filename = "killchain_report.json"
        pdf_filename = "killchain_report.pdf"

    json_path = os.path.join(reports_dir, json_filename)
    pdf_path = os.path.join(reports_dir, pdf_filename)

    json_exists = os.path.exists(json_path)
    pdf_exists = os.path.exists(pdf_path)

    if not json_exists and not pdf_exists:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    return jsonify({
        "status": "success",
        "json_report": f"/killchain/get_json_report?target={target}",
        "pdf_report": f"/killchain/download_pdf?target={target}"
    })


@killchain_bp.route('/download_pdf', methods=['GET'])
@login_required
def download_pdf_report():
    target = request.args.get('target')
    scan_dir = get_fixed_scan_dir()
    if not scan_dir: return jsonify({"status": "error"}), 404
    
    if target:
        sanitized = scan_logger.sanitize_filename(target)
        pdf_filename = f"killchain_report_{sanitized}.pdf"
    else:
        pdf_filename = "killchain_report.pdf"

    pdf_path = os.path.join(scan_dir, "reports", pdf_filename)

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
    target = request.args.get('target')
    scan_dir = get_fixed_scan_dir()
    if not scan_dir: return jsonify({"status": "error"}), 404
    
    if target:
        sanitized = scan_logger.sanitize_filename(target)
        json_filename = f"killchain_report_{sanitized}.json"
    else:
        json_filename = "killchain_report.json"

    json_path = os.path.join(scan_dir, "reports", json_filename)

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
    target = data.get('target')
    
    scan_dir = get_fixed_scan_dir()
    if not scan_dir:
        return jsonify({"status": "error", "message": "Invalid scan directory."}), 400

    if target:
        sanitized = scan_logger.sanitize_filename(target)
        json_filename = f"killchain_report_{sanitized}.json"
    else:
        json_filename = "killchain_report.json"

    json_report_path = os.path.join(scan_dir, "reports", json_filename)

    if not os.path.exists(json_report_path):
        return jsonify({
            "status": "error", 
            "message": "Report not found. Please wait for the scan to complete."
        }), 404

    return jsonify({
        "status": "success",
        "scanner_type": "killchain",
        "target": target
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
            logger.error(f"[!] Error reading history: {e}")

    return jsonify({"status": "success", "scans": scans})

@killchain_bp.route('/check_active_scan', methods=['GET'])
@login_required
def check_active_scan():
    """
    Checks if there's an active scan running for the current user's session.
    Prioritizes DB state (SSOT) over in-memory state.
    """
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    
    # 1. CHECK DB (Primary Source of Truth)
    active_log = scan_logger.get_active_scan_log(current_user.id, "Kill Chain")
    
    if active_log:
        return jsonify({
            "status": "active",
            "message": "Active scan found (DB)",
            "queue_id": f"{user_identifier}::latest", # Queue ID might change on refresh, but logging path is stable
            "scan_id": active_log.id,
            "target": active_log.target,
            "profile": active_log.scan_type,
            "start_time": active_log.start_time.isoformat()
        }), 200
    
    # 2. Fallback: Check Memory (Legacy support or race condition handling)
    active_scan_info = None
    from Services.killchain_service import active_scans 

    with threading.Lock(): 
        for queue_id, scan_info in active_scans.items():
            if queue_id.startswith(f"{user_identifier}::"):
                active_scan_info = scan_info
                # Also extract the scan_id from the queue_id
                parts = queue_id.split('::')
                if len(parts) > 1:
                    active_scan_info['scan_id'] = parts[1]
                else:
                    active_scan_info['scan_id'] = queue_id 
                active_scan_info['queue_id'] = queue_id 
                break

    if active_scan_info:
        # If found in memory but NOT in DB, it might be finishing up or DB write failed.
        # We'll trust memory in this edge case and return it.
        return jsonify({
            "status": "active",
            "message": "Active scan found (Memory)",
            "queue_id": active_scan_info['queue_id'],
            "scan_id": active_scan_info.get('scan_id'),
            "target": active_scan_info.get('target'),
            "profile": active_scan_info.get('profile'),
            "aggression": active_scan_info.get('aggression'),
            "start_time": active_scan_info.get('start_time') 
        }), 200

    return jsonify({"status": "inactive", "message": "No active scan found"}), 200


