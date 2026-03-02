from flask import Flask, render_template, jsonify, request, Response, send_from_directory, Blueprint, current_app
from flask_login import login_required, current_user
import threading
import json
import time
import os
import queue
import requests
import uuid 
from werkzeug.utils import secure_filename
import re
import logging

# [NEW] Import db to update user stats
from extensions import db

# --- Logging Setup ---
logger = logging.getLogger(__name__)

# Import the updated network_scanner module
from Services import network_scanner
# --- Import PDF Generator ---
from Services import pdf_generator
# --- Import Scan Logger ---
from Services import scan_logger
from Services import report_manager

network_scanner_bp = Blueprint('network_scanner_bp', __name__)

# --- PHASE 3: User-Specific Directory Helper ---
def get_user_results_dir():
    """
    Constructs the path: Services/results/<username_id>/network_scanner
    """
    if not current_user.is_authenticated:
        # Fallback for testing/unauthenticated (though routes are protected)
        return None
    
    # NEW LOGIC: Composite Identifier
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"

    # We navigate up from 'routes/' to root, then into Services/results
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    user_dir = os.path.join(base_dir, 'Services', 'results', user_identifier, 'network_scanner')
    
    # FIXED: Added exist_ok=True to prevent race condition crashes
    os.makedirs(user_dir, exist_ok=True)
        
    return user_dir

# ==========================================
# --- ⚙️ CONFIGURATION: PDF OUTPUT PATH ---
# ==========================================
# 1. To change the FOLDER, edit 'RESULTS_DIR' in 'Services/network_scanner.py'
# 2. To change the FILENAME, edit the variable below:
PDF_FILENAME = "network_scanner_report.pdf" 
PDF_REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'PDFs') 

# 🚨 NEW: Central server proxy URL (Must match the one in chatbot_bp.py)
SERVER_PROXY_URL = "http://localhost:5100" 
# ==========================================

def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    # Strip protocol for validation
    hostname = hostname.replace("https://", "").replace("http://", "").split('/')[0]
    if all(re.match(r"^[a-zA-Z0-9-]*$", part) for part in hostname.split(".")):
        return True
    return False

@network_scanner_bp.route('/')
@login_required
def network_scanner_page():
    """Renders the network scanner page."""
    logger.info(f"[*] Accessing Network Scanner Page (User: {current_user.username})")
    
    user_agent = request.headers.get('User-Agent')
    if user_agent and any(word in user_agent for word in ['Mobile', 'Android', 'iPhone', 'iPad']):
        return render_template('mobile_scanners/network_scanner.html')
        
    return render_template('scanners/network_scanner.html')

@network_scanner_bp.route('/init_data', methods=['GET'])
@login_required
def init_data():
    """Consolidated endpoint for initial page load data."""
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_dir = get_user_results_dir()

    # 1. Local IP
    local_ip = network_scanner.get_local_ip()

    # 2. Whitelisted Ports
    network_scanner.load_whitelist(output_dir=user_dir, user_id=user_identifier)
    whitelisted_ports = network_scanner.get_whitelisted_ports(user_id=user_identifier)

    # 3. Open Ports & Summary
    summary = network_scanner.get_scan_summary(user_identifier, output_dir=user_dir)
    # ... rest of function ...

    # 4. Report Files
    # Get user-specific paths using report_manager
    user_json_path = os.path.join(user_dir, report_manager.generate_report_filename("nmap_report", None, "json"))
    
    target = request.args.get('target')
    if target:
        filename = report_manager.generate_report_filename("network_scanner", target, "pdf")
        user_pdf_path = os.path.join(user_dir, filename)
    else:
        # Fallback to latest (Prefix-agnostic)
        history = report_manager.get_report_history(user_dir, scanner_name=None)
        if history:
            user_pdf_path = history[0]['path']
            filename = os.path.basename(user_pdf_path)
            target = history[0].get('target', target)
        else:
            user_pdf_path = os.path.join(user_dir, PDF_FILENAME)
            filename = PDF_FILENAME

    json_exists = os.path.exists(user_json_path)
    pdf_exists = os.path.exists(user_pdf_path)
    
    report_files = {
        "status": "success" if (json_exists or pdf_exists) else "pending",
        "json_report": "/network_scanner/get_json_report" if json_exists else None,
        "pdf_report": f"/network_scanner/download_pdf?filename={filename}" if pdf_exists else None
    }

    return jsonify({
        "local_ip": local_ip,
        "whitelisted_ports": whitelisted_ports,
        "summary": summary,
        "report_files": report_files
    })

@network_scanner_bp.route('/local_ip', methods=['GET'])
@login_required
def get_local_ip_route():
    """API endpoint to detect and return the local IP address."""
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    local_ip = network_scanner.get_local_ip()
    logger.info(f"\033[34m[*] Local IP Detection requested by {current_user.username}\033[0m")
    network_scanner.log(f"[*] Local IP requested: {local_ip}", user_identifier, queue_id=None, to_console=True)
    return jsonify({"local_ip": local_ip})

@network_scanner_bp.route('/scan', methods=['POST'])
@login_required
def scan_ports():
    """
    API endpoint to initiate all types of port scans.
    Runs the scan in a separate thread and generates a PDF report upon completion.
    """
    data = request.get_json()
    target_ip = data.get('target_ip')
    logger.info(f"\033[34m[*] Network Scan requested for {target_ip} by {current_user.username}\033[0m")
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    protocol_type = data.get('protocol_type', 'TCP').upper()
    scan_type = data.get('scan_type', 'default')
    
    # [NEW] Extract timing parameter (Default to 4 if not provided)
    try:
        timing = int(data.get('timing', 4))
    except ValueError:
        timing = 4

    # Validate scan type (Expanded List)
    valid_scan_types = [
        'default', 'os', 'fragmented', 'aggressive', 'tcp_syn', 'vuln', 'udp',
        'ping_sweep', 'tcp_connect', 'null', 'fin', 'xmas', 'ack', 'window', 'decoy'
    ]
    
    if scan_type not in valid_scan_types:
        return jsonify({"status": "error", "message": "Invalid scan type specified."}), 400

    # Validate timing
    if not (0 <= timing <= 5):
        return jsonify({"status": "error", "message": "Timing must be between 0 and 5."}), 400

    # If target_ip is empty, try to use local IP
    if not target_ip:
        target_ip = network_scanner.get_local_ip()
        if target_ip == "127.0.0.1" and not network_scanner.is_valid_ip_or_range(target_ip):
            network_scanner.log("[!] No target IP/range entered and local IP not detected.", user_identifier, queue_id=None)
            return jsonify({"status": "error", "message": "No target IP/range provided and local IP not detected."}), 400
        network_scanner.log(f"[*] Target IP/Range not specified, defaulting to local IP: {target_ip}", user_identifier, queue_id=None)

    # Updated to allow URLs/Domains as well as IPs
    if not network_scanner.is_valid_ip_or_range(target_ip) and not network_scanner.is_valid_hostname(target_ip):
        network_scanner.log(f"[!] Invalid target input: {target_ip}", user_identifier, queue_id=None)
        return jsonify({"status": "error", "message": "Please enter a valid IP address, Domain (URL), or IP range."}), 400
    
    if not network_scanner.is_nmap_installed():
        network_scanner.log("[!] Nmap is not installed or not in PATH.", user_identifier, queue_id=None)
        return jsonify({"status": "error", "message": "Nmap is not installed."}), 500
    
    # [NEW] Prevent Multiple Concurrent Scans for the same user
    if network_scanner.is_scan_running(user_identifier):
        logger.warning(f"[!] Network Scan already in progress for user {user_identifier}")
        return jsonify({
            "status": "error", 
            "message": "A network scan is already in progress. Please wait for it to complete."
        }), 400

    # Determine User Directory for this scan
    user_output_dir = get_user_results_dir()

    # Generate a unique ID for this scan request
    queue_id = str(uuid.uuid4())

    # --- Capture Context for Thread ---
    app = current_app._get_current_object()
    user_id_for_log = current_user.id

    # [RC-8 FIX] Atomic DB counter increment — prevents double-count on concurrent tabs
    try:
        from sqlalchemy import update as _sa_update
        from models import User as _User
        db.session.execute(
            _sa_update(_User).where(_User.id == current_user.id)
            .values(scan_count_nmap=_User.scan_count_nmap + 1)
        )
        db.session.commit()
    except Exception as e:
        db.session.rollback()  # RC-3 FIX: clean session before thread starts
        network_scanner.log(f"[!] Failed to update user stats: {e}", user_identifier, queue_id)
    
    # [NEW] Reset Log File for this new scan session
    scan_logger.reset_log_file(user_identifier, "network_scanner")

    # --- Threaded Scan Task ---
    def scan_task(queue_id): # queue_id is now a parameter
        # Use DB Logging
        with app.app_context():
            # [NEW] Log Start in DB
            log_id = scan_logger.log_scan_start(
                user_id=user_id_for_log,
                tool_name="Nmap",
                target=target_ip,
                scan_type=scan_type
            )

        # Use the captured identifier variable
        network_scanner.log(f"[*] Preparing {scan_type.upper()} scan for target: {target_ip} with T{timing}...", user_identifier, queue_id, to_console=True)        
        
        start_time = time.time()
        
        # 1. Run the Scan (Pass user directory to service)
        result_file = network_scanner.run_nmap_scan(
            target_ip, 
            protocol_type=protocol_type, 
            scan_type=scan_type,
            output_dir=user_output_dir,  # <--- DYNAMIC PATH PASSED HERE
            user_id=user_identifier,     # <--- PASS USER ID HERE
            timing=timing, # <--- PASS TIMING HERE
            queue_id=queue_id # <--- NEW: Pass queue_id
        )
        
        duration = time.time() - start_time
        
        # Determine status and count
        status = "Completed" if result_file else "Failed"
        if result_file:
             finding_count = len(network_scanner.get_current_open_ports(user_identifier)) 
        else:
             finding_count = 0

        # Log to Database (Inside App Context)
        with app.app_context():
            # [FIXED] Pass correct error message if failed
            error_msg = None if result_file else "Scan failed to produce output file."
            scan_logger.log_scan_end(log_id, status=status, finding_count=finding_count, duration=duration, error_msg=error_msg)
        
        if result_file:
            # Define specific paths for this user's PDF generation
            user_paths = network_scanner.get_output_paths(user_output_dir, target=target_ip)
            user_json_path = user_paths["json_report"]
            user_pdf_path = user_paths["pdf_report"]

            # 2. Generate PDF Report
            try:
                if os.path.exists(user_json_path):
                    network_scanner.log(f"[*] Scan complete. Generating PDF report for {target_ip}...", user_identifier, queue_id, to_console=True)
                    
                    # Ensure PDF output directory exists (needed by WeasyPrint)
                    os.makedirs(os.path.dirname(user_pdf_path), exist_ok=True)
                    
                    # Call the generator with the file path
                    pdf_generator.create_nmap_report_pdf(str(user_json_path), str(user_pdf_path))
                    
                    if os.path.exists(user_pdf_path):
                        # Final synchronization wait to ensure file handles are closed
                        time.sleep(1.5) 
                        network_scanner.log(f"[+] PDF report generated successfully", user_identifier, queue_id, to_console=True)
                        network_scanner.log(f"SYSTEM_EVENT: READY_FOR_ANALYSIS:{target_ip}", user_identifier, queue_id, to_console=True)
                    else:
                        network_scanner.log("[!] PDF generation ran but file not found (unknown error).", user_identifier, queue_id, to_console=True)
                else:
                    network_scanner.log("[!] JSON report not found. Cannot generate PDF.", user_identifier, queue_id, to_console=True)
            
            except ImportError:
                network_scanner.log("[!] Error: GTK3 Runtime missing or WeasyPrint not installed properly.", user_identifier, queue_id)
            except Exception as e:
                # This captures WeasyPrint errors and sends them to the UI Log
                network_scanner.log(f"[!] FAILED to generate PDF: {str(e)}", user_identifier, queue_id)
        else:
            network_scanner.log("[!] Scan failed to produce a result file.", user_identifier, queue_id)

    threading.Thread(target=scan_task, args=(queue_id,), daemon=True).start()  # RC-5 FIX: daemon=True prevents process hang on shutdown
    return jsonify({"status": "success", "message": f"{scan_type.upper()} scan for {target_ip} initiated.", "queue_id": queue_id})


@network_scanner_bp.route('/check_active_scan', methods=['GET'])
@login_required
def check_active_scan():
    """
    Checks if there's an active scan running for the current user's session.
    Prioritizes DB state (SSOT).
    """
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    
    # 1. CHECK DB (Primary Source of Truth)
    active_log = scan_logger.get_active_scan_log(current_user.id, "Nmap")
    
    if active_log:
        return jsonify({
            "status": "active",
            "message": "Active scan found (DB)",
            "queue_id": f"{user_identifier}::latest",
            "scan_id": active_log.id,
            "target": active_log.target,
            "profile": active_log.scan_type,
            "start_time": active_log.start_time.isoformat()
        }), 200
    
    # 2. Fallback: Check in-memory state
    if network_scanner.is_scan_running(user_identifier):
        return jsonify({
            "status": "active", 
            "message": "Active scan found (Memory)",
            "queue_id": f"{user_identifier}::latest" # Placeholder
        }), 200
        
    return jsonify({"status": "inactive", "message": "No active scan found"}), 200


@network_scanner_bp.route('/report_history', methods=['GET'])
@login_required
def get_report_history():
    """Returns the history of network scan reports (Prefix-agnostic)."""
    user_dir = get_user_results_dir()
    history = report_manager.get_report_history(user_dir, scanner_name=None)
    return jsonify({"status": "success", "history": history})

@network_scanner_bp.route('/trigger_ai_analysis', methods=['POST'])
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
        paths = network_scanner.get_output_paths(user_dir, target=target)
        pdf_path = Path(paths["pdf_report"])
    
    # Fallback 1: History search (Recent for this scanner)
    if not pdf_path or not pdf_path.exists():
        history = report_manager.get_report_history(user_dir, scanner_name="network_scanner", extension="pdf")
        if history:
            pdf_path = Path(history[0]['path'])
    
    # Fallback 2: Any PDF in the results directory
    if not pdf_path or not pdf_path.exists():
        history = report_manager.get_report_history(user_dir, scanner_name=None, extension="pdf")
        if history:
            pdf_path = Path(history[0]['path'])

    if not pdf_path or not pdf_path.exists():
        network_scanner.log(f"[!] Analysis failed: PDF report not found in {user_dir}", user_identifier)
        return jsonify({
            "status": "error", 
            "message": "PDF report not available. Please run a scan first."
        }), 404

    return jsonify({
        "status": "success",
        "scanner_type": "nmap",
        "target": target
    })

@network_scanner_bp.route('/report_files', methods=['GET'])
@login_required
def get_report_files():
    """Checks availability of reports."""
    target = request.args.get('target')
    user_dir = get_user_results_dir()
    user_json_path = os.path.join(user_dir, report_manager.generate_report_filename("network_scanner", target, "json"))
    
    if target:
        pdf_filename = report_manager.generate_report_filename("network_scanner", target, "pdf")
    else:
        pdf_filename = report_manager.generate_report_filename("network_scanner", None, "pdf")

    user_pdf_path = os.path.join(user_dir, pdf_filename)

    json_exists = os.path.exists(user_json_path)
    pdf_exists = os.path.exists(user_pdf_path)

    if not json_exists and not pdf_exists:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    return jsonify({
        "status": "success",
        "json_report": "/network_scanner/get_json_report" + (f"?target={target}" if target else ""),
        "pdf_report": f"/network_scanner/download_pdf?target={target}" if target else "/network_scanner/download_pdf"
    })

@network_scanner_bp.route('/download_pdf', methods=['GET'])
@login_required
def download_pdf_report():
    """Serves the PDF report dynamically based on the configured path."""
    user_dir = get_user_results_dir()
    requested_filename = request.args.get('filename')
    target = request.args.get('target')
    
    if requested_filename:
        filename = secure_filename(requested_filename)
        pdf_path = os.path.join(user_dir, filename)
    elif target:
        filename = report_manager.generate_report_filename("network_scanner", target, "pdf")
        pdf_path = os.path.join(user_dir, filename)
    else:
        history = report_manager.get_report_history(user_dir, scanner_name=None)
        if not history:
             return jsonify({"status": "error", "message": "No reports found."}), 404
        pdf_path = history[0]['path']
        filename = os.path.basename(pdf_path)

    if not os.path.exists(pdf_path):
        return jsonify({"status": "error", "message": "PDF report file not found."}), 404
    
    return send_from_directory(
        directory=os.path.dirname(pdf_path),
        path=filename,
        as_attachment=True
    )

@network_scanner_bp.route('/get_json_report', methods=['GET'])
@login_required
def get_json_report_file():
    user_dir = get_user_results_dir()
    target = request.args.get('target')
    user_json_path = os.path.join(user_dir, report_manager.generate_report_filename("network_scanner", target, "json"))

    if not os.path.exists(user_json_path):
        return jsonify({"status": "error", "message": "JSON report file not found."}), 404
    
    # Use dynamic pathing for JSON as well for consistency
    directory = os.path.dirname(user_json_path)
    filename = os.path.basename(user_json_path)

    return send_from_directory(
        directory=directory,
        path=filename,
        as_attachment=True
    )

# --- Standard Scan Routes (Unchanged) ---
@network_scanner_bp.route('/open_ports', methods=['GET'])
@login_required
def get_open_ports_route():
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_dir = get_user_results_dir()
    summary = network_scanner.get_scan_summary(user_identifier, output_dir=user_dir)
    return jsonify(summary)

@network_scanner_bp.route('/block_ports', methods=['POST'])
@login_required
def block_ports_route():
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    if not network_scanner.is_admin():
        network_scanner.log("[!] Insufficient privileges to block ports.", user_identifier, queue_id=None)
        return jsonify({"status": "error", "message": "Insufficient privileges."}), 403

    def block_task():
        user_data = network_scanner.get_user_open_ports(user_identifier)
        all_ports = user_data["TCP"] + user_data["UDP"]
        if not all_ports:
            network_scanner.log("[*] No open ports detected to block.", user_identifier, queue_id=None)
            return

        network_scanner.log(f"[*] Attempting to block {len(all_ports)} detected ports...", user_identifier, queue_id=None)
        whitelisted = network_scanner.get_user_whitelisted_ports(user_identifier)
        for p_info in all_ports:
            port_str = str(p_info['port'])
            protocol = p_info['protocol']
            if port_str in whitelisted:
                network_scanner.log(f"[~] Skipping whitelisted {protocol} port {port_str}.", user_identifier, queue_id=None)
                continue
            
            success = network_scanner.block_port(port_str, protocol=protocol, user_id=user_identifier)
            if success and network_scanner.is_port_blocked(port_str, protocol=protocol):
                network_scanner.log(f"[✓] {protocol} Port {port_str} blocked.", user_identifier, queue_id=None)
            else:
                network_scanner.log(f"[x] {protocol} Port {port_str} failed to verify as blocked.", user_identifier, queue_id=None)
        network_scanner.log("[+] Port blocking process completed.", user_identifier, queue_id=None)

    threading.Thread(target=block_task).start()
    return jsonify({"status": "success", "message": "Port blocking initiated."})

@network_scanner_bp.route('/verify_ports', methods=['POST'])
@login_required
def verify_ports_route():
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    data = request.get_json()
    target_ip = data.get('target_ip')
    if not target_ip:
         return jsonify({"status": "error", "message": "No target IP provided."}), 400

    def verify_task():
        network_scanner.verify_ports_closed(target_ip, user_id=user_identifier)
        network_scanner.log("[+] Port verification process completed.", user_identifier, queue_id=None)

    threading.Thread(target=verify_task).start()
    return jsonify({"status": "success", "message": "Port verification initiated."})

@network_scanner_bp.route('/add_whitelist', methods=['POST'])
@login_required
def add_whitelist_route():
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    data = request.get_json()
    user_dir = get_user_results_dir()
    if network_scanner.add_to_whitelist(data.get('ports'), output_dir=user_dir, user_id=user_identifier):
        return jsonify({"status": "success", "message": "Ports added to whitelist."})
    return jsonify({"status": "error", "message": "Failed to add ports."}), 400

@network_scanner_bp.route('/clear_whitelist', methods=['POST'])
@login_required
def clear_whitelist_route():
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_dir = get_user_results_dir()
    network_scanner.clear_whitelist(output_dir=user_dir, user_id=user_identifier)
    return jsonify({"status": "success", "message": "Whitelist cleared."})

@network_scanner_bp.route('/whitelisted_ports', methods=['GET'])
@login_required
def get_whitelisted_ports_route():
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    # Load user-specific whitelist before returning
    user_dir = get_user_results_dir()
    network_scanner.load_whitelist(output_dir=user_dir, user_id=user_identifier)
    return jsonify({"whitelisted_ports": network_scanner.get_whitelisted_ports(user_id=user_identifier)})

@network_scanner_bp.route('/get_scan_results', methods=['GET'])
@login_required
def get_scan_results():
    scan_type = request.args.get('type', 'tcp')
    
    # Map scan types to file names expected in the user dir
    # [NEW] Updated map to include all new scan types
    filename_map = {
        'tcp': "scan_result_tcp.txt",
        'udp': "scan_result_udp.txt",
        'tcp_syn': "scan_result_tcp_syn.txt",
        'os': "scan_result_os.txt",
        'fragmented': "scan_result_fragmented.txt",
        'aggressive': "scan_result_aggressive.txt",
        'ping_sweep': "scan_result_ping.txt",
        'tcp_connect': "scan_result_connect.txt",
        'null': "scan_result_null.txt",
        'fin': "scan_result_fin.txt",
        'xmas': "scan_result_xmas.txt",
        'ack': "scan_result_ack.txt",
        'window': "scan_result_window.txt",
        'decoy': "scan_result_decoy.txt"
    }
    
    filename = filename_map.get(scan_type)
    if not filename:
        return jsonify({"status": "error", "message": f"Unknown scan type: {scan_type}"}), 404

    user_dir = get_user_results_dir()
    file_path = os.path.join(user_dir, filename)
    
    if not os.path.exists(file_path):
        return jsonify({"status": "error", "message": f"No results for {scan_type}."}), 404
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return jsonify({"status": "success", "content": f.read(), "scan_type": scan_type})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@network_scanner_bp.route('/clear_log', methods=['POST'])
@login_required
def clear_log_route():
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    network_scanner.clear_log_file(user_identifier)
    return jsonify({"status": "success", "message": "Log cleared."})

@network_scanner_bp.route('/log_stream')
@login_required
def log_stream():
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    return Response(
        scan_logger.tail_log_file(user_identifier, "network_scanner"),
        mimetype='text/event-stream'
    )