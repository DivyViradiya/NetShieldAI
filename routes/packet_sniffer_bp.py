from flask import (
    Blueprint, Flask, render_template, jsonify, request,
    Response, send_from_directory, current_app
)
from flask_login import login_required, current_user
import threading
import json
import time
import os
import queue as _queue_module
import uuid
import re
from pathlib import Path
import logging
from werkzeug.utils import secure_filename 

# --- Logging Setup ---
logger = logging.getLogger(__name__)

# [NEW] Import db to update user stats
from extensions import db

# Import the packet_sniffer module
from Services import packet_sniffer
# Import PDF Generator
from Services import pdf_generator
# --- Import Scan Logger ---
from Services import scan_logger
from Services import report_manager

packet_sniffer_bp = Blueprint('packet_sniffer_bp', __name__)

# --- PHASE 3: User-Specific Directory Helper ---
def get_user_results_dir():
    """
    Constructs the path: Services/results/<username_id>/packet_sniffer
    """
    if not current_user.is_authenticated:
        return None
    
    # NEW LOGIC: Composite Identifier
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    user_dir = os.path.join(base_dir, 'Services', 'results', user_identifier, 'packet_sniffer')
    
    # FIXED: Added exist_ok=True to prevent race condition crashes
    os.makedirs(user_dir, exist_ok=True)
        
    return user_dir

# ==========================================
# --- ⚙️ CONFIGURATION (Default references)
# ==========================================
SERVER_PROXY_URL = "http://localhost:5100"
# ==========================================


@packet_sniffer_bp.route('/')
@login_required
def packet_sniffer_page():
    """Renders the packet sniffer page."""
    logger.info(f"[*] Accessing Network Monitor Page (User: {current_user.username})")
    
    user_agent = request.headers.get('User-Agent')
    if user_agent and any(word in user_agent for word in ['Mobile', 'Android', 'iPhone', 'iPad']):
        return render_template('mobile_scanners/packet_sniffer.html')
        
    return render_template('scanners/packet_sniffer.html')


# --- Interface Listing ---
@packet_sniffer_bp.route('/get_interfaces', methods=['GET'])
@login_required
def get_interfaces_route():
    """API endpoint to list available network interfaces using tshark -D."""
    if not packet_sniffer.get_packet_capture_cmd():
        return jsonify({"status": "error", "message": "TShark (Wireshark) not found."}), 500

    interfaces = packet_sniffer.list_available_interfaces()
    interface_list_output = list(interfaces.values())
    return jsonify({"status": "success", "interfaces": interface_list_output})


@packet_sniffer_bp.route('/start_capture', methods=['POST'])
@login_required
def start_capture_route():
    """
    API endpoint to initiate packet capture and analysis.
    """
    # Define user_identifier early for logging
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"

    data = request.get_json(force=True, silent=True) or {}
    target_ip = data.get('target_ip')
    logger.info(f"[*] Packet Capture requested for {target_ip} by {current_user.username}")
    duration = int(data.get('duration', 30))
    max_packets = int(data.get('max_packets', 50))

    interface_id = data.get('interface_id')
    custom_bpf_filter = data.get('custom_bpf_filter')
    if custom_bpf_filter == "":
        custom_bpf_filter = None

    if not target_ip:
        packet_sniffer.log("[!] No target IP provided for capture filter.", user_identifier)
        return jsonify({"status": "error", "message": "No target IP provided."}), 400

    # Check admin privileges (Warning only, as Npcap can be configured for non-admins)
    if not packet_sniffer.is_admin():
        packet_sniffer.log("[!] Warning: Sniffing typically requires administrator/root privileges. Proceeding anyway...", user_identifier)

    if not packet_sniffer.get_packet_capture_cmd():
        return jsonify({"status": "error", "message": "TShark (Wireshark) not found."}), 500

    # [NEW] Prevent Multiple Concurrent Captures for the same user
    if packet_sniffer.is_scan_running(user_identifier):
        logger.warning(f"[!] Packet Capture already in progress for user {user_identifier}")
        return jsonify({
            "status": "error", 
            "message": "A packet capture is already in progress. Please wait for it to complete or stop it before starting a new one."
        }), 400

    if interface_id is not None:
        interface_id = str(interface_id)

    # Determine User Directory for this capture
    user_output_dir = get_user_results_dir()

    # --- Capture Context for Thread ---
    app = current_app._get_current_object()
    user_id_for_log = current_user.id

    # [NEW] Increment Database Counter for Stats
    try:
        from models import User as _User
        db.session.execute(
            db.update(_User).where(_User.id == current_user.id)
            .values(scan_count_sniffer=_User.scan_count_sniffer + 1)
        )
        db.session.commit()
    except Exception as e:
        packet_sniffer.log(f"[!] Failed to update user stats: {e}", user_identifier)

    # [NEW] Reset Log File for this new scan session
    scan_logger.reset_log_file(user_identifier, "packet_sniffer")

    # Function to run in a separate thread
    def scan_task(interface_id_local, custom_bpf_filter_local):
        # Use DB Logging
        with app.app_context():
            log_id = scan_logger.log_scan_start(
                user_id=user_id_for_log,
                tool_name="Sniffer",
                target=target_ip,
                scan_type="Capture"
            )

        # Use the captured 'user_identifier' here
        packet_sniffer.log(f"[*] Starting capture for {target_ip} ({duration}s) User: {user_identifier}...", user_identifier, to_console=True)
        
        start_time = time.time()

        pcap_file = packet_sniffer.run_packet_capture(
            target_ip,
            duration,
            interface_id=interface_id_local,
            custom_bpf_filter=custom_bpf_filter_local,
            output_dir=user_output_dir,
            user_id=user_identifier
        )
        
        status = "Failed"
        finding_count = 0
        actual_duration = time.time() - start_time

        if not pcap_file:
            packet_sniffer.log("[!] Packet capture failed.", user_identifier, to_console=True)
            packet_sniffer.send_sse_event("analysis_complete", {"target_ip": target_ip, "status": "capture_failed"}, user_id=user_identifier)
            
            # Log failure (Inside App Context)
            with app.app_context():
                scan_logger.log_scan_end(log_id, status="Failed", duration=actual_duration, finding_count=0, error_msg="Packet capture failed.")
            return

        packet_sniffer.log("[*] Capture complete. Starting JSON analysis...", user_identifier, to_console=True)

        # Analyze
        analysis_data = packet_sniffer.analyze_pcap_to_json(
            pcap_file,
            target_ip,
            max_packets=max_packets,
            user_id=user_identifier
        )

        # Enrich and Save
        if analysis_data.get('status') == 'success':
            status = "Completed"
            # Count "findings" as total conversations detected
            finding_count = len(analysis_data.get('conversations', []))
            
            # Enrich
            structured_context = packet_sniffer.build_pdf_report_context(analysis_data)
            analysis_data["structured_context"] = {k: v for k, v in structured_context.items() if k != 'raw'}
            analysis_data["extracted_features"] = structured_context.get("features", [])

            # Save JSON report to user directory
            json_path = packet_sniffer.save_json_report(analysis_data, output_dir=user_output_dir, user_id=user_identifier, target=target_ip)
            
            # Generate PDF report in user directory
            if json_path:
                try:
                    # Get user-specific PDF path
                    user_paths = packet_sniffer.get_output_paths(user_output_dir, target=target_ip)
                    pdf_path = user_paths["pdf_report"]

                    # Ensure output directory exists
                    os.makedirs(os.path.dirname(pdf_path), exist_ok=True)

                    # Create PDF using pdf_generator
                    pdf_generator.create_packet_sniffer_report_pdf(analysis_data, str(pdf_path))

                    if os.path.exists(pdf_path):
                        # Final synchronization wait
                        time.sleep(1.5)
                        packet_sniffer.log(f"[+] PDF report generated successfully", user_identifier, to_console=True)
                        packet_sniffer.log(f"SYSTEM_EVENT: READY_FOR_ANALYSIS:{target_ip}", user_identifier, to_console=True)
                    else:
                        packet_sniffer.log("[!] PDF generation ran but file not found.", user_identifier, to_console=True)

                except ImportError:
                    packet_sniffer.log("[!] Error: PDF generator dependencies missing.", user_identifier, to_console=True)
                except Exception as e:
                    packet_sniffer.log(f"[!] FAILED to generate PDF: {str(e)}", user_identifier, to_console=True)

        else:
            packet_sniffer.log(f"[!] JSON Analysis failed: {analysis_data.get('message', 'Unknown error')}", user_identifier, to_console=True)
            packet_sniffer.send_sse_event("analysis_complete", {"target_ip": target_ip, "status": "analysis_failed"}, user_id=user_identifier)
            
            # Log failure (Analysis phase - Inside App Context)
            with app.app_context():
                scan_logger.log_scan_end(log_id, status="Analysis Failed", duration=actual_duration, finding_count=0, error_msg="JSON Analysis failed.")
            return

        # Log Success (Inside App Context)
        with app.app_context():
             scan_logger.log_scan_end(log_id, status=status, duration=actual_duration, finding_count=finding_count)

        packet_sniffer.send_sse_event("analysis_complete", {"target_ip": target_ip, "status": "success"}, user_id=user_identifier)


    # Launch the background thread
    threading.Thread(
        target=scan_task,
        args=(interface_id, custom_bpf_filter),
        daemon=True
    ).start()

    return jsonify({"status": "success", "message": f"Packet capture for {target_ip} initiated."})

@packet_sniffer_bp.route('/check_active_scan', methods=['GET'])
@login_required
def check_active_scan():
    """
    Checks if there's an active packet capture running for the current user's session.
    Prioritizes DB state (SSOT).
    """
    # 1. CHECK DB (Primary Source of Truth)
    active_log = scan_logger.get_active_scan_log(current_user.id, "Sniffer")
    
    if active_log:
        return jsonify({
            "status": "active",
            "message": "Active capture found (DB)",
            "target": active_log.target,
            "scan_id": active_log.id
        }), 200

    # 2. Fallback: Check Memory
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    if packet_sniffer.is_scan_running(user_identifier):
         return jsonify({
            "status": "active",
            "message": "Active capture found (Memory)"
        }), 200

    return jsonify({"status": "inactive", "message": "No active capture found"}), 200


@packet_sniffer_bp.route('/report_history', methods=['GET'])
@login_required
def get_sniffer_report_history():
    user_dir = get_user_results_dir()
    history = report_manager.get_report_history(user_dir, scanner_name="pcap_analysis_report")
    return jsonify({"status": "success", "history": history})


@packet_sniffer_bp.route('/stop_capture', methods=['POST'])
@login_required
def stop_capture_route():
    """API endpoint to stop the running capture process."""
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    if packet_sniffer.stop_capture(user_id=user_identifier):
        packet_sniffer.log("[*] Stop capture triggered by user.", user_identifier)
        return jsonify({"status": "success", "message": "Capture stop signal sent."})
    return jsonify({"status": "error", "message": "No active capture to stop."}), 404


@packet_sniffer_bp.route('/trigger_ai_analysis', methods=['POST'])
@login_required
def trigger_ai_analysis_route():
    """Robustly triggers AI analysis by finding the correct PDF report."""
    data = request.get_json() or {}
    target = data.get('target')
    # Normalize target
    if not target or target.lower() == 'none' or target == 'null':
        target = None
        
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_dir = get_user_results_dir()
    
    # 1. Resolve PDF Path with Fallbacks
    from pathlib import Path
    pdf_path = None
    
    if target:
        paths = packet_sniffer.get_output_paths(user_dir, target=target)
        pdf_path = Path(paths["pdf_report"])
    
    # Fallback 1: History search (Recent for this scanner)
    if not pdf_path or not pdf_path.exists():
        history = report_manager.get_report_history(user_dir, scanner_name="pcap_analysis_report", extension="pdf")
        if history:
            pdf_path = Path(history[0]['path'])
    
    # Fallback 2: Any PDF in the results directory
    if not pdf_path or not pdf_path.exists():
        history = report_manager.get_report_history(user_dir, scanner_name=None, extension="pdf")
        if history:
            pdf_path = Path(history[0]['path'])

    if not pdf_path or not pdf_path.exists():
        packet_sniffer.log(f"[!] Analysis failed: PDF report not found in {user_dir}", user_identifier)
        return jsonify({
            "status": "error", 
            "message": "PDF report not available. Please run a scan first."
        }), 404

    return jsonify({
        "status": "success",
        "scanner_type": "packet_sniffer",
        "target": target
    })


@packet_sniffer_bp.route('/report_files', methods=['GET'])
@login_required
def get_report_files():
    """Checks availability of reports in user directory."""
    target = request.args.get('target')
    user_dir = get_user_results_dir()
    if target:
        paths = packet_sniffer.get_output_paths(user_dir, target=target)
        json_exists = paths["json_report"].exists()
        pdf_exists = paths["pdf_report"].exists()
        pdf_url = f"/packet_sniffer/download_pdf?target={target}" if pdf_exists else None
        json_url = f"/packet_sniffer/get_json_report?target={target}" if json_exists else None
    else:
        pdf_history = report_manager.get_report_history(user_dir, scanner_name="pcap_analysis_report", extension="pdf")
        json_history = report_manager.get_report_history(user_dir, scanner_name="pcap_analysis_report", extension="json")

        if pdf_history:
            pdf_exists = True
            pdf_filename = pdf_history[0]['filename']
            pdf_url = f"/packet_sniffer/download_pdf?filename={pdf_filename}"
        else:
            pdf_exists = False
            pdf_url = None

        if json_history:
            json_exists = True
            json_filename = json_history[0]['filename']
            json_url = f"/packet_sniffer/get_json_report?filename={json_filename}"
        else:
            json_exists = False
            json_url = None

    if not json_exists and not pdf_exists:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    return jsonify({
        "status": "success",
        "json_report": json_url,
        "pdf_report": pdf_url
    })


@packet_sniffer_bp.route('/download_pdf', methods=['GET'])
@login_required
def download_pdf_report():
    """Serves the PDF report dynamically from user directory."""
    user_dir = get_user_results_dir()
    requested_filename = request.args.get('filename')
    target = request.args.get('target')
    
    if requested_filename:
        filename = secure_filename(requested_filename)
        pdf_path = os.path.join(user_dir, filename)
    elif target:
        filename = report_manager.generate_report_filename("pcap_analysis_report", target, "pdf")
        pdf_path = os.path.join(user_dir, filename)
    else:
        history = report_manager.get_report_history(user_dir, scanner_name="pcap_analysis_report")
        if not history:
             return jsonify({"status": "error", "message": "No reports found."}), 404
        pdf_path = history[0]['path']
        filename = os.path.basename(pdf_path)

    if not os.path.exists(pdf_path):
        return jsonify({"status": "error", "message": "PDF report file not found."}), 404

    try:
        return send_from_directory(os.path.dirname(pdf_path), filename, as_attachment=True, mimetype='application/pdf')
    except Exception as e:
        packet_sniffer.log(f"[!] Error serving PDF file: {e}", user_identifier)
        return jsonify({"status": "error", "message": "Could not serve PDF file."}), 500


@packet_sniffer_bp.route('/get_json_report', methods=['GET'])
@login_required
def get_json_report_file():
    """Serves the JSON analysis report file from user directory."""
    requested_filename = request.args.get('filename')
    target = request.args.get('target')
    user_dir = get_user_results_dir()

    if requested_filename:
        filename = secure_filename(requested_filename)
        json_path = os.path.join(user_dir, filename)
    elif target:
        filename = report_manager.generate_report_filename("pcap_analysis_report", target, "json")
        json_path = os.path.join(user_dir, filename)
    else:
        # Check history endpoint to resolve
        history = report_manager.get_report_history(user_dir, scanner_name="pcap_analysis_report", extension="json")
        if not history:
            return jsonify({"status": "error", "message": "No reports found."}), 404
        # Extract the correct string from the dict
        filename = history[0]['filename']
        json_path = os.path.join(user_dir, filename)

    if not os.path.exists(json_path):
        return jsonify({"status": "error", "message": "JSON report file not found."}), 404

    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        return jsonify({"status": "success", "report": report_data})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to parse report: {e}"}), 500


@packet_sniffer_bp.route('/clear_log', methods=['POST'])
@login_required
def clear_log_route():
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    packet_sniffer.clear_log_file(user_identifier)
    return jsonify({"status": "success", "message": "Log cleared."})


@packet_sniffer_bp.route('/log_stream')
@login_required
def log_stream():
    """Streams logs from the packet_sniffer queue to the frontend (SSE)."""
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    
    # Ensure log file exists before tailing
    log_file_path = scan_logger.get_active_log_file(user_identifier, "packet_sniffer")
    if not os.path.exists(log_file_path):
        os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
        with open(log_file_path, 'w', encoding='utf-8') as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Log stream opened.\n")
            
    return Response(
        scan_logger.tail_log_file(user_identifier, "packet_sniffer"),
        mimetype='text/event-stream'
    )