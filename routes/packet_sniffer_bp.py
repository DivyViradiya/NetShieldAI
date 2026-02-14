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
from werkzeug.utils import secure_filename 

# [NEW] Import db to update user stats
from extensions import db

# Import the packet_sniffer module
from Services import packet_sniffer
# Import PDF Generator
from Services import pdf_generator
# --- Import Scan Logger ---
from Services import scan_logger

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
    data = request.get_json(force=True, silent=True) or {}
    target_ip = data.get('target_ip')
    duration = int(data.get('duration', 30))
    max_packets = int(data.get('max_packets', 50))

    interface_id = data.get('interface_id')
    custom_bpf_filter = data.get('custom_bpf_filter')
    if custom_bpf_filter == "":
        custom_bpf_filter = None

    if not target_ip:
        packet_sniffer.log("[!] No target IP provided for capture filter.", user_identifier)
        return jsonify({"status": "error", "message": "No target IP provided."}), 400

    # Check admin privileges.
    if not packet_sniffer.is_admin():
        packet_sniffer.log("[!] Sniffing requires administrator/root privileges. Server is not elevated.", user_identifier)
        return jsonify({
            "status": "error",
            "message": "Server process lacks administrator/root privileges. Restart the Flask server as admin/root and retry."
        }), 403

    if not packet_sniffer.get_packet_capture_cmd():
        return jsonify({"status": "error", "message": "TShark (Wireshark) not found."}), 500

    if interface_id is not None:
        interface_id = str(interface_id)

    # Determine User Directory for this capture
    user_output_dir = get_user_results_dir()

    # --- Capture Context for Thread ---
    app = current_app._get_current_object()
    current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_id_for_log = current_user.id

    # [NEW] Increment Database Counter for Stats
    try:
        current_user.scan_count_sniffer += 1
        db.session.commit()
    except Exception as e:
        packet_sniffer.log(f"[!] Failed to update user stats: {e}", current_user_identifier)

    def scan_task(interface_id_local, custom_bpf_filter_local):
        # Use the captured 'current_user_identifier' here
        packet_sniffer.log(f"[*] Starting capture for {target_ip} ({duration}s) User: {current_user_identifier}...", current_user_identifier)
        
        start_time = time.time()

        # Pass user_output_dir to run_packet_capture
        pcap_file = packet_sniffer.run_packet_capture(
            target_ip,
            duration,
            interface_id=interface_id_local,
            custom_bpf_filter=custom_bpf_filter_local,
            output_dir=user_output_dir
        )
        
        status = "Failed"
        finding_count = 0
        actual_duration = time.time() - start_time

        if not pcap_file:
            packet_sniffer.log("[!] Packet capture failed.", current_user_identifier)
            packet_sniffer.send_sse_event("analysis_complete", {"target_ip": target_ip, "status": "capture_failed"})
            
            # Log failure (Inside App Context)
            with app.app_context():
                scan_logger.create_full_scan_log(
                    user_id=user_id_for_log,
                    tool_name="Sniffer",
                    target=target_ip,
                    duration=actual_duration,
                    finding_count=0,
                    status="Failed",
                    scan_type="Capture"
                )
            return

        packet_sniffer.log("[*] Capture complete. Starting JSON analysis...", current_user_identifier)

        # Analyze
        analysis_data = packet_sniffer.analyze_pcap_to_json(
            pcap_file,
            target_ip,
            max_packets=max_packets
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
            json_path = packet_sniffer.save_json_report(analysis_data, output_dir=user_output_dir)
            
            # Generate PDF report in user directory
            if json_path:
                try:
                    packet_sniffer.log("[*] Analysis complete. Generating PDF report...", current_user_identifier)

                    # Get user-specific PDF path
                    user_paths = packet_sniffer.get_output_paths(user_output_dir)
                    pdf_path = user_paths["pdf_report"]

                    # Ensure output directory exists
                    os.makedirs(pdf_path.parent, exist_ok=True)

                    # Create PDF using pdf_generator
                    pdf_generator.create_packet_sniffer_report_pdf(analysis_data, str(pdf_path))

                    if pdf_path.exists():
                        packet_sniffer.log(f"[+] PDF report generated successfully: {pdf_path}", current_user_identifier)
                    else:
                        packet_sniffer.log("[!] PDF generation ran but file not found.", current_user_identifier)

                except ImportError:
                    packet_sniffer.log("[!] Error: PDF generator dependencies missing.", current_user_identifier)
                except Exception as e:
                    packet_sniffer.log(f"[!] FAILED to generate PDF: {str(e)}", current_user_identifier)

        else:
            packet_sniffer.log(f"[!] JSON Analysis failed: {analysis_data.get('message', 'Unknown error')}", current_user_identifier)
            packet_sniffer.send_sse_event("analysis_complete", {"target_ip": target_ip, "status": "analysis_failed"})
            
            # Log failure (Analysis phase - Inside App Context)
            with app.app_context():
                scan_logger.create_full_scan_log(
                    user_id=user_id_for_log,
                    tool_name="Sniffer",
                    target=target_ip,
                    duration=actual_duration,
                    finding_count=0,
                    status="Analysis Failed",
                    scan_type="Capture"
                )
            return

        # Log Success (Inside App Context)
        with app.app_context():
            scan_logger.create_full_scan_log(
                user_id=user_id_for_log,
                tool_name="Sniffer",
                target=target_ip,
                duration=actual_duration,
                finding_count=finding_count,
                status=status,
                scan_type="Capture"
            )

        packet_sniffer.send_sse_event("analysis_complete", {"target_ip": target_ip, "status": "success"})


    # Launch the background thread
    threading.Thread(
        target=scan_task,
        args=(interface_id, custom_bpf_filter),
        daemon=True
    ).start()

    return jsonify({"status": "success", "message": f"Packet capture for {target_ip} initiated."})


@packet_sniffer_bp.route('/stop_capture', methods=['POST'])
@login_required
def stop_capture_route():
    """API endpoint to stop the running capture process."""
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    if packet_sniffer.stop_capture():
        packet_sniffer.log("[*] Stop capture triggered by user.", user_identifier)
        return jsonify({"status": "success", "message": "Capture stop signal sent."})
    return jsonify({"status": "error", "message": "No active capture to stop."}), 404


@packet_sniffer_bp.route('/trigger_ai_analysis', methods=['POST'])
@login_required
def trigger_ai_analysis_route():
    """Checks if PDF exists before triggering AI analysis."""
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_dir = get_user_results_dir()
    paths = packet_sniffer.get_output_paths(user_dir)
    pdf_path = paths["pdf_report"]

    if not pdf_path.exists():
        packet_sniffer.log(f"[!] Analysis failed: PDF report not found at {pdf_path}", user_identifier)
        return jsonify({
            "status": "error",
            "message": "PDF report not available. Please run a scan first."
        }), 404

    return jsonify({
        "status": "success",
        "scanner_type": "packet_sniffer"
    })


@packet_sniffer_bp.route('/report_files', methods=['GET'])
@login_required
def get_report_files():
    """Checks availability of reports in user directory."""
    user_dir = get_user_results_dir()
    paths = packet_sniffer.get_output_paths(user_dir)
    
    json_exists = paths["json_report"].exists()
    pdf_exists = paths["pdf_report"].exists()

    if not json_exists and not pdf_exists:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    return jsonify({
        "status": "success",
        "json_report": "/packet_sniffer/get_json_report" if json_exists else None,
        "pdf_report": "/packet_sniffer/download_pdf" if pdf_exists else None
    })


@packet_sniffer_bp.route('/download_pdf', methods=['GET'])
@login_required
def download_pdf_report():
    """Serves the PDF report dynamically from user directory."""
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_dir = get_user_results_dir()
    paths = packet_sniffer.get_output_paths(user_dir)
    pdf_path = paths["pdf_report"]

    if not pdf_path.exists():
        return jsonify({"status": "error", "message": "PDF report file not found."}), 404

    try:
        directory = str(pdf_path.parent)
        filename = pdf_path.name
        return send_from_directory(directory, filename, as_attachment=True, mimetype='application/pdf')
    except Exception as e:
        packet_sniffer.log(f"[!] Error serving PDF file: {e}", user_identifier)
        return jsonify({"status": "error", "message": "Could not serve PDF file."}), 500


@packet_sniffer_bp.route('/get_json_report', methods=['GET'])
@login_required
def get_json_report_file():
    """Serves the JSON analysis report file from user directory."""
    user_dir = get_user_results_dir()
    paths = packet_sniffer.get_output_paths(user_dir)
    json_path = paths["json_report"]

    if not json_path.exists():
        return jsonify({"status": "error", "message": "JSON report file not found."}), 404

    directory = str(json_path.parent)
    filename = json_path.name
    return send_from_directory(directory, filename, as_attachment=True, mimetype='application/json')


@packet_sniffer_bp.route('/clear_log', methods=['POST'])
@login_required
def clear_log_route():
    # If a clear_log_file function exists in packet_sniffer, call it here.
    return jsonify({"status": "success", "message": "Log cleared."})


@packet_sniffer_bp.route('/log_stream')
@login_required
def log_stream():
    """Streams logs from the packet_sniffer queue to the frontend (SSE)."""
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    def generate_logs():
        user_queue = packet_sniffer.get_user_queue(user_identifier)
        while True:
            try:
                # 10 second timeout for keep-alive
                message = user_queue.get(timeout=10)
                yield message
            except _queue_module.Empty:
                # Send a comment to keep the connection alive
                yield ": keep-alive\n\n"

    return Response(generate_logs(), mimetype='text/event-stream')