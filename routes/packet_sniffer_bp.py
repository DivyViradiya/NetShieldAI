from flask import (
    Blueprint, Flask, render_template, jsonify, request,
    Response, send_from_directory
)
import threading
import json
import time
import os
import queue as _queue_module
import uuid
import re
from pathlib import Path

# Import the packet_sniffer module
from Services import packet_sniffer
# Import PDF Generator
from Services import pdf_generator

packet_sniffer_bp = Blueprint('packet_sniffer_bp', __name__)

# ==========================================
# --- ⚙️ CONFIGURATION: PDF/JSON OUTPUT PATH
# ==========================================
# Use the paths defined in packet_sniffer for consistency
JSON_REPORT_PATH = Path(packet_sniffer.ANALYSIS_REPORT_FILE)
PDF_REPORT_PATH = Path(packet_sniffer.PDF_REPORT_FILE)
SERVER_PROXY_URL = "http://localhost:5100"
# ==========================================


@packet_sniffer_bp.route('/')
def packet_sniffer_page():
    """Renders the packet sniffer page."""
    return render_template('packet_sniffer.html')


# --- Interface Listing ---
@packet_sniffer_bp.route('/get_interfaces', methods=['GET'])
def get_interfaces_route():
    """API endpoint to list available network interfaces using tshark -D."""
    if not packet_sniffer.get_packet_capture_cmd():
        return jsonify({"status": "error", "message": "TShark (Wireshark) not found."}), 500

    interfaces = packet_sniffer.list_available_interfaces()
    interface_list_output = list(interfaces.values())
    return jsonify({"status": "success", "interfaces": interface_list_output})


@packet_sniffer_bp.route('/start_capture', methods=['POST'])
def start_capture_route():
    """
    API endpoint to initiate packet capture and analysis.
    Accepts: target_ip (required), duration (optional), max_packets (optional),
             interface_id (optional), custom_bpf_filter (optional).
    NOTE: This endpoint WILL NOT attempt to elevate privileges. The Flask server
    process must already be running with administrator/root privileges.
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
        packet_sniffer.log("[!] No target IP provided for capture filter.")
        return jsonify({"status": "error", "message": "No target IP provided."}), 400

    # Check admin privileges. IMPORTANT: do NOT attempt to prompt for elevation here.
    if not packet_sniffer.is_admin():
        packet_sniffer.log("[!] Sniffing requires administrator/root privileges. Server is not elevated.")
        return jsonify({
            "status": "error",
            "message": "Server process lacks administrator/root privileges. Restart the Flask server as admin/root and retry."
        }), 403

    if not packet_sniffer.get_packet_capture_cmd():
        return jsonify({"status": "error", "message": "TShark (Wireshark) not found."}), 500

    # Normalise interface_id to string if provided
    if interface_id is not None:
        interface_id = str(interface_id)

    def scan_task(interface_id_local, custom_bpf_filter_local):
        packet_sniffer.log(f"[*] Starting capture for {target_ip} ({duration}s)...")

        pcap_file = packet_sniffer.run_packet_capture(
            target_ip,
            duration,
            interface_id=interface_id_local,
            custom_bpf_filter=custom_bpf_filter_local
        )

        if not pcap_file:
            packet_sniffer.log("[!] Packet capture failed.")
            packet_sniffer.send_sse_event("analysis_complete", {"target_ip": target_ip, "status": "capture_failed"})
            return

        packet_sniffer.log("[*] Capture complete. Starting JSON analysis...")

        analysis_data = packet_sniffer.analyze_pcap_to_json(
            pcap_file,
            target_ip,
            max_packets=max_packets
        )

        if analysis_data.get('status') != 'success':
            packet_sniffer.log(f"[!] JSON Analysis failed: {analysis_data.get('message', 'Unknown error')}")
            packet_sniffer.send_sse_event("analysis_complete", {"target_ip": target_ip, "status": "analysis_failed"})
            return

        # Save JSON report
        json_path = packet_sniffer.save_json_report(analysis_data)

        # Extract security features (no return required)
        try:
            packet_sniffer.extract_security_features(analysis_data)
        except Exception as e:
            packet_sniffer.log(f"[!] Feature extraction failed: {e}")

        # Generate PDF report (best-effort)
        if json_path:
            try:
                packet_sniffer.log("[*] Analysis complete. Generating PDF report...")

                # Ensure output directory exists
                os.makedirs(PDF_REPORT_PATH.parent, exist_ok=True)

                # Create PDF using pdf_generator (may raise if dependencies missing)
                pdf_generator.create_packet_sniffer_report_pdf(str(JSON_REPORT_PATH), str(PDF_REPORT_PATH))

                if PDF_REPORT_PATH.exists():
                    packet_sniffer.log(f"[+] PDF report generated successfully: {PDF_REPORT_PATH}")
                else:
                    packet_sniffer.log("[!] PDF generation ran but file not found.")

            except ImportError:
                packet_sniffer.log("[!] Error: PDF generator dependencies missing.")
            except Exception as e:
                packet_sniffer.log(f"[!] FAILED to generate PDF: {str(e)}")

        # Send analysis completion event to UI (SSE)
        packet_sniffer.send_sse_event("analysis_complete", {"target_ip": target_ip, "status": "success"})

    # Launch the background thread
    threading.Thread(
        target=scan_task,
        args=(interface_id, custom_bpf_filter),
        daemon=True
    ).start()

    return jsonify({"status": "success", "message": f"Packet capture for {target_ip} initiated."})


@packet_sniffer_bp.route('/stop_capture', methods=['POST'])
def stop_capture_route():
    """API endpoint to stop the running capture process."""
    if packet_sniffer.stop_capture():
        return jsonify({"status": "success", "message": "Capture stop signal sent."})
    return jsonify({"status": "error", "message": "No active capture to stop."}), 404


@packet_sniffer_bp.route('/trigger_ai_analysis', methods=['POST'])
def trigger_ai_analysis_route():
    """Checks if PDF exists before triggering AI analysis."""
    if not PDF_REPORT_PATH.exists():
        packet_sniffer.log(f"[!] Analysis failed: PDF report not found at {PDF_REPORT_PATH}")
        return jsonify({
            "status": "error",
            "message": "PDF report not available. Please run a scan first."
        }), 404

    return jsonify({
        "status": "success",
        "scanner_type": "packet_sniffer"
    })


@packet_sniffer_bp.route('/report_files', methods=['GET'])
def get_report_files():
    """Checks availability of reports."""
    json_exists = JSON_REPORT_PATH.exists()
    pdf_exists = PDF_REPORT_PATH.exists()

    if not json_exists and not pdf_exists:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    return jsonify({
        "status": "success",
        "json_report": "/packet_sniffer/get_json_report" if json_exists else None,
        "pdf_report": "/packet_sniffer/download_pdf" if pdf_exists else None
    })


@packet_sniffer_bp.route('/download_pdf', methods=['GET'])
def download_pdf_report():
    """Serves the PDF report dynamically based on the configured path."""
    if not PDF_REPORT_PATH.exists():
        return jsonify({"status": "error", "message": "PDF report file not found."}), 404

    try:
        directory = str(PDF_REPORT_PATH.parent)
        filename = PDF_REPORT_PATH.name
        return send_from_directory(directory, filename, as_attachment=True, mimetype='application/pdf')
    except Exception as e:
        packet_sniffer.log(f"[!] Error serving PDF file: {e}")
        return jsonify({"status": "error", "message": "Could not serve PDF file."}), 500


@packet_sniffer_bp.route('/get_json_report', methods=['GET'])
def get_json_report_file():
    """Serves the JSON analysis report file."""
    if not JSON_REPORT_PATH.exists():
        return jsonify({"status": "error", "message": "JSON report file not found."}), 404

    directory = str(JSON_REPORT_PATH.parent)
    filename = JSON_REPORT_PATH.name
    return send_from_directory(directory, filename, as_attachment=True, mimetype='application/json')


@packet_sniffer_bp.route('/clear_log', methods=['POST'])
def clear_log_route():
    # If you add a clear_log_file() to packet_sniffer, call it here.
    # Example: packet_sniffer.clear_log_file()
    return jsonify({"status": "success", "message": "Log cleared."})


@packet_sniffer_bp.route('/log_stream')
def log_stream():
    """Streams logs from the packet_sniffer queue to the frontend (SSE)."""
    def generate_logs():
        while True:
            try:
                # 10 second timeout for keep-alive
                message = packet_sniffer.log_queue.get(timeout=10)
                yield message
            except _queue_module.Empty:
                # Send a comment to keep the connection alive
                yield ": keep-alive\n\n"

    return Response(generate_logs(), mimetype='text/event-stream')
