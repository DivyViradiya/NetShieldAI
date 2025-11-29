from flask import Flask, render_template, jsonify, request, Response, send_from_directory, Blueprint
import threading
import json
import time
import os
import queue
import requests
import uuid 

# Import the updated network_scanner module
from Services import network_scanner
# --- Import PDF Generator ---
from Services import pdf_generator
# from Services.api_client import login_required

network_scanner_bp = Blueprint('network_scanner_bp', __name__)

# ==========================================
# --- ⚙️ CONFIGURATION: PDF OUTPUT PATH ---
# ==========================================
# 1. To change the FOLDER, edit 'RESULTS_DIR' in 'Services/network_scanner.py'
# 2. To change the FILENAME, edit the variable below:
PDF_FILENAME = "nmap_report.pdf" 
PDF_REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'PDFs') # Assuming common PDF folder

# This constructs the full path automatically
JSON_REPORT_PATH = network_scanner.JSON_REPORT_FILE
# Use a derived path for the final PDF to ensure it is correctly accessed and served
PDF_REPORT_PATH = os.path.join(network_scanner.RESULTS_DIR, PDF_FILENAME) 
# 🚨 NEW: Central server proxy URL (Must match the one in chatbot_bp.py)
SERVER_PROXY_URL = "http://localhost:5100" # NOTE: Using 5100 based on run.py, adjust if FastAPI is on a different port (e.g., 5000)
# ==========================================

@network_scanner_bp.route('/')
def network_scanner_page():
    """Renders the network scanner page."""
    return render_template('network_scanner.html')

@network_scanner_bp.route('/local_ip', methods=['GET'])
def get_local_ip_route():
    """API endpoint to detect and return the local IP address."""
    local_ip = network_scanner.get_local_ip()
    network_scanner.log(f"[*] Local IP requested: {local_ip}")
    return jsonify({"local_ip": local_ip})

@network_scanner_bp.route('/scan', methods=['POST'])
def scan_ports():
    """
    API endpoint to initiate all types of port scans.
    Runs the scan in a separate thread and generates a PDF report upon completion.
    """
    data = request.get_json()
    target_ip = data.get('target_ip')
    protocol_type = data.get('protocol_type', 'TCP').upper()
    scan_type = data.get('scan_type', 'default')

    # Validate scan type
    valid_scan_types = ['default', 'os', 'fragmented', 'aggressive', 'tcp_syn', 'vuln', 'udp']
    if scan_type not in valid_scan_types:
        return jsonify({"status": "error", "message": "Invalid scan type specified."}), 400

    # If target_ip is empty, try to use local IP
    if not target_ip:
        target_ip = network_scanner.get_local_ip()
        if target_ip == "127.0.0.1" and not network_scanner.is_valid_ip_or_range(target_ip):
            network_scanner.log("[!] No target IP/range entered and local IP not detected.")
            return jsonify({"status": "error", "message": "No target IP/range provided and local IP not detected."}), 400
        network_scanner.log(f"[*] Target IP/Range not specified, defaulting to local IP: {target_ip}")

    if not network_scanner.is_valid_ip_or_range(target_ip):
        network_scanner.log(f"[!] Invalid target input: {target_ip}")
        return jsonify({"status": "error", "message": "Please enter a valid IP address, CIDR range, or IP range."}), 400

    if not network_scanner.is_nmap_installed():
        network_scanner.log("[!] Nmap is not installed or not in PATH.")
        return jsonify({"status": "error", "message": "Nmap is not installed."}), 500
    
    # --- Threaded Scan Task ---
    def scan_task():
        network_scanner.log(f"[*] Starting {scan_type.upper()} {protocol_type} scan for {target_ip}...")
        
        # 1. Run the Scan (This creates the JSON file via network_scanner.py logic)
        result_file = network_scanner.run_nmap_scan(target_ip, protocol_type=protocol_type, scan_type=scan_type)
        
        if result_file:
            # 2. Generate PDF Report
            try:
                if os.path.exists(JSON_REPORT_PATH):
                    network_scanner.log("[*] Scan complete. Generating PDF report...")
                    
                    # Ensure PDF output directory exists (needed by WeasyPrint)
                    os.makedirs(os.path.dirname(PDF_REPORT_PATH), exist_ok=True)
                    
                    # Call the generator with the file path
                    pdf_generator.create_nmap_report_pdf(str(JSON_REPORT_PATH), str(PDF_REPORT_PATH))
                    
                    if os.path.exists(PDF_REPORT_PATH):
                        network_scanner.log(f"[+] PDF report generated successfully: {PDF_REPORT_PATH}")
                    else:
                        network_scanner.log("[!] PDF generation ran but file not found (unknown error).")
                else:
                    network_scanner.log("[!] JSON report not found. Cannot generate PDF.")
            
            except ImportError:
                network_scanner.log("[!] Error: GTK3 Runtime missing or WeasyPrint not installed properly.")
            except Exception as e:
                # This captures WeasyPrint errors and sends them to the UI Log
                network_scanner.log(f"[!] FAILED to generate PDF: {str(e)}")
        else:
            network_scanner.log("[!] Scan failed to produce a result file.")

    threading.Thread(target=scan_task).start()
    return jsonify({"status": "success", "message": f"{scan_type.upper()} scan for {target_ip} initiated."})

@network_scanner_bp.route('/trigger_ai_analysis', methods=['POST'])
def trigger_ai_analysis_route():
    """
    Checks if PDF exists and tells the client to call the central proxy via the chatbot blueprint.
    (Proxying logic moved to chatbot_bp.py:scanner_analysis_proxy)
    """
    if not os.path.exists(PDF_REPORT_PATH):
        network_scanner.log(f"[!] Analysis failed: PDF report not found at {PDF_REPORT_PATH}")
        return jsonify({
            "status": "error", 
            "message": "PDF report not available. Please run a scan first."
        }), 404

    # Now returns the scanner type so the chatbot blueprint knows which file to read.
    return jsonify({
        "status": "success",
        "scanner_type": "nmap" 
    })

@network_scanner_bp.route('/report_files', methods=['GET'])
def get_report_files():
    """Checks availability of reports."""
    json_exists = os.path.exists(JSON_REPORT_PATH)
    pdf_exists = os.path.exists(PDF_REPORT_PATH)

    if not json_exists and not pdf_exists:
        return jsonify({"status": "pending", "message": "No reports found."}), 404

    return jsonify({
        "status": "success",
        "json_report": "/network_scanner/get_json_report" if json_exists else None,
        "pdf_report": "/network_scanner/download_pdf" if pdf_exists else None
    })

@network_scanner_bp.route('/download_pdf', methods=['GET'])
def download_pdf_report():
    """Serves the PDF report dynamically based on the configured path."""
    if not os.path.exists(PDF_REPORT_PATH):
        return jsonify({"status": "error", "message": "PDF report file not found."}), 404
    
    try:
        # Dynamically determine directory and filename from the global path
        directory = os.path.dirname(PDF_REPORT_PATH)
        filename = os.path.basename(PDF_REPORT_PATH)

        return send_from_directory(
            directory=directory,
            path=filename,
            as_attachment=True
        )
    except Exception as e:
        network_scanner.log(f"[!] Error serving PDF file: {e}")
        return jsonify({"status": "error", "message": "Could not serve PDF file."}), 500

@network_scanner_bp.route('/get_json_report', methods=['GET'])
def get_json_report_file():
    if not os.path.exists(JSON_REPORT_PATH):
        return jsonify({"status": "error", "message": "JSON report file not found."}), 404
    
    # Use dynamic pathing for JSON as well for consistency
    directory = os.path.dirname(JSON_REPORT_PATH)
    filename = os.path.basename(JSON_REPORT_PATH)

    return send_from_directory(
        directory=directory,
        path=filename,
        as_attachment=True
    )

# --- Standard Scan Routes (Unchanged) ---
@network_scanner_bp.route('/open_ports', methods=['GET'])
def get_open_ports_route():
    ports = network_scanner.get_current_open_ports()
    return jsonify({"open_ports": ports})

@network_scanner_bp.route('/block_ports', methods=['POST'])
def block_ports_route():
    if not network_scanner.is_admin():
        network_scanner.log("[!] Insufficient privileges to block ports.")
        return jsonify({"status": "error", "message": "Insufficient privileges."}), 403

    def block_task():
        all_ports = network_scanner.open_ports["TCP"] + network_scanner.open_ports["UDP"]
        if not all_ports:
            network_scanner.log("[*] No open ports detected to block.")
            return

        network_scanner.log(f"[*] Attempting to block {len(all_ports)} detected ports...")
        for p_info in all_ports:
            port_str = str(p_info['port'])
            protocol = p_info['protocol']
            if port_str in network_scanner.whitelisted_ports:
                network_scanner.log(f"[~] Skipping whitelisted {protocol} port {port_str}.")
                continue
            
            success = network_scanner.block_port(port_str, protocol=protocol)
            if success and network_scanner.is_port_blocked(port_str, protocol=protocol):
                network_scanner.log(f"[✓] {protocol} Port {port_str} blocked.")
            else:
                network_scanner.log(f"[x] {protocol} Port {port_str} failed to verify as blocked.")
        network_scanner.log("[+] Port blocking process completed.")

    threading.Thread(target=block_task).start()
    return jsonify({"status": "success", "message": "Port blocking initiated."})

@network_scanner_bp.route('/verify_ports', methods=['POST'])
def verify_ports_route():
    data = request.get_json()
    target_ip = data.get('target_ip')
    if not target_ip:
         return jsonify({"status": "error", "message": "No target IP provided."}), 400

    def verify_task():
        network_scanner.verify_ports_closed(target_ip)
        network_scanner.log("[+] Port verification process completed.")

    threading.Thread(target=verify_task).start()
    return jsonify({"status": "success", "message": "Port verification initiated."})

@network_scanner_bp.route('/add_whitelist', methods=['POST'])
def add_whitelist_route():
    data = request.get_json()
    if network_scanner.add_to_whitelist(data.get('ports')):
        return jsonify({"status": "success", "message": "Ports added to whitelist."})
    return jsonify({"status": "error", "message": "Failed to add ports."}), 400

@network_scanner_bp.route('/clear_whitelist', methods=['POST'])
def clear_whitelist_route():
    network_scanner.clear_whitelist()
    return jsonify({"status": "success", "message": "Whitelist cleared."})

@network_scanner_bp.route('/whitelisted_ports', methods=['GET'])
def get_whitelisted_ports_route():
    return jsonify({"whitelisted_ports": network_scanner.get_whitelisted_ports()})

@network_scanner_bp.route('/get_scan_results', methods=['GET'])
def get_scan_results():
    scan_type = request.args.get('type', 'tcp')
    result_files = {
        'tcp': network_scanner.SCAN_RESULT_TCP,
        'udp': network_scanner.SCAN_RESULT_UDP,
        'tcp_syn': network_scanner.SCAN_RESULT_TCP_SYN,
        'os': network_scanner.SCAN_RESULT_OS,
        'fragmented': network_scanner.SCAN_RESULT_FRAGMENTED,
        'aggressive': network_scanner.SCAN_RESULT_AGGRESSIVE
    }
    file_path = result_files.get(scan_type)
    
    if not file_path or not os.path.exists(file_path):
        return jsonify({"status": "error", "message": f"No results for {scan_type}."}), 404
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return jsonify({"status": "success", "content": f.read(), "scan_type": scan_type})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@network_scanner_bp.route('/clear_log', methods=['POST'])
def clear_log_route():
    network_scanner.clear_log_file()
    return jsonify({"status": "success", "message": "Log cleared."})

@network_scanner_bp.route('/log_stream')
def log_stream():
    def generate_logs():
        while True:
            try:
                message = network_scanner.log_queue.get(timeout=10)
                yield message
            except queue.Empty:
                yield ": keep-alive\n\n"
    return Response(generate_logs(), mimetype='text/event-stream')