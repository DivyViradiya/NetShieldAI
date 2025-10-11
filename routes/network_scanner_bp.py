from flask import Flask, render_template, jsonify, request, Response
from flask import Blueprint
import threading
import json
import time
import os
import queue

# Import the updated network_scanner module
from Services import network_scanner
from Services.api_client import login_required

network_scanner_bp = Blueprint('network_scanner_bp', __name__)

# Add this route to handle the /network_scanner URL
@network_scanner_bp.route('/')
def network_scanner_page():
    """Renders the network scanner page."""
    return render_template('network_scanner.html')  # Make sure this template exists

@network_scanner_bp.route('/local_ip', methods=['GET'])
def get_local_ip_route():
    """API endpoint to detect and return the local IP address."""
    local_ip = network_scanner.get_local_ip()
    network_scanner.log(f"[*] Local IP requested: {local_ip}")
    return jsonify({"local_ip": local_ip})

@network_scanner_bp.route('/scan', methods=['POST'])
def scan_ports():
    """
    API endpoint to initiate all types of port scans (TCP, UDP, OS, Aggressive, etc.).
    Runs the scan in a separate thread to avoid blocking the Flask app.
    """
    data = request.get_json()
    target_ip = data.get('target_ip')
    protocol_type = data.get('protocol_type', 'TCP').upper()  # Default to TCP
    scan_type = data.get('scan_type', 'default')  # Default to standard scan

    # Validate scan type
    valid_scan_types = ['default', 'os', 'fragmented', 'aggressive', 'tcp_syn']
    if scan_type not in valid_scan_types:
        return jsonify({"status": "error", "message": "Invalid scan type specified."}), 400

    # If target_ip is empty, try to use local IP
    if not target_ip:
        target_ip = network_scanner.get_local_ip()
        if target_ip == "127.0.0.1" and not network_scanner.is_valid_ip_or_range(target_ip):
            network_scanner.log("[!] No target IP/range entered and local IP not detected. Please detect IP or enter a target.")
            return jsonify({"status": "error", "message": "No target IP/range provided and local IP not detected."}), 400
        network_scanner.log(f"[*] Target IP/Range not specified, defaulting to local IP: {target_ip}")

    if not network_scanner.is_valid_ip_or_range(target_ip):
        network_scanner.log(f"[!] Invalid target input: {target_ip}")
        return jsonify({"status": "error", "message": "Please enter a valid IP address, CIDR range, or IP range."}), 400

    # Check if Nmap is installed locally instead of checking for Docker
    if not network_scanner.is_nmap_installed():
        network_scanner.log("[!] Nmap is not installed or not in PATH. Cannot perform scan.")
        return jsonify({"status": "error", "message": "Nmap is not installed. Please check the log for details."}), 500
    
    # Note: Privilege checks (is_admin) are now handled inside the network_scanner module,
    # which will log errors if scans are attempted without necessary permissions.

    # Function to run in a separate thread
    def scan_task():
        network_scanner.log(f"[*] Starting {scan_type.upper()} {protocol_type} scan for {target_ip}...")
        # The run_nmap_scan function now handles the entire process, including port extraction.
        # It will also log its own success or failure messages.
        network_scanner.run_nmap_scan(target_ip, protocol_type=protocol_type, scan_type=scan_type)

    threading.Thread(target=scan_task).start()
    return jsonify({"status": "success", "message": f"{scan_type.upper()} scan for {target_ip} ({protocol_type}) initiated."})

@network_scanner_bp.route('/open_ports', methods=['GET'])
def get_open_ports_route():
    """API endpoint to get the currently detected open ports."""
    ports = network_scanner.get_current_open_ports()
    return jsonify({"open_ports": ports})

@network_scanner_bp.route('/block_ports', methods=['POST'])
def block_ports_route():
    """
    API endpoint to initiate blocking of all detected open ports.
    Runs the blocking in a separate thread.
    """
    if not network_scanner.is_admin():
        network_scanner.log("[!] Insufficient privileges to block ports. Please run the server as administrator/root.")
        return jsonify({"status": "error", "message": "Insufficient privileges to block ports."}), 403

    def block_task():
        all_ports_to_block_info = network_scanner.open_ports["TCP"] + network_scanner.open_ports["UDP"]
        
        if not all_ports_to_block_info:
            network_scanner.log("[*] No open ports detected to block.")
            return

        network_scanner.log(f"[*] Attempting to block {len(all_ports_to_block_info)} detected ports...")
        for p_info in all_ports_to_block_info:
            # Note: The whitelisted_ports set in the module is now a set of strings
            port_str = str(p_info['port'])
            protocol = p_info['protocol']
            if port_str in network_scanner.whitelisted_ports:
                network_scanner.log(f"[~] Skipping whitelisted {protocol} port {port_str}.")
                continue
            
            success = network_scanner.block_port(port_str, protocol=protocol)
            if success and network_scanner.is_port_blocked(port_str, protocol=protocol):
                network_scanner.log(f"[✓] {protocol} Port {port_str} successfully blocked and verified.")
            else:
                network_scanner.log(f"[x] {protocol} Port {port_str} could not be verified as blocked. Manual check may be needed.")
        network_scanner.log("[+] Port blocking process completed.")

    threading.Thread(target=block_task).start()
    return jsonify({"status": "success", "message": "Port blocking initiated."})

@network_scanner_bp.route('/verify_ports', methods=['POST'])
def verify_ports_route():
    """
    API endpoint to verify if detected ports are closed.
    Runs the verification in a separate thread.
    """
    data = request.get_json()
    target_ip = data.get('target_ip')

    if not target_ip:
        target_ip = network_scanner.get_local_ip()
        if target_ip == "127.0.0.1" and not network_scanner.is_valid_ip_or_range(target_ip):
             network_scanner.log("[!] Cannot verify ports without a detected IP address or a target entered.")
             return jsonify({"status": "error", "message": "No target IP/range provided and local IP not detected for verification."}), 400

    def verify_task():
        network_scanner.verify_ports_closed(target_ip)
        network_scanner.log("[+] Port verification process completed.")

    threading.Thread(target=verify_task).start()
    return jsonify({"status": "success", "message": "Port verification initiated."})

@network_scanner_bp.route('/add_whitelist', methods=['POST'])
def add_whitelist_route():
    """API endpoint to add ports to the whitelist."""
    data = request.get_json()
    ports_str = data.get('ports')
    if network_scanner.add_to_whitelist(ports_str):
        return jsonify({"status": "success", "message": "Ports added to whitelist."})
    return jsonify({"status": "error", "message": "Failed to add ports to whitelist. Check log."}), 400

@network_scanner_bp.route('/clear_whitelist', methods=['POST'])
def clear_whitelist_route():
    """API endpoint to clear the whitelist."""
    network_scanner.clear_whitelist()
    return jsonify({"status": "success", "message": "Whitelist cleared."})

@network_scanner_bp.route('/whitelisted_ports', methods=['GET'])
def get_whitelisted_ports_route():
    """API endpoint to get the current list of whitelisted ports."""
    ports = network_scanner.get_whitelisted_ports()
    return jsonify({"whitelisted_ports": ports})

@network_scanner_bp.route('/get_scan_results', methods=['GET'])
def get_scan_results():
    """
    API endpoint to get the content of a specific scan result file.
    """
    scan_type = request.args.get('type', 'tcp')
    
    result_files = {
        'tcp': network_scanner.SCAN_RESULT_TCP,
        'udp': network_scanner.SCAN_RESULT_UDP, # Added UDP results
        'tcp_syn': network_scanner.SCAN_RESULT_TCP_SYN,
        'os': network_scanner.SCAN_RESULT_OS,
        'fragmented': network_scanner.SCAN_RESULT_FRAGMENTED,
        'aggressive': network_scanner.SCAN_RESULT_AGGRESSIVE
    }
    
    file_path = result_files.get(scan_type)
    
    if not file_path or not os.path.exists(file_path):
        return jsonify({
            "status": "error",
            "message": f"No results available for {scan_type} scan."
        }), 404
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            return jsonify({
                "status": "success",
                "content": content,
                "scan_type": scan_type
            })
    except Exception as e:
        network_scanner.log(f"[!] Error reading {scan_type} scan results: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to read {scan_type} scan results: {str(e)}"
        }), 500

@network_scanner_bp.route('/clear_log', methods=['POST'])
def clear_log_route():
    """API endpoint to clear the log file."""
    network_scanner.clear_log_file()
    return jsonify({"status": "success", "message": "Log cleared."})

@network_scanner_bp.route('/log_stream')
def log_stream():
    """
    Server-Sent Events (SSE) endpoint to stream log messages to the frontend.
    """
    def generate_logs():
        while True:
            try:
                message = network_scanner.log_queue.get(timeout=10) # Timeout to prevent endless blocking
                yield message
            except queue.Empty:
                # Send a comment to keep the connection alive
                yield ": keep-alive\n\n"

    return Response(generate_logs(), mimetype='text/event-stream')