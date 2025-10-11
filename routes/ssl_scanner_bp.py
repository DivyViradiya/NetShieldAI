from flask import Blueprint, render_template, jsonify, request, Response
import threading
import json
import time
import os
from queue import Empty # <<< ADDED: Import the Empty exception

# Import the ssl_scanner module
# This now uses the local executable, not Docker
from Services import ssl_scanner


ssl_scanner_bp = Blueprint('ssl_scanner_bp', __name__)

@ssl_scanner_bp.route('/')
def ssl_scanner_page():
    """Renders the SSL scanner page."""
    return render_template('ssl_scanner.html')

@ssl_scanner_bp.route('/scan', methods=['POST'])
def scan_ssl():
    """
    API endpoint to initiate an SSL scan using the local sslscan executable.
    Runs the scan in a separate thread to avoid blocking the Flask app.
    """
    data = request.get_json()
    target_host = data.get('target_host')

    if not target_host:
        ssl_scanner.log("[!] Target host cannot be empty for SSL scan.")
        return jsonify({"status": "error", "message": "Target host is required."}), 400

    # MODIFIED: Replaced Docker checks with a check for the local executable.
    if not ssl_scanner.is_sslscan_available():
        ssl_scanner.log("[!] sslscan.exe is not available. Cannot perform scan.")
        return jsonify({
            "status": "error",
            "message": "sslscan.exe not found. Please check server configuration and logs."
        }), 500
    
    # Function to run in a separate thread
    def scan_task():
        ssl_scanner.log(f"[*] Starting SSL scan for {target_host}...")
        
        # This function now calls the local executable with all flags
        report_file = ssl_scanner.run_ssl_scan(target_host)
        
        if report_file:
            # The enhanced parser will now run automatically
            summary = ssl_scanner.parse_ssl_report(report_file)
            if summary:
                ssl_scanner.log(f"[+] SSL scan and report parsing complete for {target_host}.")
            else:
                ssl_scanner.log(f"[!] Failed to parse SSL report for {target_host}.")
        else:
            ssl_scanner.log(f"[!] SSL scan failed for {target_host}.")

    threading.Thread(target=scan_task).start()
    return jsonify({"status": "success", "message": f"SSL scan for {target_host} initiated."})

@ssl_scanner_bp.route('/report', methods=['GET'])
def get_ssl_report():
    """
    API endpoint to get the content of the SSL scan report file.
    This now returns the parsed JSON summary instead of raw XML.
    """
    if not os.path.exists(ssl_scanner.SSL_REPORT_XML):
        return jsonify({
            "status": "error",
            "message": "No SSL scan report available. Please run a scan first."
        }), 404
    
    try:
        # We now parse the report and return the structured JSON
        parsed_summary = ssl_scanner.parse_ssl_report(str(ssl_scanner.SSL_REPORT_XML))
        if not parsed_summary:
                return jsonify({
                    "status": "error",
                    "message": "Failed to parse the existing XML report."
                }), 500

        return jsonify({
            "status": "success",
            "content": parsed_summary, # Return the parsed JSON object
            "report_file": os.path.basename(ssl_scanner.SSL_REPORT_XML)
        })
    except Exception as e:
        ssl_scanner.log(f"[!] Error reading or parsing SSL scan report: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to read or parse SSL scan report: {str(e)}"
        }), 500

@ssl_scanner_bp.route('/clear_log', methods=['POST'])
def clear_ssl_log_route():
    """API endpoint to clear the SSL scanner log file."""
    ssl_scanner.clear_log_file()
    return jsonify({"status": "success", "message": "SSL log cleared."})

@ssl_scanner_bp.route('/log_stream')
def ssl_log_stream():
    """
    Server-Sent Events (SSE) endpoint to stream SSL scanner log messages to the frontend.
    """
    def generate_logs():
        while True:
            try:
                # Use a timeout to prevent blocking indefinitely
                message = ssl_scanner.log_queue.get(timeout=10)
                yield message
            except Empty: # <<< MODIFIED: Correctly catch the imported exception
                # Send a comment to keep the connection alive
                yield ": keep-alive\n\n"
            except GeneratorExit:
                # The client has disconnected
                break

    return Response(generate_logs(), mimetype='text/event-stream')