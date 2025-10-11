import os
import threading
import json
import time
from flask import Blueprint, render_template, jsonify, request, Response

# Import the new zap_scanner module
from Services import zap_scanner

# Assuming you might still have this for other parts of your app
# from Services.api_client import login_required

zap_scanner_bp = Blueprint('zap_scanner_bp', __name__)

# --- Global variable to hold the path to the final JSON report ---
# This is derived from the new zap_scanner script's logic
JSON_REPORT_PATH = os.path.join(zap_scanner.RESULTS_DIR, "zap_report.json")
XML_REPORT_PATH = os.path.join(zap_scanner.RESULTS_DIR, "zap_report.xml")


@zap_scanner_bp.route('/')
# @login_required  # Uncomment if you want to protect this page
def zap_scanner_page():
    """Renders the ZAP scanner page."""
    return render_template('zap_scanner.html')


@zap_scanner_bp.route('/scan', methods=['POST'])
# @login_required # Uncomment if you want to protect this endpoint
def initiate_zap_scan():
    """
    API endpoint to initiate a ZAP quick scan.
    The new logic does not support different scan types; it uses the 'quickurl' command.
    The scan runs in a separate thread to avoid blocking the Flask app.
    """
    data = request.get_json()
    target_url = data.get('target_url')

    if not target_url:
        zap_scanner.log("[!] Target URL is required for ZAP scan.")
        return jsonify({"status": "error", "message": "Target URL is required."}), 400
    
    # Check if the ML model was loaded correctly on startup
    if zap_scanner.model is None:
        zap_scanner.log("[!] FATAL: ML model is not loaded. Cannot start scan.")
        return jsonify({"status": "error", "message": "ML model is not loaded. Check server logs for details."}), 500

    # Function to run the entire scan and analysis process in a background thread
    def scan_and_process_task():
        zap_scanner.log(f"[*] Starting ZAP Quick Scan for {target_url}...")
        
        # The new run_zap_scan function handles the entire process of launching ZAP
        scan_successful = zap_scanner.run_zap_scan(target_url, XML_REPORT_PATH)

        if scan_successful:
            zap_scanner.log("[+] ZAP scan command finished. Now parsing and enriching report...")
            
            # The new script separates parsing and saving
            scan_results = zap_scanner.parse_zap_xml_report(XML_REPORT_PATH)
            
            if scan_results:
                # Add the target URL to the final report data
                scan_results["target_url"] = target_url
                
                # Save the enriched data to the final JSON file
                json_report_path = zap_scanner.save_json_report(scan_results, zap_scanner.RESULTS_DIR)
                
                if json_report_path:
                    zap_scanner.log(f"[+] Scan, analysis, and prediction complete. Final report saved to {json_report_path}")
                else:
                    zap_scanner.log("[!] Failed to save the final JSON report.")
            else:
                zap_scanner.log("[!] Failed to parse the ZAP XML report after the scan.")
        else:
            zap_scanner.log(f"[!] ZAP scan failed for target: {target_url}. Check logs for details.")

    # Start the background task
    threading.Thread(target=scan_and_process_task).start()
    
    return jsonify({
        "status": "success",
        "message": f"ZAP Quick Scan initiated for {target_url}. Monitor the logs for progress."
    })


@zap_scanner_bp.route('/scan_results', methods=['GET'])
# @login_required # Uncomment if you want to protect this endpoint
def get_zap_scan_results():
    """
    API endpoint to get the final, enriched ZAP scan report.
    This now fetches the single, static JSON report file.
    """
    if not os.path.exists(JSON_REPORT_PATH):
        return jsonify({
            "status": "pending",
            "message": "No JSON report available. Please run a scan first or wait for the current one to complete."
        }), 404
    
    try:
        with open(JSON_REPORT_PATH, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        
        return jsonify({
            "status": "success",
            "data": report_data
        })
    except Exception as e:
        zap_scanner.log(f"[!] Error reading or parsing JSON report file: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to read or parse the report file. Check server logs for details."
        }), 500


@zap_scanner_bp.route('/clear_log', methods=['POST'])
# @login_required # Uncomment if you want to protect this endpoint
def clear_zap_log_route():
    """API endpoint to clear the ZAP scanner log file."""
    zap_scanner.clear_log_file()
    return jsonify({"status": "success", "message": "ZAP log cleared."})


@zap_scanner_bp.route('/log_stream')
# @login_required # Uncomment if you want to protect this endpoint
def zap_log_stream():
    """
    Server-Sent Events (SSE) endpoint to stream the ZAP scanner log file to the frontend.
    This function "tails" the log file, sending new lines as they are written.
    """
    def generate_logs():
        try:
            with open(zap_scanner.LOG_FILE, 'r', encoding='utf-8') as f:
                # Go to the end of the file
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if not line:
                        # Sleep briefly to avoid busy-waiting
                        time.sleep(0.5)
                        continue
                    # SSE format: "data: {content}\n\n"
                    yield f"data: {line.strip()}\n\n"
        except FileNotFoundError:
            # Handle case where log file doesn't exist yet
            yield "data: Log file not found. It will be created when the scan starts.\n\n"
        except Exception as e:
            # Log the error and inform the client
            print(f"Error in log stream: {e}")
            yield f"data: An error occurred in the log stream: {e}\n\n"

    return Response(generate_logs(), mimetype='text/event-stream')
