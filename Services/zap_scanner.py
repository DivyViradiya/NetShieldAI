import os
import subprocess
import time
import psutil
import socket
import shutil
import re
from datetime import datetime
import xml.etree.ElementTree as ET
import json
import pandas as pd
from pathlib import Path
import queue  # Queue for real-time streaming
import threading
from logger_setup import logger
from Services import report_manager

# --- Configuration ---
ZAP_EXECUTABLE_PATH = r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"

# --- Path and Logging Setup ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

DEFAULT_RESULTS_DIR = os.path.join(PROJECT_ROOT, "results", "zap_scanner")

LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR, exist_ok=True)

TEMP_DIR = os.path.join(BASE_DIR, "temp", "zap")
if not os.path.exists(TEMP_DIR):
    os.makedirs(TEMP_DIR, exist_ok=True)

# --- Global State for Process Management (Isolated by user_id) ---
active_scans = {} # { "user_id": {"process": Popen, "target": str, "start_time": float} }
scan_lock = threading.Lock()

# --- USER ISOLATION: Dictionary to hold a queue for each user_id ---
user_queues = {}
_queue_lock = threading.Lock()  # RC-1 FIX: protect concurrent queue creation

def get_user_queue(user_id):
    """Ensures a queue exists for the user and returns it. Thread-safe."""
    with _queue_lock:
        if user_id not in user_queues:
            user_queues[user_id] = queue.Queue()
        return user_queues[user_id]

def is_scan_running(user_id):
    """Checks if a scan is currently active for a specific user."""
    with scan_lock:
        return user_id in active_scans

# --- ML Model Setup ---
try:
    from .threat_reranker import predict_threat_risk
except ImportError:
    try:
        from threat_reranker import predict_threat_risk
    except ImportError:
        predict_threat_risk = None

model = predict_threat_risk

# --- HELPER: Find a Free Port ---
def get_free_port():
    """Finds an available port on the host machine to avoid conflicts."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0)) # Bind to port 0 lets the OS select a free port
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        port = s.getsockname()[1]
        return port

# --- LOGGING FUNCTIONS (USER-AWARE) ---

def log(message, user_id=None, to_console=False):
    """
    Logs messages to:
    1. System Console (optional)
    2. User-specific log file (logs/users/{user_id}/zap_agent_log.txt)
    3. User-specific Memory Queue (for real-time frontend)
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}"
    
    # 1. System Console
    if to_console:
        logger.info(message) # use central logger info (colored formatter auto-detects)
    
    # If a specific user is targeted
    if user_id:
        user_id = str(user_id)
        # Organized Path: logs/users/{user_id}/
        user_dir = os.path.join(LOGS_DIR, "users", user_id)
        if not os.path.exists(user_dir):
            os.makedirs(user_dir, exist_ok=True)
            
        user_log_file = os.path.join(user_dir, "zap_agent_log.txt")
        try:
            with open(user_log_file, 'a', encoding='utf-8') as f:
                f.write(log_message + "\n")
        except Exception as e:
            logger.error(f"FATAL: Failed to write to user log file {user_log_file}: {e}")

        # 3. User-Specific Queue (Streaming)
        uq = get_user_queue(user_id)
        uq.put(message)
        
    else:
        # Fallback to general system log
        system_dir = os.path.join(LOGS_DIR, "system")
        if not os.path.exists(system_dir):
            os.makedirs(system_dir, exist_ok=True)
            
        try:
            with open(os.path.join(system_dir, "zap_system_log.txt"), 'a', encoding='utf-8') as f:
                f.write(log_message + "\n")
        except:
            pass

def clear_log_file(user_id):
    """Clears the log file and queue for a specific user."""
    if not user_id: return
    user_id = str(user_id)
    user_log_file = os.path.join(LOGS_DIR, "users", user_id, "zap_agent_log.txt")
    
    try:
        if os.path.exists(user_log_file):
            with open(user_log_file, 'w', encoding='utf-8') as f:
                f.write(f"--- Log cleared at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
        
        # RC-11 FIX: Drain queue using public API instead of internal mutex/queue attributes
        uq = get_user_queue(user_id)
        while not uq.empty():
            try:
                uq.get_nowait()
            except queue.Empty:
                break
            
    except Exception as e:
        logger.error(f"FATAL: Could not clear log file for user {user_id}: {e}")

def stop_user_scan(user_id):
    """
    RC-4 FIX: Safely terminates ONLY the ZAP process owned by this specific user.
    Use this for user-triggered scan cancellation instead of kill_zap_processes().
    """
    with scan_lock:
        entry = active_scans.get(user_id)
    if entry and entry.get("process"):
        entry["process"].terminate()
        log(f"[*] ZAP process for user {user_id} terminated by user request.", user_id)
        return True
    return False

def kill_zap_processes(user_id=None):
    """
    SYSTEM-LEVEL RESET ONLY — Terminates ALL ZAP processes on the machine.

    RC-4 WARNING: This function is GLOBAL and kills every ZAP instance system-wide,
    regardless of which user owns it. It MUST NOT be called from any user-triggered
    code path (e.g. scan start, scan stop, error handlers).
    Only call this on initial server startup/full system reset.
    For per-user cancellation, use stop_user_scan(user_id) instead.
    """
    log("Checking for and terminating existing ZAP processes...", user_id)
    killed_a_process = False
    current_pid = os.getpid()
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['pid'] != current_pid and proc.info['cmdline'] and 'zap.jar' in ' '.join(proc.info['cmdline']).lower():
                log(f"Found ZAP process {proc.name()} (PID: {proc.info['pid']}). Terminating...", user_id)
                proc.kill()
                killed_a_process = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    if not killed_a_process:
        log("No running ZAP processes found.", user_id)
    else:
        log("Waiting 5 seconds for system resources to be released...", user_id)
        time.sleep(5)

# --- ML Prediction ---
from .tctr_engine import tctr_engine

def predict_risk(vulnerability_name: str, description: str = "", cwe_id: str = None):
    try:
        return tctr_engine.predict_risk(vulnerability_name, description, cwe_id=cwe_id)
    except Exception as e:
        logger.error(f"Error predicting risk with TCTR Engine: {e}")
        return 0.5

# --- Path Helper ---
def get_output_paths(output_dir=None, target=None):
    if output_dir:
        base = Path(output_dir)
    else:
        base = Path(DEFAULT_RESULTS_DIR)
    
    if not base.exists():
        try:
            base.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"[!] Error creating directory {base}: {e}")

    if target:
        json_filename = report_manager.generate_report_filename("zap_scanner", target, "json")
        pdf_filename = report_manager.generate_report_filename("zap_scanner", target, "pdf")
        xml_filename = report_manager.generate_report_filename("zap_scanner", target, "xml")
    else:
        json_filename = "zap_report.json"
        pdf_filename = "zap_report.pdf"
        xml_filename = "zap_report.xml"

    return {
        "xml_report": base / xml_filename,
        "json_report": base / json_filename,
        "pdf_report": base / pdf_filename
    }

# --- Core Scan Logic (Simultaneous Support) ---
def run_zap_scan(target_url, report_path, user_id, scan_mode='default'):
    """
    Launches ZAP and streams output to user specific log.
    Supports simultaneous execution by assigning unique ports and directories.
    """
    
    # 1. REMOVED kill_zap_processes to prevent stopping other concurrent scans.
    
    if not os.path.exists(ZAP_EXECUTABLE_PATH):
        log(f"Error: ZAP executable not found at '{ZAP_EXECUTABLE_PATH}'", user_id)
        return False

    # 2. Assign Unique Resources
    unique_zap_dir = ""
    try:
        assigned_port = get_free_port()
        
        # Create a unique directory for this specific scan instance/user in the central temp folder
        # This prevents the "HSQLDB Lock" error
        unique_zap_dir = os.path.join(TEMP_DIR, f"user_{user_id}_{assigned_port}")
        if not os.path.exists(unique_zap_dir):
            os.makedirs(unique_zap_dir, exist_ok=True)

        log(f"\n--- Starting ZAP Scan ({scan_mode.upper()}) (Isolated Instance) ---", user_id, to_console=True)
        log(f"Instance Config -> Port: {assigned_port} | Dir: {unique_zap_dir}", user_id, to_console=True)
        log(f"Target: {target_url}", user_id, to_console=True)
        log(f"Report will be saved to: {report_path}", user_id, to_console=True)

        report_dir = os.path.dirname(report_path)
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)

        # 3. Construct Command with Isolation Flags (-port and -dir)
        if scan_mode == 'spider':
            command = [
                ZAP_EXECUTABLE_PATH, '-cmd',
                '-port', str(assigned_port),
                '-dir', unique_zap_dir,
                '-spider', target_url,
                '-quickout', str(report_path),
                '-quickprogress'
            ]
        else:
            command = [
                ZAP_EXECUTABLE_PATH, '-cmd',
                '-port', str(assigned_port),
                '-dir', unique_zap_dir,
                '-quickurl', target_url,
                '-quickout', str(report_path),
                '-quickprogress'
            ]

        log(f"Executing command: {' '.join(command)}", user_id, to_console=True)
        zap_directory = os.path.dirname(ZAP_EXECUTABLE_PATH)
        
        process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            text=True, 
            encoding='utf-8', 
            errors='replace', 
            cwd=zap_directory,
            bufsize=1 
        )
        
        # Track this user's process
        with scan_lock:
            active_scans[user_id] = {"process": process, "target": target_url, "start_time": time.time()}

        log("--- ZAP Output Stream Started ---", user_id)
        
        # Stream stdout line by line
        for line in iter(process.stdout.readline, ''):
            if line:
                stripped_line = line.strip()
                # --- NOISE FILTER: Extract ZAP Progress Cleanly ---
                # Matches: [                    ] 15% /
                if "%" in stripped_line and "[" in stripped_line and "]" in stripped_line:
                    match = re.search(r'(\d+%)', stripped_line)
                    if match:
                        # Log the original line with [PROGRESS] prefix so UI can parse percent
                        # but still show the original bracket format in terminal
                        log(f"[PROGRESS] {stripped_line}", user_id)
                        continue
                
                if not stripped_line:
                    continue

                # Skip other noisy technical messages but keep important ones
                if any(x in stripped_line.lower() for x in ["copying default", "creating directory", "plugin"]):
                    if "main" in stripped_line: continue

                # We log to file/queue but NOT to console to avoid terminal clutter
                log(stripped_line, user_id, to_console=False)

        process.wait()
        
        # Unregister process
        with scan_lock:
            if user_id in active_scans:
                del active_scans[user_id]

        log("--- End of ZAP Output ---", user_id)

        success = False
        if process.returncode == 0 and os.path.exists(report_path):
            log(f"Scan completed successfully!", user_id, to_console=True)
            success = True
        else:
            log(f"Error: ZAP process failed. Return code: {process.returncode}.", user_id, to_console=True)
            success = False
            
        return success

    except Exception as e:
        log(f"An unexpected error occurred: {e}", user_id)
        return False
        
    finally:
        # 4. CLEANUP: Remove the temporary directory to save space
        if unique_zap_dir and os.path.exists(unique_zap_dir):
            try:
                log(f"Cleaning up temporary ZAP directory: {unique_zap_dir}", user_id)
                shutil.rmtree(unique_zap_dir, ignore_errors=True)
            except Exception as cleanup_error:
                log(f"Warning: Failed to clean up temp dir: {cleanup_error}", user_id)

def parse_zap_xml_report(report_file, user_id=None):
    """Parses ZAP XML and enriches with ML."""
    if not os.path.exists(report_file):
        log(f"Error: ZAP report file not found for parsing: {report_file}", user_id)
        return None
    
    log(f"Parsing ZAP report: {report_file}", user_id)
    
    # Initialize Summary with "Info" key
    report_data = {
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {"High": 0, "Medium": 0, "Low": 0, "Info": 0, "Total": 0},
        "findings": []
    }
    
    try:
        tree = ET.parse(report_file)
        root = tree.getroot()
        
        for alertitem in root.findall('.//alertitem'):
            risk = alertitem.find('riskdesc').text.split(' ')[0] if alertitem.find('riskdesc') is not None else "Info"
            finding_name = alertitem.find('alert').text
            description = get_inner_html(alertitem.find('desc'))
            cwe_id = alertitem.find('cweid').text if alertitem.find('cweid') is not None else None
            
            # TCTREngine handles fallback to name-based CWE mapping if cwe_id is missing or -1
            prediction_obj = predict_risk(finding_name, description, cwe_id=cwe_id)
            predicted_score = prediction_obj["score"]

            finding = {
                "name": finding_name,
                "risk": risk,
                "predicted_risk_score": predicted_score,
                "tctr_priority": prediction_obj["tctr_priority"],
                "base_score": prediction_obj["base_score"],
                "priority_level": prediction_obj["priority_level"],
                "risk_justification": prediction_obj["risk_justification"],
                "confidence": alertitem.find('confidence').text,
                "url": alertitem.find('.//uri').text,
                "description": description,
                "solution": get_inner_html(alertitem.find('solution')),
                "reference": get_inner_html(alertitem.find('reference'))
            }
            
            if risk in report_data["summary"]:
                report_data["summary"][risk] += 1
                report_data["summary"]["Total"] += 1
            
            report_data["findings"].append(finding)
            
        # Sort by predicted score
        report_data["findings"].sort(
            key=lambda x: x['predicted_risk_score'] if isinstance(x['predicted_risk_score'], (int, float)) else -1,
            reverse=True
        )

        log("Report parsed and enriched successfully.", user_id)
        return report_data
    except Exception as e:
        log(f"An error occurred during report parsing: {e}", user_id)
        return None

def get_inner_html(element):
    if element is None: return ""
    return (element.text or '') + ''.join(ET.tostring(e, encoding='unicode') for e in element)

def save_json_report(data, output_dir, user_id=None, target=None):
    try:
        if output_dir:
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            if target:
                filename = report_manager.generate_report_filename("zap_scanner", target, "json")
                json_path = os.path.join(output_dir, filename)
            else:
                json_path = os.path.join(output_dir, "zap_report.json")
        else:
            json_path = os.path.join(DEFAULT_RESULTS_DIR, "zap_report.json")

        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2)
        log(f"JSON report saved to: {json_path}", user_id)
        return json_path
    except Exception as e:
        log(f"Error saving JSON report: {e}", user_id)
        return None