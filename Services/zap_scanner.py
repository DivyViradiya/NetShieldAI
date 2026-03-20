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
from core.logger_setup import logger
from Services import report_manager, scan_logger
from Services.anonymity.manager import AnonymityManager
from Services.target_validator import validate_target, TargetBlockedError
from Services.process_manager import process_manager

_anon = AnonymityManager()

# --- Configuration ---
ZAP_EXECUTABLE_PATH = os.environ.get("ZAP_PATH", r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat")

# --- Path and Logging Setup ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

import tempfile

DEFAULT_RESULTS_DIR = os.path.join(PROJECT_ROOT, ".results", "zap_scanner")

LOGS_DIR = os.path.join(PROJECT_ROOT, ".logs")
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR, exist_ok=True)

# [FIX] Move temp dir outside project root to prevent Flask reloader triggering on heavy writes
TEMP_DIR = os.path.join(tempfile.gettempdir(), "NetShieldAI", "zap")
if not os.path.exists(TEMP_DIR):
    os.makedirs(TEMP_DIR, exist_ok=True)

# --- Global State for Process Management (Isolated by user_result_dir) ---
# [NEW] Using ProcessManager for global tracking. 
# Keeping active_scans for local state (target, start_time) only.
active_scans = {} # { "user_result_dir": {"target": str, "start_time": float} }
scan_lock = threading.Lock()

# --- USER ISOLATION: Dictionary to hold a queue for each user_result_dir ---
user_queues = {}
_queue_lock = threading.Lock()  # RC-1 FIX: protect concurrent queue creation

def get_user_queue(user_result_dir):
    """Ensures a queue exists for the user and returns it. Thread-safe."""
    with _queue_lock:
        if user_result_dir not in user_queues:
            user_queues[user_result_dir] = queue.Queue()
        return user_queues[user_result_dir]

def is_scan_running(user_result_dir):
    """Checks if a scan is currently active for a specific user."""
    with scan_lock:
        return user_result_dir in active_scans

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

def log(message, user_result_dir=None, to_console=False, level='INFO'):
    """
    Logs messages to:
    1. System Console (optional)
    2. User-specific log file via scan_logger
    3. User-specific Memory Queue (for real-time frontend fallback)
    """
    if to_console:
        if level.upper() in ('ERROR', 'CRITICAL'):
            logger.error(message)
        elif level.upper() == 'WARNING':
            logger.warning(message)
        else:
            logger.info(message)
    
    if user_result_dir:
        scan_logger.write_log(user_result_dir, "zap_scanner", message, level=level)
        # Keep queue for backward compatibility if the frontend polls it
        uq = get_user_queue(user_result_dir)
        uq.put(message)

def clear_log_file(user_result_dir):
    """Clears the log file and queue for a specific user."""
    if not user_result_dir: return
    user_result_dir = str(user_result_dir)
    user_log_file = os.path.join(LOGS_DIR, "users", user_result_dir, "zap_agent_log.txt")
    
    try:
        if os.path.exists(user_log_file):
            with open(user_log_file, 'w', encoding='utf-8') as f:
                f.write(f"--- Log cleared at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
        
        # RC-11 FIX: Drain queue using public API instead of internal mutex/queue attributes
        uq = get_user_queue(user_result_dir)
        while not uq.empty():
            try:
                uq.get_nowait()
            except queue.Empty:
                break
            
    except Exception as e:
        logger.error(f"FATAL: Could not clear log file for user {user_result_dir}: {e}")

def stop_user_scan(user_result_dir):
    """
    RC-4 FIX: Safely terminates ONLY the ZAP process owned by this specific user via global ProcessManager.
    """
    success = process_manager.stop_user_tool(user_result_dir, "zap")
    if success:
        log(f"[*] ZAP process for user {user_result_dir} terminated by user request.", user_result_dir)
    return success

def kill_zap_processes(user_result_dir=None):
    """
    SYSTEM-LEVEL RESET ONLY — Use with caution.
    For per-user cancellation, use stop_user_scan(user_result_dir) instead.
    """
    log("Requesting system-wide ZAP cleanup...", user_result_dir)
    process_manager.cleanup_all()

# --- ML Prediction ---
from .tctr_engine import tctr_engine

def predict_risk(vulnerability_name: str, description: str = "", cwe_id: str = None):
    try:
        return tctr_engine.predict_risk(vulnerability_name, description, cwe_id=cwe_id)
    except Exception as e:
        logger.error(f"Error predicting risk with TCTR Engine: {e}")
        return 0.5

# --- Path Helper ---
def get_output_paths(output_dir=None, target=None, timestamp=None):
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
        # Consistency Logic: If a timestamp is provided, use it for all formats.
        if timestamp:
            sanitized = report_manager.sanitize_filename(target)
            json_filename = f"zap_{sanitized}_{timestamp}.json"
            pdf_filename = f"zap_{sanitized}_{timestamp}.pdf"
            xml_filename = f"zap_{sanitized}_{timestamp}.xml"
        else:
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
def run_zap_scan(target_url, report_path, user_result_dir, scan_mode='default'):
    """
    Launches ZAP and streams output to user specific log.
    Supports simultaneous execution by assigning unique ports and directories.
    """
    # Defense-in-depth — catches background/scheduled calls that bypass the BP
    try:
        validate_target(target_url)
    except TargetBlockedError as e:
        log(f"[BLOCKED] Scan rejected by target validator: {e}", user_result_dir, level='ERROR')
        return False
        
    # 1. REMOVED kill_zap_processes to prevent stopping other concurrent scans.
    
    if not os.path.exists(ZAP_EXECUTABLE_PATH):
        log(f"Error: ZAP executable not found at '{ZAP_EXECUTABLE_PATH}'", user_result_dir)
        return False

    # 2. Assign Unique Resources
    unique_zap_dir = ""
    try:
        assigned_port = get_free_port()
        
        # Create a unique directory for this specific scan instance/user in the central temp folder
        # This prevents the "HSQLDB Lock" error
        unique_zap_dir = os.path.join(TEMP_DIR, f"user_{user_result_dir}_{assigned_port}")
        if not os.path.exists(unique_zap_dir):
            os.makedirs(unique_zap_dir, exist_ok=True)

        log(f"\n--- Starting ZAP Scan ({scan_mode.upper()}) (Isolated Instance) ---", user_result_dir, to_console=True)
        log(f"[STAGE] Starting ZAP ({scan_mode.upper()}) scan on {target_url}...", user_result_dir, level='STAGE')
        log(f"Instance Config -> Port: {assigned_port} | Dir: {unique_zap_dir}", user_result_dir, to_console=True, level='DEBUG')
        log(f"Target: {target_url}", user_result_dir, to_console=True, level='DEBUG')
        log(f"Report will be saved to: {report_path}", user_result_dir, to_console=True, level='DEBUG')

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

        log(f"[STAGE] Launching ZAP daemon...", user_result_dir, level='STAGE')
        log(f"Executing command: {' '.join(command)}", user_result_dir, level='DEBUG', to_console=True)
        zap_directory = os.path.dirname(ZAP_EXECUTABLE_PATH)
        
        command.extend(_anon.get_scan_flags("zap"))
        
        if _anon.enabled:
            logger.info(f"[🛡️] Anonymity Mode ACTIVE ({_anon.mode.upper()}). Forcing ZAP through proxy.")
        else:
            logger.info("[🛡️] Anonymity Mode OFFLINE. ZAP executing from direct connection.")
        
        with _anon.apply():
            with scan_lock:
                process = subprocess.Popen(
                    command, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.STDOUT,
                    text=True, 
                    encoding='utf-8', 
                    errors='replace', 
                    cwd=zap_directory,
                    bufsize=1,
                    env=_anon.get_subprocess_env() 
                )
                # Track this user's process globally for cleanup
                process_manager.register(user_result_dir, "zap", process)
                # Track this user's process locally for metadata
                active_scans[user_result_dir] = {"target": target_url, "start_time": time.time()}

            log("--- ZAP Output Stream Started ---", user_result_dir)
            
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
                            log(f"[PROGRESS] {stripped_line}", user_result_dir)
                            continue
                    
                    if not stripped_line:
                        continue

                    # Skip other noisy technical messages but keep important ones
                    if any(x in stripped_line.lower() for x in ["copying default", "creating directory", "plugin"]):
                        if "main" in stripped_line: continue

                    # We log to file/queue but NOT to console to avoid terminal clutter
                    log(stripped_line, user_result_dir, to_console=False, level='DEBUG')

            process.wait()
        
        # Unregister process from all trackers
        process_manager.unregister(user_result_dir, "zap")
        with scan_lock:
            if user_result_dir in active_scans:
                del active_scans[user_result_dir]

        log("--- End of ZAP Output ---", user_result_dir)

        success = False
        if process.returncode == 0 and os.path.exists(report_path):
            log(f"[SUCCESS] ZAP scan complete.", user_result_dir, level='SUCCESS', to_console=True)
            success = True
        else:
            log(f"Error: ZAP process failed. Return code: {process.returncode}.", user_result_dir, to_console=True)
            success = False
            
        return success

    except Exception as e:
        log(f"An unexpected error occurred: {e}", user_result_dir)
        return False
        
    finally:
        # 4. CLEANUP: Remove the temporary directory to save space
        if unique_zap_dir and os.path.exists(unique_zap_dir):
            try:
                log(f"Cleaning up temporary ZAP directory: {unique_zap_dir}", user_result_dir)
                shutil.rmtree(unique_zap_dir, ignore_errors=True)
            except Exception as cleanup_error:
                log(f"Warning: Failed to clean up temp dir: {cleanup_error}", user_result_dir)

def parse_zap_xml_report(report_file, user_result_dir=None):
    """Parses ZAP XML and enriches with ML."""
    if not os.path.exists(report_file):
        log(f"Error: ZAP report file not found for parsing: {report_file}", user_result_dir)
        return None
    
    log(f"Parsing ZAP report: {report_file}", user_result_dir)
    
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

        log("Report parsed and enriched successfully.", user_result_dir)
        return report_data
    except Exception as e:
        log(f"An error occurred during report parsing: {e}", user_result_dir)
        return None

def get_inner_html(element):
    if element is None: return ""
    return (element.text or '') + ''.join(ET.tostring(e, encoding='unicode') for e in element)

def save_json_report(data, output_dir, user_result_dir=None, target=None, timestamp=None):
    try:
        paths = get_output_paths(output_dir=output_dir, target=target, timestamp=timestamp)
        json_path = paths["json_report"]

        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2)
        log(f"JSON report saved to: {json_path}", user_result_dir)
        return str(json_path)
    except Exception as e:
        log(f"Error saving JSON report: {e}", user_result_dir)
        return None

