import os
import subprocess
import sys
import time
import psutil
import socket
import shutil
import uuid
from datetime import datetime
import xml.etree.ElementTree as ET
import json
import pandas as pd
import joblib
from pathlib import Path
import queue
import threading
from zapv2 import ZAPv2
from Services import report_manager
from Services import scan_logger
from core.logger_setup import logger

# --- Configuration ---
ZAP_EXECUTABLE_PATH = r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"

# --- Path and Logging Setup ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

DEFAULT_RESULTS_DIR = os.path.join(PROJECT_ROOT, "results", "api_scanner")

LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
TEMP_DIR = os.path.join(BASE_DIR, "temp", "api_scanner")

# --- Global State for Process Management ---
active_scans = {} 
scan_lock = threading.Lock()

# --- USER ISOLATION ---
user_queues = {}

def get_user_queue(user_id):
    if user_id not in user_queues:
        user_queues[user_id] = queue.Queue()
    return user_queues[user_id]

def is_scan_running(user_id):
    """Checks if a scan is currently active for a specific user."""
    with scan_lock:
        return user_id in active_scans

# --- LOGGING FUNCTIONS ---
def log(message, user_id=None, to_console=False, level='INFO'):
    """
    Logs messages using the centralized scan_logger.
    """
    if to_console:
        if level.upper() == 'ERROR' or level.upper() == 'CRITICAL':
            logger.error(message)
        elif level.upper() == 'WARNING':
            logger.warning(message)
        else:
            logger.info(message)
    
    if user_id:
        scan_logger.write_log(user_id, "api_scanner", message, level=level)

def clear_log_file(user_id):
    if not user_id: return
    log_file = scan_logger.get_active_log_file(user_id, "api")
    try:
        open(log_file, 'w').close()
    except:
        pass

# --- ML Prediction ---
from .tctr_engine import tctr_engine

def predict_risk(vulnerability_name: str, description: str = "", cwe_id: str = None):
    try:
        return tctr_engine.predict_risk(vulnerability_name, description, cwe_id=cwe_id)
    except Exception as e:
        logger.error(f"Error predicting risk with TCTR Engine: {e}")
        return {
            "score": 0.5,
            "tctr_priority": 0.0,
            "base_score": 5.0,
            "priority_level": "P2 (Medium)",
            "risk_justification": "Fallback due to prediction error"
        }

# --- Path Helper ---
def get_output_paths(user_output_dir, user_id=None, target=None):
    base = Path(user_output_dir)
    scan_uuid = str(uuid.uuid4())[:8]
    temp_xml = Path(TEMP_DIR) / f"api_temp_{user_id if user_id else 'sys'}_{scan_uuid}.xml"
    
    if target:
        json_filename = report_manager.generate_report_filename("api_scanner", target, "json")
        pdf_filename = report_manager.generate_report_filename("api_scanner", target, "pdf")
    else:
        json_filename = "api_scan_report.json"
        pdf_filename = "api_scan_report.pdf"

    return {
        "xml_report": temp_xml,
        "json_report": base / json_filename,
        "pdf_report": base / pdf_filename
    }

# --- API Authentication and GraphQL Helpers ---

def setup_api_auth(zap, auth_token=None, user_id=None):
    if not auth_token:
        return

    try:
        log(f"[AUTH] Configuring Token-Based Auth (Bearer/API-Key)...", user_id)
        zap.replacer.set_enabled('true')
        zap.replacer.add_rule(
            description='API_Auth_Token',
            enabled='true',
            matchtype='REQ_HEADER',
            matchregex='false',
            matchstring='Authorization',
            replacement=f"Bearer {auth_token}" if not auth_token.startswith("Bearer ") else auth_token,
            initiators=''
        )
        log(f"[AUTH] Header injection rule added.", user_id)
    except Exception as e:
        log(f"[!] Error setting up API Auth: {e}", user_id)

# --- Core API Scan Logic ---

def _stream_zap_output(process, user_id, ready_event, port):
    """Background thread: streams ZAP stdout, logs it, and signals when ZAP is ready."""
    for line in iter(process.stdout.readline, ''):
        stripped = line.strip()
        if not stripped:
            continue
        log(stripped, user_id)
        # ZAP logs this when it's fully up and listening
        if (f":{port}" in stripped and "listen" in stripped.lower()) or \
           "ZAP is now listening" in stripped or \
           "Started" in stripped and str(port) in stripped:
            ready_event.set()
    process.stdout.close()


def wait_for_zap(port, timeout=240, user_id=None, ready_event=None):
    """Waits for ZAP to accept connections. Uses ready_event for early detection if available."""
    start_time = time.time()
    log(f"[*] Waiting for ZAP on port {port} (timeout: {timeout}s)...", user_id)
    while time.time() - start_time < timeout:
        # Fast path: output thread detected the listening message
        if ready_event and ready_event.is_set():
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=2):
                    log(f"[+] ZAP is active on port {port}.", user_id)
                    return True
            except:
                pass  # Not quite ready yet despite the log message — keep polling

        # Slow path: TCP polling
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                log(f"[+] ZAP is active on port {port}.", user_id)
                return True
        except:
            time.sleep(2)

    log(f"[!] ZAP failed to respond on port {port} after {timeout} seconds.", user_id)
    return False


def run_api_scan(target_url, definition_url, report_path, user_id, auth_token=None):
    if not os.path.exists(ZAP_EXECUTABLE_PATH):
        log(f"Error: ZAP executable not found at {ZAP_EXECUTABLE_PATH}", user_id)
        return False

    # Get a free port (same pattern as zap_scanner.py)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        assigned_port = s.getsockname()[1]

    unique_zap_dir = os.path.join(TEMP_DIR, f"user_{user_id}_{assigned_port}")
    os.makedirs(unique_zap_dir, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)

    log(f"--- Initializing API Scanner (Port: {assigned_port}) ---", user_id, to_console=True)
    log(f"[*] Target: {target_url} | Definition: {definition_url}", user_id)

    command = [
        ZAP_EXECUTABLE_PATH,
        '-daemon',
        '-silent',          # Skip GUI component init — much faster startup
        '-port', str(assigned_port),
        '-dir', unique_zap_dir,
        '-config', 'api.disablekey=true',
        '-config', 'api.addrs.addr.name=.*',
        '-config', 'api.addrs.addr.regex=true',
        '-config', 'connection.timeoutInSecs=10',
    ]

    process = None
    zap = None
    reader_thread = None
    ready_event = threading.Event()

    try:
        log(f"[*] Launching ZAP daemon...", user_id, to_console=True)

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace',
            cwd=os.path.dirname(ZAP_EXECUTABLE_PATH),
            bufsize=1,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0
        )

        with scan_lock:
            active_scans[user_id] = {"process": process, "target": target_url, "start_time": time.time()}

        # Stream ZAP output in background so we can detect readiness from its logs
        reader_thread = threading.Thread(
            target=_stream_zap_output,
            args=(process, user_id, ready_event, assigned_port),
            daemon=True
        )
        reader_thread.start()

        if not wait_for_zap(assigned_port, timeout=240, user_id=user_id, ready_event=ready_event):
            log(f"[!] ZAP did not start. Check ZAP installation at: {ZAP_EXECUTABLE_PATH}", user_id, level='ERROR')
            return False

        log(f"[*] Connecting to ZAP API on port {assigned_port}...", user_id)
        zap = ZAPv2(proxies={
            'http': f'http://127.0.0.1:{assigned_port}',
            'https': f'http://127.0.0.1:{assigned_port}'
        })

        if auth_token:
            setup_api_auth(zap, auth_token, user_id)

        # Import API definition
        if "graphql" in definition_url.lower() or "graphql" in target_url.lower():
            log("[STAGE] Importing GraphQL Schema...", user_id)
            zap.graphql.import_url(definition_url)
        else:
            log("[STAGE] Importing OpenAPI Definition...", user_id)
            zap.openapi.import_url(definition_url)

        time.sleep(2)

        log(f"[STAGE] Starting Web Spider...", user_id)
        zap.spider.scan(target_url)
        while int(zap.spider.status()) < 100:
            status = int(zap.spider.status())
            filled = status // 5
            bracket = "[" + ("=" * filled) + (" " * (20 - filled)) + "]"
            log(f"[PROGRESS] {bracket} {status}%", user_id)
            time.sleep(2)

        log(f"[STAGE] Starting Active Scan...", user_id)
        scan_id = zap.ascan.scan(target_url)

        last_progress = -1
        while True:
            current_progress = int(zap.ascan.status(scan_id))
            if current_progress > last_progress:
                filled = current_progress // 5
                bracket = "[" + ("=" * filled) + (" " * (20 - filled)) + "]"
                log(f"[PROGRESS] {bracket} {current_progress}%", user_id)
                last_progress = current_progress
            if current_progress >= 100:
                break
            time.sleep(5)

        log("Generating XML report...", user_id)
        xml_report = zap.core.xmlreport()
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(xml_report)
        return True

    except Exception as e:
        log(f"Scan Error: {e}", user_id, level='ERROR')
        return False
    finally:
        with scan_lock:
            if user_id in active_scans:
                del active_scans[user_id]
        if zap:
            try: zap.core.shutdown()
            except: pass
        if process:
            process.terminate()
            try: process.wait(timeout=5)
            except: process.kill()
        if os.path.exists(unique_zap_dir):
            shutil.rmtree(unique_zap_dir, ignore_errors=True)


def parse_xml_report(report_file, user_id=None):
    if not os.path.exists(report_file): return None
    report_data = {
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {"High": 0, "Medium": 0, "Low": 0, "Info": 0, "Total": 0},
        "findings": []
    }
    try:
        tree = ET.parse(report_file)
        root = tree.getroot()
        for alert in root.findall('.//alertitem'):
            risk = alert.find('riskdesc').text.split(' ')[0] if alert.find('riskdesc') is not None else "Info"
            finding_name = alert.find('alert').text
            desc_text = alert.find('desc').text if alert.find('desc') is not None else ""
            cwe_id = alert.find('cweid').text if alert.find('cweid') is not None else None
            
            # predicted_score = predict_risk(finding_name, desc_text, cwe_id=cwe_id)
            prediction_obj = predict_risk(finding_name, desc_text, cwe_id=cwe_id)
            predicted_score = prediction_obj["score"]
            
            finding = {
                "name": finding_name, 
                "risk": risk,
                "predicted_risk_score": predicted_score,
                "tctr_priority": prediction_obj["tctr_priority"],
                "base_score": prediction_obj["base_score"],
                "priority_level": prediction_obj["priority_level"],
                "risk_justification": prediction_obj["risk_justification"],
                "url": alert.find('.//uri').text, 
                "method": alert.find('.//method').text or "GET",
                "description": desc_text
            }
            if risk in report_data["summary"]:
                report_data["summary"][risk] += 1
                report_data["summary"]["Total"] += 1
            report_data["findings"].append(finding)
            
        report_data["findings"].sort(
            key=lambda x: x['predicted_risk_score'] if isinstance(x['predicted_risk_score'], (int, float)) else -1,
            reverse=True
        )
        return report_data
    except Exception as e:
        logger.error(f"Error parse_xml_report: {e}")
        return None
    finally:
        if os.path.exists(report_file): os.remove(report_file)

def save_json_report(data, output_dir, user_id=None, target=None):
    try:
        os.makedirs(output_dir, exist_ok=True)
        if target:
            filename = report_manager.generate_report_filename("api_scanner", target, "json")
            json_path = os.path.join(output_dir, filename)
        else:
            json_path = os.path.join(output_dir, "api_scan_report.json")
        with open(json_path, 'w') as f: json.dump(data, f, indent=2)
        return json_path
    except: return None
