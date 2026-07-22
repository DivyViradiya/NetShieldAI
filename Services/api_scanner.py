import os
import tempfile
import subprocess
import sys
import time
import psutil
import socket
import shutil
import uuid
from core.time_utils import get_now_ist, get_now_ist_str
import xml.etree.ElementTree as ET
import json
import pandas as pd
import joblib
from pathlib import Path
import queue
import threading
from zapv2 import ZAPv2
from Services import report_manager
from Services.anonymity.manager import AnonymityManager

_anon = AnonymityManager()
from Services import scan_logger
from core.logger_setup import logger

def _find_zap_executable():
    env_path = os.environ.get("ZAP_PATH")
    if env_path and os.path.exists(env_path):
        return env_path
    which_zap = shutil.which("zap.sh") or shutil.which("zap")
    if which_zap:
        return which_zap
    mac_paths = [
        "/Applications/OWASP ZAP.app/Contents/Java/zap.sh",
        "/Applications/ZAP.app/Contents/Java/zap.sh",
    ]
    for p in mac_paths:
        if os.path.exists(p):
            return p
    win_path = r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"
    if os.path.exists(win_path):
        return win_path
    return env_path or "zap.sh"

ZAP_EXECUTABLE_PATH = _find_zap_executable()

# --- Path and Logging Setup ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

DEFAULT_RESULTS_DIR = os.path.join(PROJECT_ROOT, ".results", "api_scanner")

LOGS_DIR = os.path.join(PROJECT_ROOT, ".logs")
TEMP_DIR = os.path.join(tempfile.gettempdir(), "NetShieldAI", "api_scanner")

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
def get_output_paths(user_output_dir, user_id=None, target=None, timestamp=None):
    base = Path(user_output_dir)
    scan_uuid = str(uuid.uuid4())[:8]
    temp_xml = Path(TEMP_DIR) / f"api_temp_{user_id if user_id else 'sys'}_{scan_uuid}.xml"
    
    if target:
        if timestamp:
            sanitized = report_manager.sanitize_filename(target)
            stem = f"api_{sanitized}_{timestamp}"
            json_filename = f"{stem}.json"
            pdf_filename = f"{stem}.pdf"
        else:
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
        log(stripped, user_id, level='DEBUG')
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
                    log(f"[SUCCESS] ZAP is active on port {port}.", user_id, level='SUCCESS')
                    return True
            except:
                pass  # Not quite ready yet despite the log message — keep polling

        # Slow path: TCP polling
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                log(f"[SUCCESS] ZAP is active on port {port}.", user_id, level='SUCCESS')
                return True
        except:
            time.sleep(2)

    log(f"[!] ZAP failed to respond on port {port} after {timeout} seconds.", user_id)
    return False


def run_api_scan(target_url, definition_url, report_path, user_id, auth_token=None):
    if not os.path.exists(ZAP_EXECUTABLE_PATH):
        log(f"Error: ZAP executable not found at {ZAP_EXECUTABLE_PATH}", user_id)
        return False

    # Defense-in-depth — catches background/scheduled calls that bypass the BP
    try:
        from Services.target_validator import validate_target, TargetBlockedError
        validate_target(target_url)
    except TargetBlockedError as e:
        log(f"[BLOCKED] Scan rejected by target validator: {e}", user_id, level='ERROR')
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
        log(f"[STAGE] Launching ZAP API daemon on port {assigned_port}...", user_id, level='STAGE')
        log(f"Executing zap command: {' '.join(command)}", user_id, level='DEBUG', to_console=True)
        zap_directory = os.path.dirname(ZAP_EXECUTABLE_PATH)
        
        command.extend(_anon.get_scan_flags("zap"))
        
        if _anon.enabled:
            logger.info(f"[🛡️] Anonymity Mode ACTIVE ({_anon.mode.upper()}). Proxying API scan.")
        else:
            logger.info("[🛡️] Anonymity Mode OFFLINE. API Scanner on direct connection.")

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
                    env=_anon.get_subprocess_env(),
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0
                )
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
            while True:
                try:
                    status = int(zap.spider.status())
                except (ValueError, TypeError):
                    status = 100
                if status >= 100:
                    break
                filled = status // 5
                bracket = "[" + ("=" * filled) + (" " * (20 - filled)) + "]"
                log(f"[PROGRESS] {bracket} {status}%", user_id)
                time.sleep(2)

            log(f"[STAGE] Starting Active Scan...", user_id)
            scan_id = zap.ascan.scan(target_url)

            last_progress = -1
            while True:
                try:
                    current_progress = int(zap.ascan.status(scan_id))
                except (ValueError, TypeError):
                    log(f"[!] Warning: Active scan status unavailable. breaking loop.", user_id)
                    current_progress = 100 # Force exit
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

            log("[SUCCESS] Scan completed successfully!", user_id, level='SUCCESS')
            
            # --- Generate Reports ---
            try:
                from Services import pdf_generator
                report_data = parse_xml_report(report_path, user_id=user_id)
                if report_data:
                    # Deriving metadata for JSON/PDF naming
                    output_dir = os.path.dirname(report_path)
                    target = target_url
                    timestamp = get_now_ist().strftime("%Y%m%d_%H%M%S")
                    
                    # Save JSON
                    save_json_report(report_data, output_dir, user_id=user_id, target=target, timestamp=timestamp)
                    
                    # Ensure target_url is in data for PDF template
                    report_data["target_url"] = target_url
                    
                    # Generate PDF
                    paths = get_output_paths(user_output_dir=output_dir, user_id=user_id, target=target, timestamp=timestamp)
                    pdf_path = paths["pdf_report"]
                    pdf_generator.create_api_report_pdf(report_data, pdf_path, user_id=user_id)
                    
                    log(f"[SUCCESS] API reports (JSON/PDF) generated successfully.", user_id, level='SUCCESS')
            except Exception as e:
                log(f"[!] Error generating API reports: {e}", user_id, level='ERROR')
            
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
        "scan_date": get_now_ist_str(),
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
        # File removal is now managed by the BP or final cleanup tasks to avoid race conditions.
        pass

def save_json_report(data, output_dir, user_id=None, target=None, timestamp=None):
    try:
        os.makedirs(output_dir, exist_ok=True)
        paths = get_output_paths(user_output_dir=output_dir, user_id=user_id, target=target, timestamp=timestamp)
        json_path = paths["json_report"]
        with open(json_path, 'w') as f: json.dump(data, f, indent=2)
        return str(json_path)
    except: return None

