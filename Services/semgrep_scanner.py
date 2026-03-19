import subprocess
import tempfile
import os
import shutil
import json
import uuid
import zipfile
import queue
import threading
import platform
import sys
import time
from datetime import datetime
from pathlib import Path
from Services import report_manager
from .tctr_engine import tctr_engine

# --- Configuration ---
BASE_DIR = Path(__file__).parent.parent
DEFAULT_RESULTS_DIR = BASE_DIR / "results" / "semgrep_scanner"
LOG_DIR = BASE_DIR / "logs"
TEMP_DIR = Path(tempfile.gettempdir()) / "NetShieldAI" / "semgrep"

# --- Global State for Process Management (Isolated by user_id) ---
active_scans = {} # { "user_id": {"target": str, "start_time": float} }
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

from Services import scan_logger
from core.logger_setup import logger

# --- Logging & Events ---
def log(message, user_id=None, to_console=False, level='INFO'):
    """
    Logs messages using the centralized scan_logger.
    """
    if to_console:
        if level == 'INFO':
            logger.info(message)
        elif level == 'WARNING':
            logger.warning(message)
        elif level == 'ERROR':
            logger.error(message)
        else:
            logger.debug(message)
    
    if user_id:
        scan_logger.write_log(user_id, "semgrep_scanner", message, level=level)

def send_sse_event(event_name, data="", user_id=None):
    """
    Simulates SSE event by logging a special format line that tail_log_file can pick up.
    """
    if isinstance(data, (dict, list)): data_str = json.dumps(data)
    else: data_str = str(data)
    
    log(f"EVENT: {event_name} | PAYLOAD: {data_str}", user_id)

def clear_log_file(user_id):
    if not user_id: return
    user_id = str(user_id)
    try:
        log_path = LOG_DIR / "users" / user_id / "semgrep_agent_log.txt"
        if log_path.exists():
            with open(log_path, 'w', encoding='utf-8') as f: f.write("")
        uq = get_user_queue(user_id)
        with uq.mutex: uq.queue.clear()
    except: pass

def get_semgrep_path():
    if shutil.which("semgrep"): return "semgrep"
    possible = [os.path.join(sys.prefix, 'Scripts', 'semgrep.exe'), os.path.join(sys.prefix, 'bin', 'semgrep')]
    for p in possible:
        if os.path.exists(p): return p
    return None

def get_output_paths(output_dir=None, user_id=None, target=None, timestamp=None):
    base = Path(output_dir) if output_dir else DEFAULT_RESULTS_DIR
    user_temp = TEMP_DIR / (user_id if user_id else "default")
    user_temp.mkdir(parents=True, exist_ok=True)
    
    # Multi-user unique raw report
    scan_uuid = str(uuid.uuid4())[:8]
    
    if target:
        if timestamp:
            sanitized = report_manager.sanitize_filename(target)
            stem = f"semgrep_{sanitized}_{timestamp}"
            json_filename = f"{stem}.json"
            pdf_filename = f"{stem}.pdf"
        else:
            json_filename = report_manager.generate_report_filename("semgrep_scanner", target, "json")
            pdf_filename = report_manager.generate_report_filename("semgrep_scanner", target, "pdf")
    else:
        json_filename = "semgrep_report.json"
        pdf_filename = "semgrep_report.pdf"

    return {
        "raw_json": user_temp / f"semgrep_raw_{scan_uuid}.json",
        "parsed_json": base / json_filename,
        "pdf_report": base / pdf_filename,
        "source_code": user_temp / f"source_{scan_uuid}"
    }

def run_semgrep_scan(target_input, input_type="zip", output_dir=None, user_id=None, target=None):
    semgrep_cmd = get_semgrep_path()
    if not semgrep_cmd: return None

    paths = get_output_paths(output_dir, user_id)
    source_dir = paths["source_code"]
    raw_report_path = paths["raw_json"]

    # Track active scan
    with scan_lock:
        active_scans[user_id] = {"target": str(target_input), "start_time": time.time()}

    # Defense-in-depth Target Validation for Git URLs
    if input_type == "git":
        try:
            from Services.target_validator import validate_target, TargetBlockedError
            validate_target(target_input)
        except TargetBlockedError as e:
            log(f"[BLOCKED] Scan rejected by target validator for {target_input}: {e}", user_id, level='ERROR')
            return None

    source_dir.mkdir(parents=True, exist_ok=True)
    try:
        if input_type == "zip":
            with zipfile.ZipFile(target_input, 'r') as z:
                file_count = len(z.namelist())
                log(f"[*] Extracting {file_count} files from zip...", user_id)
                z.extractall(source_dir)
        elif input_type == "git":
            log(f"[*] Cloning repository: {target_input}", user_id)
            subprocess.run(["git", "clone", "--depth", "1", target_input, str(source_dir)], check=True, capture_output=True, text=True, encoding='utf-8')
        
        cmd = [semgrep_cmd, "scan", "--json", "--output", str(raw_report_path), 
               "--config", "p/ci", "--config", "p/security-audit", 
               "--config", "p/secrets", "--config", "p/python", 
               "--no-git-ignore", 
               "."] # Scan extracted source root
        
        log("Starting Semgrep static analysis...", user_id, level='STAGE')
        # Force UTF-8 for subprocess to prevent UnicodeEncodeError on Windows
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        
        start_time = time.time()
        # Use cwd to ensure relative paths in output
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', cwd=str(source_dir), env=env)
        scan_duration = time.time() - start_time
        log(f"Semgrep engine finished in {scan_duration:.1f}s.", user_id, level='INFO')

        # Log Semgrep's summary from stderr (contains file count and finding summary)
        if result.stderr:
            # Filter out noisy lines, keep the summary
            summary_lines = [l for l in result.stderr.splitlines() if "Scan info" in l or "Findings" in l or "Scanned" in l]
            for line in summary_lines:
                log(f"[Semgrep] {line.strip()}", user_id)

        if result.returncode != 0 and not raw_report_path.exists():
            log(f"[!] Semgrep engine error (Code {result.returncode}): {result.stderr}", user_id)
            return None

        if not raw_report_path.exists(): 
            log(f"[!] Semgrep finished but no results file was generated.", user_id)
            return None
            
        return parse_semgrep_results(raw_report_path, output_dir, user_id, target=target, scan_duration=scan_duration)
    except Exception as e:
        log(f"Scan Error: {e}", user_id)
        return None
    finally:
        with scan_lock:
            if user_id in active_scans:
                del active_scans[user_id]
        if source_dir.exists(): shutil.rmtree(source_dir, ignore_errors=True)
        if raw_report_path.exists(): raw_report_path.unlink()

def parse_semgrep_results(raw_json_path, output_dir=None, user_id=None, target=None, scan_duration=None):
    paths = get_output_paths(output_dir, user_id, target=target)
    output_file = paths["parsed_json"]
    try:
        with open(raw_json_path, 'r', encoding='utf-8') as f: 
            data = json.load(f)
        
        report = {
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tool": "Semgrep OSS",
            "target": target or "Unknown",
            "scan_duration": scan_duration,
            "total_findings": 0,
            "severity_counts": {"ERROR": 0, "WARNING": 0, "INFO": 0},
            "findings": []
        }

        if 'results' in data:
            for r in data['results']:
                extra = r.get('extra', {})
                severity = extra.get('severity', 'INFO').upper()
                
                # Update Counts
                if severity in report["severity_counts"]:
                    report["severity_counts"][severity] += 1
                else:
                    report["severity_counts"]["INFO"] += 1

                finding = {
                    "check_id": r.get('check_id'),
                    "path": r.get('path'),
                    "line": r.get('start', {}).get('line'),
                    "column": r.get('start', {}).get('col'),
                    "message": extra.get('message'),
                    "severity": severity,
                    "code_snippet": extra.get('lines'),
                    "fix_suggestion": extra.get('fix')
                }
                report["findings"].append(finding)
        
        report["total_findings"] = len(report["findings"])
        
        # Apply ML Threat Re-ranking
        try:
            for finding in report["findings"]:
                # Try to extract CWE from message or check_id
                cwe_id = None
                if finding.get("check_id"):
                    cwe_match = re.search(r'cwe-(\d+)', finding["check_id"].lower())
                    if cwe_match:
                        cwe_id = cwe_match.group(1)
                
                prediction_obj = tctr_engine.predict_risk(
                    finding["check_id"], 
                    finding["message"], 
                    cwe_id=cwe_id
                )
                finding["predicted_risk_score"] = prediction_obj["score"]
                finding["tctr_priority"] = prediction_obj["tctr_priority"]
                finding["base_score"] = prediction_obj["base_score"]
                finding["priority_level"] = prediction_obj["priority_level"]
                finding["risk_justification"] = prediction_obj["risk_justification"]
            
            # Sort by predicted score
            report["findings"].sort(
                key=lambda x: x.get('predicted_risk_score', 0),
                reverse=True
            )
        except Exception as e:
            log(f"ML Re-ranking failed for Semgrep: {e}", user_id)
        
        with open(output_file, 'w', encoding='utf-8') as f: 
            json.dump(report, f, indent=4)
        return str(output_file)
    except Exception as e:
        log(f"Error parsing results: {e}", user_id)
        return None
