import subprocess
import os
import shutil
import json
import uuid
import zipfile
import queue
import threading
import platform
import sys
from datetime import datetime
from pathlib import Path

# --- Configuration ---
BASE_DIR = Path(__file__).parent.parent
DEFAULT_RESULTS_DIR = BASE_DIR / "Services" / "results" / "semgrep_scanner"
LOG_DIR = BASE_DIR / "logs"
TEMP_DIR = BASE_DIR / "Services" / "temp" / "semgrep"

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

# --- Logging & Events ---
def log(message, user_id=None, to_console=False):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"data: [{timestamp}] {message}\n\n"
    if to_console: print(f"[{timestamp}] {message}")
    
    if user_id:
        user_id = str(user_id)
        uq = get_user_queue(user_id)
        uq.put(message)
        log_dir = LOG_DIR / "users" / user_id
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "semgrep_agent_log.txt"
    else:
        log_path = LOG_DIR / "system" / "semgrep_system_log.txt"

    try:
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {message}\n")
    except: pass

def send_sse_event(event_name, data="", user_id=None):
    if isinstance(data, (dict, list)): data_str = json.dumps(data)
    else: data_str = str(data)
    sse_message = f"event: {event_name}\ndata: {data_str}\n\n"
    if user_id:
        uq = get_user_queue(user_id)
        uq.put(sse_message)

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

def get_output_paths(output_dir=None, user_id=None):
    base = Path(output_dir) if output_dir else DEFAULT_RESULTS_DIR
    user_temp = TEMP_DIR / (user_id if user_id else "default")
    user_temp.mkdir(parents=True, exist_ok=True)
    
    # Multi-user unique raw report
    scan_uuid = str(uuid.uuid4())[:8]
    
    return {
        "raw_json": user_temp / f"semgrep_raw_{scan_uuid}.json",
        "parsed_json": base / "semgrep_report.json",
        "source_code": user_temp / f"source_{scan_uuid}"
    }

def run_semgrep_scan(target_input, input_type="zip", output_dir=None, user_id=None):
    semgrep_cmd = get_semgrep_path()
    if not semgrep_cmd: return None

    paths = get_output_paths(output_dir, user_id)
    source_dir = paths["source_code"]
    raw_report_path = paths["raw_json"]

    # Track active scan
    with scan_lock:
        active_scans[user_id] = {"target": str(target_input), "start_time": time.time()}

    source_dir.mkdir(parents=True, exist_ok=True)
    try:
        if input_type == "zip":
            with zipfile.ZipFile(target_input, 'r') as z: z.extractall(source_dir)
        elif input_type == "git":
            subprocess.run(["git", "clone", "--depth", "1", target_input, str(source_dir)], check=True, capture_output=True, text=True, encoding='utf-8')
        
        cmd = [semgrep_cmd, "scan", "--json", "--output", str(raw_report_path), "--config", "p/security-audit", str(source_dir)]
        subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')

        if not raw_report_path.exists(): return None
        return parse_semgrep_results(raw_report_path, output_dir, user_id)
    except Exception as e:
        log(f"Scan Error: {e}", user_id)
        return None
    finally:
        with scan_lock:
            if user_id in active_scans:
                del active_scans[user_id]
        if source_dir.exists(): shutil.rmtree(source_dir, ignore_errors=True)
        if raw_report_path.exists(): raw_report_path.unlink()

def parse_semgrep_results(raw_json_path, output_dir=None, user_id=None):
    paths = get_output_paths(output_dir, user_id)
    output_file = paths["parsed_json"]
    try:
        with open(raw_json_path, 'r', encoding='utf-8') as f: data = json.load(f)
        report = {"scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "findings": []}
        if 'results' in data:
            for r in data['results']:
                report["findings"].append({"check_id": r.get('check_id'), "path": r.get('path'), "message": r['extra'].get('message')})
        report["total_findings"] = len(report["findings"])
        with open(output_file, 'w', encoding='utf-8') as f: json.dump(report, f, indent=4)
        return str(output_file)
    except: return None
