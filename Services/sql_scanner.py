import subprocess
import os
import sys
import threading
import queue
import time
import json
import re
from datetime import datetime
from pathlib import Path

# --- CONFIGURATION ---
# BASE_DIR should be at the root of the project (one level up from Services folder)
BASE_DIR = Path(__file__).parent.parent
# Path to your SQLMap script
SQLMAP_PATH = Path(r"D:\SQLmap_setup\sqlmap.py")

# Default Fallback Directory
DEFAULT_RESULTS_DIR = BASE_DIR / "Services" / "results" / "sql_scanner"

# Logs (Shared)
LOG_FILE = BASE_DIR / "logs" / "sql_agent_log.txt"

TEMP_DIR = BASE_DIR / "Services" / "temp" / "sqlmap"
TEMP_DIR.mkdir(parents=True, exist_ok=True)

# --- Global State for Process Management (Isolated by user_id) ---
active_scans = {} # { "user_id": {"process": Popen, "target": str, "start_time": float} }
scan_lock = threading.Lock()

# --- USER ISOLATION ---
user_queues = {}

def get_user_queue(user_id):
    """Ensures a queue exists for the user and returns it."""
    if user_id not in user_queues:
        user_queues[user_id] = queue.Queue()
    return user_queues[user_id]

def is_scan_running(user_id):
    """Checks if a scan is currently active for a specific user."""
    with scan_lock:
        return user_id in active_scans

# --- LOGGING UTILS ---
def log(message, user_id=None, to_console=False):
    """Logs messages to queue for SSE streaming and file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"data: [{timestamp}] {message}\n\n"
    
    if to_console:
        print(f"[{timestamp}] {message}")
    
    if user_id:
        user_id = str(user_id)
        uq = get_user_queue(user_id)
        uq.put(message)

    # Determine Log File Path
    log_dir = BASE_DIR / "logs"
    if user_id:
        user_id = str(user_id)
        target_dir = log_dir / "users" / user_id
        target_dir.mkdir(parents=True, exist_ok=True)
        target_log_file = target_dir / "sql_agent_log.txt"
    else:
        system_dir = log_dir / "system"
        system_dir.mkdir(parents=True, exist_ok=True)
        target_log_file = system_dir / "sql_system_log.txt"

    try:
        with open(target_log_file, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"ERROR: Failed to write to {target_log_file}: {e}")

def send_sse_event(event_name, data="", user_id=None):
    """Sends a custom SSE event to the user's log_queue."""
    if isinstance(data, (dict, list)):
        data_str = json.dumps(data)
    else:
        data_str = str(data)
    sse_message = f"event: {event_name}\ndata: {data_str}\n\n"
    
    if user_id:
        user_id = str(user_id)
        uq = get_user_queue(user_id)
        uq.put(sse_message)

def get_python_executable():
    return sys.executable

def clear_log_file(user_id=None):
    """Clears the log file for a specific user or the system log."""
    log_dir = BASE_DIR / "logs"
    if user_id:
        user_id = str(user_id)
        target_log_file = log_dir / "users" / user_id / "sql_agent_log.txt"
    else:
        target_log_file = log_dir / "system" / "sql_system_log.txt"

    try:
        if target_log_file.exists():
            with open(target_log_file, 'w', encoding='utf-8') as f:
                f.write("")
        log("[*] SQL log file cleared.", user_id)
    except Exception as e:
        log(f"[!] Error clearing SQL log file: {e}", user_id)

# --- PATH HELPERS ---
def get_output_paths(output_dir=None):
    if output_dir:
        base = Path(output_dir)
    else:
        base = DEFAULT_RESULTS_DIR
    
    if not base.exists():
        try:
            base.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            log(f"[!] Error creating directory {base}: {e}")

    # Use the central TEMP_DIR but create a user-specific subfolder to avoid collisions
    # We derive the user identifier from the output_dir path if possible
    # Example: Services/results/DivyaViradiya_1/sql_scanner -> DivyaViradiya_1
    try:
        user_id = base.parent.name if base.parent.name != "results" else "default"
    except Exception:
        user_id = "default"
        
    sqlmap_temp = TEMP_DIR / user_id
    sqlmap_temp.mkdir(parents=True, exist_ok=True)

    return {
        "json_report": base / "sql_report.json",
        "pdf_report": base / "sql_report.pdf",
        "sqlmap_base": sqlmap_temp 
    }

def save_sql_json(data, output_dir=None, user_id=None):
    paths = get_output_paths(output_dir)
    json_file = paths["json_report"]
    try:
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        log(f"[+] SQL JSON report saved to {json_file}", user_id)
        return str(json_file)
    except Exception as e:
        log(f"[!] Failed to save SQL JSON report: {e}", user_id)
        return None

# --- PARSING LOGIC (Targeting your specific log format) ---

def parse_sqlmap_output(output_dir, target_url_hint=None, captured_metadata=None, user_id=None):
    """
    Parses the SQLMap 'log' file using regex to extract vulnerability details.
    """
    report_data = {
        "target": target_url_hint if target_url_hint else "Unknown",
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities": [],
        "database_info": {
            "dbms": "Unknown",
            "version": "Unknown",
            "user": "Unknown",
            "current_db": "Unknown"
        },
        "dumped_data": [] 
    }

    # Merge Captured Metadata (from Console Stream)
    if captured_metadata:
        report_data["database_info"].update(captured_metadata)

    base_path = Path(output_dir)
    
    # 1. Locate the correct subdirectory (SQLMap uses the hostname)
    target_subdir = None
    try:
        subdirs = [x for x in base_path.iterdir() if x.is_dir()]
        if subdirs:
            # Pick the most recently modified directory
            target_subdir = max(subdirs, key=os.path.getmtime)
            log(f"[INFO] Found SQLMap results directory: {target_subdir.name}", user_id)
    except Exception as e:
        log(f"[!] Error finding SQLMap output subdirectory: {e}", user_id)

    if not target_subdir:
        log("[!] No SQLMap results directory found. The scan may not have found any vulnerabilities.", user_id)
        return report_data
    
    # 2. Parse the 'log' file
    log_file_path = target_subdir / "log"
    
    if not log_file_path.exists():
        log(f"[!] Log file not found at {log_file_path}. SQLMap might not have flushed results yet.", user_id)
        return report_data

    try:
        log(f"[INFO] Parsing log file: {log_file_path}", user_id)
        with open(log_file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        if not content.strip():
            log("[!] Log file is empty. No vulnerabilities were confirmed by SQLMap.", user_id)
            return report_data

        # --- Regex Patterns ---
        # We split by "---" which SQLMap often uses to separate parameters/vulnerabilities
        vuln_blocks = re.split(r"---(?:\r?\n)+", content)
        
        current_param = "Unknown"

        for block in vuln_blocks:
            block = block.strip()
            if not block: continue

            # Extract Parameter (if present in this block)
            param_match = re.search(r"Parameter:\s+(.+)", block, re.IGNORECASE)
            if param_match:
                current_param = param_match.group(1).strip()

            # Extract Type, Title, Payload (can be multiple per block)
            # SQLMap log format for vulnerabilities:
            # Type: ...
            # Title: ...
            # Payload: ...
            
            # Use findall to catch multiple vulnerability types for the same parameter
            types = re.findall(r"Type:\s+(.+)", block, re.IGNORECASE)
            titles = re.findall(r"Title:\s+(.+)", block, re.IGNORECASE)
            payloads = re.findall(r"Payload:\s+(.+)", block, re.IGNORECASE)

            # Zip them together (they should appear in order)
            for t, title, p in zip(types, titles, payloads):
                report_data["vulnerabilities"].append({
                    "parameter": current_param,
                    "type": t.strip(),
                    "title": title.strip(),
                    "payload": p.strip(),
                    "url": target_url_hint if target_url_hint else report_data["target"]
                })

        # --- Metadata Extraction (usually at the end of the log) ---
        dbms_match = re.search(r"back-end DBMS:\s+(.+)", content, re.IGNORECASE)
        if dbms_match:
            report_data["database_info"]["dbms"] = dbms_match.group(1).strip()

        banner_match = re.search(r"banner:\s+'(.+)'", content, re.IGNORECASE)
        if banner_match:
            report_data["database_info"]["version"] = banner_match.group(1).strip()

        user_match = re.search(r"current user:\s+'(.+)'", content, re.IGNORECASE)
        if user_match:
            report_data["database_info"]["user"] = user_match.group(1).strip()

        db_match = re.search(r"current database:\s+'(.+)'", content, re.IGNORECASE)
        if db_match:
            report_data["database_info"]["current_db"] = db_match.group(1).strip()

        log(f"[+] Successfully parsed {len(report_data['vulnerabilities'])} vulnerabilities.", user_id)

    except Exception as e:
        log(f"[!] Error reading/parsing SQLMap log file: {e}", user_id)

    return report_data

# --- MAIN SCAN FUNCTION ---

def run_sql_scan(target_url, output_dir, scan_mode='quick', user_id=None):
    """
    Runs SQLmap with optimized flags and ensures results are parsed even on partial completion.
    """
    if not os.path.exists(SQLMAP_PATH):
        log(f"[!] Critical: SQLmap not found at {SQLMAP_PATH}", user_id)
        return None

    os.makedirs(output_dir, exist_ok=True)
    paths = get_output_paths(output_dir)
    sqlmap_output_dir = paths["sqlmap_base"]
    
    # Base command optimized for speed and reliability
    cmd = [
        get_python_executable(), str(SQLMAP_PATH),
        '-u', target_url,
        '--batch',              
        '--random-agent',
        '--threads=10',          
        '--output-dir', str(sqlmap_output_dir),
        '--flush-session' 
    ]

    cmd.append('--technique=BEUSTQ') 
    
    if scan_mode == 'full':
        cmd.extend(['--level=3', '--risk=2', '--crawl=2', '--forms']) 
        timeout_seconds = 1800  # 30 mins
        log(f"[*] Starting FULL scan (Detection + Enumeration) on {target_url}", user_id, to_console=True)
    else:
        cmd.extend(['--level=1', '--risk=1', '--forms']) # Quick scan avoids crawl
        timeout_seconds = 900   # 15 mins
        log(f"[*] Starting QUICK scan (Detection) on {target_url}", user_id, to_console=True)

    cmd.extend(['--banner', '--current-user', '--current-db', '--is-dba'])

    if scan_mode == 'full':
        cmd.extend(['--dbs', '--tables', '--passwords'])

    log(f"[*] Executing SQLMap...", user_id, to_console=True)

    live_metadata = {}

    try:
        creation_flags = 0x08000000 if sys.platform == 'win32' else 0
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=creation_flags
        )

        # Track this user's process
        with scan_lock:
            active_scans[user_id] = {"process": process, "target": target_url, "start_time": time.time()}

        start_time = time.time()
        
        while True:
            if time.time() - start_time > timeout_seconds:
                process.kill()
                log(f"[!] TIME LIMIT EXCEEDED ({timeout_seconds}s). Parsing partial results...", user_id)
                break

            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            
            if output:
                line = output.strip()
                if line and not line.startswith("[*] ending"):
                    # Categorize output for better UI visibility
                    if "fetching" in line.lower() or "retrieved" in line.lower():
                        log(f"[DATA] {line}", user_id)
                    elif "testing" in line.lower() or "checking" in line.lower():
                        log(f"[STAGE] {line}", user_id)
                    elif "vulnerable" in line.lower() or "back-end DBMS" in line:
                        log(f"[+] {line}", user_id)
                    else:
                        log(line, user_id)
                    
                    # Capture live metadata as backup
                    if "back-end DBMS:" in line:
                        live_metadata["dbms"] = line.split(":", 1)[1].strip()

        # Always attempt to parse results even if it timed out or returned error
        log("[+] Scan finished. Processing results...", user_id, to_console=True)
        scan_data = parse_sqlmap_output(sqlmap_output_dir, target_url_hint=target_url, captured_metadata=live_metadata, user_id=user_id)
        
        json_path = save_sql_json(scan_data, output_dir, user_id=user_id)
        
        send_sse_event("scan_complete", {
            "status": "success",
            "target": target_url,
            "report_file": json_path,
            "vulnerability_count": len(scan_data.get("vulnerabilities", []))
        }, user_id=user_id)
        return json_path

    except Exception as e:
        log(f"[!] System Error during scan: {str(e)}", user_id, to_console=True)
        return None
    finally:
        # Unregister process
        with scan_lock:
            if user_id in active_scans:
                del active_scans[user_id]

        # CLEANUP: Remove SQLMap artifacts from temp within this scan's directory
        try:
            import shutil
            if sqlmap_output_dir.exists():
                shutil.rmtree(sqlmap_output_dir)
        except Exception as e:
            log(f"[!] Warning: Failed to clean up SQLMap temp artifacts: {e}", user_id)