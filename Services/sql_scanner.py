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
BASE_DIR = Path(__file__).parent.parent.parent
# Path to your SQLMap script
SQLMAP_PATH = Path(r"D:\SQLmap_setup\sqlmap.py")

# Default Fallback Directory
DEFAULT_RESULTS_DIR = Path(r"D:\NetShieldAI\Services\results\sql_scanner")
DEFAULT_RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Logs (Shared)
LOG_FILE = Path(r"D:\NetShieldAI\logs\sql_agent_log.txt")
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

# Global queue for logging
log_queue = queue.Queue()

# --- LOGGING UTILS ---
def log(message):
    """Logs messages to queue for SSE streaming and file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"data: [{timestamp}] {message}\n\n"
    log_queue.put(full_message)
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"ERROR: Failed to write to {LOG_FILE}: {e}")

def send_sse_event(event_name, data=""):
    """Sends a custom SSE event to the frontend."""
    if isinstance(data, (dict, list)):
        data_str = json.dumps(data)
    else:
        data_str = str(data)
    sse_message = f"event: {event_name}\ndata: {data_str}\n\n"
    log_queue.put(sse_message)

def get_python_executable():
    return sys.executable

def clear_log_file():
    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write("")
        log("[*] SQL log file cleared.")
    except Exception as e:
        log(f"[!] Error clearing SQL log file: {e}")

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

    return {
        "json_report": base / "sql_report.json",
        "pdf_report": base / "sql_report.pdf",
        "sqlmap_base": base 
    }

def save_sql_json(data, output_dir=None):
    paths = get_output_paths(output_dir)
    json_file = paths["json_report"]
    try:
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        log(f"[+] SQL JSON report saved to {json_file}")
        return str(json_file)
    except Exception as e:
        log(f"[!] Failed to save SQL JSON report: {e}")
        return None

# --- PARSING LOGIC (Targeting your specific log format) ---

def parse_sqlmap_output(output_dir, target_url_hint=None, captured_metadata=None):
    """
    Parses the SQLMap 'log' file line-by-line to extract rich vulnerability details.
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

    # 1. Merge Captured Metadata (from Console Stream)
    if captured_metadata:
        report_data["database_info"].update(captured_metadata)

    base_path = Path(output_dir)
    
    # SQLMap creates a subdirectory based on the hostname
    target_subdir = None
    try:
        # Find the most recently modified subdirectory
        subdirs = [x for x in base_path.iterdir() if x.is_dir()]
        if subdirs:
            target_subdir = max(subdirs, key=os.path.getmtime)
    except Exception as e:
        log(f"[!] Error finding SQLMap output subdirectory: {e}")

    if not target_subdir:
        log("[!] No results found in output directory.")
        return report_data
    
    # 2. Parse the 'log' file
    log_file_path = target_subdir / "log"
    
    if log_file_path.exists():
        try:
            log(f"[INFO] Parsing log file at: {log_file_path}")
            with open(log_file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            current_param = "Unknown"
            current_vuln = {}

            for line in lines:
                line = line.strip()

                # --- 1. Detect Parameter ---
                # Format: "Parameter: searchFor (POST)"
                if line.startswith("Parameter:"):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        current_param = parts[1].strip()

                # --- 2. Detect Type ---
                # Format: "Type: boolean-based blind"
                elif line.startswith("Type:"):
                    # Start a new vulnerability entry
                    current_vuln = {
                        "type": line.split(":", 1)[1].strip(),
                        "url": target_url_hint if target_url_hint else report_data["target"]
                    }

                # --- 3. Detect Title ---
                # Format: "Title: MySQL AND boolean-based blind..."
                elif line.startswith("Title:"):
                    if current_vuln:
                        current_vuln["title"] = line.split(":", 1)[1].strip()

                # --- 4. Detect Payload ---
                # Format: "Payload: searchFor=UFCm' AND..."
                elif line.startswith("Payload:"):
                    if current_vuln:
                        current_vuln["payload"] = line.split(":", 1)[1].strip()
                        
                        # Add the Parameter context to the title if needed
                        if "Parameter" not in current_vuln.get("title", ""):
                            current_vuln["parameter"] = current_param
                        
                        # Append and reset
                        report_data["vulnerabilities"].append(current_vuln)
                        current_vuln = {}

                # --- 5. Detect Metadata (Footer) ---
                elif "back-end DBMS:" in line:
                    report_data["database_info"]["dbms"] = line.split(":", 1)[1].strip()
                elif "banner:" in line:
                    report_data["database_info"]["version"] = line.split(":", 1)[1].strip().strip("'")
                elif "current user:" in line:
                    report_data["database_info"]["user"] = line.split(":", 1)[1].strip().strip("'")
                elif "current database:" in line:
                    report_data["database_info"]["current_db"] = line.split(":", 1)[1].strip().strip("'")

            log(f"[+] Parsed {len(report_data['vulnerabilities'])} vulnerabilities from log.")

        except Exception as e:
            log(f"[!] Error reading SQLMap log file: {e}")
    else:
        log(f"[!] Log file not found at {log_file_path}. Is --flush-session enabled?")

    return report_data

# --- MAIN SCAN FUNCTION ---

def run_sql_scan(target_url, output_dir, scan_mode='quick'):
    """
    Runs SQLmap with --flush-session to ensure the log file is fully populated.
    """
    if not os.path.exists(SQLMAP_PATH):
        log(f"[!] Critical: SQLmap not found at {SQLMAP_PATH}")
        return None

    os.makedirs(output_dir, exist_ok=True)
    
    cmd = [
        get_python_executable(), str(SQLMAP_PATH),
        '-u', target_url,
        '--batch',              
        '--random-agent',
        '--forms',
        '--crawl=2',
        '--threads=10',
        '--output-dir', str(output_dir),
        '--flush-session' # <--- CRITICAL: Forces SQLMap to write details to log
    ]

    cmd.append('--technique=BEUSTQ') 
    
    if scan_mode == 'full':
        cmd.extend(['--level=3', '--risk=2']) 
        timeout_seconds = 900 
        log(f"[*] Starting FULL scan (Detection + Enumeration) on {target_url}")
    else:
        cmd.extend(['--level=1', '--risk=1'])
        timeout_seconds = 600
        log(f"[*] Starting QUICK scan (Detection) on {target_url}")

    cmd.extend(['--banner', '--current-user', '--current-db', '--is-dba'])

    if scan_mode == 'full':
        cmd.extend(['--dbs', '--tables', '--passwords'])

    log(f"[*] Executing SQLMap...")

    # We capture metadata live, but the Parser will also try to read it from the log file
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

        start_time = time.time()
        
        while True:
            if time.time() - start_time > timeout_seconds:
                process.kill()
                log(f"[!] TIME LIMIT EXCEEDED ({timeout_seconds}s).")
                break

            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            
            if output:
                line = output.strip()
                if line and not line.startswith("[*] ending"):
                    if "fetched" in line or "vulnerable" in line:
                        log(f"[DATA] {line}")
                    else:
                        log(f"[SQLMap] {line}")
                    
                    # Capture live metadata as backup
                    if "back-end DBMS:" in line:
                        live_metadata["dbms"] = line.split(":", 1)[1].strip()

        if process.poll() == 0 or process.poll() is None:
            log("[+] Scan Completed. Parsing results...")
            
            # Pass target_url here so it appears correctly in the JSON
            scan_data = parse_sqlmap_output(output_dir, target_url_hint=target_url, captured_metadata=live_metadata)
            
            json_path = save_sql_json(scan_data, output_dir)
            
            send_sse_event("scan_complete", {
                "status": "success",
                "target": target_url,
                "report_file": json_path,
                "vulnerability_count": len(scan_data.get("vulnerabilities", []))
            })
            return json_path
        else:
            log("[!] Scan finished with errors.")
            return None

    except Exception as e:
        log(f"[!] System Error during scan: {str(e)}")
        return None