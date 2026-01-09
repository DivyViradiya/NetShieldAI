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

# Global queue for logging (consumed by the Blueprint)
log_queue = queue.Queue()

# --- LOGGING UTILS ---
def log(message):
    """Logs messages to queue for SSE streaming and file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 1. SSE Stream Format
    full_message = f"data: [{timestamp}] {message}\n\n"
    log_queue.put(full_message)

    # 2. File Log
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
    """Returns the current python interpreter path."""
    return sys.executable

def clear_log_file():
    """Clears the content of the log output file."""
    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write("")
        log("[*] SQL log file cleared.")
    except Exception as e:
        log(f"[!] Error clearing SQL log file: {e}")

# --- PATH & FILE HELPERS ---

def get_output_paths(output_dir=None):
    """
    Returns a dictionary of file paths based on the output directory.
    """
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
        # SQLMap creates its own subfolders, so we point to the base
        "sqlmap_base": base 
    }

def save_sql_json(data, output_dir=None):
    """Saves the parsed SQL scan data to a JSON file."""
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

# --- PARSING LOGIC ---

def parse_sqlmap_output(output_dir, captured_metadata=None):
    """
    Parses the SQLMap output directory to find the 'log' file and extracting
    vulnerability details into a structured dictionary.
    
    Args:
        output_dir: The directory where SQLMap saved its results.
        captured_metadata: A dictionary of DB info captured live from the console stream.
    """
    report_data = {
        "target": "Unknown",
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities": [],
        "database_info": {
            "dbms": "Unknown",
            "version": "Unknown",
            "user": "Unknown",
            "current_db": "Unknown"
        },
        "dumped_data": [] # For full scan tables
    }

    # 1. Merge Captured Metadata (from Console Stream)
    if captured_metadata:
        report_data["database_info"].update(captured_metadata)

    base_path = Path(output_dir)
    
    # SQLMap creates a subdirectory based on the hostname inside the output_dir
    target_subdir = None
    try:
        # Find first subdirectory that isn't empty
        for item in base_path.iterdir():
            if item.is_dir():
                target_subdir = item
                break
    except Exception as e:
        log(f"[!] Error finding SQLMap output subdirectory: {e}")
        return report_data

    if not target_subdir:
        log("[!] No results found in output directory.")
        return report_data

    report_data["target"] = target_subdir.name
    
    # 2. Parse the 'log' file (SQLMap's record of findings)
    log_file_path = target_subdir / "log"
    if log_file_path.exists():
        try:
            with open(log_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Regex to find vulnerability blocks
            # Blocks are usually separated by newlines
            vuln_blocks = content.split("\n\n")
            
            for block in vuln_blocks:
                # We need to strip whitespace because SQLMap logs are indented
                if "Type:" in block and "Payload:" in block:
                    vuln = {}
                    for line in block.split('\n'):
                        clean_line = line.strip() # <--- FIX: Remove indentation
                        
                        if clean_line.startswith("Type:"):
                            vuln['type'] = clean_line.replace("Type:", "").strip()
                        elif clean_line.startswith("Title:"):
                            vuln['title'] = clean_line.replace("Title:", "").strip()
                        elif clean_line.startswith("Payload:"):
                            vuln['payload'] = clean_line.replace("Payload:", "").strip()
                    
                    if vuln:
                        report_data["vulnerabilities"].append(vuln)
                        
            log(f"[+] Parsed {len(report_data['vulnerabilities'])} vulnerabilities from log.")
        except Exception as e:
            log(f"[!] Error reading SQLMap log file: {e}")

    # 3. Check for Dumped Data (CSV files in 'dump' folder)
    dump_dir = target_subdir / "dump"
    if dump_dir.exists():
        try:
            # Recursively find CSV files
            for csv_file in dump_dir.rglob("*.csv"):
                table_name = csv_file.stem
                report_data["dumped_data"].append(f"Table extracted: {table_name}")
        except Exception:
            pass

    return report_data

# --- MAIN SCAN FUNCTION ---

def run_sql_scan(target_url, output_dir, scan_mode='quick'):
    """
    Runs SQLmap with specific capabilities based on scan_mode.
    Captures live DB metadata from stdout to ensure the report is populated.
    """
    if not os.path.exists(SQLMAP_PATH):
        log(f"[!] Critical: SQLmap not found at {SQLMAP_PATH}")
        return None

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # --- 1. BASE COMMAND ---
    cmd = [
        get_python_executable(), str(SQLMAP_PATH),
        '-u', target_url,
        '--batch',              # Non-interactive
        '--random-agent',
        '--forms',
        '--crawl=2',
        '--threads=10',
        '--output-dir', str(output_dir) # Force output to user dir
    ]

    # --- 2. DETECTION CONFIG ---
    cmd.append('--technique=BEUSTQ') 
    
    # --- 3. INTENSITY CONFIG ---
    if scan_mode == 'full':
        cmd.extend(['--level=3', '--risk=2']) 
        timeout_seconds = 900  # 15 Minutes
        log(f"[*] Starting FULL scan (Detection + Enumeration) on {target_url}")
    else:
        cmd.extend(['--level=1', '--risk=1'])
        timeout_seconds = 600  # 10 Minutes
        log(f"[*] Starting QUICK scan (Detection) on {target_url}")

    # --- 4. FINGERPRINTING & ENUMERATION ---
    cmd.extend(['--banner', '--current-user', '--current-db', '--is-dba'])

    if scan_mode == 'full':
        cmd.extend([
            '--dbs',        # List databases
            '--tables',     # List tables
            '--passwords'   # Crack passwords
        ])

    log(f"[*] Executing SQLMap...")

    # Dictionary to hold metadata captured from the console stream
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
        
        # --- STREAM LOGS & CAPTURE METADATA ---
        while True:
            if time.time() - start_time > timeout_seconds:
                process.kill()
                log(f"[!] TIME LIMIT EXCEEDED ({timeout_seconds}s). Process killed.")
                break

            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            
            if output:
                line = output.strip()
                if line and not line.startswith("[*] ending"):
                    # 1. Clean Log for UI
                    if "fetched" in line or "vulnerable" in line:
                        log(f"[DATA] {line}")
                    else:
                        log(f"[SQLMap] {line}")

                    # 2. Capture Metadata for Report
                    # SQLMap outputs info like "back-end DBMS: MySQL", "banner: '8.0.22'"
                    if "back-end DBMS:" in line:
                        live_metadata["dbms"] = line.split(":", 1)[1].strip()
                    elif "banner:" in line:
                        live_metadata["version"] = line.split(":", 1)[1].strip().strip("'")
                    elif "current user:" in line:
                        live_metadata["user"] = line.split(":", 1)[1].strip().strip("'")
                    elif "current database:" in line:
                        live_metadata["current_db"] = line.split(":", 1)[1].strip().strip("'")

        # --- POST PROCESSING ---
        if process.poll() == 0 or process.poll() is None:
            log("[+] Scan Completed. Parsing results...")
            
            # Parse results and pass the captured metadata
            scan_data = parse_sqlmap_output(output_dir, captured_metadata=live_metadata)
            
            # Save JSON for PDF Generator
            json_path = save_sql_json(scan_data, output_dir)
            
            # Notify Frontend via SSE
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