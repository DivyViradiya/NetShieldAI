import subprocess
import tempfile
import os
import sys
import threading
import queue
import time
import json
import re
from datetime import datetime
from pathlib import Path
from core.time_utils import get_now_ist_str
from Services import report_manager, scan_logger
from .tctr_engine import tctr_engine
from Services.anonymity.manager import AnonymityManager
from Services.target_validator import validate_target, TargetBlockedError
from Services.process_manager import process_manager
from core.logger_setup import logger
import contextlib

_anon = AnonymityManager()

# --- CONFIGURATION ---
# BASE_DIR should be at the root of the project (one level up from Services folder)
BASE_DIR = Path(__file__).parent.parent
# Path to your SQLMap script
SQLMAP_PATH = os.environ.get("SQLMAP_PATH", r"D:\SQLmap_setup\sqlmap.py")

# Default Fallback Directory
DEFAULT_RESULTS_DIR = BASE_DIR / ".results" / "sql_scanner"

# Logs (Shared)
LOG_FILE = BASE_DIR / ".logs" / "sql_agent_log.txt"

TEMP_DIR = Path(tempfile.gettempdir()) / "NetShieldAI" / "sqlmap"
TEMP_DIR.mkdir(parents=True, exist_ok=True)

# --- Global State for Process Management (Isolated by user_id) ---
active_scans = {} # { "user_id": {"target": str, "start_time": float} }
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

def stop_user_scan(user_id):
    """Terminate the SQLMap process for a specific user via ProcessManager."""
    success = process_manager.stop_user_tool(user_id, "sqlmap")
    if success:
        log(f"[*] SQLMap process for user {user_id} terminated.", user_id)
    return success

from Services import scan_logger
from core.logger_setup import logger

# --- LOGGING UTILS ---
def log(message, user_id=None, to_console=False, level='INFO'):
    """
    Logs messages using the centralized scan_logger.
    Strips legacy tag prefixes for backward compatibility while refactoring.
    """
    if message.startswith("[!"):
        level = 'ERROR'
        message = message[3:].lstrip()
    elif message.startswith("[+]"):
        level = 'SUCCESS'
        message = message[3:].lstrip()
    elif message.startswith("[*]"):
        # Keep as INFO, just strip tag
        message = message[3:].lstrip()
    elif message.startswith("[INFO]"):
        message = message[6:].lstrip()
    elif message.startswith("[DATA]"):
        level = 'DATA'
        message = message[6:].lstrip()
    elif message.startswith("[STAGE]"):
        level = 'STAGE'
        message = message[7:].lstrip()

    if to_console:
        if level == 'INFO':
            logger.info(message)
        elif level == 'WARNING':
            logger.warning(message)
        elif level == 'ERROR':
            logger.error(message)
        elif level == 'SUCCESS':
            if hasattr(logger, 'success'):
                logger.success(message)
            else:
                logger.info(f"SUCCESS: {message}")
        else:
            logger.debug(message)
    
    if user_id:
        scan_logger.write_log(user_id, "sql_scanner", message, level=level)

def send_sse_event(event_name, data="", user_id=None):
    """
    Simulates SSE event by logging a special format line that tail_log_file can pick up.
    """
    if isinstance(data, (dict, list)):
        data_str = json.dumps(data)
    else:
        data_str = str(data)
    
    log(f"EVENT: {event_name} | PAYLOAD: {data_str}", user_id)

def is_local_target(target):
    """
    Checks if a target URL/IP is local (localhost, 127.0.0.1, or private IP ranges).
    """
    # Extract host from URL if needed
    host = target.replace("https://", "").replace("http://", "").split('/')[0].split(':')[0]
    
    if host.lower() in ["localhost", "127.0.0.1", "::1"]:
        return True
    
    # Private IP Regex (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
    private_ip_regex = r"^(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})$"
    if re.match(private_ip_regex, host):
        return True
        
    return False

def get_python_executable():
    return sys.executable

def clear_log_file(user_id=None):
    """Clears the log file for a specific user or the system log."""
    log_dir = BASE_DIR / ".logs"
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
def get_output_paths(output_dir=None, target=None, timestamp=None):
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
    try:
        user_id = base.parent.name if base.parent.name != ".results" else "default"
    except Exception:
        user_id = "default"
        
    if timestamp:
        sqlmap_temp = TEMP_DIR / user_id / timestamp
    else:
        sqlmap_temp = TEMP_DIR / user_id
    
    sqlmap_temp.mkdir(parents=True, exist_ok=True)

    if target:
        if timestamp:
            sanitized = report_manager.sanitize_filename(target)
            stem = f"sql_{sanitized}_{timestamp}"
            json_filename = f"{stem}.json"
            pdf_filename = f"{stem}.pdf"
        else:
            json_filename = report_manager.generate_report_filename("sql_scanner", target, "json")
            pdf_filename = report_manager.generate_report_filename("sql_scanner", target, "pdf")
    else:
        json_filename = "sql_report.json"
        pdf_filename = "sql_report.pdf"

    return {
        "json_report": base / json_filename,
        "pdf_report": base / pdf_filename,
        "sqlmap_base": sqlmap_temp 
    }

def save_sql_json(data, output_dir=None, user_id=None, target=None, timestamp=None):
    paths = get_output_paths(output_dir, target=target, timestamp=timestamp)
    json_file = paths["json_report"]
    try:
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        log(f"SQL JSON report saved to {json_file}", user_id, level='SUCCESS')
        return str(json_file)
    except Exception as e:
        log(f"Failed to save SQL JSON report: {e}", user_id, level='ERROR')
        return None

# --- PARSING LOGIC (Targeting your specific log format) ---

def parse_sqlmap_output(output_dir, target_url_hint=None, captured_metadata=None, user_id=None):
    """
    Parses the SQLMap 'log' file using regex to extract vulnerability details.
    """

    report_data = {
        "target": target_url_hint if target_url_hint else "Unknown",
        "scan_time": get_now_ist_str(),
        "status": "Completed", # Default
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
        if "critical_error" in captured_metadata:
            report_data["status"] = f"Failed: {captured_metadata['critical_error']}"
        db_metadata = {k: v for k, v in captured_metadata.items() if k != "critical_error"}
        report_data["database_info"].update(db_metadata)

    base_path = Path(output_dir)
    if not base_path.exists():
        log("[!] No SQLMap results directory found. The scan may not have found any vulnerabilities.", user_id)
        return report_data
        
    # 1. Locate the correct subdirectory (SQLMap uses the hostname)
    target_subdir = None
    try:
        subdirs = [x for x in base_path.iterdir() if x.is_dir()]
        if subdirs:
            # Pick the most recently modified directory
            target_subdir = max(subdirs, key=lambda x: x.stat().st_mtime)
            log(f"Found SQLMap results directory: {target_subdir.name}", user_id, level='INFO')
    except Exception as e:
        log(f"Error finding SQLMap output subdirectory: {e}", user_id, level='ERROR')

    if not target_subdir:
        log("[!] No SQLMap results directory found. The scan may not have found any vulnerabilities.", user_id)
        return report_data
    
    # 2. Parse the 'log' file
    log_file_path = target_subdir / "log"
    
    if not log_file_path.exists():
        log(f"[!] Log file not found at {log_file_path}. SQLMap might not have flushed results yet.", user_id)
        return report_data

    try:
        log(f"[*] Parsing logs from: {target_subdir.name}", user_id, level='INFO')
        
        file_size = log_file_path.stat().st_size
        if file_size > 10 * 1024 * 1024:  # 10MB
            log(f"[!] Large SQLMap log file detected ({file_size / 1024 / 1024:.1f} MB). Parsing may take a moment...", user_id, level='WARNING')

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

    # Apply ML Threat Re-ranking
    try:
        vulnerabilities = report_data.get("vulnerabilities", [])
        total_vulns = len(vulnerabilities)
        
        if total_vulns > 0:
            # If we have thousands of findings, only re-rank the top portion to prevent hangs
            # SQLMap often repeats findings, so we process the unique ones or top 500
            max_process = 500
            if total_vulns > max_process:
                log(f"[*] Extensive findings detected ({total_vulns}). Re-ranking top {max_process} for priority analysis...", user_id, level='INFO')
                vulnerabilities = vulnerabilities[:max_process]

            log(f"[*] Re-ranking {len(vulnerabilities)} findings with AI threat context...", user_id, level='INFO')
            
            for i, vuln in enumerate(vulnerabilities):
                # Update progress every 50 findings
                if i > 0 and i % 50 == 0:
                    log(f"[*] TCTR Progress: {i}/{len(vulnerabilities)} findings analyzed...", user_id, level='DEBUG')

                prediction_obj = tctr_engine.predict_risk(
                    vuln["title"], 
                    f"Parameter: {vuln['parameter']}\nPayload: {vuln['payload']}", 
                    cwe_id="89"
                )
                vuln["predicted_risk_score"] = prediction_obj["score"]
                vuln["tctr_priority"] = prediction_obj["tctr_priority"]
                vuln["base_score"] = prediction_obj["base_score"]
                vuln["priority_level"] = prediction_obj["priority_level"]
                vuln["risk_justification"] = prediction_obj["risk_justification"]
            
            # Update report data if we truncated (unlikely to matter as findings are usually similar)
            report_data["vulnerabilities"] = vulnerabilities
        
        # Sort by predicted score
        report_data["vulnerabilities"].sort(
            key=lambda x: x.get('predicted_risk_score', 0),
            reverse=True
        )
    except Exception as e:
        log(f"[!] ML Re-ranking failed for SQL: {e}", user_id)

    return report_data

# --- MAIN SCAN FUNCTION ---

def enqueue_output(out, queue):
    for line in iter(out.readline, ''):
        queue.put(line)
    out.close()

def run_sql_scan(target_url, output_dir=None, scan_mode='quick', user_id=None, timestamp=None, check_waf=False, risk_level='2', scan_level='3', tamper='', technique=''):
    """
    Core SQL Injection scan loop using SQLMap.
    Now optimized with non-blocking output handling.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    timeout_seconds = 900   # 15 mins default
    if scan_mode == 'full':
        timeout_seconds = 1800  # 30 mins
    # Defense-in-depth — catches background/scheduled calls that bypass the BP
    try:
        validate_target(target_url)
    except TargetBlockedError as e:
        log(f"[BLOCKED] Scan rejected by target validator: {e}", user_id, level='ERROR')
        return None
        
    if not timestamp:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    
    # [FIX] If output_dir not provided (unlikely from BP but possible from scripts), use default
    if not output_dir:
        from config import RESULTS_DIR
        output_dir = os.path.join(RESULTS_DIR, user_id if user_id else "anonymous", "sql_scanner")

    if not os.path.exists(SQLMAP_PATH):
        log(f"[!] Critical: SQLmap not found at {SQLMAP_PATH}", user_id)
        return None

    os.makedirs(output_dir, exist_ok=True)
    paths = get_output_paths(output_dir, target=target_url, timestamp=timestamp)
    sqlmap_output_dir = paths["sqlmap_base"]
    
    # Base command optimized for speed and reliability
    cmd = [
        get_python_executable(), str(SQLMAP_PATH),
        '-u', target_url,
        '--batch',              
        '--random-agent',
        '--output-dir', str(sqlmap_output_dir),
        '--answers=extending=N,follow=N,keep=N,exploit=N' # Speed up batch mode decisions
    ]

    # Dynamically adjust technique based on anonymity
    if technique:
        cmd.append(f'--technique={technique}')
    else:
        # Default to BEUQ (Boolean, Error, Union, Inline) - skip Time-based by default over Tor
        cmd.append('--technique=BEUQ') 
        
    cmd.extend([f'--level={scan_level}', f'--risk={risk_level}'])
    if tamper:
        cmd.extend([f'--tamper={tamper}'])

    if scan_mode == 'full':
        # Full scan includes further enumeration
        cmd.extend(['--crawl=2', '--forms']) 
        timeout_seconds = 1800 if int(scan_level) < 4 else 3600  # 30 mins, or 60 mins for high level
        log(f"Starting FULL scan (Detection + Enumeration + Forms) on {target_url} (Level {scan_level}, Risk {risk_level})", user_id, to_console=True)
    else:
        # Quick scan focuses on the provided parameters
        timeout_seconds = 900 if int(scan_level) < 4 else 1800   # 15 mins, or 30 mins for high level
        log(f"Starting QUICK scan (Parameter Testing) on {target_url} (Level {scan_level}, Risk {risk_level})", user_id, to_console=True)

    cmd.extend(['--banner', '--current-user', '--current-db', '--is-dba'])

    if scan_mode == 'full':
        cmd.extend(['--dbs', '--tables', '--passwords'])

    # --- Anonymity Logic ---
    # User expressly requested to bypass Tor for SQLmap to fix the timeouts
    # and maximize execution speed natively.
    use_anonymity = False
    log("[🛡️] Anonymity Mode (Tor) is manually bypassed for SQLMap. Executing directly for maximum speed.", user_id, level='INFO')
    
    # SQLMap has a hard-coded maximum limit of 10 threads. 
    cmd.extend(['--timeout=30', '--threads=10'])

    log(f"[STAGE] Executing SQLMap ({scan_mode.upper()}) on {target_url}...", user_id, level='STAGE', to_console=True)

    live_metadata = {}
    full_stdout_log = []

    try:
        creation_flags = 0x08000000 if sys.platform == 'win32' else 0
        
        if use_anonymity:
            cmd.extend(_anon.get_scan_flags("sqlmap"))
            logger.info(f"[🛡️] Anonymity Mode ACTIVE ({_anon.mode.upper()}). Proxying SQLMap traffic.")
        else:
            logger.info("[🛡️] Anonymity Mode OFFLINE/BYPASSED. Executing SQLMap from direct connection.")
        
        with (_anon.apply() if use_anonymity else contextlib.nullcontext()):
            # [FIX] If using --tor, avoid passing proxy env vars to prevent "incompatible" error
            if use_anonymity:
                if _anon.mode == "tor":
                    log("[🛡️] Using native SQLMap Tor module. Isolated environment active.", user_id, level='INFO')
                    cmd_env = os.environ.copy()
                    # Remove common proxy vars that might be inherited
                    for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]:
                        cmd_env.pop(var, None)
                else:
                    cmd_env = _anon.get_subprocess_env()
            else:
                cmd_env = os.environ.copy()
                # Clear any inherited proxy variables just to be safe and ensure direct connection
                for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]:
                    cmd_env.pop(var, None)

            with scan_lock:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    creationflags=creation_flags,
                    env=cmd_env
                )
                # Track this user's process globally
                process_manager.register(user_id, "sqlmap", process)
                # Track this user's process locally
                active_scans[user_id] = {"target": target_url, "start_time": time.time()}

            start_time = time.time()
            out_queue = queue.Queue()
            
            # Start reader threads to prevent blocking during readline()
            # This ensures we can check timeout_seconds even if SQLMap is silent
            t = threading.Thread(target=enqueue_output, args=(process.stdout, out_queue), daemon=True)
            t.start()

            while True:
                # 1. Check Global Timeout
                if time.time() - start_time > timeout_seconds:
                    log(f"[!] TIME LIMIT EXCEEDED ({timeout_seconds}s). Terminating process...", user_id, level='WARNING')
                    process_manager.stop_user_tool(user_id, "sqlmap") # Use process manager for robust kill
                    log("[*] Scan aborted due to timeout. Parsing partial results...", user_id)
                    break

                # 2. Get Output from Queue (Non-blocking with short timeout)
                try:
                    line = out_queue.get(timeout=2) 
                except queue.Empty:
                    # No output, but check if process finished
                    if process.poll() is not None:
                        break
                    continue

                if line:
                    line = line.strip()
                    full_stdout_log.append(line)
                    if not line or line.startswith("[*] ending"):
                        continue
                        
                    # Categorize output for UI
                    if "fetching" in line.lower() or "retrieved" in line.lower():
                        log(line, user_id, level='DATA')
                    elif "testing" in line.lower() or "checking" in line.lower():
                        log(line, user_id, level='STAGE')
                    elif "vulnerable" in line.lower() or "back-end DBMS" in line:
                        log(line, user_id, level='SUCCESS')
                    elif "[CRITICAL]" in line:
                        log(line, user_id, level='ERROR', to_console=True)
                        live_metadata["critical_error"] = line.split("[CRITICAL]", 1)[1].strip()
                    else:
                        log(line, user_id, level='DEBUG')
                    
                    if "back-end DBMS:" in line:
                        live_metadata["dbms"] = line.split(":", 1)[1].strip()

            process.wait()
            # Unregister
            process_manager.unregister(user_id, "sqlmap")

        log("[+] Scan finished. Processing results...", user_id, to_console=True)
        scan_data = parse_sqlmap_output(sqlmap_output_dir, target_url_hint=target_url, captured_metadata=live_metadata, user_id=user_id)
        
        # If we had a critical error and no vulns found, ensure status reflects it
        if process.returncode != 0 and not scan_data.get("vulnerabilities"):
             scan_data["status"] = f"Failed: {live_metadata.get('critical_error', 'Internal Error')}"

        json_path = save_sql_json(scan_data, output_dir, user_id=user_id, target=target_url, timestamp=timestamp)
        
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
        # Unregister process locally
        with scan_lock:
            if user_id in active_scans:
                del active_scans[user_id]

        # CLEANUP: Remove SQLMap artifacts from temp within this scan's directory
        try:
            import shutil
            
            # --- SAVE RAW LOG ---
            try:
                if output_dir:
                    saved_log_path = Path(output_dir) / f"sqlmap_raw_log_{timestamp}.txt"
                    with open(saved_log_path, 'w', encoding='utf-8') as f:
                        f.write("\n".join(full_stdout_log) if full_stdout_log else "No output captured from SQLMap.")
                    log(f"[*] Raw SQLMap execution log saved to {saved_log_path}", user_id, level='INFO')
            except Exception as e:
                log(f"[!] Warning: Failed to save raw SQLMap execution log: {e}", user_id)
            # --------------------

            if sqlmap_output_dir.exists():
                for i in range(3): # Try up to 3 times
                    try:
                        shutil.rmtree(sqlmap_output_dir)
                        break
                    except OSError:
                        if i < 2:
                            time.sleep(1.0) # Wait a bit for SQLMap to fully release files
                        else:
                            raise
        except Exception as e:
            log(f"[!] Warning: Failed to clean up SQLMap temp artifacts: {e}", user_id)
