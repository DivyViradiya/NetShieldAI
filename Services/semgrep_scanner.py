import subprocess
import os
import shutil
import json
import uuid
import zipfile
import queue
import platform
import sys
from datetime import datetime
from pathlib import Path

# --- Configuration ---
# BASE_DIR should be at the root of the project (one level up from Services folder)
BASE_DIR = Path(__file__).parent.parent

# Default results path (Fallback)
DEFAULT_RESULTS_DIR = BASE_DIR / "Services" / "results" / "semgrep_scanner"

# Logs
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "semgrep_agent_log.txt"

TEMP_DIR = BASE_DIR / "Services" / "temp" / "semgrep"
TEMP_DIR.mkdir(parents=True, exist_ok=True)

# --- USER ISOLATION ---
user_queues = {}

def get_user_queue(user_id):
    """Ensures a queue exists for the user and returns it."""
    if user_id not in user_queues:
        user_queues[user_id] = queue.Queue()
    return user_queues[user_id]

# Standard Semgrep Rulesets to use
SEMGREP_RULES = ["p/security-audit", "p/secrets", "p/python", "p/javascript", "p/flask"]


# --- Logging & Events ---
def log(message, user_id=None, to_console=False):
    """
    Logs messages to an in-memory queue and to a file.
    Organized Path: logs/users/{user_id}/semgrep_agent_log.txt
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"data: [{timestamp}] {message}\n\n"  # SSE format
    
    if to_console:
        print(f"[{timestamp}] {message}")
    
    # Put message into the user-specific queue if provided
    if user_id:
        user_id = str(user_id)
        uq = get_user_queue(user_id)
        uq.put(full_message)
        
        # User-specific log file
        log_dir = BASE_DIR / "logs" / "users" / user_id
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "semgrep_agent_log.txt"
    else:
        system_dir = BASE_DIR / "logs" / "system"
        system_dir.mkdir(parents=True, exist_ok=True)
        log_path = system_dir / "semgrep_system_log.txt"

    try:
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"ERROR: Failed to write to log: {e}")

def send_sse_event(event_name, data="", user_id=None):
    """Sends a custom SSE event to the frontend."""
    if isinstance(data, (dict, list)):
        data_str = json.dumps(data)
    else:
        data_str = str(data)
    
    sse_message = f"event: {event_name}\ndata: {data_str}\n\n"
    
    if user_id:
        user_id = str(user_id)
        uq = get_user_queue(user_id)
        uq.put(sse_message)

def clear_log_file(user_id):
    """Clears the content of the log output file and queue for a specific user."""
    if not user_id: return
    user_id = str(user_id)
    try:
        log_path = BASE_DIR / "logs" / "users" / user_id / "semgrep_agent_log.txt"
        if log_path.exists():
            with open(log_path, 'w', encoding='utf-8') as f:
                f.write("")
        
        # Clear Queue
        uq = get_user_queue(user_id)
        with uq.mutex:
            uq.queue.clear()
            
        log("[*] Semgrep log file and queue cleared.", user_id)
    except Exception as e:
        print(f"[!] Error clearing Semgrep log: {e}")


# --- Helper Functions ---
def _get_subprocess_creation_flags():
    """Returns appropriate creation flags for subprocess based on OS."""
    if platform.system() == "Windows":
        return subprocess.CREATE_NO_WINDOW
    return 0

def get_semgrep_path():
    """
    Dynamically finds the Semgrep executable in the current environment.
    Solves issues where 'semgrep' isn't in the global system PATH.
    """
    # 1. Check standard PATH (e.g. if installed globally or active venv works)
    if shutil.which("semgrep"):
        return "semgrep"
    
    # 2. Check current Python environment's Scripts folder (Windows specific)
    # This locates D:\NetShieldAI\venv\Scripts\semgrep.exe
    possible_path = os.path.join(sys.prefix, 'Scripts', 'semgrep.exe')
    if os.path.exists(possible_path):
        return possible_path
    
    # 3. Check Linux/Mac bin folder
    possible_path_linux = os.path.join(sys.prefix, 'bin', 'semgrep')
    if os.path.exists(possible_path_linux):
        return possible_path_linux

    return None

def is_semgrep_installed(user_id=None):
    """Checks if Semgrep is accessible in the environment."""
    path = get_semgrep_path()
    if path:
        return True
    
    log("[!] ERROR: 'semgrep' executable not found.", user_id)
    log(f"[!] Checked system PATH and: {os.path.join(sys.prefix, 'Scripts')}", user_id)
    log("[!] Please ensure 'pip install semgrep' was run in THIS virtual environment.", user_id)
    return False

def get_output_paths(output_dir=None):
    """
    Returns a dictionary of file paths based on the output directory.
    If output_dir is None, uses the global DEFAULT_RESULTS_DIR.
    Now uses user-specific temp paths if possible.
    """
    if output_dir:
        base = Path(output_dir)
        # Derive user identifier from output_dir (e.g. Services/results/Divy_1/semgrep_scanner -> Divy_1)
        user_id = base.parent.name
    else:
        base = DEFAULT_RESULTS_DIR
        user_id = "default"
    
    if not base.exists():
        try:
            base.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"[!] Error creating directory {base}: {e}")

    # User-specific temp directory
    user_temp = TEMP_DIR / user_id
    user_temp.mkdir(parents=True, exist_ok=True)

    return {
        "raw_json": user_temp / "semgrep_raw.json",
        "parsed_json": base / "semgrep_report.json",  # Cleaned for UI/PDF
        "source_code": user_temp / "source_code_temp"   # Temp extraction folder
    }

def smart_unzip(zip_path, extract_to, user_id=None):
    """
    Extracts a zip file but IGNORES heavy folders like node_modules/venv.
    Prevents server overload from massive dependency trees.
    """
    # Folders/Files to ignore
    IGNORE_PATTERNS = {'node_modules', 'venv', '.env', '.git', '__pycache__', 'dist', 'build', 'vendor', '.idea', '.vscode'}
    
    try:
        extract_to = Path(extract_to)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            all_files = zip_ref.namelist()
            
            for file in all_files:
                path_parts = file.split('/')
                
                # Filter 1: Check against ignore list
                if any(part in IGNORE_PATTERNS for part in path_parts):
                    continue 
                
                # Filter 2: Zip Slip Protection
                # Ensure the target path stays inside the extraction folder
                target_path = extract_to / file
                try:
                    target_path.resolve().relative_to(extract_to.resolve())
                except ValueError:
                    log(f"[!] Security Warning: Skipped suspicious file path in zip: {file}", user_id)
                    continue

                # Extract
                zip_ref.extract(file, extract_to)
        return True
    except Exception as e:
        log(f"[!] Error unzipping file: {e}", user_id)
        return False


# --- Core Scanning Logic ---

def run_semgrep_scan(target_input, input_type="zip", output_dir=None, user_id=None):
    """
    Main entry point for running a scan.
    
    :param target_input: Path to zip file OR Git URL string.
    :param input_type: 'zip' or 'git'.
    :param output_dir: Directory to store results (User ID folder).
    :param user_id: Composite user identifier for isolated logging.
    """
    semgrep_cmd = get_semgrep_path()
    if not semgrep_cmd:
        return None

    paths = get_output_paths(output_dir)
    source_dir = paths["source_code"]
    raw_report_path = paths["raw_json"]

    # 1. Prepare Source Code
    log(f"[*] Preparing source code for analysis...", user_id, to_console=True)
    
    # Ensure clean slate for source code
    if source_dir.exists():
        try:
            log(f"[*] Clearing previous temporary source directory...", user_id)
            # [FIXED] Force delete previous temp folder if it exists
            def on_rm_error(func, path, exc_info):
                os.chmod(path, 0o777)
                func(path)
            shutil.rmtree(source_dir, onerror=on_rm_error)
            log(f"[+] Temporary directory cleared.", user_id)
        except Exception as e:
            log(f"[!] Warning: Could not clear previous source dir: {e}", user_id)
            
    source_dir.mkdir(parents=True, exist_ok=True)

    try:
        if input_type == "zip":
            zip_path = Path(target_input)
            if not zip_path.exists():
                log(f"[!] Input zip file not found: {zip_path}", user_id, to_console=True)
                return None
            
            log(f"[*] Extracting {zip_path.name} (Smart Unzip)...", user_id, to_console=True)
            if not smart_unzip(zip_path, source_dir, user_id=user_id):
                log(f"[!] Failed to extract ZIP file.", user_id, to_console=True)
                return None
            log(f"[+] Extraction complete.", user_id, to_console=True)

        elif input_type == "git":
            log(f"[*] Cloning Git repository: {target_input}...", user_id, to_console=True)
            # [FIXED] Added encoding='utf-8' to prevent crashes on Windows
            subprocess.run(
                ["git", "clone", "--depth", "1", target_input, str(source_dir)],
                check=True, capture_output=True, text=True, encoding='utf-8',
                creationflags=_get_subprocess_creation_flags()
            )
        else:
            log(f"[!] Unknown input type: {input_type}", user_id, to_console=True)
            return None

        # 2. Run Semgrep
        log(f"[+] Starting Semgrep analysis on {source_dir.name}...", user_id, to_console=True)
        log(f"[*] Using rulesets: {', '.join(SEMGREP_RULES)}", user_id, to_console=True)

        # [FIXED] Use the absolute path to semgrep we found earlier
        cmd = [semgrep_cmd, "scan", "--json", "--output", str(raw_report_path)]
        
        # Add config flags
        for rule in SEMGREP_RULES:
            cmd.extend(["--config", rule])
        
        # Target the source directory
        cmd.append(str(source_dir))

        log(f"[*] Executing Semgrep command...", user_id, to_console=True)
        
        # [FIXED] Added encoding='utf-8' here to fix the UnicodeDecodeError
        process = subprocess.run(
            cmd,
            capture_output=True, text=True, encoding='utf-8',
            creationflags=_get_subprocess_creation_flags()
        )

        if not raw_report_path.exists() or raw_report_path.stat().st_size == 0:
            log(f"[!] Semgrep finished but produced no output. Error: {process.stderr}", user_id, to_console=True)
            return None

        log(f"[+] Scan complete. Raw results saved to {raw_report_path.name}", user_id, to_console=True)

        # 3. Parse and Save Final Report
        final_report = parse_semgrep_results(raw_report_path, output_dir, user_id=user_id)
        
        if final_report:
            # Notify Frontend
            send_sse_event("semgrep_scan_complete", {
                "total_findings": final_report['total_findings'],
                "high_risk": final_report['severity_counts']['ERROR'],
                "report_file": str(paths['parsed_json'])
            }, user_id=user_id)
            return str(paths['parsed_json'])
        
        return None

    except subprocess.CalledProcessError as e:
        log(f"[!] Git clone or Semgrep command failed: {e}", user_id)
        # Only log stderr if it exists and is not None
        if hasattr(e, 'stderr') and e.stderr:
            log(f"Stderr: {e.stderr}", user_id)
        return None
    except Exception as e:
        log(f"[!] Unexpected error during Semgrep scan: {e}", user_id)
        return None
    finally:
        # 4. Cleanup Source Code & Raw Report (Save disk space)
        if source_dir.exists():
            try:
                # [FIXED] Force delete even read-only files (common with Git)
                def on_rm_error(func, path, exc_info):
                    # Change permission and try again (for stubborn Git files)
                    os.chmod(path, 0o777)
                    func(path)

                shutil.rmtree(source_dir, onerror=on_rm_error)
                log("[*] Cleanup: Temporary source code directory removed.", user_id)
            except Exception as e:
                log(f"[!] Warning: Failed to cleanup temp dir: {e}", user_id)
        
        if raw_report_path.exists():
            try:
                raw_report_path.unlink()
                log("[*] Cleanup: Temporary raw report removed.", user_id)
            except Exception as e:
                log(f"[!] Warning: Failed to cleanup raw report: {e}", user_id)


def parse_semgrep_results(raw_json_path, output_dir=None, user_id=None):
    """
    Parses Semgrep raw JSON into a clean structure for the UI and PDF generator.
    """
    paths = get_output_paths(output_dir)
    output_file = paths["parsed_json"]

    try:
        with open(raw_json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        clean_report = {
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tool": "Semgrep",
            "total_findings": 0,
            "severity_counts": {"ERROR": 0, "WARNING": 0, "INFO": 0},
            "findings": []
        }

        # Extract Findings
        if 'results' in data:
            for result in data['results']:
                severity_raw = result['extra'].get('severity', 'INFO').upper()
                severity = severity_raw if severity_raw in clean_report["severity_counts"] else "INFO"
                
                # Count severity
                clean_report["severity_counts"][severity] += 1

                finding = {
                    "check_id": result.get('check_id', 'Unknown Check'),
                    "path": result.get('path', 'Unknown File'),
                    "line": result['start']['line'] if 'start' in result else 0,
                    "column": result['start']['col'] if 'start' in result else 0,
                    "message": result['extra'].get('message', 'No message provided'),
                    "severity": severity,
                    "code_snippet": result['extra'].get('lines', 'N/A').strip(),
                    "fix_suggestion": result['extra'].get('fix', 'N/A')
                }
                clean_report["findings"].append(finding)

        clean_report["total_findings"] = len(clean_report["findings"])

        # Save Parsed JSON
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(clean_report, f, indent=4)
        
        log(f"[+] Parsed report saved to {output_file}", user_id)
        return clean_report

    except json.JSONDecodeError:
        log(f"[!] Error: Raw Semgrep output is not valid JSON.", user_id)
        return None
    except Exception as e:
        log(f"[!] Error parsing Semgrep results: {e}", user_id)
        return None


# --- Main Test Block ---
if __name__ == "__main__":
    log("Starting Semgrep Scanner demonstration...")
    clear_log_file()
    
    # Simulate a user ID scan
    test_user_id = "test_user_99"
    test_output_dir = BASE_DIR / "Services" / "results" / "semgrep_scanner" / test_user_id
    
    # Uncomment to test with a real repo:
    target_repo = "https://github.com/we45/Vulnerable-Flask-App.git"
    log(f"Testing Scan on: {target_repo}")
    report = run_semgrep_scan(target_repo, input_type="git", output_dir=test_output_dir)
    
    if report:
        print(f"\n[SUCCESS] Report generated at: {report}")
    else:
        print("\n[FAILED] Scan did not complete successfully.")

    log("Semgrep Scanner agent loaded successfully.")