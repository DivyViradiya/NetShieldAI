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
BASE_DIR = Path(__file__).parent.parent
# Default results path (Fallback)
DEFAULT_RESULTS_DIR = BASE_DIR / "Services" / "results" / "semgrep_scanner"
DEFAULT_RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Logs
LOG_FILE = BASE_DIR / "logs" / "semgrep_agent_log.txt"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

# Global queue for logging messages (Consumed by Flask)
log_queue = queue.Queue()

# Standard Semgrep Rulesets to use
SEMGREP_RULES = ["p/security-audit", "p/secrets", "p/python", "p/javascript", "p/flask"]


# --- Logging & Events ---
def log(message):
    """Logs messages to an in-memory queue and to a file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"data: [{timestamp}] {message}\n\n"  # SSE format
    
    # Put message into the queue for Flask to stream
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

def clear_log_file():
    """Clears the content of the log output file."""
    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write("")
        log("[*] Semgrep log file cleared.")
    except Exception as e:
        log(f"[!] Error clearing Semgrep log file: {e}")


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

def is_semgrep_installed():
    """Checks if Semgrep is accessible in the environment."""
    path = get_semgrep_path()
    if path:
        return True
    
    log("[!] ERROR: 'semgrep' executable not found.")
    log(f"[!] Checked system PATH and: {os.path.join(sys.prefix, 'Scripts')}")
    log("[!] Please ensure 'pip install semgrep' was run in THIS virtual environment.")
    return False

def get_output_paths(output_dir=None):
    """
    Returns a dictionary of file paths based on the output directory.
    If output_dir is None, uses the global DEFAULT_RESULTS_DIR.
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
        "raw_json": base / "semgrep_raw.json",
        "parsed_json": base / "semgrep_report.json",  # Cleaned for UI/PDF
        "source_code": base / "source_code_temp"       # Temp extraction folder
    }

def smart_unzip(zip_path, extract_to):
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
                    log(f"[!] Security Warning: Skipped suspicious file path in zip: {file}")
                    continue

                # Extract
                zip_ref.extract(file, extract_to)
        return True
    except Exception as e:
        log(f"[!] Error unzipping file: {e}")
        return False


# --- Core Scanning Logic ---

def run_semgrep_scan(target_input, input_type="zip", output_dir=None):
    """
    Main entry point for running a scan.
    
    :param target_input: Path to zip file OR Git URL string.
    :param input_type: 'zip' or 'git'.
    :param output_dir: Directory to store results (User ID folder).
    """
    semgrep_cmd = get_semgrep_path()
    if not semgrep_cmd:
        return None

    paths = get_output_paths(output_dir)
    source_dir = paths["source_code"]
    raw_report_path = paths["raw_json"]

    # 1. Prepare Source Code
    log(f"[*] Preparing source code for analysis...")
    
    # Ensure clean slate for source code
    if source_dir.exists():
        try:
            # [FIXED] Force delete previous temp folder if it exists
            def on_rm_error(func, path, exc_info):
                os.chmod(path, 0o777)
                func(path)
            shutil.rmtree(source_dir, onerror=on_rm_error)
        except Exception as e:
            log(f"[!] Warning: Could not clear previous source dir: {e}")
            
    source_dir.mkdir(parents=True, exist_ok=True)

    try:
        if input_type == "zip":
            zip_path = Path(target_input)
            if not zip_path.exists():
                log(f"[!] Input zip file not found: {zip_path}")
                return None
            
            log(f"[*] Extracting {zip_path.name} (Smart Unzip)...")
            if not smart_unzip(zip_path, source_dir):
                return None

        elif input_type == "git":
            log(f"[*] Cloning Git repository: {target_input}...")
            # [FIXED] Added encoding='utf-8' to prevent crashes on Windows
            subprocess.run(
                ["git", "clone", "--depth", "1", target_input, str(source_dir)],
                check=True, capture_output=True, text=True, encoding='utf-8',
                creationflags=_get_subprocess_creation_flags()
            )
        else:
            log(f"[!] Unknown input type: {input_type}")
            return None

        # 2. Run Semgrep
        log(f"[+] Starting Semgrep analysis on {source_dir.name}...")
        log(f"[*] Using rulesets: {', '.join(SEMGREP_RULES)}")

        # [FIXED] Use the absolute path to semgrep we found earlier
        cmd = [semgrep_cmd, "scan", "--json", "--output", str(raw_report_path)]
        
        # Add config flags
        for rule in SEMGREP_RULES:
            cmd.extend(["--config", rule])
        
        # Target the source directory
        cmd.append(str(source_dir))

        log(f"[*] Executing Semgrep command...")
        
        # [FIXED] Added encoding='utf-8' here to fix the UnicodeDecodeError
        process = subprocess.run(
            cmd,
            capture_output=True, text=True, encoding='utf-8',
            creationflags=_get_subprocess_creation_flags()
        )

        if not raw_report_path.exists() or raw_report_path.stat().st_size == 0:
            log(f"[!] Semgrep finished but produced no output. Error: {process.stderr}")
            return None

        log(f"[+] Scan complete. Raw results saved to {raw_report_path.name}")

        # 3. Parse and Save Final Report
        final_report = parse_semgrep_results(raw_report_path, output_dir)
        
        if final_report:
            # Notify Frontend
            send_sse_event("semgrep_scan_complete", {
                "total_findings": final_report['total_findings'],
                "high_risk": final_report['severity_counts']['ERROR'],
                "report_file": str(paths['parsed_json'])
            })
            return str(paths['parsed_json'])
        
        return None

    except subprocess.CalledProcessError as e:
        log(f"[!] Git clone or Semgrep command failed: {e}")
        # Only log stderr if it exists and is not None
        if hasattr(e, 'stderr') and e.stderr:
            log(f"Stderr: {e.stderr}")
        return None
    except Exception as e:
        log(f"[!] Unexpected error during Semgrep scan: {e}")
        return None
    finally:
        # 4. Cleanup Source Code (Save disk space)
        if source_dir.exists():
            try:
                # [FIXED] Force delete even read-only files (common with Git)
                def on_rm_error(func, path, exc_info):
                    # Change permission and try again (for stubborn Git files)
                    os.chmod(path, 0o777)
                    func(path)

                shutil.rmtree(source_dir, onerror=on_rm_error)
                log("[*] Cleanup: Temporary source code directory removed.")
            except Exception as e:
                log(f"[!] Warning: Failed to cleanup temp dir: {e}")


def parse_semgrep_results(raw_json_path, output_dir=None):
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
                severity = result['extra'].get('severity', 'INFO')
                
                # Count severity
                if severity in clean_report["severity_counts"]:
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
        
        log(f"[+] Parsed report saved to {output_file}")
        return clean_report

    except json.JSONDecodeError:
        log(f"[!] Error: Raw Semgrep output is not valid JSON.")
        return None
    except Exception as e:
        log(f"[!] Error parsing Semgrep results: {e}")
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