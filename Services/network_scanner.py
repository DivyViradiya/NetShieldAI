import subprocess
import os
import sys
import ctypes
import socket
from datetime import datetime
import psutil
import re
import platform
import threading
import queue
import time
import json
import uuid
from pathlib import Path
from Services import report_manager
from .tctr_engine import tctr_engine

# --- PHASE 2: Dynamic Path Setup ---
# BASE_DIR should be at the root of the project (one level up from Services/network_scanner.py)
BASE_DIR = Path(__file__).parent.parent

# We keep the default global path for backward compatibility or system-wide actions.
DEFAULT_RESULTS_DIR = BASE_DIR / "Services" / "results" / "network_scanner"

# Ensure logs directory exists
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "network_agent_log.txt"

TEMP_DIR = BASE_DIR / "Services" / "temp" / "nmap"
TEMP_DIR.mkdir(parents=True, exist_ok=True)

# --- Global State for Process Management (Isolated by user_id) ---
active_scans = {} # { "user_id": {"process": Popen, "target": str, "start_time": float} }
scan_lock = threading.Lock()

# --- USER ISOLATION: Dictionary to hold a queue for each user_id ---
user_queues = {}
_queue_lock = threading.Lock()  # RC-1 FIX: protect concurrent queue creation

def get_user_queue(user_id):
    """Ensures a queue exists for the user and returns it. Thread-safe."""
    with _queue_lock:
        if user_id not in user_queues:
            user_queues[user_id] = queue.Queue()
        return user_queues[user_id]

def is_scan_running(user_id):
    """Checks if a scan is currently active for a specific user."""
    with scan_lock:
        return user_id in active_scans

# Globals for application state (Isolated by user_id)
user_open_ports = {} # { "user_id": {"TCP": [], "UDP": [], "metadata": {}} }
user_whitelisted_ports = {} # { "user_id": set() }
_ports_lock = threading.Lock()  # RC-2 FIX: protect concurrent port data access

def get_user_open_ports(user_id):
    """Ensures open_ports structure exists for the user. Thread-safe."""
    user_id = str(user_id) if user_id else "system"
    with _ports_lock:
        if user_id not in user_open_ports:
            user_open_ports[user_id] = {
                "TCP": [], 
                "UDP": [], 
                "metadata": {"os_guess": "Unknown", "host_status": "Unknown", "latency": "0ms", "insights": "Waiting for scan..."}
            }
        elif "metadata" not in user_open_ports[user_id]:
            user_open_ports[user_id]["metadata"] = {"os_guess": "Unknown", "host_status": "Unknown", "latency": "0ms", "insights": "Waiting for scan..."}
        return user_open_ports[user_id]

def get_user_whitelisted_ports(user_id):
    """Ensures whitelist set exists for the user. Thread-safe."""
    user_id = str(user_id) if user_id else "system"
    with _ports_lock:
        if user_id not in user_whitelisted_ports:
            user_whitelisted_ports[user_id] = set()
        return user_whitelisted_ports[user_id]

def load_results_from_json(output_dir, user_id):
    """Loads scan results from the persisted JSON report into memory."""
    paths = get_output_paths(output_dir)
    json_file = paths["json_report"]
    
    if not json_file.exists():
        history = report_manager.get_report_history(output_dir, scanner_name="network_scanner", extension="json")
        if history:
            json_file = Path(history[0]['path'])

    user_data = get_user_open_ports(user_id)
    
    if json_file.exists():
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                with _ports_lock:
                    # Update Ports
                    user_data["TCP"].clear()
                    user_data["UDP"].clear()
                    for p in data.get("ports", []):
                        if p.get("protocol") == "UDP":
                            user_data["UDP"].append(p)
                        else:
                            user_data["TCP"].append(p)
                    
                    user_data["metadata"]["os_guess"] = data.get("os_guess", "Unknown")
                    user_data["metadata"]["host_status"] = data.get("host_status", "Unknown")
                    
                    # Insights usually from raw processing, but we can synthesize if missing
                    current_insights = user_data["metadata"].get("insights", "")
                    if "waiting" in current_insights.lower() or "scanning" in current_insights.lower() or "detected" in current_insights.lower():
                        total_found = len(data.get("ports", []))
                        if total_found > 0:
                            user_data["metadata"]["insights"] = f"Detected {total_found} active services from persisted report."
                        else:
                            user_data["metadata"]["insights"] = "No open services detected in last scan."
                    
                return True
        except Exception as e:
            log(f"[!] Error loading persisted JSON report: {e}", user_id)
    return False

def get_scan_summary(user_id=None, output_dir=None):
    """Returns both open ports and scan metadata for the user."""
    user_data = get_user_open_ports(user_id)
    
    with _ports_lock:
        # If memory is empty but we have an output_dir, try loading from disk
        if not user_data["TCP"] and not user_data["UDP"] and output_dir:
            # Drop lock to call loader (it has its own lock)
            pass
        else:
            return {
                "open_ports": sorted(user_data["TCP"] + user_data["UDP"], key=lambda x: int(x['port']) if str(x['port']).isdigit() else 0),
                "metadata": user_data["metadata"]
            }
            
    # Load from disk if memory was empty
    if output_dir:
        load_results_from_json(output_dir, user_id)
        with _ports_lock:
            return {
                "open_ports": sorted(user_data["TCP"] + user_data["UDP"], key=lambda x: int(x['port']) if str(x['port']).isdigit() else 0),
                "metadata": user_data["metadata"]
            }
            
    return {
        "open_ports": [],
        "metadata": user_data["metadata"]
    }

from Services import scan_logger
from logger_setup import logger

def log(message, user_id=None, queue_id=None, to_console=False, level='INFO'):
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
        scan_logger.write_log(user_id, "network_scanner", message, level=level)

def send_sse_event(event_name, data="", user_id=None, queue_id=None):
    """
    Simulates SSE event by logging a special format line that tail_log_file can pick up.
    """
    # For now, just log it as a structured message
    if isinstance(data, (dict, list)):
        import json
        data_str = json.dumps(data)
    else:
        data_str = str(data)
        
    log(f"EVENT: {event_name} | PAYLOAD: {data_str}", user_id, queue_id)

def is_valid_hostname(hostname):
    """
    Validates if a string is a valid hostname/domain.
    """
    if not hostname or len(hostname) > 255:
        return False
    
    # Remove protocol if present for validation purposes
    clean_host = hostname.replace("https://", "").replace("http://", "").split('/')[0].split(':')[0]
    
    # Regex for valid domain names
    hostname_regex = r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$"
    
    return re.match(hostname_regex, clean_host) is not None

# --- PHASE 2: Dynamic Path Helper ---
def get_output_paths(output_dir=None, target=None):
    """
    Returns a dictionary of file paths.
    If output_dir is provided (User ID folder), it returns paths in that folder.
    Otherwise, it defaults to the global DEFAULT_RESULTS_DIR.
    """
    if output_dir:
        base = Path(output_dir)
    else:
        base = DEFAULT_RESULTS_DIR
    
    if not base.exists():
        try:
            base.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            log(f"[!] Error creating output directory {base}: {e}")

    # If output_dir is provided, all results (including raw) should go there for persistence
    # Otherwise, raw results go to TEMP_DIR
    raw_base = base if output_dir else TEMP_DIR

    if target:
        json_filename = report_manager.generate_report_filename("network_scanner", target, "json")
        pdf_filename = report_manager.generate_report_filename("network_scanner", target, "pdf")
    else:
        json_filename = "nmap_report.json"
        pdf_filename = "nmap_report.pdf"

    return {
        "whitelist": base / "whitelisted_ports.json",
        "json_report": base / json_filename,
        "pdf_report": base / pdf_filename,
        "tcp": raw_base / "scan_result_tcp.txt",
        "udp": raw_base / "scan_result_udp.txt",
        "os": raw_base / "scan_result_os.txt",
        "fragmented": raw_base / "scan_result_fragmented.txt",
        "aggressive": raw_base / "scan_result_aggressive.txt",
        "tcp_syn": raw_base / "scan_result_tcp_syn.txt",
        "vuln": raw_base / "scan_result_vuln.txt",
        # --- NEW PATHS FOR ADVANCED SCANS ---
        "connect": raw_base / "scan_result_connect.txt",
        "null": raw_base / "scan_result_null.txt",
        "fin": raw_base / "scan_result_fin.txt",
        "xmas": raw_base / "scan_result_xmas.txt",
        "ack": raw_base / "scan_result_ack.txt",
        "window": raw_base / "scan_result_window.txt",
        "ping": raw_base / "scan_result_ping.txt",
        "decoy": raw_base / "scan_result_decoy.txt"
    }

# --- Whitelist Persistence Functions (Updated for Phase 2) ---
def load_whitelist(output_dir=None, user_id=None, queue_id=None):
    """Loads whitelisted ports from a JSON file."""
    whitelisted_ports = get_user_whitelisted_ports(user_id)
    paths = get_output_paths(output_dir)
    whitelist_file = paths["whitelist"]

    if whitelist_file.exists():
        try:
            with open(whitelist_file, 'r', encoding='utf-8') as f:
                loaded_ports = json.load(f)
                if isinstance(loaded_ports, list):
                    whitelisted_ports.clear()
                    whitelisted_ports.update(loaded_ports)
                    log(f"[+] Loaded {len(whitelisted_ports)} whitelisted ports from {whitelist_file}.", user_id, queue_id)
                else:
                    log(f"[!] Whitelist file '{whitelist_file}' contains invalid format. Starting with empty whitelist.", user_id, queue_id)
                    whitelisted_ports.clear()
        except json.JSONDecodeError as e:
            log(f"[!] Error decoding whitelist file '{whitelist_file}': {e}. Starting with empty whitelist.", user_id, queue_id)
            whitelisted_ports.clear()
        except Exception as e:
            log(f"[!] Unexpected error loading whitelist file '{whitelist_file}': {e}. Starting with empty whitelist.", user_id, queue_id)
            whitelisted_ports.clear()
    else:
        log(f"[*] Whitelist file '{whitelist_file}' not found. Starting with empty whitelist.", user_id, queue_id)
    
    # We don't force save here on load to avoid creating files unnecessarily if reading only
    if not output_dir: 
        save_whitelist(user_id=user_id, queue_id=queue_id) # Ensure global file exists on startup if using global

def save_whitelist(output_dir=None, user_id=None, queue_id=None):
    """Saves the current whitelisted ports to a JSON file."""
    whitelisted_ports = get_user_whitelisted_ports(user_id)
    paths = get_output_paths(output_dir)
    whitelist_file = paths["whitelist"]
    try:
        with open(whitelist_file, 'w', encoding='utf-8') as f:
            json.dump(list(whitelisted_ports), f, indent=4)
        log(f"[+] Whitelist saved to {whitelist_file}.", user_id, queue_id)
    except Exception as e:
        log(f"[!] Error saving whitelist to file '{whitelist_file}': {e}", user_id, queue_id)

def clear_whitelist(output_dir=None, user_id=None, queue_id=None):
    """Clears the whitelisted ports and saves the empty state."""
    whitelisted_ports = get_user_whitelisted_ports(user_id)
    whitelisted_ports.clear()
    save_whitelist(output_dir, user_id=user_id, queue_id=queue_id)
    log("[*] Whitelist cleared.", user_id, queue_id)

# --- OS-Specific Helper Functions ---

def _get_subprocess_creation_flags():
    """Returns appropriate creation flags for subprocess based on OS."""
    if platform.system() == "Windows":
        return subprocess.CREATE_NO_WINDOW
    return 0 # Default for Linux/macOS

# Elevation
def is_admin():
    """Checks if the script is running with administrative/root privileges."""
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    else: # Linux/macOS
        return os.geteuid() == 0

def ensure_admin_privileges():
    """
    Checks for admin privileges. If not present, it attempts to re-launch the script
    with elevated permissions.
    """
    if is_admin():
        return True # We are already admin, continue execution.

    # If not admin, attempt to re-launch with privileges
    logger.info("Administrator privileges not found. Requesting elevation...")
    
    try:
        if platform.system() == "Windows":
            # Re-launch with the 'runas' verb to trigger the UAC prompt
            ctypes.windll.shell32.ShellExecuteW(
                None,           # Handle to parent window
                "runas",        # Verb: ask for elevation
                sys.executable, # File to execute (the python interpreter)
                " ".join(sys.argv), # Parameters (the script file and its args)
                None,           # Working directory
                1               # Show the new window
            )
        
        elif platform.system() in ["Linux", "Darwin"]: # Darwin is macOS
            # Re-launch using sudo
            args = ['sudo', sys.executable] + sys.argv
            subprocess.call(args)
            
        else:
            logger.error(f"Automatic privilege elevation not supported on this OS: {platform.system()}")
            time.sleep(5)
            return False

        # The original non-elevated script should exit after launching the new one
        sys.exit(0)

    except Exception as e:
        logger.error(f"Failed to re-launch with admin rights: {e}")
        time.sleep(5)
        sys.exit(1)


# Network Helpers
def get_local_ip():
    """Detects and returns the local IP address."""
    try:
        # Simplified logic to act as a fallback
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        # Fallback to the psutil method provided in original code
        interfaces = psutil.net_if_addrs()
        for iface, addrs in interfaces.items():
            if platform.system() == "Windows":
                if any(x in iface for x in ["Virtual", "VMware", "Loopback", "vEthernet", "WSL"]):
                    continue
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address.startswith("192.168."):
                        return addr.address
            else:
                if any(x in iface for x in ["lo", "docker", "virbr", "veth", "br-"]):
                    continue
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        if ip.startswith("192.168.") or ip.startswith("10.") or \
                           (ip.startswith("172.") and 16 <= int(ip.split('.')[1]) <= 31):
                            return ip
        return "127.0.0.1"
    
def resolve_to_ip(target_input, user_id=None, queue_id=None):
    """
    Checks if input is an IP/Range or a URL. 
    If it's a URL, it extracts the hostname and resolves it to an IP.
    """
    # If it's already a valid IP or CIDR range, return it as is
    if is_valid_ip_or_range(target_input):
        return target_input
    
    try:
        # Clean the URL
        clean_host = target_input.replace("https://", "").replace("http://", "").split('/')[0].split(':')[0]
        
        log(f"[*] Attempting to resolve hostname: {clean_host}", user_id, queue_id)
        resolved_ip = socket.gethostbyname(clean_host)
        log(f"[+] Resolved {clean_host} to {resolved_ip}", user_id, queue_id)
        return resolved_ip
    except socket.gaierror:
        log(f"[!] DNS Resolution failed for: {target_input}", user_id, queue_id)
        return None
    except Exception as e:
        log(f"[!] Unexpected error during resolution: {e}", user_id, queue_id)
        return None

def is_valid_ip_or_range(target):
    """
    Validates if the input is a valid IP address, CIDR range, or IP range.
    """
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    cidr_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/(?:[0-9]|[1-2][0-9]|3[0-2])$"
    ip_range_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}-(?:[0-9]{1,3})$"

    if re.match(ip_regex, target):
        octets = target.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            return True
    elif re.match(cidr_regex, target):
        ip_part, _ = target.split('/')
        octets = ip_part.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            return True
    elif re.match(ip_range_regex, target):
        parts = target.split('-')
        first_ip_octets = parts[0].split('.')
        if all(0 <= int(octet) <= 255 for octet in first_ip_octets) and 0 <= int(parts[1]) <= 255:
            return True
    
    return False

def is_nmap_installed(user_id=None, queue_id=None):
    """Checks if Nmap is installed and accessible in the system's PATH."""
    try:
        subprocess.run(
            ['nmap', '--version'],
            capture_output=True, text=True, check=True,
            creationflags=_get_subprocess_creation_flags()
        )
        return True
    except FileNotFoundError:
        log("[!] 'nmap' command not found. Please install Nmap and ensure it's in your system's PATH.", user_id, queue_id)
        return False
    except subprocess.CalledProcessError as e:
        log(f"[!] Nmap is installed but returned an error on version check: {e.stderr.strip()}", user_id, queue_id)
        return False
    except Exception as e:
        log(f"[!] An unexpected error occurred while checking for Nmap: {e}", user_id, queue_id)
        return False

def get_process_info_for_port(port_num, protocol="TCP", user_id=None, queue_id=None):
    """
    Attempts to find the process name listening on a specific TCP/UDP port.
    """
    process_name = "N/A"
    try:
        if platform.system() == "Windows":
            netstat_cmd = ['netstat', '-ano']
            netstat_output = subprocess.check_output(netstat_cmd, text=True, creationflags=_get_subprocess_creation_flags(), stderr=subprocess.PIPE)
            
            pid = None
            for line in netstat_output.splitlines():
                if f":{port_num} " in line and (protocol.upper() in line.upper()):
                    # For TCP, ensure it's in a listening state
                    if protocol.upper() == "TCP" and "LISTENING" not in line:
                        continue
                    parts = line.strip().split()
                    if parts:
                        pid = parts[-1]
                        break

            if pid and pid.isdigit():
                tasklist_cmd = ['tasklist', '/FI', f"PID eq {pid}", '/FO', 'CSV', '/NH']
                tasklist_output = subprocess.check_output(tasklist_cmd, text=True, creationflags=_get_subprocess_creation_flags(), stderr=subprocess.PIPE)
                
                if tasklist_output.strip():
                    process_name_match = re.match(r'^\"([^\"]+)\"', tasklist_output.strip())
                    if process_name_match:
                        process_name = process_name_match.group(1)
                    else:
                        process_name = f"Unknown (PID {pid})"
                else:
                    process_name = f"No process found for PID {pid}"
            else:
                process_name = "No listening PID found"

        else: # Linux/macOS
            cmd = ['lsof', '-i', f"{protocol.lower()}:{port_num}", '-P', '-n']
            lsof_output = subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE, creationflags=_get_subprocess_creation_flags())

            for line in lsof_output.splitlines():
                if f':{port_num}' in line and ('(LISTEN)' in line if protocol == "TCP" else True):
                    parts = line.split()
                    if parts:
                        process_name = parts[0]
                        try:
                            pid = parts[1]
                            # On Linux, /proc provides more command details
                            if platform.system() == "Linux":
                                with open(f'/proc/{pid}/cmdline', 'rb') as f:
                                    cmdline_raw = f.read()
                                    full_cmd = cmdline_raw.decode('utf-8', errors='ignore').replace('\x00', ' ').strip()
                                    if full_cmd:
                                        process_name = full_cmd
                        except (FileNotFoundError, IndexError):
                            pass # Stick with the process name from lsof if /proc fails
                        break
    except subprocess.CalledProcessError as e:
        if "no process found" in e.stderr.lower() or "no such file or directory" in e.stderr.lower():
            process_name = "No process found"
        else:
            log(f"[!] Error getting process info for {protocol} port {port_num}: {e.stderr.strip()}", user_id, queue_id)
            process_name = "Error (Cmd Failed)"
    except FileNotFoundError:
        log(f"[!] Command not found for process info ({'netstat/tasklist' if platform.system() == 'Windows' else 'lsof'}). Cannot determine process info.", user_id, queue_id)
        process_name = "Error (Cmd Missing)"
    except Exception as e:
        log(f"[!] Unexpected error getting process info for {protocol} port {port_num}: {e}", user_id, queue_id)
        process_name = "Error"
    
    return process_name

# --- NEW: JSON REPORT GENERATION FOR PDF ---

def parse_nmap_grepable_output(file_path, user_id=None, queue_id=None):
    """
    Parses the Nmap -oG (Grepable) text file into a Python Dictionary.
    """
    parsed_data = {
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_args": "N/A",
        "target_ip": "Unknown",
        "host_status": "Down",
        "os_guess": "Unknown / Not Detected",
        "ports": [],
        "raw_output_summary": "" 
    }

    if not os.path.exists(file_path):
        log(f"[!] Nmap grepable output file not found: {file_path}", user_id, queue_id)
        return parsed_data

    # Step 1: Pre-process the file to gather port-specific vulnerability notes
    port_vuln_notes = {}
    current_port_key = None
    general_notes = []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        is_vuln_scan = "vuln" in str(file_path)

        for line in lines:
            line = line.strip()
            
            if line.startswith("# Nmap") or line.startswith("Host:") or line.startswith("Stats:"):
                general_notes.append(line)

            if line.startswith("# Nmap") and "scan initiated" in line and "as:" in line:
                parsed_data["scan_args"] = line.split("as:", 1)[1].strip()

            if line.startswith("Host:"):
                ip_match = re.search(r"Host: ([\d\.]+)", line)
                if ip_match: parsed_data["target_ip"] = ip_match.group(1)
                if "Status: Up" in line: parsed_data["host_status"] = "Up"
                os_match = re.search(r"OS: ([^;]+)", line)
                if os_match: parsed_data["os_guess"] = os_match.group(1).strip()
            
            if "Ports:" in line:
                current_port_key = None
                
                ports_section = line.split("Ports:")[1].strip()
                port_entries = ports_section.split(',')
                
                for entry in port_entries:
                    entry = entry.strip()
                    if not entry or "Ignored State" in entry: continue
                        
                    parts = entry.split('/')
                    if len(parts) >= 3 and 'open' in parts[1]:
                        port_num = parts[0].strip()
                        protocol = parts[2].strip().upper()
                        current_port_key = f"{port_num}/{protocol}"
                        
                        if current_port_key not in port_vuln_notes:
                             port_vuln_notes[current_port_key] = []

            if current_port_key and is_vuln_scan and (
                'CVE' in line or 'VULNERABLE' in line or 'risk' in line.lower() or 'exploit' in line.lower()
            ):
                note = line.split("Host:")[0].strip()
                if note and note not in port_vuln_notes[current_port_key]:
                    port_vuln_notes[current_port_key].append(note)
            
            if line.endswith(")") and not line.startswith("Host:") and not line.startswith("# Nmap"):
                 current_port_key = None

        # Step 2: Extract structured port data
        for line in lines:
            line = line.strip()
            if "Ports:" in line:
                ports_section = line.split("Ports:")[1].strip()
                port_entries = ports_section.split(',')
                
                for entry in port_entries:
                    entry = entry.strip()
                    if not entry or "Ignored State" in entry: continue
                        
                    parts = entry.split('/')
                    if len(parts) >= 3 and 'open' in parts[1]:
                        port_num = parts[0].strip()
                        protocol = parts[2].strip().upper()
                        
                        proc_name = get_process_info_for_port(port_num, protocol=protocol, user_id=user_id)

                        vuln_key = f"{port_num}/{protocol}"
                        vulnerability_notes = "\n---\n".join(port_vuln_notes.get(vuln_key, []))

                        port_obj = {
                            "port": port_num,
                            "state": parts[1].strip(),
                            "protocol": protocol,
                            "service": parts[4].strip() if len(parts) > 4 else "unknown",
                            "version": parts[6].strip() if len(parts) > 6 else "", 
                            "process_name": proc_name,
                            "vulnerability_notes": vulnerability_notes,
                            "cpe": parts[8].strip() if len(parts) > 8 else "N/A"
                        }
                        parsed_data["ports"].append(port_obj)

        parsed_data["raw_output_summary"] = "\n".join(general_notes)

    except Exception as e:
        log(f"[!] Error parsing Nmap output file for JSON report: {e}", user_id, queue_id)
    
    # Apply ML Threat Re-ranking
    try:
        for port in parsed_data["ports"]:
            prediction_obj = tctr_engine.predict_risk(
                f"Service: {port['service']} ({port['port']}/{port['protocol']})", 
                f"Version: {port['version']}\nVulnerability: {port['vulnerability_notes']}",
                cwe_id=None # Engine will fallback to 5.0 unless we add a service-to-CWE map
            )
            port["predicted_risk_score"] = prediction_obj["score"]
            port["tctr_priority"] = prediction_obj["tctr_priority"]
            port["base_score"] = prediction_obj["base_score"]
            port["priority_level"] = prediction_obj["priority_level"]
            port["risk_justification"] = prediction_obj["risk_justification"]
        
        # Sort by predicted score
        parsed_data["ports"].sort(
            key=lambda x: x.get('predicted_risk_score', 0),
            reverse=True
        )
    except Exception as e:
        log(f"[!] ML Re-ranking skipped or failed: {e}", user_id, queue_id)

    return parsed_data

def save_nmap_json(data, output_dir=None, user_id=None, queue_id=None, target=None):
    """Saves the parsed scan data to the JSON report file for PDF generation."""
    paths = get_output_paths(output_dir, target=target)
    json_file = paths["json_report"]
    try:
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        log(f"[+] JSON Scan report saved", user_id, queue_id)
    except Exception as e:
        log(f"[!] Failed to save JSON report: {e}", user_id, queue_id)

# --- Nmap Scanning ---
# Note: All scan functions implicitly require admin rights because they call run_nmap_scan
def run_os_detection_scan(target_ip, output_dir=None, user_id=None):
    return run_nmap_scan(target_ip, scan_type="os", output_dir=output_dir, user_id=user_id)

def run_fragmented_scan(target_ip, output_dir=None, user_id=None):
    return run_nmap_scan(target_ip, scan_type="fragmented", output_dir=output_dir, user_id=user_id)

def run_aggressive_scan(target_ip, output_dir=None, user_id=None):
    return run_nmap_scan(target_ip, scan_type="aggressive", output_dir=output_dir, user_id=user_id)

def run_tcp_syn_scan(target_ip, output_dir=None, user_id=None):
    return run_nmap_scan(target_ip, scan_type="tcp_syn", output_dir=output_dir, user_id=user_id)
    
def run_vulnerability_scan(target_ip, output_dir=None, user_id=None):
    return run_nmap_scan(target_ip, scan_type="vuln", output_dir=output_dir, user_id=user_id)

# --- NEW SCAN WRAPPERS FOR PHASE 2 ---
def run_ping_sweep(target_ip, output_dir=None, user_id=None):
    """Host Discovery only (-sn)."""
    return run_nmap_scan(target_ip, scan_type="ping_sweep", output_dir=output_dir, user_id=user_id)

def run_tcp_connect_scan(target_ip, output_dir=None, user_id=None):
    """TCP Connect Scan (-sT)."""
    return run_nmap_scan(target_ip, scan_type="tcp_connect", output_dir=output_dir, user_id=user_id)

def run_null_scan(target_ip, output_dir=None, user_id=None):
    """TCP Null Scan (-sN)."""
    return run_nmap_scan(target_ip, scan_type="null", output_dir=output_dir, user_id=user_id)

def run_fin_scan(target_ip, output_dir=None, user_id=None):
    """TCP FIN Scan (-sF)."""
    return run_nmap_scan(target_ip, scan_type="fin", output_dir=output_dir, user_id=user_id)

def run_xmas_scan(target_ip, output_dir=None, user_id=None):
    """TCP Xmas Scan (-sX)."""
    return run_nmap_scan(target_ip, scan_type="xmas", output_dir=output_dir, user_id=user_id)

def run_ack_scan(target_ip, output_dir=None, user_id=None):
    """TCP ACK Scan (-sA)."""
    return run_nmap_scan(target_ip, scan_type="ack", output_dir=output_dir, user_id=user_id)

def run_window_scan(target_ip, output_dir=None, user_id=None):
    """TCP Window Scan (-sW)."""
    return run_nmap_scan(target_ip, scan_type="window", output_dir=output_dir, user_id=user_id)

def run_decoy_scan(target_ip, output_dir=None, user_id=None):
    """Decoy Scan (-D) with Random Decoys."""
    return run_nmap_scan(target_ip, scan_type="decoy", output_dir=output_dir, user_id=user_id)


def run_nmap_scan(target_ip, protocol_type="TCP", scan_type="default", output_dir=None, user_id=None, timing=4, queue_id=None):
    """
    Runs an Nmap scan with the specified parameters using local Nmap installation.
    Supports extended mechanics (Timing, Evasion, Scan Techniques).
    
    timing: Integer 0-5 (default 4 - Aggressive).
    """
    if not is_admin():
        log(f"[!] Nmap scans require administrator privileges.", user_id, queue_id)
        return None

    # URL RESOLUTION LOGIC
    original_input = target_ip
    resolved_ip = resolve_to_ip(target_ip, user_id=user_id)
    
    if not resolved_ip:
        log(f"[!] Invalid target or resolution failed: {original_input}", user_id, queue_id)
        return None
    
    target_ip = resolved_ip

    # Get Dynamic Paths
    paths = get_output_paths(output_dir)

    # Handle scan types and flags
    flags = []
    
    # --- MULTI-USER FIX: Unique Temp Filename ---
    scan_uuid = str(uuid.uuid4())[:8]
    temp_prefix = f"scan_{user_id if user_id else 'sys'}_{scan_uuid}"
    output_file = TEMP_DIR / f"{temp_prefix}.txt"
    
    # Ensure timing is within bounds
    if timing < 0: timing = 0
    if timing > 5: timing = 5
    
    timing_flag = f"-T{timing}"
    
    # Base flags common to most port scans (Pn is critical for Windows local IPs)
    base_flags = [timing_flag, '-Pn'] 

    if scan_type == "os":
        flags = base_flags + ['-O', '--osscan-limit']
    elif scan_type == "fragmented":
        flags = base_flags + ['-f', '-sS']
    elif scan_type == "aggressive":
        flags = ['-A', timing_flag] 
    elif scan_type == "tcp_syn":
        flags = base_flags + ['-sS']
    elif scan_type == "vuln":
        flags = [timing_flag, '-sC', '-sV', '--script', 'vuln', '-Pn'] 
    elif protocol_type == "UDP":
        flags = [timing_flag, '-sU', '--top-ports', '1000', '-sV', '-Pn']
    elif scan_type == "ping_sweep":
        flags = [timing_flag, '-sn'] 
    elif scan_type == "tcp_connect":
        flags = base_flags + ['-sT']
    elif scan_type == "null":
        flags = base_flags + ['-sN']
    elif scan_type == "fin":
        flags = base_flags + ['-sF']
    elif scan_type == "xmas":
        flags = base_flags + ['-sX']
    elif scan_type == "ack":
        flags = base_flags + ['-sA']
    elif scan_type == "window":
        flags = base_flags + ['-sW']
    elif scan_type == "decoy":
        flags = base_flags + ['-D', 'RND:10', '-sS']
    else: # Default TCP
        flags = base_flags + ['-sS', '--top-ports', '1000', '-sV']

    scan_type_display = scan_type.upper() if scan_type != "default" else f"{protocol_type} (Top 1000)"
    log(f"[+] Running {scan_type_display} scan on {target_ip} with timing {timing_flag}...", user_id, queue_id, to_console=True)

    # [NEW] Clear current in-memory results when a new scan starts
    user_data = get_user_open_ports(user_id)
    with _ports_lock:
        user_data["TCP"].clear()
        user_data["UDP"].clear()
        user_data["metadata"]["insights"] = f"Actively running {scan_type_display} scan..."
        user_data["metadata"]["host_status"] = "Scanning"
    
    # Notify UI that ports were cleared
    send_sse_event("ports_updated", {"ports": [], "vulnerabilities_count": 0}, user_id=user_id, queue_id=queue_id)

    if not os.path.exists(os.path.dirname(output_file)):
        os.makedirs(os.path.dirname(output_file))
    
    if not is_nmap_installed(user_id=user_id):
        return None

    # Construct Command
    cmd = ['nmap'] + flags + ['-oG', str(output_file), target_ip]

    # Add exclusion for Flask app port (5000) if scanning local IP
    local_ips = [get_local_ip(), "127.0.0.1"]
    if target_ip in local_ips or (is_valid_ip_or_range(target_ip) and target_ip.startswith("127.0.0.1")):
        if '-oG' in cmd:
            og_index = cmd.index('-oG')
            cmd.insert(og_index, '--exclude-ports')
            cmd.insert(og_index + 1, '5000')
        else:
            cmd.insert(1, '--exclude-ports')
            cmd.insert(2, '5000')

    log(f"[*] Executing: {' '.join(cmd)}", user_id, queue_id, to_console=True)
    
    try:
        # Use Popen to allow tracking if needed, or stick with run but register
        with scan_lock:
            # We use a dummy process object since run() is blocking, 
            # but for consistency with others, we'll use a thread-local identifier
            active_scans[user_id] = {"target": original_input, "start_time": time.time()}

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                creationflags=_get_subprocess_creation_flags(),
                timeout=600  # RC-5 FIX: 10-minute hard cap to prevent zombie threads
            )
        except subprocess.TimeoutExpired:
            log(f"[!] Nmap scan timed out after 600s for {target_ip}. Aborting.", user_id, queue_id, to_console=True)
            with scan_lock:
                active_scans.pop(user_id, None)
            return None

        with scan_lock:
            if user_id in active_scans:
                del active_scans[user_id]

        if result.returncode != 0:
            log(f"[!] Nmap scan failed with error: {result.stderr.strip()}", user_id, queue_id, to_console=True)
            send_sse_event("scan_failed", {"message": f"Nmap exited with code {result.returncode}"}, user_id, queue_id)
            return None

        if not output_file.exists() or output_file.stat().st_size == 0:
            log(f"[!] Nmap scan completed but no results were saved. This may be normal if no ports are open.", user_id, queue_id, to_console=True)
            
        log(f"[+] {scan_type_display} scan complete. Results synchronized.", user_id, queue_id, to_console=True)
        
        # [NEW] Persist raw results for the 'RAW DATA' tab in UI
        if output_dir:
            import shutil
            # Map scan_type to the key in get_output_paths
            scan_path_key = scan_type if scan_type in paths else 'tcp'
            if scan_type == 'default': scan_path_key = 'tcp'
            if scan_type == 'ping_sweep': scan_path_key = 'ping'
            if scan_type == 'tcp_connect': scan_path_key = 'connect'
            
            final_path = paths.get(scan_path_key, paths['tcp'])
            try:
                shutil.copy2(output_file, final_path)
                log(f"[*] Raw results persisted to: {final_path.name}", user_id, queue_id)
            except Exception as e:
                log(f"[!] Error persisting raw results: {e}", user_id, queue_id)

        # 1. Update UI (SSE)
        if scan_type != "ping_sweep":
            open_ports_list = extract_open_ports(output_file, protocol_type="TCP" if protocol_type == "TCP" or scan_type == "vuln" else protocol_type, user_id=user_id, queue_id=queue_id)
            send_sse_event("scan_complete", {
                "target": original_input, "protocol": protocol_type,
                "scan_type": scan_type, "open_ports": open_ports_list
            }, user_id=user_id, queue_id=queue_id)
        else:
             log(f"[*] Ping sweep complete. Check log or JSON report for host details.", user_id, queue_id)
             send_sse_event("scan_complete", {
                "target": original_input, "protocol": protocol_type,
                "scan_type": scan_type, "open_ports": [] # Ping sweep doesn't return open ports
            }, user_id=user_id, queue_id=queue_id)

        # 2. Generate JSON Report (PDF)
        log(f"[+] Processing results for PDF report...", user_id, queue_id)
        scan_data = parse_nmap_grepable_output(output_file, user_id=user_id, queue_id=queue_id)
        save_nmap_json(scan_data, output_dir=output_dir, user_id=user_id, queue_id=queue_id, target=original_input)
        
        return str(output_file)

    except Exception as e:
        log(f"[!] Error during {scan_type_display} scan: {str(e)}", user_id, queue_id)
        send_sse_event("scan_failed", {"message": str(e)}, user_id, queue_id)
        return None
    finally:
        # CLEANUP: Remove the temporary .txt file
        if output_file.exists():
            for i in range(5): 
                try:
                    output_file.unlink()
                    break
                except:
                    time.sleep(1)

def extract_open_ports(filename, protocol_type, user_id=None, queue_id=None):
    """
    Parses Nmap greppable output to extract open ports, process info, and
    associated vulnerability notes for UI update.
    """
    target_protocol = "TCP" if "vuln" in str(filename).lower() or protocol_type == "TCP" else "UDP"
    user_data = get_user_open_ports(user_id)

    # Wrap modifications in lock to prevent race conditions with concurrent /open_ports reads
    with _ports_lock:
        if target_protocol == "UDP":
            user_data["UDP"].clear()
        else:
            user_data["TCP"].clear()

    port_vuln_notes = {}
    current_port_key = None
    all_ports_list = []
    total_vuln_count = 0
    
    try:
        if not os.path.exists(filename):
            log(f"[!] Scan result file '{filename}' not found.", user_id, queue_id)
            return []

        with open(filename, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        is_vuln_scan = "vuln" in str(filename).lower()
        
        # Step 0: Extract Metadata (Host Status, OS, Latency)
        for line in lines:
            if line.startswith("Host:"):
                with _ports_lock:
                    if "Status: Up" in line: user_data["metadata"]["host_status"] = "Online"
                    
                    # Extract Latency
                    latency_match = re.search(r"Status: Up\s+\(([\d\.]+s)\s+latency\)", line)
                    if latency_match: user_data["metadata"]["latency"] = latency_match.group(1)
                    
                    # Extract OS Guess
                    os_match = re.search(r"OS: ([^;]+)", line)
                    if os_match: 
                        user_data["metadata"]["os_guess"] = os_match.group(1).strip()
                        
                        # Discovery Insights based on OS/Service
                        os_str = os_match.group(1).lower()
                        if "vmware" in os_str or "virtualbox" in os_str or "qemu" in os_str:
                            user_data["metadata"]["insights"] = "Virtual Machine environment detected. High probability of containerized or sandboxed infrastructure."
                        elif "aws" in os_str or "azure" in os_str or "google" in os_str:
                            user_data["metadata"]["insights"] = "Cloud Infrastructure detected. Review security groups and cloud-specific exposure."
                        elif "linux" in os_str:
                            user_data["metadata"]["insights"] = "Linux-based host identified. Check for SSH hardening and outdated kernel vulnerabilities."
                        elif "windows" in os_str:
                            user_data["metadata"]["insights"] = "Windows-based host identified. Evaluate SMB, RDP, and WinRM exposure."
                        else:
                            user_data["metadata"]["insights"] = "Physical or specialized hardware host identified. Review hardware-specific entry points."
        
        # Step 1: Pre-parse for vulnerability notes
        for line in lines:
            line = line.strip()
            if "Ports:" in line:
                current_port_key = None
                ports_section = line.split("Ports:")[1].strip()
                port_entries = ports_section.split(',')
                for p_str in port_entries:
                    p_str = p_str.strip()
                    if 'open' in p_str.lower():
                        parts = p_str.split('/')
                        if len(parts) >= 3:
                            current_port_key = f"{parts[0].strip()}/{parts[2].strip().upper()}"
                            if current_port_key not in port_vuln_notes:
                                port_vuln_notes[current_port_key] = []
                            
            if current_port_key and is_vuln_scan and (
                'CVE' in line or 'VULNERABLE' in line or 'http-title' in line or 'risk' in line.lower()
            ):
                note = line.split("Host:")[0].strip()
                if note and len(port_vuln_notes[current_port_key]) == 0:
                    port_vuln_notes[current_port_key].append(note[:50].replace('\t', ' ') + "...") 
                    total_vuln_count += 1
        
        # Step 2: Extract final port list
        for line in lines:
            if 'Ports:' in line:
                port_details_str = line.split('Ports:')[1].strip()
                port_entries = port_details_str.split(',')

                for p_str in port_entries:
                    p_str = p_str.strip()
                    if not p_str or "Ignored State" in p_str: continue

                    temp_parts = p_str.split('/')
                    if len(temp_parts) >= 3:
                        port_num = temp_parts[0].strip()
                        state = temp_parts[1].strip().lower()
                        protocol = temp_parts[2].strip().upper()
                        
                        if 'open' in state:
                            service = temp_parts[4].strip() if len(temp_parts) > 4 and temp_parts[4].strip() else 'unknown'
                            version_raw = temp_parts[6].strip() if len(temp_parts) > 6 else ''
                            version = version_raw.split('\t')[0].strip()
                            
                            process_name = get_process_info_for_port(port_num, protocol=protocol, user_id=user_id)
                            
                            vuln_key = f"{port_num}/{protocol}"
                            vulnerability_summary = " | ".join(port_vuln_notes.get(vuln_key, []))
                            if not vulnerability_summary and is_vuln_scan:
                                vulnerability_summary = "No immediate CVE/Risk found."
                            elif not is_vuln_scan:
                                vulnerability_summary = "Run VULN Scan for details."

                            port_obj = {
                                'port': port_num, 'protocol': protocol,
                                'service': service, 'version': version,
                                'process_name': process_name,
                                'vulnerability': vulnerability_summary
                            }
                            
                            all_ports_list.append(port_obj)
                            
                            # Add to user data structure with Lock
                            with _ports_lock:
                                if protocol == "UDP":
                                    if port_obj not in user_data["UDP"]: user_data["UDP"].append(port_obj)
                                else:
                                    if port_obj not in user_data["TCP"]: user_data["TCP"].append(port_obj)

        # Apply ML Threat Re-ranking for live data
        try:
            for p_obj in all_ports_list:
                 prediction_obj = tctr_engine.predict_risk(
                    f"Service: {p_obj['service']} ({p_obj['port']}/{p_obj['protocol']})", 
                    f"Version: {p_obj['version']}\nVulnerability: {p_obj['vulnerability']}",
                    cwe_id=None
                )
                 p_obj["predicted_risk_score"] = prediction_obj["score"]
                 p_obj["tctr_priority"] = prediction_obj["tctr_priority"]
                 p_obj["base_score"] = prediction_obj["base_score"]
                 p_obj["priority_level"] = prediction_obj["priority_level"]
                 p_obj["risk_justification"] = prediction_obj["risk_justification"]
            
            # Sort by predicted score
            all_ports_list.sort(
                key=lambda x: x.get('predicted_risk_score', 0),
                reverse=True
            )
        except Exception as e:
            log(f"[!] ML Re-ranking skipped or failed for live extraction: {e}", user_id, queue_id)

        with _ports_lock:
            # [NEW] Default Insights if OS detection was skipped or failed
            # Always update if we have data, unless it already contains high-quality OS info
            current_insights = user_data["metadata"].get("insights", "").lower()
            if "detected" in current_insights or "scanning" in current_insights or "waiting" in current_insights or "no open" in current_insights:
                total_ports = len(all_ports_list)
                if total_ports > 0:
                    user_data["metadata"]["insights"] = f"Detected {total_ports} active services. Host is responding to probes."
                else:
                    user_data["metadata"]["insights"] = "No open services detected. Host may be behind a firewall or using port knocking."

        # Send UI Updates
        send_sse_event("ports_updated", {
            "ports": get_current_open_ports(user_id),
            "vulnerabilities_count": total_vuln_count
        }, user_id=user_id, queue_id=queue_id)

        send_sse_event("metadata_updated", user_data["metadata"], user_id=user_id, queue_id=queue_id)

    except Exception as e:
        log(f"[!] Error extracting open ports: {e}", user_id, queue_id)
        
    return get_current_open_ports(user_id)

# --- Firewall Management ---
def block_port_windows(port, protocol="TCP", user_id=None, queue_id=None):
    """Blocks a specified port and protocol using Windows Defender Firewall."""
    rule_name = f"Block_NetShieldAI_{protocol}_Port_{port}"
    cmd = [
        "powershell", "-Command",
        f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Inbound -LocalPort {port} -Protocol {protocol} -Action Block -Enabled True"
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
        log(f"[+] Firewall rule '{rule_name}' created to block {protocol} port {port}.", user_id, queue_id)
        return True
    except subprocess.CalledProcessError as e:
        log(f"[!] Failed to block {protocol} port {port}: {e.stderr.strip() if e.stderr else 'No detailed error.'}", user_id, queue_id)
        return False

def is_port_blocked_windows(port, protocol="TCP"):
    """Checks if a specific firewall rule exists and is enabled on Windows."""
    rule_name = f"Block_NetShieldAI_{protocol}_Port_{port}"
    cmd = ["powershell", "-Command", f"Get-NetFirewallRule -DisplayName '{rule_name}'"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
        return "True" in result.stdout
    except subprocess.CalledProcessError:
        return False

def block_port_linux(port, protocol="TCP", user_id=None, queue_id=None):
    """Blocks a specified port and protocol using UFW (Uncomplicated Firewall) on Linux."""
    try:
        status_result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
        if "inactive" in status_result.stdout:
            log("[!] UFW is not active. Please enable UFW first.", user_id, queue_id)
            return False
    except FileNotFoundError:
        log("[!] UFW command not found. Cannot block ports.", user_id, queue_id)
        return False
    except subprocess.CalledProcessError as e:
        log(f"[!] Error checking UFW status: {e.stderr.strip()}", user_id, queue_id)
        return False

    rule_command = ['ufw', 'deny', f"{port}/{protocol.lower()}"]
    try:
        subprocess.run(rule_command, capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
        log(f"[+] UFW rule created to block {protocol} port {port}.", user_id, queue_id)
        return True
    except subprocess.CalledProcessError as e:
        log(f"[!] Failed to block {protocol} port {port} with UFW: {e.stderr.strip() if e.stderr else 'No detailed error.'}", user_id, queue_id)
        return False

def is_port_blocked_linux(port, protocol="TCP"):
    """Checks if a specific UFW rule to block the port exists and is active on Linux."""
    try:
        status_cmd = ['ufw', 'status', 'verbose']
        result = subprocess.run(status_cmd, capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
        
        return f"{port}/{protocol.lower()}" in result.stdout and "DENY IN" in result.stdout

    except subprocess.CalledProcessError as e:
        return False
    except FileNotFoundError:
        return False

def block_port(port, protocol="TCP", user_id=None, queue_id=None):
    """Calls the appropriate OS-specific port blocking function."""
    if platform.system() == "Windows":
        return block_port_windows(port, protocol, user_id=user_id, queue_id=queue_id)
    else:
        return block_port_linux(port, protocol, user_id=user_id, queue_id=queue_id)

def is_port_blocked(port, protocol="TCP"):
    """Calls the appropriate OS-specific port blocked check function."""
    if platform.system() == "Windows":
        return is_port_blocked_windows(port, protocol)
    else:
        return is_port_blocked_linux(port, protocol)

# --- Other Helper Functions ---
def verify_ports_closed(target_ip, user_id=None, queue_id=None):
    all_ports_to_verify_info = get_current_open_ports(user_id)
    whitelisted_ports = get_user_whitelisted_ports(user_id)
    
    if not all_ports_to_verify_info:
        log("[*] No ports to verify.", user_id, queue_id)
        return

    if '-' in target_ip or '/' in target_ip:
        log("[!] Port verification is most reliable for single IP addresses.", user_id, queue_id)
        try:
            target_ip = target_ip.split('/')[0].split('-')[0]
        except Exception:
            pass

    if not is_valid_ip_or_range(target_ip):
        log(f"[!] Could not determine a single IP for verification.", user_id, queue_id)
        return

    log(f"[*] Verifying all detected port status on {target_ip}...", user_id, queue_id)
    for p_info in all_ports_to_verify_info:
        port, protocol = p_info['port'], p_info['protocol']
        if port in whitelisted_ports:
            log(f"[~] Skipping verification for whitelisted {protocol} port {port}.", user_id, queue_id)
            continue
        
        if protocol == "TCP":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                try:
                    if s.connect_ex((target_ip, int(port))) == 0:
                        log(f"[!] TCP Port {port} (Service: {p_info['service']}) is still OPEN.", user_id, queue_id)
                    else:
                        log(f"[OK] TCP Port {port} (Service: {p_info['service']}) is CLOSED.", user_id, queue_id)
                except Exception as e:
                    log(f"[!] Error verifying TCP port {port}: {e}", user_id, queue_id)
        else:
            log(f"[~] UDP Port {port} (Service: {p_info['service']}) verification is limited.", user_id, queue_id)

def add_to_whitelist(ports_str, output_dir=None, user_id=None, queue_id=None):
    """
    Updated for Phase 2 to accept output_dir and user_id.
    """
    whitelisted_ports = get_user_whitelisted_ports(user_id)
    if ports_str:
        ports = [p.strip() for p in ports_str.split(',') if p.strip().isdigit()]
        if ports:
            save_whitelist(output_dir, user_id=user_id, queue_id=queue_id)
            log(f"[~] Whitelisted ports updated: {', '.join(ports)}", user_id, queue_id)
            return True
    log("[!] No valid port numbers found in whitelist input.", user_id, queue_id)
    return False

def get_whitelisted_ports(user_id=None):
    return sorted(list(get_user_whitelisted_ports(user_id)))

def clear_log_file(user_id=None, queue_id=None):
    """Clears the log file for a specific user or the system log."""
    if user_id:
        user_id = str(user_id)
        target_log_file = LOG_DIR / "users" / user_id / "network_agent_log.txt"
    else:
        target_log_file = LOG_DIR / "system" / "network_system_log.txt"

    try:
        if target_log_file.exists():
            with open(target_log_file, 'w', encoding='utf-8') as f:
                f.write("")
        log("[*] Log file cleared.", user_id, queue_id)
    except Exception as e:
        logger.error(f"[!] Error clearing log file: {e}")

def get_current_open_ports(user_id=None):
    user_data = get_user_open_ports(user_id)
    return sorted(user_data["TCP"] + user_data["UDP"], key=lambda x: int(x['port']))


# --- Main Test Function ---

def main_test():
    """
    A simple test function to demonstrate the script's capabilities from the command line.
    This function is intended for development and testing purposes.
    """
    # Use standard print for test runner output to distinguish from log() output
    logger.info("=============================================")
    logger.info("=          NETWORK SCANNER TEST             =")
    logger.info("=============================================")
    
    # The check for privileges is now handled automatically by ensure_admin_privileges()
    logger.info("\n[INFO] Running with administrator/root privileges.")
    
    # Check for Nmap installation
    if not is_nmap_installed():
        logger.info("[ERROR] Nmap is not installed or not in PATH. Please install it and try again.")
        return # Exit the test if nmap is missing

    # Define the target for testing
    target_ip = "192.168.29.48"
    logger.info(f"\n[INFO] This test will perform scans on {target_ip}.")
    
    # --- Test 1: Standard TCP Scan ---
    logger.info(f"\n--- [TEST 1] Performing Default TCP scan on {target_ip} ---")
    run_nmap_scan(target_ip, protocol_type="TCP", timing=4)
    
    # --- Test 2: Stealth FIN Scan (New Feature) ---
    logger.info(f"\n--- [TEST 2] Performing Stealth FIN scan on {target_ip} ---")
    run_fin_scan(target_ip)
    
    # --- Test 3: Decoy Scan (New Feature) ---
    logger.info(f"\n--- [TEST 3] Performing Decoy scan (Evasion) on {target_ip} ---")
    run_decoy_scan(target_ip)

    time.sleep(1)  # Brief pause to allow logs to process

    # --- Display Final Results ---
    logger.info("\n--- [RESULTS] All detected open ports (Accumulated) ---")
    all_open = get_current_open_ports()
    if all_open:
        logger.info(f"Found {len(all_open)} open port(s):")
        for port_info in all_open:
            # Displaying the new vulnerability field
            logger.info(
                f"  - Port: {port_info['port']}/{port_info['protocol']}, "
                f"Service: {port_info.get('service', 'n/a')}, "
                f"Version: {port_info.get('version', 'n/a')}, "
                f"Process: {port_info.get('process_name', 'n/a')}, "
                f"Vulnerability: {port_info.get('vulnerability', 'N/A')}"
            )
    else:
        logger.info("No open ports were found on the target.")
        
    logger.info(f"\n--- Test run finished. Check '{LOG_FILE}' for detailed logs. ---")

if __name__ == "__main__":
    # This function will exit and re-launch the script as admin if needed.
    # If it returns, we are guaranteed to be running with elevated privileges.
    ensure_admin_privileges()
    
    # The rest of the script will only run in the (potentially new) elevated process.
    load_whitelist()
    main_test()
