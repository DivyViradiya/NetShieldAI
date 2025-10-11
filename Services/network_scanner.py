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
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.parent

# Define paths for storing results
RESULTS_DIR = Path(r"D:\NetShieldAI\Services\results\network_scanner")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)  # Create directory if it doesn't exist

# Define file paths
WHITELIST_FILE = RESULTS_DIR / "whitelisted_ports.json"
SCAN_RESULT_TCP = RESULTS_DIR / "scan_result_tcp.txt"
SCAN_RESULT_UDP = RESULTS_DIR / "scan_result_udp.txt"
SCAN_RESULT_OS = RESULTS_DIR / "scan_result_os.txt"
SCAN_RESULT_FRAGMENTED = RESULTS_DIR / "scan_result_fragmented.txt"
SCAN_RESULT_AGGRESSIVE = RESULTS_DIR / "scan_result_aggressive.txt"
SCAN_RESULT_TCP_SYN = RESULTS_DIR / "scan_result_tcp_syn.txt"

# Ensure logs directory exists
LOG_DIR = Path(r"D:\NetShieldAI\logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "network_agent_log.txt"

# Global queue for logging messages to be consumed by Flask
log_queue = queue.Queue()

# Globals for application state
open_ports = {"TCP": [], "UDP": []}
whitelisted_ports = set()

def log(message):
    """
    Logs messages to an in-memory queue and to a file.
    This log function is designed to be consumed by the Flask app.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"data: [{timestamp}] {message}\n\n" # SSE format
    
    # Put message into the queue for Flask to stream
    log_queue.put(full_message)

    # Also write to a file for persistent logging
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        # Log to console if file write fails, as this is a critical logging function
        print(f"ERROR: Failed to write to {LOG_FILE}: {e}")

def send_sse_event(event_name, data=""):
    """Sends a custom SSE event to the frontend."""
    # Ensure data is a JSON string if it's an object/list
    if isinstance(data, (dict, list)):
        data_str = json.dumps(data)
    else:
        data_str = str(data) # Convert other types to string

    sse_message = f"event: {event_name}\ndata: {data_str}\n\n"
    log_queue.put(sse_message)

# --- Whitelist Persistence Functions ---
def load_whitelist():
    """Loads whitelisted ports from a JSON file."""
    global whitelisted_ports
    if WHITELIST_FILE.exists():
        try:
            with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
                loaded_ports = json.load(f)
                if isinstance(loaded_ports, list):
                    whitelisted_ports = set(loaded_ports)
                    log(f"[+] Loaded {len(whitelisted_ports)} whitelisted ports from {WHITELIST_FILE}.")
                else:
                    log(f"[!] Whitelist file '{WHITELIST_FILE}' contains invalid format. Starting with empty whitelist.")
                    whitelisted_ports = set()
        except json.JSONDecodeError as e:
            log(f"[!] Error decoding whitelist file '{WHITELIST_FILE}': {e}. Starting with empty whitelist.")
            whitelisted_ports = set()
        except Exception as e:
            log(f"[!] Unexpected error loading whitelist file '{WHITELIST_FILE}': {e}. Starting with empty whitelist.")
            whitelisted_ports = set()
    else:
        log(f"[*] Whitelist file '{WHITELIST_FILE}' not found. Starting with empty whitelist.")
    save_whitelist() # Ensure file exists and is valid on startup

def save_whitelist():
    """Saves the current whitelisted ports to a JSON file."""
    try:
        with open(WHITELIST_FILE, 'w', encoding='utf-8') as f:
            json.dump(list(whitelisted_ports), f, indent=4)
        log(f"[+] Whitelist saved to {WHITELIST_FILE}.")
    except Exception as e:
        log(f"[!] Error saving whitelist to file '{WHITELIST_FILE}': {e}")

def clear_whitelist():
    """Clears the whitelisted ports and saves the empty state."""
    global whitelisted_ports
    whitelisted_ports.clear()
    save_whitelist()
    log("[*] Whitelist cleared.")

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
    with elevated permissions. This will trigger a UAC prompt on Windows or a sudo
    password request on Linux/macOS. If successful, the original script exits.
    """
    if is_admin():
        return True # We are already admin, continue execution.

    # If not admin, attempt to re-launch with privileges
    print("[INFO] Administrator privileges not found. Requesting elevation...")
    
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
            print(f"[ERROR] Automatic privilege elevation not supported on this OS: {platform.system()}")
            # Hold the window open for a moment so the user can read the error
            time.sleep(5)
            return False

        # The original non-elevated script should exit after launching the new one
        sys.exit(0)

    except Exception as e:
        print(f"[ERROR] Failed to re-launch with admin rights: {e}")
        time.sleep(5)
        sys.exit(1)


# Network Helpers
def get_local_ip():
    """Detects and returns the local IP address."""
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
    return "127.0.0.1" # Fallback

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

def is_nmap_installed():
    """Checks if Nmap is installed and accessible in the system's PATH."""
    try:
        subprocess.run(
            ['nmap', '--version'],
            capture_output=True, text=True, check=True,
            creationflags=_get_subprocess_creation_flags()
        )
        return True
    except FileNotFoundError:
        log("[!] 'nmap' command not found. Please install Nmap and ensure it's in your system's PATH.")
        return False
    except subprocess.CalledProcessError as e:
        log(f"[!] Nmap is installed but returned an error on version check: {e.stderr.strip()}")
        return False
    except Exception as e:
        log(f"[!] An unexpected error occurred while checking for Nmap: {e}")
        return False

def get_process_info_for_port(port_num, protocol="TCP"):
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
            log(f"[!] Error getting process info for {protocol} port {port_num}: {e.stderr.strip()}")
            process_name = "Error (Cmd Failed)"
    except FileNotFoundError:
        log(f"[!] Command not found for process info ({'netstat/tasklist' if platform.system() == 'Windows' else 'lsof'}). Cannot determine process info.")
        process_name = "Error (Cmd Missing)"
    except Exception as e:
        log(f"[!] Unexpected error getting process info for {protocol} port {port_num}: {e}")
        process_name = "Error"
    
    return process_name

# --- Nmap Scanning ---
# Note: All scan functions implicitly require admin rights because they call run_nmap_scan,
# which uses scan types that need elevation. The main guard is at the start of execution.
def run_os_detection_scan(target_ip):
    """Runs an Nmap OS detection scan on the target IP."""
    log(f"[+] Running OS Detection scan on {target_ip}...")
    try:
        nmap_cmd = [
            'nmap', '-O', '--osscan-limit', '-T4',
            '-oG', str(SCAN_RESULT_OS), target_ip
        ]
        result = subprocess.run(
            nmap_cmd, capture_output=True, text=True,
            creationflags=_get_subprocess_creation_flags()
        )
        if result.returncode != 0:
            log(f"[!] OS Detection scan failed: {result.stderr.strip()}")
            return None
        log(f"[+] OS Detection scan complete. Results saved to {SCAN_RESULT_OS}")
        return SCAN_RESULT_OS
    except Exception as e:
        log(f"[!] An unexpected error occurred during OS Detection scan: {e}")
        return None

def run_fragmented_scan(target_ip):
    """Runs a fragmented packet scan on the target IP."""
    log(f"[+] Running Fragmented Packet scan on {target_ip}...")
    try:
        nmap_cmd = [
            'nmap', '-f', '-sS', '-T4',
            '-oG', str(SCAN_RESULT_FRAGMENTED), target_ip
        ]
        result = subprocess.run(
            nmap_cmd, capture_output=True, text=True,
            creationflags=_get_subprocess_creation_flags()
        )
        if result.returncode != 0:
            log(f"[!] Fragmented Packet scan failed: {result.stderr.strip()}")
            return None
        log(f"[+] Fragmented Packet scan complete. Results saved to {SCAN_RESULT_FRAGMENTED}")
        return SCAN_RESULT_FRAGMENTED
    except Exception as e:
        log(f"[!] An unexpected error occurred during Fragmented Packet scan: {e}")
        return None

def run_aggressive_scan(target_ip):
    """Runs an aggressive scan on the target IP."""
    log(f"[+] Running Aggressive scan on {target_ip}...")
    try:
        nmap_cmd = [
            'nmap', '-A', '-T4',
            '-oG', str(SCAN_RESULT_AGGRESSIVE), target_ip
        ]
        result = subprocess.run(
            nmap_cmd, capture_output=True, text=True,
            creationflags=_get_subprocess_creation_flags()
        )
        if result.returncode != 0:
            log(f"[!] Aggressive scan failed: {result.stderr.strip()}")
            return None
        log(f"[+] Aggressive scan complete. Results saved to {SCAN_RESULT_AGGRESSIVE}")
        return SCAN_RESULT_AGGRESSIVE
    except Exception as e:
        log(f"[!] An unexpected error occurred during Aggressive scan: {e}")
        return None

def run_tcp_syn_scan(target_ip):
    """Runs a TCP SYN scan on the target IP."""
    log(f"[+] Running TCP SYN scan on {target_ip}...")
    try:
        nmap_cmd = [
            'nmap', '-sS', '-T4',
            '-oG', str(SCAN_RESULT_TCP_SYN), target_ip
        ]
        result = subprocess.run(
            nmap_cmd, capture_output=True, text=True,
            creationflags=_get_subprocess_creation_flags()
        )
        if result.returncode != 0:
            log(f"[!] TCP SYN scan failed: {result.stderr.strip()}")
            return None
        log(f"[+] TCP SYN scan complete. Results saved to {SCAN_RESULT_TCP_SYN}")
        return SCAN_RESULT_TCP_SYN
    except Exception as e:
        log(f"[!] An unexpected error occurred during TCP SYN scan: {e}")
        return None

def run_nmap_scan(target_ip, protocol_type="TCP", scan_type="default"):
    """
    Runs an Nmap scan with the specified parameters using local Nmap installation.
    """
    if not is_admin():
        log(f"[!] Nmap scans require administrator privileges. This should have been handled on startup.")
        return None
    
    # Handle special scan types
    if scan_type == "os": return run_os_detection_scan(target_ip)
    if scan_type == "fragmented": return run_fragmented_scan(target_ip)
    if scan_type == "aggressive": return run_aggressive_scan(target_ip)
    if scan_type == "tcp_syn": return run_tcp_syn_scan(target_ip)

    # Default scan behavior (TCP/UDP)
    scan_type_display = f"{protocol_type} (Top 1000 Ports)"
    log(f"[+] Running {scan_type_display} scan on {target_ip}...")
    output_file = SCAN_RESULT_TCP if protocol_type == "TCP" else SCAN_RESULT_UDP

    try:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        
        if not is_nmap_installed():
            return None

        flags = ['-sU'] if protocol_type == "UDP" else ['-sS']
        
        nmap_cmd = [
            'nmap', *flags,
            '-sV', '-Pn', '-T4',
            '--top-ports', '1000',
            '-oG', str(output_file),
            target_ip
        ]

        # Add exclusion for Flask app port (5000) if scanning local IP
        local_ips = [get_local_ip(), "127.0.0.1"]
        if target_ip in local_ips or (is_valid_ip_or_range(target_ip) and target_ip.startswith("127.0.0.1")):
            nmap_cmd.insert(1, '--exclude-ports')
            nmap_cmd.insert(2, '5000')

        log(f"[*] Executing: {' '.join(nmap_cmd)}")
        result = subprocess.run(
            nmap_cmd, capture_output=True, text=True,
            creationflags=_get_subprocess_creation_flags()
        )

        if result.returncode != 0:
            log(f"[!] Nmap scan failed with error: {result.stderr.strip()}")
            return None

        if not output_file.exists() or output_file.stat().st_size == 0:
            log(f"[!] Nmap scan completed but no results were saved to {output_file}. This may be normal if no ports are open.")
            
        log(f"[+] {scan_type_display} scan complete. Results saved to {output_file}")
        
        open_ports_list = extract_open_ports(output_file, protocol_type)
        send_sse_event("scan_complete", {
            "target": target_ip, "protocol": protocol_type,
            "scan_type": scan_type, "open_ports": open_ports_list
        })
        
        return str(output_file)

    except Exception as e:
        log(f"[!] Error during {scan_type_display} scan: {str(e)}")
        return None

def extract_open_ports(filename, protocol_type):
    """
    Parses Nmap greppable output to extract open ports and associated info.
    """
    open_ports[protocol_type].clear()

    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                if 'Ports:' in line and 'open' in line:
                    port_details_str = line.split('Ports:')[1].strip()
                    port_entries = port_details_str.split(',')

                    for p_str in port_entries:
                        p_str = p_str.strip()
                        if 'open' in p_str.lower():
                            parts = p_str.split('/')
                            
                            port_num = parts[0]
                            protocol = parts[2].upper() 
                            service = parts[4].strip() if len(parts) > 4 and parts[4].strip() else 'unknown'
                            version = parts[6].strip() if len(parts) > 6 and parts[6].strip() else ''
                            
                            process_name = get_process_info_for_port(port_num, protocol=protocol)

                            if protocol == protocol_type:
                                open_ports[protocol].append({
                                    'port': port_num, 'protocol': protocol,
                                    'service': service, 'version': version,
                                    'process_name': process_name
                                })
        
        send_sse_event("ports_updated", json.dumps(get_current_open_ports()))

    except FileNotFoundError:
        log(f"[!] Scan result file '{filename}' not found. Cannot extract {protocol_type} ports.")
    except Exception as e:
        log(f"[!] Error extracting {protocol_type} open ports from file: {e}")
    return open_ports[protocol_type]

# --- Firewall Management ---
def block_port_windows(port, protocol="TCP"):
    """Blocks a specified port and protocol using Windows Defender Firewall."""
    rule_name = f"Block_VulnScanAI_{protocol}_Port_{port}"
    cmd = [
        "powershell", "-Command",
        f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Inbound -LocalPort {port} -Protocol {protocol} -Action Block -Enabled True"
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
        log(f"[+] Firewall rule '{rule_name}' created to block {protocol} port {port}.")
        return True
    except subprocess.CalledProcessError as e:
        log(f"[!] Failed to block {protocol} port {port}: {e.stderr.strip() if e.stderr else 'No detailed error.'}")
        return False

def is_port_blocked_windows(port, protocol="TCP"):
    """Checks if a specific firewall rule exists and is enabled on Windows."""
    rule_name = f"Block_VulnScanAI_{protocol}_Port_{port}"
    cmd = ["powershell", "-Command", f"Get-NetFirewallRule -DisplayName '{rule_name}'"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
        return "True" in result.stdout
    except subprocess.CalledProcessError:
        return False

def block_port_linux(port, protocol="TCP"):
    """Blocks a specified port and protocol using UFW (Uncomplicated Firewall) on Linux."""
    try:
        status_result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
        if "inactive" in status_result.stdout:
            log("[!] UFW is not active. Please enable UFW first (e.g., 'sudo ufw enable').")
            return False
    except FileNotFoundError:
        log("[!] UFW command not found. Please install UFW (e.g., 'sudo apt install ufw'). Cannot block ports.")
        return False
    except subprocess.CalledProcessError as e:
        log(f"[!] Error checking UFW status: {e.stderr.strip()}")
        return False

    rule_command = ['ufw', 'deny', f"{port}/{protocol.lower()}"]
    try:
        subprocess.run(rule_command, capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
        log(f"[+] UFW rule created to block {protocol} port {port}.")
        return True
    except subprocess.CalledProcessError as e:
        log(f"[!] Failed to block {protocol} port {port} with UFW: {e.stderr.strip() if e.stderr else 'No detailed error.'}")
        return False

def is_port_blocked_linux(port, protocol="TCP"):
    """Checks if a specific UFW rule to block the port exists and is active on Linux."""
    try:
        status_cmd = ['ufw', 'status', 'verbose']
        result = subprocess.run(status_cmd, capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
        
        return f"{port}/{protocol.lower()}" in result.stdout and "DENY IN" in result.stdout

    except subprocess.CalledProcessError as e:
        log(f"[!] Error checking UFW status: {e.stderr.strip() if e.stderr else 'No detailed error.'}")
        return False
    except FileNotFoundError:
        log("[!] UFW command not found. Cannot verify port block status.")
        return False

def block_port(port, protocol="TCP"):
    """Calls the appropriate OS-specific port blocking function."""
    if platform.system() == "Windows":
        return block_port_windows(port, protocol)
    else:
        return block_port_linux(port, protocol)

def is_port_blocked(port, protocol="TCP"):
    """Calls the appropriate OS-specific port blocked check function."""
    if platform.system() == "Windows":
        return is_port_blocked_windows(port, protocol)
    else:
        return is_port_blocked_linux(port, protocol)

# --- Other Helper Functions ---
def verify_ports_closed(target_ip):
    all_ports_to_verify_info = open_ports["TCP"] + open_ports["UDP"]
    if not all_ports_to_verify_info:
        log("[*] No ports to verify.")
        return

    if '-' in target_ip or '/' in target_ip:
        log("[!] Port verification is most reliable for single IP addresses. Using primary IP from range if detectable.")
        try:
            target_ip = target_ip.split('/')[0].split('-')[0]
        except Exception:
            pass

    if not is_valid_ip_or_range(target_ip):
        log(f"[!] Could not determine a single IP from '{target_ip}' for verification. Skipping.")
        return

    log(f"[*] Verifying all detected port status on {target_ip}...")
    for p_info in all_ports_to_verify_info:
        port, protocol = p_info['port'], p_info['protocol']
        if port in whitelisted_ports:
            log(f"[~] Skipping verification for whitelisted {protocol} port {port}.")
            continue
        
        if protocol == "TCP":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                try:
                    if s.connect_ex((target_ip, int(port))) == 0:
                        log(f"[!] TCP Port {port} (Service: {p_info['service']}) is still OPEN.")
                    else:
                        log(f"[OK] TCP Port {port} (Service: {p_info['service']}) is CLOSED.")
                except Exception as e:
                    log(f"[!] Error verifying TCP port {port}: {e}")
        else:
            log(f"[~] UDP Port {port} (Service: {p_info['service']}) verification is limited. Re-scan to confirm status.")

def add_to_whitelist(ports_str):
    if ports_str:
        ports = [p.strip() for p in ports_str.split(',') if p.strip().isdigit()]
        if ports:
            whitelisted_ports.update(ports)
            save_whitelist()
            log(f"[~] Whitelisted ports updated: {', '.join(ports)}")
            return True
    log("[!] No valid port numbers found in whitelist input.")
    return False

def get_whitelisted_ports():
    return sorted(list(whitelisted_ports))

def clear_log_file():
    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write("")
        log("[*] Log file cleared.")
    except Exception as e:
        log(f"[!] Error clearing log file: {e}")

def get_current_open_ports():
    return sorted(open_ports["TCP"] + open_ports["UDP"], key=lambda x: int(x['port']))


# --- Main Test Function ---

def main_test():
    """
    A simple test function to demonstrate the script's capabilities from the command line.
    This function is intended for development and testing purposes.
    """
    # Use standard print for test runner output to distinguish from log() output
    print("=============================================")
    print("=          NETWORK SCANNER TEST             =")
    print("=============================================")
    
    # The check for privileges is now handled automatically by ensure_admin_privileges()
    print("\n[INFO] Running with administrator/root privileges.")
    
    # Check for Nmap installation
    if not is_nmap_installed():
        print("[ERROR] Nmap is not installed or not in PATH. Please install it and try again.")
        return # Exit the test if nmap is missing

    # Define the target for testing
    target_ip = "192.168.29.48"
    print(f"\n[INFO] This test will perform scans on {target_ip}.")
    
    # --- Test 1: TCP Scan ---
    print(f"\n--- [TEST 1] Performing TCP scan on {target_ip} ---")
    run_nmap_scan(target_ip, protocol_type="TCP")
    time.sleep(1)  # Brief pause to allow logs to process
    

    # --- Display Final Results ---
    print("\n--- [RESULTS] All detected open ports ---")
    all_open = get_current_open_ports()
    if all_open:
        print(f"Found {len(all_open)} open port(s):")
        for port_info in all_open:
            print(
                f"  - Port: {port_info['port']}/{port_info['protocol']}, "
                f"Service: {port_info.get('service', 'n/a')}, "
                f"Version: {port_info.get('version', 'n/a')}, "
                f"Process: {port_info.get('process_name', 'n/a')}"
            )
    else:
        print("No open ports were found on the target.")
        
    print(f"\n--- Test run finished. Check '{LOG_FILE}' for detailed logs. ---")

if __name__ == "__main__":
    # This function will exit and re-launch the script as admin if needed.
    # If it returns, we are guaranteed to be running with elevated privileges.
    ensure_admin_privileges()
    
    # The rest of the script will only run in the (potentially new) elevated process.
    load_whitelist()
    main_test()