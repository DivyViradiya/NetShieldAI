import subprocess
import os
import sys
import ctypes
import uuid
import time
from datetime import datetime
import platform
import queue
import threading
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from Services import report_manager

# MODIFIED: Define path to the local sslscan.exe
BASE_DIR = Path(__file__).parent.parent
SSLSCAN_EXECUTABLE = Path(r"C:\Program Files\sslscan\sslscan.exe")

# Define default paths for storing results (Fallback)
DEFAULT_RESULTS_DIR = BASE_DIR / "Services" / "results" / "ssl_scanner"

# Logs (Shared)
LOG_FILE = BASE_DIR / "logs" / "ssl_agent_log.txt"

TEMP_DIR = BASE_DIR / "Services" / "temp" / "sslscan"
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

from Services import scan_logger
from logger_setup import logger

def log(message, user_id=None, to_console=False, level='INFO'):
    """
    Logs messages using the centralized scan_logger.
    """
    if to_console:
        logger.info(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
    
    if user_id:
        scan_logger.write_log(user_id, "ssl_scanner", message, level=level)

def send_sse_event(event_name, data="", user_id=None):
    """
    Simulates SSE event by logging a special format line that tail_log_file can pick up.
    """
    if isinstance(data, (dict, list)):
        data_str = json.dumps(data)
    else:
        data_str = str(data)
        
    log(f"EVENT: {event_name} | PAYLOAD: {data_str}", user_id)

def _get_subprocess_creation_flags():
    """Returns appropriate creation flags for subprocess based on OS."""
    if platform.system() == "Windows":
        return subprocess.CREATE_NO_WINDOW
    return 0

def is_sslscan_available(user_id=None):
    """Checks if the local sslscan.exe is found at the expected path."""
    if not SSLSCAN_EXECUTABLE.exists():
        log(f"[!] ERROR: sslscan.exe not found at {SSLSCAN_EXECUTABLE}", user_id)
        return False
    return True

# --- PHASE 2: Dynamic Path Helper ---

def get_output_paths(output_dir=None, user_id=None, target=None):
    """
    Returns a dictionary of file paths based on the output directory.
    Now supports user-specific unique temp files and timestamped reports.
    """
    if output_dir:
        base = Path(output_dir)
    else:
        base = DEFAULT_RESULTS_DIR
    
    if not base.exists():
        try:
            base.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            log(f"[!] Error creating directory {base}: {e}", user_id)

    # Multi-user unique temp file
    scan_uuid = str(uuid.uuid4())[:8]
    temp_xml = TEMP_DIR / f"ssl_temp_{user_id if user_id else 'sys'}_{scan_uuid}.xml"

    if target:
        json_filename = report_manager.generate_report_filename("ssl_report", target, "json")
        pdf_filename = report_manager.generate_report_filename("ssl_report", target, "pdf")
    else:
        json_filename = "ssl_report.json"
        pdf_filename = "ssl_report.pdf"

    return {
        "xml_report": temp_xml,
        "json_report": base / json_filename,
        "pdf_report": base / pdf_filename
    }

def save_ssl_json(data, output_dir=None, user_id=None, target=None):
    """Saves the parsed SSL scan data to a JSON file."""
    if output_dir and isinstance(output_dir, str):
        output_dir = Path(output_dir)
        
    paths = get_output_paths(output_dir, user_id=user_id, target=target)
    json_file = paths["json_report"]
    try:
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        log(f"[+] SSL JSON report saved to {json_file}", user_id)
        return str(json_file)
    except Exception as e:
        log(f"[!] Failed to save SSL JSON report: {e}", user_id)
        return None

def run_ssl_scan(target_host, output_dir=None, user_id=None):
    """Runs an SSL/TLS scan using the local sslscan.exe."""
    if output_dir and isinstance(output_dir, str):
        output_dir = Path(output_dir)
        
    if not target_host:
        log("[!] Target host cannot be empty for SSL scan.", user_id)
        return None

    log(f"[+] Running local SSL scan on {target_host}...", user_id, to_console=True)
    if not is_sslscan_available(user_id=user_id):
        return None
    
    paths = get_output_paths(output_dir, user_id=user_id, target=target_host)
    xml_report_path = paths["xml_report"]
    
    # Ensure directory exists
    if not xml_report_path.parent.exists():
        xml_report_path.parent.mkdir(parents=True, exist_ok=True)

    local_cmd = [
        str(SSLSCAN_EXECUTABLE),
        f"--xml={xml_report_path}",
        '--show-client-cas',
        '--show-cipher-ids',
        '--show-signatures',
        target_host
    ]

    try:
        log(f"[*] Executing command: {' '.join(str(x) for x in local_cmd)}", user_id, to_console=True)
        
        # Track this user's process
        with scan_lock:
            process = subprocess.Popen(
                local_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=_get_subprocess_creation_flags(),
                cwd=SSLSCAN_EXECUTABLE.parent 
            )
            active_scans[user_id] = {"process": process, "target": target_host, "start_time": time.time()}

        # Stream output in real-time
        def stream_output(pipe, prefix):
            for line in iter(pipe.readline, ''):
                if line:
                    log(f"[{prefix}] {line.strip()}", user_id)
            pipe.close()

        stdout_thread = threading.Thread(target=stream_output, args=(process.stdout, "SSLScan"))
        stderr_thread = threading.Thread(target=stream_output, args=(process.stderr, "SSLScan-Err"))
        
        stdout_thread.start()
        stderr_thread.start()
        
        # Wait for process to complete
        return_code = process.wait()
        stdout_thread.join()
        stderr_thread.join()

        # Unregister process
        with scan_lock:
            if user_id in active_scans:
                del active_scans[user_id]

        if return_code != 0 and not xml_report_path.exists():
            log(f"[!] SSL scan failed with exit code {return_code} and no report was generated.", user_id, to_console=True)
            return None
        
        # Give a small buffer for file sync
        time.sleep(0.5)

        if xml_report_path.exists() and xml_report_path.stat().st_size > 0:
            log(f"[+] SSL raw scan results synchronized.", user_id, to_console=True)
            send_sse_event("ssl_scan_complete", {"target_host": target_host, "report_file": str(xml_report_path)}, user_id=user_id)
            return str(xml_report_path)
        else:
            log(f"[!] SSL scan failed or generated an empty report.", user_id, to_console=True)
            return None
            
    except Exception as e:
        log(f"[!] An unexpected error occurred during SSL scan: {e}", user_id)
        return None

def parse_ssl_report(report_file, output_dir=None, user_id=None, target=None):
    """
    Parses an SSLScan XML report file to extract maximum details.
    """
    if output_dir and isinstance(output_dir, str):
        output_dir = Path(output_dir)
        
    if not os.path.exists(report_file):
        log(f"[!] SSLScan report file not found: {report_file}", user_id)
        return None
    
    try:
        tree = ET.parse(report_file)
        root = tree.getroot()
        
        scan_summary = {
            "target": "N/A",
            "ip": "N/A",
            "port": "N/A",
            "server_configs": {
                "tls_compression": {},
                "renegotiation": {},
                "ocsp_stapling": {},
                "fallback_scsv_supported": "N/A"
            },
            "protocols": [],
            "certificate_chain": [],
            "ciphers": [],
            "client_cas": [],
            "vulnerabilities": []
        }

        ssltest_elem = root.find('ssltest')
        if ssltest_elem is not None:
            scan_summary["target"] = ssltest_elem.get('host', 'N/A')
            scan_summary["port"] = ssltest_elem.get('port', 'N/A')
            scan_summary["ip"] = ssltest_elem.get('ip', 'N/A')

        if (comp := root.find('.//compression')) is not None:
            scan_summary["server_configs"]["tls_compression"] = {
                "supported": comp.get('supported', '0') == '1',
                "method": comp.get('method', 'N/A')
            }
        if (reneg := root.find('.//renegotiation')) is not None:
            scan_summary["server_configs"]["renegotiation"] = {
                "supported": reneg.get('supported', '0') == '1',
                "secure": reneg.get('secure', '0') == '1'
            }
        if (ocsp := root.find('.//ocsp')) is not None:
            scan_summary["server_configs"]["ocsp_stapling"] = {
                "supported": ocsp.get('stapling', 'not supported') != 'not supported',
                "response_status": ocsp.get('status', 'N/A')
            }
        if (fallback := root.find('.//fallback')) is not None:
            scan_summary["server_configs"]["fallback_scsv_supported"] = fallback.get('supported', '0') == '1'
        
        for protocol_elem in root.findall('.//protocol'):
            scan_summary["protocols"].append({
                "name": protocol_elem.get('version', 'N/A'),
                "enabled": protocol_elem.get('enabled', '0') == '1'
            })

        for cipher_elem in root.findall('.//cipher[@status="accepted"]'):
            scan_summary["ciphers"].append({
                "status": "accepted",
                "protocol": cipher_elem.get('sslversion', 'N/A'),
                "bits": int(cipher_elem.get('bits', '0')),
                "name": cipher_elem.get('cipher', 'N/A'),
                "id": cipher_elem.get('id', 'N/A')
            })

        for i, cert_elem in enumerate(root.findall('.//certificate')):
            pk_elem = cert_elem.find('pk')
            cert_data = {
                "level": "leaf" if i == 0 else f"intermediate-{i}",
                "common_name": cert_elem.findtext('subject', 'N/A'),
                "issuer": cert_elem.findtext('issuer', 'N/A'),
                "not_before": cert_elem.findtext('not-valid-before', 'N/A'),
                "not_after": cert_elem.findtext('not-valid-after', 'N/A'),
                "signature_algorithm": cert_elem.findtext('signature-algorithm', 'N/A'),
                "key_type": pk_elem.get('type', 'N/A') if pk_elem is not None else 'N/A',
                "key_size": int(pk_elem.get('bits', '0')) if pk_elem is not None else 0,
                "alt_names": [an.text for an in cert_elem.findall('altnames/altname')]
            }
            scan_summary["certificate_chain"].append(cert_data)

        scan_summary["client_cas"] = [ca.get('name', 'N/A') for ca in root.findall('.//client-cas/ca')]

        vulnerabilities = []
        if (hb := root.find('.//heartbleed')) and hb.get('vulnerable') == '1':
            vulnerabilities.append({"name": "Heartbleed", "severity": "Critical", "description": "Server is vulnerable to the Heartbleed bug."})
        if scan_summary["server_configs"]["renegotiation"].get("supported") and not scan_summary["server_configs"]["renegotiation"].get("secure"):
             vulnerabilities.append({"name": "Insecure TLS Renegotiation", "severity": "Medium", "description": "Server supports insecure client-initiated renegotiation."})
        if scan_summary["server_configs"]["tls_compression"].get("supported"):
            vulnerabilities.append({"name": "TLS Compression Enabled (CRIME)", "severity": "Medium", "description": "TLS compression is enabled."})
        for proto in scan_summary["protocols"]:
            if proto["enabled"] and ("SSLv2" in proto["name"] or "SSLv3" in proto["name"]):
                 vulnerabilities.append({"name": f"Weak Protocol Enabled: {proto['name']}", "severity": "High", "description": f"{proto['name']} is outdated."})
        for cert in scan_summary["certificate_chain"]:
            if "sha1" in cert["signature_algorithm"].lower():
                vulnerabilities.append({"name": "Weak Certificate Signature", "severity": "Medium", "description": f"Certificate uses a SHA1 signature."})
        for c in scan_summary["ciphers"]:
            if c["bits"] < 128:
                vulnerabilities.append({"name": "Weak Cipher Suite", "severity": "Medium", "description": f"Cipher {c['name']} uses a weak key size." })
            if "3DES" in c["name"]:
                vulnerabilities.append({"name": "3DES Cipher Suite", "severity": "Low", "description": f"Cipher {c['name']} is supported." })
            if "RC4" in c["name"]:
                vulnerabilities.append({"name": "RC4 Cipher Suite", "severity": "Medium", "description": f"Cipher {c['name']} is supported."})
        
        scan_summary["vulnerabilities"] = vulnerabilities
        
        # Apply ML Threat Re-ranking
        try:
            from .tctr_engine import tctr_engine
            for vuln in vulnerabilities:
                # Map to CWE-310 (Cryptographic Issues) by default for SSL
                prediction_obj = tctr_engine.predict_risk(
                    vuln["name"], 
                    vuln["description"], 
                    cwe_id="310"
                )
                vuln["predicted_risk_score"] = prediction_obj["score"]
                vuln["tctr_priority"] = prediction_obj["tctr_priority"]
                vuln["base_score"] = prediction_obj["base_score"]
                vuln["priority_level"] = prediction_obj["priority_level"]
                vuln["risk_justification"] = prediction_obj["risk_justification"]
            
            # Sort by predicted score
            vulnerabilities.sort(
                key=lambda x: x.get('predicted_risk_score', 0),
                reverse=True
            )
        except Exception as e:
            log(f"[!] ML Re-ranking failed for SSL: {e}", user_id)

        log(f"[+] SSLScan report parsed successfully.", user_id, to_console=True)
        save_ssl_json(scan_summary, output_dir=output_dir, user_id=user_id, target=target)
        send_sse_event("ssl_report_parsed", scan_summary, user_id=user_id)
        return scan_summary

    except Exception as e:
        log(f"[!] Unexpected error parsing SSLScan report: {e}", user_id, to_console=True)
        return None
    finally:
        if os.path.exists(report_file):
            try:
                os.remove(report_file)
            except:
                pass

def clear_log_file(user_id=None):
    """Clears the log file for a specific user or the system log."""
    log_dir = BASE_DIR / "logs"
    if user_id:
        user_id = str(user_id)
        target_log_file = log_dir / "users" / user_id / "ssl_agent_log.txt"
    else:
        target_log_file = log_dir / "system" / "ssl_system_log.txt"

    try:
        if target_log_file.exists():
            with open(target_log_file, 'w', encoding='utf-8') as f:
                f.write("")
        
        if user_id:
            uq = get_user_queue(user_id)
            with uq.mutex: uq.queue.clear()
            
        log("[*] SSL log file cleared.", user_id)
    except Exception as e:
        logger.error(f"[!] Error clearing SSL log file: {e}")
