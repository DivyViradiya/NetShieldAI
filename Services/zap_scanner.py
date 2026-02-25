import os
import subprocess
import time
import psutil
import socket
import shutil
import re
from datetime import datetime
import xml.etree.ElementTree as ET
import json
import pandas as pd
import joblib
from pathlib import Path
import queue  # Queue for real-time streaming
import threading
from logger_setup import logger

# --- Configuration ---
ZAP_EXECUTABLE_PATH = r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"

# --- Path and Logging Setup ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

DEFAULT_RESULTS_DIR = os.path.join(BASE_DIR, "results", "zap_scanner")

LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR, exist_ok=True)

TEMP_DIR = os.path.join(BASE_DIR, "temp", "zap")
if not os.path.exists(TEMP_DIR):
    os.makedirs(TEMP_DIR, exist_ok=True)

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

# --- ML Model Setup ---
try:
    from .threat_reranker import predict_threat_risk
except ImportError:
    try:
        from threat_reranker import predict_threat_risk
    except ImportError:
        predict_threat_risk = None

model = predict_threat_risk

# --- FULL ZAP to CWE Mapping ---
ZAP_TO_CWE_MAP = {
    'Directory Browsing': 'CWE-548',
    'Private IP Disclosure': 'CWE-497',
    'Session ID in URL Rewrite': 'CWE-598',
    'Referer Exposes Session ID': 'CWE-598',
    'Path Traversal': 'CWE-22',
    'Remote File Inclusion': 'CWE-98',
    'Source Code Disclosure - Git': 'CWE-541',
    'Source Code Disclosure - SVN': 'CWE-541',
    'Source Code Disclosure - File Inclusion': 'CWE-541',
    'Vulnerable JS Library': 'CWE-1395',
    'In Page Banner Information Leak': 'CWE-497',
    'Cookie No HttpOnly Flag': 'CWE-1004',
    'Cookie Without Secure Flag': 'CWE-614',
    'Cross-Domain JavaScript Source File Inclusion': 'CWE-829',
    'Content-Type Header Missing': 'CWE-345',
    'Content-Type Header Empty': 'CWE-345',
    'Missing Anti-clickjacking Header': 'CWE-1021',
    'Multiple X-Frame-Options Header Entries': 'CWE-1021',
    'X-Frame-Options Defined via META (Non-compliant with Spec)': 'CWE-1021',
    'X-Frame-Options Setting Malformed': 'CWE-1021',
    'X-Content-Type-Options Header Missing': 'CWE-693',
    'Information Disclosure - Debug Error Messages': 'CWE-1295',
    'Information Disclosure - Sensitive Information in URL': 'CWE-598',
    'Information Disclosure - Sensitive Information in HTTP Referrer Header': 'CWE-598',
    'HTTP Parameter Override': 'CWE-20',
    'Information Disclosure - Suspicious Comments': 'CWE-615',
    'Off-site Redirect': 'CWE-601',
    'Cookie Poisoning': 'CWE-565',
    'User Controllable Charset': 'CWE-20',
    'User Controllable HTML Element Attribute (Potential XSS)': 'CWE-20',
    'Potential IP Addresses Found in the Viewstate': 'CWE-642',
    'Emails Found in the Viewstaterelease': 'CWE-642',
    'Old Asp.Net Version in Userelease': 'CWE-642',
    'Viewstate without MAC Signature (Unsure)': 'CWE-642',
    'Viewstate without MAC Signature (Sure)': 'CWE-642',
    'Split Viewstate in Userelease': 'CWE-642',
    'Heartbleed OpenSSL Vulnerability (Indicative)': 'CWE-119',
    'Strict-Transport-Security Header Not Set': 'CWE-319',
    'Strict-Transport-Security Disabled': 'CWE-319',
    'Strict-Transport-Security Multiple Header Entries (Non-compliant with Spec)': 'CWE-319',
    'Strict-Transport-Security Header on Plain HTTP Responserelease': 'CWE-319',
    'Strict-Transport-Security Missing Max-Age (Non-compliant with Spec)': 'CWE-319',
    'Strict-Transport-Security Defined via META (Non-compliant with Spec)': 'CWE-319',
    'Strict-Transport-Security Max-Age Malformed (Non-compliant with Spec)': 'CWE-319',
    'Strict-Transport-Security Malformed Content (Non-compliant with Spec)': 'CWE-319',
    'Server Leaks its Webserver Application via "Server" HTTP Response Header Field': 'CWE-497',
    'Server Leaks Version Information via "Server" HTTP Response Header Field': 'CWE-497',
    'Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)': 'CWE-497',
    'Content Security Policy (CSP) Header Not Set': 'CWE-693',
    'Obsolete Content Security Policy (CSP) Header Found': 'CWE-693',
    'Content Security Policy (CSP) Report-Only Header Found': 'CWE-693',
    'X-Backend-Server Header Information Leak': 'CWE-497',
    'Secure Pages Include Mixed Content': 'CWE-311',
    'HTTP to HTTPS Insecure Transition in Form Post': 'CWE-319',
    'HTTPS to HTTP Insecure Transition in Form Post': 'CWE-319',
    'User Controllable JavaScript Event (XSS)': 'CWE-20',
    'Big Redirect Detected (Potential Sensitive Information Leak)': 'CWE-201',
    'Multiple HREFs Redirect Detected (Potential Sensitive Information Leak)': 'CWE-201',
    'Source Code Disclosure - /WEB-INF Folder': 'CWE-541',
    'Properties File Disclosure - /WEB-INF folder': 'CWE-541',
    'HTTPS Content Available via HTTP': 'CWE-311',
    'Remote Code Execution - Shell Shock': 'CWE-78',
    'Non-Storable Content': 'CWE-524',
    'Storable but Non-Cacheable Content': 'CWE-524',
    'Storable and Cacheable Content': 'CWE-524',
    'Relative Path Confusion': 'CWE-20',
    'X-ChromeLogger-Data (XCOLD) Header Information Leak': 'CWE-532',
    'Cookie without SameSite Attribute': 'CWE-1275',
    'Cookie with SameSite Attribute None': 'CWE-1275',
    'Cookie with Invalid SameSite Attribute': 'CWE-1275',
    'CSP: X-Content-Security-Policy': 'CWE-693',
    'CSP: X-WebKit-CSP': 'CWE-693',
    'CSP: Notices': 'CWE-693',
    'CSP: Wildcard Directive': 'CWE-693',
    'CSP: script-src unsafe-inline': 'CWE-693',
    'CSP: style-src unsafe-inline': 'CWE-693',
    'CSP: script-src unsafe-hashes': 'CWE-693',
    'CSP: style-src unsafe-hashes': 'CWE-693',
    'CSP: Malformed Policy (Non-ASCII)': 'CWE-693',
    'CSP: script-src unsafe-eval': 'CWE-693',
    'CSP: Meta Policy Invalid Directive': 'CWE-693',
    'CSP: Header & Meta': 'CWE-693',
    'CSP: Failure to Define Directive with No Fallback': 'CWE-693',
    'X-Debug-Token Information Leak': 'CWE-489',
    'Username Hash Found': 'CWE-284',
    'GET for POST': 'CWE-16',
    'X-AspNet-Version Response Header': 'CWE-933',
    'PII Disclosure': 'CWE-359',
    'Permissions Policy Header Not Set': 'CWE-693',
    'Deprecated Feature Policy Header Set': 'CWE-16',
    'ASP.NET ViewState Disclosure': 'CWE-319',
    'ASP.NET ViewState Integrity': 'CWE-642',
    'Base64 Disclosure': 'CWE-319',
    'Backup File Disclosure': 'CWE-530',
    'Timestamp Disclosure - Unix': 'CWE-497',
    'Hash Disclosure - MD4 / MD5': 'CWE-497',
    'Cross-Domain Misconfiguration': 'CWE-264',
    'Source Code Disclosure - PHP': 'CWE-540',
    'Access Control Issue - Improper Authentication': 'CWE-287',
    'Access Control Issue - Improper Authorization': 'CWE-205',
    'Image Exposes Location or Privacy Data': 'CWE-200',
    'Authentication Credentials Captured': 'CWE-287',
    'Weak Authentication Method': 'CWE-326',
    'HTTP Only Site': 'CWE-311',
    'Httpoxy - Proxy Header Misuse': 'CWE-20',
    'Reverse Tabnabbing': 'CWE-1022',
    'Dangerous JS Functions': 'CWE-749',
    'Script Served From Malicious Domain (polyfill)': 'CWE-829',
    'Absence of Anti-CSRF Tokens': 'CWE-352',
    'Anti-CSRF Tokens Check': 'CWE-352',
    'HTTP Parameter Pollution': 'CWE-20',
    'Heartbleed OpenSSL Vulnerability': 'CWE-119',
    'Source Code Disclosure - CVE-2012-1823': 'CWE-20',
    'Remote Code Execution - CVE-2012-1823': 'CWE-20',
    'External Redirect': 'CWE-601',
    'Buffer Overflow': 'CWE-120',
    'Format String Error': 'CWE-134',
    'Integer Overflow Error': 'CWE-190',
    'CRLF Injection': 'CWE-113',
    'Parameter Tampering': 'CWE-472',
    'Server Side Include': 'CWE-97',
    'Cross Site Scripting (Reflected)': 'CWE-79',
    'Session Fixation': 'CWE-384',
    'Cross Site Scripting (Persistent)': 'CWE-79',
    'LDAP Injection': 'CWE-90',
    'SQL Injection': 'CWE-89',
    'SQL Injection - MySQL (Time Based)': 'CWE-89',
    'SQL Injection - Hypersonic SQL (Time Based)': 'CWE-89',
    'SQL Injection - Oracle (Time Based)': 'CWE-89',
    'SQL Injection - PostgreSQL (Time Based)': 'CWE-89',
    'Possible Username Enumeration': 'CWE-204',
    'SQL Injection - SQLite (Time Based)': 'CWE-89',
    'Proxy Disclosure': 'CWE-204',
    'Cross Site Scripting (DOM Based)': 'CWE-79',
    'SQL Injection - MsSQL (Time Based)': 'CWE-89',
    'ELMAH Information Leak': 'CWE-941',
    'Trace.axd Information Leak': 'CWE-215',
    'Out of Band XSS': 'CWE-79',
    '.htaccess Information Leak': 'CWE-941',
    'NoSQL Injection - MongoDB': 'CWE-943',
    '.env Information Leak': 'CWE-215',
    'Hidden File Found': 'CWE-538',
    'JWT Scan Rule': 'CWE-348',
    'Web Cache Deception': 'CWE-451',
    'CORS Misconfiguration': 'CWE-942',
    'File Upload': 'CWE-434',
    'Spring Actuator Information Leak': 'CWE-215',
    'Log4Shell (CVE-2021-44228)': 'CWE-117',
    'Log4Shell (CVE-2021-45046)': 'CWE-117',
    'Exponential Entity Expansion (Billion Laughs Attack)': 'CWE-776',
    'Spring4Shell': 'CWE-78',
    'Server Side Request Forgery': 'CWE-918',
    'Text4shell (CVE-2022-42889)': 'CWE-117',
    'GraphQL Endpoint Supports Introspection': 'CWE-16',
    'GraphQL Server Implementation Identified': 'CWE-205',
    'Insecure JSF ViewState': 'CWE-642',
    'Java Serialization Object': 'CWE-502',
    'Sub Resource Integrity Attribute Missing': 'CWE-345',
    'Insufficient Site Isolation Against Spectre Vulnerability': 'CWE-693',
    'Sec-Fetch-Site Header is Missing': 'CWE-352',
    'Sec-Fetch-Mode Header is Missing': 'CWE-352',
    'Sec-Fetch-Dest Header is Missing': 'CWE-352',
    'Sec-Fetch-User Header is Missing': 'CWE-352',
    'Sec-Fetch-Site Header Has an Invalid Value': 'CWE-352',
    'Sec-Fetch-Mode Header Has an Invalid Value': 'CWE-352',
    'Sec-Fetch-Dest Header Has an Invalid Value': 'CWE-352',
    'Sec-Fetch-User Header Has an Invalid Value': 'CWE-352',
    'Charset Mismatch': 'CWE-436',
    'XSLT Injection': 'CWE-91',
    'Advanced SQL Injection': 'CWE-89',
    'Server Side Code Injection - PHP Code Injection': 'CWE-94',
    'Server Side Code Injection - ASP Code Injection': 'CWE-94',
    'Remote OS Command Injection': 'CWE-78',
    'XPath Injection': 'CWE-643',
    'XML External Entity Attack': 'CWE-611',
    'Generic Padding Oracle': 'CWE-209',
    'Expression Language Injection': 'CWE-917',
    'SOAP Action Spoofing': 'CWE-451',
    'Cookie Slack Detector': 'CWE-205',
    'Insecure HTTP Method': 'CWE-749',
    'SOAP XML Injection': 'CWE-91',
    'Loosely Scoped Cookie': 'CWE-565',
    'Cloud Metadata Potentially Exposed': 'CWE-1230',
    'Server Side Template Injection': 'CWE-1336',
    'Server Side Template Injection (Blind)': 'CWE-1336',
    'Remote OS Command Injection (Time Based)': 'CWE-78',
    'NoSQL Injection - MongoDB (Time Based)': 'CWE-943',
}

# --- HELPER: Find a Free Port ---
def get_free_port():
    """Finds an available port on the host machine to avoid conflicts."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0)) # Bind to port 0 lets the OS select a free port
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        port = s.getsockname()[1]
        return port

# --- LOGGING FUNCTIONS (USER-AWARE) ---

def log(message, user_id=None, to_console=False):
    """
    Logs messages to:
    1. System Console (optional)
    2. User-specific log file (logs/users/{user_id}/zap_agent_log.txt)
    3. User-specific Memory Queue (for real-time frontend)
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}"
    
    # 1. System Console
    if to_console:
        logger.info(message) # use central logger info (colored formatter auto-detects)
    
    # If a specific user is targeted
    if user_id:
        user_id = str(user_id)
        # Organized Path: logs/users/{user_id}/
        user_dir = os.path.join(LOGS_DIR, "users", user_id)
        if not os.path.exists(user_dir):
            os.makedirs(user_dir, exist_ok=True)
            
        user_log_file = os.path.join(user_dir, "zap_agent_log.txt")
        try:
            with open(user_log_file, 'a', encoding='utf-8') as f:
                f.write(log_message + "\n")
        except Exception as e:
            logger.error(f"FATAL: Failed to write to user log file {user_log_file}: {e}")

        # 3. User-Specific Queue (Streaming)
        uq = get_user_queue(user_id)
        uq.put(message)
        
    else:
        # Fallback to general system log
        system_dir = os.path.join(LOGS_DIR, "system")
        if not os.path.exists(system_dir):
            os.makedirs(system_dir, exist_ok=True)
            
        try:
            with open(os.path.join(system_dir, "zap_system_log.txt"), 'a', encoding='utf-8') as f:
                f.write(log_message + "\n")
        except:
            pass

def clear_log_file(user_id):
    """Clears the log file and queue for a specific user."""
    if not user_id: return
    user_id = str(user_id)
    user_log_file = os.path.join(LOGS_DIR, "users", user_id, "zap_agent_log.txt")
    
    try:
        if os.path.exists(user_log_file):
            with open(user_log_file, 'w', encoding='utf-8') as f:
                f.write(f"--- Log cleared at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
        
        # RC-11 FIX: Drain queue using public API instead of internal mutex/queue attributes
        uq = get_user_queue(user_id)
        while not uq.empty():
            try:
                uq.get_nowait()
            except queue.Empty:
                break
            
    except Exception as e:
        logger.error(f"FATAL: Could not clear log file for user {user_id}: {e}")

def stop_user_scan(user_id):
    """
    RC-4 FIX: Safely terminates ONLY the ZAP process owned by this specific user.
    Use this for user-triggered scan cancellation instead of kill_zap_processes().
    """
    with scan_lock:
        entry = active_scans.get(user_id)
    if entry and entry.get("process"):
        entry["process"].terminate()
        log(f"[*] ZAP process for user {user_id} terminated by user request.", user_id)
        return True
    return False

def kill_zap_processes(user_id=None):
    """
    SYSTEM-LEVEL RESET ONLY — Terminates ALL ZAP processes on the machine.

    RC-4 WARNING: This function is GLOBAL and kills every ZAP instance system-wide,
    regardless of which user owns it. It MUST NOT be called from any user-triggered
    code path (e.g. scan start, scan stop, error handlers).
    Only call this on initial server startup/full system reset.
    For per-user cancellation, use stop_user_scan(user_id) instead.
    """
    log("Checking for and terminating existing ZAP processes...", user_id)
    killed_a_process = False
    current_pid = os.getpid()
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['pid'] != current_pid and proc.info['cmdline'] and 'zap.jar' in ' '.join(proc.info['cmdline']).lower():
                log(f"Found ZAP process {proc.name()} (PID: {proc.info['pid']}). Terminating...", user_id)
                proc.kill()
                killed_a_process = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    if not killed_a_process:
        log("No running ZAP processes found.", user_id)
    else:
        log("Waiting 5 seconds for system resources to be released...", user_id)
        time.sleep(5)

# --- ML Prediction ---
def predict_risk(vulnerability_name: str, description: str = "", severity: str = "Medium"):
    try:
        from Services.threat_reranker import predict_threat_risk
        return predict_threat_risk(vulnerability_name, description, severity=severity)
    except Exception as e:
        logger.error(f"Error predicting risk with Threat Reranker: {e}")
        return 0.5

# --- Path Helper ---
def get_output_paths(output_dir=None):
    if output_dir:
        base = Path(output_dir)
    else:
        base = Path(DEFAULT_RESULTS_DIR)
    
    if not base.exists():
        try:
            base.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"[!] Error creating directory {base}: {e}")

    return {
        "xml_report": base / "zap_report.xml",
        "json_report": base / "zap_report.json",
        "pdf_report": base / "zap_report.pdf"
    }

# --- Core Scan Logic (Simultaneous Support) ---
def run_zap_scan(target_url, report_path, user_id):
    """
    Launches ZAP and streams output to user specific log.
    Supports simultaneous execution by assigning unique ports and directories.
    """
    
    # 1. REMOVED kill_zap_processes to prevent stopping other concurrent scans.
    
    if not os.path.exists(ZAP_EXECUTABLE_PATH):
        log(f"Error: ZAP executable not found at '{ZAP_EXECUTABLE_PATH}'", user_id)
        return False

    # 2. Assign Unique Resources
    unique_zap_dir = ""
    try:
        assigned_port = get_free_port()
        
        # Create a unique directory for this specific scan instance/user in the central temp folder
        # This prevents the "HSQLDB Lock" error
        unique_zap_dir = os.path.join(TEMP_DIR, f"user_{user_id}_{assigned_port}")
        if not os.path.exists(unique_zap_dir):
            os.makedirs(unique_zap_dir, exist_ok=True)

        log(f"\n--- Starting ZAP Quick Scan (Isolated Instance) ---", user_id, to_console=True)
        log(f"Instance Config -> Port: {assigned_port} | Dir: {unique_zap_dir}", user_id, to_console=True)
        log(f"Target: {target_url}", user_id, to_console=True)
        log(f"Report will be saved to: {report_path}", user_id, to_console=True)

        report_dir = os.path.dirname(report_path)
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)

        # 3. Construct Command with Isolation Flags (-port and -dir)
        command = [
            ZAP_EXECUTABLE_PATH, '-cmd',
            '-port', str(assigned_port),
            '-dir', unique_zap_dir,
            '-quickurl', target_url,
            '-quickout', str(report_path),
            '-quickprogress'
        ]

        log(f"Executing command: {' '.join(command)}", user_id, to_console=True)
        zap_directory = os.path.dirname(ZAP_EXECUTABLE_PATH)
        
        process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            text=True, 
            encoding='utf-8', 
            errors='replace', 
            cwd=zap_directory,
            bufsize=1 
        )
        
        # Track this user's process
        with scan_lock:
            active_scans[user_id] = {"process": process, "target": target_url, "start_time": time.time()}

        log("--- ZAP Output Stream Started ---", user_id)
        
        # Stream stdout line by line
        for line in iter(process.stdout.readline, ''):
            if line:
                stripped_line = line.strip()
                # --- NOISE FILTER: Extract ZAP Progress Cleanly ---
                # Matches: [                    ] 15% /
                if "%" in stripped_line and "[" in stripped_line and "]" in stripped_line:
                    match = re.search(r'(\d+%)', stripped_line)
                    if match:
                        # Log the original line with [PROGRESS] prefix so UI can parse percent
                        # but still show the original bracket format in terminal
                        log(f"[PROGRESS] {stripped_line}", user_id)
                        continue
                
                if not stripped_line:
                    continue

                # Skip other noisy technical messages but keep important ones
                if any(x in stripped_line.lower() for x in ["copying default", "creating directory", "plugin"]):
                    if "main" in stripped_line: continue

                # We log to file/queue but NOT to console to avoid terminal clutter
                log(stripped_line, user_id, to_console=False)

        process.wait()
        
        # Unregister process
        with scan_lock:
            if user_id in active_scans:
                del active_scans[user_id]

        log("--- End of ZAP Output ---", user_id)

        success = False
        if process.returncode == 0 and os.path.exists(report_path):
            log(f"Scan completed successfully!", user_id, to_console=True)
            success = True
        else:
            log(f"Error: ZAP process failed. Return code: {process.returncode}.", user_id, to_console=True)
            success = False
            
        return success

    except Exception as e:
        log(f"An unexpected error occurred: {e}", user_id)
        return False
        
    finally:
        # 4. CLEANUP: Remove the temporary directory to save space
        if unique_zap_dir and os.path.exists(unique_zap_dir):
            try:
                log(f"Cleaning up temporary ZAP directory: {unique_zap_dir}", user_id)
                shutil.rmtree(unique_zap_dir, ignore_errors=True)
            except Exception as cleanup_error:
                log(f"Warning: Failed to clean up temp dir: {cleanup_error}", user_id)

def parse_zap_xml_report(report_file, user_id=None):
    """Parses ZAP XML and enriches with ML."""
    if not os.path.exists(report_file):
        log(f"Error: ZAP report file not found for parsing: {report_file}", user_id)
        return None
    
    log(f"Parsing ZAP report: {report_file}", user_id)
    
    # Initialize Summary with "Info" key
    report_data = {
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {"High": 0, "Medium": 0, "Low": 0, "Info": 0, "Total": 0},
        "findings": []
    }
    
    try:
        tree = ET.parse(report_file)
        root = tree.getroot()
        
        for alertitem in root.findall('.//alertitem'):
            riskdesc = alertitem.find('riskdesc').text
            risk = riskdesc.split(' ')[0] # Extracts "High", "Medium", "Low", "Informational"
            
            # Normalize "Informational" to "Info"
            if risk == "Informational": 
                risk = "Info"

            finding_name = alertitem.find('alert').text
            description = get_inner_html(alertitem.find('desc'))
            predicted_score = predict_risk(finding_name, description, severity=risk)

            finding = {
                "name": finding_name,
                "risk": risk,
                "predicted_risk_score": predicted_score,
                "confidence": alertitem.find('confidence').text,
                "url": alertitem.find('.//uri').text,
                "description": description,
                "solution": get_inner_html(alertitem.find('solution')),
                "reference": get_inner_html(alertitem.find('reference'))
            }
            
            if risk in report_data["summary"]:
                report_data["summary"][risk] += 1
                report_data["summary"]["Total"] += 1
            
            report_data["findings"].append(finding)
            
        # Sort by predicted score
        report_data["findings"].sort(
            key=lambda x: x['predicted_risk_score'] if isinstance(x['predicted_risk_score'], (int, float)) else -1,
            reverse=True
        )

        log("Report parsed and enriched successfully.", user_id)
        return report_data
    except Exception as e:
        log(f"An error occurred during report parsing: {e}", user_id)
        return None

def get_inner_html(element):
    if element is None: return ""
    return (element.text or '') + ''.join(ET.tostring(e, encoding='unicode') for e in element)

def save_json_report(data, output_dir, user_id=None):
    try:
        if output_dir:
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            json_path = os.path.join(output_dir, "zap_report.json")
        else:
            json_path = os.path.join(DEFAULT_RESULTS_DIR, "zap_report.json")

        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2)
        log(f"JSON report saved to: {json_path}", user_id)
        return json_path
    except Exception as e:
        log(f"Error saving JSON report: {e}", user_id)
        return None