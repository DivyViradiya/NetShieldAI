import os
import subprocess
import sys
import time
import psutil
import socket
import shutil
import re
import uuid
from datetime import datetime
import xml.etree.ElementTree as ET
import json
import pandas as pd
import joblib
from pathlib import Path
import queue
import threading
from zapv2 import ZAPv2
from Services import scan_logger

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
# --- Global State for Process Management (Transient - Process Only) ---
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

# --- ML Model Setup ---
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
DATA_DIR = os.path.join(PROJECT_ROOT, "Data")
MODEL_PATH = Path(MODELS_DIR) / 'vulnerability_ranker.joblib'
PROFILES_PATH = Path(DATA_DIR) / 'cwe_profiles.csv'
TRAINING_COLUMNS_PATH = Path(MODELS_DIR) / 'training_columns.joblib'

try:
    model = joblib.load(MODEL_PATH)
    cwe_profiles = pd.read_csv(PROFILES_PATH, index_col='cwe_id')
    training_columns = joblib.load(TRAINING_COLUMNS_PATH)
except FileNotFoundError as e:
    print(f"FATAL: Could not load ML model or data files: {e}")
    model = None

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
        s.bind(('', 0)) 
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]

def wait_for_zap(port, timeout=120):
    """Waits for ZAP daemon to be ready on the assigned port."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection(('localhost', port), timeout=1):
                return True
        except:
            time.sleep(2)
    return False

# --- LOGGING FUNCTIONS (USER-AWARE) ---

def log(message, user_id=None, to_console=False, level='INFO'):
    """
    Logs messages using the centralized scan_logger.
    """
    if to_console:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
    
    if user_id:
        scan_logger.write_log(user_id, "zap", message, level=level)

def clear_log_file(user_id):
    if not user_id: return
    log_file = scan_logger.get_active_log_file(user_id, "zap")
    try:
        open(log_file, 'w').close()
    except:
        pass

# --- ML Prediction ---
def predict_risk(vulnerability_name: str):
    if model is None:
        return "N/A (Model not loaded)"

    cwe_id = ZAP_TO_CWE_MAP.get(vulnerability_name)
    if not cwe_id:
        return "N/A"

    try:
        profile = cwe_profiles.loc[[cwe_id]]
    except KeyError:
        return f"Unprofiled"

    features_to_drop = [
        'actual_risk_score', 'av_weight', 'pr_weight', 'attack_vector_<lambda>',
        'privileges_required_<lambda>', 'user_interaction_<lambda>'
    ]
    profile_features = profile.drop(columns=features_to_drop, errors='ignore')
    profile_encoded = pd.get_dummies(profile_features)
    profile_final = profile_encoded.reindex(columns=training_columns, fill_value=0)

    predicted_score = model.predict(profile_final)
    return round(float(predicted_score[0]), 2)

# --- Path Helper ---
def get_output_paths(user_output_dir):
    base = Path(user_output_dir)
    return {
        "xml_report": base / "zap_report.xml",
        "json_report": base / "zap_report.json",
        "pdf_report": base / "zap_report.pdf"
    }

# --- Context and Authentication Helpers ---

def setup_context_and_auth(zap, context_name, target_url, auth_config=None, user_id=None):
    """
    Sets up a ZAP context, defines the scope, and configures form-based authentication if credentials are provided.
    """
    try:
        # 1. Create Context
        context_id = zap.context.new_context(context_name)
        log(f"[CONTEXT] Created context '{context_name}' (ID: {context_id})", user_id)

        # 2. Define Scope (Include target URL and sub-paths)
        # We use a regex that matches the target and anything below it
        target_regex = f"{target_url.rstrip('/')}.*"
        zap.context.include_in_context(context_name, target_regex)
        log(f"[CONTEXT] Scope defined: {target_regex}", user_id)

        # 3. Handle Authentication (Form-Based)
        if auth_config and all(k in auth_config for k in ['login_url', 'username_field', 'password_field', 'username', 'password']):
            log(f"[AUTH] Configuring Form-Based Auth for {auth_config['login_url']}...", user_id)
            
            # Set Authentication Method
            login_request_data = f"{auth_config['username_field']}={auth_config['username']}&{auth_config['password_field']}={auth_config['password']}"
            zap.authentication.set_authentication_method(
                context_id, 'formBasedAuthentication', 
                f"loginUrl={auth_config['login_url']}&loginRequestData={login_request_data}"
            )

            # Set Logged In/Out Indicators (Best effort detection)
            # You can refine these based on common patterns
            zap.authentication.set_logged_out_indicator(context_id, ".*(login|signin|authenticate).*")
            
            # Create a ZAP User
            user_name = f"user_{user_id}"
            user_id_zap = zap.users.new_user(context_id, user_name)
            
            # Set User Credentials
            zap.users.set_authentication_credentials(
                context_id, user_id_zap, 
                f"username={auth_config['username']}&password={auth_config['password']}"
            )
            
            zap.users.set_user_enabled(context_id, user_id_zap, 'true')
            zap.forcedUser.set_forced_user(context_id, user_id_zap)
            zap.forcedUser.set_forced_user_mode_enabled('true')
            
            log(f"[AUTH] User '{user_name}' created and Forced User Mode enabled.", user_id)
            return context_id, user_id_zap
            
        return context_id, None
    except Exception as e:
        log(f"[!] Error setting up context/auth: {e}", user_id)
        return None, None

# --- Core Scan Logic (Upgraded with zapv2) ---
def run_zap_scan(target_url, report_path, user_id, scan_mode="Quick Scan", use_ajax=False, auth_config=None):
    """
    Launches ZAP in daemon mode and uses the API for scanning.
    Supports tiered scanning, AJAX spidering, and Form-Based Authentication.
    """
    if not os.path.exists(ZAP_EXECUTABLE_PATH):
        log(f"Error: ZAP executable not found at '{ZAP_EXECUTABLE_PATH}'", user_id)
        return False

    assigned_port = get_free_port()
    unique_zap_dir = os.path.join(TEMP_DIR, f"user_{user_id}_{assigned_port}")
    os.makedirs(unique_zap_dir, exist_ok=True)

    log(f"\n--- Starting ZAP Engine (Port: {assigned_port}) ---", user_id, to_console=True)
    log(f"Mode: {scan_mode} | AJAX: {use_ajax} | Target: {target_url}", user_id, to_console=True)

    # Launch ZAP in Daemon Mode
    command = [
        ZAP_EXECUTABLE_PATH, '-daemon', '-port', str(assigned_port), 
        '-dir', unique_zap_dir, '-config', 'api.disablekey=true',
        '-config', 'api.addrs.addr.name=.*', '-config', 'api.addrs.addr.regex=true'
    ]

    process = None
    zap = None
    try:
        process = subprocess.Popen(
            command, 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.STDOUT, 
            cwd=os.path.dirname(ZAP_EXECUTABLE_PATH),
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0
        )

        with scan_lock:
            active_scans[user_id] = {"process": process, "target": target_url, "start_time": time.time()}

        if not wait_for_zap(assigned_port):
            log("Error: ZAP daemon failed to start within timeout.", user_id)
            return False
        
        zap = ZAPv2(proxies={'http': f'http://127.0.0.1:{assigned_port}', 'https': f'http://127.0.0.1:{assigned_port}'})
        
        # 1. Setup Context & Authentication
        context_name = f"Ctx_{user_id}_{assigned_port}"
        context_id, zap_user_id = setup_context_and_auth(zap, context_name, target_url, auth_config, user_id)

        # 2. Spidering
        if use_ajax:
            log("[STAGE] Starting AJAX Spider (Deep Discovery)...", user_id)
            # AJAX spider uses the context. Forced User mode (set in setup_context_and_auth) 
            # ensures the spider runs as the authenticated user if configured.
            zap.ajaxSpider.scan(url=target_url, contextname=context_name)
            while zap.ajaxSpider.status != 'stopped':
                log(f"[PROGRESS] AJAX Spider in progress...", user_id)
                time.sleep(5)
        else:
            log("[STAGE] Starting Web Spider...", user_id)
            # Regular spider with context and user if available
            zap.spider.scan(url=target_url, contextname=context_name)
            while int(zap.spider.status()) < 100:
                status = int(zap.spider.status())
                filled = status // 5
                bracket = "[" + ("=" * filled) + (" " * (20 - filled)) + "]"
                log(f"[PROGRESS] {bracket} {status}%", user_id)
                time.sleep(2)

        # 3. Passive Scan Wait
        log("[STAGE] Waiting for Passive Scan to complete...", user_id)
        while int(zap.pscan.records_to_scan) > 0:
            log(f"Passive Scan: {zap.pscan.records_to_scan} records remaining", user_id)
            time.sleep(2)

        # 4. Active Scanning
        if scan_mode in ["Quick Scan", "Full Scan"]:
            log("[STAGE] Starting Active Scan (Core Analysis)...", user_id)
            # Active scan with context and user
            scan_id = zap.ascan.scan(url=target_url, contextid=context_id)
            
            last_progress = -1
            while True:
                current_progress = int(zap.ascan.status(scan_id))
                if current_progress > last_progress:
                    filled = current_progress // 5
                    bracket = "[" + ("=" * filled) + (" " * (20 - filled)) + "]"
                    log(f"[PROGRESS] {bracket} {current_progress}%", user_id)
                    last_progress = current_progress
                
                if current_progress >= 100:
                    break
                time.sleep(5)
        
        log("Generating XML report...", user_id)
        xml_report = zap.core.xmlreport()
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(xml_report)
            
        return True
    except Exception as e:
        log(f"ZAP Scan Error: {e}", user_id)
        return False
    finally:
        with scan_lock:
            # We no longer need active_scans dict, DB handles it.
            if user_id in active_scans:
                del active_scans[user_id]

        if zap: 
            try: zap.core.shutdown()
            except: pass
        if process:
            process.terminate()
            try: process.wait(timeout=5)
            except: process.kill()
        if os.path.exists(unique_zap_dir):
            shutil.rmtree(unique_zap_dir, ignore_errors=True)

def parse_zap_xml_report(report_file, user_id=None):
    """Parses ZAP XML and enriches with ML."""
    if not os.path.exists(report_file):
        log(f"Error: ZAP report file not found: {report_file}", user_id)
        return None
    
    log(f"Parsing ZAP report: {report_file}", user_id)
    
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
            risk = riskdesc.split(' ')[0] 
            if risk == "Informational": risk = "Info"

            finding_name = alertitem.find('alert').text
            predicted_score = predict_risk(finding_name)

            finding = {
                "name": finding_name,
                "risk": risk,
                "predicted_risk_score": predicted_score,
                "confidence": alertitem.find('confidence').text,
                "url": alertitem.find('.//uri').text,
                "method": alertitem.find('.//method').text if alertitem.find('.//method') is not None else "GET",
                "description": get_inner_html(alertitem.find('desc')),
                "solution": get_inner_html(alertitem.find('solution')),
                "reference": get_inner_html(alertitem.find('reference')),
                "evidence": {
                    "request_header": alertitem.find('requestheader').text if alertitem.find('requestheader') is not None else "",
                    "request_body": alertitem.find('requestbody').text if alertitem.find('requestbody') is not None else "",
                    "response_header": alertitem.find('responseheader').text if alertitem.find('responseheader') is not None else "",
                    "response_body": alertitem.find('responsebody').text if alertitem.find('responsebody') is not None else ""
                }
            }
            
            if risk in report_data["summary"]:
                report_data["summary"][risk] += 1
                report_data["summary"]["Total"] += 1
            
            report_data["findings"].append(finding)
            
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
        os.makedirs(output_dir, exist_ok=True)
        json_path = os.path.join(output_dir, "zap_report.json")
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2)
        return json_path
    except Exception as e:
        log(f"Error saving JSON report: {e}", user_id)
        return None
