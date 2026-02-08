import os
import subprocess
import sys
import time
import psutil
import socket
import shutil
from datetime import datetime
import xml.etree.ElementTree as ET
import json
import pandas as pd
import joblib
from pathlib import Path
import queue
from zapv2 import ZAPv2  # REQUIRED: pip install python-owasp-zap-v2.4

# --- Configuration ---
# IMPORTANT: Verify this path matches your installation exactly
ZAP_EXECUTABLE_PATH = r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"

# --- Path and Logging Setup ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

DEFAULT_RESULTS_DIR = os.path.join(BASE_DIR, "results", "api_scanner")

LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR, exist_ok=True)

TEMP_DIR = os.path.join(BASE_DIR, "temp", "api_scanner")
if not os.path.exists(TEMP_DIR):
    os.makedirs(TEMP_DIR, exist_ok=True)

# --- USER ISOLATION ---
user_queues = {}

def get_user_queue(user_id):
    if user_id not in user_queues:
        user_queues[user_id] = queue.Queue()
    return user_queues[user_id]

# --- ML Model Setup (Reused from zap_scanner) ---
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
DATA_DIR = os.path.join(PROJECT_ROOT, "Data")
MODEL_PATH = Path(MODELS_DIR) / 'vulnerability_ranker.joblib'
PROFILES_PATH = Path(DATA_DIR) / 'cwe_profiles.csv'
TRAINING_COLUMNS_PATH = Path(MODELS_DIR) / 'training_columns.joblib'

try:
    if MODEL_PATH.exists():
        model = joblib.load(MODEL_PATH)
        cwe_profiles = pd.read_csv(PROFILES_PATH, index_col='cwe_id')
        training_columns = joblib.load(TRAINING_COLUMNS_PATH)
        print("✅ ML Model loaded for API Scanner.")
    else:
        print(f"⚠️  ML Model not found at {MODEL_PATH}. Scoring will be skipped.")
        model = None
except Exception as e:
    print(f"⚠️  ML Model Load Error: {e}")
    model = None

# --- ZAP to CWE Mapping (Subset for brevity, keep your full list) ---
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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        port = s.getsockname()[1]
        return port

def get_output_paths(user_output_dir):
    """Helper for the Blueprint to find files."""
    base = Path(user_output_dir)
    return {
        "xml_report": Path(TEMP_DIR) / "api_scan_report.xml",
        "json_report": base / "api_scan_report.json",
        "pdf_report": base / "api_scan_report.pdf"
    }

# --- LOGGING FUNCTIONS ---
def log(message, user_id=None):
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_message = f"[{timestamp}] {message}"
    print(log_message)
    
    if user_id:
        user_id = str(user_id)
        # File logging (optional)
        # user_log_file = os.path.join(LOGS_DIR, f"api_scan_{user_id}.log")
        # with open(user_log_file, 'a', encoding='utf-8') as f: f.write(log_message + "\n")

        uq = get_user_queue(user_id)
        uq.put(log_message)

def clear_log_file(user_id):
    if not user_id: return
    user_id = str(user_id)
    uq = get_user_queue(user_id)
    with uq.mutex:
        uq.queue.clear()

# --- ML Prediction ---
def predict_risk(vulnerability_name: str):
    if model is None: return "N/A"
    cwe_id = ZAP_TO_CWE_MAP.get(vulnerability_name)
    
    # Simple Fallback if mapping fails but name implies risk
    if not cwe_id:
        if "SQL" in vulnerability_name or "RCE" in vulnerability_name: return 9.0
        if "XSS" in vulnerability_name: return 7.0
        return "Unprofiled"
        
    if cwe_id not in cwe_profiles.index: return "Unprofiled"
    
    try:
        profile = cwe_profiles.loc[[cwe_id]]
        features_to_drop = ['actual_risk_score', 'av_weight', 'pr_weight', 'attack_vector_<lambda>', 'privileges_required_<lambda>', 'user_interaction_<lambda>']
        profile_features = profile.drop(columns=features_to_drop, errors='ignore')
        profile_encoded = pd.get_dummies(profile_features)
        profile_final = profile_encoded.reindex(columns=training_columns, fill_value=0)
        return round(float(model.predict(profile_final)[0]), 2)
    except Exception: return "Error"

# --- CORE API SCAN LOGIC ---

def wait_for_zap(port, timeout=120):
    """Waits for ZAP to start listening on the specified port."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection(('localhost', port), timeout=1):
                return True
        except (socket.timeout, ConnectionRefusedError):
            time.sleep(2)
    return False

def run_api_scan(target_url, definition_url, report_path, user_id):
    """
    Main entry point called by the Blueprint.
    1. Starts ZAP Daemon.
    2. Imports OpenAPI definition.
    3. Scans.
    4. Saves Report.
    """
    
    if not os.path.exists(ZAP_EXECUTABLE_PATH):
        log(f"Error: ZAP executable not found at {ZAP_EXECUTABLE_PATH}", user_id)
        return False

    assigned_port = get_free_port()
    # Create a unique temp directory for this specific scan instance in the centralized temp folder
    unique_zap_dir = os.path.join(TEMP_DIR, f"user_{user_id}_{assigned_port}")
    if not os.path.exists(unique_zap_dir): os.makedirs(unique_zap_dir, exist_ok=True)

    log(f"--- Initializing API Scanner (Port: {assigned_port}) ---", user_id)
    log(f"Target API: {target_url}", user_id)
    log(f"Definition: {definition_url}", user_id)

    # 1. Start ZAP in DAEMON mode
    command = [
        ZAP_EXECUTABLE_PATH, 
        '-daemon', 
        '-port', str(assigned_port), 
        '-dir', unique_zap_dir,
        '-config', 'api.disablekey=true',
        '-config', 'api.addrs.addr.name=.*', 
        '-config', 'api.addrs.addr.regex=true'
    ]

    process = None
    zap = None

    try:
        log("Launching ZAP engine...", user_id)
        zap_dir = os.path.dirname(ZAP_EXECUTABLE_PATH)
        process = subprocess.Popen(
            command, 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.STDOUT,
            cwd=zap_dir,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0
        )

        if not wait_for_zap(assigned_port):
            log("Error: ZAP failed to start within timeout.", user_id)
            return False
        
        log("Engine started. Connecting...", user_id)
        
        # Connect to ZAP
        zap = ZAPv2(proxies={'http': f'http://127.0.0.1:{assigned_port}', 'https': f'http://127.0.0.1:{assigned_port}'})
        
        # 4. Import OpenAPI Definition
        log("Importing OpenAPI Definition...", user_id)
        try:
            # This requires the 'openapi' addon in ZAP
            zap.openapi.import_url(definition_url)
        except Exception as e:
            log(f"Error importing OpenAPI: {e}. Check if URL is valid/reachable.", user_id)
            return False

        time.sleep(5) # Allow import to populate the tree

        # 5. Start Active Scan
        log(f"Starting Active Scan on {target_url}...", user_id)
        
        # Optimize Scan Speed
        try:
            # Set number of threads per host
            zap.ascan.set_option_thread_per_host(10)
            # Disable host-specific concurrent scan limit to speed up
            zap.ascan.set_option_host_per_scan(1)
            # Ensure no artificial delay
            zap.ascan.set_option_delay_in_ms(0)
            log("[*] Scan parameters optimized for speed.", user_id)
        except Exception as e:
            log(f"Warning: Failed to optimize scan parameters: {e}", user_id)

        scan_id = zap.ascan.scan(target_url)
        
        last_progress = -1
        stuck_counter = 0
        
        while True:
            progress = int(zap.ascan.status(scan_id))
            if progress != last_progress:
                log(f"Scan Progress: {progress}%", user_id)
                last_progress = progress
                stuck_counter = 0
            else:
                stuck_counter += 1
                
            if progress >= 100:
                break
                
            # If stuck for more than 5 minutes (60 * 5 / 5 = 60 iterations), move on
            if stuck_counter > 60:
                log("[!] Scan seems stuck at certain point. Finishing early to preserve results...", user_id)
                zap.ascan.stop(scan_id)
                break
                
            time.sleep(5)
        
        log("Scan complete. Generating report...", user_id)

        # 6. Save XML Report
        xml_report = zap.core.xmlreport()
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(xml_report)
            
        return True

    except Exception as e:
        log(f"Critical Scan Error: {e}", user_id)
        return False

    finally:
        # 7. Cleanup
        log("Shutting down ZAP engine...", user_id)
        if zap:
            try: zap.core.shutdown()
            except: pass
        
        if process:
            process.terminate()
            try: process.wait(timeout=5)
            except: process.kill()
            
        if os.path.exists(unique_zap_dir):
            try: shutil.rmtree(unique_zap_dir, ignore_errors=True)
            except: pass


def parse_xml_report(report_file, user_id=None):
    if not os.path.exists(report_file):
        log(f"Error: Report file not found: {report_file}", user_id)
        return None
    
    log("Analyzing scan results...", user_id)
    
    report_data = {
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_type": "API Scan (OpenAPI)",
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

            # Get clean Description
            desc_element = alertitem.find('desc')
            description = desc_element.text if desc_element is not None else ""
            
            # Get URL/Method
            uri_element = alertitem.find('.//uri')
            url = uri_element.text if uri_element is not None else "Unknown"
            
            method_element = alertitem.find('.//method')
            method = method_element.text if method_element is not None else "GET"

            finding = {
                "name": finding_name,
                "risk": risk,
                "predicted_risk_score": predicted_score,
                "confidence": alertitem.find('confidence').text,
                "method": method,
                "url": url,
                "description": description,
                "solution": get_inner_html(alertitem.find('solution')),
                "reference": get_inner_html(alertitem.find('reference'))
            }
            
            if risk in report_data["summary"]:
                report_data["summary"][risk] += 1
                report_data["summary"]["Total"] += 1
            
            report_data["findings"].append(finding)
            
        # Sort findings by Predicted Score (High to Low)
        def get_score(x):
            val = x.get('predicted_risk_score', 0)
            return val if isinstance(val, (int, float)) else 0
            
        report_data["findings"].sort(key=get_score, reverse=True)

        return report_data
    except Exception as e:
        log(f"Parsing Error: {e}", user_id)
        return None
    finally:
        # CLEANUP: Remove temporary XML report
        if os.path.exists(report_file):
            try:
                os.remove(report_file)
            except Exception as e:
                log(f"[!] Warning: Failed to delete temporary API report {report_file}: {e}")

def get_inner_html(element):
    if element is None: return ""
    return (element.text or '') + ''.join(ET.tostring(e, encoding='unicode') for e in element)

def save_json_report(data, output_dir, user_id=None):
    try:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        json_path = os.path.join(output_dir, "api_scan_report.json")

        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2)
        return json_path
    except Exception as e:
        log(f"Error saving JSON: {e}", user_id)
        return None