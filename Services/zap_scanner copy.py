import os
import subprocess
import time
import psutil
from datetime import datetime
import xml.etree.ElementTree as ET
import json
# --- NEW: ML Imports ---
import pandas as pd
import joblib
import numpy as np  # <-- NEW
from pathlib import Path
from sentence_transformers import SentenceTransformer  # <-- NEW

# --- Configuration ---
ZAP_EXECUTABLE_PATH = r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"

# --- Path and Logging Setup ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = r"D:\NetShieldAI\Services\results\zap_scanner"
LOGS_DIR = r"D:\NetShieldAI\logs"
LOG_FILE = os.path.join(LOGS_DIR, "zap_agent_log.txt")

# --- NEW: ML Model and Data Paths (UPDATED) ---
MODELS_DIR = r"D:\NetShieldAI\models"
DATA_DIR = r"D:\NetShieldAI\Data"

# --- NEW: Paths for "Elite" Hybrid Model ---
MODEL_PATH = Path(MODELS_DIR) / 'vulnerability_ranker_hybrid_selected.joblib' # <-- UPDATED
PROFILES_PATH = Path(DATA_DIR) / 'cwe_profiles.csv' # <-- This file MUST have 'description_join'
SELECTOR_PATH = Path(MODELS_DIR) / 'kbest_selector_hybrid.joblib' # <-- NEW

# --- NEW: Load "Elite" Hybrid Model Artifacts ---
try:
    print("Loading ML artifacts...")
    # 1. Load the "Elite" XGBoost Model
    model = joblib.load(MODEL_PATH)
    
    # 2. Load the CWE Profiles (which has the 'description_join' column)
    cwe_profiles = pd.read_csv(PROFILES_PATH, index_col='cwe_id')
    
    # 3. Load the "Elite" Feature Selector
    kbest_selector = joblib.load(SELECTOR_PATH)
    
    # 4. Load the Sentence Transformer Model
    print("Loading Sentence Transformer model 'all-MiniLM-L6-v2'...")
    embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
    
    # 5. Define the 7 structured features our model expects
    structured_features = [
        'base_score_mean', 'base_score_max', 'base_score_std',
        'confidentiality_impact_numeric_mean', 'integrity_impact_numeric_mean',
        'availability_impact_numeric_mean', 'cve_count'
    ]
    print("✅ ML Model and data artifacts loaded successfully.")

except FileNotFoundError as e:
    print(f"FATAL: Could not load ML model or data files: {e}")
    print("Please ensure 'vulnerability_ranker_hybrid_selected.joblib', 'kbest_selector_hybrid.joblib',")
    print("and 'cwe_profiles.csv' (with descriptions) are in the correct directories.")
    model = None # Set to None to prevent script from running without the model
except Exception as e:
    print(f"FATAL: An unexpected error occurred loading ML artifacts: {e}")
    model = None

# --- ZAP Alert to CWE Mapping ---
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
print("✅ ZAP-to-CWE mapping created.")


def log(message):
    """Logs messages to the console and to a persistent log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}"
    print(log_message)
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(log_message + "\n")
    except Exception as e:
        print(f"[{timestamp}] FATAL: Failed to write to log file {LOG_FILE}: {e}")

def clear_log_file():
    """Clears the content of the log file at the start of a run."""
    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write(f"--- Log cleared at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
    except Exception as e:
        print(f"FATAL: Could not clear log file: {e}")

def kill_zap_processes():
    """Finds and terminates any running ZAP processes."""
    log("Checking for and terminating existing ZAP processes...")
    killed_a_process = False
    current_pid = os.getpid()
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['pid'] != current_pid and proc.info['cmdline'] and 'zap.jar' in ' '.join(proc.info['cmdline']).lower():
                log(f"Found ZAP process {proc.name()} (PID: {proc.info['pid']}). Terminating...")
                proc.kill()
                killed_a_process = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    if not killed_a_process:
        log("No running ZAP processes found.")
    else:
        log("Waiting 5 seconds for system resources to be released...")
        time.sleep(5)

# --- NEW: Prediction Function (Hybrid "Elite" Version) ---
def predict_risk(vulnerability_name: str):
    """
    Takes a vulnerability name, looks up its profile, generates hybrid features,
    and predicts its risk score using the "Elite" model.
    """
    if model is None:
        log("[!] PREDICTION ERROR: Model is not loaded.")
        return "N/A (Model not loaded)"

    # 1. Map ZAP name to CWE ID
    cwe_id = ZAP_TO_CWE_MAP.get(vulnerability_name)
    if not cwe_id:
        log(f"[!] PREDICTION: No CWE map found for '{vulnerability_name}'.")
        return "Unmapped"

    # 2. Fetch the CWE profile row
    try:
        # Use .loc[cwe_id] to get a Series, then convert to DataFrame
        profile = cwe_profiles.loc[cwe_id].to_frame().T
        profile.index.name = 'cwe_id'
    except KeyError:
        log(f"[!] PREDICTION: No profile found for {cwe_id} ('{vulnerability_name}').")
        return "Unprofiled"
    except Exception as e:
        log(f"[!] PREDICTION ERROR: {e} while fetching profile for {cwe_id}.")
        return "Error"

    try:
        # 3. Get Structured Features
        # Select the 7 structured features
        X_structured = profile[structured_features]

        # 4. Get Text Features & Apply Pipeline
        # Get the text description
        description = profile['description_join'].fillna('').tolist()
        
        # a. Generate 384 embeddings for this one description
        text_embedding = embedding_model.encode(description)
        
        # Ensure it's 2D for the selector
        if text_embedding.ndim == 1:
            text_embedding = text_embedding.reshape(1, -1)
        
        # b. Apply the KBest selector to filter it down to 30 features
        text_embedding_selected = kbest_selector.transform(text_embedding)

        # 5. Combine Features
        # Combine the 7 structured features with the 30 selected text features
        X_hybrid_final = np.hstack([X_structured.values, text_embedding_selected])

        # 6. Predict
        # The model was trained on [7 struct + 30 text], so this will work
        predicted_score = model.predict(X_hybrid_final)
        
        return round(float(predicted_score[0]), 2)
        
    except Exception as e:
        log(f"[!] PREDICTION ERROR: Failed during feature pipeline for {cwe_id}: {e}")
        return "Error"


def run_zap_scan(target_url, report_path):
    """Launches a ZAP scan and generates an XML report."""
    kill_zap_processes()
    if not os.path.exists(ZAP_EXECUTABLE_PATH):
        log(f"Error: ZAP executable not found at '{ZAP_EXECUTABLE_PATH}'")
        return False

    log(f"\n--- Starting ZAP Quick Scan ---")
    log(f"Target: {target_url}")
    log(f"Report will be saved to: {report_path}")

    command = [
        ZAP_EXECUTABLE_PATH, '-cmd',
        '-quickurl', target_url,
        '-quickout', report_path,
        '-quickprogress'
    ]

    try:
        log(f"Executing command: {' '.join(command)}")
        zap_directory = os.path.dirname(ZAP_EXECUTABLE_PATH)
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding='utf-8', errors='replace', cwd=zap_directory
        )
        log("--- ZAP Output ---")
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())
                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write(output)
        process.wait()
        log("--- End of ZAP Output ---")

        if process.returncode == 0 and os.path.exists(report_path):
            log(f"Scan completed successfully!")
            return True
        else:
            log(f"Error: ZAP process failed or report not created. Return code: {process.returncode}.")
            return False
    except Exception as e:
        log(f"An unexpected error occurred: {e}")
        return False

# --- MODIFIED: Report Parsing Function ---
def parse_zap_xml_report(report_file):
    """Parses a ZAP XML report and enriches it with predicted risk scores."""
    if not os.path.exists(report_file):
        log(f"Error: ZAP report file not found for parsing: {report_file}")
        return None
    
    log(f"Parsing ZAP report: {report_file}")
    
    report_data = {
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {"High": 0, "Medium": 0, "Low": 0, "Informational": 0, "Total": 0},
        "findings": []
    }
    
    try:
        tree = ET.parse(report_file)
        root = tree.getroot()
        
        for alertitem in root.findall('.//alertitem'):
            riskdesc = alertitem.find('riskdesc').text
            risk = riskdesc.split(' ')[0]
            
            if risk == "Informational":
                risk = "Info"

            finding_name = alertitem.find('alert').text
            
            # --- NEW: Predict risk score ---
            predicted_score = predict_risk(finding_name)

            finding = {
                "name": finding_name,
                "risk": risk,
                "predicted_risk_score": predicted_score, # Add the new score
                "confidence": alertitem.find('confidence').text,
                "url": alertitem.find('.//uri').text,
                "description": alertitem.find('desc').text if alertitem.find('desc') is not None else "",
                "solution": alertitem.find('solution').text if alertitem.find('solution') is not None else "",
                "reference": alertitem.find('reference').text if alertitem.find('reference') is not None else ""
            }
            
            if risk in report_data["summary"]:
                report_data["summary"][risk] += 1
                report_data["summary"]["Total"] += 1
            
            report_data["findings"].append(finding)
            
        # --- NEW: Sort findings by predicted risk score ---
        # Sorts in descending order, placing "N/A" values at the end
        report_data["findings"].sort(
            key=lambda x: x['predicted_risk_score'] if isinstance(x['predicted_risk_score'], (int, float)) else -1,
            reverse=True
        )

        log("Report parsed and enriched successfully.")
        return report_data
    except Exception as e:
        log(f"An error occurred during report parsing: {e}")
        return None


def save_json_report(data, output_dir):
    """Saves the scan results in JSON format with a fixed filename."""
    try:
        json_filename = "zap_report.json"
        json_path = os.path.join(output_dir, json_filename)
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2)
        log(f"JSON report saved to: {json_path}")
        return json_path
    except Exception as e:
        log(f"Error saving JSON report: {e}")
        return None

if __name__ == "__main__":
    clear_log_file()
    log("--- ZAP Scanner Script Started ---")
    
    target_to_scan = "http://www.example.com"
    xml_report_path = os.path.join(RESULTS_DIR, "zap_report.xml")
    
    log(f"Starting ZAP scan for target: {target_to_scan}")
    scan_successful = run_zap_scan(target_to_scan, xml_report_path)

    if scan_successful:
        log("Parsing and enriching scan results...")
        scan_results = parse_zap_xml_report(xml_report_path)
        if scan_results:
            scan_results["target_url"] = target_to_scan
            json_report_path = save_json_report(scan_results, RESULTS_DIR)
            
            # Print summary to console
            summary = scan_results["summary"]
            print("\n" + "="*60)
            print("                 ZAP Scan Summary & Risk Prediction")
            print("="*60)
            print(f"  Target: {target_to_scan}")
            if json_report_path:
                print(f"  JSON Report: {json_report_path}")
            print("-"*60)
            # --- MODIFIED: Print enriched findings ---
            print("  {:<45} {:<8} {:<10}".format("Finding", "Risk", "Predicted Score"))
            print("  {:<45} {:<8} {:<10}".format("-------", "----", "---------------"))
            for finding in scan_results["findings"]:
                print(f"  {finding['name'][:42]:<45} {finding['risk']:<8} {finding['predicted_risk_score']}")
            print("~"*60)
            print(f"  Total Alerts Found: {summary['Total']}")
            print("="*60)
        else:
            log("Could not generate a summary as report parsing failed.")
    else:
        log("Scan failed. Check the log file for details.")
    
    log("--- ZAP Scanner Script Finished ---")