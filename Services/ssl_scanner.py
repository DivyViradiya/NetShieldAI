import subprocess
import os
import sys
import ctypes
from datetime import datetime
import platform
import queue
import json
import xml.etree.ElementTree as ET
from pathlib import Path

# MODIFIED: Define path to the local sslscan.exe
BASE_DIR = Path(__file__).parent.parent.parent
SSLSCAN_EXECUTABLE = Path(r"C:\Program Files\sslscan\sslscan.exe")

# Define paths for storing results
RESULTS_DIR = Path(r"D:\NetShieldAI\Services\results\ssl_scanner")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)  # Create directory if it doesn't exist

SSL_REPORT_XML = RESULTS_DIR / "ssl_report.xml"
LOG_FILE = Path(r"D:\NetShieldAI\logs\ssl_agent_log.txt")

# Ensure logs directory exists
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

# Global queue for logging messages to be consumed by Flask (or similar)
log_queue = queue.Queue()

def log(message):
    """Logs messages to an in-memory queue and to a file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"data: [{timestamp}] {message}\n\n" # SSE format
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

def _get_subprocess_creation_flags():
    """Returns appropriate creation flags for subprocess based on OS."""
    if platform.system() == "Windows":
        return subprocess.CREATE_NO_WINDOW
    return 0

def is_sslscan_available():
    """Checks if the local sslscan.exe is found at the expected path."""
    if not SSLSCAN_EXECUTABLE.exists():
        log(f"[!] ERROR: sslscan.exe not found at {SSLSCAN_EXECUTABLE}")
        log("[!] Please ensure it is installed and the path is correct.")
        return False
    log("[✓] sslscan.exe found.")
    return True

def run_ssl_scan(target_host):
    """Runs an SSL/TLS scan using the local sslscan.exe."""
    if not target_host:
        log("[!] Target host cannot be empty for SSL scan.")
        return None

    log(f"[+] Running local SSL scan on {target_host}...")
    if not is_sslscan_available():
        return None
    
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    local_cmd = [
        str(SSLSCAN_EXECUTABLE),
        f"--xml={SSL_REPORT_XML}",
        '--show-client-cas',
        '--show-cipher-ids',
        '--show-signatures',
        target_host
    ]

    try:
        log(f"[*] Executing command: {' '.join(local_cmd)}")
        process = subprocess.run(
            local_cmd,
            capture_output=True,
            text=True,
            check=False,
            creationflags=_get_subprocess_creation_flags(),
            cwd=SSLSCAN_EXECUTABLE.parent 
        )
        
        if process.stdout:
            log(f"[SSLScan STDOUT]\n{process.stdout}")
        if process.stderr:
            log(f"[SSLScan STDERR]\n{process.stderr}")

        if process.returncode != 0 and not SSL_REPORT_XML.exists():
            log(f"[!] SSL scan failed with exit code {process.returncode} and no report was generated.")
            return None
        
        if SSL_REPORT_XML.exists() and SSL_REPORT_XML.stat().st_size > 0:
            log(f"[+] SSL scan complete. Report saved to {SSL_REPORT_XML}")
            send_sse_event("ssl_scan_complete", {"target_host": target_host, "report_file": str(SSL_REPORT_XML)})
            return str(SSL_REPORT_XML)
        else:
            log(f"[!] SSL scan may have failed or generated an empty report: {SSL_REPORT_XML}")
            return None
            
    except Exception as e:
        log(f"[!] An unexpected error occurred during SSL scan: {e}")
        return None

# ############################################################################
# ## MODIFIED AND ENHANCED parse_ssl_report FUNCTION
# ############################################################################
def parse_ssl_report(report_file):
    """
    Parses an SSLScan XML report file to extract maximum details, including
    specific vulnerabilities and server configuration details.
    """
    if not os.path.exists(report_file):
        log(f"[!] SSLScan report file not found: {report_file}")
        return None
    
    try:
        tree = ET.parse(report_file)
        root = tree.getroot()
        
        # Initialize a more detailed summary structure
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
            # The IP address is often not in the root element, check elsewhere if needed

        # --- Server Configuration Details ---
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
        
        # --- Protocols ---
        for protocol_elem in root.findall('.//protocol'):
            scan_summary["protocols"].append({
                "name": protocol_elem.get('version', 'N/A'),
                "enabled": protocol_elem.get('enabled', '0') == '1'
            })

        # --- Ciphers ---
        for cipher_elem in root.findall('.//cipher[@status="accepted"]'):
            scan_summary["ciphers"].append({
                "status": "accepted",
                "protocol": cipher_elem.get('sslversion', 'N/A'),
                "bits": int(cipher_elem.get('bits', '0')),
                "name": cipher_elem.get('cipher', 'N/A'),
                "id": cipher_elem.get('id', 'N/A')
            })

        # --- Certificate Chain ---
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

        # --- Client CAs ---
        scan_summary["client_cas"] = [ca.get('name', 'N/A') for ca in root.findall('.//client-cas/ca')]

        # --- Enhanced Vulnerability Detection ---
        vulnerabilities = []
        # Heartbleed
        if (hb := root.find('.//heartbleed')) and hb.get('vulnerable') == '1':
            vulnerabilities.append({"name": "Heartbleed", "severity": "Critical", "description": "Server is vulnerable to the Heartbleed bug (CVE-2014-0160)."})
        # Insecure Renegotiation
        if scan_summary["server_configs"]["renegotiation"].get("supported") and not scan_summary["server_configs"]["renegotiation"].get("secure"):
             vulnerabilities.append({"name": "Insecure TLS Renegotiation", "severity": "Medium", "description": "Server supports insecure client-initiated renegotiation."})
        # TLS Compression (CRIME)
        if scan_summary["server_configs"]["tls_compression"].get("supported"):
            vulnerabilities.append({"name": "TLS Compression Enabled (CRIME)", "severity": "Medium", "description": "TLS compression is enabled, which can expose the application to the CRIME attack."})
        # Weak Protocols (SSLv2, SSLv3)
        for proto in scan_summary["protocols"]:
            if proto["enabled"] and ("SSLv2" in proto["name"] or "SSLv3" in proto["name"]):
                 vulnerabilities.append({"name": f"Weak Protocol Enabled: {proto['name']}", "severity": "High", "description": f"{proto['name']} is outdated and vulnerable to attacks like POODLE."})
        # Weak Signature Algorithm in Certificate
        for cert in scan_summary["certificate_chain"]:
            if "sha1" in cert["signature_algorithm"].lower():
                vulnerabilities.append({"name": "Weak Certificate Signature", "severity": "Medium", "description": f"Certificate uses a SHA1 signature, which is deprecated and insecure. (Issuer: {cert['issuer']})"})
        # Weak Ciphers (3DES, RC4, Low Bit)
        for c in scan_summary["ciphers"]:
            if c["bits"] < 128:
                vulnerabilities.append({"name": "Weak Cipher Suite", "severity": "Medium", "description": f"Cipher {c['name']} uses a weak key size ({c['bits']}-bit)." })
            if "3DES" in c["name"]:
                vulnerabilities.append({"name": "3DES Cipher Suite", "severity": "Low", "description": f"Cipher {c['name']} is supported, which is vulnerable to Sweet32." })
            if "RC4" in c["name"]:
                vulnerabilities.append({"name": "RC4 Cipher Suite", "severity": "Medium", "description": f"Cipher {c['name']} is supported, which is insecure."})
        
        scan_summary["vulnerabilities"] = vulnerabilities

        log(f"[+] SSLScan report '{os.path.basename(report_file)}' parsed successfully.")
        send_sse_event("ssl_report_parsed", scan_summary)
        return scan_summary

    except ET.ParseError as e:
        log(f"[!] Error parsing SSLScan XML report '{report_file}': {e}")
        return None
    except Exception as e:
        log(f"[!] Unexpected error parsing SSLScan report '{report_file}': {e}")
        return None

def clear_log_file():
    """Clears the content of the log output file."""
    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write("")
        log("[*] SSL log file cleared.")
    except Exception as e:
        log(f"[!] Error clearing SSL log file: {e}")

# Main execution block
if __name__ == "__main__":
    log("Starting SSL Scanner demonstration...")
    clear_log_file()

    target = "expired.badssl.com" # Using a test site with known issues
    log(f"Attempting SSL Scan on: {target}")
    report_path = run_ssl_scan(target)
    
    if report_path:
        log(f"SSL Scan completed. Parsing report: {report_path}")
        summary = parse_ssl_report(report_path)
        if summary:
            print("\n--- SSL Scan Summary (Max Information) ---")
            # Using json.dumps for a clean, full view of the extracted data
            print(json.dumps(summary, indent=4))
        else:
            log("[!] Failed to parse SSL report.")
    else:
        log("[!] SSL Scan failed.")

    log("SSL Scanner demonstration finished.")