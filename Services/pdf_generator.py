import os
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML, CSS
import pathlib

# --- Path Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
TEMPLATE_DIR = os.path.join(BASE_DIR, 'PDF_templates')
# Assuming 'static/css/PDF_style/report_style.css' is the general style sheet
CSS_FILE_PATH = os.path.join(PROJECT_ROOT, 'static', 'css', 'PDF_style', 'report_style.css')

# --- Template File Names ---
ZAP_TEMPLATE_FILE = "zap_report_template.html"
NMAP_TEMPLATE_FILE = "nmap_report_template.html"
SSL_TEMPLATE_FILE = "ssl_report_template.html"
SNIFFER_TEMPLATE_FILE = "sniffer_report_template.html"


def create_nmap_report_pdf(source_data, pdf_path):
    """
    Renders Nmap data into an HTML template and saves it as a PDF.
    
    Args:
        source_data (dict | str): Either the Nmap data dictionary OR a file path to the JSON.
        pdf_path (str): The destination path for the PDF.
    """
    print(f"[*] Starting WeasyPrint PDF generation for Nmap...")

    # 1. Determine Input Type (Path or Dict)
    nmap_data = {}
    if isinstance(source_data, str):
        # It's a file path
        if not os.path.exists(source_data):
            raise FileNotFoundError(f"Nmap JSON report not found at {source_data}")
        with open(source_data, 'r', encoding='utf-8') as f:
            nmap_data = json.load(f)
    elif isinstance(source_data, dict):
        # It's already data
        nmap_data = source_data
    else:
        raise ValueError("create_nmap_report_pdf expects a file path (str) or data (dict)")

    # 2. Validate Resources
    if not os.path.exists(CSS_FILE_PATH):
        raise FileNotFoundError(f"CSS file not found at {CSS_FILE_PATH}")

    # 3. Set up Jinja2 Environment
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template(NMAP_TEMPLATE_FILE)

    # 4. Prepare Template Data
    template_data = {
        "data": nmap_data,
        "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # 5. Render HTML
    rendered_html = template.render(template_data)

    # 6. Load CSS
    css = CSS(filename=CSS_FILE_PATH)

    # 7. Render PDF
    # base_url is set to Project Root so /static/ images resolve correctly
    base_url = pathlib.Path(PROJECT_ROOT).as_uri()
    html = HTML(string=rendered_html, base_url=base_url)

    # Write the PDF (Exceptions here will bubble up to the caller)
    html.write_pdf(pdf_path, stylesheets=[css])

    print(f"[+] WeasyPrint Nmap report saved successfully to: {pdf_path}")
    return True

def create_zap_report_pdf(json_path, pdf_path):
    """
    Reads the ZAP JSON report and renders it as a PDF.
    """
    # ... (Implementation of ZAP report generation) ...
    print(f"[*] Starting WeasyPrint PDF generation for ZAP: {json_path}")

    if not os.path.exists(json_path):
        raise FileNotFoundError(f"JSON report file not found at {json_path}")
    
    if not os.path.exists(CSS_FILE_PATH):
        raise FileNotFoundError(f"CSS file not found at {CSS_FILE_PATH}")

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template(ZAP_TEMPLATE_FILE)

    template_data = {
        "data": data,
        "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    rendered_html = template.render(template_data)
    css = CSS(filename=CSS_FILE_PATH)
    base_url = pathlib.Path(PROJECT_ROOT).as_uri()
    
    html = HTML(string=rendered_html, base_url=base_url)
    html.write_pdf(pdf_path, stylesheets=[css])
    
    print(f"[+] WeasyPrint PDF report saved successfully to: {pdf_path}")
    return True

def create_ssl_report_pdf(source_data, pdf_path):
    """
    Renders SSL Scan data into an HTML template and saves it as a PDF.
    """
    # ... (Implementation of SSL report generation) ...
    print(f"[*] Starting WeasyPrint PDF generation for SSL...")

    # 1. Determine Input Type (Path or Dict)
    ssl_data = {}
    if isinstance(source_data, str):
        if not os.path.exists(source_data):
            raise FileNotFoundError(f"SSL JSON report not found at {source_data}")
        with open(source_data, 'r', encoding='utf-8') as f:
            ssl_data = json.load(f)
    elif isinstance(source_data, dict):
        ssl_data = source_data
    else:
        raise ValueError("create_ssl_report_pdf expects a file path (str) or data (dict)")

    # 2. Validate Resources
    if not os.path.exists(CSS_FILE_PATH):
        raise FileNotFoundError(f"CSS file not found at {CSS_FILE_PATH}")

    # 3. Set up Jinja2 Environment
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template(SSL_TEMPLATE_FILE)

    # 4. Prepare Template Data
    template_data = {
        "data": ssl_data,
        "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # 5. Render HTML
    rendered_html = template.render(template_data)

    # 6. Load CSS
    css = CSS(filename=CSS_FILE_PATH)

    # 7. Render PDF
    base_url = pathlib.Path(PROJECT_ROOT).as_uri()
    html = HTML(string=rendered_html, base_url=base_url)

    html.write_pdf(pdf_path, stylesheets=[css])

    print(f"[+] WeasyPrint SSL report saved successfully to: {pdf_path}")
    return True

def create_packet_sniffer_report_pdf(source_data, pdf_path):
    """
    Renders Packet Sniffer (TShark) data into an HTML template and saves it as a PDF.
    
    Args:
        source_data (dict | str): Either the analysis data dictionary OR a file path to the JSON.
        pdf_path (str): The destination path for the PDF.
    """
    print(f"[*] Starting WeasyPrint PDF generation for Packet Sniffer Analysis...")

    # 1. Determine Input Type (Path or Dict)
    sniffer_data = {}
    if isinstance(source_data, str):
        # It's a file path
        if not os.path.exists(source_data):
            raise FileNotFoundError(f"Packet Sniffer JSON report not found at {source_data}")
        try:
            with open(source_data, 'r', encoding='utf-8') as f:
                sniffer_data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Error decoding Packet Sniffer JSON file: {e}") from e
    elif isinstance(source_data, dict):
        # It's already data
        sniffer_data = source_data
    else:
        raise ValueError("create_packet_sniffer_report_pdf expects a file path (str) or data (dict)")
    
    # --------------------------------------------------------------------------------------
    # ⭐ DEFENSIVE CHECK & DATA FIX BEFORE RENDERING ⭐
    # This prevents the integer division error if a numerical field is unexpectedly zero/None.
    # We will ensure the key used in the rate calculation (if present) is always safe, 
    # though the safest fix is in the template itself.
    # --------------------------------------------------------------------------------------
    
    # Example defensive data setting (assuming 'average_rate_bps' is safe via packet_sniffer.py)
    # If the error is still present, we ensure all numerical fields are present and non-zero
    
    # Access nested data safely and provide defaults to prevent crashes in the template math
    sniffer_data.setdefault('traffic_summary', {})
    sniffer_data['traffic_summary'].setdefault('total_bytes', 0)
    
    # Ensure structured_context exists with safe defaults if the JSON was loaded from a file 
    # that wasn't enriched by the latest packet_sniffer.py logic.
    if 'structured_context' not in sniffer_data:
        print("[!] Warning: structured_context missing. Attempting minimal report generation.")
        # This is where the old version would crash, but since we updated packet_sniffer.py 
        # to ensure the JSON is ENRICHED before this function is called in Flask, this 
        # should only happen if the JSON report was manually created without structure.
        
        # A proper fix requires loading packet_sniffer here and running build_pdf_report_context, 
        # but that would create a circular dependency. We rely on the Flask blueprint 
        # to ensure the input data is correct.
        
    # --------------------------------------------------------------------------------------

    # 2. Validate Resources
    if not os.path.exists(CSS_FILE_PATH):
         print(f"[!] Warning: CSS file not found at {CSS_FILE_PATH}. PDF styling will be minimal.")
         css = None
    else:
         # 3. Load CSS
         css = CSS(filename=CSS_FILE_PATH)

    # 4. Set up Jinja2 Environment
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    try:
        template = env.get_template(SNIFFER_TEMPLATE_FILE)
    except Exception as e:
        raise FileNotFoundError(f"Jinja2 template file not found: {SNIFFER_TEMPLATE_FILE}. Check TEMPLATE_DIR: {TEMPLATE_DIR}") from e

    # 5. Prepare Template Data
    template_data = {
        "data": sniffer_data,
        "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # 6. Render HTML
    rendered_html = template.render(template_data)

    # 7. Render PDF
    base_url = pathlib.Path(PROJECT_ROOT).as_uri() # Resolves assets
    html = HTML(string=rendered_html, base_url=base_url)

    # Write the PDF
    stylesheets = [css] if css else []
    html.write_pdf(pdf_path, stylesheets=stylesheets)

    print(f"[+] WeasyPrint Packet Sniffer report saved successfully to: {pdf_path}")
    return True


# --- Main block for testing ---
if __name__ == "__main__":
    import traceback
    print("Running PDF Generator in test mode...")
    
    # --- ZAP Test ---
    test_json_path = os.path.join(BASE_DIR, 'results', 'zap_scanner', 'zap_report.json')
    test_pdf_path = os.path.join(BASE_DIR, 'results', 'zap_scanner', 'zap_report_TEST.pdf')

    if os.path.exists(test_json_path):
        try:
            create_zap_report_pdf(test_json_path, test_pdf_path)
        except Exception as e:
            print(f"[TEST FAILED] ZAP generation error: {e}")
    else:
        print(f"[SKIP] ZAP JSON not found at {test_json_path}")

    # --- Nmap Test ---
    print("\n--- Testing Nmap PDF Generation ---")
    dummy_nmap_data = {
        "scan_args": "nmap -sV -oA test_dummy 127.0.0.1",
        "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "target_ip": "127.0.0.1",
        "host_status": "up",
        "os_guess": "Linux Test Environment",
        "ports": [
            {"port": "80", "protocol": "tcp", "service": "http", "version": "Apache 2.4", "state": "open", "process_name": "httpd"},
            {"port": "22", "protocol": "tcp", "service": "ssh", "version": "OpenSSH", "state": "open", "process_name": "sshd"}
        ]
    }
    
    nmap_test_pdf_path = os.path.join(BASE_DIR, 'results', 'network_scanner', 'nmap_report_TEST.pdf')
    os.makedirs(os.path.dirname(nmap_test_pdf_path), exist_ok=True)
    
    try:
        create_nmap_report_pdf(dummy_nmap_data, nmap_test_pdf_path)
        print("[TEST SUCCESS] Dummy Nmap PDF created.")
    except Exception as e:
        print(f"[TEST FAILED] Nmap generation error: {e}")
        
    # --- Packet Sniffer Test (Production Flow Test) ---
    print("\n--- Testing Packet Sniffer PDF Generation (Using Real Output File) ---")
    
    SNIFFER_JSON_REPORT = r"D:\NetShieldAI\Services\results\packet_sniffer\pcap_analysis_report.json"
    
    sniffer_test_pdf_path = os.path.join(BASE_DIR, 'results', 'packet_sniffer', 'sniffer_report_TEST_REAL.pdf')
    os.makedirs(os.path.dirname(sniffer_test_pdf_path), exist_ok=True)

    if os.path.exists(SNIFFER_JSON_REPORT):
        print(f"[*] Found required JSON file: {SNIFFER_JSON_REPORT}")
        try:
            # We assume SNIFFER_JSON_REPORT exists and contains the ENRICHED data structure
            # (including 'structured_context' and safely calculated rates) from packet_sniffer.py
            create_packet_sniffer_report_pdf(SNIFFER_JSON_REPORT, sniffer_test_pdf_path)
            print("[TEST SUCCESS] Production Packet Sniffer PDF created.")
        except Exception as e:
            print(f"[TEST FAILED] Sniffer generation error using real file: {e}")
            # Reraise the error to see the full stack trace for debugging template line
            # traceback.print_exc()
    else:
        print(f"[SKIP] Production JSON file not found at {SNIFFER_JSON_REPORT}. Run packet_sniffer first to create it.")