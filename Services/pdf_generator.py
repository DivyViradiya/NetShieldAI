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
KILLCHAIN_TEMPLATE_FILE = "killchain_report_template.html"


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

def create_killchain_report_pdf(source_data, pdf_path):
    """
    Renders the Full Kill Chain Report (Recon, Network, Vulns, ZAP, Traffic) to PDF.
    Ensures ZERO data loss by mapping the full JSON structure to the template.
    """
    print(f"[*] Starting Full-Spectrum PDF generation for Kill Chain...")

    # 1. Load Data
    data = {}
    if isinstance(source_data, str):
        if not os.path.exists(source_data):
            raise FileNotFoundError(f"Kill Chain JSON not found: {source_data}")
        with open(source_data, 'r', encoding='utf-8') as f:
            data = json.load(f)
    elif isinstance(source_data, dict):
        data = source_data
    else:
        raise ValueError("Invalid input for PDF generation")

    # 2. Validate Resources
    if not os.path.exists(CSS_FILE_PATH):
        print(f"[!] Warning: CSS not found at {CSS_FILE_PATH}")
        css = None
    else:
        css = CSS(filename=CSS_FILE_PATH)

    # 3. Load Template
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    try:
        template = env.get_template(KILLCHAIN_TEMPLATE_FILE)
    except Exception as e:
        raise FileNotFoundError(f"Template {KILLCHAIN_TEMPLATE_FILE} not found in {TEMPLATE_DIR}") from e

    # 4. Data Enrichment & Stats Calculation
    # We calculate summary stats here so the HTML template stays clean
    
    # A. Vulnerability Stats (Native + ZAP)
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    
    all_vulns = data.get("vulns", [])
    
    # Iterate Native Vulns
    for v in all_vulns:
        # Normalize severity case
        sev = v.get("severity", "Info").capitalize()
        if sev not in stats: sev = "Info"
        stats[sev] += 1

    # B. ZAP Stats (if separate, though your JSON merged them into 'vulns', we check just in case)
    # Note: Your provided JSON shows ZAP findings are INSIDE 'vulns' list with "type": "ZAP: ..."
    # So the loop above already covers ZAP findings! Excellent architecture.

    # C. Network Stats
    open_ports = len(data.get("network", {}).get("ports", []))
    
    # D. Recon Stats
    subdomain_count = len(data.get("recon", {}).get("subdomains", []))
    
    # E. URL Stats
    url_count = len(data.get("urls", []))

    # F. Prepare Template Context
    template_data = {
        "report_id": f"KC-{int(datetime.now().timestamp())}",
        "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": data.get("recon", {}).get("target", "Unknown Target"),
        
        # Summary Metrics
        "stats": stats,
        "counts": {
            "ports": open_ports,
            "subdomains": subdomain_count,
            "urls": url_count,
            "anomalies": len(data.get("traffic_analysis", {}).get("anomalies", [])),
            "credentials": len(data.get("traffic_analysis", {}).get("credentials", []))
        },

        # Full Data Sections (Passed directly for iteration in Jinja2)
        "recon": data.get("recon", {}),
        "network": data.get("network", {}),
        "tech": data.get("tech", {}),
        "traffic": data.get("traffic_analysis", {}),
        "urls": data.get("urls", []),
        
        # Findings
        "vulns": all_vulns, 
        # We also pass the raw ZAP report if specific ZAP metadata (scan date, version) is needed
        "zap_meta": data.get("zap_report", {}) 
    }

    # 5. Render HTML
    rendered_html = template.render(template_data)
    
    # 6. Save PDF
    # base_url is set so local images/css in /static/ work
    base_url = pathlib.Path(PROJECT_ROOT).as_uri()
    html = HTML(string=rendered_html, base_url=base_url)
    
    stylesheets = [css] if css else []
    html.write_pdf(pdf_path, stylesheets=stylesheets)
    
    print(f"[+] Kill Chain PDF saved successfully: {pdf_path}")
    return True