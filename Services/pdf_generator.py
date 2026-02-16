import os
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML, CSS
import pathlib
import re
from Services.network_scanner import log

# --- Path Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
TEMPLATE_DIR = os.path.join(BASE_DIR, 'PDF_templates')
CSS_FILE_PATH = os.path.join(PROJECT_ROOT, 'static', 'css', 'PDF_style', 'report_style.css')

# --- Template File Names ---
ZAP_TEMPLATE_FILE = "zap_report_template.html"
NMAP_TEMPLATE_FILE = "nmap_report_template.html"
SSL_TEMPLATE_FILE = "ssl_report_template.html"
SNIFFER_TEMPLATE_FILE = "sniffer_report_template.html"
KILLCHAIN_TEMPLATE_FILE = "killchain_report_template.html"
SQL_TEMPLATE_FILE = "sql_report_template.html"
SEMGREP_TEMPLATE_FILE = "semgrep_report_template.html"


def create_nmap_report_pdf(source_data, pdf_path):
    """
    Renders Nmap data into an HTML template and saves it as a PDF.
    Designed to handle the specific NetShieldAI JSON structure.
    """
    # Import log locally to avoid circular import issues if placed at top
    from Services.network_scanner import log 

    log(f"[*] Starting Detailed PDF generation for Nmap Target: {pdf_path}", to_console=True)

    # 1. Handle Input
    if isinstance(source_data, str):
        if not os.path.exists(source_data):
            log(f"[!] Error: Nmap JSON file not found at {source_data}")
            return False
        with open(source_data, 'r', encoding='utf-8') as f:
            nmap_data = json.load(f)
    else:
        nmap_data = source_data

    # 2. Advanced Data Preparation
    ports_list = nmap_data.get("ports", [])
    open_count = sum(1 for p in ports_list if p.get('state') == 'open')
    
    # Check if any port has vulnerability notes
    has_vulns = any(len(p.get('vulnerability_notes', '')) > 0 for p in ports_list)

    duration = "N/A"
    raw_summary = nmap_data.get("raw_output_summary", "")
    if "scanned in" in raw_summary:
        try:
            duration = raw_summary.split("scanned in")[-1].strip()
        except:
            pass

    # 3. Comprehensive Template Context
    logo_path = os.path.join(PROJECT_ROOT, 'static', 'images', 'NetShieldAI_logo_PDF.png')
    footer_logo_path = os.path.join(PROJECT_ROOT, 'static', 'images', 'NS_Logo_pdf.png')

    template_data = {
        "logo_url": pathlib.Path(logo_path).as_uri(),
        "logo_url_small": pathlib.Path(footer_logo_path).as_uri(),
        "scan_date": nmap_data.get("scan_date"),
        "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_args": nmap_data.get("scan_args"),
        "target_ip": nmap_data.get("target_ip"),
        "host_status": nmap_data.get("host_status", "Unknown"),
        "os_guess": nmap_data.get("os_guess", "Unknown"),
        "stats": {
            "total_ports_found": len(ports_list),
            "open_ports": open_count,
            "scan_duration": duration
        },
        "ports": ports_list,
        "raw_summary": raw_summary,
        "has_vulns": has_vulns  # It is defined here in the dictionary
    }

    # 4. Resource Validation
    css = None
    if os.path.exists(CSS_FILE_PATH):
        css = CSS(filename=CSS_FILE_PATH)
    else:
        log(f"[!] Warning: CSS file not found at {CSS_FILE_PATH}. PDF will be unstyled.")

    # 5. Render using Jinja2
    try:
        env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
        template = env.get_template(NMAP_TEMPLATE_FILE)
        
        # --- FIX IS HERE ---
        # We removed 'has_vulns=has_vulns' because it is already in **template_data
        rendered_html = template.render(
            data=template_data,       
            **template_data           
        )
    except Exception as e:
        log(f"[!] PDF Template Error: {e}")
        raise e 

    # 6. Generate PDF with WeasyPrint
    try:
        base_url = pathlib.Path(PROJECT_ROOT).as_uri()
        html = HTML(string=rendered_html, base_url=base_url)
        html.write_pdf(pdf_path, stylesheets=[css] if css else [])
        
        log(f"[+] Nmap PDF Report generated: {pdf_path}", to_console=True)
        return True
    except Exception as e:
        log(f"[!] WeasyPrint PDF Generation Error: {e}")
        if "dlopen" in str(e) or "dll" in str(e).lower():
            log(f"[HINT] This is likely a missing GTK3 dependency. Please install GTK3 for Windows.")
        raise e
    
def create_zap_report_pdf(source_data, pdf_path):
    """
    Renders ZAP Web Vulnerability data into an HTML template and saves it as a PDF.
    """
    log(f"[*] Starting WeasyPrint PDF generation for ZAP: {pdf_path}", to_console=True)

    if isinstance(source_data, str):
        with open(source_data, 'r', encoding='utf-8') as f:
            zap_data = json.load(f)
    else:
        zap_data = source_data

    findings = zap_data.get("findings", [])
    risk_priority = {"High": 4, "Medium": 3, "Low": 2, "Informational": 1, "Info": 1}
    sorted_findings = sorted(findings, key=lambda x: risk_priority.get(x.get("risk"), 0), reverse=True)

    logo_path = os.path.join(PROJECT_ROOT, 'static', 'images', 'NetShieldAI_logo_PDF.png')
    footer_logo_path = os.path.join(PROJECT_ROOT, 'static', 'images', 'NS_Logo_pdf.png')

    template_data = {
        "logo_url": pathlib.Path(logo_path).as_uri(),
        "logo_url_small": pathlib.Path(footer_logo_path).as_uri(),
        "target_url": zap_data.get("target_url"),
        "scan_date": zap_data.get("scan_date"),
        "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": zap_data.get("summary", {}),
        "findings": sorted_findings,
        "risk_classes": {"High": "danger", "Medium": "warning", "Low": "info", "Informational": "secondary"}
    }

    css = CSS(filename=CSS_FILE_PATH) if os.path.exists(CSS_FILE_PATH) else None
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    
    try:
        template = env.get_template(ZAP_TEMPLATE_FILE)
        # FIX: Pass as data=template_data
        rendered_html = template.render(data=template_data)
    except Exception as e:
        raise RuntimeError(f"Error rendering ZAP template: {e}")

    base_url = pathlib.Path(PROJECT_ROOT).as_uri()
    HTML(string=rendered_html, base_url=base_url).write_pdf(pdf_path, stylesheets=[css] if css else [])
    log(f"[+] ZAP PDF report saved successfully to: {pdf_path}", to_console=True)
    return True

def create_ssl_report_pdf(source_data, pdf_path):
    """
    Renders SSL Scan data into an HTML template and saves it as a PDF.
    Captures all fields including Client CAs, full Cert Chain, and detailed Configs.
    """
    log(f"[*] Starting SSL PDF generation for target: {pdf_path}", to_console=True)

    # 1. Load data
    if isinstance(source_data, str):
        try:
            with open(source_data, 'r', encoding='utf-8') as f:
                ssl_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            log(f"[!] Error loading JSON source: {e}")
            return False
    else:
        ssl_data = source_data

    # --- Helper: Date Formatter for Certificates ---
    def format_cert_date(date_str):
        """Converts 'Dec 3 15:49:27 2025 GMT' to '2025-12-03'."""
        try:
            # Adjust format string matches your JSON output specifically
            dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y GMT")
            return dt.strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            return date_str  # Return original if parsing fails

    # 2. Process Vulnerabilities
    vulns = ssl_data.get("vulnerabilities", [])
    severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for v in vulns:
        sev = v.get("severity", "Info")
        # Normalize casing (e.g. "medium" -> "Medium")
        sev = sev.capitalize()
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            # Handle unexpected severity labels safely
            severity_counts.setdefault(sev, 0)
            severity_counts[sev] += 1

    # 3. Group Ciphers by Protocol (and Sort by Strength)
    grouped_ciphers = {}
    raw_ciphers = ssl_data.get("ciphers", [])
    
    # Sort ciphers by bit strength (descending) before grouping
    # This ensures the report lists strongest ciphers first
    raw_ciphers.sort(key=lambda x: int(x.get("bits", 0)), reverse=True)

    for cipher in raw_ciphers:
        proto = cipher.get("protocol", "Unknown")
        if proto not in grouped_ciphers:
            grouped_ciphers[proto] = []
        grouped_ciphers[proto].append(cipher)

    # 4. Process FULL Certificate Chain
    # We create a cleaner list of dicts for the template to iterate over easily
    processed_chain = []
    raw_chain = ssl_data.get("certificate_chain", [])
    
    for cert in raw_chain:
        processed_chain.append({
            "level": cert.get("level", "N/A"), # leaf, intermediate, root
            "subject": cert.get("common_name", "N/A"),
            "issuer": cert.get("issuer", "N/A"),
            "algorithm": cert.get("signature_algorithm", "N/A"),
            "bits": cert.get("key_size", "N/A"),
            "key_type": cert.get("key_type", "N/A"),
            "not_before": format_cert_date(cert.get("not_before")),
            "not_after": format_cert_date(cert.get("not_after")),
            "alt_names": ", ".join(cert.get("alt_names", [])) if cert.get("alt_names") else "None"
        })

    # Extract Primary (Leaf) Cert for the Summary Header
    primary_cert = processed_chain[0] if processed_chain else {
        "subject": "N/A", "issuer": "N/A", "algorithm": "N/A", "bits": "N/A", "not_after": "N/A"
    }

    # 5. Extract Server Configs & Client CAs
    configs = ssl_data.get("server_configs", {})
    client_cas = ssl_data.get("client_cas", [])

    # 6. Prepare Template Data
    logo_path = os.path.join(PROJECT_ROOT, 'static', 'images', 'NetShieldAI_logo_PDF.png')
    footer_logo_path = os.path.join(PROJECT_ROOT, 'static', 'images', 'NS_Logo_pdf.png')

    template_data = {
        "logo_url": pathlib.Path(logo_path).as_uri(),
        "logo_url_small": pathlib.Path(footer_logo_path).as_uri(),
        # -- Target Info --
        "target": ssl_data.get("target", "Unknown Target"),
        "ip": ssl_data.get("ip", "N/A"),
        "port": ssl_data.get("port", "443"),
        "grade": ssl_data.get("grade", "N/A"), 
        "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

        # -- Configuration --
        "configs": configs,
        "tls_compression": configs.get("tls_compression", {}), # Explicit access
        "renegotiation": configs.get("renegotiation", {}),
        "ocsp_stapling": configs.get("ocsp_stapling", {}),     # Previously missing
        "fallback_scsv": configs.get("fallback_scsv_supported", "N/A"),

        # -- Protocols & Ciphers --
        "protocols": ssl_data.get("protocols", []),
        "grouped_ciphers": grouped_ciphers,
        "client_cas": client_cas, # Previously missing

        # -- Certificates --
        "cert": primary_cert,       # For summary view
        "certificates": processed_chain, # For detailed chain table

        # -- Vulnerabilities --
        "vulnerabilities": vulns,
        "severity_summary": severity_counts,
        "severity_map": {
            "High": "#ff4d4d", 
            "Medium": "#ffa500", 
            "Low": "#ffff00", 
            "Info": "#add8e6"
        }
    }

    # 7. Render HTML
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    try:
        template = env.get_template(SSL_TEMPLATE_FILE)
        rendered_html = template.render(data=template_data)
    except Exception as e:
        log(f"[!] Template Rendering Error: {e}")
        # Consider logging the full traceback here
        return False

    # 8. Generate PDF with WeasyPrint
    try:
        base_url = pathlib.Path(PROJECT_ROOT).as_uri()
        html_obj = HTML(string=rendered_html, base_url=base_url)
        
        stylesheets = []
        if os.path.exists(CSS_FILE_PATH):
            stylesheets.append(CSS(filename=CSS_FILE_PATH))
        else:
            log(f"[!] Warning: CSS file not found at {CSS_FILE_PATH}")
            
        html_obj.write_pdf(pdf_path, stylesheets=stylesheets)
        log(f"[+] SSL PDF report saved successfully to: {pdf_path}", to_console=True)
        return True
    except Exception as e:
        log(f"[!] FAILED to generate PDF: {e}")
        return False

def create_packet_sniffer_report_pdf(source_data, pdf_path):
    """
    Renders Packet Sniffer (TShark) data into a condensed PDF report.
    Parses raw TShark strings into structured data for tables.
    """
    log(f"[*] Starting Condensed PDF generation for Packet Sniffer...", to_console=True)

    if isinstance(source_data, str):
        with open(source_data, 'r', encoding='utf-8') as f:
            sniffer_data = json.load(f)
    else:
        sniffer_data = source_data

    traffic = sniffer_data.get("traffic_summary", {})
    anomalies = sniffer_data.get("security_anomaly_report", {})
    summary_io = traffic.get("summary_io", {})
    
    # --- FIX 1: PARSE PROTOCOL HIERARCHY ---
    # Raw Input: "  ip    frames:111 bytes:41883"
    proto_raw = traffic.get("protocol_distribution", [])
    parsed_hierarchy = []
    
    for line in proto_raw:
        match = re.search(r"^\s*([a-z0-9\._-]+)\s+frames:(\d+)\s+bytes:(\d+)", line.strip())
        if match:
            parsed_hierarchy.append({
                "proto": match.group(1),
                "frames": int(match.group(2)),
                "bytes": int(match.group(3))
            })
    
    if not parsed_hierarchy and proto_raw:
        parsed_hierarchy = [{"proto": line, "frames": "-", "bytes": "-"} for line in proto_raw if ":" in line]

    # --- FIX 2: PARSE TCP CONVERSATIONS ---
    tcp_raw = traffic.get("tcp_conversations", [])
    parsed_conversations = []
    
    for line in tcp_raw:
        if "<->" in line:
            parts = line.split("<->")
            if len(parts) >= 2:
                src = parts[0].strip()
                dst_parts = parts[1].strip().split()
                dst = dst_parts[0] if dst_parts else "Unknown"
                
                parsed_conversations.append({
                    "src": src,
                    "dst": dst
                })

    # --- FIX 3: FLATTEN PACKET SAMPLES ---
    raw_packets = sniffer_data.get("dissected_packets", [])[:15] 
    processed_packets = []
    
    for p in raw_packets:
        layers = p.get("_source", {}).get("layers", {})
        raw_proto = layers.get("frame", {}).get("frame.protocols", "Unknown")
        short_proto = raw_proto.split(":")[-1].upper() if ":" in raw_proto else raw_proto.upper()

        p_info = {
            "time": layers.get("frame", {}).get("frame.time_relative", "0.00"),
            "protocol": short_proto,
            "len": layers.get("frame", {}).get("frame.len", "0"),
            "src": "N/A",
            "dst": "N/A"
        }

        if "ip" in layers:
            p_info["src"] = layers["ip"].get("ip.src")
            p_info["dst"] = layers["ip"].get("ip.dst")
        elif "ipv6" in layers:
            p_info["src"] = layers["ipv6"].get("ipv6.src")
            p_info["dst"] = layers["ipv6"].get("ipv6.dst")
        elif "eth" in layers:
            p_info["src"] = layers["eth"].get("eth.src")
            p_info["dst"] = layers["eth"].get("eth.dst")

        processed_packets.append(p_info)

    logo_path = os.path.join(PROJECT_ROOT, 'static', 'images', 'NetShieldAI_logo_PDF.png')
    footer_logo_path = os.path.join(PROJECT_ROOT, 'static', 'images', 'NS_Logo_pdf.png')

    template_data = {
        "logo_url": pathlib.Path(logo_path).as_uri(),
        "logo_url_small": pathlib.Path(footer_logo_path).as_uri(),
        "target_ip": sniffer_data.get("target_ip", "Unknown"),
        "timestamp": sniffer_data.get("timestamp"),
        "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "metrics": {
            "total_packets": summary_io.get("total_packets", 0),
            "total_bytes": f"{summary_io.get('total_bytes', 0) / 1024:.2f} KB",
            "duration": f"{traffic.get('effective_capture_duration_seconds', 0)}s",
            "avg_rate": f"{traffic.get('average_rate_bps', 0):.2f} bps"
        },
        "hierarchy": parsed_hierarchy, 
        "tcp_conversations": parsed_conversations,
        "anomalies": anomalies.get("summary", "No anomalies detected."),
        "anomaly_details": {
            "scans": anomalies.get("port_scans", []),
            "creds": anomalies.get("cleartext_credentials", []),
            "web_attacks": anomalies.get("web_attacks", [])
        },
        "packet_samples": processed_packets
    }

    try:
        env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
        template = env.get_template(SNIFFER_TEMPLATE_FILE)
        rendered_html = template.render(data=template_data)
        
        base_url = pathlib.Path(PROJECT_ROOT).as_uri()
        stylesheets = [CSS(filename=CSS_FILE_PATH)] if os.path.exists(CSS_FILE_PATH) else []
        
        HTML(string=rendered_html, base_url=base_url).write_pdf(pdf_path, stylesheets=stylesheets)
        log(f"[+] Condensed Sniffer Report saved: {pdf_path}", to_console=True)
        return True
    except Exception as e:
        log(f"[!] PDF Generation Error: {e}")
        return False

def create_killchain_report_pdf(source_data, pdf_path):
    """
    Renders the Full-Spectrum Kill Chain Report aligned to the NetShieldAI JSON structure.
    """
    log(f"[*] Starting Master Kill Chain PDF generation: {pdf_path}", to_console=True)

    # 1. Data Loading
    if isinstance(source_data, str):
        try:
            with open(source_data, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            log(f"[!] Error loading JSON file: {e}")
            return False
    else:
        data = source_data

    # 2. Enhanced Stats Calculation
    # Uses 'vulns_grouped' from JSON to generate high-level stats for the dashboard
    grouped = data.get("vulns_grouped", {})
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    
    # Calculate counts with a default of 0 if the category is missing
    stats = {sev: len(grouped.get(sev, [])) for sev in severity_order}
    stats["Total"] = sum(stats.values())

    # 3. Technology Mapping
    # Updated to capture both 'technologies' (the stack) and 'versions' (specific version numbers)
    tech_node = data.get("tech", {})
    
    # 4. Comprehensive Template Context
    logo_path = os.path.join(PROJECT_ROOT, 'static', 'images', 'NetShieldAI_logo_PDF.png')
    footer_logo_path = os.path.join(PROJECT_ROOT, 'static', 'images', 'NS_Logo_pdf.png')

    template_data = {
        "logo_url": pathlib.Path(logo_path).as_uri(),
        "logo_url_small": pathlib.Path(footer_logo_path).as_uri(),
        # --- Metadata ---
        "target": data.get("target", "Unknown Target"),
        "profile": data.get("profile", "full_audit").replace("_", " ").title(),
        "scan_date": data.get("scan_date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "report_id": f"KC-{int(datetime.now().timestamp())}",
        
        # --- Phase 1: Recon & Discovery ---
        "recon": data.get("recon", {}),
        "urls_discovered": len(data.get("urls", [])),
        "raw_urls": data.get("urls", []), # List of strings from JSON
        
        # --- Phase 2: Network & Infrastructure ---
        "network": data.get("network", {}), # Contains status, ports (service/version), and network vulns
        "traffic": data.get("traffic_analysis", {}), # Stats, anomalies, credentials
        
        # --- Phase 3: Tech Stack & Fingerprinting ---
        # Passing the full dictionaries so template can iterate over key/values
        "tech_stack": {
            "technologies": tech_node.get("technologies", {}),
            "versions": tech_node.get("versions", {}),
            "target_url": tech_node.get("target")
        },
        
        # --- Phase 4: Vulnerabilities (The "Kill Chain") ---
        "stats": stats,
        "grouped_findings": grouped, # The main categorized dictionary (Critical, High, etc.)
        "flat_findings": data.get("vulns", []), # The chronological flat list with timestamps
        
        # --- Phase 5: Tool Specifics (OWASP ZAP) ---
        "zap_report": {
            "meta": data.get("zap_report", {}).get("summary", {}), # High/Medium/Low counts specific to ZAP
            "info": {
                "tool": data.get("zap_report", {}).get("tool"),
                "scan_date": data.get("zap_report", {}).get("scan_date")
            },
            "findings": data.get("zap_report", {}).get("findings", []) # Detailed ZAP findings with solution/CWE
        }
    }

    # 5. PDF Rendering
    try:
        # Initialize Jinja2 Environment
        env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
        
        # Add custom filters if needed (e.g., for date formatting)
        # env.filters['datetime_format'] = some_filter_function
        
        template = env.get_template(KILLCHAIN_TEMPLATE_FILE)
        
        # Render HTML
        rendered_html = template.render(data=template_data)
        
        # Prepare WeasyPrint assets
        base_url = pathlib.Path(PROJECT_ROOT).as_uri()
        stylesheets = []
        if os.path.exists(CSS_FILE_PATH):
            stylesheets.append(CSS(filename=CSS_FILE_PATH))
        
        # Generate PDF
        HTML(string=rendered_html, base_url=base_url).write_pdf(
            pdf_path, 
            stylesheets=stylesheets
        )
        
        log(f"[+] Master Kill Chain Report successfully generated at: {pdf_path}", to_console=True)
        return True
        
    except Exception as e:
        log(f"[!] Error generating Master Report: {e}")
        return False
    
    
def create_sql_report_pdf(source_data, pdf_path):
    """
    Renders SQLMap Scan data into an HTML template and saves it as a PDF.
    Optimized for specific JSON structure: extracts DB version, user, and groups vulns.
    """
    log(f"[*] Starting SQL Injection PDF generation: {pdf_path}", to_console=True)

    # 1. Load Data
    if isinstance(source_data, str):
        if not os.path.exists(source_data):
            log(f"[!] JSON source not found: {source_data}")
            return False
        try:
            with open(source_data, 'r', encoding='utf-8') as f:
                sql_data = json.load(f)
        except json.JSONDecodeError as e:
            log(f"[!] Invalid JSON format: {e}")
            return False
    else:
        sql_data = source_data

    # 2. Extract & Organize Data
    # Use .get() safely to handle potential missing keys in the JSON
    raw_vulns = sql_data.get("vulnerabilities", [])
    db_info = sql_data.get("database_info", {})
    dumped_data = sql_data.get("dumped_data", [])

    # SORTING: Sort vulnerabilities by type so "boolean-based" and "error-based" 
    # appear in contiguous blocks in the PDF, rather than mixed.
    sorted_vulns = sorted(raw_vulns, key=lambda x: x.get("type", "Unknown"))

    # STATS: Calculate overview metrics
    stats = {
        "total_vulns": len(raw_vulns),
        "by_type": {},
        "unique_titles": set()
    }

    for v in raw_vulns:
        # Count occurences of specific types (e.g., "boolean-based blind")
        v_type = v.get("type", "Unknown")
        stats["by_type"][v_type] = stats["by_type"].get(v_type, 0) + 1
        
        # Track unique titles to differentiate between payload variations vs distinct flaws
        if "title" in v:
            stats["unique_titles"].add(v["title"])

    # 3. Prepare Template Context
    # Structure this to match the specific keys in your JSON (target, scan_time, db_info)
    logo_path = os.path.join(PROJECT_ROOT, 'static', 'images', 'NetShieldAI_logo_PDF.png')
    footer_logo_path = os.path.join(PROJECT_ROOT, 'static', 'images', 'NS_Logo_pdf.png')

    template_data = {
        "logo_url": pathlib.Path(logo_path).as_uri(),
        "logo_url_small": pathlib.Path(footer_logo_path).as_uri(),
        "target": sql_data.get("target", "Unknown Target"),
        "scan_time": sql_data.get("scan_time", "N/A"),
        "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

        # Database Fingerprint - Directly mapped from your JSON structure
        "db_info": {
            "dbms": db_info.get("dbms", "Not Detected"),
            "version": db_info.get("version", "Not Detected"),
            "user": db_info.get("user", "Not Detected"),
            "current_db": db_info.get("current_db", "Not Detected")
        },

        # Findings
        "stats": {
            "total_vulns": stats["total_vulns"],
            "types": stats["by_type"],
            "unique_issues": len(stats["unique_titles"])
        },
        "vulnerabilities": sorted_vulns, 
        
        # Exfiltrated Data (checking length to conditionally render section in HTML)
        "dumped_data": dumped_data,
        "has_dumped_data": len(dumped_data) > 0
    }

    # 4. Render HTML using Jinja2
    try:
        env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
        template = env.get_template(SQL_TEMPLATE_FILE)
        
        # Render with the organized context
        rendered_html = template.render(data=template_data)
    except Exception as e:
        log(f"[!] Error rendering SQL HTML template: {e}")
        return False

    # 5. Generate PDF with WeasyPrint
    try:
        base_url = pathlib.Path(PROJECT_ROOT).as_uri()
        
        stylesheets = []
        if os.path.exists(CSS_FILE_PATH):
            stylesheets.append(CSS(filename=CSS_FILE_PATH))
            
        HTML(string=rendered_html, base_url=base_url).write_pdf(
            pdf_path, 
            stylesheets=stylesheets
        )
        
        log(f"[+] SQL PDF Report generated successfully: {pdf_path}", to_console=True)
        return True
    except Exception as e:
        log(f"[!] PDF Generation Failed: {e}")
        return False
        
def create_semgrep_report_pdf(source_data, pdf_path):
    """
    Renders Semgrep SAST data into an HTML template and saves it as a PDF.
    Optimized for large reports: limits findings and truncates snippets.
    """
    log(f"[*] Starting Semgrep PDF generation: {pdf_path}", to_console=True)

    # 1. Load Data
    if isinstance(source_data, str):
        if not os.path.exists(source_data):
            log(f"[!] JSON source not found: {source_data}")
            return False
        try:
            with open(source_data, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            log(f"[!] Invalid JSON: {e}")
            return False
    else:
        data = source_data

    # 2. Path Cleaning, Sorting & Truncation
    findings = data.get("findings", [])
    
    # Sorting (Error -> Warning -> Info)
    severity_order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    findings.sort(key=lambda x: severity_order.get(x.get("severity", "INFO"), 3))

    # LIMIT: Only show top 200 findings in PDF to prevent massive files/hangs
    total_findings_count = len(findings)
    if len(findings) > 200:
        log(f"[*] Warning: Large report ({total_findings_count} findings). Truncating to 200 for PDF.")
        findings = findings[:200]

    for f in findings:
        # Clean Path
        full_path = f.get("path", "")
        if "source_code_temp" in full_path:
            clean_path = full_path.split("source_code_temp")[-1]
            f["display_path"] = clean_path.lstrip(os.sep).lstrip("/")
        else:
            f["display_path"] = os.path.basename(full_path)
            
        # TRUNCATE SNIPPET: Limit snippet size to prevent template bloating
        snippet = f.get("code_snippet", "")
        if len(snippet) > 1000:
            f["code_snippet"] = snippet[:1000] + "\n... [TRUNCATED FOR REPORT] ..."

    # 3. Prepare Template Context
    logo_path = os.path.join(PROJECT_ROOT, 'static', 'images', 'NetShieldAI_logo_PDF.png')
    footer_logo_path = os.path.join(PROJECT_ROOT, 'static', 'images', 'NS_Logo_pdf.png')
    
    template_data = {
        "scan_date": data.get("scan_date"),
        "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tool": data.get("tool", "Semgrep"),
        "logo_url": pathlib.Path(logo_path).as_uri(),
        "logo_url_small": pathlib.Path(footer_logo_path).as_uri(),
        "stats": {
            "total": total_findings_count,
            "severity_counts": data.get("severity_counts", {})
        },
        "findings": findings,
        "is_truncated": total_findings_count > 200
    }

    # 4. Render
    try:
        env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
        template = env.get_template(SEMGREP_TEMPLATE_FILE)
        rendered_html = template.render(data=template_data)
    except Exception as e:
        log(f"[!] Semgrep Template Rendering Error: {e}")
        return False

    # 5. Write PDF
    try:
        base_url = pathlib.Path(PROJECT_ROOT).as_uri()
        stylesheets = []
        if os.path.exists(CSS_FILE_PATH):
            stylesheets.append(CSS(filename=CSS_FILE_PATH))
            
        HTML(string=rendered_html, base_url=base_url).write_pdf(
            pdf_path, 
            stylesheets=stylesheets
        )
        log(f"[+] Semgrep PDF saved: {pdf_path}", to_console=True)
        return True
    except Exception as e:
        log(f"[!] PDF Write Error: {e}")
        return False