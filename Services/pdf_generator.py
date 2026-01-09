import os
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML, CSS
import pathlib
import re

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


def create_nmap_report_pdf(source_data, pdf_path):
    """
    Renders Nmap data into an HTML template and saves it as a PDF.
    Designed to handle the specific NetShieldAI JSON structure.
    """
    print(f"[*] Starting Detailed PDF generation for Nmap Target: {pdf_path}")

    # 1. Handle Input
    if isinstance(source_data, str):
        if not os.path.exists(source_data):
            raise FileNotFoundError(f"Nmap JSON file not found: {source_data}")
        with open(source_data, 'r', encoding='utf-8') as f:
            nmap_data = json.load(f)
    else:
        nmap_data = source_data

    # 2. Advanced Data Preparation
    ports_list = nmap_data.get("ports", [])
    open_count = sum(1 for p in ports_list if p.get('state') == 'open')
    
    duration = "N/A"
    raw_summary = nmap_data.get("raw_output_summary", "")
    if "scanned in" in raw_summary:
        duration = raw_summary.split("scanned in")[-1].strip()

    # 3. Comprehensive Template Context
    template_data = {
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
        "raw_summary": raw_summary
    }

    # 4. Resource Validation
    css = CSS(filename=CSS_FILE_PATH) if os.path.exists(CSS_FILE_PATH) else None

    # 5. Render using Jinja2
    try:
        env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
        template = env.get_template(NMAP_TEMPLATE_FILE)
        # FIX: Pass as data=template_data to match your HTML template
        rendered_html = template.render(data=template_data)
    except Exception as e:
        raise RuntimeError(f"Failed to render Nmap HTML: {e}")

    # 6. Generate PDF with WeasyPrint
    base_url = pathlib.Path(PROJECT_ROOT).as_uri()
    html = HTML(string=rendered_html, base_url=base_url)
    html.write_pdf(pdf_path, stylesheets=[css] if css else [])

    print(f"[+] Nmap PDF Report generated: {pdf_path}")
    return True

def create_zap_report_pdf(source_data, pdf_path):
    """
    Renders ZAP Web Vulnerability data into an HTML template and saves it as a PDF.
    """
    print(f"[*] Starting WeasyPrint PDF generation for ZAP: {pdf_path}")

    if isinstance(source_data, str):
        with open(source_data, 'r', encoding='utf-8') as f:
            zap_data = json.load(f)
    else:
        zap_data = source_data

    findings = zap_data.get("findings", [])
    risk_priority = {"High": 4, "Medium": 3, "Low": 2, "Informational": 1, "Info": 1}
    sorted_findings = sorted(findings, key=lambda x: risk_priority.get(x.get("risk"), 0), reverse=True)

    template_data = {
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
    print(f"[+] ZAP PDF report saved successfully to: {pdf_path}")
    return True

def create_ssl_report_pdf(source_data, pdf_path):
    """
    Renders SSL Scan data into an HTML template and saves it as a PDF.
    Captures all fields including Client CAs, full Cert Chain, and detailed Configs.
    """
    print(f"[*] Starting SSL PDF generation for target: {pdf_path}")

    # 1. Load data
    if isinstance(source_data, str):
        try:
            with open(source_data, 'r', encoding='utf-8') as f:
                ssl_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[!] Error loading JSON source: {e}")
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
    template_data = {
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
        print(f"[!] Template Rendering Error: {e}")
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
            print(f"[!] Warning: CSS file not found at {CSS_FILE_PATH}")
            
        html_obj.write_pdf(pdf_path, stylesheets=stylesheets)
        print(f"[+] SSL PDF report saved successfully to: {pdf_path}")
        return True
    except Exception as e:
        print(f"[!] FAILED to generate PDF: {e}")
        return False

def create_packet_sniffer_report_pdf(source_data, pdf_path):
    """
    Renders Packet Sniffer (TShark) data into a condensed PDF report.
    Parses raw TShark strings into structured data for tables.
    """
    print(f"[*] Starting Condensed PDF generation for Packet Sniffer...")

    if isinstance(source_data, str):
        with open(source_data, 'r', encoding='utf-8') as f:
            sniffer_data = json.load(f)
    else:
        sniffer_data = source_data

    traffic = sniffer_data.get("traffic_summary", {})
    anomalies = sniffer_data.get("security_anomaly_report", {})
    
    # --- FIX 1: PARSE PROTOCOL HIERARCHY ---
    # Raw Input: "  ip    frames:111 bytes:41883"
    # Output: {'proto': 'ip', 'frames': 111, 'bytes': 41883}
    proto_raw = traffic.get("protocol_hierarchy_stats", [])
    parsed_hierarchy = []
    
    for line in proto_raw:
        # Regex to capture: (Protocol Name) (frames:Numbers) (bytes:Numbers)
        # Handles indentation and variable whitespace
        match = re.search(r"^\s*([a-z0-9\._-]+)\s+frames:(\d+)\s+bytes:(\d+)", line.strip())
        if match:
            parsed_hierarchy.append({
                "proto": match.group(1),
                "frames": int(match.group(2)),
                "bytes": int(match.group(3))
            })
    
    # If regex failed (fallback), just pass raw lines to avoid empty table
    if not parsed_hierarchy and proto_raw:
        # Create dummy dicts to prevent template crash
        parsed_hierarchy = [{"proto": line, "frames": "-", "bytes": "-"} for line in proto_raw]

    # --- FIX 2: PARSE TCP CONVERSATIONS ---
    # Raw Input: "192.168.29.48:45143 <-> 192.168.29.196:8009      38 18 kB      25 2545 bytes..."
    tcp_raw = traffic.get("tcp_conversation_stats", [])
    parsed_conversations = []
    
    for line in tcp_raw:
        if "<->" in line:
            parts = line.split("<->")
            if len(parts) >= 2:
                src = parts[0].strip()
                # The right side contains the IP and the stats. We split by space to get just the IP.
                dst_parts = parts[1].strip().split()
                dst = dst_parts[0] if dst_parts else "Unknown"
                
                parsed_conversations.append({
                    "src": src,
                    "dst": dst
                })

    # --- FIX 3: FLATTEN PACKET SAMPLES ---
    # Extracts deep JSON keys into a flat dict for the HTML table
    raw_packets = sniffer_data.get("dissected_packets", [])[:15] # Grab top 15
    processed_packets = []
    
    for p in raw_packets:
        layers = p.get("_source", {}).get("layers", {})
        
        # Get Protocol (safely)
        raw_proto = layers.get("frame", {}).get("frame.protocols", "Unknown")
        # "eth:ip:tcp" -> "TCP"
        short_proto = raw_proto.split(":")[-1].upper() if ":" in raw_proto else raw_proto.upper()

        p_info = {
            "time": layers.get("frame", {}).get("frame.time_relative", "0.00"),
            "protocol": short_proto,
            "len": layers.get("frame", {}).get("frame.len", "0"),
            "src": "N/A",
            "dst": "N/A"
        }

        # Address extraction logic (IP > IPv6 > Eth)
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

    template_data = {
        "target_ip": sniffer_data.get("target_ip", "Unknown"),
        "timestamp": sniffer_data.get("timestamp"),
        "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "metrics": {
            "total_packets": traffic.get("total_packets", 0),
            "total_bytes": f"{traffic.get('total_bytes', 0) / 1024:.2f} KB",
            "duration": f"{traffic.get('effective_capture_duration_seconds', 0)}s",
            "avg_rate": f"{traffic.get('average_rate_bps', 0):.2f} bps"
        },
        # Pass the PARSED data structure
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
        print(f"[+] Condensed Sniffer Report saved: {pdf_path}")
        return True
    except Exception as e:
        print(f"[!] PDF Generation Error: {e}")
        return False

def create_killchain_report_pdf(source_data, pdf_path):
    """
    Renders the Full-Spectrum Kill Chain Report aligned to the NetShieldAI JSON structure.
    """
    print(f"[*] Starting Master Kill Chain PDF generation: {pdf_path}")

    # 1. Data Loading
    if isinstance(source_data, str):
        try:
            with open(source_data, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            print(f"[!] Error loading JSON file: {e}")
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
    template_data = {
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
        
        print(f"[+] Master Kill Chain Report successfully generated at: {pdf_path}")
        return True
        
    except Exception as e:
        print(f"[!] Error generating Master Report: {e}")
        import traceback
        traceback.print_exc() # Helpful for debugging template errors
        return False
    
    
def create_sql_report_pdf(source_data, pdf_path):
    """
    Renders SQLMap Scan data into an HTML template and saves it as a PDF.
    Optimized for specific JSON structure: extracts DB version, user, and groups vulns.
    """
    print(f"[*] Starting SQL Injection PDF generation: {pdf_path}")

    # 1. Load Data
    if isinstance(source_data, str):
        if not os.path.exists(source_data):
            print(f"[!] JSON source not found: {source_data}")
            return False
        try:
            with open(source_data, 'r', encoding='utf-8') as f:
                sql_data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[!] Invalid JSON format: {e}")
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
    template_data = {
        "meta": {
            "target": sql_data.get("target", "Unknown Target"),
            "scan_time": sql_data.get("scan_time", "N/A"),
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },

        # Database Fingerprint - Directly mapped from your JSON structure
        "db_info": {
            "dbms": db_info.get("dbms", "Not Detected"),
            "version": db_info.get("version", "Not Detected"),
            "user": db_info.get("user", "Not Detected"),
            "current_db": db_info.get("current_db", "Not Detected")
        },

        # Findings
        "stats": {
            "total": stats["total_vulns"],
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
        print(f"[!] Error rendering SQL HTML template: {e}")
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
        
        print(f"[+] SQL PDF Report generated successfully: {pdf_path}")
        return True
    except Exception as e:
        print(f"[!] PDF Generation Failed: {e}")
        return False