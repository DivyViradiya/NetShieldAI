import os
import pathlib
import sys
import json
import logging
import time
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from core.time_utils import get_now_ist, get_now_ist_str
import contextlib

# --- Suppress GLib/GIO Warnings (Windows) during WeasyPrint Import ---
@contextlib.contextmanager
def suppress_stderr():
    """
    Suppresses stderr at the OS level (file descriptor 2).
    Need to flush Python's sys.stderr first to avoid mixed output.
    """
    old_stderr_fd = None
    devnull = None
    try:
        sys.stderr.flush()
        devnull = open(os.devnull, "w")
        old_stderr_fd = os.dup(sys.stderr.fileno())
        os.dup2(devnull.fileno(), sys.stderr.fileno())
    except Exception:
        pass

    try:
        yield
    finally:
        if old_stderr_fd is not None:
            try:
                os.dup2(old_stderr_fd, sys.stderr.fileno())
                os.close(old_stderr_fd)
            except:
                pass
        if devnull is not None:
            devnull.close()

with suppress_stderr():
    from weasyprint import HTML, CSS

import pathlib
import re
from Services import scan_logger
from core.logger_setup import logger

def log(message, user_id=None, queue_id=None, to_console=False, level='INFO', scanner_name="pdf_generator"):
    if to_console:
        if level.upper() == 'ERROR' or level.upper() == 'CRITICAL':
            logger.error(message)
        elif level.upper() == 'WARNING':
            logger.warning(message)
        else:
            logger.info(message)
    if user_id:
        scan_logger.write_log(user_id, scanner_name, message, level=level)

# --- Suppress Noisy Logs ---
logging.getLogger('weasyprint').setLevel(logging.ERROR)
logging.getLogger('fontTools').setLevel(logging.ERROR)
logging.getLogger('fontTools.subset').setLevel(logging.ERROR)
logging.getLogger('fontTools.ttLib').setLevel(logging.ERROR)
logging.getLogger('fontTools.ttLib.tables').setLevel(logging.ERROR)
logging.getLogger('fontTools.otlLib').setLevel(logging.ERROR)
logging.getLogger('fontTools.varLib').setLevel(logging.ERROR)
logging.getLogger('PIL').setLevel(logging.ERROR)
logging.getLogger('urllib3').setLevel(logging.ERROR)

# --- Path Configuration ---
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
TEMPLATE_DIR = os.path.join(BASE_DIR, 'PDF_templates')
CSS_DIR      = os.path.join(PROJECT_ROOT, 'static', 'css', 'PDF_style')

# --- CSS Files ---
CSS_BASE      = os.path.join(CSS_DIR, 'report_base.css')
CSS_NMAP      = os.path.join(CSS_DIR, 'report_nmap.css')
CSS_ZAP       = os.path.join(CSS_DIR, 'report_zap.css')
CSS_SSL       = os.path.join(CSS_DIR, 'report_ssl.css')
CSS_SNIFFER   = os.path.join(CSS_DIR, 'report_sniffer.css')
CSS_KILLCHAIN = os.path.join(CSS_DIR, 'report_killchain.css')
CSS_SQL       = os.path.join(CSS_DIR, 'report_sql.css')
CSS_SEMGREP   = os.path.join(CSS_DIR, 'report_semgrep.css')
CSS_API       = os.path.join(CSS_DIR, 'report_api.css')
CSS_EXECUTIVE = os.path.join(CSS_DIR, 'report_executive.css')
CSS_ASSET_DISCOVERY = os.path.join(CSS_DIR, 'report_asset_discovery.css')

# --- [SECURITY] Shared Jinja2 Environment with autoescape enabled ---
jinja_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=True  # CRITICAL: Prevent SSTI/XSS
)

# --- Template File Names ---
ZAP_TEMPLATE_FILE               = "zap_report_template.html"
NMAP_TEMPLATE_FILE              = "nmap_report_template.html"
SSL_TEMPLATE_FILE               = "ssl_report_template.html"
SNIFFER_TEMPLATE_FILE           = "sniffer_report_template.html"
KILLCHAIN_TEMPLATE_FILE         = "killchain_report_template.html"
SQL_TEMPLATE_FILE               = "sql_report_template.html"
SEMGREP_TEMPLATE_FILE           = "semgrep_report_template.html"
EXECUTIVE_SUMMARY_TEMPLATE_FILE = "executive_summary_template.html"
API_TEMPLATE_FILE               = "api_report_template.html"
ASSET_DISCOVERY_TEMPLATE_FILE     = "asset_discovery_report_template.html"


# =============================================================================
# SHARED HELPERS
# =============================================================================

def _logo_paths():
    """Returns (logo_url, footer_logo_url) as file:// URI strings."""
    logo        = os.path.join(PROJECT_ROOT, 'static', 'images', 'NetShieldAI_logo_PDF.png')
    footer_logo = os.path.join(PROJECT_ROOT, 'static', 'images', 'NS_Logo_pdf.png')
    return pathlib.Path(logo).as_uri(), pathlib.Path(footer_logo).as_uri()


def _build_stylesheets(*css_paths):
    """
    Loads WeasyPrint CSS objects from a list of file paths.
    Skips missing files and logs a warning for each.
    Always pass base CSS first, then template-specific CSS.
    """
    sheets = []
    for path in css_paths:
        if os.path.exists(path):
            sheets.append(CSS(filename=path))
        else:
            log(f"[!] CSS not found, skipping: {path}")
    return sheets


def _render_to_pdf(template_name, template_data, pdf_path,
                   css_paths, scanner_name="pdf_generator", user_id=None):
    """
    Shared render pipeline: Jinja2 template → HTML string → WeasyPrint PDF.
    Returns True on success, False on any failure.
    """
    # Step 1 — Render HTML
    try:
        template     = jinja_env.get_template(template_name)
        rendered_html = template.render(data=template_data)
    except Exception as e:
        log(f"[!] Template render error [{template_name}]: {e}",
            to_console=True, scanner_name=scanner_name, user_id=user_id)
        return False

    # Step 2 — Write PDF
    try:
        base_url    = pathlib.Path(PROJECT_ROOT).as_uri()
        stylesheets = _build_stylesheets(*css_paths)
        HTML(string=rendered_html, base_url=base_url).write_pdf(
            pdf_path, stylesheets=stylesheets
        )
        return True
    except Exception as e:
        log(f"[!] PDF write error [{template_name}]: {e}",
            to_console=True, scanner_name=scanner_name, user_id=user_id)
        if "dlopen" in str(e) or "dll" in str(e).lower():
            log("[HINT] Likely a missing GTK3 dependency. Install GTK3 for Windows.",
                user_id=user_id)
        return False


# =============================================================================
# REPORT GENERATORS
# =============================================================================

def create_nmap_report_pdf(source_data, pdf_path, user_id=None):
    """
    Renders Nmap scan data into an HTML template and saves it as a PDF.
    """
    log(f"[*] Starting Nmap PDF generation: {pdf_path}",
        to_console=True, scanner_name="nmap_scanner", user_id=user_id)

    # 1. Load data
    if isinstance(source_data, str):
        if not os.path.exists(source_data):
            log(f"[!] Nmap JSON not found: {source_data}", user_id=user_id)
            return False
        with open(source_data, 'r', encoding='utf-8') as f:
            nmap_data = json.load(f)
    else:
        nmap_data = source_data

    # 2. Derived values & Sorting
    ports_list = nmap_data.get("ports", [])
    
    # Sort ports by risk score descending (High risk first)
    ports_list = sorted(
        ports_list, 
        key=lambda x: x.get("predicted_risk_score", 0), 
        reverse=True
    )
    
    open_count = sum(1 for p in ports_list if p.get('state') == 'open')
    has_vulns  = any(len(p.get('vulnerability_notes', '')) > 0 for p in ports_list) or any(p.get('predicted_risk_score', 0) > 0.5 for p in ports_list)

    duration    = "N/A"
    raw_summary = nmap_data.get("raw_output_summary", "")
    if "scanned in" in raw_summary:
        try:
            duration = raw_summary.split("scanned in")[-1].strip()
        except Exception:
            pass

    # 3. Build context
    logo_url, logo_url_small = _logo_paths()
    template_data = {
        "logo_url":        logo_url,
        "logo_url_small":  logo_url_small,
        "css_path":        pathlib.Path(CSS_BASE).as_uri(),
        "scan_date":       nmap_data.get("scan_date"),
        "generation_date": get_now_ist().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_args":       nmap_data.get("scan_args"),
        "target_ip":       nmap_data.get("target_ip"),
        "host_status":     nmap_data.get("host_status", "Unknown"),
        "os_guess":        nmap_data.get("os_guess", "Unknown"),
        "stats": {
            "total_ports_found": len(ports_list),
            "open_ports":        open_count,
            "scan_duration":     duration,
        },
        "ports":       ports_list,
        "raw_summary": raw_summary,
        "has_vulns":   has_vulns,
    }

    # 4. Render
    success = _render_to_pdf(
        NMAP_TEMPLATE_FILE, template_data, pdf_path,
        [CSS_BASE, CSS_NMAP], "nmap_scanner", user_id
    )
    if success:
        log(f"[+] Nmap PDF generated: {pdf_path}",
            to_console=True, scanner_name="nmap_scanner", user_id=user_id)
    return success


def create_zap_report_pdf(source_data, pdf_path, user_id=None):
    """
    Renders ZAP web vulnerability data into an HTML template and saves it as a PDF.
    """
    log(f"[*] Starting ZAP PDF generation: {pdf_path}",
        to_console=True, scanner_name="zap_scanner", user_id=user_id)

    # 1. Load data
    if isinstance(source_data, str):
        with open(source_data, 'r', encoding='utf-8') as f:
            zap_data = json.load(f)
    else:
        zap_data = source_data

    # 2. Sort findings by risk priority
    risk_priority   = {"High": 4, "Medium": 3, "Low": 2, "Informational": 1, "Info": 1}
    sorted_findings = sorted(
        zap_data.get("findings", []),
        key=lambda x: risk_priority.get(x.get("risk"), 0),
        reverse=True
    )

    # 3. Build context
    logo_url, logo_url_small = _logo_paths()
    template_data = {
        "logo_url":        logo_url,
        "logo_url_small":  logo_url_small,
        "css_path":        pathlib.Path(CSS_BASE).as_uri(),
        "target_url":      zap_data.get("target_url"),
        "scan_mode":       zap_data.get("scan_mode"),
        "use_ajax":        zap_data.get("use_ajax"),
        "scan_date":       zap_data.get("scan_date"),
        "generation_date": get_now_ist().strftime("%Y-%m-%d %H:%M:%S"),
        "summary":         zap_data.get("summary", {}),
        "findings":        sorted_findings,
        "risk_classes":    {
            "High": "danger", "Medium": "warning",
            "Low": "info", "Informational": "secondary"
        },
    }

    # 4. Render
    success = _render_to_pdf(
        ZAP_TEMPLATE_FILE, template_data, pdf_path,
        [CSS_BASE, CSS_ZAP], "zap_scanner", user_id
    )
    if success:
        log(f"[+] ZAP PDF generated: {pdf_path}",
            to_console=True, scanner_name="zap_scanner", user_id=user_id)
    return success


def create_ssl_report_pdf(source_data, pdf_path, user_id=None):
    """
    Renders SSL/TLS scan data into an HTML template and saves it as a PDF.
    Captures full certificate chain, cipher suites, and server configuration.
    """
    log(f"[*] Starting SSL PDF generation: {pdf_path}",
        to_console=True, scanner_name="ssl_scanner", user_id=user_id)

    # 1. Load data
    if isinstance(source_data, str):
        try:
            with open(source_data, 'r', encoding='utf-8') as f:
                ssl_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            log(f"[!] Error loading SSL JSON: {e}", scanner_name="ssl_scanner")
            return False
    else:
        ssl_data = source_data

    # 2. Certificate date formatter
    def format_cert_date(date_str):
        """Converts 'Dec 3 15:49:27 2025 GMT' → '2025-12-03'."""
        try:
            dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y GMT")
            return dt.strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            return date_str

    # 3. Process vulnerabilities
    vulns          = ssl_data.get("vulnerabilities", [])
    severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for v in vulns:
        sev = v.get("severity", "Info").capitalize()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # 4. Group ciphers by protocol, sorted by strength
    grouped_ciphers = {}
    raw_ciphers     = ssl_data.get("ciphers", [])
    raw_ciphers.sort(key=lambda x: int(x.get("bits", 0)), reverse=True)
    for cipher in raw_ciphers:
        proto = cipher.get("protocol", "Unknown")
        grouped_ciphers.setdefault(proto, []).append(cipher)

    # 5. Process certificate chain
    processed_chain = []
    for cert in ssl_data.get("certificate_chain", []):
        processed_chain.append({
            "level":     cert.get("level", "N/A"),
            "subject":   cert.get("common_name", "N/A"),
            "issuer":    cert.get("issuer", "N/A"),
            "algorithm": cert.get("signature_algorithm", "N/A"),
            "bits":      cert.get("key_size", "N/A"),
            "key_type":  cert.get("key_type", "N/A"),
            "not_before": format_cert_date(cert.get("not_before")),
            "not_after":  format_cert_date(cert.get("not_after")),
            "alt_names":  ", ".join(cert.get("alt_names", [])) if cert.get("alt_names") else "None",
        })

    primary_cert = processed_chain[0] if processed_chain else {
        "subject": "N/A", "issuer": "N/A", "algorithm": "N/A",
        "bits": "N/A", "not_after": "N/A"
    }

    # 6. Server configs
    configs    = ssl_data.get("server_configs", {})
    client_cas = ssl_data.get("client_cas", [])

    # 7. Build context
    logo_url, logo_url_small = _logo_paths()
    template_data = {
        "logo_url":        logo_url,
        "logo_url_small":  logo_url_small,
        "css_path":        pathlib.Path(CSS_BASE).as_uri(),
        "target":          ssl_data.get("target", "Unknown Target"),
        "ip":              ssl_data.get("ip", "N/A"),
        "port":            ssl_data.get("port", "443"),
        "grade":           ssl_data.get("grade", "N/A"),
        "generation_date": get_now_ist().strftime("%Y-%m-%d %H:%M:%S"),
        "configs":         configs,
        "tls_compression": configs.get("tls_compression", {}),
        "renegotiation":   configs.get("renegotiation", {}),
        "ocsp_stapling":   configs.get("ocsp_stapling", {}),
        "fallback_scsv":   configs.get("fallback_scsv_supported", "N/A"),
        "protocols":       ssl_data.get("protocols", []),
        "grouped_ciphers": grouped_ciphers,
        "client_cas":      client_cas,
        "cert":            primary_cert,
        "certificates":    processed_chain,
        "vulnerabilities": vulns,
        "severity_summary": severity_counts,
    }

    # 8. Render
    success = _render_to_pdf(
        SSL_TEMPLATE_FILE, template_data, pdf_path,
        [CSS_BASE, CSS_SSL], "ssl_scanner", user_id
    )
    if success:
        log(f"[+] SSL PDF generated: {pdf_path}",
            to_console=True, scanner_name="ssl_scanner", user_id=user_id)
    return success


def create_packet_sniffer_report_pdf(source_data, pdf_path, user_id=None):
    """
    Renders packet sniffer (TShark) data into a PDF report.
    Parses raw TShark strings into structured data for tables.
    """
    log(f"[*] Starting Sniffer PDF generation: {pdf_path}",
        to_console=True, scanner_name="packet_sniffer", user_id=user_id)

    # 1. Load data
    if isinstance(source_data, str):
        with open(source_data, 'r', encoding='utf-8') as f:
            sniffer_data = json.load(f)
    else:
        sniffer_data = source_data

    traffic    = sniffer_data.get("traffic_summary", {})
    anomalies  = sniffer_data.get("security_anomaly_report", {})
    summary_io = traffic.get("summary_io", {})

    # 2. Parse protocol hierarchy
    proto_raw        = traffic.get("protocol_distribution", [])
    parsed_hierarchy = []
    for line in proto_raw:
        match = re.search(r"^\s*([a-z0-9\._-]+)\s+frames:(\d+)\s+bytes:(\d+)", line.strip())
        if match:
            parsed_hierarchy.append({
                "proto":  match.group(1),
                "frames": int(match.group(2)),
                "bytes":  int(match.group(3)),
            })
    if not parsed_hierarchy and proto_raw:
        parsed_hierarchy = [
            {"proto": line, "frames": "-", "bytes": "-"}
            for line in proto_raw if ":" in line
        ]

    # 3. Parse TCP conversations
    parsed_conversations = []
    for line in traffic.get("tcp_conversations", []):
        if "<->" in line:
            parts = line.split("<->")
            if len(parts) >= 2:
                src       = parts[0].strip()
                dst_parts = parts[1].strip().split()
                dst       = dst_parts[0] if dst_parts else "Unknown"
                parsed_conversations.append({"src": src, "dst": dst})

    # 4. Flatten packet samples
    processed_packets = []
    for p in sniffer_data.get("dissected_packets", [])[:15]:
        layers    = p.get("_source", {}).get("layers", {})
        raw_proto = layers.get("frame", {}).get("frame.protocols", "Unknown")
        short_proto = (
            raw_proto.split(":")[-1].upper() if ":" in raw_proto else raw_proto.upper()
        )
        p_info = {
            "time":     layers.get("frame", {}).get("frame.time_relative", "0.00"),
            "protocol": short_proto,
            "len":      layers.get("frame", {}).get("frame.len", "0"),
            "src":      "N/A",
            "dst":      "N/A",
            "predicted_risk_score": p.get("predicted_risk_score", 0),
            "priority_level":       p.get("priority_level", "P3 (Low)"),
            "risk_justification":   p.get("risk_justification", ""),
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

    # 5. Build context
    logo_url, logo_url_small = _logo_paths()
    template_data = {
        "logo_url":        logo_url,
        "logo_url_small":  logo_url_small,
        "css_path":        pathlib.Path(CSS_BASE).as_uri(),
        "target_ip":       sniffer_data.get("target_ip", "Unknown"),
        "timestamp":       sniffer_data.get("timestamp"),
        "generation_date": get_now_ist().strftime("%Y-%m-%d %H:%M:%S"),
        "metrics": {
            "total_packets": summary_io.get("total_packets", 0),
            "total_bytes":   f"{summary_io.get('total_bytes', 0) / 1024:.2f} KB",
            "duration":      f"{traffic.get('effective_capture_duration_seconds', 0)}s",
            "avg_rate":      f"{traffic.get('average_rate_bps', 0):.2f} bps",
        },
        "hierarchy":          parsed_hierarchy,
        "tcp_conversations":  parsed_conversations,
        "anomalies":          anomalies.get("summary", "No anomalies detected."),
        "anomaly_details": {
            "scans":       anomalies.get("port_scans", []),
            "creds":       anomalies.get("cleartext_credentials", []),
            "web_attacks": anomalies.get("web_attacks", []),
        },
        "packet_samples": processed_packets,
    }

    # 6. Render
    success = _render_to_pdf(
        SNIFFER_TEMPLATE_FILE, template_data, pdf_path,
        [CSS_BASE, CSS_SNIFFER], "packet_sniffer", user_id
    )
    if success:
        log(f"[+] Sniffer PDF generated: {pdf_path}",
            to_console=True, scanner_name="packet_sniffer", user_id=user_id)
    return success


def create_killchain_report_pdf(source_data, pdf_path, user_id=None):
    """
    Renders the full-spectrum Kill Chain report.
    Aggregates and groups findings from all scanners by severity.
    """
    log(f"[*] Starting Kill Chain PDF generation: {pdf_path}",
        to_console=True, scanner_name="killchain_service", user_id=user_id)

    # 1. Load data
    if isinstance(source_data, str):
        try:
            with open(source_data, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            log(f"[!] Error loading Kill Chain JSON: {e}", user_id=user_id)
            return False
    else:
        data = source_data

    # 2. Severity normalisation and grouping
    severity_order_map = {
        "Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1, "Informational": 1
    }
    severity_counts  = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    grouped_findings = {"Critical": [], "High": [], "Medium": [], "Low": [], "Info": []}

    for finding in data.get("all_findings", []):
        raw_sev    = finding.get("severity", finding.get("risk", "Info"))
        normalized = "Info"
        for sev_key in severity_order_map:
            if sev_key.lower() in raw_sev.lower():
                normalized = sev_key
                break
        severity_counts[normalized]  += 1
        grouped_findings[normalized].append(finding)

    stats          = {s: severity_counts[s] for s in ["Critical", "High", "Medium", "Low", "Info"]}
    stats["Total"] = sum(stats.values())

    # 3. Tech stack
    tech_node = data.get("tech", {}) if isinstance(data, dict) else {}

    # 4. Build context
    logo_url, logo_url_small = _logo_paths()
    template_data = {
        "logo_url":        logo_url,
        "logo_url_small":  logo_url_small,
        "css_path":        pathlib.Path(CSS_BASE).as_uri(),
        "target":          str(data.get("target", "Unknown Target")),
        "target_ip":       str(data.get("target_ip", "N/A")),
        "profile":         str(data.get("profile", "Unknown Profile")).replace("_", " ").title(),
        "aggression":      str(data.get("aggression", "Normal")).replace("_", " ").title(),
        "scan_date":       str(data.get("scan_date", get_now_ist_str())),
        "generation_date": get_now_ist_str(),
        "report_id":       f"KC-{int(get_now_ist().timestamp())}",
        "recon": {
            "subdomains":     data.get("recon", {}).get("subdomains", [])      if isinstance(data.get("recon"), dict) else [],
            "resolved_hosts": data.get("recon", {}).get("resolved_hosts", []) if isinstance(data.get("recon"), dict) else [],
        },
        "network": {
            "nmap_scan":          data.get("network", {}).get("nmap_scan", {}),
            "exploiter_findings": data.get("network", {}).get("exploiter_findings", []),
        },
        "web_audit": {
            "waf_detection":          data.get("web_audit", {}).get("waf_detection", {}),
            "crawled_urls":           data.get("web_audit", {}).get("crawled_urls", []),
            "forms_found":            data.get("web_audit", {}).get("forms_found", []),
            "api_endpoints":          data.get("web_audit", {}).get("api_endpoints", []),
            "directory_fuzzing":      data.get("web_audit", {}).get("directory_fuzzing", {}),
            "vuln_scanner_findings":  data.get("web_audit", {}).get("vuln_scanner_findings", []),
            "custom_scanner_findings":data.get("web_audit", {}).get("custom_scanner_findings", []),
            "logic_scanner_findings": data.get("web_audit", {}).get("logic_scanner_findings", []),
            "zap_findings":           data.get("web_audit", {}).get("zap_findings", {}),
        },
        "traffic_analysis": data.get("traffic_analysis", {}),
        "tech_stack": {
            "technologies": tech_node.get("technologies", {}),
            "versions":     tech_node.get("versions", {}),
            "target_url":   tech_node.get("target"),
        },
        "stats":            stats,
        "grouped_findings": grouped_findings,
        "all_findings":     data.get("all_findings", []),
    }

    # 5. Render
    success = _render_to_pdf(
        KILLCHAIN_TEMPLATE_FILE, template_data, pdf_path,
        [CSS_BASE, CSS_KILLCHAIN], "killchain_service", user_id
    )
    if success:
        log(f"[+] Kill Chain PDF generated: {pdf_path}",
            to_console=True, scanner_name="killchain_service", user_id=user_id)
    return success


def create_sql_report_pdf(source_data, pdf_path, user_id=None):
    """
    Renders SQLMap scan data into an HTML template and saves it as a PDF.
    """
    log(f"[*] Starting SQL Injection PDF generation: {pdf_path}",
        to_console=True, scanner_name="sql_scanner", user_id=user_id)

    # 1. Load data
    if isinstance(source_data, str):
        if not os.path.exists(source_data):
            log(f"[!] SQL JSON not found: {source_data}", user_id=user_id)
            return False
        try:
            with open(source_data, 'r', encoding='utf-8') as f:
                sql_data = json.load(f)
        except json.JSONDecodeError as e:
            log(f"[!] Invalid SQL JSON: {e}", user_id=user_id)
            return False
    else:
        sql_data = source_data

    # 2. Extract and organise
    raw_vulns   = sql_data.get("vulnerabilities", [])
    db_info     = sql_data.get("database_info", {})
    dumped_data = sql_data.get("dumped_data", [])

    sorted_vulns       = sorted(raw_vulns, key=lambda x: x.get("type", "Unknown"))
    total_vulns_count  = len(raw_vulns) if isinstance(raw_vulns, list) else 0
    vulns_by_type      = {}
    unique_titles_set  = set()

    if isinstance(raw_vulns, list):
        for v in raw_vulns:
            if not isinstance(v, dict):
                continue
            v_type = str(v.get("type", "Unknown"))
            vulns_by_type[v_type] = vulns_by_type.get(v_type, 0) + 1
            if v.get("title"):
                unique_titles_set.add(str(v["title"]))

    # 3. Build context
    logo_url, logo_url_small = _logo_paths()
    template_data = {
        "logo_url":        logo_url,
        "logo_url_small":  logo_url_small,
        "css_path":        pathlib.Path(CSS_BASE).as_uri(),
        "target":          sql_data.get("target", "Unknown Target"),
        "scan_time":       sql_data.get("scan_time", "N/A"),
        "generation_date": get_now_ist().strftime("%Y-%m-%d %H:%M:%S"),
        "db_info": {
            "dbms":       db_info.get("dbms",       "Not Detected"),
            "version":    db_info.get("version",    "Not Detected"),
            "user":       db_info.get("user",       "Not Detected"),
            "current_db": db_info.get("current_db", "Not Detected"),
        },
        "stats": {
            "total_vulns":   total_vulns_count,
            "types":         vulns_by_type,
            "unique_issues": len(unique_titles_set),
        },
        "vulnerabilities":  sorted_vulns,
        "dumped_data":      dumped_data,
        "has_dumped_data":  len(dumped_data) > 0,
    }

    # 4. Render
    success = _render_to_pdf(
        SQL_TEMPLATE_FILE, template_data, pdf_path,
        [CSS_BASE, CSS_SQL], "sql_scanner", user_id
    )
    if success:
        log(f"[+] SQL PDF generated: {pdf_path}",
            to_console=True, scanner_name="sql_scanner", user_id=user_id)
    return success


def create_semgrep_report_pdf(source_data, pdf_path, user_id=None):
    """
    Renders Semgrep SAST data into an HTML template and saves it as a PDF.
    Limits output to 200 findings and truncates large code snippets.
    """
    log(f"[*] Starting Semgrep PDF generation: {pdf_path}",
        to_console=True, scanner_name="semgrep_scanner", user_id=user_id)

    # 1. Load data
    if isinstance(source_data, str):
        if not os.path.exists(source_data):
            log(f"[!] Semgrep JSON not found: {source_data}", user_id=user_id)
            return False
        try:
            with open(source_data, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            log(f"[!] Invalid Semgrep JSON: {e}", user_id=user_id)
            return False
    else:
        data = source_data

    # 2. Sort, limit, and clean findings
    findings = data.get("findings", [])
    severity_order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    findings.sort(key=lambda x: severity_order.get(x.get("severity", "INFO"), 3))

    total_findings_count = len(findings)
    if total_findings_count > 200:
        log(f"[*] Large Semgrep report ({total_findings_count} findings) — truncating to 200.",
            scanner_name="semgrep_scanner", user_id=user_id)
        findings = findings[:200]

    for f in findings:
        full_path = f.get("path", "")
        if "source_code_temp" in full_path:
            clean_path        = full_path.split("source_code_temp")[-1]
            f["display_path"] = clean_path.lstrip(os.sep).lstrip("/")
        else:
            f["display_path"] = os.path.basename(full_path)

        snippet = f.get("code_snippet", "")
        if len(snippet) > 1000:
            f["code_snippet"] = snippet[:1000] + "\n... [TRUNCATED FOR REPORT] ..."

    # 3. Build context
    logo_url, logo_url_small = _logo_paths()
    template_data = {
        "logo_url":        logo_url,
        "logo_url_small":  logo_url_small,
        "css_path":        pathlib.Path(CSS_BASE).as_uri(),
        "scan_date":       data.get("scan_date"),
        "generation_date": get_now_ist().strftime("%Y-%m-%d %H:%M:%S"),
        "tool":            data.get("tool", "Semgrep"),
        "stats": {
            "total":           total_findings_count,
            "severity_counts": data.get("severity_counts", {}),
        },
        "findings":     findings,
        "is_truncated": total_findings_count > 200,
    }

    # 4. Render
    success = _render_to_pdf(
        SEMGREP_TEMPLATE_FILE, template_data, pdf_path,
        [CSS_BASE, CSS_SEMGREP], "semgrep_scanner", user_id
    )
    if success:
        log(f"[+] Semgrep PDF generated: {pdf_path}",
            to_console=True, scanner_name="semgrep_scanner", user_id=user_id)
    return success


def create_api_report_pdf(source_data, pdf_path, user_id=None):
    """
    Renders API scanner data into an HTML template and saves it as a PDF.
    """
    log(f"[*] Starting API PDF generation: {pdf_path}",
        to_console=True, scanner_name="api_scanner", user_id=user_id)

    # 1. Load data
    if isinstance(source_data, str):
        with open(source_data, 'r', encoding='utf-8') as f:
            api_data = json.load(f)
    else:
        api_data = source_data

    # 2. Build context
    logo_url, logo_url_small = _logo_paths()
    template_data = {
        "logo_url":        logo_url,
        "logo_url_small":  logo_url_small,
        "css_path":        pathlib.Path(CSS_BASE).as_uri(),
        "api_results":     api_data,
        "generation_date": get_now_ist_str(),
    }

    # 3. Render
    success = _render_to_pdf(
        API_TEMPLATE_FILE, template_data, pdf_path,
        [CSS_BASE, CSS_API], "api_scanner", user_id
    )
    if success:
        log(f"[+] API PDF generated: {pdf_path}",
            to_console=True, scanner_name="api_scanner", user_id=user_id)
    return success


def create_asset_discovery_report_pdf(source_data, pdf_path, user_id=None):
    """
    Renders Asset Discovery & Inventory data into an HTML template and saves it as a PDF.
    Processes: asset inventory, SSL cert digest, mail posture, cloud exposure, WHOIS, ASN.
    """
    log(f"[*] Starting Asset Discovery PDF generation: {pdf_path}",
        to_console=True, scanner_name="asset_discovery", user_id=user_id)

    # 1. Load data
    if isinstance(source_data, str):
        try:
            with open(source_data, 'r', encoding='utf-8') as f:
                discovery_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            log(f"[!] Error loading Asset Discovery JSON: {e}", scanner_name="asset_discovery")
            return False
    else:
        discovery_data = source_data

    assets        = discovery_data.get("assets", [])
    target_domain = discovery_data.get("target_domain", "Unknown")
    summary       = discovery_data.get("summary", {})
    mail_posture  = discovery_data.get("mail_posture", {})
    cloud_exp     = discovery_data.get("cloud_exposure", [])
    whois_data    = discovery_data.get("whois", {})

    # 2. Asset Statistics
    total      = len(assets)
    domains    = sum(1 for a in assets if a.get("type") == "domain")
    subdomains = sum(1 for a in assets if a.get("type") == "subdomain")
    resolved   = sum(1 for a in assets if a.get("details", {}).get("ip"))
    tech_found = sum(1 for a in assets if a.get("details", {}).get("tech"))

    # 3. Criticality Distribution
    crit_dist = {"High": 0, "Medium": 0, "Low": 0}
    for a in assets:
        bv = a.get("business_value", "Medium")
        crit_dist[bv] = crit_dist.get(bv, 0) + 1

    # 4. SSL Certificate Digest
    ssl_groups = {"Valid": [], "Expiring Soon": [], "Expired": [], "No SSL": []}
    for a in assets:
        ssl_info = (a.get("details") or {}).get("ssl") or {}
        status   = ssl_info.get("status", "No SSL")
        bucket   = ssl_groups.get(status, ssl_groups["No SSL"])
        bucket.append({
            "value":         a["value"],
            "type":          a.get("type", "unknown"),
            "expiry_date":   ssl_info.get("expiry_date"),
            "issuer":        ssl_info.get("issuer"),
            "days_remaining": ssl_info.get("days_remaining"),
        })

    ssl_alert_count = len(ssl_groups["Expired"]) + len(ssl_groups["Expiring Soon"])

    # 5. Technology Fingerprint Summary (aggregate across all assets)
    tech_tallies = {}
    for a in assets:
        tech = (a.get("details") or {}).get("tech") or {}
        for category, value in tech.items():
            if category not in tech_tallies:
                tech_tallies[category] = {}
            key = str(value)
            tech_tallies[category][key] = tech_tallies[category].get(key, 0) + 1

    # 6. Build top-N asset tables split by type
    domain_assets    = [a for a in assets if a.get("type") == "domain"]
    subdomain_assets = [a for a in assets if a.get("type") == "subdomain"]

    # 7. Build template context
    logo_url, logo_url_small = _logo_paths()
    template_data = {
        "logo_url":        logo_url,
        "logo_url_small":  logo_url_small,
        "css_path":        pathlib.Path(CSS_BASE).as_uri(),
        "target_domain":   target_domain,
        "scan_date":       discovery_data.get("scan_date", get_now_ist_str()),
        "generation_date": get_now_ist_str(),
        "generated_by":    discovery_data.get("generated_by", "NetShieldAI"),

        # WHOIS
        "whois": {
            "registrar":     whois_data.get("registrar"),
            "creation_date": whois_data.get("creation_date"),
            "expiry_date":   whois_data.get("expiry_date"),
        },

        # Core stats
        "stats": {
            "total_assets":   total,
            "domains":        domains,
            "subdomains":     subdomains,
            "resolved_count": resolved,
            "tech_count":     tech_found,
            "new_assets":     summary.get("new_assets", 0),
            "ssl_alerts":     ssl_alert_count,
            "cloud_found":    len(cloud_exp),
            "has_cloud":      bool(cloud_exp),
        },

        # Criticality breakdown
        "criticality_distribution": crit_dist,

        # SSL certificate inventory
        "ssl_groups":      ssl_groups,
        "ssl_alert_count": ssl_alert_count,

        # Mail & Identity posture
        "mail_posture": {
            "spf":          bool(mail_posture.get("spf")),
            "dmarc":        bool(mail_posture.get("dmarc")),
            "dkim":         bool(mail_posture.get("dkim")),
            "mx_count":     mail_posture.get("mx_count", 0),
            "spf_record":   mail_posture.get("spf_record"),
            "dmarc_record": mail_posture.get("dmarc_record"),
        },

        # Cloud exposure
        "cloud_exposure": cloud_exp,

        # Technology landscape
        "tech_tallies": tech_tallies,

        # Asset lists
        "domain_assets":    domain_assets,
        "subdomain_assets": subdomain_assets[:100],  # cap for PDF size
        "assets":           assets,
        "total_truncated":  max(0, len(subdomain_assets) - 100),
    }

    # 8. Render
    success = _render_to_pdf(
        ASSET_DISCOVERY_TEMPLATE_FILE, template_data, pdf_path,
        [CSS_BASE, CSS_ASSET_DISCOVERY], "asset_discovery", user_id
    )
    if success:
        log(f"[+] Asset Discovery PDF generated: {pdf_path}",
            to_console=True, scanner_name="asset_discovery", user_id=user_id)
    return success


from bs4 import BeautifulSoup

# =============================================================================
# ENRICHMENT HELPERS
# =============================================================================

def _enrich_executive_summary_html(html_content):
    """
    Transforms plain Markdown-generated HTML into the structured archetypes 
    seen in the chatbot (finding cards, section dividers, etc.).
    """
    if not html_content:
        return ""

    soup = BeautifulSoup(html_content, 'html.parser')

    # --- Pass 1: Section Dividers (h2 with numbers) ---
    for h2 in soup.find_all('h2'):
        text = h2.get_text().strip()
        # Match "1. Executive Summary" or "2. Technical Findings"
        match = re.match(r'^(\d+)\.\s+(.+)$', text)
        if match:
            divider = soup.new_tag('div', attrs={'class': 'llm-section-divider'})
            divider.append(soup.new_tag('div', attrs={'class': 'llm-divider-line'}))

            pill = soup.new_tag('span', attrs={'class': 'llm-section-pill'})
            pill.string = f"§{match.group(1)}"
            divider.append(pill)

            title = soup.new_tag('span', attrs={'class': 'llm-section-title'})
            title.string = match.group(2)
            divider.append(title)

            divider.append(soup.new_tag('div', attrs={'class': 'llm-divider-line llm-divider-line-rev'}))
            h2.replace_with(divider)

    # --- Pass 2: Finding Cards ---
    # Patterns: "Finding #1 — Name | Severity"
    finding_pattern = re.compile(r'Finding\s+#?(\d+)\s*[\u2014\u2013-]\s*(.+?)\s*\|\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)', re.IGNORECASE)

    # Check headers first
    for h in soup.find_all(['h3', 'h4']):
        text = h.get_text().strip()
        match = finding_pattern.search(text)
        if match:
            num, name, sev = match.groups()
            sev = sev.upper()

            card = soup.new_tag('div', attrs={'class': f'llm-finding-card sev-{sev.lower()}'})

            header = soup.new_tag('div', attrs={'class': 'llm-finding-header'})
            meta = soup.new_tag('div', attrs={'class': 'llm-finding-meta'})

            f_num = soup.new_tag('span', attrs={'class': 'llm-finding-number'})
            f_num.string = f"FINDING #{num}"
            meta.append(f_num)

            f_name = soup.new_tag('span', attrs={'class': 'llm-finding-name'})
            f_name.string = name.strip()
            meta.append(f_name)

            header.append(meta)

            badge = soup.new_tag('span', attrs={'class': 'llm-severity-badge'})
            badge.string = sev
            header.append(badge)

            card.append(header)

            body = soup.new_tag('div', attrs={'class': 'llm-finding-body'})
            # Collect siblings until next header or divider
            curr = h.next_sibling
            to_remove = []
            while curr and getattr(curr, 'name', None) not in ['h2', 'h3', 'h4', 'div']:
                if hasattr(curr, 'extract'):
                    body.append(curr.extract())
                    curr = h.next_sibling
                else:
                    curr = curr.next_sibling

            card.append(body)
            h.replace_with(card)

    # --- Pass 3: Table Panels ---
    for table in soup.find_all('table'):
        # Skip if already wrapped (unlikely but safe)
        if table.parent and 'llm-table-panel' in table.parent.get('class', []):
            continue

        # Try to find a label (header or paragraph before the table)
        label_text = "REPORT DATA"
        prev = table.find_previous(['h2', 'h3', 'h4', 'p'])
        if prev:
            ptxt = prev.get_text().strip()
            if ptxt and len(ptxt) < 100:
                label_text = ptxt.upper()

        panel = soup.new_tag('div', attrs={'class': 'llm-table-panel'})
        header = soup.new_tag('div', attrs={'class': 'llm-table-panel-header'})
        header.string = label_text
        panel.append(header)

        table.replace_with(panel)
        panel.append(table)

    # --- Pass 4: Risk Labels in Tables ---
    risk_map = {
        'critical': 'critical', 'high': 'high', 'moderate': 'moderate', 
        'medium': 'moderate', 'low': 'low', 'safe': 'safe', 'info': 'safe'
    }
    for td in soup.find_all('td'):
        txt = td.get_text().strip().lower()
        if txt in risk_map:
            cls = risk_map[txt]
            badge = soup.new_tag('span', attrs={'class': f'llm-risk-label {cls}'})
            badge.string = td.get_text().strip().upper()
            td.string = ""
            td.append(badge)

    # --- Pass 5: Score Bars ---
    for td in soup.find_all('td'):
        # Only if not already a risk label
        if td.find('span', class_='llm-risk-label'):
            continue

        txt = td.get_text().strip()
        try:
            score = float(txt)
            if 0 <= score <= 10 and (txt == str(score) or txt == f"{score:.1f}"):
                td['class'] = td.get('class', []) + ['llm-score-cell']

                # We need a container for text to sit above the bar
                container = soup.new_tag('div', attrs={'class': 'llm-score-bar-container'})
                container.string = txt

                bar = soup.new_tag('div', attrs={'class': 'llm-score-bar'})
                # We can't do easy animation in PDF but we can set the width
                bar['style'] = f"width: {score*10}%;"

                td.string = ""
                td.append(bar)
                td.append(container)
        except ValueError:
            continue

    return str(soup)


def create_executive_summary_report_pdf(summary_text, metadata, pdf_path, user_id=None):
    """
    Renders an AI-generated Markdown summary into an Executive Summary PDF.
    Converts Markdown → HTML, enriches it with archetypes, then renders.
    """
    log(f"[*] Starting Executive Summary PDF generation: {pdf_path}",
        to_console=True, user_id=user_id)

    # 1. Convert Markdown to HTML
    try:
        import markdown
        html_summary = markdown.markdown(
            summary_text,
            extensions=['tables', 'fenced_code', 'nl2br']
        )
    except Exception as e:
        log(f"[!] Markdown conversion failed: {e} — falling back to plain text.",
            scanner_name="executive_summary", user_id=user_id)
        html_summary = f"<pre>{summary_text}</pre>"

    # 2. Enrich HTML with Chatbot-style Archetypes
    try:
        enriched_html = _enrich_executive_summary_html(html_summary)
    except Exception as e:
        log(f"[!] HTML Enrichment failed: {e} — using raw HTML.",
            scanner_name="executive_summary", user_id=user_id)
        enriched_html = html_summary

    # 3. Build context
    logo_url, logo_url_small = _logo_paths()
    template_data = {
        "logo_url":        logo_url,
        "logo_url_small":  logo_url_small,
        "css_path":        pathlib.Path(CSS_BASE).as_uri(),
        "summary_content": enriched_html,   # Enriched HTML — use | safe in template
        "metadata": {
            "target":    metadata.get("target",    "N/A"),
            "tool_name": metadata.get("tool_name", "Security Analyzer"),
            "date":      metadata.get("date",      get_now_ist_str()),
        },
        "generation_date": get_now_ist_str(),
    }

    # 4. Render
    success = _render_to_pdf(
        EXECUTIVE_SUMMARY_TEMPLATE_FILE, template_data, pdf_path,
        [CSS_BASE, CSS_EXECUTIVE], "executive_summary", user_id
    )
    if success:
        log(f"[+] Executive Summary PDF generated: {pdf_path}",
            to_console=True, scanner_name="executive_summary", user_id=user_id)
    return success
