from flask import Blueprint, render_template, jsonify, request, send_from_directory
from flask_login import login_required, current_user
import os
import json
import requests
from werkzeug.utils import secure_filename
import re  
import logging
from datetime import datetime
from Services import compliance_engine
import glob
from pathlib import Path


# --- Logging Setup ---
logger = logging.getLogger(__name__)

dashboard_bp = Blueprint('dashboard_bp', __name__)

# --- Helper Functions ---

def get_user_results_dir():
    """
    Constructs the path: Services/results/<username_id>
    """
    if not current_user.is_authenticated:
        return None
    
    # Composite Identifier: username_id
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    user_dir = os.path.join(base_dir, 'Services', 'results', user_identifier)
    
    return user_dir

def load_json_safe(path):
    """Helper to load JSON without crashing if file is missing/corrupt."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None

def get_all_reports(user_dir):
    """
    Scans the user's result directory for all PDF reports.
    Returns a list of dicts: { name, type, date, size, download_url }
    """
    if not user_dir or not os.path.exists(user_dir):
        return []

    reports = []
    
    # Define mapping from folder name to Scanner Type
    scanner_map = {
        "zap_scanner": "Web Vulnerability",
        "network_scanner": "Network Scan",
        "ssl_scanner": "SSL/TLS",
        "packet_sniffer": "Traffic Analysis",
        "killchain": "Kill Chain Audit",
        "sql_scanner": "SQL Injection",
        "api_scanner": "API Security",
        "semgrep_scanner": "SAST Code Analysis"
    }

    # Walk through the directory
    # Structure: Services/results/<user>/<scanner_folder>/.../*.pdf
    # Killchain has an extra 'reports' subfolder: .../killchain/reports/*.pdf
    
    for root, dirs, files in os.walk(user_dir):
        for file in files:
            if file.lower().endswith('.pdf'):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, user_dir)
                
                # Determine scanner type from the first folder in relative path
                parts = Path(rel_path).parts
                scanner_folder = parts[0] if parts else "Unknown"
                
                # Pretty Type Name
                scan_type = scanner_map.get(scanner_folder, "General Report")
                
                # File Stats
                try:
                    stats = os.stat(full_path)
                    mtime = datetime.fromtimestamp(stats.st_mtime)
                    size_kb = round(stats.st_size / 1024, 1)
                    
                    # Generate safe download link
                    # Passing relative path relative to user_dir so we can serve it genericially
                    # or mapped to specific routes.
                    # We'll use a generic download route in dashboard to serve any file from user dir
                    
                    reports.append({
                        "filename": file,
                        "type": scan_type,
                        "date": mtime.strftime("%b %d, %Y %I:%M %p"),
                        "timestamp": stats.st_mtime, # for sorting
                        "size": f"{size_kb} KB",
                        "folder": scanner_folder,
                        "rel_path": rel_path.replace("\\", "/") # Ensure web-safe paths
                    })
                except Exception as e:
                    logger.warning(f"Error processing report {file}: {e}")

    # Sort by newest first
    reports.sort(key=lambda x: x['timestamp'], reverse=True)
    return reports

# --- Main Route ---

@dashboard_bp.route('/')
@login_required
def dashboard():
    """Renders the dashboard UI frame."""
    logger.info(f"\033[34m[*] Accessing Security Posture Dashboard (User: {current_user.username})\033[0m")
    return render_template('dashboard/dashboard.html')

# --- Modular API Endpoints ---

# [NEW] --- Kill Chain Combined Stats ---
@dashboard_bp.route('/api/stats/killchain')
@login_required
def get_killchain_stats():
    """
    Parses the killchain_report JSON to provide a high-level 
    security posture overview for the Home page and Dashboard.
    """
    logger.info(f"\033[34m[*] Fetching Kill Chain Stats for {current_user.username}\033[0m")
    user_dir = get_user_results_dir()
    
    response = {
        "status": "Not Scanned",
        "target": "N/A",
        "scan_date": "N/A",
        "vuln_summary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
        "top_risks": [],
        "tech_stack": {},
        "network_summary": {"open_ports": 0, "subdomains": 0, "urls_crawled": 0}
    }

    if not user_dir: return jsonify(response)

    # --- FIX 1: Service saves killchain_report_<target>.json (not a fixed name) ---
    # Use glob to find the most recently modified JSON in the reports folder.
    kc_reports_dir = os.path.join(user_dir, 'killchain', 'reports')
    kc_path = None
    if os.path.isdir(kc_reports_dir):
        candidates = glob.glob(os.path.join(kc_reports_dir, 'killchain_report*.json'))
        if candidates:
            # Pick the most recently modified file
            kc_path = max(candidates, key=os.path.getmtime)

    if not kc_path:
        return jsonify(response)

    data = load_json_safe(kc_path)

    if data:
        # 1. Basic Metadata
        response['status'] = "Completed"
        response['target'] = data.get('target', 'Unknown')
        response['scan_date'] = data.get('scan_date', 'N/A')

        # --- FIX 2: JSON uses 'all_findings' (flat list with 'severity' field),
        #            NOT 'vulns_grouped'. Build severity groups from the flat list. ---
        all_findings = data.get('all_findings', [])

        # Group by severity
        vuln_groups = {"Critical": [], "High": [], "Medium": [], "Low": [], "Info": []}
        for item in all_findings:
            sev = item.get('severity', 'Info')
            # Normalise casing (e.g. 'low' -> 'Low')
            sev_key = sev.capitalize() if sev.capitalize() in vuln_groups else 'Info'
            vuln_groups[sev_key].append(item)

        # 2. Vulnerability Summary counts
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            response['vuln_summary'][severity] = len(vuln_groups[severity])

        # 3. Extract Top Risks (Critical → High → Medium, up to 5)
        def format_risk(vuln_item, sev_label):
            return {
                "type": vuln_item.get('type', 'Unknown Vulnerability'),
                "severity": sev_label,
                "evidence": vuln_item.get('evidence', '')[:100],
                "param": vuln_item.get('parameter', 'N/A')
            }

        top_risks = []
        for sev in ['Critical', 'High', 'Medium']:
            for v in vuln_groups[sev]:
                if len(top_risks) >= 5: break
                top_risks.append(format_risk(v, sev))
            if len(top_risks) >= 5: break

        response['top_risks'] = top_risks

        # 4. Tech Stack
        tech_data = data.get('tech', {}).get('technologies', {})
        response['tech_stack'] = tech_data

        # --- FIX 3: Ports are under network.nmap_scan.ports, not network.ports ---
        ports = data.get('network', {}).get('nmap_scan', {}).get('ports', [])
        subdomains = data.get('recon', {}).get('subdomains', [])
        crawled_urls = data.get('web_audit', {}).get('crawled_urls', data.get('urls', []))

        response['network_summary'] = {
            "open_ports": len(ports),
            "subdomains": len(subdomains),
            "urls_crawled": len(crawled_urls),
            "ports_list": [f"{p.get('port')}/{p.get('service')}" for p in ports[:5]]
        }

    return jsonify(response)


# [EXISTING] --- Network Stats ---
@dashboard_bp.route('/api/stats/network')
@login_required
def get_network_stats():
    """Returns aggregated stats for Nmap/Network Scanner."""
    logger.info(f"\033[34m[*] Fetching Network Stats for {current_user.username}\033[0m")
    user_dir = get_user_results_dir()
    
    response = {
        "status": "Not Scanned",
        "target": "N/A",
        "scan_date": "N/A",
        "host_status": "Unknown",
        "os_detected": "Unknown",
        "open_ports_count": 0,
        "open_ports_list": [], 
        "top_services": []     
    }

    if not user_dir: return jsonify(response)

    nmap_path = os.path.join(user_dir, 'network_scanner', 'nmap_report.json')
    nmap_data = load_json_safe(nmap_path)

    if nmap_data:
        ports_list = nmap_data.get('ports', [])
        
        detailed_services = []
        for p in ports_list:
            port = p.get('port', '?')
            service = p.get('service', 'unknown')
            version = p.get('version', '').strip()
            
            if version:
                label = f"{port}: {service} ({version})"
            else:
                label = f"{port}: {service}"
            
            detailed_services.append(label)

        response.update({
            "status": "Scanned",
            "target": nmap_data.get('target_ip', 'Unknown'),
            "scan_date": nmap_data.get('scan_date', 'N/A'),
            "host_status": nmap_data.get('host_status', 'Down'),
            "os_detected": nmap_data.get('os_guess', 'Unknown'),
            "open_ports_count": len(ports_list),
            "open_ports_list": [p.get('port') for p in ports_list],
            "top_services": detailed_services[:5] 
        })
    
    return jsonify(response)


# [EXISTING] --- ZAP Stats ---
@dashboard_bp.route('/api/stats/zap')
@login_required
def get_zap_stats():
    """Returns aggregated stats for ZAP Web Scanner."""
    logger.info(f"\033[34m[*] Fetching ZAP Web Scanner Stats for {current_user.username}\033[0m")
    user_dir = get_user_results_dir()
    
    response = {
        "status": "Not Scanned",
        "target": "N/A",
        "scan_date": "N/A",
        "alerts_summary": {"high": 0, "medium": 0, "low": 0, "info": 0},
        "top_risks": [] 
    }

    if not user_dir: return jsonify(response)

    zap_path = os.path.join(user_dir, 'zap_scanner', 'zap_report.json')
    zap_data = load_json_safe(zap_path)

    if zap_data:
        summary = zap_data.get('summary', {})
        findings = zap_data.get('findings', [])
        
        seen_alerts = set()
        processed_risks = []

        def clean_html(raw_html):
            cleaner = re.compile('<.*?>')
            text = re.sub(cleaner, '', raw_html)
            return text.strip()

        for f in findings:
            name = f.get('name')
            risk = f.get('risk', 'Low')
            
            if name not in seen_alerts:
                seen_alerts.add(name)
                
                raw_sol = f.get('solution', '')
                clean_sol = clean_html(raw_sol)
                short_sol = (clean_sol[:100] + '...') if len(clean_sol) > 100 else clean_sol

                processed_risks.append({
                    "name": name,
                    "risk": risk,
                    "solution": short_sol,
                    "confidence": f.get('confidence', '1')
                })

        risk_order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
        processed_risks.sort(key=lambda x: risk_order.get(x["risk"], 4))

        response.update({
            "status": "Scanned",
            "target": zap_data.get('target_url', 'Unknown'),
            "scan_date": zap_data.get('scan_date', 'N/A'),
            "alerts_summary": {
                "high": summary.get('High', 0),
                "medium": summary.get('Medium', 0),
                "low": summary.get('Low', 0),
                "info": summary.get('Info', 0)
            },
            "top_risks": processed_risks[:5] 
        })

    return jsonify(response)


# [EXISTING] --- SSL Stats ---
@dashboard_bp.route('/api/stats/ssl')
@login_required
def get_ssl_stats():
    """Returns aggregated stats for SSL Scanner."""
    logger.info(f"\033[34m[*] Fetching SSL Scanner Stats for {current_user.username}\033[0m")
    user_dir = get_user_results_dir()
    
    response = {
        "status": "Not Scanned",
        "target": "N/A",
        "issuer": "N/A",
        "days_left": "--",
        "key_info": "N/A",
        "weak_protocols": [],
        "vulnerabilities": [],
        "is_secure": True
    }

    if not user_dir: return jsonify(response)

    ssl_path = os.path.join(user_dir, 'ssl_scanner', 'ssl_report.json')
    ssl_data = load_json_safe(ssl_path)

    if ssl_data:
        cert_chain = ssl_data.get('certificate_chain', [])
        primary_cert = cert_chain[0] if cert_chain else {}
        
        days_left_str = "Unknown"
        expiry_str = primary_cert.get('not_after', '')
        if expiry_str:
            try:
                clean_date = expiry_str.replace(' GMT', '')
                expiry_dt = datetime.strptime(clean_date, "%b %d %H:%M:%S %Y")
                delta = expiry_dt - datetime.now()
                days_left_str = f"{delta.days} Days"
            except Exception:
                pass

        k_type = primary_cert.get('key_type', 'RSA')
        k_size = primary_cert.get('key_size', 'Unknown')
        key_info = f"{k_type} {k_size} bits"

        weak_protocols_found = []
        for proto in ssl_data.get('protocols', []):
            p_name = proto.get('name', '') 
            if proto.get('enabled') and p_name in ['SSLv2', 'SSLv3', '1.0', '1.1']:
                full_name = f"TLS {p_name}" if p_name[0].isdigit() else p_name
                weak_protocols_found.append(full_name)

        vulns_list = ssl_data.get('vulnerabilities', [])
        vuln_names = list(set([v.get('name') for v in vulns_list]))
        
        is_secure = (len(weak_protocols_found) == 0) and (len(vulns_list) == 0)

        response.update({
            "status": "Scanned",
            "target": ssl_data.get('target', 'Unknown'),
            "issuer": primary_cert.get('issuer', 'Unknown'),
            "days_left": days_left_str,
            "key_info": key_info,
            "weak_protocols": weak_protocols_found,
            "vulnerabilities": vuln_names,
            "is_secure": is_secure
        })

    return jsonify(response)


# [EXISTING] --- Sniffer Stats ---
@dashboard_bp.route('/api/stats/sniffer')
@login_required
def get_sniffer_stats():
    """Returns aggregated stats for Packet Sniffer."""
    logger.info(f"\033[34m[*] Fetching Packet Sniffer Stats for {current_user.username}\033[0m")
    user_dir = get_user_results_dir()
    
    response = {
        "status": "Not Scanned",
        "target": "N/A", 
        "total_packets": 0,
        "duration": "0s",
        "unique_ips": 0,
        "protocol_breakdown": {},
        "top_talkers": []
    }

    if not user_dir: return jsonify(response)

    sniffer_path = os.path.join(user_dir, 'packet_sniffer', 'pcap_analysis_report.json')
    sniffer_data = load_json_safe(sniffer_path)

    if sniffer_data:
        summ = sniffer_data.get('traffic_summary', {})
        
        response["status"] = "Analyzed"
        response["target"] = sniffer_data.get('target_ip', 'Unknown')
        response["total_packets"] = summ.get('total_packets', 0)
        response["duration"] = f"{round(summ.get('effective_capture_duration_seconds', 0), 2)}s"

        proto_stats = summ.get('protocol_hierarchy_stats', [])
        protocols = {}
        
        for line in proto_stats:
            if "frames:" in line:
                match = re.search(r'\s+([a-z0-9]+)\s+frames:(\d+)', line)
                if match:
                    p_name = match.group(1).upper()
                    p_count = int(match.group(2))
                    if p_name not in ['FRAME', 'ETH', 'IP', 'DATA', 'VLAN']:
                        protocols[p_name] = p_count

        response["protocol_breakdown"] = protocols

        conv_stats = summ.get('tcp_conversation_stats', [])
        talkers = []
        
        for line in conv_stats:
            if "<->" in line:
                match = re.search(r'([\d\.]+):(\d+)\s+<->\s+([\d\.]+):(\d+).*?\s+(\d+)\s+bytes', line)
                if match:
                    src_ip = match.group(1)
                    dst_ip = match.group(3)
                    total_bytes = int(match.group(5))
                    
                    talkers.append({
                        "source": src_ip,
                        "destination": dst_ip,
                        "bytes": total_bytes,
                        "display": f"{src_ip} ↔ {dst_ip}"
                    })

        talkers.sort(key=lambda x: x['bytes'], reverse=True)
        response["top_talkers"] = talkers[:5]
        
        unique_ips = set()
        for t in talkers:
            unique_ips.add(t['source'])
            unique_ips.add(t['destination'])
        response["unique_ips"] = len(unique_ips)

    return jsonify(response)


# [NEW] --- API Scanner Stats ---
@dashboard_bp.route('/api/stats/api')
@login_required
def get_api_stats():
    """Returns aggregated stats for API Scanner."""
    logger.info(f"\033[34m[*] Fetching API Scanner Stats for {current_user.username}\033[0m")
    user_dir = get_user_results_dir()
    
    response = {
        "status": "Not Scanned",
        "target": "N/A",
        "scan_date": "N/A",
        "alerts_summary": {"High": 0, "Medium": 0, "Low": 0, "Info": 0},
        "top_risks": []
    }

    if not user_dir: return jsonify(response)

    api_path = os.path.join(user_dir, 'api_scanner', 'api_scan_report.json')
    api_data = load_json_safe(api_path)

    if api_data:
        summary = api_data.get('summary', {})
        findings = api_data.get('findings', [])
        
        # Deduplicate findings for top risks
        seen_alerts = set()
        processed_risks = []

        for f in findings:
            name = f.get('name')
            risk = f.get('risk', 'Low')
            
            if name not in seen_alerts:
                seen_alerts.add(name)
                processed_risks.append({
                    "name": name,
                    "risk": risk,
                    "method": f.get('method', 'N/A'),
                    "confidence": f.get('confidence', '1')
                })

        # Sort by risk
        risk_order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
        processed_risks.sort(key=lambda x: risk_order.get(x["risk"], 4))

        response.update({
            "status": "Scanned",
            "target": "API Endpoint", # Target is not always explicitly in top-level json, usually inferred
            "scan_date": api_data.get('scan_date', 'N/A'),
            "alerts_summary": {
                "High": summary.get('High', 0),
                "Medium": summary.get('Medium', 0),
                "Low": summary.get('Low', 0),
                "Info": summary.get('Info', 0)
            },
            "top_risks": processed_risks[:5]
        })

    return jsonify(response)


# [NEW] --- SQL Scanner Stats ---
@dashboard_bp.route('/api/stats/sql')
@login_required
def get_sql_stats():
    """Returns aggregated stats for SQL Scanner."""
    logger.info(f"\033[34m[*] Fetching SQL Scanner Stats for {current_user.username}\033[0m")
    user_dir = get_user_results_dir()
    
    response = {
        "status": "Not Scanned",
        "target": "N/A",
        "scan_date": "N/A",
        "vuln_count": 0,
        "database_info": "Unknown",
        "vulnerabilities": []
    }

    if not user_dir: return jsonify(response)

    # Note: SQL Scanner uses a dynamic user-specific folder inside results/sql_scanner/ but 
    # based on the tool code, it saves `sql_report.json` in the user_dir passed to it.
    # We need to verify where the controller saves it. 
    # Assuming standard pattern: Services/results/<user_id>/sql_scanner/sql_report.json
    sql_path = os.path.join(user_dir, 'sql_scanner', 'sql_report.json')
    sql_data = load_json_safe(sql_path)

    if sql_data:
        vulns = sql_data.get('vulnerabilities', [])
        db_info = sql_data.get('database_info', {})
        
        db_label = f"{db_info.get('dbms', 'Unknown')} {db_info.get('version', '')}"

        top_vulns = []
        for v in vulns[:5]:
            top_vulns.append({
                "type": v.get('type', 'SQL Injection'),
                "parameter": v.get('parameter', 'Unknown'),
                "payload": v.get('payload', '')[:50] + "..." if len(v.get('payload', '')) > 50 else v.get('payload', '')
            })

        response.update({
            "status": "Scanned",
            "target": sql_data.get('target', 'Unknown'),
            "scan_date": sql_data.get('scan_time', 'N/A'),
            "vuln_count": len(vulns),
            "database_info": db_label.strip(),
            "vulnerabilities": top_vulns
        })

    return jsonify(response)


# [NEW] --- Semgrep (SAST) Stats ---
@dashboard_bp.route('/api/stats/semgrep')
@login_required
def get_semgrep_stats():
    """Returns aggregated stats for Semgrep SAST Scanner."""
    logger.info(f"\033[34m[*] Fetching Semgrep SAST Stats for {current_user.username}\033[0m")
    user_dir = get_user_results_dir()
    
    response = {
        "status": "Not Scanned",
        "scan_date": "N/A",
        "total_findings": 0,
        "severity_counts": {"ERROR": 0, "WARNING": 0, "INFO": 0},
        "top_findings": []
    }

    if not user_dir: return jsonify(response)

    semgrep_path = os.path.join(user_dir, 'semgrep_scanner', 'semgrep_report.json')
    semgrep_data = load_json_safe(semgrep_path)

    if semgrep_data:
        findings = semgrep_data.get('findings', [])
        
        top_findings = []
        for f in findings[:5]:
            top_findings.append({
                "message": f.get('message', ''),
                "file": f.get('path', ''),
                "severity": f.get('severity', 'INFO')
            })

        response.update({
            "status": "Scanned",
            "scan_date": semgrep_data.get('scan_date', 'N/A'),
            "total_findings": semgrep_data.get('total_findings', 0),
            "severity_counts": semgrep_data.get('severity_counts', {}),
            "top_findings": top_findings
        })

    return jsonify(response)


@dashboard_bp.route('/api/stats/usage')
@login_required
def get_usage_stats():
    """
    Returns the usage metrics recorded in the User database model.
    This powers the 'Usage Statistics' section of the dashboard.
    """
    logger.info(f"\033[34m[*] Fetching System Usage Telemetry for {current_user.username}\033[0m")
    # current_user is a proxy for the User model record defined in models.py
    user = current_user
    
    # [NEW] Dynamically Fetch AI Session Count from Chatbot Service
    ai_session_count = 0
    try:
        user_identifier = f"{secure_filename(user.username)}_{user.id}"
        # Port 5000 is where the FastAPI chatbot server is running
        proxy_url = "http://127.0.0.1:5000/get_user_sessions"
        resp = requests.get(proxy_url, params={'user_id': user_identifier}, timeout=2)
        if resp.status_code == 200:
            ai_data = resp.json()
            ai_session_count = len(ai_data.get('sessions', []))
    except Exception as e:
        logger.warning(f"Could not fetch AI sessions for usage stats: {e}")
        ai_session_count = user.scan_count_ai # Fallback to legacy counter

    # Format the last login date safely
    last_login_str = "Never"
    if user.last_login_at:
        # Format example: "Jan 05, 2026 12:45 PM"
        last_login_str = user.last_login_at.strftime("%b %d, %Y %I:%M %p")

    # Calculate system usage using the fresh session count instead of raw interactions
    total_usage = (
        user.scan_count_nmap + 
        user.scan_count_zap + 
        user.scan_count_ssl + 
        user.scan_count_sniffer +
        user.scan_count_sql +
        ai_session_count + 
        user.scan_count_killchain +
        getattr(user, 'scan_count_api', 0) +
        getattr(user, 'scan_count_semgrep', 0)
    )

    response = {
        "username": user.username,
        "organization": user.organization or "Freelance",
        "account_type": "Admin" if user.is_admin else "Standard",
        
        # --- Activity Metrics ---
        "total_logins": user.login_count,
        "last_login": last_login_str,
        "last_ip": user.last_login_ip or "Unknown",
        
        # --- Scan Counters ---
        "scans": {
            "nmap": user.scan_count_nmap,
            "zap": user.scan_count_zap,
            "ssl": user.scan_count_ssl,
            "sniffer": user.scan_count_sniffer,
            "ai_analysis": ai_session_count, # Reported as sessions
            "killchain": user.scan_count_killchain,
            "api": getattr(user, 'scan_count_api', 0),
            "sql": getattr(user, 'scan_count_sql', 0),
            "semgrep": getattr(user, 'scan_count_semgrep', 0)
        },
        
        # --- Aggregates ---
        "total_system_usage": total_usage
    }

    return jsonify(response)

@dashboard_bp.route('/api/stats/compliance')
@login_required
def get_compliance_stats():
    """
    Generates/Retrieves the Compliance Report.
    """
    logger.info(f"\033[34m[*] Evaluating Compliance Frameworks for {current_user.username}\033[0m")
    user_dir = get_user_results_dir()
    if not user_dir:
        return jsonify({"status": "error", "message": "User directory not found"})

    # Check if report exists, if not, generate it on the fly
    report_path = os.path.join(user_dir, "compliance_report.json")
    
    # Optional: Re-generate every time page loads, OR check timestamp
    # For now, let's regenerate it to ensure it has the latest scan data
    data = compliance_engine.generate_compliance_report(user_dir)
    
    return jsonify(data)


@dashboard_bp.route('/api/stats/reports')
@login_required
def get_pdf_reports():
    """Returns a list of all PDF reports for the current user."""
    logger.info(f"\033[34m[*] Listing PDF Reports for {current_user.username}\033[0m")
    user_dir = get_user_results_dir()
    reports = get_all_reports(user_dir)
    return jsonify({"status": "success", "reports": reports})


@dashboard_bp.route('/download/report')
@login_required
def download_generic_report():
    """
    Generic download handler for any report in the user's directory.
    Params: path (relative to user's result dir)
    """
    rel_path = request.args.get('path')
    if not rel_path:
        return jsonify({"status": "error", "message": "Missing path"}), 400
        
    user_dir = get_user_results_dir()
    if not user_dir:
        return jsonify({"status": "error", "message": "User directory unavailable"}), 404
        
    # Security Check: Ensure the resolved path is within user_dir
    # normalize path separators
    clean_rel = rel_path.replace("..", "") # Basic traversal prevention
    
    file_path = os.path.join(user_dir, clean_rel)
    
    # Rigorous check
    abs_user_dir = os.path.abspath(user_dir)
    abs_file_path = os.path.abspath(file_path)
    
    if not abs_file_path.startswith(abs_user_dir):
        logger.warning(f"Security Alert: User {current_user.username} attempted path traversal: {rel_path}")
        return jsonify({"status": "error", "message": "Access denied"}), 403
        
    if not os.path.exists(file_path):
        return jsonify({"status": "error", "message": "File not found"}), 404
        
    directory = os.path.dirname(file_path)
    filename = os.path.basename(file_path)
    
    return send_from_directory(directory=directory, path=filename, as_attachment=True)
