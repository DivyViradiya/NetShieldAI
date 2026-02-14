from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user
import os
import json
from werkzeug.utils import secure_filename
import re  
from datetime import datetime
from Services import compliance_engine

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

# --- Main Route ---

@dashboard_bp.route('/')
@login_required
def dashboard():
    """Renders the dashboard UI frame."""
    return render_template('dashboard/dashboard.html')

# --- Modular API Endpoints ---

# [NEW] --- Kill Chain Combined Stats ---
@dashboard_bp.route('/api/stats/killchain')
@login_required
def get_killchain_stats():
    """
    Parses the massive killchain_report.json to provide a high-level 
    security posture overview for the Dashboard.
    """
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

    # Path to the killchain specific report
    # Path: Services/results/{User_ID}/killchain/reports/killchain_report.json
    kc_path = os.path.join(user_dir, 'killchain', 'reports', 'killchain_report.json')
    data = load_json_safe(kc_path)

    if data:
        # 1. Basic Metadata
        response['status'] = "Completed"
        response['target'] = data.get('target', 'Unknown')
        response['scan_date'] = data.get('scan_date', 'N/A')

        # 2. Vulnerability Summary (Counts from vulns_grouped)
        # Structure: "vulns_grouped": { "Critical": [...], "High": [...] }
        vuln_groups = data.get('vulns_grouped', {})
        total_vulns = 0
        
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            count = len(vuln_groups.get(severity, []))
            response['vuln_summary'][severity] = count
            total_vulns += count

        # 3. Extract Top Risks (Critical & High)
        # We take up to 5 items, prioritizing Critical then High
        top_risks = []
        
        # Helper to format risk for UI
        def format_risk(vuln_item, sev_label):
            return {
                "type": vuln_item.get('type', 'Unknown Vulnerability'),
                "severity": sev_label,
                "evidence": vuln_item.get('evidence', '')[:100], # Truncate evidence
                "param": vuln_item.get('parameter', 'N/A')
            }

        for v in vuln_groups.get('Critical', []):
            top_risks.append(format_risk(v, 'Critical'))
        
        # If we have space left, add Highs
        if len(top_risks) < 5:
            for v in vuln_groups.get('High', []):
                if len(top_risks) >= 5: break
                top_risks.append(format_risk(v, 'High'))
        
        response['top_risks'] = top_risks

        # 4. Tech Stack Extraction
        # Structure: "tech": { "technologies": { "Server": ["nginx"], "Language": ["PHP"] } }
        tech_data = data.get('tech', {}).get('technologies', {})
        response['tech_stack'] = tech_data

        # 5. Network/Recon Summary
        # Structure: "network": { "ports": [...] }, "recon": { "subdomains": [...] }
        ports = data.get('network', {}).get('ports', [])
        subdomains = data.get('recon', {}).get('subdomains', [])
        
        # [UPDATED] Added urls_crawled count here
        response['network_summary'] = {
            "open_ports": len(ports),
            "subdomains": len(subdomains),
            "urls_crawled": len(data.get('urls', [])), 
            "ports_list": [f"{p.get('port')}/{p.get('service')}" for p in ports[:5]] # Quick preview
        }

    return jsonify(response)


# [EXISTING] --- Network Stats ---
@dashboard_bp.route('/api/stats/network')
@login_required
def get_network_stats():
    """Returns aggregated stats for Nmap/Network Scanner."""
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
    # current_user is a proxy for the User model record defined in models.py
    user = current_user
    
    # Format the last login date safely
    last_login_str = "Never"
    if user.last_login_at:
        # Format example: "Jan 05, 2026 12:45 PM"
        last_login_str = user.last_login_at.strftime("%b %d, %Y %I:%M %p")

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
            "ai_analysis": user.scan_count_ai,
            "killchain": user.scan_count_killchain,
            "api": getattr(user, 'scan_count_api', 0),
            "sql": getattr(user, 'scan_count_sql', 0),
            "semgrep": getattr(user, 'scan_count_semgrep', 0)
        },
        
        # --- Aggregates ---
        # Using the @property total_scans defined in your models.py
        "total_system_usage": user.total_scans
    }

    return jsonify(response)

@dashboard_bp.route('/api/stats/compliance')
@login_required
def get_compliance_stats():
    """
    Generates/Retrieves the Compliance Report.
    """
    user_dir = get_user_results_dir()
    if not user_dir:
        return jsonify({"status": "error", "message": "User directory not found"})

    # Check if report exists, if not, generate it on the fly
    report_path = os.path.join(user_dir, "compliance_report.json")
    
    # Optional: Re-generate every time page loads, OR check timestamp
    # For now, let's regenerate it to ensure it has the latest scan data
    data = compliance_engine.generate_compliance_report(user_dir)
    
    return jsonify(data)