from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user
import os
import json
from werkzeug.utils import secure_filename
import re  
from datetime import datetime

dashboard_bp = Blueprint('dashboard_bp', __name__)

# --- Helper Functions ---

def get_user_results_dir():
    """
    Constructs the path: Services/results/<username_id>
    Matches the logic used in scanner blueprints.
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
    """Renders the dashboard UI frame. The JS will fetch data from APIs below."""
    return render_template('dashboard.html')

# --- Modular API Endpoints ---

@dashboard_bp.route('/api/stats/network')
@login_required
def get_network_stats():
    """Returns aggregated stats for Nmap/Network Scanner."""
    user_dir = get_user_results_dir()
    
    # Default response structure
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

    # File: nmap_report.json
    nmap_path = os.path.join(user_dir, 'network_scanner', 'nmap_report.json')
    nmap_data = load_json_safe(nmap_path)

    if nmap_data:
        ports_list = nmap_data.get('ports', [])
        
        # --- NEW: Extract Rich Service Data ---
        detailed_services = []
        for p in ports_list:
            port = p.get('port', '?')
            service = p.get('service', 'unknown')
            version = p.get('version', '').strip()
            
            # Format: "135: msrpc (Microsoft Windows RPC)"
            # If version is empty, just show "445: microsoft-ds"
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
            "top_services": detailed_services[:5] # Return top 5 rich strings
        })
    
    return jsonify(response)


@dashboard_bp.route('/api/stats/zap')
@login_required
def get_zap_stats():
    """Returns aggregated stats for ZAP Web Scanner with detailed solutions."""
    user_dir = get_user_results_dir()
    
    response = {
        "status": "Not Scanned",
        "target": "N/A",
        "scan_date": "N/A",
        "alerts_summary": {"high": 0, "medium": 0, "low": 0, "info": 0},
        "top_risks": [] 
    }

    if not user_dir: return jsonify(response)

    # File: zap_report.json
    zap_path = os.path.join(user_dir, 'zap_scanner', 'zap_report.json')
    zap_data = load_json_safe(zap_path)

    if zap_data:
        summary = zap_data.get('summary', {})
        findings = zap_data.get('findings', [])
        
        # 1. Process Findings (Deduplicate & Clean HTML)
        seen_alerts = set()
        processed_risks = []

        # Helper to strip HTML tags for clean dashboard text
        def clean_html(raw_html):
            cleaner = re.compile('<.*?>')
            text = re.sub(cleaner, '', raw_html)
            return text.strip()

        for f in findings:
            name = f.get('name')
            risk = f.get('risk', 'Low')
            
            # Key to ensure we don't show "Missing Headers" 50 times
            if name not in seen_alerts:
                seen_alerts.add(name)
                
                # Clean the solution text (take first sentence or 100 chars)
                raw_sol = f.get('solution', '')
                clean_sol = clean_html(raw_sol)
                short_sol = (clean_sol[:100] + '...') if len(clean_sol) > 100 else clean_sol

                processed_risks.append({
                    "name": name,
                    "risk": risk,
                    "solution": short_sol,
                    "confidence": f.get('confidence', '1')
                })

        # 2. Sort by Severity (High -> Medium -> Low)
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
            # Return top 5 distinct risks for the UI
            "top_risks": processed_risks[:5] 
        })

    return jsonify(response)


@dashboard_bp.route('/api/stats/ssl')
@login_required
def get_ssl_stats():
    """Returns aggregated stats for SSL Scanner with expiry calculation."""
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

    # File: ssl_report.json
    ssl_path = os.path.join(user_dir, 'ssl_scanner', 'ssl_report.json')
    ssl_data = load_json_safe(ssl_path)

    if ssl_data:
        cert_chain = ssl_data.get('certificate_chain', [])
        primary_cert = cert_chain[0] if cert_chain else {}
        
        # 1. Calculate Days Remaining
        # Format example: "Feb 25 15:49:26 2026 GMT"
        days_left_str = "Unknown"
        expiry_str = primary_cert.get('not_after', '')
        if expiry_str:
            try:
                # Strip ' GMT' and parse
                clean_date = expiry_str.replace(' GMT', '')
                expiry_dt = datetime.strptime(clean_date, "%b %d %H:%M:%S %Y")
                delta = expiry_dt - datetime.now()
                days_left_str = f"{delta.days} Days"
            except Exception:
                pass

        # 2. Key Information
        k_type = primary_cert.get('key_type', 'RSA')
        k_size = primary_cert.get('key_size', 'Unknown')
        key_info = f"{k_type} {k_size} bits"

        # 3. Check Protocols (Flag 1.0, 1.1, SSLv2, SSLv3)
        weak_protocols_found = []
        for proto in ssl_data.get('protocols', []):
            p_name = proto.get('name', '') # e.g., "1.0", "1.1"
            if proto.get('enabled') and p_name in ['SSLv2', 'SSLv3', '1.0', '1.1']:
                # Format "1.0" -> "TLS 1.0"
                full_name = f"TLS {p_name}" if p_name[0].isdigit() else p_name
                weak_protocols_found.append(full_name)

        # 4. Check Vulnerabilities
        vulns_list = ssl_data.get('vulnerabilities', [])
        # Deduplicate vulnerability names
        vuln_names = list(set([v.get('name') for v in vulns_list]))
        
        # Security Score Logic
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


@dashboard_bp.route('/api/stats/sniffer')
@login_required
def get_sniffer_stats():
    """Returns aggregated stats for Packet Sniffer (parses TShark text output)."""
    user_dir = get_user_results_dir()
    
    response = {
        "status": "Not Scanned",
        "target": "N/A", 
        "total_packets": 0,
        "duration": "0s",
        "unique_ips": 0,
        "protocol_breakdown": {}, # e.g. {'TCP': 50, 'UDP': 120}
        "top_talkers": []         # e.g. [{'src': '192.168.1.1', 'dst': '8.8.8.8', 'bytes': 500}]
    }

    if not user_dir: return jsonify(response)

    # File: pcap_analysis_report.json
    sniffer_path = os.path.join(user_dir, 'packet_sniffer', 'pcap_analysis_report.json')
    sniffer_data = load_json_safe(sniffer_path)

    if sniffer_data:
        summ = sniffer_data.get('traffic_summary', {})
        
        # 1. Basic Metrics
        response["status"] = "Analyzed"
        response["target"] = sniffer_data.get('target_ip', 'Unknown')
        response["total_packets"] = summ.get('total_packets', 0)
        response["duration"] = f"{round(summ.get('effective_capture_duration_seconds', 0), 2)}s"

        # 2. Extract Protocol Counts (Parsing the text hierarchy)
        # The JSON contains a list of strings mimicking a table. We look for "protocol  frames:N"
        proto_stats = summ.get('protocol_hierarchy_stats', [])
        protocols = {}
        
        for line in proto_stats:
            # Regex to find lines like: "   tcp     frames:51"
            # We skip 'eth', 'ip', 'frame' to focus on transport/app layer
            if "frames:" in line:
                match = re.search(r'\s+([a-z0-9]+)\s+frames:(\d+)', line)
                if match:
                    p_name = match.group(1).upper()
                    p_count = int(match.group(2))
                    
                    # Filter out low-level noise
                    if p_name not in ['FRAME', 'ETH', 'IP', 'DATA', 'VLAN']:
                        protocols[p_name] = p_count

        response["protocol_breakdown"] = protocols

        # 3. Top Talkers (Parsing TCP Conversation Stats)
        # We look for lines like: "192.168.29.48:28187 <-> 192.168.29.196:8009 ... 984 bytes"
        conv_stats = summ.get('tcp_conversation_stats', [])
        talkers = []
        
        for line in conv_stats:
            if "<->" in line:
                # Regex to extract IPs and Byte count
                # Matches: IP:Port <-> IP:Port ... N bytes
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

        # Sort by bytes (highest first) and take top 5
        talkers.sort(key=lambda x: x['bytes'], reverse=True)
        response["top_talkers"] = talkers[:5]
        
        # Estimate unique IPs from talkers if not explicit
        unique_ips = set()
        for t in talkers:
            unique_ips.add(t['source'])
            unique_ips.add(t['destination'])
        response["unique_ips"] = len(unique_ips)

    return jsonify(response)