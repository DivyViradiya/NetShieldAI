#!/usr/bin/env python3
import subprocess
import tempfile
import os
import sys
import ctypes
import socket
import re
import platform
import threading
import queue
import time
import json
import uuid
import psutil
from datetime import datetime, timezone
from pathlib import Path
from Services import report_manager
from .tctr_engine import tctr_engine

# --- Configuration Paths ---
BASE_DIR = Path(__file__).parent.parent

# Default global path (fallback)
DEFAULT_RESULTS_DIR = BASE_DIR / "Services" / "results" / "packet_sniffer"
DEFAULT_RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Logs (Shared)
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Centralized Temp
TEMP_DIR = Path(tempfile.gettempdir()) / "NetShieldAI" / "sniffer"
TEMP_DIR.mkdir(parents=True, exist_ok=True)

# --- Global State for Process Management (Isolated by user_id) ---
# We use a dictionary to track active processes per user
active_captures = {} # { "user_id": {"process": Popen, "stop_event": Event} }
capture_lock = threading.Lock()

# --- USER ISOLATION ---
user_queues = {}

def is_scan_running(user_id):
    """Checks if a capture is currently active for a specific user."""
    with capture_lock:
        return user_id in active_captures

def get_user_queue(user_id):
    """Ensures a queue exists for the user and returns it."""
    if user_id not in user_queues:
        user_queues[user_id] = queue.Queue()
    return user_queues[user_id]

# --- Logging and SSE Helpers ---

# --- Logging and SSE Helpers ---

from Services import scan_logger
from core.logger_setup import logger

# --- Logging and SSE Helpers ---

def log(message, user_id=None, to_console=False, level='INFO'):
    """
    Logs messages using the centralized scan_logger.
    """
    if to_console:
        if level.upper() == 'ERROR' or level.upper() == 'CRITICAL':
            logger.error(message)
        elif level.upper() == 'WARNING':
            logger.warning(message)
        else:
            logger.info(message)
    
    if user_id:
        scan_logger.write_log(user_id, "packet_sniffer", message, level=level)

def send_sse_event(event_name, data="", user_id=None):
    """
    Simulates SSE event by logging a special format line that tail_log_file can pick up.
    """
    if isinstance(data, (dict, list)):
        data_str = json.dumps(data)
    else:
        data_str = str(data)
    
    log(f"EVENT: {event_name} | PAYLOAD: {data_str}", user_id)

def clear_log_file(user_id):
    """Clears the log file and queue for a specific user."""
    if not user_id: return
    user_id = str(user_id)
    user_log_file = LOG_DIR / "users" / user_id / "packet_sniffer_log.txt"
    
    try:
        if user_log_file.exists():
            with open(user_log_file, 'w', encoding='utf-8') as f:
                f.write(f"--- Log cleared at {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
        
        # Clear Queue
        uq = get_user_queue(user_id)
        with uq.mutex:
            uq.queue.clear()
            
    except Exception as e:
        logger.error(f"FATAL: Could not clear log file: {e}")

# --- OS-Specific and Network Helpers ---

def _get_subprocess_creation_flags():
    """Returns appropriate creation flags for subprocess based on OS."""
    if platform.system() == "Windows":
        return subprocess.CREATE_NO_WINDOW
    return 0

def is_admin():
    """Checks if the script has administrator/root privileges."""
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    else:
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False

def ensure_admin_privileges(user_id=None):
    if is_admin():
        return True
    log("[!] Admin privileges missing.", user_id)
    return False

def get_local_ip():
    """Detects and returns the local IP address (best-effort)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_packet_capture_cmd():
    """Checks for the availability of the TShark tool."""
    candidates = ['tshark', r'C:\Program Files\Wireshark\tshark.exe', r'C:\Program Files (x86)\Wireshark\tshark.exe']
    for cmd in candidates:
        try:
            subprocess.run([cmd, '-h'], capture_output=True, text=True, check=True,
                           creationflags=_get_subprocess_creation_flags())
            return cmd
        except:
            continue
    return None

def list_available_interfaces(user_id=None):
    tshark_cmd = get_packet_capture_cmd()
    if not tshark_cmd:
        return {}

    interface_list = {}
    try:
        cmd = [tshark_cmd, '-D']
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True,
            creationflags=_get_subprocess_creation_flags(), encoding='utf-8'
        )

        for line in result.stdout.strip().split('\n'):
            parts = line.split('. ', 1)
            if len(parts) == 2:
                index = parts[0].strip()
                name_desc = parts[1].strip()
                match = re.match(r'(\S+)\s+\((.+)\)', name_desc)
                if match:
                    name = match.group(1)
                    description = match.group(2)
                else:
                    name = name_desc.split(' ', 1)[0]
                    description = name_desc
                interface_list[index] = {
                    "id": index,
                    "name": name,
                    "description": description
                }
        return interface_list
    except:
        return {}

def get_selected_interface(interface_id=None, user_id=None):
    interface_list = list_available_interfaces(user_id)
    if not interface_list:
        return None

    if interface_id and str(interface_id) in interface_list:
        selected_if = interface_list[str(interface_id)]
        log(f"[*] Interface selected: {selected_if['description']}", user_id, to_console=True)
        return selected_if['name']

    local_ip = get_local_ip()
    interfaces_by_ip = psutil.net_if_addrs()
    for name, addrs in interfaces_by_ip.items():
        for addr in addrs:
            if getattr(socket, 'AF_INET', None) and addr.family == socket.AF_INET and addr.address == local_ip:
                for if_data in interface_list.values():
                    if name in if_data['name'] or name in if_data['description']:
                        log(f"[*] Auto-detected interface: {if_data['description']}", user_id)
                        return if_data['name']
    return None

# --- PHASE 2: Dynamic Path Helper ---

def get_output_paths(output_dir=None, user_id=None, target=None, timestamp=None):
    if output_dir:
        base = Path(output_dir)
    else:
        base = DEFAULT_RESULTS_DIR
    
    if not base.exists():
        try:
            base.mkdir(parents=True, exist_ok=True)
        except:
            pass

    # Multi-user unique pcap filename
    scan_uuid = str(uuid.uuid4())[:8]
    pcap_filename = f"capture_{user_id if user_id else 'sys'}_{scan_uuid}.pcap"

    if target:
        if timestamp:
            sanitized = report_manager.sanitize_filename(target)
            stem = f"sniffer_{sanitized}_{timestamp}"
            json_filename = f"{stem}.json"
            pdf_filename = f"{stem}.pdf"
        else:
            json_filename = report_manager.generate_report_filename("pcap_analysis_report", target, "json")
            pdf_filename = report_manager.generate_report_filename("pcap_analysis_report", target, "pdf")
    else:
        json_filename = "pcap_analysis_report.json"
        pdf_filename = "pcap_analysis_report.pdf"

    return {
        "pcap": TEMP_DIR / pcap_filename,
        "json_report": base / json_filename,
        "pdf_report": base / pdf_filename 
    }

# --- Core Capture Logic ---

def run_packet_capture(target_ip, duration_seconds=30, interface_id=None, custom_bpf_filter=None, output_dir=None, user_id=None):
    """
    Runs a TShark capture in a subprocess in the background.
    Isolated per user.
    """
    ensure_admin_privileges(user_id) # Just logs a warning now if not admin

    capture_cmd = get_packet_capture_cmd()
    if not capture_cmd:
        return None

    # Defense-in-depth Target Validation
    try:
        from Services.target_validator import validate_ip_target, TargetBlockedError
        validate_ip_target(target_ip)
    except TargetBlockedError as e:
        log(f"[BLOCKED] Capture rejected by target validator for {target_ip}: {e}", user_id, level='ERROR')
        return None

    interface_name = get_selected_interface(interface_id=interface_id, user_id=user_id)
    if not interface_name:
        log("[!] Failed to find network interface.", user_id)
        return None

    filter_expression = custom_bpf_filter if custom_bpf_filter else f"host {target_ip}"
    paths = get_output_paths(output_dir, user_id=user_id)
    pcap_file_path = paths["pcap"]

    cmd = [
        capture_cmd, '-i', interface_name, '-w', str(pcap_file_path),
        '-f', filter_expression,
        '-a', f"duration:{duration_seconds}"
    ]

    log(f"[+] Starting capture for host {target_ip} on '{interface_name}'...", user_id, to_console=True)

    stop_event = threading.Event()
    
    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=_get_subprocess_creation_flags()
        )

        # Track this user's process
        with capture_lock:
            active_captures[user_id] = {"process": process, "stop_event": stop_event}

        while process.poll() is None and not stop_event.is_set():
            time.sleep(1)

        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except:
                process.kill()

        return_code = process.poll()
        if return_code is not None and return_code != 0:
            if stop_event.is_set():
                log(f"[*] Capture stopped by user request.", user_id, to_console=True)
            else:
                stderr = process.stderr.read().decode('utf-8', errors='replace')
                log(f"[!] TShark process exited with code {return_code}. Stderr: {stderr}", user_id, to_console=True)
                return None

        log(f"[+] Capture finished.", user_id, to_console=True)
        return str(pcap_file_path)

    except Exception as e:
        log(f"[!] Capture error: {e}", user_id)
        return None

    finally:
        with capture_lock:
            if user_id in active_captures:
                del active_captures[user_id]
        send_sse_event("capture_complete", str(pcap_file_path), user_id=user_id)

def stop_capture(user_id=None):
    """Signals the running capture for a SPECIFIC user to stop."""
    with capture_lock:
        if user_id in active_captures:
            log(f"[*] Stopping capture for user {user_id}", user_id)
            active_captures[user_id]["stop_event"].set()
            return True
    return False

# --- Analysis Logic ---

def get_traffic_statistics(pcap_path, user_id=None):
    stats_data = {}
    tshark_cmd = get_packet_capture_cmd()
    if not tshark_cmd: return stats_data

    try:
        # Protocol Hierarchy Statistics
        cmd_phs = [tshark_cmd, '-r', pcap_path, '-z', 'io,phs']
        result_phs = subprocess.run(cmd_phs, capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags(), encoding='utf-8')
        stats_data['protocol_distribution'] = result_phs.stdout.strip().split('\n')

        # TCP Conversation Statistics
        cmd_conv = [tshark_cmd, '-r', pcap_path, '-z', 'conv,tcp']
        result_conv = subprocess.run(cmd_conv, capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags(), encoding='utf-8')
        stats_data['tcp_conversations'] = result_conv.stdout.strip().split('\n')

        # --- IMPROVED SUMMARY EXTRACTION ---
        total_packets = 0
        total_bytes = 0
        
        # Look for the last line starting with "Filter:" or just the last line of Phs
        phs_lines = stats_data.get('protocol_distribution', [])
        for line in reversed(phs_lines):
            if 'frames:' in line and 'bytes:' in line:
                match_packets = re.search(r'frames:(\d+)', line)
                match_bytes = re.search(r'bytes:(\d+)', line)
                if match_packets: total_packets = int(match_packets.group(1))
                if match_bytes: total_bytes = int(match_bytes.group(1))
                break

        # --- DURATION CALCULATION ---
        duration = 0
        try:
            # Get first and last timestamp
            cmd_dur = [tshark_cmd, '-r', pcap_path, '-T', 'fields', '-e', 'frame.time_relative']
            result_dur = subprocess.run(cmd_dur, capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
            times = result_dur.stdout.strip().split('\n')
            if times:
                first = float(times[0])
                last = float(times[-1])
                duration = round(last - first, 2)
        except:
            pass

        if duration <= 0:
            try:
                import os
                ctime = os.path.getctime(pcap_path)
                mtime = os.path.getmtime(pcap_path)
                if mtime > ctime:
                    duration = round(mtime - ctime, 2)
            except:
                pass

        avg_rate = (total_bytes * 8) / duration if duration > 0 else 0


        stats_data['summary_io'] = {
            "total_packets": total_packets, 
            "total_bytes": total_bytes
        }
        stats_data['effective_capture_duration_seconds'] = duration
        stats_data['average_rate_bps'] = avg_rate
        
        log(f"[+] Statistics extracted. Packets: {total_packets}, Duration: {duration}s", user_id)
    except Exception as e:
        log(f"[!] Statistics extraction failed: {e}", user_id)
    return stats_data

def extract_application_flows(pcap_path, user_id=None):
    tshark_cmd = get_packet_capture_cmd()
    if not tshark_cmd: return {"flows": [], "summary": "N/A"}
    flow_data = []
    http_cmd = [
        tshark_cmd, '-r', pcap_path, '-Y', 'http', '-T', 'fields',
        '-e', 'frame.time', '-e', 'ip.src', '-e', 'ip.dst',
        '-e', 'http.request.method', '-e', 'http.request.full_uri',
        '-e', 'http.response.code', '-e', 'http.response.phrase',
        '-E', 'separator=,', '-E', 'header=y'
    ]
    try:
        result = subprocess.run(http_cmd, capture_output=True, text=True, check=False, creationflags=_get_subprocess_creation_flags(), encoding='utf-8')
        lines = result.stdout.strip().split('\n')
        if lines and len(lines) >= 2:
            header = lines[0].split(',')
            for line in lines[1:]:
                parts = line.split(',')
                if len(parts) == len(header):
                    flow = dict(zip(header, parts))
                    if flow.get('http.request.method'):
                        flow_data.append({
                            "timestamp": flow.get('frame.time'), "src_ip": flow.get('ip.src'),
                            "dst_ip": flow.get('ip.dst'), "method": flow.get('http.request.method'),
                            "uri": flow.get('http.request.full_uri'), "response_code": flow.get('http.response.code')
                        })
    except: pass
    return {"flows": flow_data, "summary": f"Extracted {len(flow_data)} HTTP flows."}

def detect_anomalies(analysis_report_data, target_ip, user_id=None):
    log("[*] Running Security Anomaly Detection...", user_id)
    anomalies = {"port_scans": [], "fragmentation_alerts": [], "web_attacks": [], "summary": "No anomalies."}
    syn_counter = {}
    
    for packet in analysis_report_data.get('dissected_packets', []):
        layers = packet.get('_source', {}).get('layers', {})
        ip_layer = layers.get('ip', {})
        tcp_layer = layers.get('tcp', {})
        
        src_ip = ip_layer.get('ip.src')
        dst_ip = ip_layer.get('ip.dst')
        if not (src_ip and dst_ip): continue

        if tcp_layer.get('tcp.flags.syn') == '1' and tcp_layer.get('tcp.flags.ack') == '0' and dst_ip == target_ip:
            syn_counter.setdefault(src_ip, set()).add(tcp_layer.get('tcp.dstport'))

    for src_ip, ports in syn_counter.items():
        if len(ports) >= 5:
            anomalies['port_scans'].append({"type": "Port Scan", "source_ip": src_ip, "details": f"Scanned {len(ports)} ports."})

    # Apply ML Threat Re-ranking to anomalies
    try:
        for category in ['port_scans', 'fragmentation_alerts', 'web_attacks']:
            if anomalies[category]:
                for item in anomalies[category]:
                    # Map to CWE-319 (Cleartext Transmission) or generic anomaly CWE
                    cwe_id = "319" if category == "web_attacks" else "200"
                    prediction_obj = tctr_engine.predict_risk(
                        item.get("type", "Anomaly"), 
                        item.get("details", ""), 
                        cwe_id=cwe_id
                    )
                    item["predicted_risk_score"] = prediction_obj["score"]
                    item["tctr_priority"] = prediction_obj["tctr_priority"]
                    item["base_score"] = prediction_obj["base_score"]
                    item["priority_level"] = prediction_obj["priority_level"]
                    item["risk_justification"] = prediction_obj["risk_justification"]
                
                # Sort category by score
                anomalies[category].sort(
                    key=lambda x: x.get('predicted_risk_score', 0),
                    reverse=True
                )
    except Exception as e:
        log(f"[!] ML Re-ranking failed for Anomaly Report: {e}", user_id)

    total = sum(len(v) for k, v in anomalies.items() if isinstance(v, list))
    if total > 0: anomalies['summary'] = f"Detected {total} anomalies."
    return anomalies

def analyze_pcap_to_json(pcap_path, target_ip, max_packets=50, user_id=None):
    if not Path(pcap_path).exists(): return {"status": "error"}
    
    packet_data = []
    try:
        display_filter = f"(ip.addr == {target_ip}) or (arp) or (dns)"
        cmd = [get_packet_capture_cmd(), '-r', pcap_path, '-T', 'json', '-Y', display_filter, '-c', str(max_packets)]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags(), encoding='utf-8')
        packet_data = json.loads(result.stdout)
    except: pass

    # Apply ML Reranking to dissected packets
    if packet_data:
        try:
            for p in packet_data:
                layers = p.get('_source', {}).get('layers', {})
                proto_full = layers.get('frame', {}).get('frame.protocols', "")
                proto = proto_full.split(':')[-1].upper() if proto_full else "DATA"
                length = layers.get('frame', {}).get('frame.len', "0")
                
                prediction_obj = tctr_engine.predict_risk(
                    f"Packet {proto}", 
                    f"Flow analysis packet. Len: {length}", 
                    cwe_id="200"
                )
                p['predicted_risk_score'] = prediction_obj["score"]
                p['tctr_priority'] = prediction_obj["tctr_priority"]
                p['base_score'] = prediction_obj["base_score"]
                p['priority_level'] = prediction_obj["priority_level"]
                p['risk_justification'] = prediction_obj["risk_justification"]
        except Exception as e:
            log(f"[!] Packet reranking failed: {e}", user_id)

    stats = get_traffic_statistics(pcap_path, user_id=user_id)
    flows = extract_application_flows(pcap_path, user_id=user_id)
    anomalies = detect_anomalies({"dissected_packets": packet_data, "application_flow_analysis": flows}, target_ip, user_id=user_id)

    return {
        "status": "success", "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_ip": target_ip, "pcap_file": str(pcap_path),
        "traffic_summary": stats, "application_flow_analysis": flows,
        "security_anomaly_report": anomalies, "packets_analyzed_detail": len(packet_data),
        "dissected_packets": packet_data
    }

def build_pdf_report_context(analysis_data):
    # (Existing context logic remains compatible)
    return {"metadata": analysis_data.get('traffic_summary', {}), "anomalies": analysis_data.get('security_anomaly_report', {}), "raw": analysis_data}

def save_json_report(analysis_data, output_dir=None, user_id=None, target=None, timestamp=None):
    paths = get_output_paths(output_dir, user_id=user_id, target=target, timestamp=timestamp)
    json_path = paths["json_report"]
    try:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(analysis_data, f, indent=4)
        log(f"[+] JSON report saved: {json_path}", user_id)
        return str(json_path)
    except: return None
