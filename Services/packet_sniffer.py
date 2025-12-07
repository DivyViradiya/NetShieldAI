#!/usr/bin/env python3
"""
Packet Sniffer / Analyzer (single-file)
- Integrated admin privilege auto-elevation (Windows UAC / Linux/macOS sudo)
- Robust parsing for frame.time_epoch (numeric or ISO string)
- Uses TShark for captures and analysis
- Writes JSON analysis report and optional PDF path (PDF generation not implemented here)
- Emits log messages to a queue (simulate SSE)
"""

import subprocess
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
import psutil
from datetime import datetime, timezone
from pathlib import Path

# --- Configuration Paths ---
BASE_DIR = Path(__file__).parent
RESULTS_DIR = Path(r"D:\NetShieldAI\Services\results\packet_sniffer")
ANALYSIS_REPORT_FILE = RESULTS_DIR / "pcap_analysis_report.json"
PCAP_FILE = RESULTS_DIR / "capture.pcap"
LOG_DIR = Path(r"D:\NetShieldAI\logs")
LOG_FILE = LOG_DIR / "packet_sniffer_log.txt"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ⭐ PDF Path Configuration (Must match BP) ⭐
PDF_OUTPUT_DIR = Path(r"D:\NetShieldAI\Services\PDFs")
PDF_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
PDF_REPORT_FILE = PDF_OUTPUT_DIR / "pcap_analysis_report.pdf"

# --- Global State for Threading Control ---
TCPDUMP_PROCESS = None
TCPDUMP_STOP_EVENT = threading.Event()
log_queue = queue.Queue()

# --- Logging and SSE Helpers ---

def log(message):
    """Logs messages to queue and file."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"data: [{timestamp}] {message}\n\n"
    try:
        log_queue.put(full_message)
    except Exception:
        pass

    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"ERROR: Failed to write log file: {e}", file=sys.stderr)

def send_sse_event(event_name, data=""):
    """Sends a custom SSE event to the log_queue."""
    if isinstance(data, (dict, list)):
        data_str = json.dumps(data)
    else:
        data_str = str(data)
    sse_message = f"event: {event_name}\ndata: {data_str}\n\n"
    try:
        log_queue.put(sse_message)
    except Exception:
        pass

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

def ensure_admin_privileges():
    """
    Ensures the program is running with admin/root privileges.
    If not, it automatically attempts elevation:
      • Windows → UAC prompt
      • Linux/macOS → sudo relaunch (exec)
    """
    if is_admin():
        log("[*] Administrator privileges confirmed.")
        return True

    log("[!] Admin privileges missing → attempting elevation...")

    try:
        if platform.system() == "Windows":
            params = " ".join(f'"{arg}"' for arg in sys.argv)
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                params,
                None,
                1
            )
            log("[*] Windows elevation requested via UAC. Exiting non-elevated process.")
            sys.exit(0)
        else:
            args = ['sudo', sys.executable] + sys.argv
            log("[*] Attempting to relaunch with sudo...")
            os.execvp("sudo", args)

    except Exception as e:
        log(f"[ERROR] Failed to elevate privileges: {e}")
        time.sleep(2)
        sys.exit(1)

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
    try:
        subprocess.run(['tshark', '-h'], capture_output=True, text=True, check=True,
                       creationflags=_get_subprocess_creation_flags())
        return 'tshark'
    except (FileNotFoundError, subprocess.CalledProcessError):
        log("[!] 'tshark' not found. Ensure Wireshark/TShark is installed and its directory is in your PATH.")
        return None

def list_available_interfaces():
    """
    Runs 'tshark -D' to list available interfaces and their descriptions.
    Returns a dictionary mapping interface ID (string) to data.
    """
    log("[*] Listing available network interfaces...")
    tshark_cmd = get_packet_capture_cmd()
    if not tshark_cmd:
        return {}

    interface_list = {}
    try:
        cmd = [tshark_cmd, '-D']
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            creationflags=_get_subprocess_creation_flags(),
            encoding='utf-8'
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

        log(f"[+] Found {len(interface_list)} interfaces.")
        return interface_list

    except subprocess.CalledProcessError as e:
        log(f"[!] Failed to list interfaces with tshark -D: {e.stderr.strip() if getattr(e, 'stderr', None) else str(e)}")
        return {}
    except Exception as e:
        log(f"[!] Unexpected error during interface listing: {e}")
        return {}

def get_selected_interface(interface_id=None):
    """
    Uses the tshark -D list to find the specified interface name or defaults to
    the best guess if no ID is provided (using the local IP logic).
    Returns the interface name (string) ready for TShark command, or None.
    """
    interface_list = list_available_interfaces()
    if not interface_list:
        return None

    if interface_id and str(interface_id) in interface_list:
        selected_if = interface_list[str(interface_id)]
        log(f"[*] User selected interface ID {interface_id}: {selected_if['description']}")
        return selected_if['name']

    local_ip = get_local_ip()
    if local_ip == "127.0.0.1":
        log(f"[!] Could not determine a suitable primary interface automatically.")
        return None

    interfaces_by_ip = psutil.net_if_addrs()
    for name, addrs in interfaces_by_ip.items():
        for addr in addrs:
            if getattr(socket, 'AF_INET', None) and addr.family == socket.AF_INET and addr.address == local_ip:
                for if_data in interface_list.values():
                    if name in if_data['name'] or name in if_data['description']:
                        log(f"[*] Auto-detected primary interface: {if_data['description']} (IP: {local_ip})")
                        return if_data['name']

    log(f"[!] Could not reliably auto-detect a primary interface name matching IP {local_ip}. Manual selection required.")
    return None

# --- Core Capture Logic ---

def run_packet_capture(target_ip, duration_seconds=30, interface_id=None, custom_bpf_filter=None):
    """
    Runs a TShark capture in a subprocess in the background.
    :param interface_id: Optional ID (string/int) of the interface to use (from tshark -D list).
    :param custom_bpf_filter: Optional custom BPF string (e.g., "tcp port 80").
    """
    global TCPDUMP_PROCESS, TCPDUMP_STOP_EVENT

    if not ensure_admin_privileges():
        return None

    capture_cmd = get_packet_capture_cmd()
    if not capture_cmd:
        return None

    interface_name = get_selected_interface(interface_id=interface_id)
    if not interface_name:
        log("[!] Cannot start capture: failed to find network interface.")
        return None

    if custom_bpf_filter:
        filter_expression = custom_bpf_filter
        log(f"[*] Using custom BPF filter: '{filter_expression}'")
    else:
        filter_expression = f"host {target_ip}"
        log(f"[*] Using default host filter: '{filter_expression}'")

    cmd = [
        capture_cmd, '-i', interface_name, '-w', str(PCAP_FILE),
        '-f', filter_expression,
    ]

    log(f"[+] Starting packet capture for host {target_ip} on '{interface_name}'...")

    TCPDUMP_STOP_EVENT.clear()
    try:
        if PCAP_FILE.exists():
            PCAP_FILE.unlink()
    except Exception as e:
        log(f"[!] Failed to remove existing PCAP file: {e}")

    try:
        TCPDUMP_PROCESS = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=_get_subprocess_creation_flags()
        )

        start_time = time.time()

        while TCPDUMP_PROCESS.poll() is None and not TCPDUMP_STOP_EVENT.is_set():
            time.sleep(1)
            if time.time() - start_time >= duration_seconds:
                log(f"[~] Capture time limit ({duration_seconds}s) reached. Stopping...")
                break

        if TCPDUMP_PROCESS.poll() is None:
            TCPDUMP_PROCESS.terminate()
            try:
                TCPDUMP_PROCESS.wait(timeout=5)
            except subprocess.TimeoutExpired:
                TCPDUMP_PROCESS.kill()
                log("[!] Forced termination of tshark process.")

        log(f"[+] Packet capture finished. Data saved to {PCAP_FILE}.")
        return str(PCAP_FILE)

    except Exception as e:
        log(f"[!] Error during packet capture: {e}")
        return None
    finally:
        TCPDUMP_PROCESS = None
        TCPDUMP_STOP_EVENT.clear()
        send_sse_event("capture_complete", str(PCAP_FILE))

def stop_capture():
    """Signals the running capture thread to stop."""
    global TCPDUMP_PROCESS
    if TCPDUMP_PROCESS:
        log("[*] Received stop signal. Setting stop event.")
        TCPDUMP_STOP_EVENT.set()
        return True
    log("[!] No active capture process to stop.")
    return False

# --- Analysis Logic with Statistics & Flow Reassembly ---

def get_traffic_statistics(pcap_path):
    """
    Uses TShark to generate Protocol Hierarchy Statistics and Conversation Stats.
    Returns a dictionary of gathered statistics.
    """
    stats_data = {}
    tshark_cmd = get_packet_capture_cmd()
    if not tshark_cmd:
        return stats_data

    try:
        cmd_phs = [tshark_cmd, '-r', pcap_path, '-z', 'io,phs']
        log("[*] Running TShark Protocol Hierarchy Statistics...")

        result_phs = subprocess.run(
            cmd_phs, capture_output=True, text=True, check=True,
            creationflags=_get_subprocess_creation_flags(), encoding='utf-8'
        )
        stats_data['protocol_distribution'] = result_phs.stdout.strip().split('\n')

        cmd_conv = [tshark_cmd, '-r', pcap_path, '-z', 'conv,tcp']
        log("[*] Running TShark TCP Conversation Statistics...")

        result_conv = subprocess.run(
            cmd_conv, capture_output=True, text=True, check=True,
            creationflags=_get_subprocess_creation_flags(), encoding='utf-8'
        )
        stats_data['tcp_conversations'] = result_conv.stdout.strip().split('\n')

        cmd_count = [tshark_cmd, '-r', pcap_path, '-q', '-z', 'io,stat,0']
        log("[*] Running TShark IO Summary Statistics...")
        subprocess.run(
            cmd_count, capture_output=True, text=True, check=True,
            creationflags=_get_subprocess_creation_flags(), encoding='utf-8'
        )

        total_packets = 0
        total_bytes = 0

        phs_lines = stats_data.get('protocol_distribution', [])
        for line in phs_lines:
            if line.strip().startswith('frame'):
                match_packets = re.search(r'frames:(\d+)', line)
                match_bytes = re.search(r'bytes:(\d+)', line)
                if match_packets:
                    total_packets = int(match_packets.group(1))
                if match_bytes:
                    total_bytes = int(match_bytes.group(1))
                break

        stats_data['summary_io'] = {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
        }

        log(f"[+] Traffic statistics successfully extracted. Packets: {total_packets}, Bytes: {total_bytes}")

    except subprocess.CalledProcessError as e:
        log(f"[!] TShark Statistics Failed: {e.stderr.strip() if getattr(e, 'stderr', None) else str(e)}")
    except Exception as e:
        log(f"[!] Unexpected error during statistics gathering: {e}")

    return stats_data

def extract_application_flows(pcap_path):
    """
    Uses TShark to extract reassembled application-layer data (e.g., HTTP requests/responses).
    Returns a dictionary of structured flow data.
    """
    log("[*] Starting application-layer flow analysis and reassembly...")
    tshark_cmd = get_packet_capture_cmd()
    if not tshark_cmd:
        return {"flows": [], "summary": "TShark not available."}

    flow_data = []

    http_cmd = [
        tshark_cmd,
        '-r', pcap_path,
        '-Y', 'http',
        '-T', 'fields',
        '-e', 'frame.time',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'http.request.method',
        '-e', 'http.request.full_uri',
        '-e', 'http.response.code',
        '-e', 'http.response.phrase',
        '-E', 'separator=,',
        '-E', 'header=y'
    ]

    try:
        result = subprocess.run(
            http_cmd,
            capture_output=True,
            text=True,
            check=False,
            creationflags=_get_subprocess_creation_flags(),
            encoding='utf-8'
        )

        lines = result.stdout.strip().split('\n')
        if not lines or len(lines) < 2:
            log("[*] No HTTP traffic found for flow extraction.")

        header = lines[0].split(',') if lines and 'frame.time' in lines[0] else []

        for line in lines[1:]:
            parts = line.split(',')
            if len(parts) == len(header):
                flow = dict(zip(header, parts))
                if flow.get('http.request.method'):
                    flow_data.append({
                        "timestamp": flow.get('frame.time'),
                        "src_ip": flow.get('ip.src'),
                        "dst_ip": flow.get('ip.dst'),
                        "method": flow.get('http.request.method'),
                        "uri": flow.get('http.request.full_uri'),
                        "response_code": flow.get('http.response.code'),
                        "response_phrase": flow.get('http.response.phrase'),
                    })

    except Exception as e:
        log(f"[!] Unexpected error during flow extraction: {e}")
        return {"flows": flow_data, "summary": f"Extraction failed due to error: {e}"}

    log(f"[+] Extracted {len(flow_data)} application-layer flows (HTTP).")
    return {"flows": flow_data, "summary": f"Successfully extracted {len(flow_data)} HTTP flows."}

def extract_security_features(analysis_report_data):
    """Iterates through dissected packets and extracts a concise list of security features."""
    log("[*] Starting feature extraction for AI Analyser...")

    feature_list = []

    for packet in analysis_report_data.get('dissected_packets', []):
        layers = packet.get('_source', {}).get('layers', {})
        ip_layer = layers.get('ip', {})
        src_ip = ip_layer.get('ip.src')
        dst_ip = ip_layer.get('ip.dst')

        if not (src_ip and dst_ip):
            continue

        protocol_num = ip_layer.get('ip.proto')
        protocol_name = ""
        transport_layer = {}

        if protocol_num == '6':
            protocol_name = "TCP"
            transport_layer = layers.get('tcp', {})
        elif protocol_num == '17':
            protocol_name = "UDP"
            transport_layer = layers.get('udp', {})
        elif protocol_num == '1':
            protocol_name = "ICMP"

        dst_port = transport_layer.get(f'{protocol_name.lower()}.dstport') if protocol_name else ""
        payload_len = transport_layer.get(f'{protocol_name.lower()}.length') if protocol_name else None
        is_encrypted = 'tls' in layers or 'ssl' in layers or (dst_port in ['443', '8443'] and protocol_name == 'TCP')

        feature_vector = {
            "time_relative": layers.get('frame', {}).get('frame.time_relative'),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol_name,
            "dst_port": dst_port,
            "is_encrypted": is_encrypted,
            "payload_len": int(payload_len) if payload_len and str(payload_len).isdigit() else 0,
        }

        feature_list.append(feature_vector)

    log(f"[+] Extracted {len(feature_list)} feature vectors for the AI.")
    return feature_list

# --- Security Anomaly Detection Module ---

def detect_anomalies(analysis_report_data, target_ip):
    """
    Analyzes dissected packets and application flows to detect common security anomalies.
    """
    log("[*] Starting Security Anomaly Detection...")
    anomalies = {
        "port_scans": [],
        "fragmentation_alerts": [],
        "protocol_violations": [],
        "cleartext_credentials": [],
        "summary": "No anomalies detected.",
    }

    syn_counter = {}
    total_fragments = 0

    for packet in analysis_report_data.get('dissected_packets', []):
        layers = packet.get('_source', {}).get('layers', {})
        ip_layer = layers.get('ip', {})
        tcp_layer = layers.get('tcp', {})

        src_ip = ip_layer.get('ip.src')
        dst_ip = ip_layer.get('ip.dst')

        if not (src_ip and dst_ip):
            continue

        if tcp_layer.get('tcp.flags.syn') == '1' and dst_ip == target_ip:
            dst_port = tcp_layer.get('tcp.dstport')
            syn_counter.setdefault(src_ip, set()).add(dst_port)

        if ip_layer.get('ip.flags.mf') == '1' or ip_layer.get('ip.frag_offset') not in (None, '0', 0):
            total_fragments += 1
            if total_fragments > 5 and not anomalies['fragmentation_alerts']:
                anomalies['fragmentation_alerts'].append({
                    "type": "Excessive IP Fragmentation",
                    "details": f"Total fragmented packets: {total_fragments}. Could indicate evasion.",
                    "source_ip": src_ip,
                    "target_ip": dst_ip
                })

        if tcp_layer:
            is_fin = tcp_layer.get('tcp.flags.fin') == '1'
            is_urg = tcp_layer.get('tcp.flags.urg') == '1'
            is_psh = tcp_layer.get('tcp.flags.push') == '1' or tcp_layer.get('tcp.flags.psh') == '1'
            if is_fin and is_urg and is_psh:
                anomalies['protocol_violations'].append({
                    "type": "TCP Protocol Violation (Xmas Scan)",
                    "details": "FIN, URG, and PSH flags set in a single TCP packet, typical of a Xmas tree scan.",
                    "source_ip": src_ip,
                    "target_ip": dst_ip,
                    "frame_number": layers.get('frame', {}).get('frame.number')
                })

    PORT_SCAN_THRESHOLD = 5
    for src_ip, ports_set in syn_counter.items():
        if len(ports_set) >= PORT_SCAN_THRESHOLD:
            anomalies['port_scans'].append({
                "type": "TCP Port Scan Detected",
                "details": f"Source IP {src_ip} sent SYN packets to {len(ports_set)} unique ports on target IP {target_ip}.",
                "source_ip": src_ip,
                "unique_ports_hit": len(ports_set)
            })

    for flow in analysis_report_data.get('application_flow_analysis', {}).get('flows', []):
        method = flow.get('method', '').upper()
        uri = flow.get('uri', '')
        if method in ['GET', 'POST', 'PUT'] and not (flow.get('response_code') == '302' or str(uri).lower().startswith('https')):
            if re.search(r'password|credential|auth|login', uri, re.IGNORECASE):
                anomalies['cleartext_credentials'].append({
                    "type": "Cleartext Credential Leak (Potential)",
                    "details": f"Unencrypted {method} request with sensitive keywords in URI: {uri}",
                    "source_ip": flow.get('src_ip'),
                    "timestamp": flow.get('timestamp')
                })

    if any(len(v) > 0 for k, v in anomalies.items() if k != "summary"):
        anomalies['summary'] = f"Detected {sum(len(v) for k, v in anomalies.items() if k != 'summary')} total anomalies."
        log(f"[!!!] ANOMALIES DETECTED: {anomalies['summary']}")
    else:
        log("[+] No security anomalies detected.")

    return anomalies

# --- Helper: Robust time parsing ---

def _parse_frame_time_epoch(val):
    """
    Return epoch seconds as float. Accepts:
      - Numeric strings like '1672531200.123456'
      - ISO timestamps like '2025-11-30T09:27:05.743112000Z'
    """
    if val is None:
        return 0.0
    # direct numeric
    try:
        return float(val)
    except Exception:
        pass
    # try ISO format
    try:
        s = str(val)
        if s.endswith('Z'):
            s = s[:-1]
        if '.' in s:
            date_part, frac = s.split('.', 1)
            frac = frac[:6]  # microseconds max
            s = f"{date_part}.{frac}"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return 0.0

# --- Main Analysis Function ---

def analyze_pcap_to_json(pcap_path, target_ip, max_packets=20):
    """Analyzes the PCAP file using TShark to generate a JSON report, including statistics, flows, and anomalies."""
    if not Path(pcap_path).exists():
        return {"status": "error", "message": "PCAP file not found"}

    analysis_start_time = time.time()
    packet_data = []

    # 1. Get raw packet dissections
    try:
        display_filter = f"(ip.addr == {target_ip}) and not (arp or dns)"
        cmd = [
            get_packet_capture_cmd(), '-r', pcap_path, '-T', 'json',
            '-Y', display_filter, '-c', str(max_packets)
        ]
        log(f"[*] Running TShark packet dissection command...")

        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True,
            creationflags=_get_subprocess_creation_flags(), encoding='utf-8'
        )
        packet_data = json.loads(result.stdout)

    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        log(f"[!] TShark Packet Dissection Failed: {getattr(e, 'stderr', str(e)).strip()}")

    # 2. Get traffic statistics
    traffic_stats = get_traffic_statistics(pcap_path)

    # 3. Get application-layer flows
    application_flows = extract_application_flows(pcap_path)

    # 4. Get security anomaly detections
    security_anomalies = detect_anomalies(
        {"dissected_packets": packet_data, "application_flow_analysis": application_flows},
        target_ip
    )

    analysis_end_time = time.time()

    # Calculate capture duration using robust parser
    capture_duration = 0.0
    try:
        time_epochs = []
        for p in packet_data:
            raw = p.get('_source', {}).get('layers', {}).get('frame', {}).get('frame.time_epoch', None)
            epoch = _parse_frame_time_epoch(raw)
            if epoch and epoch > 0:
                time_epochs.append(epoch)
        if time_epochs:
            min_time = min(time_epochs)
            max_time = max(time_epochs)
            capture_duration = max_time - min_time
    except Exception:
        capture_duration = 0.0

    total_bytes = traffic_stats.get('summary_io', {}).get('total_bytes', 0)
    effective_duration = capture_duration if capture_duration > 0.0 else 1.0
    rate_bps = total_bytes / effective_duration if effective_duration else 0

    final_report = {
        "status": "success",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_ip": target_ip,
        "pcap_file": str(pcap_path),
        "analysis_time_seconds": round(analysis_end_time - analysis_start_time, 2),
        "traffic_summary": {
            "total_packets": traffic_stats.get('summary_io', {}).get('total_packets', 0),
            "total_bytes": total_bytes,
            "effective_capture_duration_seconds": round(effective_duration, 2),
            "average_rate_bps": round(rate_bps, 2),
            "protocol_hierarchy_stats": traffic_stats.get('protocol_distribution', ["N/A"]),
            "tcp_conversation_stats": traffic_stats.get('tcp_conversations', ["N/A"]),
        },
        "application_flow_analysis": application_flows,
        "security_anomaly_report": security_anomalies,
        "packets_analyzed_detail": len(packet_data),
        "dissected_packets": packet_data
    }

    return final_report

import math
from datetime import datetime, timezone

def _safe_get(list_or_none, idx, default=None):
    try:
        return list_or_none[idx]
    except Exception:
        return default

def _parse_proto_lines(proto_lines):
    """
    Convert protocol_hierarchy_stats (text lines) into structured list:
    [{'name':'tcp', 'frames':6, 'bytes':764, 'example_line': '...'}, ...]
    """
    entries = []
    if not proto_lines:
        return entries

    # Join to single text and look for lines like "  tcp                                frames:6 bytes:764"
    text = "\n".join(proto_lines)
    # simple regex for lines with 'frames:' and 'bytes:'
    import re
    for m in re.finditer(r'([A-Za-z0-9\(\)\s\/\._+-]{1,50})\s+frames:(\d+)\s+bytes:(\d+)', text):
        name = m.group(1).strip()
        frames = int(m.group(2))
        bytes_ = int(m.group(3))
        entries.append({
            "name": name,
            "frames": frames,
            "bytes": bytes_,
            "example_line": m.group(0)
        })
    # If no matches found, try to parse the per-packet lines as examples
    return entries

def _parse_tcp_conv_lines(conv_lines):
    """
    Parse tcp_conversation_stats into structured conversations. Will look for a summary line
    such as: "192.168.29.48:26214        <-> 192.168.29.196:8009              2 328 bytes       4 436 bytes       6 764 bytes     0.000000000         5.0823"
    Returns list of dicts with src, src_port, dst, dst_port, frames, bytes, duration
    """
    convs = []
    if not conv_lines:
        return convs
    import re
    text = "\n".join(conv_lines)
    # find lines with pattern "<->"
    for line in text.splitlines():
        if "<->" in line:
            parts = re.split(r'\s{2,}', line.strip())
            # basic parsing, tolerant to format variance
            try:
                # first part contains endpoints
                endpoints = parts[0].strip()
                # endpoints like "192.168.29.48:26214        <-> 192.168.29.196:8009"
                ep_match = re.match(r'([^<]+)<->\s*([^\s]+)', endpoints)
                if not ep_match:
                    # fallback: split on <-> token
                    left, right = endpoints.split('<->')
                    left = left.strip()
                    right = right.strip()
                else:
                    left = ep_match.group(1).strip()
                    right = ep_match.group(2).strip()

                # After endpoints there should be summary numbers somewhere in parts
                # We'll try to extract total frames/bytes from the combined string
                rest = " ".join(parts[1:]) if len(parts) > 1 else line
                # Grab the totals: look for pattern like "6 764 bytes" or "... 6 764 bytes"
                tot_match = re.search(r'(\d+)\s+(\d+)\s+bytes', rest)
                frames_total = None
                bytes_total = None
                if tot_match:
                    # Sometimes 'frames bytes' grouping is reversed across columns — be tolerant
                    frames_total = int(tot_match.group(1))
                    bytes_total = int(tot_match.group(2))
                # Duration attempt
                dur_match = re.search(r'(\d+\.\d+)$', line.strip())
                duration = float(dur_match.group(1)) if dur_match else None

                # split left/right ip:port
                def split_ipport(s):
                    if ':' in s:
                        ip, port = s.rsplit(':', 1)
                        return ip.strip(), port.strip()
                    return s.strip(), ''
                src_ip, src_port = split_ipport(left)
                dst_ip, dst_port = split_ipport(right)

                convs.append({
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "frames": frames_total,
                    "bytes": bytes_total,
                    "duration": duration,
                    "raw": line.strip()
                })
            except Exception:
                # skip lines we can't parse
                continue
    return convs

def _build_packet_timeline(dissected_packets, max_entries=100):
    """
    Build a small chronological list of packets suitable for templates:
    [{time_iso, time_relative, frame_number, src, dst, proto, length, short_info}, ...]
    """
    out = []
    if not dissected_packets:
        return out
    for p in dissected_packets[:max_entries]:
        layers = p.get('_source', {}).get('layers', {})
        frame = layers.get('frame', {})
        ip = layers.get('ip', {})
        tcp = layers.get('tcp', {})
        udp = layers.get('udp', {})
        tls = layers.get('tls', {})

        # time parsing: prefer frame.time or frame.time_epoch
        t_iso = frame.get('frame.time') or frame.get('frame.time_utc') or frame.get('frame.time_epoch')
        # fallback to now
        if not t_iso:
            t_iso = datetime.now(timezone.utc).isoformat()

        src = ip.get('ip.src') or ''
        dst = ip.get('ip.dst') or ''
        proto = ''
        if tcp:
            proto = 'TCP'
        elif udp:
            proto = 'UDP'
        elif 'icmp' in layers:
            proto = 'ICMP'
        elif tls:
            proto = 'TLS'

        length = int(frame.get('frame.len')) if frame.get('frame.len') and str(frame.get('frame.len')).isdigit() else None
        # short info — first line of the example packet text if available
        short_info = None
        # attempt to get tcp payload summary or tls.app_data_proto etc
        if tls and tls.get('tls.record', {}):
            short_info = tls.get('tls.record', {}).get('tls.app_data_proto') or 'TLS Application Data'
        elif tcp and tcp.get('tcp.flags_tree'):
            short_info = tcp.get('tcp.flags_tree', {}).get('tcp.flags.str') or ''
        # Append
        out.append({
            "time": t_iso,
            "time_relative": frame.get('frame.time_relative'),
            "frame_number": frame.get('frame.number'),
            "src": src,
            "dst": dst,
            "proto": proto,
            "length": length,
            "info": short_info
        })
    return out

def _sample_packet_hexdump(dissected_packets, sample_count=3, bytes_limit=256):
    """
    Extract some printable hex or payload snippets to include as examples.
    """
    out = []
    if not dissected_packets:
        return out
    for p in dissected_packets[:sample_count]:
        layers = p.get('_source', {}).get('layers', {})
        # prefer tcp.payload, udp.payload, or raw frame bytes if available
        payload = ''
        if 'tcp' in layers:
            payload = layers.get('tcp', {}).get('tcp.payload') or ''
        if not payload and 'udp' in layers:
            payload = layers.get('udp', {}).get('udp.payload') or ''
        # Limit length for the PDF
        if isinstance(payload, str):
            clean_payload = payload.replace(':', '')  # remove separators if colon hex
            clean_payload = clean_payload[:bytes_limit*2]
            out.append(clean_payload)
        else:
            out.append('')
    return out

def build_pdf_report_context(analysis_data):
    """
    Given the raw analysis_data (the JSON you currently save), produce a richer
    context dict that's easy to render from Jinja templates and includes:
     - metadata summary (packets/bytes/duration)
     - structured protocol list
     - structured TCP conversations
     - top talkers (simple src IP grouping)
     - timeline (chronological short view)
     - sample packet payloads (hex)
     - extracted features (if present)
     - anomalies (if present)
     - application flows
    """
    if not analysis_data or not isinstance(analysis_data, dict):
        return {"error": "No data"}

    # Basic metadata
    traffic = analysis_data.get('traffic_summary', {})
    meta = {
        "pcap_file": analysis_data.get('pcap_file'),
        "target_ip": analysis_data.get('target_ip'),
        "analysis_time_seconds": analysis_data.get('analysis_time_seconds'),
        "total_packets": traffic.get('total_packets') or 0,
        "total_bytes": traffic.get('total_bytes') or 0,
        "effective_capture_duration_seconds": traffic.get('effective_capture_duration_seconds') or 0,
        "average_rate_bps": traffic.get('average_rate_bps') or 0
    }

    # Protocol breakdown
    proto_lines = traffic.get('protocol_hierarchy_stats', [])
    protocols = _parse_proto_lines(proto_lines)
    # If parse failed, try to fallback to raw text chunks
    if not protocols and proto_lines:
        protocols = [{"name": l, "frames": None, "bytes": None, "example_line": l} for l in proto_lines]

    # TCP conversation parsing
    conv_lines = traffic.get('tcp_conversation_stats', [])
    conversations = _parse_tcp_conv_lines(conv_lines)

    # Top talkers: quick aggregation by src IP from dissected_packets
    top_talkers = {}
    for p in analysis_data.get('dissected_packets', []):
        layers = p.get('_source', {}).get('layers', {})
        ip = layers.get('ip', {})
        src = ip.get('ip.src')
        if not src:
            continue
        top_talkers.setdefault(src, {"frames": 0, "bytes": 0})
        # Try to increment frames by 1 and bytes by frame.len if available
        top_talkers[src]["frames"] += 1
        frame_len = layers.get('frame', {}).get('frame.len')
        if frame_len and str(frame_len).isdigit():
            top_talkers[src]["bytes"] += int(frame_len)

    # Convert top_talkers dict to sorted list
    top_talkers_list = sorted(
        [{"ip": ip, "frames": v["frames"], "bytes": v["bytes"]} for ip, v in top_talkers.items()],
        key=lambda x: x["bytes"], reverse=True
    )

    # Packet timeline
    timeline = _build_packet_timeline(analysis_data.get('dissected_packets', []), max_entries=200)

    # Sample hexdumps
    sample_payloads = _sample_packet_hexdump(analysis_data.get('dissected_packets', []), sample_count=5)

    # Features (if extract_security_features was run)
    features = analysis_data.get('extracted_features') or analysis_data.get('features') or []
    # If features are not present but a function exists, attempt to generate it
    try:
        if not features and 'extract_security_features' in globals():
            features = extract_security_features(analysis_data)
    except Exception:
        features = features

    # Anomalies
    anomalies = analysis_data.get('security_anomaly_report') or {}

    # Application flows
    app_flows = analysis_data.get('application_flow_analysis') or {"flows": [], "summary": ""}

    # Build final context
    context = {
        "metadata": meta,
        "protocols": protocols,
        "tcp_conversations": conversations,
        "top_talkers": top_talkers_list,
        "timeline": timeline,
        "sample_payloads": sample_payloads,
        "features": features,
        "anomalies": anomalies,
        "application_flows": app_flows,
        # include raw analysis_data for any template-level ad-hoc access
        "raw": analysis_data
    }

    return context


def save_json_report(analysis_data):
    """Saves the final analysis dictionary to a JSON file."""
    try:
        with open(ANALYSIS_REPORT_FILE, 'w', encoding='utf-8') as f:
            json.dump(analysis_data, f, indent=4)
        log(f"[+] Analysis report saved to {ANALYSIS_REPORT_FILE}")
        return str(ANALYSIS_REPORT_FILE)
    except Exception as e:
        log(f"[!] Failed to save JSON report: {e}")
        return None

def run_analyzer_service(target_ip: str, capture_duration_seconds: int = 10, interface_id: str = None, bpf_filter: str = None, max_packets_for_detail: int = 50):
    """
    The primary function to execute the full packet sniffer and analyzer workflow.

    1. Ensures admin privileges.
    2. Runs a TShark packet capture for the specified duration and filter.
    3. Analyzes the resulting PCAP file to generate a comprehensive JSON report.

    :param target_ip: The primary IP address to focus the capture and analysis on.
    :param capture_duration_seconds: How long to run the live capture (default: 10s).
    :param interface_id: Optional ID of the interface to use (from tshark -D).
    :param bpf_filter: Optional custom BPF string (e.g., "tcp port 80").
    :param max_packets_for_detail: Max number of packets to include in the detailed JSON dissection.
    :return: The final analysis report dictionary or None on fatal failure.
    """
    log("--- STARTING PACKET ANALYZER SERVICE ---")

    # 1. Check for TShark and Admin Privileges
    if not get_packet_capture_cmd():
        log("[FATAL] TShark not found. Aborting service.")
        return {"status": "error", "message": "TShark executable not found."}
    
    # Privilege check is done inside run_packet_capture, but we can do a quick check here too
    if not is_admin():
        # If admin is missing, we rely on the auto-elevation logic
        log("[WARNING] Running without confirmed admin rights. Attempting elevation now...")
        # Note: If elevation fails, the whole process will exit inside ensure_admin_privileges()

    # Determine BPF filter
    final_filter = bpf_filter if bpf_filter is not None else f"host {target_ip}"
    
    # 2. Start and Wait for Packet Capture
    capture_thread = threading.Thread(
        target=run_packet_capture,
        args=(target_ip, capture_duration_seconds, interface_id, final_filter)
    )
    capture_thread.start()
    capture_thread.join()

    # 3. Analyze the PCAP file
    if PCAP_FILE.exists():
        log("--- STARTING PCAP ANALYSIS ---")
        try:
            report_data = analyze_pcap_to_json(str(PCAP_FILE), target_ip, max_packets=max_packets_for_detail)
            
            # 4. Save and Summarize Report
            save_json_report(report_data)

            if report_data.get('status') == 'success':
                # Re-run feature extraction since analyze_pcap_to_json doesn't save it to report_data
                features = extract_security_features(report_data)
                
                log(f"Extracted Features Sample: {features[:5]}")
                log(f"Application Flow Summary: {report_data['application_flow_analysis'].get('summary', 'N/A')}")
                
                anomaly_summary = report_data['security_anomaly_report'].get('summary', 'N/A')
                log(f"Security Anomaly Summary: {anomaly_summary}")
                if anomaly_summary != "No anomalies detected.":
                    log(f"Full Anomaly Report: {json.dumps(report_data['security_anomaly_report'], indent=2)}")

            log("--- SERVICE COMPLETED ---")
            return report_data
        
        except Exception as e:
            log(f"[FATAL] Analysis failed: {e}")
            return {"status": "error", "message": f"Analysis failed: {str(e)}"}
    else:
        log("[!!!] PCAP file was not created. Check administrator privileges, TShark installation, or interface selection.")
        return {"status": "error", "message": "PCAP file creation failed."}


# --- Entry Point Demo (REPLACEMENT) ---

if __name__ == '__main__':
    # 1. Ensure elevation first, as everything else depends on it
    # If this fails, the script will exit. If it relaunches successfully, it will run the rest.
    ensure_admin_privileges()

    # --- Test Parameters ---
    TARGET_IP = "192.168.29.48"
    CAPTURE_TIME = 30
    
    # Test with a specific filter (e.g., target IP, focusing only on HTTP)
    CUSTOM_FILTER = f"host {TARGET_IP} and tcp port 80"
    
    # Display interfaces for user information, but allow run_analyzer_service to auto-detect
    interfaces = list_available_interfaces()
    if interfaces:
        print("\nAvailable Interfaces (Select an ID to use it explicitly):")
        for idx, data in interfaces.items():
            print(f"  {idx}. {data['description']} ({data['name']})")
    
    # Set interface_to_use to None to rely on auto-detection logic in get_selected_interface
    interface_to_use = None 
    
    print(f"\n--- Running Full Test Workflow for IP: {TARGET_IP} (Duration: {CAPTURE_TIME}s) ---")
    
    final_report = run_analyzer_service(
        target_ip=TARGET_IP, 
        capture_duration_seconds=CAPTURE_TIME,
        interface_id=interface_to_use,
        bpf_filter=CUSTOM_FILTER,
        max_packets_for_detail=100
    )

    print("\n--- SIMULATED SSE/LOG OUTPUT ---")
    while not log_queue.empty():
        try:
            print(log_queue.get().strip())
        except Exception:
            break
            
    if final_report and final_report.get('status') == 'success':
        print(f"\n✅ Final Report Status: {final_report.get('status')}. See {ANALYSIS_REPORT_FILE} for full details.")
