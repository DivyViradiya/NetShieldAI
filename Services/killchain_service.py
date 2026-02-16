import os
import sys
import json
import time
import socket
import threading
import queue
import traceback
import uuid
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# --- Tool Imports ---
from Services.pentest_modules.recon import ReconScanner
from Services.pentest_modules.scanner import NetworkScanner
from Services.pentest_modules.crawler import WebCrawler
from Services.pentest_modules.custom_scanner import CustomScanner
from Services.pentest_modules.network_exploiter import NetworkExploiter
from Services.pentest_modules.tech_detector import TechDetector
from Services.pentest_modules.dir_fuzzer import DirectoryFuzzer
from Services.pentest_modules.waf_detector import WAFDetector
from Services.pentest_modules.logic_scanner import LogicScanner
from Services.pentest_modules.vuln_scanner import VulnScanner       
from Services.pentest_modules.zap_wrapper import ZAPScanner         
from Services.pentest_modules.traffic_analyzer import TrafficAnalyzer 

from Services import pdf_generator
# --- Import Scan Logger ---
from Services import scan_logger

# ==========================================
# 1. OUTPUT REDIRECTION (Isolated per User)
# ==========================================

scan_context = threading.local()
user_log_queues = {}
active_scans = {} # { "queue_id": {"target": str, "start_time": float} }
scan_lock = threading.Lock()

def get_scan_queue(queue_id):
    if queue_id not in user_log_queues:
        user_log_queues[queue_id] = queue.Queue()
    return user_log_queues[queue_id]

def is_scan_running(queue_id):
    """Checks if an audit is currently active for a specific user identifier."""
    with scan_lock:
        return queue_id in active_scans

def cleanup_queue(queue_id):
    if queue_id in user_log_queues:
        del user_log_queues[queue_id]

class SmartLogger:
    def __init__(self, original_stdout):
        self.original_stdout = original_stdout

    def write(self, message):
        queue_id = getattr(scan_context, 'queue_id', None)
        if queue_id and message.strip():
            try:
                get_scan_queue(queue_id).put(f"data: {message.strip()}\n\n")
            except: pass
        self.original_stdout.write(message)
        self.original_stdout.flush()

    def flush(self):
        self.original_stdout.flush()

if not isinstance(sys.stdout, SmartLogger):
    sys.stdout = SmartLogger(sys.stdout)

# ==========================================
# 3. LOGGING HELPERS
# ==========================================

def log(queue_id, message, level="INFO", to_console=True):
    timestamp = datetime.now().strftime("%H:%M:%S")
    formatted_msg = f"[{timestamp}] [{level}] {message}"
    print(formatted_msg) 

def send_sse_event(queue_id, event_name, data):
    if not queue_id: return
    data_str = json.dumps(data) if isinstance(data, (dict, list)) else str(data)
    sse_message = f"event: {event_name}\ndata: {data_str}\n\n"
    get_scan_queue(queue_id).put(sse_message)

# ==========================================
# 4. KILL CHAIN ORCHESTRATOR
# ==========================================

class KillChainService:
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=10)

    def _get_paths(self, user_output_dir, queue_id):
        base = Path(user_output_dir)
        reports_dir = base / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        service_dir = Path(__file__).parent.resolve()
        temp_dir = service_dir.parent / "Services" / "temp" / "killchain"
        temp_dir.mkdir(parents=True, exist_ok=True)

        # Multi-user unique pcap
        scan_uuid = str(uuid.uuid4())[:8]

        return {
            "root": base,
            "reports": reports_dir,
            "json_report": reports_dir / "killchain_report.json",
            "pdf_report": reports_dir / "killchain_report.pdf",
            "pcap_file": temp_dir / f"capture_{queue_id}_{scan_uuid}.pcap" 
        }

    def run_job(self, target, profile_name, aggression_level, queue_id, user_output_dir, log_id=None, app=None):
        scan_context.queue_id = queue_id
        
        # Track active audit
        with scan_lock:
            active_scans[queue_id] = {"target": target, "start_time": time.time()}

        try:
            tools = {
                "recon": ReconScanner(), "net": NetworkScanner(), "waf": WAFDetector(),
                "tech": TechDetector(), "crawler": WebCrawler(), "dir_fuzz": DirectoryFuzzer(),
                "injector": CustomScanner(), "logic": LogicScanner(), "vuln": VulnScanner(),
                "zap": ZAPScanner(), "exploiter": NetworkExploiter(), "traffic": TrafficAnalyzer()
            }

            paths = self._get_paths(user_output_dir, queue_id)
            results = {
                "target": target, "profile": profile_name,
                "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "recon": {}, "network": {}, "vulns": [], "urls": [], "tech": {}
            }

            log(queue_id, f"[START] Kill Chain Audit: {target}", "START")
            domain = target.replace("http://", "").replace("https://", "").split("/")[0]
            
            try: target_ip = socket.gethostbyname(domain)
            except: 
                send_sse_event(queue_id, "scan_failed", {"message": "DNS Failed"})
                return

            tools["traffic"].start_capture(target_ip, str(paths["pcap_file"]))

            log(queue_id, "[PHASE 1] RECONNAISSANCE - Surface Area Discovery")
            log(queue_id, "[STAGE] Scanning for subdomains and active hosts...")
            results["recon"] = tools["recon"].subdomain_scan(domain)
            log(queue_id, f"[+] Found {len(results['recon'].get('subdomains', []))} subdomains.")

            log(queue_id, "[PHASE 2] WEAPONIZATION - Vulnerability Assessment")
            log(queue_id, "[STAGE] Identifying technologies and application stack...")
            results["tech"] = tools["tech"].detect(target)
            
            log(queue_id, "[PHASE 3] DELIVERY - Attack Vector Mapping")
            log(queue_id, "[STAGE] Crawling application for input vectors...")
            results["urls"] = tools["crawler"].crawl(target)
            
            log(queue_id, "[PHASE 4] EXPLOITATION - Deep Vulnerability Verification")
            log(queue_id, "[STAGE] Running advanced vulnerability scanners...")
            results["vulns"] = tools["vuln"].scan(target)

            log(queue_id, "[PHASE 5] INSTALLATION - Persistence Analysis")
            log(queue_id, "[STAGE] Finalizing data aggregation and risk scoring...")

            log(queue_id, "Generating Comprehensive Reports...")
            with open(paths["json_report"], "w", encoding='utf-8') as f:
                json.dump(results, f, indent=4)

            pdf_generator.create_killchain_report_pdf(results, str(paths["pdf_report"]))
            if paths["pdf_report"].exists():
                time.sleep(1.5)
                log(queue_id, "SYSTEM_EVENT: READY_FOR_ANALYSIS")
                send_sse_event(queue_id, "report_ready", {"pdf_url": "/killchain/download_pdf"})

            send_sse_event(queue_id, "scan_complete", {})
            log(queue_id, "AUDIT COMPLETED.", "SUCCESS")

        except Exception as e:
            log(queue_id, f"FAILURE: {str(e)}", "ERROR")
        finally:
            # Unregister
            with scan_lock:
                if queue_id in active_scans:
                    del active_scans[queue_id]

            if 'tools' in locals(): tools["traffic"].stop_capture()
            if paths["pcap_file"].exists(): paths["pcap_file"].unlink()
            scan_context.queue_id = None
            time.sleep(5)
            cleanup_queue(queue_id)

killchain_service = KillChainService()
