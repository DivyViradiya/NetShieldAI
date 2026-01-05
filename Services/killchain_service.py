import os
import sys
import json
import time
import socket
import threading
import queue
import traceback
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

# ==========================================
# 1. OUTPUT REDIRECTION (THE FIX)
# ==========================================

# Thread-local storage: Allows us to know WHICH scan (queue_id) 
# the current running thread belongs to.
scan_context = threading.local()

user_log_queues = {}

def get_scan_queue(queue_id):
    if queue_id not in user_log_queues:
        user_log_queues[queue_id] = queue.Queue()
    return user_log_queues[queue_id]

def cleanup_queue(queue_id):
    if queue_id in user_log_queues:
        del user_log_queues[queue_id]

class SmartLogger:
    """
    Intercepts sys.stdout (print).
    1. It ALWAYS prints to the real server console (so you can debug).
    2. If the current thread has a 'queue_id' set, it ALSO pushes the text to that user's stream.
    """
    def __init__(self, original_stdout):
        self.original_stdout = original_stdout

    def write(self, message):
        # 1. Print to server console as normal
        self.original_stdout.write(message)
        self.original_stdout.flush()

        # 2. Check if this thread is part of a user scan
        # This captures prints from ALL tools running in this thread
        if hasattr(scan_context, 'queue_id') and scan_context.queue_id:
            # We only push if there is actual content (ignore blank newlines sometimes sent by print)
            if message.strip(): 
                try:
                    q = get_scan_queue(scan_context.queue_id)
                    # Push as raw SSE data
                    # We strip to avoid double newlines in the UI, then append \n\n for SSE protocol
                    safe_msg = message.strip()
                    q.put(f"data: {safe_msg}\n\n")
                except Exception:
                    pass 

    def flush(self):
        self.original_stdout.flush()

# Apply the hook globally ONCE
# Now, every print() in the system goes through SmartLogger
if not isinstance(sys.stdout, SmartLogger):
    sys.stdout = SmartLogger(sys.stdout)


# ==========================================
# 2. CONFIGURATION & CONSTANTS
# ==========================================

PROFILE_PHASES = {
    "full_audit": {"recon", "tech", "network", "discovery", "web_exploit", "cve", "brute"},
    "recon_only": {"recon", "tech"},
    "web_audit":  {"recon", "tech", "discovery", "web_exploit"},
    "network_audit": {"recon", "network", "cve", "brute"}
}

CONFIG_MAP = {
    "stealth": { "threads": 2, "request_delay": 2.0, "nmap_mode": "quick", "waf_bypass": True, "brute_force": False },
    "normal":  { "threads": 15, "request_delay": 0.5, "nmap_mode": "standard", "waf_bypass": False, "brute_force": True },
    "attack":  { "threads": 50, "request_delay": 0.0, "nmap_mode": "full", "waf_bypass": False, "brute_force": True }
}

# ==========================================
# 3. LOGGING HELPERS
# ==========================================

def log(queue_id, message, level="INFO"):
    """
    Explicit logger for the service steps.
    Since we hooked sys.stdout, we just need to PRINT here.
    SmartLogger will handle sending it to the queue.
    """
    if not queue_id:
        print(f"[{level}] {message}") 
        return

    timestamp = datetime.now().strftime("%H:%M:%S")
    formatted_msg = f"[{timestamp}] [{level}] {message}"
    
    # Simple print triggers the SmartLogger logic
    print(formatted_msg) 

def send_sse_event(queue_id, event_name, data):
    """
    Sends structured events (like progress bars).
    These bypass print() because they are technical events, not logs.
    """
    if not queue_id: return
    
    if isinstance(data, (dict, list)): data_str = json.dumps(data)
    else: data_str = str(data)
    
    sse_message = f"event: {event_name}\ndata: {data_str}\n\n"
    q = get_scan_queue(queue_id)
    q.put(sse_message)

# ==========================================
# 4. KILL CHAIN ORCHESTRATOR
# ==========================================

class KillChainService:
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=5)

    def _get_paths(self, user_output_dir):
        """
        Setup paths.
        1. Reports go to the user directory (e.g. .../killchain/reports)
        2. Artifacts (pcap) go to the global pentest_modules/scan_results directory
        """
        # User Output: We assume user_output_dir is the full path (e.g., .../DivyViradiya_1/killchain)
        base = Path(user_output_dir)
        
        # Create reports directory in the user folder
        reports_dir = base / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        # Global Artifacts: Locate Services/pentest_modules/scan_results relative to this script
        service_dir = Path(__file__).parent.resolve()
        artifacts_dir = service_dir / "pentest_modules" / "scan_results"
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        return {
            "root": base,
            "pcaps": artifacts_dir, # Updated to point to global artifacts
            "reports": reports_dir,
            "json_report": reports_dir / "killchain_report.json",
            "pdf_report": reports_dir / "killchain_report.pdf",
            # This ensures capture.pcap is saved in pentest_modules/scan_results
            "pcap_file": artifacts_dir / "capture.pcap" 
        }

    def run_job(self, target, profile_name, aggression_level, queue_id, user_output_dir):
        """
        The main logic loop.
        """
        # --- CRITICAL: Set Thread Context ---
        # This tells SmartLogger that ANY print() in this thread belongs to this user.
        scan_context.queue_id = queue_id
        
        try:
            # Instantiate tools locally
            tools = {
                "recon": ReconScanner(),
                "net": NetworkScanner(),
                "waf": WAFDetector(),
                "tech": TechDetector(),
                "crawler": WebCrawler(),
                "dir_fuzz": DirectoryFuzzer(),
                "injector": CustomScanner(),
                "logic": LogicScanner(),
                "vuln": VulnScanner(),         
                "zap": ZAPScanner(),           
                "exploiter": NetworkExploiter(),
                "traffic": TrafficAnalyzer()    
            }

            paths = self._get_paths(user_output_dir)
            results = {
                "target": target, "profile": profile_name,
                "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "recon": {}, "network": {}, "vulns": [], "vulns_grouped": {}, 
                "urls": [], "tech": {}, "traffic_analysis": {}, "zap_report": {}
            }

            log(queue_id, f"[START] Starting Kill Chain Audit on {target}", "START")
            
            config = CONFIG_MAP.get(aggression_level, CONFIG_MAP["normal"])
            phases = PROFILE_PHASES.get(profile_name, PROFILE_PHASES["full_audit"])

            raw_target = target
            domain = raw_target.replace("http://", "").replace("https://", "").split("/")[0]
            base_url = "http://" + domain if not raw_target.startswith("http") else raw_target
            target_ip = "0.0.0.0"

            # --- IP Resolution ---
            try:
                target_ip = socket.gethostbyname(domain)
                log(queue_id, f"Resolved IP: {target_ip}")
            except:
                log(queue_id, "Could not resolve IP address. Aborting scan.", "CRITICAL")
                send_sse_event(queue_id, "scan_failed", {"message": "DNS Resolution Failed"})
                time.sleep(2)
                cleanup_queue(queue_id)
                return

            # --- PHASE 0: TRAFFIC ---
            log(queue_id, "Starting Flight Recorder (Traffic Capture)...")
            # Uses the new path: pentest_modules/scan_results/capture.pcap
            tools["traffic"].start_capture(target_ip, str(paths["pcap_file"]))

            # --- PHASE 1: RECON ---
            if "recon" in phases:
                send_sse_event(queue_id, "progress_update", {"percent": 10, "phase": "Reconnaissance"})
                log(queue_id, "[PHASE 1] RECONNAISSANCE...")
                
                # Any print() inside these tools is now captured!
                waf_info = tools["waf"].detect(base_url)
                if waf_info.get('has_waf'):
                    log(queue_id, f"[WARN] WAF DETECTED: {waf_info.get('waf_name')}. Throttling requests.", "WARNING")
                    config["threads"] = max(2, config["threads"] // 2)
                
                recon_data = tools["recon"].subdomain_scan(domain)
                results["recon"] = recon_data
                log(queue_id, f"Recon Complete. Found {len(recon_data.get('subdomains', []))} subdomains.")

            # --- PHASE 2: TECH ---
            if "tech" in phases:
                send_sse_event(queue_id, "progress_update", {"percent": 25, "phase": "Tech Detection"})
                log(queue_id, "[PHASE 2] TECH FINGERPRINTING...")
                results["tech"] = tools["tech"].detect_tech(base_url)
                log(queue_id, f"Identified technologies: {', '.join(results['tech'].get('technologies', []))}")

            # --- PHASE 3: NETWORK ---
            open_ports_list = []
            if "network" in phases:
                send_sse_event(queue_id, "progress_update", {"percent": 40, "phase": "Network Scan"})
                log(queue_id, f"[PHASE 3] NETWORK SCAN ({target_ip})...")
                
                net_data = tools["net"].run_scan(target_ip, scan_type=config['nmap_mode'])
                results["network"] = net_data
                open_ports_list = net_data.get("ports", [])
                log(queue_id, f"Network Scan Complete. {len(open_ports_list)} ports open.")

            # --- PHASE 4: DISCOVERY ---
            all_urls = []
            if "discovery" in phases:
                send_sse_event(queue_id, "progress_update", {"percent": 55, "phase": "Content Discovery"})
                log(queue_id, "[PHASE 4] DISCOVERY & CRAWLING...")
                
                crawled = tools["crawler"].crawl(base_url, max_threads=config['threads'])
                
                tools["dir_fuzz"].threads = config['threads']
                tech_sigs = results.get("tech", {}).get("technologies", [])
                
                fuzzed = tools["dir_fuzz"].fuzz(base_url, technologies=tech_sigs)
                
                all_urls = list(set(crawled + [f['url'] for f in fuzzed.get('findings', [])]))
                results["urls"] = all_urls
                log(queue_id, f"Discovery Complete. Total URLs found: {len(all_urls)}")

            # --- PHASE 5: VULNERABILITY ---
            if "web_exploit" in phases:
                send_sse_event(queue_id, "progress_update", {"percent": 75, "phase": "Vulnerability Analysis"})
                log(queue_id, "[PHASE 5] VULNERABILITY ANALYSIS...")

                log(queue_id, "Running Python Native Deep Scan...")
                vuln_findings = tools["vuln"].run_all_checks(domain, open_ports=open_ports_list)
                results["vulns"].extend(vuln_findings)

                log(queue_id, f"Running OWASP ZAP Scan on {base_url}...")
                
                def zap_logger(msg):
                    # We just print. SmartLogger handles the rest.
                    print(f"[ZAP] {msg}")

                zap_report = tools["zap"].run_scan(base_url, log_callback=zap_logger)
                
                if "error" not in zap_report:
                    results["zap_report"] = zap_report
                    for finding in zap_report.get("findings", []):
                        results["vulns"].append({
                            "type": f"ZAP: {finding['name']}",
                            "severity": finding.get('risk', 'Medium'),
                            "evidence": finding.get('url', 'N/A'),
                            "description": finding.get('description', 'No description')
                        })
                    log(queue_id, "ZAP Scan completed successfully.")
                else:
                    log(queue_id, f"ZAP Scan Failed: {zap_report['error']}", "ERROR")

                targets = [u for u in all_urls if "?" in u]
                if not targets: targets = [base_url]
                if aggression_level == "stealth": targets = targets[:5]

                log(queue_id, f"Testing {len(targets)} URLs for Logic/Injection flaws...")
                for i, url in enumerate(targets):
                    if config["request_delay"] > 0: time.sleep(config["request_delay"])
                    inj_res = tools["injector"].run_scan(url)
                    results["vulns"].extend(inj_res.get("findings", []))
                    log_res = tools["logic"].run_scan(url)
                    results["vulns"].extend(log_res.get("findings", []))

            # --- PHASE 6: BRUTE FORCE ---
            if "brute" in phases and config["brute_force"]:
                send_sse_event(queue_id, "progress_update", {"percent": 90, "phase": "Brute Force"})
                log(queue_id, "[PHASE 6] BRUTE FORCE...")
                ports = results.get("network", {}).get("ports", [])
                if ports:
                    services = [{'port': p['port'], 'service': p['service']} for p in ports]
                    tools["exploiter"].threads = config["threads"]
                    bf_res = tools["exploiter"].run_all_brute_force(target_ip, services)
                    results["vulns"].extend(bf_res)
                else:
                    log(queue_id, "No open ports eligible for brute force.")

            # --- DEDUPLICATION ---
            log(queue_id, "Processing and deduplicating findings...")
            unique_vulns = []
            seen_hashes = set()
            for v in results["vulns"]:
                v_type = v.get('type', 'Unknown')
                v_evidence = v.get('evidence') or v.get('url') or 'General'
                sig = (v_type, v_evidence)
                if sig not in seen_hashes:
                    seen_hashes.add(sig)
                    unique_vulns.append(v)
            
            severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
            unique_vulns.sort(key=lambda x: severity_rank.get(x.get('severity', 'Info'), 5))
            results["vulns"] = unique_vulns
            
            grouped_vulns = {k: [] for k in severity_rank.keys()}
            for v in unique_vulns:
                sev = v.get('severity', 'Info')
                if sev not in grouped_vulns: grouped_vulns[sev] = []
                grouped_vulns[sev].append(v)
            results["vulns_grouped"] = grouped_vulns

        except Exception as e:
            log(queue_id, f"CRITICAL FAILURE: {str(e)}", "ERROR")
            log(queue_id, traceback.format_exc(), "DEBUG")

        finally:
            # --- CLEANUP & REPORTING ---
            send_sse_event(queue_id, "progress_update", {"percent": 95, "phase": "Finalizing"})
            log(queue_id, "Stopping Flight Recorder...", "FINALIZE")
            
            # Stop tools
            if 'tools' in locals() and "traffic" in tools:
                tools["traffic"].stop_capture()
                if paths["pcap_file"].exists():
                    analysis = tools["traffic"].analyze_capture(target_ip)
                    results["traffic_analysis"] = analysis
                    if analysis.get("anomalies"):
                        log(queue_id, f"Traffic Analysis detected {len(analysis['anomalies'])} anomalies.", "WARNING")
                        results["vulns"].extend(analysis["anomalies"])
            
            # Save JSON
            try:
                with open(paths["json_report"], "w", encoding='utf-8') as f:
                    json.dump(results, f, indent=4, default=str)
                log(queue_id, f"JSON Report Saved: {paths['json_report']}")
            except Exception as e:
                log(queue_id, f"Failed to save JSON: {e}", "ERROR")

            # Generate PDF
            try:
                log(queue_id, "Generating PDF Report...")
                pdf_generator.create_killchain_report_pdf(results, str(paths["pdf_report"]))
                if paths["pdf_report"].exists():
                    log(queue_id, f"PDF Report Generated: {paths['pdf_report']}")
                    send_sse_event(queue_id, "report_ready", {
                        "json_url": "/killchain/get_json_report",
                        "pdf_url": "/killchain/download_pdf"
                    })
                else:
                    log(queue_id, "PDF generation failed (file not found).", "ERROR")
            except Exception as e:
                log(queue_id, f"PDF Generation Error: {e}", "ERROR")

            send_sse_event(queue_id, "progress_update", {"percent": 100, "phase": "Complete"})
            send_sse_event(queue_id, "scan_complete", {})
            log(queue_id, "KILL CHAIN AUDIT COMPLETED.", "SUCCESS")
            
            # Clear Thread Context so this thread can be reused safely by pool (if used later)
            scan_context.queue_id = None
            
            time.sleep(10)
            cleanup_queue(queue_id)

killchain_service = KillChainService()