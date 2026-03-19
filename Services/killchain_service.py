import os
import tempfile
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
from Services import scan_logger
from Services import report_manager
from core.logger_setup import logger
from Services.tctr_engine import tctr_engine

# ==========================================
# 1. OUTPUT REDIRECTION (Isolated per User)
# ==========================================

scan_context = threading.local()
active_scans = {} # { "queue_id": {"target": str, "start_time": float} }
scan_lock = threading.Lock()

def is_scan_running(queue_id):
    """Checks if an audit is currently active for a specific user identifier."""
    with scan_lock:
        return queue_id in active_scans

def is_user_scanning(user_id):
    """Checks if ANY audit is currently active for a specific user ID."""
    user_id_str = f"{user_id}::"
    with scan_lock:
        return any(q_id.startswith(user_id_str) for q_id in active_scans)

# Note: active_scans and these helpers are still used for concurrency control, 
# but logging is now handled by scan_logger. queue_id is used as a unique identifier.

def cleanup_queue(queue_id):
    # No longer needed for logging, but kept if used elsewhere
    pass

class SmartLogger:
    def __init__(self, original_stdout):
        self.original_stdout = original_stdout

    def write(self, message):
        queue_id = getattr(scan_context, 'queue_id', None)
        if queue_id and message.strip():
            # Try to log to key file
            try:
                # queue_id is "user_id_scan_id"
                user_id = queue_id.split('_')[0]
                # Log to file via scan_logger helper logic (manual write to avoid import cycle/overhead)
                # But easiest is to call log() if we can
                # We'll just print to original stdout for now, and rely on explicit log() calls for persistence
                # or we can write to file.
                pass 
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
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_msg = f"[{timestamp}] [{level}] {message}"
    
    if to_console:
        if level in ["ERROR", "CRITICAL"]:
            logger.error(f"[{level}] {message}")
        elif level == "WARNING":
            logger.warning(f"[{level}] {message}")
        else:
            logger.info(f"[{level}] {message}")
        
    if queue_id:
        try:
            # Matches queue_id format: user_identifier::scan_id
            user_id = queue_id.split('::')[0]
            log_file = scan_logger.get_active_log_file(user_id, "killchain")
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"{formatted_msg}\n")
        except Exception as e:
            logger.error(f"ERROR: Failed to write to log file: {e}")

def send_sse_event(queue_id, event_name, data):
    """
    Simulates SSE event by logging a special format line that tail_log_file can pick up.
    """
    if not queue_id: return
    
    if isinstance(data, (dict, list)):
        data_str = json.dumps(data)
    else:
        data_str = str(data)
    
    # We log it so tail_log_file picks it up
    log(queue_id, f"EVENT: {event_name} | PAYLOAD: {data_str}", level="EVENT", to_console=False)

# ==========================================
# 4. KILL CHAIN ORCHESTRATOR
# ==========================================

class KillChainService:
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.SCAN_PROFILES = {
            "Recon Only": {
                "Normal": {
                    "phases": ["recon_phase", "tech_detect_phase"],
                    "recon_params": {"passive_only": True, "resolve_ips": True},
                    "tech_detect_params": {},
                    "aggression_tuning": { # for traffic analyzer
                        "threads": 10,
                        "delay": 0.5
                    }
                },
                "Stealth": {
                    "phases": ["recon_phase", "tech_detect_phase"],
                    "recon_params": {"passive_only": True, "resolve_ips": False},
                    "tech_detect_params": {"passive_only": True},
                    "aggression_tuning": {
                        "threads": 5,
                        "delay": 1.0
                    }
                },
            },
            "Network Audit": {
                "Normal": {
                    "phases": ["network_audit_phase"],
                    "network_audit_params": {"scan_type": "standard", "brute_force_level": "normal"},
                    "aggression_tuning": {
                        "threads": 15,
                        "delay": 0.2
                    }
                },
                "Stealth": {
                    "phases": ["network_audit_phase"],
                    "network_audit_params": {"scan_type": "stealth", "brute_force_level": "none"},
                    "aggression_tuning": {
                        "threads": 5,
                        "delay": 1.0
                    }
                },
                "Attack": {
                    "phases": ["network_audit_phase"],
                    "network_audit_params": {"scan_type": "full", "brute_force_level": "aggressive"},
                     "aggression_tuning": {
                        "threads": 20,
                        "delay": 0.1
                    }
                },
            },
            "Web Audit": {
                "Normal": {
                    "phases": ["waf_detect_phase", "web_audit_phase"],
                    "waf_detect_params": {},
                    "web_audit_params": {
                        "crawler_max_pages": 100, "crawler_max_threads": 5,
                        "dirfuzz_max_depth": 2, "dirfuzz_threads": 5,
                        "vuln_aggressive": False, "custom_aggressive": False
                    },
                    "aggression_tuning": {
                        "threads": 10,
                        "delay": 0.5
                    }
                },
                "Stealth": {
                    "phases": ["waf_detect_phase", "web_audit_phase"],
                    "waf_detect_params": {"provocation": False},
                    "web_audit_params": {
                        "crawler_max_pages": 50, "crawler_max_threads": 3,
                        "dirfuzz_enabled": False, # disable dir fuzz in stealth
                        "vuln_aggressive": False, "custom_aggressive": False
                    },
                    "aggression_tuning": {
                        "threads": 5,
                        "delay": 1.0
                    }
                },
                "Attack": {
                    "phases": ["waf_detect_phase", "web_audit_phase", "zap_scan_phase"],
                    "waf_detect_params": {"provocation": True},
                    "web_audit_params": {
                        "crawler_max_pages": 500, "crawler_max_threads": 10,
                        "dirfuzz_max_depth": 3, "dirfuzz_threads": 10,
                        "vuln_aggressive": True, "custom_aggressive": True
                    },
                    "zap_scan_params": {"full_scan": True},
                    "aggression_tuning": {
                        "threads": 15,
                        "delay": 0.2
                    }
                }
            },
            "Full Scan": {
                "Normal": {
                    "phases": ["recon_phase", "network_audit_phase", "waf_detect_phase", "web_audit_phase", "traffic_analysis_phase"],
                    "recon_params": {"passive_only": False, "resolve_ips": True},
                    "network_audit_params": {"scan_type": "standard", "brute_force_level": "normal"},
                    "waf_detect_params": {},
                    "web_audit_params": {
                        "crawler_max_pages": 200, "crawler_max_threads": 5,
                        "dirfuzz_max_depth": 2, "dirfuzz_threads": 5,
                        "vuln_aggressive": False, "custom_aggressive": False
                    },
                    "traffic_analysis_params": {},
                    "aggression_tuning": {
                        "threads": 10,
                        "delay": 0.5
                    }
                },
                "Stealth": {
                    "phases": ["recon_phase", "network_audit_phase", "waf_detect_phase", "web_audit_phase", "traffic_analysis_phase"],
                    "recon_params": {"passive_only": True, "resolve_ips": False},
                    "network_audit_params": {"scan_type": "stealth", "brute_force_level": "none"},
                    "waf_detect_params": {"provocation": False},
                    "web_audit_params": {
                        "crawler_max_pages": 50, "crawler_max_threads": 3,
                        "dirfuzz_enabled": False,
                        "vuln_aggressive": False, "custom_aggressive": False
                    },
                    "traffic_analysis_params": {},
                    "aggression_tuning": {
                        "threads": 5,
                        "delay": 1.0
                    }
                },
                "Attack": {
                    "phases": ["recon_phase", "network_audit_phase", "waf_detect_phase", "web_audit_phase", "zap_scan_phase", "traffic_analysis_phase"],
                    "recon_params": {"passive_only": False, "resolve_ips": True},
                    "network_audit_params": {"scan_type": "full", "brute_force_level": "aggressive"},
                    "waf_detect_params": {"provocation": True},
                    "web_audit_params": {
                        "crawler_max_pages": 1000, "crawler_max_threads": 20,
                        "dirfuzz_max_depth": 4, "dirfuzz_threads": 20,
                        "vuln_aggressive": True, "custom_aggressive": True
                    },
                    "zap_scan_params": {"full_scan": True},
                    "traffic_analysis_params": {"aggressive": True},
                    "aggression_tuning": {
                        "threads": 20,
                        "delay": 0.1
                    }
                },
            },
            "Reconfigure": { # Custom profile where everything can be tweaked
                "Normal": { # This will be the default fallback for "Reconfigure"
                    "phases": [], # Empty by default, user will define
                    "aggression_tuning": {"threads": 10, "delay": 0.5}
                }
            }
        }

    # --- Phase Execution Methods ---

    def _run_recon_phase(self, target, tools, results, queue_id, params):
        log(queue_id, "[PHASE] RECONNAISSANCE - Surface Area Discovery", "PHASE")
        log(queue_id, "[STAGE] Scanning for subdomains and active hosts...", "STAGE")
        
        domain = target.replace("http://", "").replace("https://", "").split("/")[0]
        
        recon_data = tools["recon"].subdomain_scan(domain)
        results["recon"]["subdomains"] = recon_data.get("subdomains", [])
        log(queue_id, f"[+] Found {len(results['recon']['subdomains'])} potential subdomains.")

        if params.get("resolve_ips", True) and results["recon"]["subdomains"]:
            log(queue_id, "[STAGE] Resolving subdomain IPs...", "STAGE")
            resolved_ips = tools["recon"].dns_resolver.bulk_resolve(results["recon"]["subdomains"])
            results["recon"]["resolved_hosts"] = resolved_ips
            log(queue_id, f"[+] Resolved {len(resolved_ips)} host IPs.")

        log(queue_id, "[STAGE] Detecting target technology stack...", "STAGE")
        tech_data = tools["tech"].detect(target)
        results["tech"] = tech_data
        log(queue_id, f"[+] Detected technologies: {', '.join(tech_data.get('technologies', {}).keys())}")
        
        return results

    def _run_network_audit_phase(self, target, tools, results, queue_id, params):
        log(queue_id, "[PHASE] NETWORK AUDIT - Infrastructure Assessment", "PHASE")
        domain = target.replace("http://", "").replace("https://", "").split("/")[0]
        target_ip = None
        try:
            target_ip = socket.gethostbyname(domain)
            results["target_ip"] = target_ip
            log(queue_id, f"[+] Resolved {domain} to IP: {target_ip}", "INFO")
        except socket.gaierror:
            log(queue_id, f"[!] Could not resolve IP for {domain}. Skipping network audit.", "ERROR")
            send_sse_event(queue_id, "scan_warning", {"message": f"DNS resolution failed for {domain}"})
            return results

        log(queue_id, f"[STAGE] Running Nmap {params.get('scan_type', 'standard')} scan on {target_ip}...", "STAGE")
        nmap_results = tools["net"].run_scan(target_ip, scan_type=params.get("scan_type", "standard"))
        results["network"]["nmap_scan"] = nmap_results
        log(queue_id, f"[+] Nmap scan completed. Found {len(nmap_results.get('ports', []))} open ports.", "INFO")
        
        # Extract open ports for exploiter
        open_ports_list = nmap_results.get('ports', [])
        
        if params.get("brute_force_level") != "none" and open_ports_list:
            log(queue_id, f"[STAGE] Attempting brute-force on open services (Level: {params.get('brute_force_level', 'normal')})...", "STAGE")
            exploiter_results = tools["exploiter"].run_all_brute_force(target_ip, open_ports_list)
            if exploiter_results:
                results["network"]["exploiter_findings"] = exploiter_results
                log(queue_id, f"[!] Exploiter found {len(exploiter_results)} potential weak credentials/exploits.", "WARNING")
            else:
                log(queue_id, "[+] No exploitable services found or brute-force failed.", "INFO")
        
        return results
        
    def _run_web_audit_phase(self, target, tools, results, queue_id, params):
        log(queue_id, "[PHASE] WEB AUDIT - Application Assessment", "PHASE")

        # NOTE: WAF detection is handled separately in waf_detect_phase for profiles
        # that include it. Only run here if it hasn't been run already.
        if "waf_detection" not in results.get("web_audit", {}):
            log(queue_id, "[STAGE] Checking for Web Application Firewall (WAF)...", "STAGE")
            waf_data = tools["waf"].detect(target)
            results["web_audit"]["waf_detection"] = waf_data
            if waf_data.get("has_waf"):
                log(queue_id, f"[!] WAF Detected: {waf_data.get('waf_name')}. Scanning will be adjusted.", "WARNING")
            else:
                log(queue_id, "[+] No WAF detected.", "INFO")

        log(queue_id, f"[STAGE] Crawling web application (Max Pages: {params.get('crawler_max_pages')})...", "STAGE")
        crawled_urls = tools["crawler"].crawl(
            target,
            max_pages=params.get("crawler_max_pages", 100),
            max_threads=params.get("crawler_max_threads", 5)
        )
        results["web_audit"]["crawled_urls"] = crawled_urls
        results["web_audit"]["forms_found"] = tools["crawler"].forms_found
        results["web_audit"]["api_endpoints"] = list(tools["crawler"].api_endpoints)
        log(queue_id, f"[+] Crawler found {len(crawled_urls)} URLs, {len(tools['crawler'].forms_found)} forms, and {len(tools['crawler'].api_endpoints)} API endpoints.", "INFO")

        if params.get("dirfuzz_enabled", True): # Dir fuzz can be disabled for stealth
            log(queue_id, f"[STAGE] Performing directory fuzzing (Max Depth: {params.get('dirfuzz_max_depth')})...", "STAGE")
            dir_fuzz_results = tools["dir_fuzz"].fuzz(
                target,
                technologies=results["tech"].get("technologies", {}),
                max_depth=params.get("dirfuzz_max_depth", 2)
            )
            results["web_audit"]["directory_fuzzing"] = dir_fuzz_results
            log(queue_id, f"[+] Directory fuzzer found {dir_fuzz_results.get('found_count', 0)} potential paths.", "INFO")
        else:
            log(queue_id, "[STAGE] Directory fuzzing disabled for this profile.", "INFO")

        log(queue_id, "[STAGE] Running advanced web vulnerability checks...", "STAGE")
        web_vuln_results = tools["vuln"].run_all_checks(target) # This runs the passive and web CVE checks
        results["web_audit"]["vuln_scanner_findings"] = web_vuln_results
        log(queue_id, f"[+] Web vulnerability scanner found {len(web_vuln_results)} findings.", "INFO")
        
        log(queue_id, "[STAGE] Running custom parameter injection scanner...", "STAGE")
        custom_scanner_results = tools["injector"].run_scan(target) # This runs active parameter injection
        results["web_audit"]["custom_scanner_findings"] = custom_scanner_results.get("findings", [])
        log(queue_id, f"[+] Custom scanner found {len(custom_scanner_results.get('findings', []))} findings.", "INFO")

        log(queue_id, "[STAGE] Running logic-based vulnerability checks...", "STAGE")
        logic_scanner_results = tools["logic"].run_scan(target)
        results["web_audit"]["logic_scanner_findings"] = logic_scanner_results.get("findings", [])
        log(queue_id, f"[+] Logic scanner found {len(logic_scanner_results.get('findings', []))} findings.", "INFO")
        
        return results
        
    def _run_zap_scan_phase(self, target, tools, results, queue_id, paths):
        log(queue_id, "[PHASE] ZAP SCAN - Comprehensive DAST", "PHASE")
        log(queue_id, "[STAGE] Starting OWASP ZAP quick scan...", "STAGE")
        
        # Pass a log_callback to ZAPScanner to pipe its output
        zap_log_callback = lambda msg: log(queue_id, msg, "ZAP")
        
        zap_results = tools["zap"].run_scan(target, log_callback=zap_log_callback)
        results["web_audit"]["zap_findings"] = zap_results
        
        if zap_results.get("error"):
            log(queue_id, f"[!] ZAP scan encountered an error: {zap_results['error']}", "ERROR")
        else:
            log(queue_id, f"[+] ZAP scan completed. Found {zap_results.get('summary', {}).get('Total', 0)} findings.", "INFO")
        
        return results

    def _run_traffic_analysis_phase(self, target, tools, results, queue_id, paths, params):
        log(queue_id, "[PHASE] TRAFFIC ANALYSIS - Post-Scan Forensics", "PHASE")
        log(queue_id, "[STAGE] Analyzing captured network traffic...", "STAGE")
        
        target_ip = results.get("target_ip")
        if not target_ip:
            log(queue_id, "[!] Target IP not found for traffic analysis. Skipping.", "ERROR")
            return results

        traffic_analysis_results = tools["traffic"].analyze_capture(target_ip)
        results["traffic_analysis"] = traffic_analysis_results
        
        if traffic_analysis_results.get("error"):
            log(queue_id, f"[!] Traffic analysis encountered an error: {traffic_analysis_results['error']}", "ERROR")
        else:
            log(queue_id, "[+] Traffic analysis completed.", "INFO")

        return results

    def _run_full_scan_phase(self, target, tools, results, queue_id, profile_config, paths):
        # This orchestrates calls to other phase methods based on the full scan profile
        # This method is primarily for conceptual grouping in the profile config.
        # The actual phases will be called iteratively in run_job.
        pass


    def _get_paths(self, user_output_dir, queue_id, target=None, timestamp=None):
        base = Path(user_output_dir)
        reports_dir = base / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        service_dir = Path(__file__).parent.resolve()
        temp_dir = Path(tempfile.gettempdir()) / "NetShieldAI" / "killchain"
        temp_dir.mkdir(parents=True, exist_ok=True)

        # Multi-user unique pcap
        scan_uuid = str(uuid.uuid4())[:8]

        if timestamp:
            sanitized = report_manager.sanitize_filename(target)
            json_name = f"killchain_{sanitized}_{timestamp}.json"
            pdf_name = f"killchain_{sanitized}_{timestamp}.pdf"
        else:
            json_name = report_manager.generate_report_filename("killchain", target, "json") if target else "killchain_report.json"
            pdf_name = report_manager.generate_report_filename("killchain", target, "pdf") if target else "killchain_report.pdf"

        return {
            "root": base,
            "reports": reports_dir,
            "json_report": reports_dir / json_name,
            "pdf_report": reports_dir / pdf_name,
            "pcap_file": temp_dir / f"capture_{queue_id}_{scan_uuid}.pcap" 
        }

    def run_job(self, target, profile_name, aggression_level, queue_id, user_output_dir, log_id=None, app=None, timestamp=None):
        scan_context.queue_id = queue_id
        
        # Track active audit
        with scan_lock:
            active_scans[queue_id] = {"target": target, "start_time": time.time(), "profile": profile_name, "aggression": aggression_level}

        paths = {}  # Always defined so finally block can reference it
        traffic_analyzer_started = False
        start_time = time.time()  # Always defined so error handlers can reference it

        try:
            # Validate profile and aggression level
            if profile_name not in self.SCAN_PROFILES:
                raise ValueError(f"Unknown scan profile: {profile_name}")
            
            profile_config = self.SCAN_PROFILES[profile_name]
            if aggression_level not in profile_config:
                # Fallback to 'Normal' if specific aggression level not defined for profile
                log(queue_id, f"WARNING: Aggression level '{aggression_level}' not defined for profile '{profile_name}'. Falling back to 'Normal'.", "WARNING")
                aggression_level = "Normal"
                
            current_profile_config = profile_config.get(aggression_level)
            if not current_profile_config:
                raise ValueError(f"Invalid aggression level '{aggression_level}' for profile '{profile_name}'")

            tools = {
                "recon": ReconScanner(), "net": NetworkScanner(), "waf": WAFDetector(),
                "tech": TechDetector(), "crawler": WebCrawler(), "dir_fuzz": DirectoryFuzzer(),
                "injector": CustomScanner(), "logic": LogicScanner(), "vuln": VulnScanner(),
                "zap": ZAPScanner(), "exploiter": NetworkExploiter(), "traffic": TrafficAnalyzer()
            }

            paths = self._get_paths(user_output_dir, queue_id, target=target, timestamp=timestamp)
            results = {
                "target": target, "profile": profile_name, "aggression": aggression_level,
                "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "recon": {}, "network": {}, "web_audit": {}, "vulns": [], "urls": [], "tech": {}
            }

            log(queue_id, f"[START] Kill Chain Audit: {target} (Profile: {profile_name}, Aggression: {aggression_level})", "START")
            send_sse_event(queue_id, "scan_status", {"message": "Starting scan...", "phase": "Initialization"})

            # Defense-in-depth Target Validation (Hard Blocks)
            try:
                from Services.target_validator import validate_target, TargetBlockedError
                validate_target(target, user_confirmed_auth=True)
            except TargetBlockedError as e:
                log(queue_id, f"[BLOCKED] Audit aborted by target validator for {target}: {e}", "CRITICAL")
                send_sse_event(queue_id, "scan_failed", {"message": f"Scan Prohibited: {str(e)}"})
                if log_id and app:
                    with app.app_context():
                         scan_logger.log_scan_end(log_id, status="Blocked", finding_count=0, duration=time.time() - start_time)
                return

            domain = target.replace("http://", "").replace("https://", "").split("/")[0]
            try: 
                target_ip = socket.gethostbyname(domain)
                results["target_ip"] = target_ip
                log(queue_id, f"[+] Resolved {domain} to IP: {target_ip}", "INFO")
            except socket.gaierror: 
                send_sse_event(queue_id, "scan_failed", {"message": "DNS resolution failed. Target unreachable."})
                log(queue_id, f"ERROR: DNS resolution failed for {domain}.", "ERROR")
                return

            # Traffic Analysis Management (Start if enabled in any phase)
            if "traffic_analysis_phase" in current_profile_config["phases"]:
                log(queue_id, "[SETUP] Starting background traffic capture...", "INFO")
                traffic_analyzer_started = tools["traffic"].start_capture(target_ip, str(paths["pcap_file"]))
                if not traffic_analyzer_started:
                    log(queue_id, "[!] WARNING: Traffic capture failed to start.", "WARNING")
                    send_sse_event(queue_id, "scan_warning", {"message": "Traffic capture failed to start."})
            
            # --- Execute Phases based on Profile ---
            for phase_name in current_profile_config["phases"]:
                send_sse_event(queue_id, "scan_status", {"message": f"Running {phase_name.replace('_', ' ').title()}...", "phase": phase_name})
                try:
                    if phase_name == "recon_phase":
                        params = current_profile_config.get("recon_params", {})
                        self._run_recon_phase(target, tools, results, queue_id, params)
                    elif phase_name == "network_audit_phase":
                        params = current_profile_config.get("network_audit_params", {})
                        self._run_network_audit_phase(target, tools, results, queue_id, params)
                    elif phase_name == "waf_detect_phase":
                        params = current_profile_config.get("waf_detect_params", {})
                        log(queue_id, "[PHASE] WAF DETECTION", "PHASE")
                        log(queue_id, "[STAGE] Checking for Web Application Firewall (WAF)...", "STAGE")
                        waf_data = tools["waf"].detect(target)
                        results["web_audit"]["waf_detection"] = waf_data
                        if waf_data.get("has_waf"):
                            log(queue_id, f"[!] WAF Detected: {waf_data.get('waf_name')}. Scanning will be adjusted.", "WARNING")
                        else:
                            log(queue_id, "[+] No WAF detected.", "INFO")
                    elif phase_name == "tech_detect_phase": # Can be standalone in Recon Only profile
                        params = current_profile_config.get("tech_detect_params", {})
                        log(queue_id, "[PHASE] TECHNOLOGY DETECTION", "PHASE")
                        log(queue_id, "[STAGE] Detecting target technology stack...", "STAGE")
                        tech_data = tools["tech"].detect(target)
                        results["tech"] = tech_data
                        log(queue_id, f"[+] Detected technologies: {', '.join(tech_data.get('technologies', {}).keys())}", "INFO")
                    elif phase_name == "web_audit_phase":
                        params = current_profile_config.get("web_audit_params", {})
                        self._run_web_audit_phase(target, tools, results, queue_id, params)
                    elif phase_name == "zap_scan_phase":
                        params = current_profile_config.get("zap_scan_params", {})
                        self._run_zap_scan_phase(target, tools, results, queue_id, paths)
                    elif phase_name == "traffic_analysis_phase":
                        params = current_profile_config.get("traffic_analysis_params", {})
                        # This phase is for *analyzing* the capture after other scans
                        if traffic_analyzer_started:
                            # Stop capture before analysis
                            log(queue_id, "[SETUP] Stopping background traffic capture for analysis...", "INFO")
                            tools["traffic"].stop_capture()
                            traffic_analyzer_started = False # Mark as stopped
                            self._run_traffic_analysis_phase(target, tools, results, queue_id, paths, params)
                        else:
                            log(queue_id, "[!] Traffic analysis phase skipped: capture was not started.", "WARNING")
                    elif phase_name == "full_scan_phase": # This is a conceptual phase name, actual phases are iterated
                         log(queue_id, "[PHASE] FULL SCAN - Comprehensive Assessment", "PHASE")
                    else:
                        log(queue_id, f"WARNING: Unknown phase '{phase_name}' in profile '{profile_name}'. Skipping.", "WARNING")
                except Exception as e:
                    log(queue_id, f"ERROR in {phase_name}: {str(e)}", "ERROR")
                    send_sse_event(queue_id, "scan_warning", {"message": f"Error in {phase_name}: {str(e)}"})
                    # Optionally, break or continue based on severity of error
            
            log(queue_id, "[PHASE] REPORT GENERATION - Finalizing Audit", "PHASE")
            send_sse_event(queue_id, "scan_status", {"message": "Generating reports...", "phase": "Report Generation"})

            # Aggregate all findings into a single list for consistent PDF generation
            all_findings = []
            if "network" in results and "exploiter_findings" in results["network"]:
                all_findings.extend(results["network"]["exploiter_findings"])
            if "web_audit" in results:
                if "vuln_scanner_findings" in results["web_audit"]:
                    all_findings.extend(results["web_audit"]["vuln_scanner_findings"])
                if "custom_scanner_findings" in results["web_audit"]:
                    all_findings.extend(results["web_audit"]["custom_scanner_findings"])
                if "logic_scanner_findings" in results["web_audit"]:
                    all_findings.extend(results["web_audit"]["logic_scanner_findings"])
                if "zap_findings" in results["web_audit"] and "findings" in results["web_audit"]["zap_findings"]:
                    all_findings.extend(results["web_audit"]["zap_findings"]["findings"])
            # Add other findings here as new phases are implemented

            # --- Apply ML Threat Re-ranking (TCTR) ---
            log(queue_id, "[STAGE] Applying ML Threat Re-ranking (TCTR)...", "STAGE")
            for f in all_findings:
                name = f.get("name") or f.get("type") or f.get("alert") or "Unknown Finding"
                desc = f.get("description") or f.get("evidence") or f.get("solution") or ""
                original_risk = f.get("risk") or f.get("severity") or "Info"
                cwe_id = f.get("cwe_id") or f.get("cweid") or None
                
                prediction = tctr_engine.predict_risk(name, desc, cwe_id)
                
                # Enrich finding with SOC Dashboard Metrics
                f["predicted_risk_score"] = prediction["score"]
                f["tctr_priority"] = prediction["tctr_priority"]
                f["base_score"] = prediction["base_score"]
                f["priority_level"] = prediction["priority_level"]
                f["risk_justification"] = prediction["risk_justification"]

            results["all_findings"] = all_findings


            log(queue_id, f"Generating Comprehensive Reports for {target}...", "INFO")
            with open(paths["json_report"], "w", encoding='utf-8') as f:
                json.dump(results, f, indent=4)

            # Ensure PDF generation can handle the new results structure
            pdf_generator.create_killchain_report_pdf(results, str(paths["pdf_report"]))
            
            if paths["pdf_report"].exists():
                time.sleep(1.5) # Give file system a moment
                send_sse_event(queue_id, "report_ready", {
                    "pdf_url": f"/killchain/download_pdf?target={target}",
                    "json_url": f"/killchain/download_json?target={target}",
                    "target": target
                })
            else:
                log(queue_id, "[!] PDF Report was not generated.", "ERROR")
                send_sse_event(queue_id, "scan_warning", {"message": "PDF Report failed to generate."})

            # Log Completion to Database
            if log_id and app:
                with app.app_context():
                     scan_logger.log_scan_end(log_id, status="Completed", finding_count=len(all_findings), duration=time.time() - start_time, report_path=str(paths["pdf_report"]) if paths["pdf_report"].exists() else None)

            send_sse_event(queue_id, "scan_complete", {"message": "Audit completed successfully!"})
            log(queue_id, "AUDIT COMPLETED.", "SUCCESS")

        except ValueError as ve:
            log(queue_id, f"CONFIGURATION ERROR: {str(ve)}", "CRITICAL")
            send_sse_event(queue_id, "scan_failed", {"message": f"Configuration Error: {str(ve)}"})
            if log_id and app:
                with app.app_context():
                     scan_logger.log_scan_end(log_id, status="Failed", finding_count=0, duration=time.time() - start_time)
        except Exception as e:
            log(queue_id, f"CRITICAL FAILURE: {str(e)}", "CRITICAL")
            send_sse_event(queue_id, "scan_failed", {"message": f"Critical Scan Failure: {str(e)}"})
            traceback.print_exc() # Print full traceback for debugging
            if log_id and app:
                with app.app_context():
                     scan_logger.log_scan_end(log_id, status="Failed", finding_count=0, duration=time.time() - start_time)
        finally:
            # Ensure traffic capture is stopped if it was started
            if traffic_analyzer_started:
                log(queue_id, "[CLEANUP] Stopping background traffic capture...", "INFO")
                tools["traffic"].stop_capture()
            
            if "pcap_file" in paths and paths["pcap_file"].exists():
                try:
                    paths["pcap_file"].unlink()
                    log(queue_id, f"[CLEANUP] Removed temporary PCAP file: {paths['pcap_file']}", "INFO")
                except Exception as e:
                    log(queue_id, f"[CLEANUP] Error removing PCAP file {paths['pcap_file']}: {e}", "ERROR")

            # Unregister scan
            with scan_lock:
                if queue_id in active_scans:
                    del active_scans[queue_id]
            
            scan_context.queue_id = None
            time.sleep(1) # Small delay before cleanup
            cleanup_queue(queue_id)
            log(queue_id, "Scan context cleaned up.", "INFO")
            send_sse_event(queue_id, "scan_finalized", {"message": "Cleanup complete."})

killchain_service = KillChainService()
