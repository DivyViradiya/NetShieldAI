import subprocess
import sys
import os
import ssl
import socket
import json
import threading
import time
import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime, timezone

# Services and Core
from core.extensions import db
from models.models import Asset, DomainInventory, User, ScanLog
from core.time_utils import get_now_ist_str, get_now_ist_naive
from Services import scan_logger, report_manager, pdf_generator
from Services.target_validator import validate_target, TargetBlockedError

# [NEW] Pentest Modules
from Services.pentest_modules.recon import ReconScanner, SubdomainFinder
from Services.pentest_modules.tech_detector import TechDetector
from Services.pentest_modules.crawler import WebCrawler
from Services.pentest_modules.dir_fuzzer import DirectoryFuzzer

# Initialize singletons for the service
_recon = ReconScanner()
_tech_detect = TechDetector()
_crawler = WebCrawler()
_fuzzer = DirectoryFuzzer(threads=5)


BASE_DIR = Path(__file__).parent.parent

# Results isolation
RESULTS_DIR = BASE_DIR / ".results" / "asset_discovery"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# --- Global State for Process Management ---
active_scans = {}  # { user_id: {"target": str, "start_time": float, "log_id": int} }
scan_lock = threading.Lock()

def is_scan_running(user_id):
    """Checks if a discovery scan is currently active for a specific user."""
    with scan_lock:
        return user_id in active_scans

# --- Logging Helper ---
def log(user_id_or_ident, message, level='INFO'):
    """
    Writes a log message to both debug and active stream.
    Accepts user_id (int) or user_identifier (str).
    """
    scan_logger.write_log(user_id_or_ident, "asset_discovery", message, level=level)


# =============================================================================
# NATIVE OSINT ENGINES (Replaces Subfinder, Assetfinder, Amass)
# =============================================================================

def _query_hackertarget(domain, user_id):
    """Queries HackerTarget for subdomain enumeration."""
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            lines = response.text.splitlines()
            subdomains = [line.split(',')[0].strip().lower() for line in lines if ',' in line]
            return [s for s in subdomains if domain in s]
    except Exception as e:
        log(user_id, f"[!] HackerTarget query failed: {e}", level='DEBUG')
    return []

def _query_threatcrowd(domain, user_id):
    """Queries ThreatCrowd for subdomains."""
    try:
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            subdomains = [s.strip().lower() for s in data.get('subdomains', [])]
            return [s for s in subdomains if domain in s]
    except Exception as e:
        log(user_id, f"[!] ThreatCrowd query failed: {e}", level='DEBUG')
    return []

def _query_alienvault(domain, user_id):
    """Queries AlienVault OTX for passive DNS entries."""
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            subdomains = set()
            for record in data.get('passive_dns', []):
                hostname = record.get('hostname', '').strip().lower()
                if hostname and domain in hostname:
                    subdomains.add(hostname)
            return list(subdomains)
    except Exception as e:
        log(user_id, f"[!] AlienVault query failed: {e}", level='DEBUG')
    return []

def _query_anubis(domain, user_id):
    """Queries Anubis for subdomains."""
    try:
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list):
                return [s.strip().lower() for s in data if domain in s]
    except Exception as e:
        log(user_id, f"[!] Anubis query failed: {e}", level='DEBUG')
    return []


# =============================================================================
# STAGE 1 — SUBDOMAIN DISCOVERY WRAPPERS
# =============================================================================

def run_subfinder(domain, user_id):
    """Native Implementation: Replaces Subfinder with HackerTarget + crt.sh."""
    log(user_id, f"[*] Launching Passive Discovery (Subfinder-equiv) for {domain}...")
    subdomains = set()
    
    # Aggregate from native sources
    subdomains.update(_query_hackertarget(domain, user_id))
    
    found = list(subdomains)
    log(user_id, f"[+] Passive Discovery (Subfinder-equiv) found {len(found)} subdomains.")
    return found


def run_assetfinder(domain, user_id):
    """Native Implementation: Replaces Assetfinder with ThreatCrowd + Anubis."""
    log(user_id, f"[*] Launching Passive Discovery (Assetfinder-equiv) for {domain}...")
    subdomains = set()
    
    subdomains.update(_query_threatcrowd(domain, user_id))
    subdomains.update(_query_anubis(domain, user_id))
    
    found = list(subdomains)
    log(user_id, f"[+] Passive Discovery (Assetfinder-equiv) found {len(found)} subdomains.")
    return found


def run_amass(domain, user_id):
    """Native Implementation: Replaces Amass with AlienVault + Deep OSINT Sweep."""
    log(user_id, f"[*] Launching Deep Passive Discovery (Amass-equiv) for {domain}...")
    subdomains = set()
    
    # Amass functionality is comprehensive OSINT
    subdomains.update(_query_alienvault(domain, user_id))
    
    # We can also double-check other sources for maximal coverage
    subdomains.update(_query_anubis(domain, user_id))
    subdomains.update(_query_hackertarget(domain, user_id))
    
    found = list(subdomains)
    log(user_id, f"[+] Deep Discovery (Amass-equiv) found {len(found)} subdomains.")
    return found


def discover_via_crtsh(domain, user_id):
    """Fallback: Queries crt.sh for subdomains via certificate transparency logs."""
    log(user_id, f"[*] Querying crt.sh for {domain}...")
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=20)
        if response.status_code == 200:
            data = response.json()
            subdomains = set()
            for entry in data:
                name = entry.get('name_value', '')
                for sub in name.split('\n'):
                    sub = sub.strip()
                    if sub and '*' not in sub and domain in sub:
                        subdomains.add(sub)
            log(user_id, f"[+] crt.sh found {len(subdomains)} subdomains.")
            return list(subdomains)
    except Exception as e:
        log(user_id, f"[!] crt.sh query failed: {e}", level='ERROR')
    return []


# =============================================================================
# STAGE 2 — INTELLIGENCE & ENRICHMENT PROBES
# =============================================================================

def get_dns_records(domain):
    """
    Retrieves A, AAAA, MX, TXT, NS, and CNAME records for a domain.
    Uses a per-record timeout to avoid hangs on unresponsive nameservers.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    records = {"A": [], "AAAA": [], "MX": [], "TXT": [], "NS": [], "CNAME": []}
    for rtype in records.keys():
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                records[rtype].append(str(rdata))
        except Exception:
            continue
    return records


def get_whois_data(domain):
    """
    Retrieves WHOIS registrar and lifecycle dates for a domain.
    Returns a dict with registrar, creation_date, expiry_date (ISO strings).
    """
    result = {"registrar": None, "creation_date": None, "expiry_date": None}
    try:
        import whois
        w = whois.whois(domain)
        result["registrar"] = str(w.registrar) if w.registrar else None

        def _to_iso(val):
            if isinstance(val, list):
                val = val[0]
            if isinstance(val, datetime):
                return val.isoformat()
            return str(val) if val else None

        result["creation_date"] = _to_iso(w.creation_date)
        result["expiry_date"]   = _to_iso(w.expiration_date)
    except Exception:
        pass
    return result


def get_asn_info(ip):
    """
    Queries ipinfo.io for ASN and carrier information for a resolved IP.
    Returns a string like 'AS15169 Google LLC' or None.
    """
    if not ip:
        return None
    try:
        response = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=8,
            headers={"Accept": "application/json"}
        )
        if response.status_code == 200:
            data = response.json()
            org = data.get("org")   # e.g. "AS15169 Google LLC"
            return org
    except Exception:
        pass
    return None


def get_ssl_info(domain):
    """
    Performs an SSL/TLS certificate check on port 443.
    Returns a dict with: status, expiry_date, issuer, subject, days_remaining.
    ssl_status values: 'Valid', 'Expiring Soon', 'Expired', 'No SSL', 'Error'
    """
    result = {
        "ssl_status":    "No SSL",
        "expiry_date":   None,
        "issuer":        None,
        "subject":       None,
        "days_remaining": None,
        "key_bits":      None,
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        # Parse expiry
        not_after_str = cert.get("notAfter")
        if not_after_str:
            expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            expiry = expiry.replace(tzinfo=timezone.utc)
            now    = datetime.now(timezone.utc)
            days   = (expiry - now).days
            result["expiry_date"]    = expiry.strftime("%Y-%m-%d")
            result["days_remaining"] = days

            if days < 0:
                result["ssl_status"] = "Expired"
            elif days <= 30:
                result["ssl_status"] = "Expiring Soon"
            else:
                result["ssl_status"] = "Valid"

        # Issuer
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        result["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName")

        # Subject
        subject_dict = dict(x[0] for x in cert.get("subject", []))
        result["subject"] = subject_dict.get("commonName")

    except ssl.SSLError:
        result["ssl_status"] = "Error"
    except (socket.timeout, ConnectionRefusedError, OSError):
        result["ssl_status"] = "No SSL"
    except Exception:
        result["ssl_status"] = "No SSL"
    return result


def get_email_posture(domain):
    """
    Audits SPF, DMARC, DKIM, and MX posture for a domain.
    Returns: {"spf": bool, "dmarc": bool, "dkim": bool, "mx_count": int,
              "spf_record": str|None, "dmarc_record": str|None}
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    posture = {
        "spf":         False,
        "dmarc":       False,
        "dkim":        False,
        "mx_count":    0,
        "spf_record":  None,
        "dmarc_record": None,
    }

    # SPF — look in TXT records for "v=spf1"
    try:
        txt_answers = resolver.resolve(domain, "TXT")
        for rdata in txt_answers:
            full = str(rdata).strip('"')
            if full.lower().startswith("v=spf1"):
                posture["spf"]        = True
                posture["spf_record"] = full[:255]  # truncate for storage
                break
    except Exception:
        pass

    # DMARC — resolve _dmarc.{domain}
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_answers:
            full = str(rdata).strip('"')
            if "v=dmarc1" in full.lower():
                posture["dmarc"]        = True
                posture["dmarc_record"] = full[:255]
                break
    except Exception:
        pass

    # DKIM — probe common selectors
    for selector in ["google", "default", "k1", "mail", "smtp", "selector1", "selector2"]:
        try:
            resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            posture["dkim"] = True
            break
        except Exception:
            continue

    # MX count
    try:
        mx_answers = resolver.resolve(domain, "MX")
        posture["mx_count"] = len(list(mx_answers))
    except Exception:
        pass

    return posture


def check_cloud_exposure(domain):
    """
    Probes for exposed cloud storage assets linked to a domain.
    Checks: AWS S3, Azure Blob, Firebase.
    Returns a list of found exposure dicts: [{"provider", "url", "status"}]
    """
    root = domain.split('.')[0]  # e.g. "example" from "example.com"
    exposures  = []
    candidates = [
        # AWS S3
        (f"https://{domain}.s3.amazonaws.com",            "AWS S3"),
        (f"https://{root}.s3.amazonaws.com",              "AWS S3"),
        (f"https://www.{root}.s3.amazonaws.com",          "AWS S3"),
        (f"https://cdn.{root}.s3.amazonaws.com",          "AWS S3"),
        # Azure Blob
        (f"https://{root}.blob.core.windows.net",         "Azure Blob"),
        # Firebase
        (f"https://{root}.firebaseio.com/.json",          "Firebase"),
        (f"https://{root}-default-rtdb.firebaseio.com/.json", "Firebase"),
    ]

    for url, provider in candidates:
        try:
            r = requests.head(url, timeout=5, allow_redirects=True)
            # 200/403 indicate the bucket exists (403 = exists but private)
            if r.status_code in (200, 403):
                access = "Public" if r.status_code == 200 else "Private (Exists)"
                exposures.append({"provider": provider, "url": url, "status": access})
        except Exception:
            continue

    return exposures

def calculate_criticality(asset_value, asset_type, enrichment):
    """
    Calculates asset criticality score (0-10) using multi-factor weighting.
    Incorporates: asset type, naming sensitivity, tech stack, SSL posture,
    mail posture, cloud exposure, and ASN context.
    """
    score = 3.0  # Baseline

    # Asset type weight
    if asset_type == 'domain':
        score += 3.0
    else:
        score += 1.0

    # Sensitivity prefixes
    high_sensitivity = ['api', 'dev', 'vpn', 'stage', 'internal', 'prod',
                        'db', 'git', 'admin', 'staging', 'test', 'mail',
                        'smtp', 'ftp', 'ssh', 'mgmt', 'management']
    if any(asset_value.lower().startswith(p + '.') for p in high_sensitivity):
        score += 2.0

    tech_stack = enrichment.get('tech', {}) or {}
    ssl_info   = enrichment.get('ssl', {}) or {}
    mail       = enrichment.get('mail', {}) or {}
    cloud      = enrichment.get('cloud', []) or []

    # Tech stack factors
    if tech_stack:
        score += 0.5
        if any(cms in str(tech_stack).lower() for cms in ['wordpress', 'drupal', 'joomla', 'magento']):
            score += 0.5  # Publicly known attack surface

    # SSL posture (penalty for bad certs)
    ssl_status = ssl_info.get('ssl_status', 'No SSL')
    if ssl_status == 'Expired':
        score += 2.0
    elif ssl_status == 'Expiring Soon':
        score += 1.0
    elif ssl_status == 'No SSL':
        score += 1.5

    # Mail identity posture (penalty for missing controls)
    if not mail.get('spf'):
        score += 0.5
    if not mail.get('dmarc'):
        score += 0.5

    # Cloud exposure (high risk)
    if cloud:
        score += 2.0

    return min(10.0, round(score, 1))


# =============================================================================
# STAGE 3 — MAIN ORCHESTRATION
# =============================================================================

def start_asset_discovery(domain, user_id, user_identifier=None):
    """
    Orchestrates the full asset discovery pipeline for a given domain.
    Stages: Subdomain Enum → DNS/SSL/WHOIS/Mail/Cloud Enrichment → Micro-Crawl/Fuzz → Persist → Report
    """
    user_id = int(user_id)
    # Use identifier if provided (for SSE logging), otherwise fall back to ID
    log_target = user_identifier if user_identifier else user_id

    from run import app

    with app.app_context():
        log_id = scan_logger.log_scan_start(
            user_id=user_id,
            tool_name="asset_discovery",
            target=domain,
            scan_type="Discovery Sweep"
        )

    with scan_lock:
        active_scans[user_id] = {"target": domain, "start_time": time.time(), "log_id": log_id}

    try:
        log(user_id, f"[STAGE] Starting Asset Discovery for: {domain}", level='STAGE')

        # Safety Guardrails
        try:
            validate_target(domain)
        except TargetBlockedError as e:
            log(user_id, f"[BLOCKED] Validation failed: {e}", level='ERROR')
            return []

        # ── STAGE 1: Discovery Engines (parallel) ──────────────────────────
        log(log_target, "[STAGE] Running subdomain enumeration engines...", level='STAGE')
        all_subdomains = set()
        all_subdomains.add(domain)

        def worker(func, _domain, _user_id_or_ident, target_set):
            found = func(_domain, _user_id_or_ident)
            for s in found:
                s = s.strip().lower()
                if s and _domain in s:
                    target_set.add(s)

        # Base OSINT Engines
        threads = []
        engines = [run_subfinder, run_assetfinder, run_amass, discover_via_crtsh]
        
        for engine in engines:
            t = threading.Thread(target=worker, args=(engine, domain, log_target, all_subdomains))
            threads.append(t)
            t.start()
        
        # [NEW] Recon Module Integration
        def recon_worker():
            try:
                log(log_target, "[*] Running Recon Subdomain Discovery...")
                res = _recon.subdomain_scan(domain)
                for s in res.get('subdomains', []):
                    all_subdomains.add(s.strip().lower())
            except Exception as e:
                log(log_target, f"[!] Recon module failed: {e}", level='DEBUG')
        
        t_recon = threading.Thread(target=recon_worker)
        threads.append(t_recon)
        t_recon.start()

        for t in threads:
            t.join()

        unique_subs = sorted(list(all_subdomains))
        log(log_target, f"[SUCCESS] Discovery phase complete. Found {len(unique_subs)} unique assets.", level='SUCCESS')

        # ── STAGE 2: Parallel Enrichment ───────────────────────────────────
        from run import app
        with app.app_context():
            log(log_target, "[STAGE] Running intelligence enrichment pipeline...", level='STAGE')

            def enrich_asset(sub):
                """Runs all 6+ probes for a single asset. Each probe is isolated."""
                is_root = (sub == domain)

                # DNS (always)
                dns_data = get_dns_records(sub)
                resolved_ip = dns_data['A'][0] if dns_data['A'] else None

                # [NEW] Tech Stack via TechDetector
                try:
                    res = _tech_detect.detect(sub)
                    tech_data = res.get("technologies", {})
                    # Add versions too
                    if res.get("versions"):
                        tech_data["versions"] = res["versions"]
                except Exception:
                    tech_data = {}

                # SSL/TLS
                try:
                    ssl_data = get_ssl_info(sub)
                except Exception:
                    ssl_data = {"ssl_status": "Error"}

                # WHOIS (only for root domain to avoid rate limits)
                whois_data = {}
                if is_root:
                    try:
                        whois_data = get_whois_data(sub)
                    except Exception:
                        pass

                # ASN lookup
                asn_info = None
                if resolved_ip:
                    try:
                        asn_info = get_asn_info(resolved_ip)
                    except Exception:
                        pass

                # Mail posture (only for root domain + mail-prefix subdomains)
                mail_data = {}
                if is_root or any(sub.startswith(p + '.') for p in ['mail', 'smtp', 'mx']):
                    try:
                        mail_data = get_email_posture(domain)  # Always use root domain
                    except Exception:
                        pass

                # Cloud exposure (only for root domain)
                cloud_data = []
                if is_root:
                    try:
                        cloud_data = check_cloud_exposure(domain)
                    except Exception:
                        pass

                # [NEW] Advanced Probes for Root Domain (Crawl & Fuzz)
                extra_intel = {"forms": [], "endpoints": [], "sensitive_paths": []}
                if is_root:
                    try:
                        log(log_target, "[*] Launching Micro-Crawl on root domain...")
                        found_params = _crawler.crawl(sub, max_pages=10)
                        extra_intel["endpoints"] = found_params
                        extra_intel["forms"] = _crawler.forms_found
                    except Exception as e:
                        log(log_target, f"[!] Crawler failed: {e}", level='DEBUG')

                    try:
                        log(log_target, "[*] Launching Smart Fuzzing on root domain...")
                        fuzz_res = _fuzzer.fuzz(sub, technologies=tech_data, max_depth=1)
                        if fuzz_res.get("findings"):
                            extra_intel["sensitive_paths"] = [f["url"] for f in fuzz_res["findings"] if f["status"] == 200]
                    except Exception as e:
                        log(log_target, f"[!] Fuzzer failed: {e}", level='DEBUG')

                return sub, {
                    "dns":   dns_data,
                    "tech":  tech_data,
                    "ssl":   ssl_data,
                    "whois": whois_data,
                    "asn":   asn_info,
                    "mail":  mail_data,
                    "cloud": cloud_data,
                    "ip":    resolved_ip,
                    "extra": extra_intel
                }

            enriched_data = {}
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_sub = {executor.submit(enrich_asset, sub): sub for sub in unique_subs}
                for future in as_completed(future_to_sub):
                    try:
                        sub, data = future.result()
                        enriched_data[sub] = data
                        log(log_target, f"[+] Enriched: {sub} (IP: {data['ip'] or 'none'}, SSL: {data['ssl'].get('ssl_status', 'N/A')})")
                    except Exception as e:
                        log(log_target, f"[!] Enrichment failed for asset: {e}", level='ERROR')

            # ── STAGE 3: Persistence ────────────────────────────────────────
            log(log_target, "[STAGE] Persisting enriched assets to database...", level='STAGE')
            new_assets_count     = 0
            updated_assets_count = 0

            for sub in unique_subs:
                if sub not in enriched_data:
                    continue

                e = enriched_data[sub]
                asset_type  = 'domain' if sub == domain else 'subdomain'
                crit_score  = calculate_criticality(sub, asset_type, e)

                asset = Asset.query.filter_by(user_id=user_id, value=sub).first()
                if not asset:
                    asset = Asset(
                        user_id=user_id,
                        asset_type=asset_type,
                        value=sub,
                        discovery_method='automated',
                        criticality_score=crit_score,
                        business_value=_score_to_label(crit_score),
                        created_at=get_now_ist_naive(),
                        last_seen=get_now_ist_naive()
                    )
                    db.session.add(asset)
                    db.session.flush()
                    new_assets_count += 1
                else:
                    asset.last_seen        = get_now_ist_naive()
                    asset.criticality_score = crit_score
                    asset.business_value   = _score_to_label(crit_score)
                    updated_assets_count   += 1

                # Upsert DomainInventory — write all intelligence fields
                inventory = DomainInventory.query.filter_by(asset_id=asset.id).first()
                if not inventory:
                    inventory = DomainInventory(asset_id=asset.id)
                    db.session.add(inventory)

                inventory.dns_records  = e['dns']
                inventory.tech_stack   = e['tech']
                inventory.resolved_ip  = e['ip']
                inventory.email_posture = e['mail'] or None
                inventory.ssl_status   = e['ssl'].get('ssl_status')
                inventory.asn_info     = e['asn']
                inventory.updated_at   = get_now_ist_naive()

                # [NEW] Persist Extra Intel (Crawler/Fuzzer) into tech_stack JSON for now
                if e.get('extra'):
                    existing_tech = inventory.tech_stack or {}
                    existing_tech.update(e['extra'])
                    inventory.tech_stack = existing_tech

                # WHOIS fields (root domain only)
                if e.get('whois'):
                    inventory.registrar      = e['whois'].get('registrar')
                    inventory.creation_date  = _parse_date(e['whois'].get('creation_date'))
                    inventory.expiry_date    = _parse_date(e['whois'].get('expiry_date'))

                # Cloud exposure stored in tech_stack dict
                if e.get('cloud'):
                    existing_tech = inventory.tech_stack or {}
                    existing_tech['cloud_assets'] = e['cloud']
                    inventory.tech_stack = existing_tech

                # SSL detail stored in tech_stack
                ssl_info = dict(e['ssl'])
                ssl_info.pop('ssl_status', None)  # status is in its own column
                if ssl_info:
                    existing_tech = inventory.tech_stack or {}
                    existing_tech['ssl_detail'] = ssl_info
                    inventory.tech_stack = existing_tech

            db.session.commit()
            log(log_target, f"[+] Sync complete. New: {new_assets_count}, Updated: {updated_assets_count}")

            # ── STAGE 4: Report Generation ──────────────────────────────────
            try:
                log(log_target, "[STAGE] Archiving structured results to user directory...", level='STAGE')

                user = db.session.get(User, user_id)
                user_base_dir    = report_manager.get_user_results_dir(user)
                user_results_dir = os.path.join(user_base_dir, 'asset_discovery')
                os.makedirs(user_results_dir, exist_ok=True)

                timestamp    = report_manager.get_timestamp()
                json_filename = report_manager.generate_report_filename(
                    "asset_discovery", domain, extension="json", timestamp=timestamp)
                json_path    = os.path.join(user_results_dir, json_filename)

                # Build rich report payload
                formatted_assets = _build_report_assets(user_id, domain, enriched_data)

                # Overall mail + SSL summary (from root domain data)
                root_data = enriched_data.get(domain, {})
                report_data = {
                    "target_domain":  domain,
                    "scan_date":      datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                    "generated_by":   "NetShieldAI Asset Discovery Engine",
                    "summary": {
                        "total_assets":   len(unique_subs),
                        "new_assets":     new_assets_count,
                        "updated_assets": updated_assets_count,
                    },
                    "mail_posture":   root_data.get('mail', {}),
                    "cloud_exposure": root_data.get('cloud', []),
                    "whois":          root_data.get('whois', {}),
                    "assets":         formatted_assets,
                }

                with open(json_path, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, indent=4, default=str)
                log(log_target, f"[+] JSON archive created: {json_filename}")

                # PDF Report
                log(log_target, "[STAGE] Generating PDF Intelligence Report...", level='STAGE')
                pdf_filename = report_manager.generate_report_filename(
                    "asset_discovery", domain, timestamp=timestamp)
                pdf_path = os.path.join(user_results_dir, pdf_filename)

                success = pdf_generator.create_asset_discovery_report_pdf(
                    report_data, pdf_path, user_id=user_id)

                if success:
                    scan_logger.log_scan_end(
                        log_id,
                        status="Completed",
                        finding_count=len(formatted_assets),
                        report_path=pdf_path
                    )
                    log(log_target, f"[SUCCESS] PDF Report generated: {pdf_filename}", level='SUCCESS')
                    log(log_target, f"SYSTEM_EVENT: READY_FOR_ANALYSIS:{domain}", level='INFO')
                else:
                    scan_logger.log_scan_end(log_id, status="Partial Success",
                                             error_msg="PDF generation failed")

            except Exception as e:
                log(log_target, f"[!] Failed to archive or generate PDF: {e}", level='ERROR')
                scan_logger.log_scan_end(log_id, status="Error", error_msg=str(e))

            return unique_subs

    finally:
        with scan_lock:
            if user_id in active_scans:
                del active_scans[user_id]


# =============================================================================
# PRIVATE HELPERS
# =============================================================================

def _score_to_label(score):
    """Maps a numeric criticality score to a business value label."""
    if score >= 7.0:
        return 'High'
    if score >= 4.0:
        return 'Medium'
    return 'Low'


def _parse_date(date_str):
    """Safely parses an ISO date string to a naive datetime for SQLAlchemy."""
    if not date_str:
        return None
    try:
        dt = datetime.fromisoformat(str(date_str).replace('Z', '+00:00'))
        return dt.replace(tzinfo=None)
    except Exception:
        return None


def _build_report_assets(user_id, domain, enriched_data):
    """
    Builds the rich `assets` list for the JSON report and PDF template.
    Pulls from both the enriched_data dict and the DB (for persisted assets).
    """
    final_assets = Asset.query.filter_by(user_id=user_id).all()
    formatted = []

    for a in final_assets:
        if domain not in a.value:
            continue

        e = enriched_data.get(a.value, {})
        inv = a.inventory

        ssl_info  = e.get('ssl', {})
        mail_info = e.get('mail', {})
        cloud     = e.get('cloud', [])
        tech      = dict(inv.tech_stack) if inv and inv.tech_stack else {}

        # Strip internal keys from display tech stack
        tech_display = {k: v for k, v in tech.items()
                        if k not in ('cloud_assets', 'ssl_detail')}

        formatted.append({
            "value":            a.value,
            "type":             a.asset_type,
            "business_value":   a.business_value or 'Medium',
            "criticality":      a.criticality_score,
            "discovery_method": a.discovery_method,
            "last_seen":        a.last_seen.isoformat() if a.last_seen else None,
            "details": {
                "ip":          inv.resolved_ip if inv else e.get('ip'),
                "asn":         inv.asn_info if inv else e.get('asn'),
                "registrar":   inv.registrar if inv else e.get('whois', {}).get('registrar'),
                "created":     inv.creation_date.isoformat() if (inv and inv.creation_date) else None,
                "expires":     inv.expiry_date.isoformat() if (inv and inv.expiry_date) else None,
                "tech":        tech_display,
                "dns":         inv.dns_records if inv else e.get('dns', {}),
                "ssl": {
                    "status":         inv.ssl_status if inv else ssl_info.get('ssl_status', 'Unknown'),
                    "expiry_date":    ssl_info.get('expiry_date'),
                    "issuer":         ssl_info.get('issuer'),
                    "days_remaining": ssl_info.get('days_remaining'),
                },
                "mail_posture": {
                    "spf":          mail_info.get('spf', False),
                    "dmarc":        mail_info.get('dmarc', False),
                    "dkim":         mail_info.get('dkim', False),
                    "mx_count":     mail_info.get('mx_count', 0),
                    "spf_record":   mail_info.get('spf_record'),
                    "dmarc_record": mail_info.get('dmarc_record'),
                } if mail_info else None,
                "cloud_exposure": cloud or None,
            }
        })

    # Sort by criticality (highest first), domains before subdomains
    formatted.sort(key=lambda x: (x['type'] != 'domain', -(x['criticality'] or 0)))
    return formatted
