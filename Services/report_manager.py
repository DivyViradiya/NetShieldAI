import os
import re
import glob
import time
from datetime import datetime
from pathlib import Path
from core.time_utils import get_now_ist, to_ist

def sanitize_filename(target):
    r"""
    Sanitizes a target (IP, URL, Domain) for use in a filename.
    Replaces common delimiters (e.g., ., :, /, \) with underscores.
    """
    if not target:
        return "unknown_target"
    
    # Remove protocol prefix (http://, https://)
    clean_target = re.sub(r'^https?://', '', str(target))
    
    # Replace all non-alphanumeric (except underscores/hyphens/dots) with underscores
    # [BEAUTIFY] Keeping dots for domains/IPs makes them more readable than underscores
    clean_target = re.sub(r'[^a-zA-Z0-9._-]', '_', clean_target)
    
    # Remove trailing/leading underscores/dots
    return clean_target.strip('_.')

def get_timestamp():
    """Returns a current timestamp string for filenames in IST."""
    # [BEAUTIFY] Use hyphenated date for better block separation
    return get_now_ist().strftime("%Y-%m-%d_%H%M%S")

def generate_report_filename(scanner_name, target, extension="pdf", include_timestamp=True, timestamp=None):
    """
    Generates a beautified, standardized filename for a scan report.
    Format: Audit_Scanner_Target_YYYY-MM-DD_HHMMSS.extension
    """
    sanitized_target = sanitize_filename(target)
    
    # Ensure scanner name is lowercase and clean
    scanner_name = scanner_name.lower().replace(" ", "_").replace("_scanner", "")
    
    if include_timestamp:
        ts = f"_{timestamp}" if timestamp else f"_{get_timestamp()}"
    else:
        ts = ""
    
    return f"Audit_{scanner_name}_{sanitized_target}{ts}.{extension}"

def parse_report_metadata(filename):
    """
    Safely extracts scanner, target, and timestamp from a filename.
    Handles both legacy (nmap_127.0.0.1_TS) and beautified (Audit_nmap_127.0.0.1_TS) formats.
    """
    stem = Path(filename).stem
    
    # 1. Remove optional "Audit_" prefix
    if stem.startswith("Audit_"):
        stem = stem[6:]
    
    parts = stem.split('_')
    
    # 2. Identify Timestamp (Look for YYYYMMDD or YYYY-MM-DD + HHMMSS)
    timestamp = None
    target_parts = []
    scanner = parts[0] if parts else "unknown"
    
    # Format Check: [Scanner] [Target...] [Date] [Time]
    if len(parts) >= 3:
        # Check last two parts for timestamp (HHMMSS and Date)
        time_part = parts[-1]
        date_part = parts[-2]
        
        # New format: YYYY-MM-DD (part of parts due to hyphen)
        # Old format: YYYYMMDD
        is_time = re.match(r'^\d{6}$', time_part)
        is_date = re.match(r'^\d{4}-\d{2}-\d{2}$', date_part) or re.match(r'^\d{8}$', date_part)
        
        if is_time and is_date:
            timestamp = f"{date_part}_{time_part}"
            target_parts = parts[1:-2]
        else:
            target_parts = parts[1:]
    else:
        target_parts = parts[1:] if len(parts) > 1 else []

    target = "_".join(target_parts)
    
    return {
        "scanner": scanner,
        "target": target,
        "timestamp_str": timestamp,
        "is_unique": bool(timestamp)
    }

def get_user_results_dir(user):
    """
    Constructs the path: results/<username_id>/
    """
    from models.models import get_user_result_dir_name
    user_result_dir = get_user_result_dir_name(user)
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    user_dir = os.path.join(base_dir, '.results', user_result_dir)
    
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def find_latest_report(user_results_dir, scanner_name=None, target=None, extension="pdf", exclude_executive=True):
    """
    Finds the latest matching report. Supports both legacy and beautified formats via flexible glob.
    """
    results_path = Path(user_results_dir)
    if not results_path.exists():
        return None
        
    clean_scanner = scanner_name.lower().replace(" ", "_").replace("_scanner", "") if scanner_name else "*"
    clean_target = sanitize_filename(target) if target else "*"
    
    # [FLEXIBLE GLOB] Matches:
    # 1. scanner_target...
    # 2. Audit_scanner_target...
    # 3. *_*_target... (fallback)
    patterns = [
        f"**/Audit_{clean_scanner}_{clean_target}*.{extension}",
        f"**/{clean_scanner}_{clean_target}*.{extension}",
        f"**/*_{clean_target}*.{extension}"
    ]
    
    all_candidates = []
    for pattern in patterns:
        all_candidates.extend(results_path.glob(pattern))
        
    if not all_candidates:
        return None

    # [FIX] Filter out any '_executive.pdf' summaries if we only want technical reports
    if exclude_executive and extension == "pdf":
         all_candidates = [c for c in all_candidates if not str(c).lower().endswith("_executive.pdf")]
         
    if not all_candidates:
        return None
        
    return str(max(all_candidates, key=os.path.getmtime))

def wait_for_file(file_path, timeout=10, check_interval=0.5):
    if not file_path:
        return False
    start_time = time.time()
    while time.time() - start_time < timeout:
        if os.path.exists(file_path):
            try:
                size1 = os.path.getsize(file_path)
                time.sleep(0.2)
                size2 = os.path.getsize(file_path)
                if size1 == size2 and size1 > 0:
                    return True
            except OSError:
                pass 
        time.sleep(check_interval)
    return False

def get_report_history(user_results_dir, scanner_name=None, extension="pdf"):
    """
    Lists reports with support for both legacy and beautified formats.
    """
    reports = []
    results_path = Path(user_results_dir)
    if not results_path.exists():
        return []

    # Use a broad glob and filter in Python for robustness
    for report_file in results_path.glob(f"**/*.{extension}"):
        metadata = parse_report_metadata(report_file.name)
        
        # Optional filter by scanner
        if scanner_name:
            clean_name = scanner_name.lower().replace(" ", "_").replace("_scanner", "")
            if metadata["scanner"] != clean_name:
                continue

        stats = report_file.stat()
        created_at_ist = to_ist(datetime.fromtimestamp(stats.st_mtime))
        
        reports.append({
            "filename": report_file.name,
            "path": str(report_file),
            "relative_path": str(report_file.relative_to(results_path.parent.parent)), 
            "scanner": metadata["scanner"],
            "target": metadata["target"],
            "is_unique": metadata["is_unique"],
            "size_bytes": stats.st_size,
            "created_at": created_at_ist.strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp": stats.st_mtime
        })

    reports.sort(key=lambda x: x["timestamp"], reverse=True)
    return reports
