import os
import re
import glob
from datetime import datetime
from pathlib import Path
from Services.scan_logger import sanitize_filename

def get_timestamp():
    """Returns a current timestamp string for filenames."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def generate_report_filename(scanner_name, target, extension="pdf", include_timestamp=True):
    """
    Generates a standardized filename for a scan report.
    Format: scanner_target_timestamp.extension
    Example: nmap_192_168_1_1_20240317_123045.pdf
    """
    sanitized_target = sanitize_filename(target)
    
    # Ensure scanner name is lowercase and clean
    scanner_name = scanner_name.lower().replace(" ", "_").replace("_scanner", "")
    
    timestamp = f"_{get_timestamp()}" if include_timestamp else ""
    
    return f"{scanner_name}_{sanitized_target}{timestamp}.{extension}"

def parse_report_metadata(filename):
    """
    Safely extracts scanner, target, and timestamp from a filename.
    Handles both old and new formats.
    """
    # Remove extension
    stem = Path(filename).stem
    parts = stem.split('_')
    
    # Format: scanner_target_YYYYMMDD_HHMMSS
    # Look for the timestamp pattern at the end
    timestamp = None
    target_parts = []
    scanner = parts[0] if parts else "unknown"
    
    # Basic heuristic: check if the last two parts look like YYYYMMDD and HHMMSS
    if len(parts) >= 3:
        last_part = parts[-1]
        second_last = parts[-2]
        
        # Check if last_part is HHMMSS (6 digits) and second_last is YYYYMMDD (8 digits)
        if re.match(r'^\d{6}$', last_part) and re.match(r'^\d{8}$', second_last):
            timestamp = f"{second_last}_{last_part}"
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
    Centralized SSOT for file storage location.
    """
    from models.models import get_user_result_dir_name
    user_result_dir = get_user_result_dir_name(user)
    
    # We navigate up from 'Services/' to root, then into .results
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    user_dir = os.path.join(base_dir, '.results', user_result_dir)
    
    # Create directory if it doesn't exist
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def find_latest_report(user_results_dir, scanner_name=None, target=None, extension="pdf"):
    """
    Robustly finds the most recent report file matching the criteria.
    Useful for routes that don't have a specific database ID.
    """
    results_path = Path(user_results_dir)
    if not results_path.exists():
        return None
        
    # Build search pattern
    # Some older files were "scanner_target.pdf", newer "scanner_target_TS.pdf"
    # So we glob for "scanner_target*.pdf"
    clean_scanner = scanner_name.lower().replace(" ", "_").replace("_scanner", "") if scanner_name else "*"
    clean_target = sanitize_filename(target) if target else "*"
    
    pattern = f"**/{clean_scanner}_{clean_target}*.{extension}"
    
    candidates = list(results_path.glob(pattern))
    if not candidates:
        # Fallback: maybe the scanner name in the filename is different
        if scanner_name:
             pattern = f"**/*_{clean_target}*.{extension}"
             candidates = list(results_path.glob(pattern))
             
    if not candidates:
        return None
        
    # Return the one with the latest modification time
    return str(max(candidates, key=os.path.getmtime))

def wait_for_file(file_path, timeout=10, check_interval=0.5):
    """
    Polls the filesystem until a file exists and is not being written to.
    Returns True if file found and stable, False on timeout.
    """
    if not file_path:
        return False
        
    start_time = time.time()
    while time.time() - start_time < timeout:
        if os.path.exists(file_path):
            # Check if size is stable (not being written to)
            try:
                size1 = os.path.getsize(file_path)
                time.sleep(0.2)
                size2 = os.path.getsize(file_path)
                if size1 == size2 and size1 > 0:
                    return True
            except OSError:
                pass # File might be locked or deleted
        time.sleep(check_interval)
    return False

def get_report_history(user_results_dir, scanner_name=None, extension="pdf"):
    """
    Lists all reports in the user's result directory, optionally filtered by scanner and extension.
    Returns a list of dictionaries with metadata.
    """
    reports = []
    results_path = Path(user_results_dir)
    
    if not results_path.exists():
        return []

    pattern = f"*.{extension}"
    if scanner_name:
        clean_name = scanner_name.lower().replace(" ", "_").replace("_scanner", "")
        pattern = f"{clean_name}_*.{extension}"

    for report_file in results_path.glob(f"**/{pattern}"):
        stats = report_file.stat()
        
        # Use the new robust parser
        metadata = parse_report_metadata(report_file.name)
        
        reports.append({
            "filename": report_file.name,
            "path": str(report_file),
            "relative_path": str(report_file.relative_to(results_path.parent.parent)), 
            "scanner": metadata["scanner"],
            "target": metadata["target"],
            "is_unique": metadata["is_unique"],
            "size_bytes": stats.st_size,
            "created_at": datetime.fromtimestamp(stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp": stats.st_mtime
        })

    # Sort by timestamp descending (newest first)
    reports.sort(key=lambda x: x["timestamp"], reverse=True)
    return reports
