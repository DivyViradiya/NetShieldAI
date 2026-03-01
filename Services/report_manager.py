import os
import re
from datetime import datetime
from pathlib import Path
from Services.scan_logger import sanitize_filename

def get_timestamp():
    """Returns a current timestamp string for filenames."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def generate_report_filename(scanner_name, target, extension="pdf"):
    """
    Generates a standardized filename for a scan report without timestamps.
    Example: nmap_192_168_1_1.pdf
    """
    sanitized_target = sanitize_filename(target)
    
    # Ensure scanner name is lowercase and clean
    scanner_name = scanner_name.lower().replace(" ", "_")
    
    return f"{scanner_name}_{sanitized_target}.{extension}"

def get_report_history(user_results_dir, scanner_name=None, extension="pdf"):
    """
    Lists all reports in the user's result directory, optionally filtered by scanner and extension.
    Returns a list of dictionaries with metadata.
    """
    reports = []
    results_path = Path(user_results_dir)
    
    if not results_path.exists():
        return []

    # If scanner_name is provided, we might be looking in a subfolder or filtering files
    # NetShield usually uses: Services/results/<user>/<scanner_name>/
    # But some logic might call this on the base user results dir.
    
    pattern = f"*.{extension}"
    if scanner_name:
        clean_name = scanner_name.lower().replace(" ", "_")
        pattern = f"{clean_name}_*.{extension}"

    for report_file in results_path.glob(f"**/{pattern}"):
        stats = report_file.stat()
        
        # Try to parse scanner and target from filename: scanner_target_timestamp.pdf
        parts = report_file.stem.split('_')
        
        # Default metadata if parsing fails
        detected_scanner = parts[0] if len(parts) > 0 else "unknown"
        
        reports.append({
            "filename": report_file.name,
            "path": str(report_file),
            "relative_path": str(report_file.relative_to(results_path.parent.parent)), # Relative to Services/results
            "scanner": detected_scanner,
            "size_bytes": stats.st_size,
            "created_at": datetime.fromtimestamp(stats.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp": stats.st_ctime
        })

    # Sort by timestamp descending (newest first)
    reports.sort(key=lambda x: x["timestamp"], reverse=True)
    return reports
