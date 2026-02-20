import re
from datetime import datetime
import os
import time
from extensions import db
from models import ScanLog, User

BASE_LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
USERS_LOG_DIR = os.path.join(BASE_LOG_DIR, "users")

def get_active_log_file(user_id, tool_name):
    """
    Returns the absolute path to the active log file for a specific tool and user.
    """
    user_dir = os.path.join(USERS_LOG_DIR, f"{user_id}")
    os.makedirs(user_dir, exist_ok=True)
    return os.path.join(user_dir, f"{tool_name}_active.log")

def tail_log_file(user_id, tool_name):
    """
    Generator that tails the active log file for a user/tool.
    Yields new lines as they are written.
    """
    log_file = get_active_log_file(user_id, tool_name)
    
    # Wait for file to exist
    tries = 0
    while not os.path.exists(log_file):
        time.sleep(0.5)
        tries += 1
        if tries > 10: return # Give up if file doesn't appear

    with open(log_file, "r") as f:
        # Move to end if we only want new? No, we want full history for refresh.
        # So we start from beginning.
        while True:
            line = f.readline()
            if line:
                yield f"data: {line.strip()}\n\n"
            else:
                time.sleep(0.5) # Wait for new content

def sanitize_filename(target):
    r"""
    Sanitizes a target (IP, URL, Domain) for use in a filename.
    Replaces common delimiters (e.g., ., :, /, \) with underscores.
    """
    if not target:
        return "unknown_target"
    
    # Remove protocol prefix (http://, https://)
    clean_target = re.sub(r'^https?://', '', str(target))
    
    # Replace all non-alphanumeric (except underscores/hyphens) with underscores
    clean_target = re.sub(r'[^a-zA-Z0-9_-]', '_', clean_target)
    
    # Remove trailing/leading underscores
    return clean_target.strip('_')

def log_scan_start(user_id, tool_name, target, scan_type="Standard"):
    """
    Creates a new ScanLog entry with status 'Running'.
    Returns the ID of the log entry to update later.
    Caller must be inside an app_context.
    """
    try:
        new_log = ScanLog(
            user_id=user_id,
            tool_name=tool_name,
            target=target,
            scan_type=scan_type,
            status="Running",
            start_time=datetime.utcnow()
        )
        db.session.add(new_log)
        db.session.commit()
        return new_log.id
    except Exception as e:
        print(f"[!] Error logging scan start: {e}")
        return None

def log_scan_end(log_id, status="Completed", finding_count=0, critical_count=0, error_msg=None, duration=None):
    """
    Updates an existing ScanLog entry with completion details.
    Caller must be inside an app_context.
    """
    if not log_id: return

    try:
        log_entry = db.session.get(ScanLog, log_id)
        if log_entry:
            log_entry.end_time = datetime.utcnow()
            log_entry.status = status
            log_entry.finding_count = finding_count
            log_entry.severity_critical = critical_count
            log_entry.error_message = error_msg
            
            # Calculate Duration
            if duration is not None:
                log_entry.duration_seconds = duration
            elif log_entry.start_time:
                delta = log_entry.end_time - log_entry.start_time
                log_entry.duration_seconds = delta.total_seconds()
            
            db.session.commit()
    except Exception as e:
        print(f"[!] Error logging scan end: {e}")

def create_full_scan_log(user_id, tool_name, target, duration, finding_count, status="Completed", scan_type="Standard"):
    """
    For tools that don't support async start/end logging easily, 
    this logs the entire event at once (e.g., for Nmap after it returns).
    Caller must be inside an app_context.
    """
    try:
        # Calculate implied start time
        end_time = datetime.utcnow()
        start_time = datetime.fromtimestamp(end_time.timestamp() - duration)
        
        new_log = ScanLog(
            user_id=user_id,
            tool_name=tool_name,
            target=target,
            scan_type=scan_type,
            status=status,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration,
            finding_count=finding_count
        )
        db.session.add(new_log)
        db.session.commit()
    except Exception as e:
        print(f"[!] Error logging full scan: {e}")

def reset_log_file(user_id, tool_name):
    """
    Truncates the active log file for a specific user and tool.
    This ensures that new scans start with a fresh log view.
    """
    log_file = get_active_log_file(user_id, tool_name)
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        # Open in write mode to truncate
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Log cleared for new {tool_name} scan.\n")
    except Exception as e:
        print(f"[!] Error resetting log file {log_file}: {e}")

def get_active_scan_log(user_id, tool_name):
    """
    Checks if there's an active (Running) scan for this user and tool in the DB.
    Returns the ScanLog object or None.
    Caller must be inside an application context.
    """
    try:
        # Check for any scan with status 'Running' for this user and tool
        active_scan = ScanLog.query.filter_by(
            user_id=user_id, 
            tool_name=tool_name, 
            status='Running'
        ).order_by(ScanLog.start_time.desc()).first()
        
        return active_scan
    except Exception as e:
        print(f"[!] Error fetching active scan from DB: {e}")
        return None

def mark_scan_failed(log_id, error_message="Scan interrupted or server restarted."):
    """
    Updates a specific scan log to 'Failed'. Used for cleanup of stale scans.
    Caller must be inside an application context.
    """
    try:
        scan = db.session.get(ScanLog, log_id)
        if scan and scan.status == 'Running':
            scan.status = 'Failed'
            scan.end_time = datetime.utcnow()
            scan.error_message = error_message
            db.session.commit()
            return True
    except Exception as e:
        print(f"[!] Error marking scan {log_id} as failed: {e}")
    return False

def get_debug_log_file(user_id, tool_name):
    """
    Returns the absolute path to the debug log file for a specific tool and user.
    """
    user_dir = os.path.join(USERS_LOG_DIR, f"{user_id}")
    os.makedirs(user_dir, exist_ok=True)
    return os.path.join(user_dir, f"{tool_name}_debug.log")

def clean_log_message(message):
    """
    Beautifies log messages for the user.
    Removes absolute paths, simplifies command lines, and hides secrets.
    """
    if not message: return ""
    
    # Preserve SSE Events
    if message.startswith("EVENT:"):
        return message
    
    # 1. Hide Absolute Paths (Windows/Linux)
    # Matches X:\... or /... until a space or end of line
    message = re.sub(r'([a-zA-Z]:\\[^ \n]+|/[a-zA-Z0-9/_.-]+)', '[FILE_PATH]', message)
    
    # 2. Simplify Command Lines
    if "nmap" in message.lower() and "[FILE_PATH]" in message:
        return "Executing Network Scan..."
    if "zap" in message.lower() and "daemon" in message.lower():
        return "Starting ZAP Engine..."
    if "sslscan" in message.lower() and "xml" in message.lower():
        return "Running SSL Configuration Scan..."
        
    return message

def write_log(user_id, tool_name, message, level='INFO'):
    """
    Centralized logging function.
    - Writes EVERYTHING to {tool_name}_debug.log
    - Writes ONLY CLEAN 'INFO' level messages to {tool_name}_active.log (User Stream)
    """
    timestamp = datetime.now().strftime("%H:%M:%S")
    full_line = f"[{timestamp}] [{level}] {message}"
    
    # 1. Write to Debug Log
    debug_file = get_debug_log_file(user_id, tool_name)
    try:
        with open(debug_file, 'a', encoding='utf-8') as f:
            f.write(full_line + "\n")
    except Exception as e:
        print(f"Error writing to debug log: {e}")

    # 2. Write to User Log (Active Stream) if level is INFO
    if level == 'INFO':
        clean_message = clean_log_message(message)
        # Verify message isn't empty or just a placeholder after cleaning
        if clean_message and clean_message.strip():
             user_file = get_active_log_file(user_id, tool_name)
             user_line = f"[{timestamp}] {clean_message}"
             try:
                with open(user_file, 'a', encoding='utf-8') as f:
                    f.write(user_line + "\n")
             except Exception as e:
                print(f"Error writing to user log: {e}")
