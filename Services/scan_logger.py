import re
from datetime import datetime
from core.time_utils import get_now_ist
import os
import time
from core.extensions import db
from models.models import ScanLog, User
from core.logger_setup import logger

BASE_LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".logs")
USERS_LOG_DIR = os.path.join(BASE_LOG_DIR, "users")

def get_active_log_file(user_result_dir, tool_name):
    """
    Returns the absolute path to the active log file for a specific tool and user.
    """
    user_dir = os.path.join(USERS_LOG_DIR, str(user_result_dir))
    os.makedirs(user_dir, exist_ok=True)
    return os.path.join(user_dir, f"{tool_name}_active.log")

# Pattern to detect SSE event lines written by send_sse_event()
# Format in log: [timestamp] [EVENT] EVENT: <event_name> | PAYLOAD: <json>
import re as _re
_SSE_EVENT_RE = _re.compile(r'\[EVENT\]\s+EVENT:\s+(\S+)\s+\|\s+PAYLOAD:\s+(.+)')

def tail_log_file(user_result_dir, tool_name):
    """
    Generator that tails the active log file for a user/tool.
    Yields new lines as they are written.
    Named SSE events written by send_sse_event() are emitted as proper
    'event: <name>\ndata: <payload>' SSE frames so JS EventSource.addEventListener
    listeners receive them correctly.
    """
    log_file = get_active_log_file(user_result_dir, tool_name)
    
    # Wait for file to exist (up to 10 × 0.5 s = 5 s)
    tries = 0
    while not os.path.exists(log_file):
        time.sleep(0.5)
        tries += 1
        if tries > 10:
            return  # Give up if file never appears

    heartbeat_count = 0
    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
        while True:
            # Handle file truncation (new scan reset)
            try:
                if os.path.exists(log_file) and os.path.getsize(log_file) < f.tell():
                    f.seek(0)
            except Exception:
                pass

            line = f.readline()
            if line:
                heartbeat_count = 0
                stripped = line.strip()
                if not stripped:
                    time.sleep(0.1)
                    continue
                try:
                    # Check if this line encodes a named SSE event
                    match = _SSE_EVENT_RE.search(stripped)
                    if match:
                        event_name = match.group(1)
                        payload    = match.group(2)
                        # Emit proper named SSE frame
                        yield f"event: {event_name}\ndata: {payload}\n\n"
                    else:
                        # Regular log line — emit as plain data message
                        yield f"data: {stripped}\n\n"
                except (OSError, GeneratorExit):
                    return  # Client disconnected
            else:
                # [REFINED] Heartbeat every ~4.5 seconds (15 * 0.3)
                heartbeat_count += 1
                if heartbeat_count >= 15:
                    yield ": keep-alive\n\n"
                    heartbeat_count = 0
                time.sleep(0.3)  # Wait for new content

from Services.report_manager import sanitize_filename

def log_scan_start(user_id, tool_name, target, scan_type="Standard", origin="manual"):
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
            start_time=get_now_ist(),
            origin=origin
        )
        db.session.add(new_log)
        db.session.commit()
        return new_log.id
    except Exception as e:
        logger.error(f"[!] Error logging scan start: {e}")
        return None

def log_scan_end(log_id, status="Completed", finding_count=0, critical_count=0, error_msg=None, duration=None, report_path=None):
    """
    Updates an existing ScanLog entry with completion details.
    Caller must be inside an app_context.
    """
    if not log_id: return

    try:
        log_entry = db.session.get(ScanLog, log_id)
        if log_entry:
            log_entry.end_time = get_now_ist()
            log_entry.status = status
            log_entry.finding_count = finding_count
            log_entry.severity_critical = critical_count
            log_entry.error_message = error_msg
            log_entry.report_path = report_path
            
            # Calculate Duration
            if duration is not None:
                log_entry.duration_seconds = duration
            elif log_entry.start_time:
                delta = log_entry.end_time - log_entry.start_time
                log_entry.duration_seconds = delta.total_seconds()
            
            db.session.commit()
    except Exception as e:
        logger.error(f"[!] Error logging scan end: {e}")

def create_full_scan_log(user_id, tool_name, target, duration, finding_count, status="Completed", scan_type="Standard", report_path=None, origin="manual"):
    """
    For tools that don't support async start/end logging easily, 
    this logs the entire event at once (e.g., for Nmap after it returns).
    Caller must be inside an app_context.
    """
    try:
        # Calculate implied start time
        now_ist = get_now_ist()
        end_time = now_ist
        start_time = datetime.fromtimestamp(now_ist.timestamp() - duration, now_ist.tzinfo)
        
        new_log = ScanLog(
            user_id=user_id,
            tool_name=tool_name,
            target=target,
            scan_type=scan_type,
            status=status,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration,
            finding_count=finding_count,
            report_path=report_path,
            origin=origin
        )
        db.session.add(new_log)
        db.session.commit()
    except Exception as e:
        logger.error(f"[!] Error logging full scan: {e}")

def reset_log_file(user_result_dir, tool_name):
    """
    Truncates the active log file for a specific user and tool.
    This ensures that new scans start with a fresh log view.
    """
    log_file = get_active_log_file(user_result_dir, tool_name)
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        # Open in write mode to truncate
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write(f"[{get_now_ist().strftime('%Y-%m-%d %H:%M:%S')}] Log cleared for new {tool_name} scan.\n")
    except Exception as e:
        logger.error(f"[!] Error resetting log file {log_file}: {e}")

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
        logger.error(f"[!] Error fetching active scan from DB: {e}")
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
            scan.end_time = get_now_ist()
            scan.error_message = error_message
            db.session.commit()
            return True
    except Exception as e:
        logger.error(f"[!] Error marking scan {log_id} as failed: {e}")
    return False

def get_debug_log_file(user_result_dir, tool_name):
    """
    Returns the absolute path to the debug log file for a specific tool and user.
    """
    user_dir = os.path.join(USERS_LOG_DIR, str(user_result_dir))
    os.makedirs(user_dir, exist_ok=True)
    return os.path.join(user_dir, f"{tool_name}_debug.log")

def clean_log_message(message):
    """
    Beautifies log messages for the user.
    Removes absolute paths, simplifies command lines, and hides secrets.
    """
    if not message: return ""
    
    # Preserve SSE Events (SYSTEM_EVENT or EVENT)
    if "SYSTEM_EVENT:" in message or "EVENT:" in message:
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

# Standard tags for user active logs
MSG_TAGS = {
    'INFO': '[*]',
    'STAGE': '[~]',
    'DATA': '[#]',
    'SUCCESS': '[+]',
    'WARNING': '[!]',
    'ERROR': '[!]'
}

def write_log(user_result_dir, tool_name, message, level='INFO'):
    """
    Centralized logging function.
    - Writes EVERYTHING to {tool_name}_debug.log
    - Writes ONLY CLEAN formatted messages to {tool_name}_active.log (User Stream) if in MSG_TAGS
    """
    timestamp = get_now_ist().strftime("%H:%M:%S")
    full_line = f"[{timestamp}] [{level}] {message}"
    
    # 1. Write to Debug Log (All levels)
    debug_file = get_debug_log_file(user_result_dir, tool_name)
    try:
        with open(debug_file, 'a', encoding='utf-8') as f:
            f.write(full_line + "\n")
    except Exception as e:
        logger.error(f"Error writing to debug log: {e}")

    # 2. Write to User Log (Active Stream) if level is supported
    if level in MSG_TAGS:
        tag = MSG_TAGS[level]
        clean_message = clean_log_message(message)
        
        # Verify message isn't empty or just a placeholder after cleaning
        if clean_message and clean_message.strip():
             user_file = get_active_log_file(user_result_dir, tool_name)
             # Use the tag (e.g., [*], [~], [+], [!])
             user_line = f"[{timestamp}] {tag} {clean_message}"
             
             try:
                with open(user_file, 'a', encoding='utf-8') as f:
                    f.write(user_line + "\n")
             except Exception as e:
                logger.error(f"Error writing to user log: {e}")

class ScannerLogger:
    """
    Helper class for scanners to log structured messsages with correct methods
    instead of relying on manual string pre-pending on client-side.
    """
    def __init__(self, user_result_dir, tool_name):
        self.user_result_dir = user_result_dir
        self.tool_name = tool_name

    def info(self, msg):
        write_log(self.user_result_dir, self.tool_name, msg, level='INFO')

    def stage(self, msg):
        write_log(self.user_result_dir, self.tool_name, msg, level='STAGE')

    def data(self, msg):
        write_log(self.user_result_dir, self.tool_name, msg, level='DATA')

    def success(self, msg):
        write_log(self.user_result_dir, self.tool_name, msg, level='SUCCESS')

    def warning(self, msg):
        write_log(self.user_result_dir, self.tool_name, msg, level='WARNING')

    def error(self, msg):
        write_log(self.user_result_dir, self.tool_name, msg, level='ERROR')

def get_scanner_logger(user_result_dir, tool_name):
    """Factory function to provide ScannerLogger instance."""
    return ScannerLogger(user_result_dir, tool_name)

def cleanup_old_logs(days=7):
    """
    Deletes log files (*.log, *.txt) in the USERS_LOG_DIR older than the specified number of days.
    """
    if not os.path.exists(USERS_LOG_DIR):
        return

    now = time.time()
    cutoff = now - (days * 86400)
    deleted_count = 0

    try:
        for user_folder in os.listdir(USERS_LOG_DIR):
            user_path = os.path.join(USERS_LOG_DIR, user_folder)
            if os.path.isdir(user_path):
                for filename in os.listdir(user_path):
                    if filename.endswith('.log') or filename.endswith('.txt'):
                        file_path = os.path.join(user_path, filename)
                        try:
                            if os.path.isfile(file_path):
                                mtime = os.path.getmtime(file_path)
                                if mtime < cutoff:
                                    os.remove(file_path)
                                    deleted_count += 1
                        except Exception as e:
                            logger.error(f"[!] Log cleanup error on {file_path}: {e}")
        
        logger.info(f"[*] [LOG CLEANUP] Removed {deleted_count} old log files.")
    except Exception as e:
         logger.error(f"[!] Fatal error during log cleanup: {e}")

