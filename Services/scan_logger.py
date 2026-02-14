from datetime import datetime
from extensions import db
from models import ScanLog, User

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

def log_scan_end(log_id, status="Completed", finding_count=0, critical_count=0, error_msg=None):
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
            if log_entry.start_time:
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
