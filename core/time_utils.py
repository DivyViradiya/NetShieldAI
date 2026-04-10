from datetime import datetime, timezone, timedelta

# Indian Standard Time (IST) is UTC + 5:30
IST_OFFSET = timedelta(hours=5, minutes=30)
IST = timezone(IST_OFFSET)

def get_now_ist():
    """Returns the current datetime object in IST."""
    return datetime.now(IST)

def get_now_ist_str(format_str="%Y-%m-%d %H:%M:%S"):
    """Returns the current IST time as a formatted string."""
    return get_now_ist().strftime(format_str)

def get_now_ist_iso():
    """Returns the current IST time in ISO 8601 format."""
    return get_now_ist().isoformat()

def to_ist(dt_obj):
    """Converts an existing datetime object (naive or aware) to IST."""
    if dt_obj is None:
        return None
    
    # If naive, assume it was UTC (common for our DB)
    if dt_obj.tzinfo is None:
        dt_obj = dt_obj.replace(tzinfo=timezone.utc)
    
    return dt_obj.astimezone(IST)
