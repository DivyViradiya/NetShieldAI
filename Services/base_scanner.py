import time

class BaseScanner:
    def __init__(self, user_id, tool_name, target):
        self.user_id = user_id
        self.tool_name = tool_name
        self.target = target
        self.log_id = None
        self.start_time = None

    def start_scan(self, scan_type="Standard", origin="manual"):
        """Creates a ScanLog entry and marks the start time."""
        from Services import scan_logger
        self.log_id = scan_logger.log_scan_start(
            self.user_id, self.tool_name, self.target, scan_type=scan_type, origin=origin
        )
        self.start_time = time.time()
        return self.log_id

    def finalize_scan(self, status, finding_count, result_data, timestamp, scanner_type_key, critical_count=0, error_msg=None):
        """Updates the ScanLog and enqueues the async PDF task."""
        from Services import scan_logger, pdf_generator
        duration = time.time() - self.start_time if self.start_time else 0
        
        scan_logger.log_scan_end(
            self.log_id, 
            status=status, 
            finding_count=finding_count, 
            critical_count=critical_count,
            error_msg=error_msg,
            duration=duration
        )
        
        # Dispatch to async PDF generator
        if status == "Completed":
            pdf_generator.enqueue_pdf_task(
                self.log_id, scanner_type_key, result_data, self.user_id, self.target, timestamp
            )
