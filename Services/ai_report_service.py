import os
import requests
import logging
import traceback
from Services import pdf_generator, report_manager
from core.extensions import db
from core.time_utils import get_now_ist_str
from models.models import ScanLog

logger = logging.getLogger(__name__)

def generate_executive_summary(log_id, user_identifier, report_path=None, target=None, tool_name=None):
    """
    Orchestrates the AI executive summary generation:
    1. Finds the technical report if not provided.
    2. Calls the Chatbot to get an AI summary.
    3. Generates an executive PDF.
    4. Updates the database.
    """
    try:
        # 1. Resolve Data from log_id if needed
        log_row = db.session.get(ScanLog, log_id)
        if not log_row:
            logger.error(f"[!] Log ID {log_id} not found.")
            return False, "Scan log not found."

        if not target:
            target = log_row.target
        if not tool_name:
            tool_name = log_row.tool_name
        
        # Resolve Report Path
        if not report_path:
            # Find latest PDF for this user/target
            user_results_root = report_manager.get_user_results_dir(None) # Not ideal without user object
            # Better: use the path from the log if available or search specifically
            # For now, we expect report_path to be passed or we look in files
            pass

        if not report_path or not os.path.exists(report_path):
            return False, "Technical report PDF not found. Analysis aborted."

        exec_path = report_path.replace(".pdf", "_executive.pdf")

        # [NEW] Deduplication: If executive report already exists, don't re-run LLM
        if log_row.executive_summary_path and os.path.exists(log_row.executive_summary_path):
            logger.info(f"[*] Executive Summary already exists for Log {log_id}. Skipping LLM call.")
            return True, log_row.executive_summary_path

        # 2. Call Chatbot API
        # [FIX] Load from environment to match dashboard_bp.py
        SERVER_PROXY_URL = os.environ.get("CHATBOT_API_URL", "http://127.0.0.1:5000")
        proxy_url = f"{SERVER_PROXY_URL}/upload_report"

        params = {
            'llm_mode': 'gemini-2.5-flash',
            'user_id': user_identifier,
            'file_path': os.path.abspath(report_path),
            'background': False
        }

        logger.info(f"[*] Triggering AI Executive Summary for {target} (Log: {log_id})")
        resp = requests.post(proxy_url, params=params, proxies={"http": None, "https": None}) 
        resp.raise_for_status()

        data = resp.json()
        summary_text = data.get('summary')
        
        if not summary_text or "Analysis and summary are being generated" in summary_text:
             logger.warning(f"[!] Chatbot backend returned placeholder or no summary for Log {log_id}")
             return False, "AI summary engine returned an empty response. Please try again."

        # 3. Create PDF
        metadata = {
            "target": target,
            "tool_name": tool_name,
            "date": get_now_ist_str()
        }
        
        success = pdf_generator.create_executive_summary_report_pdf(summary_text, metadata, exec_path, user_id=user_identifier)
        
        if success:
            # 4. Save to DB
            log_row.executive_summary_path = exec_path
            db.session.commit()
            logger.info(f"[+] Executive Summary PDF created: {exec_path}")
            return True, exec_path
        else:
            return False, "Failed to render executive PDF."

    except Exception as e:
        logger.error(f"[!] Error generating executive summary: {e}")
        traceback.print_exc()
        return False, str(e)

