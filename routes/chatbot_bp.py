from flask import Blueprint, render_template, request, jsonify, session, Response, stream_with_context
from flask_login import login_required, current_user
import requests
import os
import json
import sys
import uuid
import logging
import time
import threading
from logging.handlers import RotatingFileHandler
from datetime import datetime
from pathlib import Path
from core.time_utils import get_now_ist, get_now_ist_str, to_ist
from werkzeug.utils import secure_filename

# [NEW] Import db for stats tracking
from core.extensions import db
from Services import network_scanner, zap_scanner, ssl_scanner, sql_scanner, packet_sniffer, api_scanner, killchain_service, semgrep_scanner, scan_logger, report_manager
from models.models import ScanLog, get_user_result_dir_name
from models.scheduler_models import ScanProfile, ProfileScanConfig, ProfileTarget, ScheduledScanJob
from Services import scheduler_service

# Initialize the Flask Blueprint for chatbot-related routes
chatbot_bp = Blueprint('chatbot_bp', __name__)

# --- TTL Cache for get_all_active_scans ---
# Without this, every get_history call runs 8 sequential DB queries + zombie checks.
# Cache prevents redundant checks within a 10-second window per user.
_active_scans_cache = {}   # { user_identifier: (timestamp, result) }
_active_scans_lock = threading.Lock()
_ACTIVE_SCANS_TTL = 10  # seconds

def get_all_active_scans(user_result_dir):
    """Checks status across all scanner modules for a user using the DATABASE.
    Results are TTL-cached per user to avoid 8x DB queries + zombie checks on every get_history call.
    """
    # [PERF] Return cached result if still fresh (avoids expensive repeated checks within 10s)
    with _active_scans_lock:
        cached = _active_scans_cache.get(user_result_dir)
        if cached and (time.time() - cached[0]) < _ACTIVE_SCANS_TTL:
            return cached[1]

    active = {}
    
    try:
        # We need the user_id (int) for DB lookups
        user_id = int(user_result_dir.split('_')[-1])
        
        # 1. Query DB for LATEST scan for each DB-supported tool
        # This ensures that even if a scan is Completed/Failed, the UI knows about it.
        db_tools = {
            'ZAP': {'key': 'zap_scan', 'stream': '/zap_scanner/log_stream'},
            'API': {'key': 'api_security_scan', 'stream': '/api_scanner/log_stream'},
            'Nmap': {'key': 'nmap_scan', 'stream': '/network_scanner/log_stream'},
            'SSLScan': {'key': 'ssl_scan', 'stream': '/ssl_scanner/log_stream'},
            'SQLMap': {'key': 'sql_injection_scan', 'stream': '/sql_scanner/log_stream'},
            'Sniffer': {'key': 'packet_sniffer', 'stream': '/packet_sniffer/log_stream'},
            'Semgrep SAST': {'key': 'semgrep_sast_scan', 'stream': '/semgrep_scanner/log_stream'},
            'Kill Chain': {'key': 'killchain_audit', 'stream': '/killchain/log_stream'}
        }

        for tool_name, config in db_tools.items():
            latest = ScanLog.query.filter_by(user_id=user_id, tool_name=tool_name).order_by(ScanLog.start_time.desc()).first()
            
            if latest:
                # Zombie Check (Only if DB says Running)
                if latest.status == 'Running':
                    is_actually_running = False
                    if tool_name == 'ZAP':
                        is_actually_running = zap_scanner.is_scan_running(user_result_dir)
                    elif tool_name == 'API':
                        is_actually_running = api_scanner.is_scan_running(user_result_dir)
                    elif tool_name == 'Nmap':
                        is_actually_running = network_scanner.is_scan_running(user_result_dir)
                    elif tool_name == 'SSLScan':
                        is_actually_running = ssl_scanner.is_scan_running(user_result_dir)
                    elif tool_name == 'SQLMap':
                        is_actually_running = sql_scanner.is_scan_running(user_result_dir)
                    elif tool_name == 'Sniffer':
                        is_actually_running = packet_sniffer.is_scan_running(user_result_dir)
                    elif tool_name == 'Semgrep SAST':
                        is_actually_running = semgrep_scanner.is_scan_running(user_result_dir)
                    elif tool_name == 'Kill Chain':
                        is_actually_running = killchain_service.is_user_scanning(user_result_dir)
                    
                    if not is_actually_running:
                        latest.status = 'Interrupted'
                        db.session.commit()

                active[config['key']] = {
                    'stream_url': config['stream'],
                    'status': latest.status.lower(), # running, completed, interrupted
                    'target': latest.target,
                    'timestamp': latest.start_time.strftime("%Y-%m-%d %H:%M:%S")
                }

    except Exception as e:
        logger.error(f"Error checking active scans: {e}")

    # [PERF] Store result in TTL cache (avoids repeated expensive checks)
    with _active_scans_lock:
        _active_scans_cache[user_result_dir] = (time.time(), active)

    return active

# --- Logging Setup ---
BASE_LOG_DIR = Path(__file__).parent.parent / ".logs"
SYSTEM_LOG_DIR = BASE_LOG_DIR / "system"
USERS_LOG_DIR = BASE_LOG_DIR / "users"

SYSTEM_LOG_DIR.mkdir(parents=True, exist_ok=True)
USERS_LOG_DIR.mkdir(parents=True, exist_ok=True)

# System Chatbot Logger
log_file = os.path.join(SYSTEM_LOG_DIR, 'chatbot_system_logs.txt')
logger = logging.getLogger('chatbot_system')
logger.setLevel(logging.INFO)

if not logger.handlers:
    file_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024 * 5, backupCount=5, encoding='utf-8')
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

def get_user_logger(user_identifier):
    """Returns a logger specifically for a user, saving to .logs/users/{user_id}/chatbot.log"""
    user_dir = os.path.join(USERS_LOG_DIR, user_identifier)
    os.makedirs(user_dir, exist_ok=True)
    
    user_log_file = os.path.join(user_dir, 'chatbot.log')
    user_logger = logging.getLogger(f'chatbot_user_{user_identifier}')
    
    if not user_logger.handlers:
        user_logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(user_log_file, maxBytes=1024 * 1024 * 2, backupCount=3, encoding='utf-8')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        handler.setFormatter(formatter)
        user_logger.addHandler(handler)
        
    return user_logger

logger.info("Chatbot Blueprint initialized")

# =======================================================================
# Proxy Configuration
# =======================================================================
# Use 127.0.0.1 to bypass DNS lookup for "localhost"
SERVER_PROXY_URL = "http://127.0.0.1:5000"

# Persistent Session for HTTP Keep-Alive
http_session = requests.Session()
http_session.trust_env = False  # Ignore system proxies for internal traffic

MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB

@chatbot_bp.route('/chatbot_uploads/<path:filename>')
@login_required
def proxy_uploads(filename):
    """Proxies static file requests to the FastAPI backend."""
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    target_url = f"{SERVER_PROXY_URL}/chatbot_uploads/{filename}"
    params = {'user_id': user_identifier}
    try:
        resp = http_session.get(target_url, stream=True, params=params)
        resp.raise_for_status()
        return Response(resp.content, content_type=resp.headers.get('content-type'))
    except Exception as e:
        return f"File not found: {e}", 404

def map_llm_mode(mode):
    """Maps frontend mode aliases to backend supported modes."""
    mapping = {
        'gemini': 'gemini-2.5-flash',
        'local': 'local'
    }
    return mapping.get(mode, mode)

def proxy_json_response(resp, user_logger=None):
    """
    Standardizes how we return JSON from the backend.
    Preserves RFC 7807 problem details and status codes.
    Also handles session sync (clearing local session on 404).
    """
    # 1. Session Sync: If session is missing in backend, purge local cookie
    if resp.status_code == 404:
        if 'chatbot_session_id' in session:
            if user_logger:
                user_logger.info(f"Purging local session ID {session['chatbot_session_id']} due to 404 from backend.")
            session.pop('chatbot_session_id', None)

    # 2. Extract JSON payload
    try:
        data = resp.json()
    except Exception:
        # Fallback if response is not JSON
        return jsonify({"error": resp.text or "Backend returned an empty or invalid response"}), resp.status_code

    return jsonify(data), resp.status_code

# --- Helper to resolve User Paths ---
def get_user_pdf_path(scanner_type, target=None):
    """
    Dynamically resolves the path to a specific report PDF for the current user.
    """
    if not current_user.is_authenticated:
        return None
        
    user_results_root = report_manager.get_user_results_dir(current_user)
    
    # Map scanner aliases to (Subfolder, ScannerPrefix)
    tool_map = {
        'nmap': ('network_scanner', 'network'),
        'zap': ('zap_scanner', 'zap'),
        'ssl': ('ssl_scanner', 'ssl'),
        'packet_sniffer': ('packet_sniffer', 'pcap_analysis_report'),
        'sql': ('sql_scanner', 'sql'),
        'killchain': ('killchain', 'killchain'),
        'api': ('api_scanner', 'api'),
        'semgrep': ('semgrep_scanner', 'semgrep')
    }
    
    if scanner_type not in tool_map:
        return None
        
    folder, scanner_prefix = tool_map[scanner_type]
    scan_dir = os.path.join(user_results_root, folder)
    
    if scanner_type == 'killchain':
        scan_dir = os.path.join(scan_dir, 'reports')

    if not os.path.exists(scan_dir):
        return None
        
    try:
        # report_manager.find_latest_report is now robust enough to handle the beautified prefixes
        return report_manager.find_latest_report(scan_dir, scanner_name=scanner_prefix, target=target, extension="pdf")
    except Exception as e:
        logger.error(f"Error finding latest PDF in {scan_dir}: {e}")
        return None


@chatbot_bp.route('/')
@login_required
def chatbot_page():
    """Renders the chatbot UI page with PRE-LOADED session data to prevent UI lag."""
    logger.info(f"[*] Accessing AI Analyst Page (User: {current_user.username})")
    user_result_dir = get_user_result_dir_name(current_user)
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    
    # [NEW] Handle Session ID from URL (e.g. after redirect from scanner)
    url_session_id = request.args.get('session_id')
    if url_session_id:
        session['chatbot_session_id'] = url_session_id
        user_logger.info(f"Session switched via URL parameter to: {url_session_id}")

    try:
        # If no session ID exists, generate one but don't persist to DB until user chats/uploads
        if 'chatbot_session_id' not in session:
            session['chatbot_session_id'] = str(uuid.uuid4())
            user_logger.info(f"New local chat session started: {session['chatbot_session_id']}")
        
        # [NEW] Pre-fetch Sessions Server-Side
        initial_sessions = []
        try:
            proxy_url = f"{SERVER_PROXY_URL}/get_user_sessions"
            resp = http_session.get(proxy_url, params={'user_id': user_identifier}, timeout=2)
            
            if resp.status_code == 200:
                data = resp.json()
                initial_sessions = data.get('sessions', [])
            else:
                user_logger.warning(f"Backend returned status {resp.status_code} during pre-fetch.")
                
        except Exception as e:
            user_logger.warning(f"Server-side session pre-fetch failed: {e}")

        # [NEW] Active Session Identifier for Frontend
        active_session_id = session.get('chatbot_session_id')

        # [NEW] Device Detection for Separate Frontend
        ua = request.headers.get('User-Agent', '').lower()
        is_mobile = any(keyword in ua for keyword in ['mobile', 'android', 'iphone', 'ipad', 'ipod'])
        template_name = 'chatbot_mobile.html' if is_mobile else 'chatbot.html'

        # Pass the pre-fetched data directly to the template
        return render_template(template_name, 
                               initial_sessions=initial_sessions, 
                               active_session_id=active_session_id)
        
    except Exception as e:
        logger.error(f"Error in chatbot_page for user {user_identifier}: {str(e)}", exc_info=True)
        return jsonify({"error": "An error occurred while loading the chatbot page"}), 500


@chatbot_bp.route('/upload_report', methods=['POST'])
@login_required
def upload_report():
    """Handles manual file uploads by sending them to the central server proxy."""
    user_result_dir = get_user_result_dir_name(current_user)
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        logger.info(f"[*] Manual Report Upload: {file.filename} (User: {current_user.username})")
        llm_mode_param = map_llm_mode(request.form.get('llm_mode', 'gemini-2.5-flash'))

        ALLOWED_EXTENSIONS = {'.pdf', '.png', '.jpg', '.jpeg', '.log', '.txt', '.pcap', '.pcapng', '.yaml', '.json'}
        ext = os.path.splitext(file.filename)[1].lower()
        
        if file and ext in ALLOWED_EXTENSIONS:
            if file.content_length > MAX_FILE_SIZE_BYTES:
                return jsonify({'error': f'File size exceeds the limit of {MAX_FILE_SIZE_BYTES / (1024 * 1024)}MB.'}), 413

            try:
                # Read file into memory to proxy it
                files_to_send = {'file': (file.filename, file.read(), file.content_type)}
                
                # [FIXED] Force a new session for report uploads
                params = {
                    'llm_mode': llm_mode_param,
                    'user_id': user_identifier,
                    'session_id': None 
                }
                
                proxy_upload_url = f"{SERVER_PROXY_URL}/upload_report"
                
                user_logger.info(f"Sending file to server proxy ({llm_mode_param} mode)")
                
                # Send request using persistent session
                response = http_session.post(proxy_upload_url, files=files_to_send, params=params)
                response.raise_for_status()

                analysis_result = response.json()
                
                # Update session ID if backend provides one
                if 'session_id' in analysis_result:
                    session['chatbot_session_id'] = analysis_result['session_id'] 
                    user_logger.info(f"Stored session ID from server: {analysis_result['session_id']}")

                if "error" in analysis_result:
                    return jsonify(analysis_result), response.status_code
                
                return jsonify({'message': analysis_result.get('summary', 'Report uploaded and processed.')})
            
            except requests.exceptions.RequestException as e:
                user_logger.error(f"Error communicating with server proxy during upload: {e}", exc_info=True)
                return jsonify({'error': f'Error communicating with the central server: {str(e)}'}), 500
            except Exception as e:
                user_logger.error(f"An unexpected error occurred during upload: {e}", exc_info=True)
                return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

        return jsonify({'error': f'Invalid file format. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'}), 400
    except Exception as e:
        user_logger.error(f"Error in upload_report: {str(e)}", exc_info=True)
        return jsonify({"error": "An error occurred while uploading the report"}), 500


def _prepare_chat_request():
    """Shared helper to extract and format chat request data for proxying."""
    if request.is_json:
        data = request.json
    else:
        # formData can contain both fields and files
        data = request.form
    
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_message = data.get('message')
    verbosity = data.get('verbosity', 'standard')
    is_incognito = data.get('is_incognito', False)
    # Convert 'true' strings from JS FormData if needed
    if isinstance(is_incognito, str):
        is_incognito = is_incognito.lower() == 'true'
        
    llm_mode = map_llm_mode(data.get('llm_mode', 'gemini-2.5-flash'))
    current_session_id = session.get('chatbot_session_id')

    payload = {
        'message': user_message,
        'session_id': current_session_id,
        'user_id': user_identifier,
        'verbosity': verbosity,
        'is_incognito': is_incognito,
        'llm_mode': llm_mode
    }

    files_to_send = []
    if request.files:
        # Support both 'files' and 'files[]' naming conventions
        file_list = request.files.getlist('files') or request.files.getlist('files[]')
        for f in file_list:
            files_to_send.append(('files', (f.filename, f.read(), f.content_type)))

    return payload, files_to_send, user_identifier, current_session_id

@chatbot_bp.route('/chat', methods=['POST'])
@login_required
def chat_with_ai():
    """Standard (Blocking) Chat Endpoint Proxy."""
    try:
        payload, files, user_id, _ = _prepare_chat_request()
        user_logger = get_user_logger(user_id)
        
        logger.info(f"[*] AI Chat Request from {current_user.username} (Blocking)")
        
        proxy_chat_url = f"{SERVER_PROXY_URL}/chat"
        params = {'user_id': user_id}

        if files:
            # Multipart POST
            response = http_session.post(proxy_chat_url, data=payload, files=files, params=params)
        else:
            # JSON POST
            response = http_session.post(proxy_chat_url, json=payload, params=params)
            
        return proxy_json_response(response, user_logger)

    except Exception as e:
        logger.error(f"Error in chat_with_ai proxy: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chatbot_bp.route('/chat_stream', methods=['POST'])
@login_required
def chat_with_ai_stream():
    """Proxies the streaming chat request to the backend with options."""
    try:
        payload, files, user_id, current_session_id = _prepare_chat_request()
        user_logger = get_user_logger(user_id)
        
        proxy_chat_url = f"{SERVER_PROXY_URL}/chat_stream"
        params = {'user_id': user_id}
        
        user_logger.info(f"Initiating stream for session {current_session_id}")
        
        if files:
            req = http_session.post(proxy_chat_url, data=payload, files=files, stream=True, params=params)
        else:
            req = http_session.post(proxy_chat_url, json=payload, stream=True, params=params)
        
        # Sync session ID from header if backend changed it (new session)
        new_sess_id = req.headers.get("X-Session-ID")
        if new_sess_id and new_sess_id != current_session_id:
             session['chatbot_session_id'] = new_sess_id

        def generate():
            try:
                for chunk in req.iter_content(chunk_size=None):
                    if chunk:
                        yield chunk
            except Exception as e:
                user_logger.error(f"Stream Proxy Error: {e}")
                yield b" [Connection Error during stream]"

        headers = {"X-Session-ID": new_sess_id} if new_sess_id else {}
        return Response(stream_with_context(generate()), mimetype='text/plain', headers=headers)

    except Exception as e:
        logger.error(f"Error in chat_with_ai_stream proxy: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500


@chatbot_bp.route('/scanner_analysis', methods=['POST'])
@login_required
def scanner_analysis_proxy():
    """
    Optimized PDF analysis: Sends the FILE PATH instead of the full BYTES.
    FastAPI will read the file directly from the local disk.
    """
    user_result_dir = get_user_result_dir_name(current_user)
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    try:
        data = request.get_json()
        scanner_type = data.get('scanner_type')
        target = data.get('target') # [NEW]
        llm_mode = map_llm_mode(data.get('llm_mode', 'gemini-2.5-flash'))
        # [NEW] Allow caller to decide if a fresh session is needed
        force_new_session = data.get('force_new_session', False)

        if not scanner_type:
            return jsonify({'error': 'Missing scanner type'}), 400

        # Dynamically resolve the absolute PDF path (handling target specificity)
        pdf_path = get_user_pdf_path(scanner_type, target=target)

        if not pdf_path:
             return jsonify({'error': 'Invalid scanner type provided.'}), 400

        if not os.path.exists(pdf_path):
            return jsonify({'error': f'PDF report for {scanner_type} not found. Please run a scan first.'}), 404
        
        # Optimization: We only send the path string, not the file content
        # [FIXED] We only force a new session if force_new_session is True (e.g. from scanner pages)
        current_session_id = None if force_new_session else session.get('chatbot_session_id')

        params = {
            'llm_mode': llm_mode,
            'user_id': user_identifier,
            'file_path': pdf_path, # Send the path to backend
            'session_id': current_session_id,
            'background': 'false' # Ensure synchronous response
        }
        
        proxy_upload_url = f"{SERVER_PROXY_URL}/upload_report"
        
        user_logger.info(f"Sending {scanner_type} path-based analysis request to backend (Target: {target})")
        
        # Use session and send without multipart files
        response = http_session.post(proxy_upload_url, params=params)
        response.raise_for_status()

        analysis_result = response.json()
        
        if 'session_id' in analysis_result:
            session['chatbot_session_id'] = analysis_result['session_id'] 
            user_logger.info(f"Stored session ID from server: {analysis_result['session_id']}")

        return jsonify({
            'status': 'success',
            'summary': analysis_result.get('summary', 'Report processed via shared storage.'),
            'llm_mode': llm_mode,
            'session_id': session.get('chatbot_session_id')
        })

    except requests.exceptions.RequestException as e:
        user_logger.error(f"Error communicating with server proxy during scanner analysis: {e}", exc_info=True)
        return jsonify({'error': f'Error communicating with the central server: {str(e)}'}), 500
    except Exception as e:
        user_logger.error(f"An unexpected error occurred during scanner analysis: {e}", exc_info=True)
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500


@chatbot_bp.route('/clear_history', methods=['POST'])
@login_required
def clear_history_proxy():
    """
    Wipes the chat history for the active session but keeps the report context.
    """
    user_result_dir = get_user_result_dir_name(current_user)
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    try:
        session_id = session.get('chatbot_session_id')
        if not session_id:
             return jsonify({'error': 'No active session'}), 400

        proxy_url = f"{SERVER_PROXY_URL}/clear_history"
        params = {'user_id': user_identifier}
        response = http_session.post(proxy_url, json={'session_id': session_id}, params=params)
        return proxy_json_response(response, user_logger)
    except Exception as e:
        user_logger.error(f"Error in clear_history: {e}")
        return jsonify({'error': str(e)}), 500


@chatbot_bp.route('/clear_memory', methods=['POST'])
@login_required
def clear_memory_proxy():
    """
    Wipes the agentic long-term memory (Rules & Facts) for the current user.
    """
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    try:
        proxy_url = f"{SERVER_PROXY_URL}/clear_memory"
        # The FastAPI endpoint expects a JSON payload with user_id
        payload = {'user_id': user_identifier}
        response = http_session.post(proxy_url, json=payload, timeout=10)
        return proxy_json_response(response, user_logger)
    except Exception as e:
        user_logger.error(f"Error in clear_memory: {e}")
        return jsonify({'error': str(e)}), 500


@chatbot_bp.route('/delete_all_sessions', methods=['POST'])
@login_required
def delete_all_sessions_proxy():
    """
    Master Reset: Deletes EVERYTHING for the current user.
    """
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    try:
        proxy_url = f"{SERVER_PROXY_URL}/delete_all_sessions"
        params = {'user_id': user_identifier}
        response = http_session.post(proxy_url, json={'user_id': user_identifier}, params=params)
        
        # Clear local session
        session.pop('chatbot_session_id', None)
        
        return proxy_json_response(response, user_logger)
    except Exception as e:
        user_logger.error(f"Error in delete_all_sessions: {e}")
        return jsonify({'error': str(e)}), 500


@chatbot_bp.route('/clear_chat', methods=['POST'])
@login_required
def clear_chat():
    """
    Legacy endpoint: clears the ACTIVE session.
    """
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    try:
        session_id = session.get('chatbot_session_id')
        if not session_id:
            return jsonify({'status': 'success', 'message': 'No active session to clear.'})

        proxy_clear_url = f"{SERVER_PROXY_URL}/delete_session"
        params = {'user_id': user_identifier}
        
        payload = {
            'session_id': session_id
        }
        
        try:
            response = http_session.post(proxy_clear_url, json=payload, params=params, timeout=10)
            return proxy_json_response(response, user_logger)
            
        except requests.exceptions.RequestException as e:
            user_logger.error(f"Error clearing chat via server proxy for session {session_id}: {e}")
            session.pop('chatbot_session_id', None) 
            return jsonify({'status': 'error', 'message': f'Failed to communicate with the backend service.'}), 500

    except Exception as e:
        user_logger.error(f"An unexpected error occurred in clear_chat: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'An unexpected server error occurred.'}), 500
    
    
@chatbot_bp.route('/execute_action', methods=['POST'])
@login_required
def execute_action():
    """
    Executes a security scan based on an AI-triggered action.
    Maps tool names to the internal Flask scanner endpoints.
    """
    user_result_dir = get_user_result_dir_name(current_user)
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    
    try:
        data = request.json
        tool = data.get('tool')
        params = data.get('parameters', {})
        action_id = data.get('action_id')
        
        if not tool:
            return jsonify({'error': 'No tool specified'}), 400

        user_logger.info(f"AI Action Execution requested: {tool} with params {params}")

        # Mapping of AI tool names to local Flask endpoints
        # We use absolute URLs via request.host_url to call our own blueprints
        base_url = request.host_url.rstrip('/')
        
        action_map = {
            'nmap_scan': {
                'url': f"{base_url}/network_scanner/scan",
                'stream_url': f"{base_url}/network_scanner/log_stream",
                'payload': {
                    'target_ip': params.get('target_ip'),
                    'scan_type': params.get('scan_type', 'default'),
                    'protocol_type': params.get('protocol_type', 'TCP'),
                    'timing': params.get('timing', 4)
                }
            },
            'zap_scan': {
                'url': f"{base_url}/zap_scanner/scan",
                'stream_url': f"{base_url}/zap_scanner/log_stream",
                'payload': {
                    'target_url': params.get('target_url'),
                    'scan_mode': params.get('scan_mode', 'Quick Scan'),
                    'use_ajax': params.get('use_ajax', False),
                    'auth_config': params.get('auth_config')
                }
            },
            'ssl_scan': {
                'url': f"{base_url}/ssl_scanner/scan",
                'stream_url': f"{base_url}/ssl_scanner/log_stream",
                'payload': {
                    'target_host': params.get('target_host')
                }
            },
            'sql_injection_scan': {
                'url': f"{base_url}/sql_scanner/scan",
                'stream_url': f"{base_url}/sql_scanner/log_stream",
                'payload': {
                    'target_url': params.get('target_url'),
                    'scan_mode': params.get('scan_mode', 'quick'),
                    'risk_level': params.get('risk_level', '3'),
                    'scan_level': params.get('scan_level', '3'),
                    'check_waf': params.get('check_waf', False)
                }
            },
            'packet_sniffer': {
                'url': f"{base_url}/packet_sniffer/start_capture",
                'stream_url': f"{base_url}/packet_sniffer/log_stream",
                'payload': {
                    'target_ip': params.get('target_ip'),
                    'duration': params.get('duration', 30),
                    'max_packets': params.get('max_packets', 50)
                }
            },
            'api_security_scan': {
                'url': f"{base_url}/api_scanner/scan",
                'stream_url': f"{base_url}/api_scanner/log_stream",
                'payload': {
                    'target_url': params.get('target_url'),
                    'definition_url': params.get('definition_url'),
                    'auth_token': params.get('auth_token')
                }
            },
            'killchain_audit': {
                'url': f"{base_url}/killchain/dispatch",
                'stream_url': f"{base_url}/killchain/log_stream",
                'payload': {
                    'target': params.get('target'),
                    'profile': params.get('profile', 'Full Scan'),
                    'aggression': params.get('aggression', 'Normal')
                }
            },
            'semgrep_sast_scan': {
                'url': f"{base_url}/semgrep_scanner/scan",
                'stream_url': f"{base_url}/semgrep_scanner/log_stream",
                'payload': {
                    'git_url': params.get('git_url')
                }
            }
        }

        if tool not in action_map:
            return jsonify({'error': f"Unsupported tool: {tool}"}), 400

        config = action_map[tool]
        
        # Security: Forward the session cookie so the sub-request is authenticated as the same user
        cookies = request.cookies
        
        # Avoid routing via external ngrok URLs for server-to-server call.
        # Ensure it hits the Flask app on port 5100.
        flask_local_base = "http://127.0.0.1:5100"
        internal_url = config['url'].replace(base_url, flask_local_base)
        
        user_logger.info(f"Triggering scanner: {internal_url} for user {current_user.username}")
        
        # Trigger the scan as a separate POST request
        # We don't wait for the scan to finish (they are already threaded in their bps)
        try:
            if action_id:
                config['payload']['action_id'] = action_id
                
            # Note: We use verify=False if using self-signed certs in dev, but usually not needed for localhost
            resp = requests.post(
                internal_url, 
                json=config['payload'], 
                cookies=cookies,
                headers={'X-CSRFToken': request.headers.get('X-CSRFToken')}, # Pass CSRF if needed
                timeout=5,
                proxies={"http": None, "https": None}
            )
            
            # If the scanner returned an error immediately (e.g. invalid IP)
            if resp.status_code >= 400:
                error_data = resp.json() if resp.headers.get('Content-Type') == 'application/json' else {'message': resp.text}
                return jsonify({
                    'status': 'error',
                    'message': f"Scanner Error: {error_data.get('message', 'Unknown failure')}"
                }), resp.status_code

            return jsonify({
                'status': 'success',
                'tool': tool,
                'stream_url': config.get('stream_url'),
                'message': f"Successfully initiated {tool.replace('_', ' ').title()}.",
                'scanner_response': resp.json()
            })

        except requests.exceptions.RequestException as e:
            user_logger.error(f"Error calling internal scanner {tool}: {e}")
            return jsonify({'status': 'error', 'message': f"Internal communication error: {str(e)}"}), 500

    except Exception as e:
        user_logger.error(f"Error in execute_action: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@chatbot_bp.route('/execute_schedule', methods=['POST'])
@login_required
def execute_schedule():
    """
    Schedules a security mission based on AI-triggered parameters.
    Creates or updates a 'Global AI Orchestration' profile.
    """
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    
    try:
        data = request.json
        tool_name = data.get('tool_name')
        target_val = data.get('target')
        tool_params = data.get('tool_parameters', {})
        schedule_type = data.get('schedule_type')
        
        if not tool_name or not target_val or not schedule_type:
            return jsonify({'status': 'error', 'message': 'Missing required scheduling parameters.'}), 400

        user_logger.info(f"AI Scheduling requested: {tool_name} on {target_val} ({schedule_type})")

        # 1. Map Tool Name
        mapping = {
            'nmap_scan': 'nmap', 'zap_scan': 'zap', 'ssl_scan': 'ssl',
            'sql_injection_scan': 'sql', 'packet_sniffer': 'sniffer',
            'semgrep_sast_scan': 'semgrep', 'api_security_scan': 'api',
            'killchain_audit': 'killchain'
        }
        module_id = mapping.get(tool_name)
        if not module_id:
            return jsonify({'status': 'error', 'message': f'Unsupported tool for scheduling: {tool_name}'}), 400

        # 2. Find or Create AI Profile
        profile_name = "Global AI Orchestration"
        profile = ScanProfile.query.filter_by(user_id=current_user.id, name=profile_name).first()
        if not profile:
            profile = ScanProfile(
                user_id=current_user.id,
                name=profile_name,
                description="Missions orchestrated via AI Analyst."
            )
            db.session.add(profile)
            db.session.commit()
            user_logger.info(f"Created new AI profile: {profile_name}")

        # 3. Add/Update Config for this module in the profile
        # For simplicity, we create a new config for each scheduled request to allow different params
        config = ProfileScanConfig(
            profile_id=profile.id,
            module=module_id,
            config_json=json.dumps(tool_params),
            display_label=f"AI: {tool_name.replace('_', ' ').title()}"
        )
        db.session.add(config)
        
        # 4. Add/Update Target
        target = ProfileTarget.query.filter_by(profile_id=profile.id, target_url=target_val).first()
        if not target:
            target = ProfileTarget(
                profile_id=profile.id,
                target_url=target_val
            )
            db.session.add(target)
        
        db.session.commit()

        # 5. Create the Job
        # Handle datetime conversion for once/one-shot
        one_shot_at = None
        if schedule_type == 'once' and data.get('one_shot_at'):
            try:
                one_shot_at = datetime.fromisoformat(data['one_shot_at'])
            except (ValueError, TypeError):
                user_logger.warning(f"Invalid datetime format: {data['one_shot_at']}")

        job = ScheduledScanJob(
            profile_id=profile.id,
            schedule_type=schedule_type,
            cron_hour=data.get('hour', 0),
            cron_minute=data.get('minute', 0),
            cron_day_of_week=data.get('day_of_week'),
            cron_day_of_month=str(data.get('day_of_month', '')),
            interval_minutes=data.get('interval_minutes'),
            one_shot_at=one_shot_at,
            is_enabled=True,
            send_report_email=True
        )
        db.session.add(job)
        db.session.commit()

        # 6. Register with APScheduler
        aps_id = scheduler_service.register_job(job)
        if aps_id:
            job.apscheduler_job_id = aps_id
            db.session.commit()
            user_logger.info(f"Registered job {aps_id} with APScheduler.")

        return jsonify({
            'status': 'success',
            'message': f"Mission scheduled successfully for {target_val}.",
            'job_id': job.id,
            'schedule': schedule_type,
            'next_run': job.next_run_at.isoformat() if job.next_run_at else None
        })

    except Exception as e:
        user_logger.error(f"Error in execute_schedule: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@chatbot_bp.route('/get_action_status', methods=['GET'])
@login_required
def get_action_status():
    """
    Returns the real-time status of a scan based on its Chatbot action_id.
    """
    action_id = request.args.get('action_id')
    if not action_id:
        return jsonify({"status": "error", "message": "Missing action_id"}), 400
        
    try:
        from Services import scan_logger
        scan = scan_logger.get_scan_log_by_correlation_id(action_id)
        
        if not scan:
            return jsonify({"status": "not_found", "message": "Scan not found for this action_id"}), 404
            
        tool_stream_map = {
            'Nmap': '/network_scanner/log_stream',
            'ZAP': '/zap_scanner/log_stream',
            'SSLScan': '/ssl_scanner/log_stream',
            'SQLMap': '/sql_scanner/log_stream',
            'Sniffer': '/packet_sniffer/log_stream',
            'Semgrep SAST': '/semgrep_scanner/log_stream',
            'API': '/api_scanner/log_stream',
            'Kill Chain': '/killchain/log_stream'
        }
            
        return jsonify({
            "status": "success",
            "scan_status": scan.status, # Running, Completed, Failed
            "tool": scan.tool_name,
            "stream_url": tool_stream_map.get(scan.tool_name)
        })
    except Exception as e:
        logger.error(f"Error getting action status: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@chatbot_bp.route('/get_history', methods=['GET'])
@login_required
def get_chat_history_proxy():
    """
    Proxies the history fetch request to the backend.
    """
    user_result_dir = get_user_result_dir_name(current_user)
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    try:
        session_id = request.args.get('session_id') or session.get('chatbot_session_id')
        
        if not session_id:
            return jsonify({'chat_history': [], 'session_metadata': None})

        proxy_url = f"{SERVER_PROXY_URL}/get_history"
        params = {
            'user_id': user_identifier, 
            'session_id': session_id
        }
        
        try:
            response = http_session.get(proxy_url, params=params, timeout=5)
            # We handle 404/sync inside the proxy helper
            # But get_history needs extra logic for active scans
            if response.status_code != 200:
                return proxy_json_response(response, user_logger)
                
            history_data = response.json()
            
            # Inject active scan status
            history_data['active_scans'] = get_all_active_scans(user_identifier)
            
            return jsonify(history_data)
        except requests.exceptions.RequestException as e:
            user_logger.warning(f"Could not fetch history from backend: {e}")
            return jsonify({'chat_history': [], 'session_metadata': None})

    except Exception as e:
        user_logger.error(f"Error in get_chat_history_proxy: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    
    
@chatbot_bp.route('/get_sessions', methods=['GET'])
@login_required
def get_sessions_proxy():
    """Proxies the request to get all user sessions."""
    try:
        user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
        proxy_url = f"{SERVER_PROXY_URL}/get_user_sessions"
        params = {'user_id': user_identifier}
        
        response = http_session.get(proxy_url, params=params, timeout=5)
        return proxy_json_response(response)
    except Exception as e:
        return jsonify({'sessions': []})

@chatbot_bp.route('/switch_session', methods=['POST'])
@login_required
def switch_session():
    """Updates the Flask session to point to a specific past session ID or clears it."""
    try:
        data = request.json
        
        # Check if the key exists in the payload
        if 'session_id' in data:
            new_session_id = data.get('session_id')
            
            if new_session_id:
                # Switch to a specific history item
                session['chatbot_session_id'] = new_session_id
            else:
                # Logic for "New Chat" (Received null) -> Clear the cookie
                # This forces chatbot_page to generate a fresh UUID on reload
                session.pop('chatbot_session_id', None)
                
            return jsonify({'success': True})
            
        return jsonify({'success': False, 'message': 'No session_id provided'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@chatbot_bp.route('/session/<session_id>/graph', methods=['GET'])
@login_required
def get_session_graph_proxy(session_id):
    """Proxies the request to fetch the interactive topology graph."""
    user_result_dir = get_user_result_dir_name(current_user)
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    try:
        proxy_url = f"{SERVER_PROXY_URL}/chatbot/session/{session_id}/graph"
        params = {'user_id': user_identifier}
        response = http_session.get(proxy_url, params=params, timeout=5)
        return proxy_json_response(response, user_logger)
            
    except requests.exceptions.RequestException as e:
        user_logger.error(f"Error fetching graph proxy: {e}")
        return jsonify({'success': False, 'message': 'Failed to connect to backend service.'}), 500
    except Exception as e:
        user_logger.error(f"Unexpected error in graph proxy: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

# =======================================================================
# NEW ROUTES FOR PIN, RENAME, DELETE
# =======================================================================

@chatbot_bp.route('/delete_session', methods=['POST'])
@login_required
def delete_session_proxy():
    """
    Proxies the request to delete a SPECIFIC session (not necessarily the active one).
    """
    user_result_dir = get_user_result_dir_name(current_user)
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    try:
        data = request.json
        target_session_id = data.get('session_id')
        
        if not target_session_id:
             return jsonify({'error': 'Missing session_id'}), 400

        proxy_url = f"{SERVER_PROXY_URL}/delete_session"
        params = {'user_id': user_identifier}
        response = http_session.post(proxy_url, json={'session_id': target_session_id}, params=params)
        
        # If the deleted session was the currently active one, clear the cookie
        if session.get('chatbot_session_id') == target_session_id:
            session.pop('chatbot_session_id', None)
            
        return proxy_json_response(response, user_logger)
    except Exception as e:
        user_logger.error(f"Error deleting session: {e}")
        return jsonify({'error': str(e)}), 500


@chatbot_bp.route('/rename_session', methods=['POST'])
@login_required
def rename_session_proxy():
    """
    Proxies the request to rename a session.
    """
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    try:
        data = request.json
        # Expects: { session_id: "...", new_title: "..." }
        proxy_url = f"{SERVER_PROXY_URL}/rename_session"
        params = {'user_id': user_identifier}
        response = http_session.post(proxy_url, json=data, params=params)
        return proxy_json_response(response, user_logger)
    except Exception as e:
         return jsonify({'error': str(e)}), 500


@chatbot_bp.route('/toggle_pin', methods=['POST'])
@login_required
def toggle_pin_proxy():
    """
    Proxies the request to pin/unpin a session.
    """
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    try:
        data = request.json
        # Expects: { session_id: "...", is_pinned: boolean }
        proxy_url = f"{SERVER_PROXY_URL}/toggle_pin"
        params = {'user_id': user_identifier}
        response = http_session.post(proxy_url, json=data, params=params)
        return proxy_json_response(response, user_logger)
    except Exception as e:
         return jsonify({'error': str(e)}), 500

@chatbot_bp.route('/submit_feedback', methods=['POST'])
@login_required
def submit_feedback():
    """
    Handles Like/Dislike feedback for AI responses.
    Proxies to the backend if an endpoint exists, or simply logs it.
    """
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    try:
        data = request.json
        session_id = data.get('session_id')
        is_helpful = data.get('is_helpful')
        
        user_logger.info(f"[*] User Feedback: Session {session_id} | Helpful: {is_helpful}")
        
        # Proxy to FastAPI backend
        proxy_url = f"{SERVER_PROXY_URL}/submit_feedback"
        params = {'user_id': user_identifier}
        try:
            resp = http_session.post(proxy_url, json=data, timeout=3, params=params)
            return proxy_json_response(resp, user_logger)
        except Exception:
            # If backend doesn't have this yet, just return success since we logged it
            return jsonify({'success': True, 'message': 'Feedback received.'})
            
    except Exception as e:
        user_logger.error(f"Error in submit_feedback: {e}")
        return jsonify({'error': str(e)}), 500

