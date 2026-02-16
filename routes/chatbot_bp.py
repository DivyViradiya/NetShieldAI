from flask import Blueprint, render_template, request, jsonify, session, Response, stream_with_context
from flask_login import login_required, current_user
import requests
import os
import uuid
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from werkzeug.utils import secure_filename

# [NEW] Import db for stats tracking
from extensions import db
from Services import network_scanner, zap_scanner, ssl_scanner, sql_scanner, packet_sniffer, api_scanner, killchain_service, semgrep_scanner

# Initialize the Flask Blueprint for chatbot-related routes
chatbot_bp = Blueprint('chatbot_bp', __name__)

def get_all_active_scans(user_identifier):
    """Checks status across all scanner modules for a user and returns their stream endpoints."""
    active = {}
    try:
        if network_scanner.is_scan_running(user_identifier): 
            active['nmap_scan'] = {'stream_url': '/network_scanner/log_stream'}
        if zap_scanner.is_scan_running(user_identifier): 
            active['zap_scan'] = {'stream_url': '/zap_scanner/log_stream'}
        if ssl_scanner.is_scan_running(user_identifier): 
            active['ssl_scan'] = {'stream_url': '/ssl_scanner/log_stream'}
        if sql_scanner.is_scan_running(user_identifier): 
            active['sql_injection_scan'] = {'stream_url': '/sql_scanner/log_stream'}
        if packet_sniffer.is_scan_running(user_identifier): 
            active['packet_sniffer'] = {'stream_url': '/packet_sniffer/log_stream'}
        if api_scanner.is_scan_running(user_identifier): 
            active['api_security_scan'] = {'stream_url': '/api_scanner/log_stream'}
        if killchain_service.is_scan_running(user_identifier): 
            active['killchain_audit'] = {'stream_url': '/killchain/log_stream'}
        if semgrep_scanner.is_scan_running(user_identifier): 
            active['semgrep_sast_scan'] = {'stream_url': '/semgrep_scanner/log_stream'}
    except Exception as e:
        logger.error(f"Error checking active scans: {e}")
    return active

# --- Logging Setup ---
BASE_LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
SYSTEM_LOG_DIR = os.path.join(BASE_LOG_DIR, "system")
USERS_LOG_DIR = os.path.join(BASE_LOG_DIR, "users")

os.makedirs(SYSTEM_LOG_DIR, exist_ok=True)
os.makedirs(USERS_LOG_DIR, exist_ok=True)

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
    """Returns a logger specifically for a user, saving to logs/users/{user_id}/chatbot.log"""
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

MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB

# --- Helper to resolve User Paths ---
def get_user_pdf_path(scanner_type):
    """
    Dynamically resolves the path to a specific report PDF for the current user.
    """
    if not current_user.is_authenticated:
        return None
        
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # NEW LOGIC: Composite Identifier (Matches other blueprints)
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    results_root = os.path.join(base_dir, 'Services', 'results', user_identifier)
    
    # Map scanner types to their folder and filename conventions
    path_map = {
        'nmap': os.path.join(results_root, 'network_scanner', 'nmap_report.pdf'),
        'zap': os.path.join(results_root, 'zap_scanner', 'zap_report.pdf'),
        'ssl': os.path.join(results_root, 'ssl_scanner', 'ssl_report.pdf'),
        'packet_sniffer': os.path.join(results_root, 'packet_sniffer', 'pcap_analysis_report.pdf'),
        'sql': os.path.join(results_root, 'sql_scanner', 'sql_report.pdf'),
        'killchain': os.path.join(results_root, 'killchain', 'reports', 'killchain_report.pdf')
    }

    return path_map.get(scanner_type)


@chatbot_bp.route('/')
@login_required
def chatbot_page():
    """Renders the chatbot UI page with PRE-LOADED session data to prevent UI lag."""
    print(f"\033[35m[*] Accessing AI Analyst Page (User: {current_user.username})\033[0m")
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

        # Pass the pre-fetched data directly to the template
        return render_template('chatbot.html', initial_sessions=initial_sessions)
        
    except Exception as e:
        logger.error(f"Error in chatbot_page for user {user_identifier}: {str(e)}", exc_info=True)
        return jsonify({"error": "An error occurred while loading the chatbot page"}), 500


@chatbot_bp.route('/upload_report', methods=['POST'])
@login_required
def upload_report():
    """Handles manual file uploads by sending them to the central server proxy."""
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        print(f"\033[35m[*] Manual Report Upload: {file.filename} (User: {current_user.username})\033[0m")
        llm_mode_param = request.form.get('llm_mode', 'gemini-2.5-flash')

        if file and file.filename.endswith('.pdf'):
            if file.content_length > MAX_FILE_SIZE_BYTES:
                return jsonify({'error': f'File size exceeds the limit of {MAX_FILE_SIZE_BYTES / (1024 * 1024)}MB.'}), 413

            try:
                # [NEW] Increment AI Usage Counter
                try:
                    current_user.scan_count_ai += 1
                    db.session.commit()
                except Exception as e:
                    user_logger.error(f"Failed to update AI stats: {e}")

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

        return jsonify({'error': 'Invalid file format. Only PDF files are allowed.'}), 400
    except Exception as e:
        user_logger.error(f"Error in upload_report: {str(e)}", exc_info=True)
        return jsonify({"error": "An error occurred while uploading the report"}), 500


@chatbot_bp.route('/chat', methods=['POST'])
@login_required
def chat_with_ai():
    """
    Standard (Blocking) Chat Endpoint.
    Updated to handle options like verbosity and incognito mode.
    """
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    try:
        data = request.json
        user_message = data.get('message')
        print(f"\033[35m[*] AI Chat Request from {current_user.username}: {user_message[:50]}...\033[0m")
        verbosity = data.get('verbosity', 'standard')
        is_incognito = data.get('is_incognito', False)
        llm_mode = data.get('llm_mode', 'gemini-2.5-flash')
        
        current_session_id = session.get('chatbot_session_id')

        # Increment AI Usage Counter (Only if not incognito)
        if not is_incognito:
            try:
                current_user.scan_count_ai += 1
                db.session.commit()
            except Exception as e:
                user_logger.error(f"Failed to update AI stats: {e}")

        payload_to_server = {
            'message': user_message,
            'session_id': current_session_id,
            'user_id': user_identifier,
            'verbosity': verbosity,
            'is_incognito': is_incognito,
            'llm_mode': llm_mode
        }

        proxy_chat_url = f"{SERVER_PROXY_URL}/chat"
        
        # Make the request using persistent session
        response = http_session.post(proxy_chat_url, json=payload_to_server)
        response.raise_for_status()

        result_from_server = response.json()

        # Update local session ID if the backend created a new one
        if 'session_id' in result_from_server and result_from_server['session_id']:
            new_session_id = result_from_server['session_id']
            if new_session_id != current_session_id:
                session['chatbot_session_id'] = new_session_id
                user_logger.info(f"Local session ID updated by server to: {session['chatbot_session_id']}")

        return jsonify(result_from_server)

    except requests.exceptions.RequestException as e:
        user_logger.error(f"Error communicating with server proxy chat service: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'Failed to get response from server. ({e})'}), 500
    except Exception as e:
        user_logger.error(f"An unexpected error occurred in chat route: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'An unexpected error occurred: {e}'}), 500


# =======================================================================
# NEW STREAMING PROXY ENDPOINT
# =======================================================================
@chatbot_bp.route('/chat_stream', methods=['POST'])
@login_required
def chat_with_ai_stream():
    """
    Proxies the streaming chat request to the backend with options.
    """
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    try:
        data = request.json
        user_message = data.get('message')
        verbosity = data.get('verbosity', 'standard')
        is_incognito = data.get('is_incognito', False)
        llm_mode = data.get('llm_mode', 'gemini-2.5-flash')
        
        current_session_id = session.get('chatbot_session_id')

        # [NEW] Increment AI Usage Counter (Only if not incognito)
        if not is_incognito:
            try:
                current_user.scan_count_ai += 1
                db.session.commit()
            except Exception as e:
                user_logger.error(f"Failed to update AI stats: {e}")

        payload_to_server = {
            'message': user_message,
            'session_id': current_session_id,
            'user_id': user_identifier,
            'verbosity': verbosity,
            'is_incognito': is_incognito,
            'llm_mode': llm_mode
        }

        # Point to the NEW FastAPI endpoint
        proxy_chat_url = f"{SERVER_PROXY_URL}/chat_stream"
        
        user_logger.info(f"Initiating stream to {proxy_chat_url} for session {current_session_id}")
        
        # Use persistent session for streaming too
        req = http_session.post(proxy_chat_url, json=payload_to_server, stream=True)
        
        new_sess_id = req.headers.get("X-Session-ID")
        if new_sess_id and new_sess_id != current_session_id:
             session['chatbot_session_id'] = new_sess_id
             user_logger.info(f"Stream updated local session ID to: {new_sess_id}")

        # 3. Generator to forward chunks
        def generate():
            try:
                for chunk in req.iter_content(chunk_size=None): # None = yield as received
                    if chunk:
                        yield chunk
            except Exception as e:
                user_logger.error(f"Stream Proxy Iteration Error: {e}")
                yield b" [Connection Error during stream]"

        headers = {"X-Session-ID": new_sess_id} if new_sess_id else {}
        return Response(stream_with_context(generate()), mimetype='text/plain', headers=headers)

    except requests.exceptions.RequestException as e:
        user_logger.error(f"Error communicating with server proxy stream: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'Failed to connect to AI server.'}), 500
    except Exception as e:
        user_logger.error(f"Unexpected error in stream proxy: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500


@chatbot_bp.route('/scanner_analysis', methods=['POST'])
@login_required
def scanner_analysis_proxy():
    """
    Optimized PDF analysis: Sends the FILE PATH instead of the full BYTES.
    FastAPI will read the file directly from the local disk.
    """
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    try:
        data = request.get_json()
        scanner_type = data.get('scanner_type')
        llm_mode = data.get('llm_mode', 'gemini-2.5-flash')
        # [NEW] Allow caller to decide if a fresh session is needed
        force_new_session = data.get('force_new_session', False)

        if not scanner_type:
            return jsonify({'error': 'Missing scanner type'}), 400

        # Dynamically resolve the absolute PDF path
        pdf_path = get_user_pdf_path(scanner_type)

        if not pdf_path:
             return jsonify({'error': 'Invalid scanner type provided.'}), 400

        if not os.path.exists(pdf_path):
            return jsonify({'error': f'PDF report for {scanner_type} not found. Please run a scan first.'}), 404
        
        try:
            current_user.scan_count_ai += 1
            db.session.commit()
        except Exception as e:
            user_logger.error(f"Failed to update AI stats: {e}")

        # Optimization: We only send the path string, not the file content
        # [FIXED] We only force a new session if force_new_session is True (e.g. from scanner pages)
        current_session_id = None if force_new_session else session.get('chatbot_session_id')

        params = {
            'llm_mode': llm_mode,
            'user_id': user_identifier,
            'file_path': pdf_path, # Send the path to backend
            'session_id': current_session_id
        }
        
        proxy_upload_url = f"{SERVER_PROXY_URL}/upload_report"
        
        user_logger.info(f"Sending {scanner_type} path-based analysis request to backend")
        
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
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    try:
        session_id = session.get('chatbot_session_id')
        if not session_id:
             return jsonify({'error': 'No active session'}), 400

        proxy_url = f"{SERVER_PROXY_URL}/clear_history"
        response = http_session.post(proxy_url, json={'session_id': session_id})
        return jsonify(response.json())
    except Exception as e:
        user_logger.error(f"Error in clear_history: {e}")
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
        response = http_session.post(proxy_url, json={'user_id': user_identifier})
        
        # Clear local session
        session.pop('chatbot_session_id', None)
        
        return jsonify(response.json())
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
        
        payload = {
            'session_id': session_id
        }
        
        try:
            response = requests.post(proxy_clear_url, json=payload, timeout=10)
            
            # Clear local flask session data
            session.pop('chatbot_session_id', None)
            return jsonify({'status': 'success', 'message': 'Chat session has been cleared successfully.'})
            
        except requests.exceptions.RequestException as e:
            user_logger.error(f"Error clearing chat via server proxy for session {session_id}: {e}")
            session.pop('chatbot_session_id', None) 
            return jsonify({'status': 'error', 'message': f'Failed to communicate with the backend service, but local session cleared.'}), 500

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
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    
    try:
        data = request.json
        tool = data.get('tool')
        params = data.get('parameters', {})
        
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
                    'target_url': params.get('target_url')
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
                    'scan_mode': params.get('scan_mode', 'quick')
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
                    'definition_url': params.get('definition_url')
                }
            },
            'killchain_audit': {
                'url': f"{base_url}/killchain/dispatch",
                'stream_url': f"{base_url}/killchain/log_stream",
                'payload': {
                    'target': params.get('target'),
                    'profile': params.get('profile', 'full_audit'),
                    'aggression': params.get('aggression', 'normal')
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
        
        user_logger.info(f"Triggering scanner: {config['url']} for user {current_user.username}")
        
        # Trigger the scan as a separate POST request
        # We don't wait for the scan to finish (they are already threaded in their bps)
        try:
            # Note: We use verify=False if using self-signed certs in dev, but usually not needed for localhost
            resp = requests.post(
                config['url'], 
                json=config['payload'], 
                cookies=cookies,
                headers={'X-CSRFToken': request.headers.get('X-CSRFToken')}, # Pass CSRF if needed
                timeout=5
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

@chatbot_bp.route('/get_history', methods=['GET'])
@login_required
def get_chat_history_proxy():
    """
    Proxies the history fetch request to the backend.
    """
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    try:
        session_id = session.get('chatbot_session_id')
        
        if not session_id:
            return jsonify({'chat_history': [], 'session_metadata': None})

        proxy_url = f"{SERVER_PROXY_URL}/get_history"
        params = {
            'user_id': user_identifier, 
            'session_id': session_id
        }
        
        try:
            response = requests.get(proxy_url, params=params, timeout=5)
            response.raise_for_status()
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
        current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
        proxy_url = f"{SERVER_PROXY_URL}/get_user_sessions"
        params = {'user_id': current_user_identifier}
        
        response = requests.get(proxy_url, params=params, timeout=5)
        return jsonify(response.json())
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

# =======================================================================
# NEW ROUTES FOR PIN, RENAME, DELETE
# =======================================================================

@chatbot_bp.route('/delete_session', methods=['POST'])
@login_required
def delete_session_proxy():
    """
    Proxies the request to delete a SPECIFIC session (not necessarily the active one).
    """
    user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
    user_logger = get_user_logger(user_identifier)
    try:
        data = request.json
        target_session_id = data.get('session_id')
        
        if not target_session_id:
             return jsonify({'error': 'Missing session_id'}), 400

        proxy_url = f"{SERVER_PROXY_URL}/delete_session"
        response = requests.post(proxy_url, json={'session_id': target_session_id})
        
        # If the deleted session was the currently active one, clear the cookie
        if session.get('chatbot_session_id') == target_session_id:
            session.pop('chatbot_session_id', None)
            
        return jsonify(response.json()), response.status_code
    except Exception as e:
        user_logger.error(f"Error deleting session: {e}")
        return jsonify({'error': str(e)}), 500


@chatbot_bp.route('/rename_session', methods=['POST'])
@login_required
def rename_session_proxy():
    """
    Proxies the request to rename a session.
    """
    try:
        data = request.json
        # Expects: { session_id: "...", new_title: "..." }
        proxy_url = f"{SERVER_PROXY_URL}/rename_session"
        response = requests.post(proxy_url, json=data)
        return jsonify(response.json()), response.status_code
    except Exception as e:
         return jsonify({'error': str(e)}), 500


@chatbot_bp.route('/toggle_pin', methods=['POST'])
@login_required
def toggle_pin_proxy():
    """
    Proxies the request to pin/unpin a session.
    """
    try:
        data = request.json
        # Expects: { session_id: "...", is_pinned: boolean }
        proxy_url = f"{SERVER_PROXY_URL}/toggle_pin"
        response = requests.post(proxy_url, json=data)
        return jsonify(response.json()), response.status_code
    except Exception as e:
         return jsonify({'error': str(e)}), 500