from flask import Blueprint, render_template, request, jsonify, session
from flask_login import login_required, current_user
import requests
import os
import uuid
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from werkzeug.utils import secure_filename

# Initialize the Flask Blueprint for chatbot-related routes
chatbot_bp = Blueprint('chatbot_bp', __name__)

# --- Logging Setup ---
log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'chatbot_logs.txt')

logger = logging.getLogger('chatbot')
logger.setLevel(logging.INFO)

# Use RotatingFileHandler to prevent logs from growing indefinitely
file_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024 * 5, backupCount=5, encoding='utf-8')
file_handler.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.ERROR)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)
logger.info("Chatbot Blueprint initialized")

# =======================================================================
# Proxy Configuration
# =======================================================================
# This points to the AI Backend Service.
# NOTE: Ensure your AI Backend (FastAPI/Flask) is running on this specific port.
SERVER_PROXY_URL = "http://localhost:5000"

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
        'packet_sniffer': os.path.join(results_root, 'packet_sniffer', 'pcap_analysis_report.pdf')
    }
    
    return path_map.get(scanner_type)


@chatbot_bp.route('/')
@login_required
def chatbot_page():
    """Renders the chatbot UI page and ensures a session ID exists."""
    try:
        # If no session ID exists, generate one but don't persist to DB until user chats/uploads
        if 'chatbot_session_id' not in session:
            session['chatbot_session_id'] = str(uuid.uuid4())
            logger.info(f"New local chat session started for user {current_user.id}: {session['chatbot_session_id']}")
        return render_template('chatbot.html')
    except Exception as e:
        logger.error(f"Error in chatbot_page: {str(e)}", exc_info=True)
        return jsonify({"error": "An error occurred while loading the chatbot page"}), 500


@chatbot_bp.route('/upload_report', methods=['POST'])
@login_required
def upload_report():
    """Handles manual file uploads by sending them to the central server proxy."""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        llm_mode_param = request.form.get('llm_mode', 'local')

        if file and file.filename.endswith('.pdf'):
            if file.content_length > MAX_FILE_SIZE_BYTES:
                return jsonify({'error': f'File size exceeds the limit of {MAX_FILE_SIZE_BYTES / (1024 * 1024)}MB.'}), 413

            try:
                # Read file into memory to proxy it
                files_to_send = {'file': (file.filename, file.read(), file.content_type)}
                
                # Inject composite user_id into params
                current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
                params = {
                    'llm_mode': llm_mode_param,
                    'user_id': current_user_identifier
                }
                
                proxy_upload_url = f"{SERVER_PROXY_URL}/upload_report"
                
                logger.info(f"Sending file to server proxy ({llm_mode_param} mode) for User {current_user_identifier}")
                
                # Send request (no timeout set here to allow large file processing, but consider adding one in prod)
                response = requests.post(proxy_upload_url, files=files_to_send, params=params)
                response.raise_for_status()

                analysis_result = response.json()
                
                # Update session ID if backend provides one
                if 'session_id' in analysis_result:
                    session['chatbot_session_id'] = analysis_result['session_id'] 
                    logger.info(f"Stored session ID from server: {analysis_result['session_id']}")

                if "error" in analysis_result:
                    return jsonify(analysis_result), response.status_code
                
                return jsonify({'message': analysis_result.get('summary', 'Report uploaded and processed.')})
            
            except requests.exceptions.RequestException as e:
                logger.error(f"Error communicating with server proxy during upload: {e}", exc_info=True)
                return jsonify({'error': f'Error communicating with the central server: {str(e)}'}), 500
            except Exception as e:
                logger.error(f"An unexpected error occurred during upload: {e}", exc_info=True)
                return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

        return jsonify({'error': 'Invalid file format. Only PDF files are allowed.'}), 400
    except Exception as e:
        logger.error(f"Error in upload_report: {str(e)}", exc_info=True)
        return jsonify({"error": "An error occurred while uploading the report"}), 500


@chatbot_bp.route('/chat', methods=['POST'])
@login_required
def chat_with_ai():
    """Sends a chat message to the central server proxy."""
    try:
        user_message = request.json.get('message')
        current_session_id = session.get('chatbot_session_id')

        # Inject composite user_id into payload
        current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
        payload_to_server = {
            'message': user_message,
            'session_id': current_session_id,
            'user_id': current_user_identifier
        }

        proxy_chat_url = f"{SERVER_PROXY_URL}/chat"
        
        # Make the request to the server proxy
        response = requests.post(proxy_chat_url, json=payload_to_server)
        response.raise_for_status()

        result_from_server = response.json()

        # Update local session ID if the backend created a new one
        if 'session_id' in result_from_server and result_from_server['session_id']:
            new_session_id = result_from_server['session_id']
            if new_session_id != current_session_id:
                session['chatbot_session_id'] = new_session_id
                logger.info(f"Local session ID updated by server to: {session['chatbot_session_id']}")

        return jsonify(result_from_server)

    except requests.exceptions.RequestException as e:
        logger.error(f"Error communicating with server proxy chat service: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'Failed to get response from server. ({e})'}), 500
    except Exception as e:
        logger.error(f"An unexpected error occurred in chat route: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'An unexpected error occurred: {e}'}), 500

@chatbot_bp.route('/scanner_analysis', methods=['POST'])
@login_required
def scanner_analysis_proxy():
    """
    Handles PDF analysis requests initiated by the scanner pages. 
    Reads the specific scanner's PDF file from the USER's directory and proxies it.
    """
    try:
        data = request.get_json()
        scanner_type = data.get('scanner_type')
        llm_mode = data.get('llm_mode', 'local')

        if not scanner_type:
            return jsonify({'error': 'Missing scanner type'}), 400

        # Dynamically resolve the PDF path for the current logged-in user
        pdf_path = get_user_pdf_path(scanner_type)

        if not pdf_path:
             return jsonify({'error': 'Invalid scanner type provided.'}), 400

        if not os.path.exists(pdf_path):
            return jsonify({'error': f'PDF report for {scanner_type} not found. Please run a scan first.'}), 404
        
        # 1. Read the file content
        with open(pdf_path, 'rb') as f:
            pdf_content = f.read()

        # 2. Prepare the request
        filename = os.path.basename(pdf_path)
        files_to_send = {'file': (filename, pdf_content, 'application/pdf')}
        
        # 3. Inject composite user_id into params
        current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
        params = {
            'llm_mode': llm_mode,
            'user_id': current_user_identifier
        }
        
        proxy_upload_url = f"{SERVER_PROXY_URL}/upload_report"
        
        logger.info(f"Sending {scanner_type} report to server proxy ({llm_mode} mode) for User {current_user_identifier}")
        
        response = requests.post(proxy_upload_url, files=files_to_send, params=params)
        response.raise_for_status()

        analysis_result = response.json()
        
        if 'session_id' in analysis_result:
            session['chatbot_session_id'] = analysis_result['session_id'] 
            logger.info(f"Stored session ID from server: {analysis_result['session_id']}")

        if "error" in analysis_result:
            return jsonify(analysis_result), response.status_code
        
        return jsonify({
            'status': 'success',
            'summary': analysis_result.get('summary', 'Report uploaded and processed.'),
            'llm_mode': llm_mode
        })

    except requests.exceptions.RequestException as e:
        logger.error(f"Error communicating with server proxy during scanner analysis: {e}", exc_info=True)
        return jsonify({'error': f'Error communicating with the central server: {str(e)}'}), 500
    except Exception as e:
        logger.error(f"An unexpected error occurred during scanner analysis: {e}", exc_info=True)
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500


@chatbot_bp.route('/clear_chat', methods=['POST'])
@login_required
def clear_chat():
    """
    Legacy endpoint: clears the ACTIVE session.
    """
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
            logger.error(f"Error clearing chat via server proxy for session {session_id}: {e}")
            session.pop('chatbot_session_id', None) 
            return jsonify({'status': 'error', 'message': f'Failed to communicate with the backend service, but local session cleared.'}), 500

    except Exception as e:
        logger.error(f"An unexpected error occurred in clear_chat: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'An unexpected server error occurred.'}), 500
    
    
@chatbot_bp.route('/get_history', methods=['GET'])
@login_required
def get_chat_history_proxy():
    """
    Proxies the history fetch request to the backend.
    """
    try:
        session_id = session.get('chatbot_session_id')
        
        if not session_id:
            return jsonify({'chat_history': [], 'session_metadata': None})

        current_user_identifier = f"{secure_filename(current_user.username)}_{current_user.id}"
        
        proxy_url = f"{SERVER_PROXY_URL}/get_history"
        params = {
            'user_id': current_user_identifier, 
            'session_id': session_id
        }
        
        try:
            response = requests.get(proxy_url, params=params, timeout=5)
            response.raise_for_status()
            return jsonify(response.json())
        except requests.exceptions.RequestException as e:
            logger.warning(f"Could not fetch history from backend: {e}")
            return jsonify({'chat_history': [], 'session_metadata': None})

    except Exception as e:
        logger.error(f"Error in get_chat_history_proxy: {e}", exc_info=True)
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
        logger.error(f"Error deleting session: {e}")
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