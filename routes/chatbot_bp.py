from flask import Blueprint, render_template, request, jsonify, session
import requests
import os
import uuid
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from werkzeug.utils import secure_filename
from Services.api_client import login_required
from flask import redirect, url_for, flash # Make sure redirect, url_for, and flash are imported

# Initialize the Flask Blueprint for chatbot-related routes
chatbot_bp = Blueprint('chatbot_bp', __name__)

# --- Logging Setup (No changes needed) ---
log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'chatbot_logs.txt')
logger = logging.getLogger('chatbot')
logger.setLevel(logging.INFO)
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
# --- End of Logging Setup ---


# =======================================================================
# NEW: Configure the URL to point to the proxy on your main server.
# This is the only address the local app needs to know.
# =======================================================================
SERVER_PROXY_URL = "http://localhost:5000"

MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'uploads')


@chatbot_bp.route('/')
def chatbot_page():
    """Renders the chatbot UI page and ensures a session ID exists."""
    try:
        if 'chatbot_session_id' not in session:
            session['chatbot_session_id'] = str(uuid.uuid4())
            logger.info(f"New local chat session started: {session['chatbot_session_id']}")
        return render_template('chatbot.html')
    except Exception as e:
        logger.error(f"Error in chatbot_page: {str(e)}", exc_info=True)
        return jsonify({"error": "An error occurred while loading the chatbot page"}), 500


@chatbot_bp.route('/upload_report', methods=['POST'])
def upload_report():
    """Handles file uploads by sending them to the central server proxy."""
    try:
        if 'report_file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['report_file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        llm_mode_param = request.form.get('llm_mode', 'local')

        if file and file.filename.endswith('.pdf'):
            if file.content_length > MAX_FILE_SIZE_BYTES:
                return jsonify({'error': f'File size exceeds the limit of {MAX_FILE_SIZE_BYTES / (1024 * 1024)}MB.'}), 413

            # No need to save the file locally on the client app anymore,
            # we can just stream it directly.
            try:
                files_to_send = {'report_file': (file.filename, file.read(), file.content_type)}
                # The llm_mode is now sent as form data alongside the file
                form_data = {'llm_mode': llm_mode_param}
                
                # Construct the URL to the server's proxy endpoint
                proxy_upload_url = f"{SERVER_PROXY_URL}/upload_report"
                
                logger.info(f"Sending file to server proxy ({llm_mode_param} mode): {proxy_upload_url}")
                # Send the request to the server proxy
                response = requests.post(proxy_upload_url, files=files_to_send, data=form_data)
                response.raise_for_status()

                analysis_result = response.json()
                
                # The proxy returns the session_id from FastAPI, store it locally
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
def chat_with_ai():
    """Sends a chat message to the central server proxy."""
    try:
        user_message = request.json.get('message')
        current_session_id = session.get('chatbot_session_id')

        # This payload is sent to the proxy, which forwards it to FastAPI
        payload_to_server = {
            'message': user_message,
            'session_id': current_session_id
        }

        # Construct the URL to the server's proxy endpoint
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




@chatbot_bp.route('/clear_chat', methods=['POST'])
def clear_chat():
    """
    Receives an API request to clear the chat session.
    Returns a JSON response indicating success or failure.
    """
    try:
        session_id = session.get('chatbot_session_id')
        if not session_id:
            # If there's no session, the goal is achieved. Return success.
            return jsonify({'status': 'success', 'message': 'No active session to clear.'})

        # It's better to get the URL from app config
        proxy_clear_url = f"{SERVER_PROXY_URL}/clear_chat"
        payload = {'session_id': session_id}
        
        try:
            # Make the request to the backend service
            response = requests.post(proxy_clear_url, json=payload, timeout=10)
            response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
            
            # Clear local flask session data only after successful proxy call
            session.pop('chatbot_session_id', None)
            return jsonify({'status': 'success', 'message': 'Chat session has been cleared successfully.'})
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error clearing chat via server proxy for session {session_id}: {e}")
            return jsonify({'status': 'error', 'message': f'Failed to communicate with the backend service.'}), 500

    except Exception as e:
        logger.error(f"An unexpected error occurred in clear_chat: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'An unexpected server error occurred.'}), 500
