import requests
import os
from functools import wraps
from flask import session, redirect, url_for, flash

# --- Configuration ---
API_BASE_URL = "https://isectrain.com/vulnscanai/api" # Use your actual hosted app URL

TOKEN_FILE_PATH = os.path.join(os.path.dirname(__file__), '..', '.auth_token')

# --- Token Management (No changes here) ---

def save_token(token):
    """Saves the JWT to a local file."""
    try:
        with open(TOKEN_FILE_PATH, "w") as f:
            f.write(token)
    except IOError as e:
        print(f"Error saving token: {e}")

def load_token():
    """Loads the JWT from the local file if it exists."""
    if os.path.exists(TOKEN_FILE_PATH):
        try:
            with open(TOKEN_FILE_PATH, "r") as f:
                return f.read().strip()
        except IOError as e:
            print(f"Error loading token: {e}")
    return None

def remove_token():
    """Deletes the local token file to log out."""
    if os.path.exists(TOKEN_FILE_PATH):
        os.remove(TOKEN_FILE_PATH)

# --- API Interaction Functions ---

def api_login(email, password):
    """
    Contacts the web app's API to log in.
    Returns (True, None) on success, and (False, "Error Message") on failure.
    """
    try:
        response = requests.post(f"{API_BASE_URL}/login", json={"email": email, "password": password}, timeout=10)
        
        if response.status_code == 200:
            token = response.json().get('access_token')
            save_token(token)
            return True, None
        else:
            error_msg = response.json().get("msg", "An unknown error occurred.")
            return False, error_msg
            
    except requests.exceptions.RequestException as e:
        return False, f"Could not connect to the server: {e}"

def get_user_profile():
    """
    Fetches user data from the server using the stored token.
    Returns the user data dictionary on success, None on failure.
    """
    token = load_token()
    if not token:
        return None

    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.get(f"{API_BASE_URL}/user", headers=headers, timeout=10)
        if response.status_code == 200:
            user_data = response.json()
            # --- CHANGE IS HERE ---
            # We now store all the required user details in the session
            session['username'] = user_data.get('username')
            session['email'] = user_data.get('email')
            session['phone_number'] = user_data.get('phone_number')
            session['subscription_plan'] = user_data.get('subscription_plan')
            session['subscription_expiry'] = user_data.get('subscription_expiry')
            session['is_subscription_active'] = user_data.get('is_subscription_active')
            return user_data
        else:
            logout()
            return None
    except requests.exceptions.RequestException:
        return None

def logout():
    """Logs the user out by deleting the local token and clearing the session."""
    remove_token()
    session.clear()

# --- Custom Decorator for Protecting Routes (No changes here) ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if get_user_profile() is None:
            flash("Your session has expired or you are not logged in. Please log in.", "warning")
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function
