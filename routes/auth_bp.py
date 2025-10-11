from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from Services.api_client import api_login, logout, get_user_profile

# Create a new blueprint for authentication
auth_bp = Blueprint('auth', __name__, template_folder='templates')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles the login page for the desktop application.
    Displays the login form and sends credentials to the web app's API.
    """
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Email and password are required.', 'danger')
            return render_template('login.html')

        # Call the API client function to perform login
        success, error_message = api_login(email, password)

        if success:
            # On successful login, fetch the user profile to populate the session
            get_user_profile()
            flash('Login successful!', 'success')
            return redirect(url_for('index')) # Redirect to the main home page
        else:
            flash(f'Login Failed: {error_message}', 'danger')
            return render_template('login.html')

    # If it's a GET request, just show the login page
    return render_template('login.html')

@auth_bp.route('/logout')
def logout_route():
    """
    Handles logging out the user.
    """
    logout() # This calls the function from api_client.py
    flash('You have been logged out.', 'info')
    return redirect(url_for('index')) 
