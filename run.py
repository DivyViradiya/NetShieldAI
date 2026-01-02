from flask import Flask, render_template, jsonify, request, Response
import threading
import json
import time
import os
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect

# --- Phase 1 Imports (Extensions & Models) ---
from extensions import db, login_manager
from models import User

# Import blueprints
from routes.network_scanner_bp import network_scanner_bp
from routes.zap_scanner_bp import zap_scanner_bp
from routes.ssl_scanner_bp import ssl_scanner_bp
from routes.chatbot_bp import chatbot_bp
from routes.auth_bp import auth_bp
from routes.packet_sniffer_bp import packet_sniffer_bp
from routes.dashboard_bp import dashboard_bp  # <--- NEW IMPORT

# --- Import the elevation function ---
from Services.network_scanner import ensure_admin_privileges

app = Flask(__name__)

# --- CONFIGURATION ---
app.secret_key = 'VulnScanAI' 

# Database Configuration (SQLite)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- INITIALIZE EXTENSIONS ---
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

# Initialize Global CSRF Protection
csrf = CSRFProtect(app)

# --- USER LOADER ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id)) 

# --- REGISTER BLUEPRINTS ---
app.register_blueprint(network_scanner_bp, url_prefix='/network_scanner')
app.register_blueprint(zap_scanner_bp, url_prefix='/zap_scanner')
app.register_blueprint(ssl_scanner_bp, url_prefix='/ssl_scanner')
app.register_blueprint(packet_sniffer_bp, url_prefix='/packet_sniffer')
app.register_blueprint(chatbot_bp, url_prefix='/chatbot')
app.register_blueprint(auth_bp)

# Register the new Dashboard Blueprint
app.register_blueprint(dashboard_bp, url_prefix='/dashboard') # <--- NEW REGISTRATION

@app.route('/')
def index():
    """Renders the main HTML page of the application."""
    return render_template('home.html')

@app.route('/arsenal')
def tools_hub():
    """Renders the central tools hub."""
    return render_template('tools_hub.html')


if __name__ == '__main__':
    ensure_admin_privileges()
    
    with app.app_context():
        db.create_all()

    app.run(host='0.0.0.0', port=5100, debug=True)