import sys
import os
import time
from pathlib import Path


from flask import Flask, render_template, jsonify, request
from flask_login import current_user
from flask_wtf.csrf import CSRFProtect
import logging
from colorama import Fore, Style, init

init(autoreset=True)

# --- Logging Setup ---
from logger_setup import logger

from extensions import db, login_manager
from models import User
from routes.network_scanner_bp import network_scanner_bp
from routes.zap_scanner_bp import zap_scanner_bp
from routes.ssl_scanner_bp import ssl_scanner_bp
from routes.chatbot_bp import chatbot_bp
from routes.auth_bp import auth_bp
from routes.packet_sniffer_bp import packet_sniffer_bp
from routes.dashboard_bp import dashboard_bp
from routes.killchain_bp import killchain_bp
from routes.sql_scanner_bp import sql_scanner_bp
from routes.semgrep_scanner_bp import semgrep_bp
from routes.api_scanner_bp import api_scanner_bp
from Services.network_scanner import ensure_admin_privileges



app = Flask(__name__)
app.secret_key = 'NetShieldAI' 

# --- [FIX] Use Absolute Path for Database ---
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'instance', 'users_db.sqlite3')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB limit for uploads

db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
csrf = CSRFProtect(app)

# Register Blueprints
logger.info("[*] Registering Core Modules...")
app.register_blueprint(network_scanner_bp, url_prefix='/network_scanner')
app.register_blueprint(zap_scanner_bp, url_prefix='/zap_scanner')
app.register_blueprint(ssl_scanner_bp, url_prefix='/ssl_scanner')
app.register_blueprint(packet_sniffer_bp, url_prefix='/packet_sniffer')
app.register_blueprint(chatbot_bp, url_prefix='/chatbot')
app.register_blueprint(auth_bp)
app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
app.register_blueprint(killchain_bp, url_prefix='/killchain')
app.register_blueprint(sql_scanner_bp, url_prefix='/sql_scanner')
app.register_blueprint(semgrep_bp, url_prefix='/semgrep_scanner')
app.register_blueprint(api_scanner_bp, url_prefix='/api_scanner')
logger.info("[+] 11 Modules Loaded Successfully.")

def print_banner():
    banner = fr"""
{Fore.WHITE}{Style.BRIGHT}    _   __     __  _____ __    _      __    __      ___    ____   
{Fore.WHITE}{Style.BRIGHT}   / | / /__  / /_/ ___// /_  (_)__  / /___/ /     /   |  /  _/   
{Fore.WHITE}{Style.BRIGHT}  /  |/ / _ \/ __/\__ \/ __ \/ / _ \/ / __  /_____/ /| |  / /     
{Fore.WHITE}{Style.BRIGHT} / /|  /  __/ /_ ___/ / / / / /  __/ / /_/ /_____/ ___ |_/ /      
{Fore.WHITE}{Style.BRIGHT}/_/ |_/\___/\__//____/_/ /_/_/\___/_/\__,_/     /_/  |_|___/      
                                                        
{Fore.BLUE}{Style.BRIGHT} [>] NetShieldAI Pentest Suite v3.0
{Fore.WHITE} [>] Engine Status: {Fore.GREEN}Ready
{Fore.WHITE} {"="*55}
    """
    # Print banner directly to console to keep logs clean
    print(banner)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id)) 

@app.before_request
def log_request_info():
    if not request.path.startswith('/static'):
        # Clean log format without colors
        logger.info(f"[>] {request.method} {request.path} from {request.remote_addr}")

@app.route('/')
def index():
    logger.info("[*] Accessing Home Page")
    return render_template('base/home.html')

@app.route('/arsenal')
def tools_hub():
    logger.info("[*] Accessing Security Arsenal Hub")
    return render_template('base/tools_hub.html')

# --- REVISED MAIN BLOCK ---
if __name__ == '__main__':
    try:
        # 1. ALWAYS check privileges first. 
        # Note: If this re-executes the script as admin, the current non-admin process will exit here.
        ensure_admin_privileges()

        # 2. Only perform setup logic in the MAIN process (not the reloader)
        if not os.environ.get("WERKZEUG_RUN_MAIN"):
            os.system('cls' if os.name == 'nt' else 'clear')
            print_banner()
            
            logger.info("[*] Initializing Secure Database...")
            with app.app_context():
                db.create_all()
            logger.info("[+] Database schema verified.")
            
            logger.info("[+] System checks complete. Launching interface...\n")

        # 3. Run Flask. 
        # Tip: If it still closes, try setting use_reloader=False inside app.run
        app.run(host='0.0.0.0', port=5100, debug=True, use_reloader=True, threaded=True)

    except Exception as e:
        logger.error("[!] CRITICAL SYSTEM ERROR:")
        logger.error(str(e))
        logger.info("[*] Troubleshooting Steps:")
        logger.info("1. Ensure no other instance is running on port 5100.")
        logger.info("2. Try running the terminal as Administrator manually.")
        input("Press ENTER to close this window...")