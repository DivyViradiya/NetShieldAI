import sys
import os
import time
from pathlib import Path

def silence_low_level_noise():
    """
    MODIFIED: Only silence noise if NOT in debug mode.
    While fixing crashes, we NEED to see the stderr.
    """
    try:
        if os.name == 'nt':
            devnull = os.open(os.devnull, os.O_RDWR)
            os.dup2(devnull, 2)
        os.environ["G_MESSAGES_DEBUG"] = "none"
    except Exception:
        pass

silence_low_level_noise()

from flask import Flask, render_template, jsonify, request
from flask_login import current_user
from flask_wtf.csrf import CSRFProtect
from colorama import Fore, Style, init

init(autoreset=True)

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
from Services.network_scanner import ensure_admin_privileges

app = Flask(__name__)
app.secret_key = 'VulnScanAI' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
csrf = CSRFProtect(app)

# Register Blueprints
app.register_blueprint(network_scanner_bp, url_prefix='/network_scanner')
app.register_blueprint(zap_scanner_bp, url_prefix='/zap_scanner')
app.register_blueprint(ssl_scanner_bp, url_prefix='/ssl_scanner')
app.register_blueprint(packet_sniffer_bp, url_prefix='/packet_sniffer')
app.register_blueprint(chatbot_bp, url_prefix='/chatbot')
app.register_blueprint(auth_bp)
app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
app.register_blueprint(killchain_bp, url_prefix='/killchain')

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
    print(banner)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id)) 

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/arsenal')
def tools_hub():
    return render_template('tools_hub.html')

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
            
            print(f"{Fore.BLUE}[*] Initializing Secure Database...")
            with app.app_context():
                db.create_all()
            
            print(f"{Fore.GREEN}[+] System checks complete. Launching interface...\n")

        # 3. Run Flask. 
        # Tip: If it still closes, try setting use_reloader=False inside app.run
        app.run(host='0.0.0.0', port=5100, debug=True, use_reloader=True)

    except Exception as e:
        print(f"\n{Fore.RED}{Style.BRIGHT}[!] CRITICAL SYSTEM ERROR:")
        print(f"{Fore.WHITE}{str(e)}")
        print(f"\n{Fore.YELLOW}[*] Troubleshooting Steps:")
        print("1. Ensure no other instance is running on port 5100.")
        print("2. Try running the terminal as Administrator manually.")
        input(f"\n{Fore.WHITE}Press ENTER to close this window...")