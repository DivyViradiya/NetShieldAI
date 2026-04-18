import sys
import os
import time
import threading
import traceback
from pathlib import Path
from datetime import datetime, timezone
from core.time_utils import get_now_ist

def global_excepthook(exc_type, exc_value, exc_tb):
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "crash_log.txt"), "w") as f:
            traceback.print_exception(exc_type, exc_value, exc_tb, file=f)
        print("CRASH DETECTED. See crash_log.txt for details.")
        input("Press ENTER to close this window...")
    except:
        pass

sys.excepthook = global_excepthook


# ===========================================================================
# CRITICAL: Check admin privileges FIRST — before importing any heavy modules.
# If not admin, this forks a new elevated process and exits immediately.
# This prevents the ML models from being loaded in the non-admin process.
# ===========================================================================
if __name__ == '__main__':
    # We need a minimal import just to call ensure_admin_privileges()
    # network_scanner itself is lightweight at this stage (no ML models yet)
    from Services.network_scanner import ensure_admin_privileges
    ensure_admin_privileges()
    # If we reach here, we ARE admin (either already were, or just re-elevated).

from dotenv import load_dotenv
# --- [FIX] Load .env using absolute path for elevated process context ---
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'), override=True)

from flask import Flask, render_template, jsonify, request
from flask_login import current_user
from flask_wtf.csrf import CSRFProtect
import logging
from colorama import Fore, Style, init

init(autoreset=True)

# --- Logging Setup ---
from core.logger_setup import logger

from core.extensions import db, login_manager, mail, limiter
from models.models import User
from routes.network_scanner_bp import network_scanner_bp
from routes.zap_scanner_bp import zap_scanner_bp
from routes.ssl_scanner_bp import ssl_scanner_bp
from routes.chatbot_bp import chatbot_bp
from routes.auth_bp import auth_bp
from routes.packet_sniffer_bp import packet_sniffer_bp
from routes.dashboard_bp import dashboard_bp
from routes.killchain_bp import killchain_bp
from routes.sql_scanner_bp import sql_scanner_bp
from routes.semgrep_scanner_bp import semgrep_scanner_bp
from routes.api_scanner_bp import api_scanner_bp
from routes.scheduler_bp import scheduler_bp
from routes.asset_discovery_bp import asset_discovery_bp



app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24)) 

# --- [FIX] Use Absolute Path for Database ---
basedir = os.path.abspath(os.path.dirname(__file__))
db_dir = os.path.join(basedir, '.instance')
os.makedirs(db_dir, exist_ok=True)

db_path = os.path.join(db_dir, 'users_db.sqlite3')
# Increase timeout to 20s for better concurrency
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}?timeout=20'
app.config['BASE_URL'] = os.environ.get('BASE_URL', 'http://localhost:5100')

# --- Scheduler DB (separate SQLite file) ---
scheduler_db_path = os.path.join(db_dir, 'scheduler_db.sqlite3')
app.config['SQLALCHEMY_BINDS'] = {
    'scheduler': f'sqlite:///{scheduler_db_path}?timeout=20'
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB limit for uploads

db.init_app(app)
limiter.init_app(app)

# --- SQLite Concurrency Fix: Enable WAL Mode ---
from sqlalchemy import event

with app.app_context():
    # Primary DB
    @event.listens_for(db.engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

    # Scheduler DB Bind
    scheduler_engine = db.engines['scheduler']
    @event.listens_for(scheduler_engine, "connect")
    def set_scheduler_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

# --- [NEW] Startup Cleanup Hook ---
def cleanup_stale_scans():
    """Marks any 'Running' or 'Pending' scans from a previous session as failed."""
    from models.models import ScanLog
    try:
        with app.app_context():
            stale_scans = ScanLog.query.filter(ScanLog.status.in_(['Running', 'Pending'])).all()

            if stale_scans:
                logger.info(f"[*] Found {len(stale_scans)} abandoned scans from a previous session. Marking as failed...")
                for scan in stale_scans:
                    scan.status = "Failed (System Restart)"
                    scan.end_time = get_now_ist()
                db.session.commit()
                logger.info("[+] Stale scan cleanup complete.")
    except Exception as e:
        logger.error(f"[!] Error during startup cleanup: {e}")

login_manager.init_app(app)
login_manager.login_view = 'auth.login'
csrf = CSRFProtect(app)

# --- Initialize Scheduler Models (Registers with shared db) ---
from models.scheduler_models import ScanProfile, ProfileScanConfig, ProfileTarget, ProfileRecipient, ScheduledScanJob

from core.extensions import oauth
oauth.init_app(app)
oauth.register(
    name='google',
    client_id=os.environ.get('OAUTH_CLIENT_ID'),
    client_secret=os.environ.get('OAUTH_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)
oauth.register(
    name='github',
    client_id=os.environ.get('GITHUB_CLIENT_ID'),
    client_secret=os.environ.get('GITHUB_CLIENT_SECRET'),
    authorize_url='https://github.com/login/oauth/authorize',
    access_token_url='https://github.com/login/oauth/access_token',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'}
)
# --- Mail Configuration ---
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
app.config['MAIL_DEBUG'] = True  # Prevent SMTP base64 logging to terminal

mail.init_app(app)  # --- [FIX] Initialize after configuration set ---

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
app.register_blueprint(semgrep_scanner_bp, url_prefix='/semgrep_scanner')
app.register_blueprint(api_scanner_bp, url_prefix='/api_scanner')
app.register_blueprint(scheduler_bp, url_prefix='/scheduler')
app.register_blueprint(asset_discovery_bp, url_prefix='/asset_discovery')
logger.info("[+] 13 Modules Loaded Successfully.")

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
        # Admin check already happened at the top of this file (before imports).
        # Only perform setup logic in the MAIN process (not the reloader child).
        if not os.environ.get("WERKZEUG_RUN_MAIN"):
            os.system('cls' if os.name == 'nt' else 'clear')
            print_banner()

            # --- Auto-Start Tor Daemon ---
            if os.getenv("ANONYMITY_MODE", "off").lower() == "tor":
                import subprocess
                try:
                    import psutil
                    tor_running = any("tor.exe" in p.name().lower() for p in psutil.process_iter(['name']))
                except ImportError:
                    output = subprocess.run('tasklist', capture_output=True, text=True).stdout
                    tor_running = 'tor.exe' in output.lower()
                    
                if not tor_running:
                    logger.info("[*] Starting local Tor proxy daemon (Background)...")
                    tor_paths = [
                        r"D:\tor\tor.exe",
                        r"D:\Tor\tor.exe",
                        r"D:\Tor\tor\tor.exe",
                        r"D:\Tor\Tor\tor.exe",
                        r"D:\Tor\tor-0.4.9.5\tor.exe",
                        r"D:\Tor\tor-0.4.9.5\Tor\tor.exe",
                        r"C:\tor\tor.exe",
                        r"C:\Tor\tor.exe",
                        r"C:\Tor\tor\tor.exe"
                    ]
                    tor_exe = next((p for p in tor_paths if os.path.exists(p)), None)
                    if tor_exe:
                        subprocess.Popen([tor_exe], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
                        logger.info(f"[+] Tor proxy spawned from {tor_exe} on 127.0.0.1:9050.")
                    else:
                        logger.warning("[!] Tor executable not found. Automatic startup skipped.")
                else:
                    logger.info("[+] Tor proxy is already running.")

            logger.info("[*] Initializing Secure Database...")
            with app.app_context():
                db.create_all()
            logger.info("[+] Database schemas verified (primary + scheduler).")
            cleanup_stale_scans()
            logger.info("[+] System checks complete. Launching interface...\n")

        # --- Pre-warm ML models only in the HTTP-serving process.
        # With use_reloader=True, Flask spawns two processes:
        #   - Parent (watcher):  WERKZEUG_RUN_MAIN is NOT set  -> skip pre-warm
        #   - Child (HTTP server): WERKZEUG_RUN_MAIN=true      -> pre-warm HERE
        # This prevents the model from loading twice (once per process).
        if os.environ.get("WERKZEUG_RUN_MAIN"):
            def _prewarm_ml():
                try:
                    logger.info("[*] [BG] Pre-loading ML models (TCTR LightGBM + SentenceTransformer)...")
                    from Services.tctr_engine import get_engine
                    get_engine()  # loads singleton once; all later callers reuse it
                    logger.info("[+] [BG] ML models ready — cold-start cost eliminated.")
                except Exception as _e:
                    logger.error(f"[!] [BG] ML pre-load failed: {_e}")

            _ml_thread = threading.Thread(target=_prewarm_ml, name="ML-Prewarm", daemon=True)
            _ml_thread.start()

            # --- Start APScheduler ---
            from Services import scheduler_service
            import atexit
            scheduler_db_uri = f'sqlite:///{scheduler_db_path}'
            scheduler_service.init_scheduler(app, scheduler_db_uri)
            atexit.register(scheduler_service.shutdown_scheduler)

        # Run Flask.
        debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
        app.run(host='0.0.0.0', port=5100, debug=debug_mode, use_reloader=True, threaded=True)

    except Exception as e:
        logger.error("[!] CRITICAL SYSTEM ERROR:")
        logger.error(str(e))
        logger.info("[*] Troubleshooting Steps:")
        logger.info("1. Ensure no other instance is running on port 5100.")
        logger.info("2. Try running the terminal as Administrator manually.")
        input("Press ENTER to close this window...")
