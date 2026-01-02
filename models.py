from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from extensions import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    # --- Identity & Contact ---
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    full_name = db.Column(db.String(150), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    
    # --- Professional Context (Useful for Reports) ---
    organization = db.Column(db.String(150), nullable=True)
    job_title = db.Column(db.String(100), nullable=True)
    
    # --- Security & Authentication ---
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active_account = db.Column(db.Boolean, default=True)
    
    # --- Audit Trail ---
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(45), nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)

    # --- Activity Metrics ---
    login_count = db.Column(db.Integer, default=0)

    # --- Usage Statistics (Command Center Data) ---
    scan_count_nmap = db.Column(db.Integer, default=0)
    scan_count_zap = db.Column(db.Integer, default=0)
    scan_count_ssl = db.Column(db.Integer, default=0)
    scan_count_sniffer = db.Column(db.Integer, default=0)
    
    # [NEW] Track AI Analysis Usage
    scan_count_ai = db.Column(db.Integer, default=0)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def update_login_stats(self, ip_address):
        """Helper to update audit fields on successful login."""
        self.last_login_at = datetime.utcnow()
        self.last_login_ip = ip_address
        self.failed_login_attempts = 0 # Reset counter on success
        
        # Increment login counter
        self.login_count += 1
        
        db.session.commit()

    @property
    def total_scans(self):
        """Helper to calculate total system usage for this user."""
        # Returns the sum of all specific tool counters including AI
        return (self.scan_count_nmap + 
                self.scan_count_zap + 
                self.scan_count_ssl + 
                self.scan_count_sniffer +
                self.scan_count_ai)