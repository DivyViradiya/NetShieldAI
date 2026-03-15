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
    
    # [NEW] Track SQL Scanner Usage
    scan_count_sql = db.Column(db.Integer, default=0)
    
    # [NEW] Track AI Analysis Usage
    scan_count_ai = db.Column(db.Integer, default=0)

    # [NEW] Track Kill Chain Usage
    scan_count_killchain = db.Column(db.Integer, default=0)
    scan_count_semgrep = db.Column(db.Integer, default=0)
    
    # [NEW] Track API Scanner Usage
    scan_count_api = db.Column(db.Integer, default=0)

    # --- Relationships ---
    scan_logs = db.relationship('ScanLog', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_reset_token(self, expires_sec=1800):
        from flask import current_app
        from itsdangerous import URLSafeTimedSerializer as Serializer
        s = Serializer(current_app.config['SECRET_KEY'])
        hash_fragment = self.password_hash[-10:] if self.password_hash else ''
        return s.dumps({'user_id': self.id, 'p_hash': hash_fragment})

    @staticmethod
    def verify_reset_token(token):
        from flask import current_app
        from itsdangerous import URLSafeTimedSerializer as Serializer
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token, max_age=1800)
            user_id = data['user_id']
            p_hash = data.get('p_hash', '')
        except:
            return None
        
        user = db.session.get(User, user_id)
        if user:
            current_hash = user.password_hash[-10:] if user.password_hash else ''
            if current_hash != p_hash:
                return None
        return user

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
        # Returns the sum of all specific tool counters including SQL, AI and Kill Chain
        return (self.scan_count_nmap + 
                self.scan_count_zap + 
                self.scan_count_ssl + 
                self.scan_count_sniffer +
                self.scan_count_sql +
                self.scan_count_ai +
                self.scan_count_killchain +
                self.scan_count_semgrep +
                self.scan_count_api)


class ScanLog(db.Model):
    """
    Centralized log for all scan executions across the platform.
    Used for Admin Dashboard reporting (Success rates, durations, etc.)
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    tool_name = db.Column(db.String(50), nullable=False)   # Nmap, ZAP, SQLMap, etc.
    scan_type = db.Column(db.String(50), nullable=True)    # Quick, Full, TCP, etc.
    target = db.Column(db.String(255), nullable=True)
    
    status = db.Column(db.String(20), default='Pending')   # Running, Completed, Failed
    
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    duration_seconds = db.Column(db.Float, default=0.0)
    
    finding_count = db.Column(db.Integer, default=0)       # High-level vuln count
    severity_critical = db.Column(db.Integer, default=0)   # Specific critical count (optional)
    
    error_message = db.Column(db.Text, nullable=True)      # If status == Failed

    def __repr__(self):
        return f"<ScanLog {self.tool_name} on {self.target} - {self.status}>"

class PasswordResetOTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, default=0) # Track invalid guesses for rate limiting

    user = db.relationship('User', backref=db.backref('otp_resets', lazy=True))

    def __repr__(self):
        return f"<PasswordResetOTP for User {self.user_id} - Code {self.code}>"
