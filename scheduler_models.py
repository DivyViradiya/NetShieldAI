"""
Scheduler Database Models
=========================
Separate SQLAlchemy instance + models for the Scheduled Scanning feature.
Uses its own SQLite DB (instance/scheduler_db.sqlite3) with user_id referencing
the primary User table at the application layer (no cross-DB FK constraint).
"""

from datetime import datetime
from extensions import db


class ScanProfile(db.Model):
    __bind_key__ = 'scheduler'
    """
    A named scan configuration owned by a user.
    Contains multiple scan configs, targets, and recipients.
    """
    __tablename__ = 'scan_profile'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships (cascade delete)
    configs = db.relationship('ProfileScanConfig', backref='profile', lazy=True, cascade='all, delete-orphan')
    targets = db.relationship('ProfileTarget', backref='profile', lazy=True, cascade='all, delete-orphan')
    recipients = db.relationship('ProfileRecipient', backref='profile', lazy=True, cascade='all, delete-orphan')
    jobs = db.relationship('ScheduledScanJob', backref='profile', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'name': self.name,
            'description': self.description,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'config_count': len(self.configs),
            'target_count': len(self.targets),
            'recipient_count': len(self.recipients),
            'job_count': len(self.jobs),
            'configs': [c.to_dict() for c in self.configs],
            'targets': [t.to_dict() for t in self.targets],
            'recipients': [r.to_dict() for r in self.recipients],
            'jobs': [j.to_dict() for j in self.jobs],
        }

    def __repr__(self):
        return f"<ScanProfile '{self.name}' (User {self.user_id})>"


class ProfileScanConfig(db.Model):
    __bind_key__ = 'scheduler'
    """
    A single scanner configuration attached to a profile.
    Multiple configs per profile (even for the same module) are supported.
    """
    __tablename__ = 'profile_scan_config'

    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey('scan_profile.id'), nullable=False)
    module = db.Column(db.String(30), nullable=False)  # nmap, zap, ssl, sniffer, sql, semgrep, api, killchain
    config_json = db.Column(db.Text, nullable=True, default='{}')  # JSON string of module-specific params
    display_label = db.Column(db.String(100), nullable=True)  # User-friendly label
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Valid modules
    VALID_MODULES = ['nmap', 'zap', 'ssl', 'sniffer', 'sql', 'semgrep', 'api', 'killchain']

    # Module config schemas (for frontend rendering + validation)
    MODULE_SCHEMAS = {
        'nmap': {
            'scan_type': {
                'type': 'select',
                'label': 'Scan Type',
                'options': ['default', 'os', 'fragmented', 'aggressive', 'tcp_syn', 'vuln', 'udp',
                            'ping_sweep', 'tcp_connect', 'null', 'fin', 'xmas', 'ack', 'window', 'decoy'],
                'default': 'default'
            },
            'protocol_type': {
                'type': 'select',
                'label': 'Protocol',
                'options': ['TCP', 'UDP'],
                'default': 'TCP'
            },
            'timing': {
                'type': 'number',
                'label': 'Timing (0-5)',
                'min': 0,
                'max': 5,
                'default': 4
            }
        },
        'zap': {
            'scan_mode': {
                'type': 'select',
                'label': 'Scan Mode',
                'options': ['default', 'full'],
                'default': 'default'
            }
        },
        'ssl': {},  # No configurable params — target only
        'sniffer': {
            'duration': {
                'type': 'number',
                'label': 'Capture Duration (seconds)',
                'min': 10,
                'max': 300,
                'default': 60
            }
        },
        'sql': {
            'scan_type': {
                'type': 'select',
                'label': 'Scan Type',
                'options': ['standard', 'aggressive'],
                'default': 'standard'
            }
        },
        'semgrep': {
            'ruleset': {
                'type': 'select',
                'label': 'Ruleset',
                'options': ['auto', 'owasp-top-ten', 'cwe-top-25', 'security-audit'],
                'default': 'auto'
            }
        },
        'api': {
            'scan_mode': {
                'type': 'select',
                'label': 'Scan Mode',
                'options': ['quick', 'full'],
                'default': 'quick'
            }
        },
        'killchain': {
            'profile': {
                'type': 'select',
                'label': 'Kill Chain Profile',
                'options': ['Recon Only', 'Network Audit', 'Web Audit', 'Full Scan'],
                'default': 'Full Scan'
            },
            'aggression': {
                'type': 'select',
                'label': 'Aggression Level',
                'options': ['Normal', 'Stealth', 'Attack'],
                'default': 'Normal'
            }
        }
    }

    def to_dict(self):
        import json
        return {
            'id': self.id,
            'profile_id': self.profile_id,
            'module': self.module,
            'config': json.loads(self.config_json) if self.config_json else {},
            'display_label': self.display_label or f"{self.module.upper()} Config",
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<ProfileScanConfig {self.module} for Profile {self.profile_id}>"


class ProfileTarget(db.Model):
    __bind_key__ = 'scheduler'
    """Target URLs/IPs subscribed to a profile."""
    __tablename__ = 'profile_target'

    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey('scan_profile.id'), nullable=False)
    target_url = db.Column(db.String(500), nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'profile_id': self.profile_id,
            'target_url': self.target_url,
            'added_at': self.added_at.isoformat() if self.added_at else None,
        }

    def __repr__(self):
        return f"<ProfileTarget '{self.target_url}' for Profile {self.profile_id}>"


class ProfileRecipient(db.Model):
    __bind_key__ = 'scheduler'
    """Per-profile email recipients."""
    __tablename__ = 'profile_recipient'

    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey('scan_profile.id'), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='technical')  # 'technical' or 'executive'
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'profile_id': self.profile_id,
            'email': self.email,
            'role': self.role,
            'added_at': self.added_at.isoformat() if self.added_at else None,
        }

    def __repr__(self):
        return f"<ProfileRecipient '{self.email}' ({self.role}) for Profile {self.profile_id}>"


class ScheduledScanJob(db.Model):
    __bind_key__ = 'scheduler'
    """A scheduled execution entry tied to a scan profile."""
    __tablename__ = 'scheduled_scan_job'

    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey('scan_profile.id'), nullable=False)
    schedule_type = db.Column(db.String(20), nullable=False)  # daily, weekly, monthly, once
    cron_hour = db.Column(db.Integer, default=0)
    cron_minute = db.Column(db.Integer, default=0)
    cron_day_of_week = db.Column(db.String(20), nullable=True)  # mon, tue,fri etc.
    cron_day_of_month = db.Column(db.Integer, nullable=True)
    interval_minutes = db.Column(db.Integer, nullable=True)  # For periodic scans
    cron_expression = db.Column(db.String(100), nullable=True)  # For advanced cron
    one_shot_at = db.Column(db.DateTime, nullable=True)
    is_enabled = db.Column(db.Boolean, default=True)
    last_run_at = db.Column(db.DateTime, nullable=True)
    next_run_at = db.Column(db.DateTime, nullable=True)
    apscheduler_job_id = db.Column(db.String(100), nullable=True, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    VALID_SCHEDULE_TYPES = ['daily', 'weekly', 'monthly', 'once', 'periodic', 'cron']

    def to_dict(self):
        return {
            'id': self.id,
            'profile_id': self.profile_id,
            'schedule_type': self.schedule_type,
            'cron_hour': self.cron_hour,
            'cron_minute': self.cron_minute,
            'cron_day_of_week': self.cron_day_of_week,
            'cron_day_of_month': self.cron_day_of_month,
            'interval_minutes': self.interval_minutes,
            'cron_expression': self.cron_expression,
            'one_shot_at': self.one_shot_at.isoformat() if self.one_shot_at else None,
            'is_enabled': self.is_enabled,
            'last_run_at': self.last_run_at.isoformat() if self.last_run_at else None,
            'next_run_at': self.next_run_at.isoformat() if self.next_run_at else None,
            'apscheduler_job_id': self.apscheduler_job_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<ScheduledScanJob {self.schedule_type} for Profile {self.profile_id}>"
