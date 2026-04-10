import os
import secrets
from datetime import datetime, timedelta
from core.time_utils import get_now_ist
from pathlib import Path
from flask import current_app
from core.extensions import db
from models.models import Report, User, get_user_result_dir_name

class StorageService:
    @staticmethod
    def get_base_dir():
        """Returns the absolute path to the data directory."""
        data_dir = os.environ.get("NETSHIELD_DATA_DIR")
        if not data_dir:
            # Fallback to .data in project root if not set
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            data_dir = os.path.join(base_dir, ".data")
        
        if not os.path.exists(data_dir):
            os.makedirs(data_dir, exist_ok=True)
        return data_dir

    @staticmethod
    def get_user_dir(user_id):
        """Returns the user-specific directory within storage."""
        user = db.session.get(User, user_id)
        if not user:
            raise ValueError(f"User with ID {user_id} not found.")
        
        user_dir_name = get_user_result_dir_name(user)
        base_dir = StorageService.get_base_dir()
        user_path = os.path.join(base_dir, user_dir_name)
        
        os.makedirs(user_path, exist_ok=True)
        return user_path, user_dir_name

    @staticmethod
    def save_report(file_path_or_bytes, user_id, scan_log_id, filename, category, file_type='pdf', retention_days=7):
        """
        Saves a report file and records it in the database.
        file_path_or_bytes: Path to existing file to move/copy, or raw bytes.
        """
        user_path, user_dir_name = StorageService.get_user_dir(user_id)
        
        # Determine category folder
        category_dir = os.path.join(user_path, category)
        os.makedirs(category_dir, exist_ok=True)
        
        dest_path = os.path.join(category_dir, filename)
        
        # Save file to disk
        if isinstance(file_path_or_bytes, (str, Path)):
            import shutil
            shutil.move(str(file_path_or_bytes), dest_path)
        else:
            with open(dest_path, 'wb') as f:
                f.write(file_path_or_bytes)
        
        # Relative path for DB storage (relative to base storage dir)
        rel_path = os.path.join(user_dir_name, category, filename)
        
        # Create DB entry with IST naive timestamp
        expires_at = get_now_ist().replace(tzinfo=None) + timedelta(days=retention_days)
        
        report = Report(
            scan_log_id=scan_log_id,
            user_id=user_id,
            filename=filename,
            relative_path=rel_path,
            file_type=file_type,
            category=category,
            expires_at=expires_at
        )
        
        db.session.add(report)
        db.session.commit()
        
        return report

    @staticmethod
    def generate_download_token(report_id, expires_minutes=10):
        """Generates a short-lived download token for a report."""
        report = db.session.get(Report, report_id)
        if not report:
            return None
        
        token = secrets.token_urlsafe(32)
        report.download_token = token
        report.token_expiry = get_now_ist().replace(tzinfo=None) + timedelta(minutes=expires_minutes)
        
        db.session.commit()
        return token

    @staticmethod
    def get_report_by_token(token):
        """Retrieves a report if the token is valid."""
        report = Report.query.filter_by(download_token=token).first()
        if report and report.is_token_valid():
            # Construct absolute path
            abs_path = os.path.join(StorageService.get_base_dir(), report.relative_path)
            if os.path.exists(abs_path):
                return report, abs_path
        return None, None

    @staticmethod
    def cleanup_expired_reports():
        """Deletes expired reports from disk and database."""
        now = get_now_ist().replace(tzinfo=None)
        expired_reports = Report.query.filter(Report.expires_at < now).all()
        
        count = 0
        base_dir = StorageService.get_base_dir()
        
        for report in expired_reports:
            try:
                abs_path = os.path.join(base_dir, report.relative_path)
                if os.path.exists(abs_path):
                    os.remove(abs_path)
                
                db.session.delete(report)
                count += 1
            except Exception as e:
                print(f"Error cleaning up report {report.id}: {e}")
        
        db.session.commit()
        return count
