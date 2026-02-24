import os
import shutil
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from urllib.parse import urlparse  
from sqlalchemy import func 
from models import User, ScanLog # [UPDATED] Import ScanLog
from extensions import db
from forms import RegistrationForm, LoginForm, UpdateProfileForm, ChangePasswordForm
from logger_setup import logger

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        logger.info("[*] Accessing Login Page")
    # 1. If user is already logged in, redirect based on their Role
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('auth.admin_dashboard'))
        return redirect(url_for('index'))
        
    form = LoginForm()
    
    # 2. Validate Form
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        # 3. Check credentials
        if user and user.check_password(form.password.data):
            # Check if account is suspended
            if not user.is_active_account:
                flash('Your account has been suspended. Please contact the administrator.', 'danger')
                return render_template('base/login.html', form=form)

            login_user(user)
            
            # 4. Update Stats
            try:
                user.update_login_stats(request.remote_addr)
            except Exception:
                pass 
            
            # 5. Role-Based Redirect Logic
            next_page = request.args.get('next')
            
            if not next_page or urlparse(next_page).netloc != '':
                if user.is_admin:
                    next_page = url_for('auth.admin_dashboard')
                else:
                    next_page = url_for('index')
            
            return redirect(next_page)
        else:
            # [NEW] Track failed login attempt
            if user:
                user.failed_login_attempts += 1
                db.session.commit()
            flash('Invalid username or password.', 'danger')
            
    return render_template('base/login.html', form=form)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        logger.info("[*] Accessing Registration Page")
    # Redirect if already logged in
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('auth.admin_dashboard'))
        return redirect(url_for('index'))
        
    form = RegistrationForm()
    
    if form.validate_on_submit():
        logger.info(f"[+] New User Registration Attempt: {form.username.data}")
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists. Please choose another.', 'warning')
            return render_template('register.html', form=form)
            
        if User.query.filter_by(email=form.email.data).first():
            flash('Email address is already registered.', 'warning')
            return render_template('register.html', form=form)

        new_user = User(
            username=form.username.data,
            email=form.email.data,
            full_name=form.full_name.data,
            phone_number=form.phone_number.data,
            organization=form.organization.data,
            job_title=form.job_title.data
        )
        new_user.set_password(form.password.data)
        
        # Auto-Assign Admin to the First User
        if User.query.count() == 0:
            new_user.is_admin = True
            
        try:
            db.session.add(new_user)
            db.session.commit()
            logger.info(f"[+] User {form.username.data} registered successfully.")
            
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Database Error: {str(e)}', 'danger')
        
    return render_template('base/register.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    logger.info(f"[*] User Logout: {current_user.username}")
    logout_user()
    flash('You have been logged out securely.', 'info')
    return redirect(url_for('auth.login'))


# =========================================================
#  COMMAND CENTER DASHBOARD & CONTROLS
# =========================================================

@auth_bp.route('/admin')
@login_required
def admin_dashboard():
    logger.info(f"[*] Accessing Admin Control Center (User: {current_user.username})")
    if not current_user.is_admin:
        flash('Access Denied: Administrator privileges required.', 'danger')
        return redirect(url_for('index'))
    
    users = User.query.all()
    
    # --- 1. High-Level KPI Stats ---
    total_users = len(users)
    active_users = User.query.filter_by(is_active_account=True).count()
    
    # [UPDATED] Calculate Total System Scans (Sum of all users' scans)
    total_system_scans = db.session.query(
        func.sum(User.scan_count_nmap) + 
        func.sum(User.scan_count_zap) + 
        func.sum(User.scan_count_ssl) + 
        func.sum(User.scan_count_sniffer) + 
        func.sum(User.scan_count_ai) + 
        func.sum(User.scan_count_killchain) +
        func.sum(User.scan_count_sql) +
        func.sum(User.scan_count_api) +
        func.sum(User.scan_count_semgrep)
    ).scalar() or 0

    # --- 2. Graph Data Preparation ---
    
    # [UPDATED] Graph A: Tool Popularity (Now includes all tools)
    tool_usage_stats = {
        'Nmap': db.session.query(func.sum(User.scan_count_nmap)).scalar() or 0,
        'ZAP': db.session.query(func.sum(User.scan_count_zap)).scalar() or 0,
        'SSL': db.session.query(func.sum(User.scan_count_ssl)).scalar() or 0,
        'Sniffer': db.session.query(func.sum(User.scan_count_sniffer)).scalar() or 0,
        'AI Analyst': db.session.query(func.sum(User.scan_count_ai)).scalar() or 0,
        'Kill Chain': db.session.query(func.sum(User.scan_count_killchain)).scalar() or 0,
        'SQL Map': db.session.query(func.sum(User.scan_count_sql)).scalar() or 0,
        'API Scan': db.session.query(func.sum(User.scan_count_api)).scalar() or 0,
        'SAST': db.session.query(func.sum(User.scan_count_semgrep)).scalar() or 0
    }

    # Graph B: Top Power Users (For Bar Chart)
    # Sort users by total_scans (descending) and take top 5
    # Note: User.total_scans property in models.py now includes Kill Chain count automatically
    sorted_users = sorted(users, key=lambda u: u.total_scans, reverse=True)[:5]
    top_users_labels = [u.username for u in sorted_users]
    top_users_data = [u.total_scans for u in sorted_users]

    # --- 3. [NEW] Advanced Telemetry ---
    
    # A. Scan Success Rates
    total_logged_scans = ScanLog.query.count()
    successful_scans = ScanLog.query.filter_by(status='Completed').count()
    failed_scans = ScanLog.query.filter(ScanLog.status.like('%Failed%')).count()
    
    success_rate = round((successful_scans / total_logged_scans * 100), 1) if total_logged_scans > 0 else 0
    
    # B. Performance Metrics
    avg_duration = db.session.query(func.avg(ScanLog.duration_seconds)).filter(ScanLog.status == 'Completed').scalar() or 0
    avg_duration = round(avg_duration, 1)
    
    # C. Global Threat Summary
    total_findings = db.session.query(func.sum(ScanLog.finding_count)).scalar() or 0
    total_critical = db.session.query(func.sum(ScanLog.severity_critical)).scalar() or 0
    
    # D. System Health (Storage)
    try:
        # Get disk usage for the partition where the project resides
        total, used, free = shutil.disk_usage(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        storage_info = {
            "percent": round((used / total) * 100, 1),
            "used_gb": round(used / (1024**3), 1),
            "total_gb": round(total / (1024**3), 1)
        }
    except:
        storage_info = {"percent": 0, "used_gb": 0, "total_gb": 0}

    # E. Security Audit
    total_failed_logins = db.session.query(func.sum(User.failed_login_attempts)).scalar() or 0
    
    # F. Recent Activity Feed
    recent_scans = ScanLog.query.order_by(ScanLog.start_time.desc()).limit(15).all()

    return render_template('dashboard/admin_dashboard.html', 
                           users=users,
                           total_users=total_users,
                           active_users=active_users,
                           total_system_scans=total_system_scans,
                           tool_usage_stats=tool_usage_stats,
                           top_users_labels=top_users_labels,
                           top_users_data=top_users_data,
                           # New Stats
                           success_rate=success_rate,
                           failed_scans=failed_scans,
                           avg_duration=avg_duration,
                           total_findings=total_findings,
                           total_critical=total_critical,
                           storage_info=storage_info,
                           total_failed_logins=total_failed_logins,
                           recent_scans=recent_scans)


@auth_bp.route('/admin/toggle_status/<int:user_id>', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    """Suspend or Activate a user account."""
    if not current_user.is_admin:
        return redirect(url_for('index'))
        
    user = db.session.get(User, user_id)
    if user:
        if user.id == current_user.id:
            flash('Safety Protocol: You cannot disable your own account.', 'warning')
        else:
            user.is_active_account = not user.is_active_account
            db.session.commit()
            status = "activated" if user.is_active_account else "suspended"
            flash(f'User {user.username} has been {status}.', 'success')
            
    return redirect(url_for('auth.admin_dashboard'))


@auth_bp.route('/admin/toggle_role/<int:user_id>', methods=['POST'])
@login_required
def toggle_user_role(user_id):
    """Promote to Admin or Demote to User."""
    if not current_user.is_admin:
        return redirect(url_for('index'))

    user = db.session.get(User, user_id)
    if user:
        if user.id == current_user.id:
            flash('Safety Protocol: You cannot demote yourself.', 'warning')
        else:
            user.is_admin = not user.is_admin
            db.session.commit()
            role = "Administrator" if user.is_admin else "Standard User"
            flash(f'User {user.username} is now a {role}.', 'success')

    return redirect(url_for('auth.admin_dashboard'))


@auth_bp.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    """Permanently delete a user."""
    if not current_user.is_admin:
        return redirect(url_for('index'))

    user = db.session.get(User, user_id)
    if user:
        if user.id == current_user.id:
            flash('Safety Protocol: You cannot delete your own account.', 'danger')
        else:
            # Note: In a real production app, you might want to delete their 
            # 'Services/results/<user_id>' folder here using shutil.rmtree
            db.session.delete(user)
            db.session.commit()
            flash(f'User {user.username} has been permanently deleted.', 'info')

    return redirect(url_for('auth.admin_dashboard'))


# =========================================================
#  USER SETTINGS
# =========================================================

@auth_bp.route('/account/settings', methods=['GET', 'POST'])
@login_required
def account_settings():
    # Initialize forms
    profile_form = UpdateProfileForm(obj=current_user) 
    security_form = ChangePasswordForm()

    # --- Handle Profile Update ---
    if profile_form.submit_profile.data and profile_form.validate_on_submit():
        if profile_form.email.data != current_user.email:
            if User.query.filter_by(email=profile_form.email.data).first():
                flash('That email is already in use.', 'danger')
                return redirect(url_for('auth.account_settings'))
        
        current_user.email = profile_form.email.data
        current_user.full_name = profile_form.full_name.data
        current_user.phone_number = profile_form.phone_number.data
        current_user.organization = profile_form.organization.data
        current_user.job_title = profile_form.job_title.data
        
        try:
            db.session.commit()
            flash('Your profile has been updated.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'danger')
        
        return redirect(url_for('auth.account_settings'))

    # --- Handle Password Change ---
    if security_form.submit_security.data and security_form.validate_on_submit():
        if not current_user.check_password(security_form.current_password.data):
            flash('Incorrect current password.', 'danger')
        else:
            current_user.set_password(security_form.new_password.data)
            db.session.commit()
            flash('Your password has been changed successfully.', 'success')
            return redirect(url_for('auth.account_settings'))

    return render_template('base/account_settings.html', 
                           profile_form=profile_form, 
                           security_form=security_form)