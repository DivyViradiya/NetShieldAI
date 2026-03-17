import os
import shutil
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from urllib.parse import urlparse  
from sqlalchemy import func 
from models.models import User, ScanLog, PasswordResetOTP, RegistrationOTP
from core.extensions import db, mail, oauth
from core.forms import RegistrationForm, LoginForm, UpdateProfileForm, ChangePasswordForm, ForgotPasswordForm, ResetPasswordForm, VerifyOTPForm, OnboardUsernameForm
from flask_mail import Message
from flask import session
from core.logger_setup import logger
from Services.email_service import send_otp_email


auth_bp = Blueprint('auth', __name__)

@auth_bp.before_app_request
def check_onboarding():
    """
    [SECURITY] Intercept users that logged in with Google but haven't chosen a username yet.
    Redirect them to the setup screen.
    """
    from flask import request
    if current_user.is_authenticated:
        if hasattr(current_user, 'is_email_verified') and not current_user.is_email_verified:
            if request.endpoint and request.endpoint not in ['auth.verify_registration', 'auth.logout', 'static']:
                return redirect(url_for('auth.verify_registration'))
        if hasattr(current_user, 'is_onboarded') and not current_user.is_onboarded:
            if request.endpoint and request.endpoint not in ['auth.onboard_username', 'auth.logout', 'static']:
                return redirect(url_for('auth.onboard_username'))

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
        raw_username = form.username.data.strip()
        logger.info(f"[*] Login attempt for: {raw_username}")
        
        # In SQLite, LIKE is case-insensitive by default for ASCII
        # [UX UPDATE] Allow logging in with either username OR email address
        user = User.query.filter((User.username.like(raw_username)) | (User.email.like(raw_username))).first()

        # 3. Check credentials
        if user:
            # [SECURITY] Check if account is locked due to too many failed attempts
            MAX_FAILED_ATTEMPTS = 5
            if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                flash('Your account is locked due to too many failed login attempts. Please contact an administrator.', 'danger')
                logger.warning(f"[!] Login blocked for locked account: {user.username}")
                return render_template('base/login.html', form=form)

            logger.debug(f"[+] User '{user.username}' found in database.")
            is_valid_pw = user.check_password(form.password.data)
            logger.debug(f"[?] Password match for '{user.username}': {is_valid_pw}")
            
            if is_valid_pw:
                # Check if account is suspended
                if not user.is_active_account:
                    flash('Your account has been suspended. Please contact the administrator.', 'danger')
                    return render_template('base/login.html', form=form)

                # Reset failed attempts on successful login
                user.failed_login_attempts = 0
                db.session.commit()

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
                # [SECURITY] Track failed login attempt for lockout
                user.failed_login_attempts += 1
                db.session.commit()
                flash('Invalid username or password.', 'danger')
                logger.warning(f"[!] Login failed (Incorrect Password) for username: {form.username.data} (Attempt {user.failed_login_attempts})")
        else:
            flash('Invalid username or password.', 'danger')
            logger.warning(f"[!] Login failed (User Not Found) for username: {form.username.data}")
            
    return render_template('base/login.html', form=form)


@auth_bp.route('/login/google')
def login_google():
    """Redirect to Google for authentication."""
    redirect_uri = url_for('auth.google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@auth_bp.route('/login/google/callback')
def google_callback():
    """Handle the response from Google authentication."""
    import secrets
    try:
        token = oauth.google.authorize_access_token()
        user_info = token.get('userinfo')
        if not user_info:
             # Fallback to GET userinfo
             user_info = oauth.google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()

        email = user_info.get('email')
        if not email:
            flash('Failed to retrieve email from Google.', 'danger')
            return redirect(url_for('auth.login'))

        user = User.query.filter_by(email=email).first()

        if not user:
            flash('No account found with this email. Please create an account first.', 'warning')
            return redirect(url_for('auth.register'))

        logger.info(f"[+] User logged in via Google OAuth: {user.username}")

        # Log support audit data
        user.update_login_stats(request.remote_addr)
        login_user(user)

        # Flash success message
        flash('Logged in with Google successfully!', 'success')
        
        # Redirect Logic identical to standard login
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            if user.is_admin:
                next_page = url_for('auth.admin_dashboard')
            else:
                next_page = url_for('index')
        return redirect(next_page)

    except Exception as e:
        logger.error(f"[!] Google OAuth Error: {str(e)}")
        flash('Google authentication failed. Please try again.', 'danger')
        return redirect(url_for('auth.login'))


@auth_bp.route('/login/github')
def login_github():
    """Redirect to GitHub for authentication."""
    redirect_uri = url_for('auth.github_callback', _external=True)
    return oauth.github.authorize_redirect(redirect_uri)


@auth_bp.route('/login/github/callback')
def github_callback():
    """Handle the response from GitHub authentication."""
    import secrets
    try:
        token = oauth.github.authorize_access_token()
        resp = oauth.github.get('user')
        user_info = resp.json()

        # GitHub might return email=None if it's private.
        email = user_info.get('email')
        if not email:
            # Fetch from user/emails endpoint if scope was user:email
            emails_resp = oauth.github.get('user/emails')
            emails = emails_resp.json()
            # Find primary verified email
            for e in emails:
                if e.get('primary') and e.get('verified'):
                    email = e['email']
                    break
            
            if not email and emails:
                for e in emails:
                    if e.get('verified'):
                        email = e['email']
                        break

        if not email:
            flash('Failed to retrieve email from GitHub.', 'danger')
            return redirect(url_for('auth.login'))

        user = User.query.filter_by(email=email).first()

        if not user:
            flash('No account found with this email. Please create an account first.', 'warning')
            return redirect(url_for('auth.register'))

        logger.info(f"[+] User logged in via GitHub OAuth: {user.username}")

        user.update_login_stats(request.remote_addr)
        login_user(user)

        flash('Logged in with GitHub successfully!', 'success')
        
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            if user.is_admin:
                next_page = url_for('auth.admin_dashboard')
            else:
                next_page = url_for('index')
        return redirect(next_page)

    except Exception as e:
        logger.error(f"[!] GitHub OAuth Error: {str(e)}")
        flash('GitHub authentication failed. Please try again.', 'danger')
        return redirect(url_for('auth.login'))


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
        username_lower = form.username.data.lower()
        logger.info(f"[+] New User Registration Attempt: {form.username.data}")
        
        if User.query.filter(func.lower(User.username) == username_lower).first():
            flash('Username already exists. Please choose another.', 'warning')
            logger.warning(f"[!] Registration failed: Username '{form.username.data}' already exists.")
            return render_template('base/register.html', form=form)
            
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
        
        # [SECURITY] Removed automatic admin assignment for the first user.
        # Admins should be created via init_db.py or by an existing admin.
            
        try:
            db.session.add(new_user)
            db.session.commit()
            # [OTP VERIFICATION] Generate and send OTP
            import random
            from datetime import datetime, timedelta
            otp_code = str(random.randint(100000, 999999))
            expires_at = datetime.utcnow() + timedelta(minutes=15)
            
            otp_entry = RegistrationOTP(user_id=new_user.id, code=otp_code, expires_at=expires_at)
            db.session.add(otp_entry)
            db.session.commit()
            
            # Send Email
            from flask import current_app
            html_content = render_template('email/register_otp.html', 
                                         user=new_user, 
                                         otp_code=otp_code, 
                                         current_year=datetime.now().year)
            
            logo_path = os.path.join(current_app.root_path, 'static', 'images', 'NS_Logo.png')
            send_otp_email(new_user.email, otp_code, html_content=html_content, logo_path=logo_path)
            
            session['pending_verification_user_id'] = new_user.id
            logger.info(f"[+] User {form.username.data} registered. OTP sent to {new_user.email}.")
            
            flash('Account created! Please verify your email with the 6-digit code sent to your inbox.', 'info')
            return redirect(url_for('auth.verify_registration'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Database Error: {str(e)}', 'danger')
        
    return render_template('base/register.html', form=form)


@auth_bp.route('/logout', methods=['GET', 'POST'])
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
    # Use a try-except to handle cases where total_scans might not be an int
    try:
        sorted_users = sorted(users, key=lambda u: u.total_scans if isinstance(u.total_scans, int) else 0, reverse=True)
        top_5_users = list(sorted_users)[:5]
        top_users_labels = [u.username for u in top_5_users]
        top_users_data = [u.total_scans for u in top_5_users]
    except Exception as e:
        logger.error(f"Error sorting users for telemetry: {e}")
        top_users_labels = []
        top_users_data = []

    # --- 3. [NEW] Advanced Telemetry ---
    
    # A. Scan Success Rates
    total_logged_scans = ScanLog.query.count()
    successful_scans = ScanLog.query.filter_by(status='Completed').count()
    failed_scans = ScanLog.query.filter(ScanLog.status.like('%Failed%')).count()
    
    
    # Calculate success rate as a safe float
    try:
        if total_logged_scans > 0:
            success_rate = round(float(successful_scans) / float(total_logged_scans) * 100.0, 1)
        else:
            success_rate = 0.0
    except (ZeroDivisionError, TypeError):
        success_rate = 0.0
    
    # B. Performance Metrics
    avg_duration_query = db.session.query(func.avg(ScanLog.duration_seconds)).filter(ScanLog.status == 'Completed').scalar()
    avg_duration = float(avg_duration_query) if avg_duration_query is not None else 0.0
    avg_duration = round(avg_duration, 1)
    
    # C. Global Threat Summary
    findings_sum = db.session.query(func.sum(ScanLog.finding_count)).scalar()
    total_findings = int(findings_sum) if findings_sum is not None else 0
    
    critical_sum = db.session.query(func.sum(ScanLog.severity_critical)).scalar()
    total_critical = int(critical_sum) if critical_sum is not None else 0
    
    # D. System Health (Storage)
    try:
        # Get disk usage for the partition where the project resides
        total, used, free = shutil.disk_usage(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        storage_info = {
            "percent": round(float((used / total) * 100), 1) if total > 0 else 0.0,
            "used_gb": round(float(used / (1024**3)), 1),
            "total_gb": round(float(total / (1024**3)), 1)
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
            # 'results/<user_id>' folder here using shutil.rmtree
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


def send_reset_email(user):
    from flask import current_app, render_template
    from datetime import datetime, timedelta
    import random
    
    # 1. Generate 6-Digit OTP code
    otp_code = str(random.randint(100000, 999999))
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    # 2. Overwrite any existing active resets for this user in DB
    PasswordResetOTP.query.filter_by(user_id=user.id).delete()
    
    otp_entry = PasswordResetOTP(user_id=user.id, code=otp_code, expires_at=expires_at)
    db.session.add(otp_entry)
    db.session.commit()
    
    # 3. Store active context in session for anti-hijack session binding
    session['reset_user_id'] = user.id

    msg = Message('Password Reset Verification Code',
                  sender=current_app.config['MAIL_DEFAULT_SENDER'],
                  recipients=[user.email],
                  extra_headers={'Auto-Submitted': 'auto-generated', 'Precedence': 'bulk'})
                  
    # --- [DESIGN] Render HTML Email with Design ---
    html_content = render_template('email/reset_password.html', 
                                   user=user, 
                                   otp_code=otp_code, 
                                   current_year=datetime.now().year)
                                   
    msg.html = html_content
    try:
        # Use Gmail API with HTML support and logo CID
        logo_path = os.path.join(current_app.root_path, 'static', 'images', 'NS_Logo.png')
        success = send_otp_email(user.email, otp_code, html_content=html_content, logo_path=logo_path)
        
        if success:
            logger.info(f"[+] Password reset email sent to {user.email} via Gmail API")
        else:
            raise Exception("Gmail API failed to send email")
    except Exception as e:
        logger.error(f"[!] Failed to send email via Gmail API: {str(e)}")


@auth_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
        else:
            # [SECURITY] Set dummy session state for non-existent users to prevent enumeration
            session['reset_user_id'] = -1
            session['fake_attempts'] = 0
            
        # Act like it always works to avoid email enumeration leaks
        # [UX UPDATE] Better wording that creates slight doubt about typos without leaking
        flash('If that email is registered in our system, a 6-digit verification code has been sent.', 'info')
        return redirect(url_for('auth.verify_otp'))
    return render_template('base/forgot_password.html', form=form)


@auth_bp.route('/resend_otp', methods=['POST'])
def resend_otp():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    reset_user_id = session.get('reset_user_id')
    if not reset_user_id:
        flash('Session expired. Please request a new code.', 'warning')
        return redirect(url_for('auth.forgot_password'))
        
    # [SECURITY] Handle dummy user flow to prevent enumeration leaks
    if reset_user_id == -1:
        flash('A new 6-digit verification code has been sent.', 'info')
        return redirect(url_for('auth.verify_otp'))
        
    user = db.session.get(User, reset_user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('auth.forgot_password'))
        
    send_reset_email(user)
    flash('A new 6-digit verification code has been sent.', 'info')
    return redirect(url_for('auth.verify_otp'))


@auth_bp.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    reset_user_id = session.get('reset_user_id')
    if not reset_user_id:
        flash('Session expired or invalid request. Please request a new code.', 'warning')
        return redirect(url_for('auth.forgot_password'))
        
    form = VerifyOTPForm()
    if form.validate_on_submit():
        # [SECURITY] Handle dummy user flow to prevent enumeration leaks
        if reset_user_id == -1:
            session['fake_attempts'] = session.get('fake_attempts', 0) + 1
            if session['fake_attempts'] >= 3:
                session.pop('reset_user_id', None)
                session.pop('fake_attempts', None)
                flash('Too many failed attempts. Code invalidated for security. Please request a new one.', 'danger')
                return redirect(url_for('auth.forgot_password'))
            flash(f'Invalid code. You have {3 - session["fake_attempts"]} attempts remaining.', 'danger')
            return render_template('base/verify_otp.html', form=form)
            
        otp_entry = PasswordResetOTP.query.filter_by(user_id=reset_user_id).order_by(PasswordResetOTP.created_at.desc()).first()
        
        if not otp_entry:
            flash('No active verification request found. Please retry.', 'danger')
            return redirect(url_for('auth.forgot_password'))
            
        from datetime import datetime
        if otp_entry.expires_at < datetime.utcnow():
            db.session.delete(otp_entry)
            db.session.commit()
            flash('This verification code has expired. Please request a new one.', 'danger')
            return redirect(url_for('auth.forgot_password'))
            
        if otp_entry.code != form.code.data:
            otp_entry.attempts += 1
            db.session.commit()
            
            if otp_entry.attempts >= 3:
                db.session.delete(otp_entry)
                db.session.commit()
                session.pop('reset_user_id', None)
                flash('Too many failed attempts. Code invalidated for security. Please request a new one.', 'danger')
                return redirect(url_for('auth.forgot_password'))
                
            flash(f'Invalid code. You have {3 - otp_entry.attempts} attempts remaining.', 'danger')
            return render_template('base/verify_otp.html', form=form)
            
        # Success
        session['otp_verified'] = True
        flash('Code verified! Please create your new password.', 'success')
        return redirect(url_for('auth.reset_password'))
        
    return render_template('base/verify_otp.html', form=form)


@auth_bp.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if not session.get('otp_verified') or not session.get('reset_user_id'):
        flash('Access denied. Please verify your OTP code first.', 'danger')
        return redirect(url_for('auth.forgot_password'))
        
    user_id = session.get('reset_user_id')
    user = db.session.get(User, user_id)
    
    if not user:
        flash('User account not found.', 'danger')
        return redirect(url_for('auth.forgot_password'))
        
    form = ResetPasswordForm()
    if form.validate_on_submit():
        if user.check_password(form.password.data):
            flash('Your new password cannot be the same as your old password.', 'danger')
            return render_template('base/reset_password.html', form=form)
            
        user.set_password(form.password.data)
        
        session.pop('otp_verified', None)
        session.pop('reset_user_id', None)
        PasswordResetOTP.query.filter_by(user_id=user_id).delete()
        db.session.commit()
        
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('auth.login'))
        
    return render_template('base/reset_password.html', form=form)

@auth_bp.route('/onboard_username', methods=['GET', 'POST'])
@login_required
def onboard_username():
    """
    [SECURITY] Render setup view mapping users onboarding custom username strings properly.
    """
    # If already set, get out
    if current_user.is_onboarded:
        return redirect(url_for('index'))
        
    form = OnboardUsernameForm()
    if form.validate_on_submit():
        new_username = form.username.data.strip()
        
        from sqlalchemy import func
        # Check for conflict (case-insensitive)
        if User.query.filter(func.lower(User.username) == func.lower(new_username)).first():
            flash('Username is already taken. Please try another.', 'danger')
            return render_template('base/onboard_username.html', form=form)
            
        current_user.username = new_username
        current_user.is_onboarded = True
        db.session.commit()
        flash('Username saved successfully! Welcome aboard.', 'success')
        return redirect(url_for('index'))
        
    return render_template('base/onboard_username.html', form=form)

@auth_bp.route('/verify_registration', methods=['GET', 'POST'])
def verify_registration():
    """
    Handle OTP verification for new registrations.
    """
    # 1. Check for logged in user who isn't verified
    if current_user.is_authenticated:
        if current_user.is_email_verified:
            return redirect(url_for('index'))
        user = current_user
    else:
        # 2. Check session for pending user
        user_id = session.get('pending_verification_user_id')
        if not user_id:
            flash('Session expired. Please log in to resend verification code.', 'warning')
            return redirect(url_for('auth.login'))
        user = db.session.get(User, user_id)
        if not user:
            return redirect(url_for('auth.login'))

    form = VerifyOTPForm()
    if form.validate_on_submit():
        otp_entry = RegistrationOTP.query.filter_by(user_id=user.id).order_by(RegistrationOTP.created_at.desc()).first()
        
        if not otp_entry:
            flash('No verification request found. Try resending the code.', 'danger')
            return render_template('base/verify_registration.html', form=form)
            
        from datetime import datetime
        if otp_entry.expires_at < datetime.utcnow():
            flash('This code has expired. Please request a new one.', 'danger')
            return render_template('base/verify_registration.html', form=form)
            
        if otp_entry.code != form.code.data:
            otp_entry.attempts += 1
            db.session.commit()
            if otp_entry.attempts >= 3:
                db.session.delete(otp_entry)
                db.session.commit()
                flash('Too many failed attempts. Please request a new code.', 'danger')
                return render_template('base/verify_registration.html', form=form)
            flash(f'Invalid code. {3 - otp_entry.attempts} attempts remaining.', 'danger')
            return render_template('base/verify_registration.html', form=form)
            
        # Success
        user.is_email_verified = True
        db.session.delete(otp_entry)
        db.session.commit()
        
        session.pop('pending_verification_user_id', None)
        
        if not current_user.is_authenticated:
            login_user(user)
            
        flash('Email verified successfully! Welcome to NetShieldAI.', 'success')
        return redirect(url_for('index'))
        
    return render_template('base/verify_registration.html', form=form)

@auth_bp.route('/resend_verification', methods=['POST'])
def resend_verification():
    """Route to resend the registration OTP."""
    if current_user.is_authenticated:
        user = current_user
    else:
        user_id = session.get('pending_verification_user_id')
        if not user_id:
            flash('Session expired. Please log in.', 'warning')
            return redirect(url_for('auth.login'))
        user = db.session.get(User, user_id)

    if user.is_email_verified:
        return redirect(url_for('index'))

    # Generate and send new OTP
    import random
    from datetime import datetime, timedelta
    otp_code = str(random.randint(100000, 999999))
    expires_at = datetime.utcnow() + timedelta(minutes=15)

    otp_entry = RegistrationOTP(user_id=user.id, code=otp_code, expires_at=expires_at)
    db.session.add(otp_entry)
    db.session.commit()

    from flask import current_app
    html_content = render_template('email/register_otp.html', 
                                 user=user, 
                                 otp_code=otp_code, 
                                 current_year=datetime.now().year)
    
    logo_path = os.path.join(current_app.root_path, 'static', 'images', 'NS_Logo.png')
    send_otp_email(user.email, otp_code, html_content=html_content, logo_path=logo_path)

    flash('A new verification code has been sent to your email.', 'info')
    return redirect(url_for('auth.verify_registration'))
