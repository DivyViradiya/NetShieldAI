from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from models import User
from extensions import db
from forms import RegistrationForm, LoginForm  # Import the new WTForms

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    # 1. If user is already logged in, redirect to dashboard immediately
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard'))
        
    form = LoginForm()
    
    # 2. Validate Form on Submit (Checks CSRF & Field requirements)
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        # 3. Check credentials
        if user and user.check_password(form.password.data):
            login_user(user)
            
            # 4. Update Security Audit Fields (IP Address & Timestamp)
            # (Requires the update_login_stats method we added to models.py)
            try:
                user.update_login_stats(request.remote_addr)
            except Exception:
                # Non-critical failure; don't block login if stats fail
                pass 
            
            # 5. Handle "Next" redirect (if user tried to access a protected page)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
            
    return render_template('login.html', form=form)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard'))
        
    form = RegistrationForm()
    
    if form.validate_on_submit():
        # 1. Unique Constraints Check
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists. Please choose another.', 'warning')
            return render_template('register.html', form=form)
            
        if User.query.filter_by(email=form.email.data).first():
            flash('Email address is already registered.', 'warning')
            return render_template('register.html', form=form)

        # 2. Create User Object with Enhanced Fields
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            full_name=form.full_name.data,
            phone_number=form.phone_number.data,
            organization=form.organization.data,
            job_title=form.job_title.data
        )
        new_user.set_password(form.password.data)
        
        # 3. Auto-Assign Admin to the First User
        if User.query.count() == 0:
            new_user.is_admin = True
            
        try:
            db.session.add(new_user)
            db.session.commit()
            
            # 4. Success & Redirect
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Database Error: {str(e)}', 'danger')
        
    return render_template('register.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out securely.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/admin')
@login_required
def admin_dashboard():
    """
    Admin-only view to see registered users.
    """
    if not current_user.is_admin:
        flash('Access Denied: Administrator privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    users = User.query.all()
    # Ensure you have an 'admin_dashboard.html' template, or remove this route if unused.
    return render_template('admin_dashboard.html', users=users)