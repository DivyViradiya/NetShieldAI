from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
from wtforms.validators import Optional

class RegistrationForm(FlaskForm):
    """
    Secure registration form with validation for all new user fields.
    """
    # --- Identity Section ---
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=25, message="Username must be between 4 and 25 characters.")
    ])
    
    email = StringField('Email Address', validators=[
        DataRequired(),
        Email(message="Please enter a valid email address.")
    ])
    
    full_name = StringField('Full Name', validators=[
        DataRequired(),
        Length(max=100)
    ])
    
    phone_number = StringField('Phone Number', validators=[
        Optional(),
        # Optional field, but if entered, must be valid length
        Length(min=10, max=15, message="Please enter a valid phone number.")
    ])

    # --- Professional Context ---
    organization = StringField('Organization', validators=[
        DataRequired(message="Organization name is required.")
    ])
    
    job_title = StringField('Job Title', validators=[
        Length(max=100)
    ])

    # --- Security Section ---
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        # Regex enforces: At least one letter, one number, and one special character
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$',
               message="Password must contain at least 1 letter, 1 number, and 1 special character.")
    ])
    
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    
    tos_agreement = BooleanField('I agree to the Terms of Service and Privacy Policy', validators=[
        DataRequired(message="You must agree to the Terms of Service and Privacy Policy to register.")
    ])
    
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    """
    Secure login form.
    """
    username = StringField('Username', validators=[
        DataRequired(message="Please enter your username.")
    ])
    
    password = PasswordField('Password', validators=[
        DataRequired(message="Please enter your password.")
    ])
    
    submit = SubmitField('Login')
    
    
class UpdateProfileForm(FlaskForm):
    """
    Form to update non-sensitive user profile information.
    """
    # Username is read-only to prevent broken links/sessions
    username = StringField('Username', render_kw={'readonly': True})
    
    email = StringField('Email Address', validators=[
        DataRequired(),
        Email(message="Please enter a valid email address.")
    ])
    
    full_name = StringField('Full Name', validators=[
        Optional(),
        Length(max=100)
    ])
    
    phone_number = StringField('Phone Number', validators=[
        Optional(),
        Length(min=10, max=15, message="Please enter a valid phone number.")
    ])
    
    organization = StringField('Organization', validators=[
        Optional(),
        Length(max=150)
    ])
    
    job_title = StringField('Job Title', validators=[
        Optional(),
        Length(max=100)
    ])
    
    submit_profile = SubmitField('Save Changes')


class ChangePasswordForm(FlaskForm):
    """
    Separate form specifically for changing the password securely.
    """
    current_password = PasswordField('Current Password', validators=[
        DataRequired()
    ])
    
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        # Same regex as registration to ensure consistent security policy
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$',
               message="Password must contain at least 1 letter, 1 number, and 1 special character.")
    ])
    
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('new_password', message='Passwords must match.')
    ])
    
    submit_security = SubmitField('Update Password')


class ForgotPasswordForm(FlaskForm):
    """
    Form to request a password reset link.
    """
    email = StringField('Email Address', validators=[
        DataRequired(),
        Email(message="Please enter a valid email address.")
    ])
    submit = SubmitField('Request Reset')


class ResetPasswordForm(FlaskForm):
    """
    Form to enter a new password.
    """
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$',
               message="Password must contain at least 1 letter, 1 number, and 1 special character.")
    ])
    
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    
    submit = SubmitField('Update Password')


class VerifyOTPForm(FlaskForm):
    """
    Form to verify the 6-digit OTP code sent via email.
    """
    code = StringField('Verification Code', validators=[
        DataRequired(),
        Length(min=6, max=6, message="Code must be exactly 6 digits.")
    ])
    submit = SubmitField('Verify Code')

class OnboardUsernameForm(FlaskForm):
    """
    Form to prompt Google OAuth users for a custom username on first login.
    """
    username = StringField('Choose Username', validators=[
        DataRequired(message="Please enter a username."),
        Length(min=4, max=25, message="Username must be between 4 and 25 characters."),
        Regexp(r'^[a-zA-Z0-9_]+$', message="Username can only contain letters, numbers, and underscores.")
    ])
    submit = SubmitField('Save & Continue')
