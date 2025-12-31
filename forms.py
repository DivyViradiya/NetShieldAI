from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp

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