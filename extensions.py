from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# Initialize these here, but connect them to the app in run.py
db = SQLAlchemy()
login_manager = LoginManager()