from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from celery import Celery
from authlib.integrations.flask_client import OAuth

# Initialize these here, but connect them to the app in run.py
db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()
oauth = OAuth()

def make_celery(app_name=__name__):
    return Celery(
        app_name,
        backend='redis://localhost:6379/0',
        broker='redis://localhost:6379/0'
    )

celery = make_celery()