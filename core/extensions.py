from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from celery import Celery
from authlib.integrations.flask_client import OAuth
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize these here, but connect them to the app in run.py
db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()
oauth = OAuth()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per day", "200 per hour"],
    storage_uri="memory://"
)

def make_celery(app_name=__name__):
    return Celery(
        app_name,
        backend='redis://localhost:6379/0',
        broker='redis://localhost:6379/0'
    )

celery = make_celery()
