import os
import logging
from datetime import datetime, timedelta

from flask import Flask, render_template, redirect, url_for, flash, session
from flask_login import LoginManager, current_user
from flask_mail import Mail
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

from models import db, User
from config import Config
from blueprints.auth import auth_bp
from blueprints.main import main_bp

# Configure logging for better debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'auth.login'  # Updated to blueprint name

oauth = OAuth(app)
mail = Mail(app)

oauth.register(
    name='google',
    client_id=app.config.get("GOOGLE_CLIENT_ID"),
    client_secret=app.config.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def create_table():
    with app.app_context():
        db.create_all()

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/')
app.register_blueprint(main_bp, url_prefix='/')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)