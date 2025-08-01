import os
import random
import logging
from datetime import datetime, timedelta
from uuid import uuid4

from forms import RegisterationForm, LoginForm, OTPForm, ResetPasswordForm
from models import db, User
from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from authlib.common.security import generate_token
from flask_mail import Mail, Message
from smtplib import SMTPException

# Configure logging for better debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__)

secret_key_from_env = os.environ.get("FLASK_SECRET_KEY")
if secret_key_from_env:
    app.config['SECRET_KEY'] = secret_key_from_env
else:
    logger.warning("FLASK_SECRET_KEY environment variable not found. Using a default key for development.")
    app.config['SECRET_KEY'] = 'a-fallback-secret-key-for-dev-only-do-not-use-in-production'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jay.db'
app.config['SESSION_COOKIE_NAME'] = 'google-oauth-session'
app.config['SERVER_NAME'] = os.environ.get("FLASK_SERVER_NAME")

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')

db.init_app(app)

login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

oauth = OAuth(app)
mail = Mail(app)

oauth.register(
    name='google',
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

def send_email(email, subject, body):
    try:
        msg = Message(subject, recipients=[email])
        msg.body = body
        logger.debug(f"Attempting to send email to {email}: {subject}")
        mail.send(msg)
        logger.info(f"Email sent successfully to {email}")
        return True
    except SMTPException as e:
        logger.error(f"SMTP Error sending email to {email}: {str(e)}")
        flash(f"Email sending failed: {str(e)}. Check your email configuration.", "error")
        return False
    except Exception as e:
        logger.error(f"General Error sending email to {email}: {str(e)}")
        flash("An unexpected error occurred while sending the email. Please try again.", "error")
        return False

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.password_hash and user.check_password(form.password.data):
            session['login_email'] = user.email
            session['login_user_id'] = user.id
            otp = str(random.randint(100000, 999999))
            session['current_otp_for_verification'] = otp
            if send_email(user.email, 'Your MyBlog Verification Code', 
                         f'Your One-Time Password (OTP) for login is: {otp}'):
                flash("An OTP has been sent to your email. Please verify to log in.", "info")
                return redirect(url_for('verify'))
            else:
                session.pop('login_email', None)
                session.pop('login_user_id', None)
                session.pop('current_otp_for_verification', None)
                return redirect(url_for('login'))
        else:
            flash("Invalid email or password", 'danger')
    return render_template('login.html', form=form)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            # Generate a unique reset token
            reset_token = str(uuid4())
            user.reset_token = reset_token
            user.reset_token_expiry = datetime.utcnow() + timedelta(minutes=30)
            db.session.commit()

            # Create reset link
            reset_url = url_for('reset_password', token=reset_token, _external=True)
            if send_email(email, 'MyBlog Password Reset Request',
                         f'Click this link to reset your password: {reset_url}\nThis link is valid for 30 minutes.'):
                flash("A password reset link has been sent to your email.", "info")
            else:
                flash("Failed to send reset link. Please try again.", "error")
        else:
            flash("No account found with that email.", "error")
        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    user = User.query.filter_by(reset_token=token).first()
    if not user or user.reset_token_expiry < datetime.utcnow():
        flash("Invalid or expired reset link.", "error")
        return redirect(url_for('login'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password_hash = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        flash("Your password has been reset successfully. Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form, token=token)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegisterationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email is already registered!", 'warning')
            return redirect(url_for('login'))

        otp = str(random.randint(100000, 999999))
        session['signup_data'] = {
            'name': form.name.data,
            'email': form.email.data,
            'password_hash': generate_password_hash(form.password.data, method='pbkdf2:sha256'),
            'otp': otp
        }
        
        if send_email(form.email.data, 'Your MyBlog Verification Code',
                     f'Your One-Time Password (OTP) for account verification is: {otp}'):
            flash("An OTP has been sent to your email. Please verify to complete registration.", "info")
            return redirect(url_for('verify'))
        else:
            session.pop('signup_data', None)
            return redirect(url_for('register'))

    return render_template('register.html', form=form)

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = OTPForm()
    signup_data = session.get('signup_data')
    login_email = session.get('login_email')
    verification_email = session.get('verification_email')

    email_to_verify = None
    expected_otp = None
    context = None

    if signup_data:
        email_to_verify = signup_data['email']
        expected_otp = signup_data['otp']
        context = 'signup'
    elif login_email:
        email_to_verify = login_email
        expected_otp = session.get('current_otp_for_verification')
        context = 'login'
    elif verification_email:
        email_to_verify = verification_email
        expected_otp = session.get('current_otp_for_verification')
        context = 'google'
    else:
        flash("No pending verification. Please register or log in again.", "error")
        return redirect(url_for('register'))
    
    if form.validate_on_submit():
        if form.otp.data == expected_otp:
            if context == 'signup':
                new_user = User(
                    name=signup_data['name'],
                    email=signup_data['email'],
                    password_hash=signup_data['password_hash'],
                    is_verified=True
                )
                db.session.add(new_user)
                db.session.commit()
                session.pop('signup_data', None)
                flash("Account verified and created successfully! You can now log in.", "success")
                return redirect(url_for('login'))
            elif context == 'login':
                user = User.query.get(session.get('login_user_id'))
                if user:
                    login_user(user, remember=True)
                    flash("Login successful!", "success")
                    session.pop('login_email', None)
                    session.pop('login_user_id', None)
                    session.pop('current_otp_for_verification', None)
                    return redirect(url_for('dashboard'))
                else:
                    flash("User not found for verification.", "error")
                    session.pop('login_email', None)
                    session.pop('login_user_id', None)
                    session.pop('current_otp_for_verification', None)
                    return redirect(url_for('login'))
            elif context == 'google':
                user = User.query.filter_by(email=verification_email).first()
                if user:
                    user.is_verified = True
                    db.session.commit()
                    login_user(user)
                    flash("Your account has been successfully verified!", "success")
                    session.pop('verification_email', None)
                    session.pop('current_otp_for_verification', None)
                    return redirect(url_for('dashboard'))
                else:
                    flash("User not found for verification.", "error")
                    session.pop('verification_email', None)
                    session.pop('current_otp_for_verification', None)
                    return redirect(url_for('login'))
        else:
            flash("Invalid OTP. Please try again.", "error")
    
    return render_template('verify.html', form=form, email=email_to_verify)

@app.route('/resend_otp')
def resend_otp():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    email_to_resend = (session.get('signup_data', {}).get('email') or 
                       session.get('login_email') or 
                       session.get('verification_email'))
    
    if not email_to_resend:
        flash("No email found for OTP resend. Please register or log in again.", "error")
        return redirect(url_for('register'))

    otp = str(random.randint(100000, 999999))
    if session.get('signup_data'):
        session['signup_data']['otp'] = otp
    else:
        session['current_otp_for_verification'] = otp
    
    if send_email(email_to_resend, 'Your MyBlog Verification Code',
                 f'Your One-Time Password (OTP) for account verification is: {otp}'):
        flash(f"A new OTP has been sent to {email_to_resend}.", "info")
    return redirect(url_for('verify'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('google_id', None)
    session.pop('google_oauth_nonce', None)
    session.pop('signup_data', None)
    session.pop('login_email', None)
    session.pop('login_user_id', None)
    session.pop('verification_email', None)
    session.pop('current_otp_for_verification', None)
    flash("You have been logged out.", 'info')
    return redirect(url_for('index'))

@app.route('/login/google')
def login_google():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    nonce = generate_token()
    session['google_oauth_nonce'] = nonce

    redirect_uri = url_for('authorize_google', _external=True)
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce, prompt='consent')

@app.route('/authorize/google')
def authorize_google():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    expected_nonce = session.pop('google_oauth_nonce', None)
    if not expected_nonce:
        flash("Missing nonce in session. Possible replay attack or session expired.", 'danger')
        return redirect(url_for('login'))

    try:
        token = oauth.google.authorize_access_token()
    except Exception as e:
        logger.error(f"Authlib error: {str(e)}")
        flash(f"Error during Google OAuth: {str(e)}", 'danger')
        return redirect(url_for('login'))

    user_info = oauth.google.parse_id_token(token, nonce=expected_nonce)
    logger.debug(f"Google user_info picture: {user_info.get('picture')}")

    google_id = user_info.get('sub')
    email = user_info.get('email')
    name = user_info.get('name', email.split('@')[0] if email else 'Google User')
    picture = user_info.get('picture')

    if not email:
        flash("Google did not provide an email address. Cannot log in.", "error")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()

    if user:
        if not user.google_id:
            user.google_id = google_id
            user.profile_pic_url = picture
            db.session.commit()
        session['login_email'] = user.email
        session['login_user_id'] = user.id
        otp = str(random.randint(100000, 999999))
        session['current_otp_for_verification'] = otp
        if send_email(user.email, 'Your MyBlog Verification Code',
                     f'Your One-Time Password (OTP) for login is: {otp}'):
            flash("An OTP has been sent to your email for verification.", "info")
        return redirect(url_for('verify'))
    else:
        new_user = User(
            name=name,
            email=email,
            password_hash=None,
            google_id=google_id,
            profile_pic_url=picture,
            is_verified=False
        )
        db.session.add(new_user)
        db.session.commit()
        session['verification_email'] = email
        otp = str(random.randint(100000, 999999))
        session['current_otp_for_verification'] = otp
        if send_email(email, 'Your MyBlog Verification Code',
                     f'Your One-Time Password (OTP) for account verification is: {otp}'):
            flash("An OTP has been sent to your email for verification.", "info")
        return redirect(url_for('verify'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)