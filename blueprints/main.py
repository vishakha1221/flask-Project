# blueprints/main.py

from flask import Blueprint, render_template
from flask_login import login_required, current_user

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    # This renders the 'index.html' template
    return render_template('index.html')

@main_bp.route('/dashboard')
@login_required
def dashboard():
    # This renders the 'dashboard.html' template
    return render_template('dashboard.html', user=current_user)