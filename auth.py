# auth.py

from flask import Blueprint, request, redirect, url_for, session, render_template, flash
from functools import wraps

auth_bp = Blueprint('auth', __name__)

# Dummy user list (replace later with DB or secure store)
users = {
    'alex': 'raketich',
    'joshna': 'kurra',
    'mami': 'hayashida',
    'james': 'griffioen',
    'zongming': 'fei',
    'charles': 'carpenter',
    'hussamuddin': 'nasir',
    'pinyi': 'shi',
    'yongwook': 'song'
}

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['user_id'] = username
            return redirect(url_for('home_route'))  # or 'main.dashboard' if dashboard is in another blueprint
        else:
            flash('Invalid credentials', 'danger')
            return render_template('login.html')
    
    # If GET request, show login form
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function
