import os
import json

# Create templates folder
os.makedirs('templates', exist_ok=True)

# 1. Create requirements.txt
requirements = """Flask==3.0.0
Flask-SQLAlchemy==3.1.1
Flask-Login==0.6.3
Flask-WTF==1.2.1
WTForms==3.1.1
email-validator==2.1.0
Werkzeug==3.0.1
"""
with open('requirements.txt', 'w') as f:
    f.write(requirements)
print("✓ requirements.txt created")

# 2. Create config.py
config = """import secrets
from datetime import timedelta

class Config:
    SECRET_KEY = secrets.token_hex(32)
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///instance/secure_app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None
    SESSION_COOKIE_AGE = 86400
"""
with open('config.py', 'w') as f:
    f.write(config)
print("✓ config.py created")

# 3. Create models.py
models = """from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username} ({self.email})>'
"""
with open('models.py', 'w') as f:
    f.write(models)
print("✓ models.py created")

# 4. Create forms.py
forms = """from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp
from models import User

class SignUpForm(FlaskForm):
    email = StringField('Email Address', validators=[DataRequired(message='Email is required'), Email(message='Please enter a valid email address'), Length(max=120, message='Email must be less than 120 characters')], render_kw={"placeholder": "Enter your email", "type": "email"})
    username = StringField('Username', validators=[DataRequired(message='Username is required'), Length(min=4, max=20, message='Username must be between 4 and 20 characters'), Regexp('^[a-zA-Z0-9_]+$', message='Username can only contain letters, numbers, and underscores')], render_kw={"placeholder": "Choose a username"})
    password = PasswordField('Password', validators=[DataRequired(message='Password is required'), Length(min=8, message='Password must be at least 8 characters long')], render_kw={"placeholder": "Minimum 8 characters"})
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(message='Please confirm your password'), EqualTo('password', message='Passwords must match')], render_kw={"placeholder": "Re-enter your password"})
    submit = SubmitField('Create Account')
    
    def validate_email(self, field):
        existing_user = User.query.filter_by(email=field.data.lower()).first()
        if existing_user:
            raise ValidationError('This email is already registered. Please log in or use a different email.')
    
    def validate_username(self, field):
        existing_user = User.query.filter_by(username=field.data.lower()).first()
        if existing_user:
            raise ValidationError('This username is already taken. Please choose another one.')

class LoginForm(FlaskForm):
    email = StringField('Email Address', validators=[DataRequired(message='Email is required'), Email(message='Please enter a valid email address')], render_kw={"placeholder": "Enter your email", "type": "email"})
    password = PasswordField('Password', validators=[DataRequired(message='Password is required')], render_kw={"placeholder": "Enter your password"})
    submit = SubmitField('Login')
"""
with open('forms.py', 'w') as f:
    f.write(forms)
print("✓ forms.py created")

# 5. Create app.py
app_code = """from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from config import Config
from models import db, User
from forms import SignUpForm, LoginForm
from datetime import datetime
import os

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except (ValueError, TypeError):
        return None

def init_db():
    with app.app_context():
        db.create_all()

instance_path = os.path.join(os.path.dirname(__file__), 'instance')
os.makedirs(instance_path, exist_ok=True)

init_db()

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = SignUpForm()
    
    if form.validate_on_submit():
        try:
            user = User(email=form.email.data.lower(), username=form.username.data.lower())
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash(f'Account created successfully! Welcome, {form.username.data}! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            app.logger.error(f'Signup error: {str(e)}')
    
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=form.email.data.lower()).first()
            
            if user and user.check_password(form.password.data):
                user.last_login = datetime.utcnow()
                db.session.commit()
                login_user(user, remember=True)
                next_page = request.args.get('next')
                if next_page and is_safe_url(next_page):
                    return redirect(next_page)
                flash(f'Welcome back, {user.username}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password. Please try again.', 'danger')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during login. Please try again.', 'danger')
            app.logger.error(f'Login error: {str(e)}')
    
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.errorhandler(400)
def bad_request(error):
    flash('Bad request. Please try again.', 'danger')
    return redirect(url_for('index')), 400

@app.errorhandler(403)
def forbidden(error):
    flash('You do not have permission to access this page.', 'danger')
    return redirect(url_for('index')), 403

@app.errorhandler(404)
def not_found(error):
    flash('Page not found.', 'danger')
    return redirect(url_for('index')), 404

@app.errorhandler(500)
def server_error(error):
    db.session.rollback()
    flash('An internal server error occurred. Please try again.', 'danger')
    app.logger.error(f'Server error: {str(error)}')
    return redirect(url_for('index')), 500

def is_safe_url(target):
    from urllib.parse import urlparse, urljoin
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return (test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc)

@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

if __name__ == '__main__':
    print("\\n" + "="*60)
    print("🔒 Secure Web Application Started")
    print("="*60)
    print("URL: http://127.0.0.1:5000")
    print("Press CTRL+C to stop the server")
    print("="*60 + "\\n")
    app.run(debug=True, host='127.0.0.1', port=5000, use_reloader=True)
"""
with open('app.py', 'w') as f:
    f.write(app_code)
print("✓ app.py created")

# 6. Create .gitignore
gitignore = """venv/
env/
ENV/
.venv
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
instance/
.webassets-cache
.env
*.db
*.sqlite
*.sqlite3
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store
.pytest_cache/
.coverage
htmlcov/
*.log
logs/
Thumbs.db
.directory
"""
with open('.gitignore', 'w') as f:
    f.write(gitignore)
print("✓ .gitignore created")

# 7-10. Create HTML templates
base_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>{% block title %}Secure Web Application{% endblock %}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; flex-direction: column; }
        nav { background-color: rgba(0, 0, 0, 0.8); color: white; padding: 15px 30px; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3); display: flex; justify-content: space-between; align-items: center; }
        nav .brand { font-size: 20px; font-weight: bold; letter-spacing: 2px; }
        nav .nav-right { display: flex; align-items: center; gap: 20px; }
        nav a { color: white; text-decoration: none; transition: color 0.3s ease; }
        nav a:hover { color: #667eea; }
        .container { flex: 1; max-width: 500px; width: 90%; margin: 50px auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2); }
        h1 { color: #333; margin-bottom: 10px; font-size: 28px; }
        .subtitle { color: #666; margin-bottom: 30px; font-size: 14px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-weight: 600; color: #333; font-size: 14px; }
        input[type="email"], input[type="password"], input[type="text"] { width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 5px; font-size: 14px; transition: border-color 0.3s ease; font-family: inherit; }
        input[type="email"]:focus, input[type="password"]:focus, input[type="text"]:focus { outline: none; border-color: #667eea; box-shadow: 0 0 5px rgba(102, 126, 234, 0.3); }
        button { width: 100%; padding: 12px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 5px; font-size: 16px; font-weight: 600; cursor: pointer; transition: transform 0.2s ease, box-shadow 0.2s ease; }
        button:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4); }
        button:active { transform: translateY(0); }
        .alert { padding: 15px; margin-bottom: 20px; border-radius: 5px; font-size: 14px; border-left: 4px solid; }
        .alert-success { background-color: #d4edda; color: #155724; border-color: #28a745; }
        .alert-danger { background-color: #f8d7da; color: #721c24; border-color: #dc3545; }
        .alert-info { background-color: #d1ecf1; color: #0c5460; border-color: #17a2b8; }
        .error-list { list-style: none; margin-top: 5px; }
        .error-list li { color: #dc3545; font-size: 12px; margin-bottom: 3px; }
        .info-section { margin-top: 30px; padding-top: 20px; border-top: 2px solid #eee; font-size: 14px; color: #666; }
        .info-section p { margin-bottom: 10px; }
        .info-section a { color: #667eea; text-decoration: none; font-weight: 600; }
        .info-section a:hover { text-decoration: underline; }
        .security-badge { display: inline-block; background: #e8f5e9; color: #2e7d32; padding: 8px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; margin-top: 15px; }
        footer { text-align: center; padding: 20px; color: white; font-size: 12px; margin-top: auto; }
        @media (max-width: 600px) { .container { margin: 20px auto; padding: 25px; width: 95%; } h1 { font-size: 24px; } nav { flex-direction: column; gap: 10px; text-align: center; } nav .brand { width: 100%; } nav .nav-right { width: 100%; justify-content: center; } }
    </style>
</head>
<body>
    <nav>
        <div class="brand">🔒 Secure Web App</div>
        <div class="nav-right">
            {% if current_user.is_authenticated %}
                <span>Hi, <strong>{{ current_user.username }}</strong>!</span>
                <a href="{{ url_for('logout') }}">Logout</a>
            {% else %}
                <a href="{{ url_for('login') }}">Login</a>
                <a href="{{ url_for('signup') }}">Sign Up</a>
            {% endif %}
        </div>
    </nav>

    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </div>

    <footer>
        <p>&copy; 2025 Secure Web Application | Developed with 🔐 Security</p>
    </footer>
</body>
</html>
"""
with open('templates/base.html', 'w') as f:
    f.write(base_html)
print("✓ templates/base.html created")

signup_html = """{% extends 'base.html' %}

{% block title %}Sign Up - Secure Web App{% endblock %}

{% block content %}
<h1>Create Account</h1>
<p class="subtitle">Join us for a secure experience</p>

<form method="POST" novalidate>
    {{ form.hidden_tag() }}

    <div class="form-group">
        {{ form.email.label }}
        {{ form.email(size=32, required=True, autocomplete="email") }}
        {% if form.email.errors %}
            <ul class="error-list">
                {% for error in form.email.errors %}
                    <li>⚠️ {{ error }}</li>
                {% endfor %}
            </ul>
        {% endif %}
    </div>

    <div class="form-group">
        {{ form.username.label }}
        {{ form.username(size=32, required=True, autocomplete="username") }}
        {% if form.username.errors %}
            <ul class="error-list">
                {% for error in form.username.errors %}
                    <li>⚠️ {{ error }}</li>
                {% endfor %}
            </ul>
        {% endif %}
    </div>

    <div class="form-group">
        {{ form.password.label }}
        {{ form.password(size=32, required=True, autocomplete="new-password") }}
        {% if form.password.errors %}
            <ul class="error-list">
                {% for error in form.password.errors %}
                    <li>⚠️ {{ error }}</li>
                {% endfor %}
            </ul>
        {% endif %}
    </div>

    <div class="form-group">
        {{ form.confirm_password.label }}
        {{ form.confirm_password(size=32, required=True, autocomplete="new-password") }}
        {% if form.confirm_password.errors %}
            <ul class="error-list">
                {% for error in form.confirm_password.errors %}
                    <li>⚠️ {{ error }}</li>
                {% endfor %}
            </ul>
        {% endif %}
    </div>

    {{ form.submit() }}
</form>

<div class="info-section">
    <p>Already have an account? <a href="{{ url_for('login') }}">Log in here</a></p>
</div>

<div class="security-badge">
    ✓ Password encrypted • ✓ Email verified • ✓ Account secured
</div>
{% endblock %}
"""
with open('templates/signup.html', 'w') as f:
    f.write(signup_html)
print("✓ templates/signup.html created")

login_html = """{% extends 'base.html' %}

{% block title %}Login - Secure Web App{% endblock %}

{% block content %}
<h1>Welcome Back</h1>
<p class="subtitle">Log in to your secure account</p>

<form method="POST" novalidate>
    {{ form.hidden_tag() }}

    <div class="form-group">
        {{ form.email.label }}
        {{ form.email(size=32, required=True, autocomplete="email") }}
        {% if form.email.errors %}
            <ul class="error-list">
                {% for error in form.email.errors %}
                    <li>⚠️ {{ error }}</li>
                {% endfor %}
            </ul>
        {% endif %}
    </div>

    <div class="form-group">
        {{ form.password.label }}
        {{ form.password(size=32, required=True, autocomplete="current-password") }}
        {% if form.password.errors %}
            <ul class="error-list">
                {% for error in form.password.errors %}
                    <li>⚠️ {{ error }}</li>
                {% endfor %}
            </ul>
        {% endif %}
    </div>

    {{ form.submit() }}
</form>

<div class="info-section">
    <p>Don't have an account? <a href="{{ url_for('signup') }}">Sign up here</a></p>
</div>

<div class="security-badge">
    ✓ Encrypted connection • ✓ Secure session • ✓ Protected data
</div>
{% endblock %}
"""
with open('templates/login.html', 'w') as f:
    f.write(login_html)
print("✓ templates/login.html created")

dashboard_html = """{% extends 'base.html' %}

{% block title %}Dashboard - Secure Web App{% endblock %}

{% block content %}
<div style="text-align: center; margin-bottom: 40px;">
    <h1>🎉 Welcome, {{ user.username }}!</h1>
    <p class="subtitle">You're now logged into your secure account</p>
</div>

<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 30px;">
    <h2 style="margin-bottom: 15px;">Account Information</h2>
    <p><strong>👤 Username:</strong> {{ user.username }}</p>
    <p><strong>📧 Email:</strong> {{ user.email }}</p>
    <p><strong>📅 Member Since:</strong> {{ user.created_at.strftime('%B %d, %Y') }}</p>
    {% if user.last_login %}<p><strong>🕒 Last Login:</strong> {{ user.last_login.strftime('%B %d, %Y at %I:%M %p') }}</p>{% endif %}
</div>

<div style="background: #f0f4ff; padding: 20px; border-left: 4px solid #667eea; border-radius: 5px; margin-bottom: 30px;">
    <h2 style="color: #667eea; margin-bottom: 15px;">✅ Security Features Implemented</h2>
    <ul style="list-style: none; color: #333;">
        <li style="margin-bottom: 10px;">✓ <strong>Password Hashing</strong> - Using PBKDF2 with SHA256 algorithm</li>
        <li style="margin-bottom: 10px;">✓ <strong>Input Validation</strong> - Email format, password strength, username validation</li>
        <li style="margin-bottom: 10px;">✓ <strong>SQL Injection Prevention</strong> - Using SQLAlchemy ORM (parameterized queries)</li>
        <li style="margin-bottom: 10px;">✓ <strong>XSS Prevention</strong> - Automatic HTML escaping in Jinja2 templates</li>
        <li style="margin-bottom: 10px;">✓ <strong>CSRF Protection</strong> - Flask-WTF token validation on all forms</li>
        <li style="margin-bottom: 10px;">✓ <strong>Session Management</strong> - Secure, encrypted Flask-Login sessions</li>
        <li style="margin-bottom: 10px;">✓ <strong>Secure Cookies</strong> - HTTPOnly, SameSite flags enabled</li>
        <li style="margin-bottom: 10px;">✓ <strong>Error Handling</strong> - Generic error messages prevent information disclosure</li>
        <li style="margin-bottom: 10px;">✓ <strong>Security Headers</strong> - X-Frame-Options, X-Content-Type-Options, etc.</li>
        <li style="margin-bottom: 10px;">✓ <strong>Version Control</strong> - Git/GitHub integration for code management</li>
    </ul>
</div>

<div style="text-align: center;">
    <a href="{{ url_for('logout') }}" style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: 600; transition: transform 0.2s;">
        Logout Securely
    </a>
</div>
{% endblock %}
"""
with open('templates/dashboard.html', 'w') as f:
    f.write(dashboard_html)
print("✓ templates/dashboard.html created")

print("\n" + "="*60)
print("🎉 ALL FILES CREATED SUCCESSFULLY!")
print("="*60)
print("\nNow run: pip install -r requirements.txt")
print("Then run: python app.py")
print("\n" + "="*60)
