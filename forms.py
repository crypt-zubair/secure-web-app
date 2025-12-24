from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp
from models import User

class SignUpForm(FlaskForm):
    email = StringField('Email Address', validators=[DataRequired(message='Email is required'), Email(message='Please enter a valid email address')], render_kw={"placeholder": "Enter your email", "type": "email"})
    username = StringField('Username', validators=[DataRequired(message='Username is required'), Length(min=4, max=20, message='Username must be between 4 and 20 characters'), Regexp('^[a-zA-Z0-9_]+$', message='Username can only contain letters, numbers, and underscores')], render_kw={"placeholder": "Choose a username"})
    password = PasswordField('Password', validators=[DataRequired(message='Password is required'), Length(min=8, message='Password must be at least 8 characters long')], render_kw={"placeholder": "Minimum 8 characters"})
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(message='Please confirm your password'), EqualTo('password', message='Passwords must match')], render_kw={"placeholder": "Re-enter your password"})
    submit = SubmitField('Create Account')
    
    def validate_email(self, field):
        existing_user = User.query.filter_by(email=field.data.lower()).first()
        if existing_user:
            raise ValidationError('This email is already registered.')
    
    def validate_username(self, field):
        existing_user = User.query.filter_by(username=field.data.lower()).first()
        if existing_user:
            raise ValidationError('This username is already taken.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message='Username is required')], render_kw={"placeholder": "Enter your username", "autocomplete": "username"})
    password = PasswordField('Password', validators=[DataRequired(message='Password is required')], render_kw={"placeholder": "Enter your password"})
    submit = SubmitField('Login Securely')
