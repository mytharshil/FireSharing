import re
from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, FileField, SelectField,
    BooleanField, SubmitField, IntegerField
)
from wtforms.validators import (
    DataRequired, Email, Length, EqualTo, ValidationError, Optional, NumberRange
)
from config import Config


class PasswordPolicy:
    def __init__(self):
        self.min_length = Config.PASSWORD_MIN_LENGTH

    def __call__(self, form, field):
        password = field.data
        if len(password) < self.min_length:
            raise ValidationError(f'Must be at least {self.min_length} characters.')
        if not re.search(r'[A-Z]', password):
            raise ValidationError('Must contain an uppercase letter.')
        if not re.search(r'[a-z]', password):
            raise ValidationError('Must contain a lowercase letter.')
        if not re.search(r'[0-9]', password):
            raise ValidationError('Must contain a digit.')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-]', password):
            raise ValidationError('Must contain a special character.')


class UsernamePolicy:
    def __call__(self, form, field):
        if not re.match(r'^[a-zA-Z0-9_]{3,32}$', field.data):
            raise ValidationError(
                '3-32 characters, letters, digits and underscores only.'
            )


# ====================================================================
# Auth Forms
# ====================================================================

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), UsernamePolicy()
    ])
    email = StringField('Email', validators=[
        DataRequired(), Email(message='Invalid email address.')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(), PasswordPolicy()
    ])
    confirm = PasswordField('Confirm Password', validators=[
        DataRequired(), EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(), PasswordPolicy()
    ])
    confirm = PasswordField('Confirm New Password', validators=[
        DataRequired(), EqualTo('new_password', message='Passwords must match.')
    ])
    submit = SubmitField('Change Password')


# ====================================================================
# File Forms
# ====================================================================

class UploadForm(FlaskForm):
    file = FileField('Select File', validators=[DataRequired()])
    submit = SubmitField('Upload & Encrypt')


class ShareForm(FlaskForm):
    username = StringField('Recipient Username', validators=[DataRequired()])
    permission = SelectField('Permission', choices=[
        ('download', 'Can Download'),
        ('view', 'View Only (cannot download)'),
    ], default='download')
    expiry_hours = IntegerField('Expiry (hours, 0 = never)', validators=[
        Optional(), NumberRange(min=0, max=720)
    ], default=0)
    submit = SubmitField('Share')


class DeleteAccountForm(FlaskForm):
    password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Delete My Account')
