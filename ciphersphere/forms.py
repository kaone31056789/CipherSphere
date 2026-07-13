"""Server-side forms. JSON endpoints remain protected by the global CSRF layer."""

from __future__ import annotations

from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileRequired
from wtforms import BooleanField, EmailField, HiddenField, PasswordField, SelectField, StringField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional, Regexp


ALLOWED_EXTENSIONS = [
    "txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif",
    "bmp", "webp", "svg", "zip", "rar", "7z", "tar", "gz", "mp3", "wav", "mp4", "avi", "mkv",
    "mov", "json", "xml", "csv", "log", "md", "py", "js", "css", "html",
]


class LoginForm(FlaskForm):
    username = StringField("Email or username", validators=[DataRequired(), Length(max=254)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=256)])
    remember = BooleanField("Remember me")


class RegisterForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=3, max=80), Regexp(r"^[A-Za-z0-9_]+$")],
    )
    full_name = StringField("Full name", validators=[DataRequired(), Length(min=2, max=120)])
    email = EmailField("Email", validators=[DataRequired(), Email(), Length(max=254)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=256)])
    confirm_password = PasswordField("Confirm password", validators=[DataRequired(), EqualTo("password")])


class ForgotPasswordForm(FlaskForm):
    username = StringField("Email or username", validators=[DataRequired(), Length(max=254)])


class ResetPasswordForm(FlaskForm):
    access_token = HiddenField(validators=[DataRequired()])
    refresh_token = HiddenField(validators=[DataRequired()])
    new_password = PasswordField("New password", validators=[DataRequired(), Length(min=8, max=256)])
    confirm_password = PasswordField("Confirm password", validators=[DataRequired(), EqualTo("new_password")])


class EncryptForm(FlaskForm):
    algorithm = SelectField("Encryption algorithm", choices=[(x, x) for x in ("AES", "Fernet", "RSA")], validators=[DataRequired()])
    text_content = TextAreaField("Text content", validators=[Optional()])
    file = FileField("Upload file", validators=[Optional(), FileAllowed(ALLOWED_EXTENSIONS, "Unsupported file type")])
    key = StringField("Encryption key", validators=[Optional(), Length(max=10000)])
    save_to_vault = BooleanField("Save to vault", default=True)


class DecryptForm(FlaskForm):
    algorithm = SelectField("Decryption algorithm", choices=[(x, x) for x in ("AES", "Fernet", "RSA")], validators=[DataRequired()])
    text_content = TextAreaField("Encrypted text", validators=[Optional()])
    file = FileField("Encrypted file", validators=[Optional()])
    key = StringField("Decryption key", validators=[DataRequired(), Length(max=10000)])


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[DataRequired()])
    new_password = PasswordField("New password", validators=[DataRequired(), Length(min=8, max=256)])
    confirm_new_password = PasswordField("Confirm new password", validators=[DataRequired(), EqualTo("new_password")])


class AvatarUploadForm(FlaskForm):
    avatar = FileField(
        "Profile photo",
        validators=[
            FileRequired("Choose a profile photo."),
            FileAllowed(
                ["png", "jpg", "jpeg", "webp"],
                "Use a PNG, JPEG, or WebP image.",
            ),
        ],
    )
