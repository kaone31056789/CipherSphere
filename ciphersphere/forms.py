from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, TextAreaField, SelectField, BooleanField, EmailField
from wtforms.validators import DataRequired, Length, EqualTo, Email, Optional

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    full_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=120)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', 
                                   validators=[DataRequired(), EqualTo('password')])
    security_question = SelectField('Security Question', 
                                  choices=[
                                      ('What was the name of your first pet?', 'What was the name of your first pet?'),
                                      ('What city were you born in?', 'What city were you born in?'),
                                      ('What was your first car?', 'What was your first car?'),
                                      ('What is your mother\'s maiden name?', 'What is your mother\'s maiden name?'),
                                      ('What was the name of your first school?', 'What was the name of your first school?')
                                  ],
                                  validators=[DataRequired()])
    security_answer = StringField('Security Answer', validators=[DataRequired(), Length(min=2)])

class EncryptForm(FlaskForm):
    algorithm = SelectField('Encryption Algorithm', 
                          choices=[
                              ('AES', 'AES (Advanced Encryption Standard)'),
                              ('Fernet', 'Fernet (Symmetric Encryption)'),
                              ('RSA', 'RSA (Asymmetric Encryption)')
                          ],
                          validators=[DataRequired()])
    
    text_content = TextAreaField('Text Content', validators=[Optional()])
    file = FileField('Upload File', validators=[Optional(), FileAllowed(['txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg', 'zip', 'rar', '7z', 'tar', 'gz', 'mp3', 'wav', 'mp4', 'avi', 'mkv', 'mov', 'json', 'xml', 'csv', 'log', 'md', 'py', 'js', 'css', 'html'], 'Invalid file type')])
    key = StringField('Encryption Key (leave blank for auto-generation)', validators=[Optional()])
    save_to_vault = BooleanField('Save to Personal Vault', default=True)

class DecryptForm(FlaskForm):
    algorithm = SelectField('Decryption Algorithm', 
                          choices=[
                              ('AES', 'AES (Advanced Encryption Standard)'),
                              ('Fernet', 'Fernet (Symmetric Encryption)'),
                              ('RSA', 'RSA (Asymmetric Encryption)')
                          ],
                          validators=[DataRequired()])
    
    text_content = TextAreaField('Encrypted Text Content', validators=[Optional()])
    file = FileField('Upload Encrypted File', validators=[Optional()])
    key = StringField('Decryption Key', validators=[DataRequired()])

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_new_password = PasswordField('Confirm New Password', 
                                       validators=[DataRequired(), EqualTo('new_password')])

class SecurityQuestionForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    security_question = SelectField('Security Question', 
                                  choices=[
                                      ('What was the name of your first pet?', 'What was the name of your first pet?'),
                                      ('What city were you born in?', 'What city were you born in?'),
                                      ('What was your first car?', 'What was your first car?'),
                                      ('What is your mother\'s maiden name?', 'What is your mother\'s maiden name?'),
                                      ('What was the name of your first school?', 'What was the name of your first school?')
                                  ],
                                  validators=[DataRequired()])
    security_answer = StringField('Security Answer', validators=[DataRequired(), Length(min=2)])

class ShareFileForm(FlaskForm):
    recipient_username = StringField('Recipient Username', validators=[DataRequired()])
    permissions = SelectField('Permissions', 
                             choices=[
                                 ('read', 'Read Only'),
                                 ('download', 'Read & Download'),
                                 ('edit', 'Full Access')
                             ],
                             default='download',
                             validators=[DataRequired()])
    message = TextAreaField('Optional Message', validators=[Optional()])

class ForgotPasswordForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])

class ResetPasswordForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    security_answer = StringField('Security Answer', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', 
                                   validators=[DataRequired(), EqualTo('new_password')])

class AdminUserForm(FlaskForm):
    action = SelectField('Action', 
                        choices=[
                            ('reset_password', 'Reset Password'),
                            ('toggle_admin', 'Toggle Admin Status'),
                            ('delete_user', 'Delete User'),
                            ('unlock_account', 'Unlock Account')
                        ],
                        validators=[DataRequired()])
    new_password = PasswordField('New Password (for reset)', validators=[Optional(), Length(min=6)])

class DownloadForm(FlaskForm):
    temp_filename = StringField('Temp Filename', validators=[DataRequired()])
    filename = StringField('Original Filename', validators=[DataRequired()])
