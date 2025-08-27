from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, session, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import secrets
from datetime import datetime, timedelta
import json
from ciphersphere.encryption import EncryptionManager
from ciphersphere.models import db, User, EncryptedFile, ActivityLog, SharedFile
from ciphersphere.forms import LoginForm, RegisterForm, EncryptForm, ChangePasswordForm, SecurityQuestionForm
import base64

app = Flask(__name__, 
            template_folder='ciphersphere/templates',
            static_folder='ciphersphere/static')
# File upload configurations
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg',
    'zip', 'rar', '7z', 'tar', 'gz',
    'mp3', 'wav', 'mp4', 'avi', 'mkv', 'mov',
    'json', 'xml', 'csv', 'log', 'md', 'py', 'js', 'css', 'html'
}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ciphersphere.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'ciphersphere/uploads'
app.config['VAULT_FOLDER'] = 'ciphersphere/vault'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Ensure upload and vault directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['VAULT_FOLDER'], exist_ok=True)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

encryption_manager = EncryptionManager()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        # Check if username exists
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            suggestions = generate_username_suggestions(form.full_name.data, form.username.data)
            return render_template('register.html', form=form, 
                                 error="Username already exists", 
                                 suggestions=suggestions)
        
        # Create new user
        user = User(
            username=form.username.data,
            full_name=form.full_name.data,
            email=form.email.data,
            password_hash=generate_password_hash(form.password.data),
            security_question=form.security_question.data,
            security_answer_hash=generate_password_hash(form.security_answer.data.lower())
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Log registration activity
        log_activity(user.id, 'User registered')
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            log_activity(user.id, 'User logged in')
            
            # Check if admin
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, 'User logged out')
    logout_user()
    return redirect(url_for('index'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    from ciphersphere.forms import ForgotPasswordForm
    form = ForgotPasswordForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            # Store username in session for next step
            session['reset_username'] = user.username
            return redirect(url_for('reset_password'))
        else:
            flash('Username not found', 'error')
    
    return render_template('forgot_password.html', form=form)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    from ciphersphere.forms import ResetPasswordForm
    
    if 'reset_username' not in session:
        return redirect(url_for('forgot_password'))
    
    form = ResetPasswordForm()
    username = session['reset_username']
    user = User.query.filter_by(username=username).first()
    
    if not user:
        session.pop('reset_username', None)
        return redirect(url_for('forgot_password'))
    
    # Pre-fill username
    form.username.data = username
    
    if form.validate_on_submit():
        # Verify security answer
        if user.security_answer.lower() == form.security_answer.data.lower():
            # Update password
            user.password_hash = generate_password_hash(form.new_password.data)
            db.session.commit()
            
            # Clear session
            session.pop('reset_username', None)
            
            # Log activity
            log_activity(user.id, 'Password reset via security question')
            
            flash('Password reset successfully! You can now log in with your new password.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Security answer is incorrect', 'error')
    
    return render_template('reset_password.html', form=form, security_question=user.security_question)

@app.route('/dashboard')
@login_required
def dashboard():
    # Get recent activity
    recent_activity = ActivityLog.query.filter_by(user_id=current_user.id)\
                                      .order_by(ActivityLog.timestamp.desc())\
                                      .limit(10).all()
    
    # Get recent files
    recent_files = EncryptedFile.query.filter_by(user_id=current_user.id)\
                                     .order_by(EncryptedFile.created_at.desc())\
                                     .limit(5).all()
    
    # Get shared files
    shared_files = SharedFile.query.filter_by(shared_with_user_id=current_user.id)\
                                   .order_by(SharedFile.shared_at.desc())\
                                   .limit(5).all()
    
    return render_template('dashboard.html', 
                         recent_activity=recent_activity,
                         recent_files=recent_files,
                         shared_files=shared_files)

@app.route('/encrypt', methods=['GET', 'POST'])
@login_required
def encrypt():
    form = EncryptForm()
    
    if form.validate_on_submit():
        try:
            algorithm = form.algorithm.data
            key = form.key.data or generate_random_key(algorithm)
            
            if form.text_content.data:
                # Encrypt text
                result = encryption_manager.encrypt_text(
                    form.text_content.data, key, algorithm
                )
                
                # Save to vault if requested
                if form.save_to_vault.data:
                    encrypted_file = EncryptedFile(
                        user_id=current_user.id,
                        filename='text_content.txt',
                        original_filename='text_content.txt',
                        algorithm=algorithm,
                        is_text=True,
                        file_size=len(form.text_content.data)
                    )
                    db.session.add(encrypted_file)
                    db.session.commit()
                    
                    # Save encrypted content
                    vault_path = os.path.join(app.config['VAULT_FOLDER'], 
                                            f"{encrypted_file.id}_{encrypted_file.filename}")
                    with open(vault_path, 'wb') as f:
                        f.write(result['data'])
                
                log_activity(current_user.id, f'Text encrypted using {algorithm}')
                
                return render_template('encrypt_result.html', 
                                     result=result, 
                                     algorithm=algorithm,
                                     key=key,
                                     is_text=True)
            
            elif form.file.data:
                # Encrypt file
                file = form.file.data
                filename = secure_filename(file.filename)
                
                # Validate file type
                if not allowed_file(filename):
                    flash(f'File type not allowed. Supported types: {", ".join(sorted(ALLOWED_EXTENSIONS))}', 'error')
                    return render_template('encrypt.html', form=form)
                
                # Check file size (50MB limit)
                file.seek(0, 2)  # Seek to end of file
                file_size = file.tell()
                file.seek(0)  # Reset to beginning
                
                if file_size > app.config['MAX_CONTENT_LENGTH']:
                    flash('File too large. Maximum size is 50MB.', 'error')
                    return render_template('encrypt.html', form=form)
                
                # Save uploaded file temporarily
                temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(temp_path)
                
                try:
                    result = encryption_manager.encrypt_file(temp_path, key, algorithm)
                    
                    # Save to vault if requested
                    if form.save_to_vault.data:
                        encrypted_file = EncryptedFile(
                            user_id=current_user.id,
                            filename=f"encrypted_{filename}",
                            original_filename=filename,
                            algorithm=algorithm,
                            is_text=False,
                            file_size=os.path.getsize(temp_path)
                        )
                        db.session.add(encrypted_file)
                        db.session.commit()
                        
                        # Move encrypted file to vault
                        vault_path = os.path.join(app.config['VAULT_FOLDER'], 
                                                f"{encrypted_file.id}_{encrypted_file.filename}")
                        os.rename(result['file_path'], vault_path)
                    
                    log_activity(current_user.id, f'File {filename} encrypted using {algorithm}')
                    
                    return render_template('encrypt_result.html', 
                                         result=result, 
                                         algorithm=algorithm,
                                         key=key,
                                         is_text=False,
                                         filename=filename)
                
                finally:
                    # Clean up temporary file
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
        
        except Exception as e:
            flash(f'Encryption failed: {str(e)}', 'error')
    
    return render_template('encrypt.html', form=form)

@app.route('/decrypt', methods=['GET', 'POST'])
@login_required
def decrypt():
    form = EncryptForm()
    
    if form.validate_on_submit():
        try:
            algorithm = form.algorithm.data
            key = form.key.data
            
            if form.text_content.data:
                # Decrypt text
                result = encryption_manager.decrypt_text(
                    form.text_content.data, key, algorithm
                )
                
                log_activity(current_user.id, f'Text decrypted using {algorithm}')
                
                return render_template('decrypt_result.html', 
                                     result=result, 
                                     algorithm=algorithm,
                                     is_text=True)
            
            elif form.file.data:
                # Decrypt file
                file = form.file.data
                filename = secure_filename(file.filename)
                
                # Save uploaded file temporarily
                temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(temp_path)
                
                try:
                    result = encryption_manager.decrypt_file(temp_path, key, algorithm)
                    
                    log_activity(current_user.id, f'File {filename} decrypted using {algorithm}')
                    
                    return render_template('decrypt_result.html', 
                                         result=result, 
                                         algorithm=algorithm,
                                         is_text=False,
                                         filename=filename)
                
                finally:
                    # Clean up temporary file
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
        
        except Exception as e:
            flash(f'Decryption failed: {str(e)}', 'error')
    
    return render_template('decrypt.html', form=form)

@app.route('/vault')
@login_required
def vault():
    files = EncryptedFile.query.filter_by(user_id=current_user.id)\
                              .order_by(EncryptedFile.created_at.desc()).all()
    return render_template('vault.html', files=files)

@app.route('/vault/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = EncryptedFile.query.filter_by(id=file_id, user_id=current_user.id).first()
    if not file:
        flash('File not found.', 'error')
        return redirect(url_for('vault'))
    
    # Look for file in vault folder
    file_path = os.path.join(app.config['VAULT_FOLDER'], f"{file.id}_{file.filename}")
    if not os.path.exists(file_path):
        # Fallback: try original filename in vault
        file_path = os.path.join(app.config['VAULT_FOLDER'], file.filename)
        if not os.path.exists(file_path):
            # Last fallback: try upload folder
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            if not os.path.exists(file_path):
                flash('File not found on disk.', 'error')
                return redirect(url_for('vault'))
    
    # Log activity
    log_activity(current_user.id, 'file_download', f'Downloaded file: {file.original_filename}')
    
    return send_file(file_path, as_attachment=True, download_name=file.original_filename)

@app.route('/vault/share/<int:file_id>', methods=['POST'])
@login_required
def share_file(file_id):
    file = EncryptedFile.query.filter_by(id=file_id, user_id=current_user.id).first()
    if not file:
        flash('File not found.', 'error')
        return redirect(url_for('vault'))
    
    email = request.form.get('email')
    if not email:
        flash('Email is required for sharing.', 'error')
        return redirect(url_for('vault'))
    
    # Create a share record (you might want to create a SharedFile model)
    # For now, just log the activity
    log_activity(current_user.id, 'file_share', f'Shared file {file.original_filename} with {email}')
    
    flash(f'File shared with {email} successfully!', 'success')
    return redirect(url_for('vault'))

@app.route('/vault/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = EncryptedFile.query.filter_by(id=file_id, user_id=current_user.id).first()
    if not file:
        return jsonify({'success': False, 'message': 'File not found'})
    
    try:
        # Delete physical file
        file_path = os.path.join(app.config['VAULT_FOLDER'], f"{file.id}_{file.filename}")
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete database record
        db.session.delete(file)
        db.session.commit()
        
        # Log activity
        log_activity(current_user.id, 'file_delete', f'Deleted file: {file.original_filename}')
        
        return jsonify({'success': True, 'message': 'File deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error deleting file: {str(e)}'})

@app.route('/vault/change-key/<int:file_id>', methods=['POST'])
@login_required
def change_security_key(file_id):
    file = EncryptedFile.query.filter_by(id=file_id, user_id=current_user.id).first()
    if not file:
        return jsonify({'success': False, 'message': 'File not found'})
    
    try:
        data = request.get_json()
        current_key = data.get('current_key')
        new_key = data.get('new_key')
        
        if not current_key or not new_key:
            return jsonify({'success': False, 'message': 'Both current and new keys are required'})
        
        # Get the file path
        file_path = os.path.join(app.config['VAULT_FOLDER'], f"{file.id}_{file.filename}")
        
        if not os.path.exists(file_path):
            return jsonify({'success': False, 'message': 'File not found on disk'})
        
        # Read the encrypted file
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Try to decrypt with current key
        try:
            decrypted_data = encryption_manager.decrypt_data(encrypted_data, current_key, file.algorithm)
        except Exception:
            return jsonify({'success': False, 'message': 'Invalid current key'})
        
        # Re-encrypt with new key
        try:
            new_encrypted_data = encryption_manager.encrypt_data(decrypted_data, new_key, file.algorithm)
        except Exception as e:
            return jsonify({'success': False, 'message': f'Failed to encrypt with new key: {str(e)}'})
        
        # Save the re-encrypted file
        with open(file_path, 'wb') as f:
            f.write(new_encrypted_data)
        
        # Log activity
        log_activity(current_user.id, 'key_change', f'Security key changed for file: {file.original_filename}')
        
        return jsonify({'success': True, 'message': 'Security key changed successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error changing security key: {str(e)}'})

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'change_password':
            form = ChangePasswordForm()
            if form.validate_on_submit():
                if check_password_hash(current_user.password_hash, form.current_password.data):
                    current_user.password_hash = generate_password_hash(form.new_password.data)
                    db.session.commit()
                    log_activity(current_user.id, 'password_change', 'Password changed')
                    flash('Password changed successfully!', 'success')
                else:
                    flash('Current password is incorrect', 'error')
        
        elif action == 'update_security':
            security_form = SecurityQuestionForm()
            if security_form.validate_on_submit():
                # Verify current password
                if check_password_hash(current_user.password_hash, security_form.current_password.data):
                    current_user.security_question = security_form.security_question.data
                    current_user.security_answer_hash = generate_password_hash(
                        security_form.security_answer.data.lower()
                    )
                    db.session.commit()
                    log_activity(current_user.id, 'security_update', 'Security question updated')
                    flash('Security question updated successfully!', 'success')
                else:
                    flash('Current password is incorrect', 'error')
        
        elif action == 'upload_picture':
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and file.filename != '':
                    # Check file type
                    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
                    file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
                    
                    if file_ext in allowed_extensions:
                        # Create uploads directory if it doesn't exist
                        profile_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'profiles')
                        os.makedirs(profile_dir, exist_ok=True)
                        
                        # Generate secure filename
                        import uuid
                        filename = f"{current_user.id}_{uuid.uuid4().hex[:8]}.{file_ext}"
                        filepath = os.path.join(profile_dir, filename)
                        
                        try:
                            # Delete old profile picture if it's not default
                            if current_user.profile_picture and current_user.profile_picture != 'default.jpg':
                                old_path = os.path.join(profile_dir, current_user.profile_picture)
                                if os.path.exists(old_path):
                                    os.remove(old_path)
                            
                            # Save new file
                            file.save(filepath)
                            current_user.profile_picture = filename
                            db.session.commit()
                            
                            log_activity(current_user.id, 'profile_update', 'Profile picture updated')
                            flash('Profile picture updated successfully!', 'success')
                        except Exception as e:
                            flash('Error uploading profile picture.', 'error')
                    else:
                        flash('Invalid file type. Please upload PNG, JPG, JPEG, or GIF files.', 'error')
                else:
                    flash('No file selected.', 'error')
    
    password_form = ChangePasswordForm()
    security_form = SecurityQuestionForm()
    
    return render_template('profile.html', 
                         password_form=password_form,
                         security_form=security_form)

@app.route('/profile_picture/<filename>')
def profile_picture(filename):
    """Serve profile pictures"""
    profile_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'profiles')
    
    # Check if file exists
    file_path = os.path.join(profile_dir, filename)
    if os.path.exists(file_path):
        return send_file(file_path)
    
    # If file doesn't exist, create a simple SVG avatar
    from flask import Response
    
    # Get the first letter of the current user's name
    letter = current_user.full_name[0].upper() if current_user.is_authenticated else '?'
    
    svg_content = f'''<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200" viewBox="0 0 200 200">
        <defs>
            <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" style="stop-color:#3399ff;stop-opacity:1" />
                <stop offset="100%" style="stop-color:#0066cc;stop-opacity:1" />
            </linearGradient>
        </defs>
        <circle cx="100" cy="100" r="100" fill="url(#grad)"/>
        <text x="100" y="130" font-family="Arial, sans-serif" font-size="80" font-weight="bold" 
              text-anchor="middle" fill="white">{letter}</text>
    </svg>'''
    
    return Response(svg_content, mimetype='image/svg+xml')

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get system stats
    total_users = User.query.count()
    total_files = EncryptedFile.query.count()
    total_activities = ActivityLog.query.count()
    
    # Get today's stats
    from datetime import date
    today = date.today()
    new_users_today = User.query.filter(User.created_at >= today).count() if hasattr(User, 'created_at') else 0
    new_files_today = EncryptedFile.query.filter(EncryptedFile.created_at >= today).count()
    
    # Get recent activity
    recent_activities = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()
    
    # Get active users count (users with activity in last 24 hours)
    from datetime import datetime, timedelta
    yesterday = datetime.now() - timedelta(days=1)
    active_users = User.query.join(ActivityLog).filter(ActivityLog.timestamp >= yesterday).distinct().count()
    
    # Get active sessions count (approximate)
    active_sessions = User.query.filter(User.last_login >= yesterday).count() if hasattr(User, 'last_login') else active_users
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_files=total_files,
                         total_activities=total_activities,
                         new_users_today=new_users_today,
                         new_files_today=new_files_today,
                         recent_activities=recent_activities,
                         active_users=active_users,
                         active_sessions=active_sessions)

@app.route('/admin/api/stats')
@login_required
def admin_api_stats():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        # Get system stats
        total_users = User.query.count()
        total_files = EncryptedFile.query.count()
        
        # Get today's activities
        from datetime import date
        today = date.today()
        activities_today = ActivityLog.query.filter(ActivityLog.timestamp >= today).count()
        
        return jsonify({
            'total_users': total_users,
            'total_files': total_files,
            'activities_today': activities_today
        })
    except Exception as e:
        return jsonify({'error': 'Failed to load stats'}), 500

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
def admin_create_user():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            # Get form data
            username = request.form.get('username')
            full_name = request.form.get('full_name')
            email = request.form.get('email')
            password = request.form.get('password')
            security_question = request.form.get('security_question')
            security_answer = request.form.get('security_answer')
            is_admin = 'is_admin' in request.form
            
            # Validate required fields
            if not all([username, full_name, email, password, security_question, security_answer]):
                flash('All fields are required.', 'error')
                return redirect(url_for('admin_create_user'))
            
            # Check if user already exists
            if User.query.filter_by(username=username).first():
                flash('Username already exists.', 'error')
                return redirect(url_for('admin_create_user'))
            
            if User.query.filter_by(email=email).first():
                flash('Email already exists.', 'error')
                return redirect(url_for('admin_create_user'))
            
            # Create new user
            new_user = User(
                username=username,
                full_name=full_name,
                email=email,
                password_hash=generate_password_hash(password),
                security_question=security_question,
                security_answer_hash=generate_password_hash(security_answer.lower()),
                is_admin=is_admin,
                created_at=datetime.utcnow()
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            # Log activity
            log_activity(current_user.id, 'user_create', f'Created user: {username}')
            
            flash(f'User {username} created successfully!', 'success')
            return redirect(url_for('admin_users'))
            
        except Exception as e:
            db.session.rollback()
            flash('Error creating user. Please try again.', 'error')
            return redirect(url_for('admin_create_user'))
    
    return render_template('admin/create_user.html')

@app.route('/admin/files')
@login_required
def admin_files():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    files = EncryptedFile.query.all()
    total_files = len(files)
    total_size = sum(f.file_size or 0 for f in files)
    
    # Group files by algorithm
    algorithms = {}
    for file in files:
        alg = file.algorithm
        if alg not in algorithms:
            algorithms[alg] = {'count': 0, 'size': 0}
        algorithms[alg]['count'] += 1
        algorithms[alg]['size'] += file.file_size or 0
    
    return render_template('admin/files.html', 
                         files=files, 
                         total_files=total_files,
                         total_size=total_size,
                         algorithms=algorithms)

@app.route('/admin/activity')
@login_required
def admin_activity():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    activities = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False)
    
    # Get activity statistics
    total_activities = ActivityLog.query.count()
    today_activities = ActivityLog.query.filter(
        ActivityLog.timestamp >= datetime.now().replace(hour=0, minute=0, second=0)
    ).count()
    
    # Get most active users
    from sqlalchemy import func
    active_users = db.session.query(
        User.username, User.full_name, func.count(ActivityLog.id).label('activity_count')
    ).join(ActivityLog).group_by(User.id).order_by(
        func.count(ActivityLog.id).desc()
    ).limit(10).all()
    
    return render_template('admin/activity.html',
                         activities=activities,
                         total_activities=total_activities,
                         today_activities=today_activities,
                         active_users=active_users)

@app.route('/admin/settings')
@login_required
def admin_settings():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    # System information
    import psutil
    import platform
    
    system_info = {
        'platform': platform.system(),
        'platform_release': platform.release(),
        'platform_version': platform.version(),
        'architecture': platform.machine(),
        'hostname': platform.node(),
        'processor': platform.processor(),
        'ram': f"{round(psutil.virtual_memory().total / (1024.0 ** 3), 2)} GB",
        'cpu_usage': psutil.cpu_percent(),
        'memory_usage': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent
    }
    
    # Database statistics
    db_stats = {
        'users': User.query.count(),
        'files': EncryptedFile.query.count(),
        'activities': ActivityLog.query.count(),
        'shared_files': SharedFile.query.count() if hasattr(db.Model, 'SharedFile') else 0
    }
    
    return render_template('admin/settings.html',
                         system_info=system_info,
                         db_stats=db_stats)

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})
    
    user = User.query.get_or_404(user_id)
    
    # Don't allow deleting admin users
    if user.is_admin:
        return jsonify({'success': False, 'message': 'Cannot delete admin users'})
    
    # Delete user's files and activities
    EncryptedFile.query.filter_by(user_id=user_id).delete()
    ActivityLog.query.filter_by(user_id=user_id).delete()
    
    # Delete user
    db.session.delete(user)
    db.session.commit()
    
    log_activity(current_user.id, f'Deleted user: {user.username}')
    
    return jsonify({'success': True, 'message': 'User deleted successfully'})

@app.route('/admin/users/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
def admin_toggle_user_admin(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})
    
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    
    action = 'granted' if user.is_admin else 'revoked'
    log_activity(current_user.id, f'Admin privileges {action} for user: {user.username}')
    
    return jsonify({
        'success': True, 
        'message': f'Admin privileges {action} successfully',
        'is_admin': user.is_admin
    })

@app.route('/admin/files/<int:file_id>/delete', methods=['POST'])
@login_required
def admin_delete_file(file_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})
    
    file = EncryptedFile.query.get_or_404(file_id)
    
    # Delete physical file
    try:
        file_path = os.path.join(app.config['VAULT_FOLDER'], file.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        pass  # Continue even if file deletion fails
    
    # Delete database record
    db.session.delete(file)
    db.session.commit()
    
    log_activity(current_user.id, f'Deleted file: {file.original_filename}')
    
    return jsonify({'success': True, 'message': 'File deleted successfully'})

@app.route('/share_encrypted_data', methods=['POST'])
@login_required
def share_encrypted_data():
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('email'):
            return jsonify({'success': False, 'error': 'Email address is required'})
        
        # Check if user exists
        target_user = User.query.filter_by(email=data['email']).first()
        if not target_user:
            return jsonify({'success': False, 'error': 'User not found'})
        
        # Create shared file record
        shared_file = SharedFile(
            owner_id=current_user.id,
            shared_with_id=target_user.id,
            content_type=data.get('content_type', 'text'),
            content=data.get('content', '') if data.get('content_type') == 'text' else None,
            file_id=data.get('file_id') if data.get('content_type') == 'file' else None,
            encryption_key=data.get('encryption_key', ''),
            algorithm=data.get('algorithm', 'AES'),
            access_level=data.get('access_level', 'view'),
            expires_at=datetime.utcnow() + timedelta(days=int(data.get('expiry_days', 7))) if int(data.get('expiry_days', 7)) > 0 else None
        )
        
        db.session.add(shared_file)
        db.session.commit()
        
        log_activity(current_user.id, f'Shared encrypted data with {data["email"]}')
        log_activity(target_user.id, f'Received shared encrypted data from {current_user.email}')
        
        return jsonify({'success': True, 'message': 'Data shared successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/shared_files')
@login_required
def shared_files():
    # Files shared with current user
    shared_with_me = SharedFile.query.filter_by(shared_with_id=current_user.id).all()
    
    # Files shared by current user
    shared_by_me = SharedFile.query.filter_by(owner_id=current_user.id).all()
    
    return render_template('shared_files.html', 
                         shared_with_me=shared_with_me,
                         shared_by_me=shared_by_me)

@app.route('/view_shared/<int:share_id>')
@login_required
def view_shared(share_id):
    shared_file = SharedFile.query.get_or_404(share_id)
    
    # Check if user has access
    if shared_file.shared_with_id != current_user.id and shared_file.owner_id != current_user.id:
        flash('You do not have permission to view this file.', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if expired
    if shared_file.expires_at and shared_file.expires_at < datetime.utcnow():
        flash('This shared file has expired.', 'error')
        return redirect(url_for('shared_files'))
    
    return render_template('view_shared.html', shared_file=shared_file)

@app.route('/generate_security_key')
@login_required
def generate_security_key():
    """Generate a new security key in real-time"""
    algorithm = request.args.get('algorithm', 'AES')
    key = generate_random_key(algorithm)
    
    return jsonify({
        'success': True,
        'key': key,
        'algorithm': algorithm,
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/get_shared_key/<int:share_id>')
@login_required
def get_shared_key(share_id):
    shared_file = SharedFile.query.get_or_404(share_id)
    
    # Check if user has decrypt access
    if shared_file.shared_with_id != current_user.id or shared_file.access_level != 'decrypt':
        return jsonify({'success': False, 'error': 'Access denied'})
    
    return jsonify({'success': True, 'key': shared_file.encryption_key})

@app.route('/download_shared/<int:share_id>')
@login_required
def download_shared(share_id):
    shared_file = SharedFile.query.get_or_404(share_id)
    
    # Check if user has download access
    if shared_file.shared_with_id != current_user.id or shared_file.access_level not in ['download', 'decrypt']:
        flash('Access denied', 'error')
        return redirect(url_for('shared_files'))
    
    # Check if expired
    if shared_file.expires_at and shared_file.expires_at < datetime.utcnow():
        flash('This shared file has expired', 'error')
        return redirect(url_for('shared_files'))
    
    if shared_file.content_type == 'text':
        # Create text file
        response = Response(shared_file.content, mimetype='text/plain')
        response.headers['Content-Disposition'] = 'attachment; filename=shared_content.txt'
        return response
    else:
        # Handle file download
        if shared_file.file_id:
            encrypted_file = EncryptedFile.query.get(shared_file.file_id)
            if encrypted_file:
                file_path = os.path.join(app.config['VAULT_FOLDER'], 
                                       f"{encrypted_file.id}_{encrypted_file.filename}")
                if os.path.exists(file_path):
                    return send_file(file_path, as_attachment=True, 
                                   download_name=encrypted_file.original_filename)
    
    flash('File not found', 'error')
    return redirect(url_for('shared_files'))

@app.route('/revoke_share/<int:share_id>', methods=['POST'])
@login_required
def revoke_share(share_id):
    shared_file = SharedFile.query.get_or_404(share_id)
    
    # Check if user owns the share
    if shared_file.owner_id != current_user.id:
        return jsonify({'success': False, 'error': 'Access denied'})
    
    db.session.delete(shared_file)
    db.session.commit()
    
    log_activity(current_user.id, f'Revoked share with {shared_file.shared_with.email}')
    
    return jsonify({'success': True})

@app.route('/extend_share/<int:share_id>', methods=['POST'])
@login_required
def extend_share(share_id):
    shared_file = SharedFile.query.get_or_404(share_id)
    
    # Check if user owns the share
    if shared_file.owner_id != current_user.id:
        return jsonify({'success': False, 'error': 'Access denied'})
    
    data = request.get_json()
    days = int(data.get('days', 7))
    
    if shared_file.expires_at:
        shared_file.expires_at = shared_file.expires_at + timedelta(days=days)
    else:
        shared_file.expires_at = datetime.utcnow() + timedelta(days=days)
    
    db.session.commit()
    
    log_activity(current_user.id, f'Extended share with {shared_file.shared_with.email} by {days} days')
    
    return jsonify({'success': True})

@app.route('/check_username')
def check_username():
    username = request.args.get('username', '')
    existing_user = User.query.filter_by(username=username).first()
    
    if existing_user:
        suggestions = generate_username_suggestions('', username)
        return jsonify({'available': False, 'suggestions': suggestions})
    else:
        return jsonify({'available': True})

# Helper functions
def generate_username_suggestions(full_name, username):
    suggestions = []
    base_names = []
    
    if full_name:
        parts = full_name.lower().split()
        base_names.extend(parts)
        if len(parts) > 1:
            base_names.append(parts[0] + parts[-1])
    
    base_names.append(username.lower())
    
    for base in base_names[:3]:
        for i in range(10):
            suggestion = f"{base}{i+1}"
            if not User.query.filter_by(username=suggestion).first():
                suggestions.append(suggestion)
            if len(suggestions) >= 5:
                break
        if len(suggestions) >= 5:
            break
    
    return suggestions[:5]

def generate_random_key(algorithm):
    if algorithm == 'AES':
        return secrets.token_urlsafe(32)
    elif algorithm == 'Fernet':
        return secrets.token_urlsafe(32)
    elif algorithm == 'RSA':
        return 'RSA_AUTO_GENERATED'
    return secrets.token_urlsafe(32)

def log_activity(user_id, action, description=None):
    # Combine action and description if description is provided
    if description:
        full_action = f"{action}: {description}"
    else:
        full_action = action
    
    activity = ActivityLog(
        user_id=user_id,
        action=full_action,
        timestamp=datetime.utcnow()
    )
    db.session.add(activity)
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                full_name='System Administrator',
                email='admin@ciphersphere.com',
                password_hash=generate_password_hash('admin123'),
                is_admin=True,
                security_question='What is the name of this system?',
                security_answer_hash=generate_password_hash('ciphersphere')
            )
            db.session.add(admin)
            db.session.commit()
    
    app.run(debug=True, host='0.0.0.0', port=5000)
