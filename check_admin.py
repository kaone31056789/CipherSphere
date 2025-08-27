from app import app, User, db

with app.app_context():
    admin = User.query.filter_by(username='admin').first()
    if admin:
        print(f'Admin user exists: {admin.username}, Email: {admin.email}, Is Admin: {admin.is_admin}')
    else:
        print('No admin user found, creating one...')
        from werkzeug.security import generate_password_hash
        admin_user = User(
            username='admin',
            email='admin@ciphersphere.com',
            password_hash=generate_password_hash('admin123'),
            is_admin=True
        )
        db.session.add(admin_user)
        db.session.commit()
        print('Admin user created successfully!')
        print('Username: admin')
        print('Password: admin123')
        print('Email: admin@ciphersphere.com')
