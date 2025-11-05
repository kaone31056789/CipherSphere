from app import app, User, db

with app.app_context():
    admin = User.query.filter_by(username='admin').first()
    from werkzeug.security import generate_password_hash
    if admin:
        print(f'Admin user exists: {admin.username}, Email: {admin.email}, Is Admin: {admin.is_admin}')
        admin.password_hash = generate_password_hash('12345')
        db.session.commit()
        print('Admin password has been reset to: 12345')
    else:
        print('No admin user found, creating one...')
        admin_user = User(
            username='admin',
            email='admin@ciphersphere.com',
            password_hash=generate_password_hash('12345'),
            is_admin=True
        )
        db.session.add(admin_user)
        db.session.commit()
        print('Admin user created successfully!')
        print('Username: admin')
        print('Password: 12345')
        print('Email: admin@ciphersphere.com')
