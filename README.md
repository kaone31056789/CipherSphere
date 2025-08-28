# 🔒 CipherSphere

A futuristic, military-grade encryption platform built with Flask, featuring advanced cryptographic algorithms and a stunning cyberpunk-inspired interface.

![CipherSphere](https://img.shields.io/badge/CipherSphere-v1.0-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.13-green?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.3.3-red?style=for-the-badge&logo=flask)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

## 🌟 Features

### 🔐 Encryption & Security
- **Multiple Encryption Algorithms**: AES-256, RSA-4096, and Fernet symmetric encryption
- **Text & File Encryption**: Secure both text messages and files up to 50MB
- **Military-Grade Security**: Advanced cryptographic implementations with secure key management
- **Password Hashing**: Bcrypt-based password security with salt

### 👥 User Management
- **User Authentication**: Secure login/logout with session management
- **Profile Management**: Customizable user profiles with picture upload
- **Security Questions**: Additional security layer for password recovery
- **Admin Dashboard**: Comprehensive administration panel

### 📁 File Management
- **Secure Vault**: Personal encrypted file storage
- **File Sharing**: Share encrypted files between users with permission controls
- **Multiple File Types**: Support for documents, images, archives, and media files
- **Favorites System**: Mark frequently used files as favorites

### 🎨 Modern Interface
- **Cyberpunk Theme**: Futuristic, animated UI with Tesla-inspired design
- **Responsive Design**: Mobile-friendly interface that works on all devices
- **Interactive Animations**: Smooth transitions and visual effects
- **Dark Mode**: Eye-friendly dark theme with neon accents

### 📊 Analytics & Monitoring
- **Activity Logging**: Track all user actions and system events
- **Admin Analytics**: Monitor system usage and user activities
- **File Statistics**: Detailed information about encrypted files
- **Security Monitoring**: Track login attempts and security events

## 🚀 Quick Start

### Prerequisites
- Python 3.13 or higher
- pip package manager
- Git (optional)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/ciphersphere.git
   cd ciphersphere
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the database**
   ```bash
   python app.py
   ```
   The application will automatically create the SQLite database on first run.

5. **Run the application**
   ```bash
   python app.py
   ```
   Visit `http://localhost:5000` in your browser.

### First-Time Setup

1. **Create an Admin Account**
   - Register a new account through the web interface
   - Run the admin creation script:
     ```bash
     python check_admin.py
     ```

2. **Access Admin Dashboard**
   - Login with your admin account
   - Navigate to `/admin` to access the admin panel

## 🏗️ Project Structure

```
ciphersphere/
│
├── app.py                      # Main Flask application
├── check_admin.py             # Admin user creation utility
├── requirements.txt           # Python dependencies
│
├── ciphersphere/              # Main application package
│   ├── encryption.py          # Encryption algorithms and utilities
│   ├── forms.py              # WTForms for form handling
│   ├── models.py             # SQLAlchemy database models
│   │
│   ├── static/               # Static assets
│   │   ├── css/              # Stylesheets
│   │   │   ├── style.css     # Main stylesheet
│   │   │   ├── style_tesla.css  # Tesla theme
│   │   │   └── style_new.css # Alternative theme
│   │   ├── js/               # JavaScript files
│   │   │   ├── main.js       # Main JavaScript
│   │   │   └── animations.js # UI animations
│   │   └── images/           # Image assets
│   │
│   ├── templates/            # Jinja2 templates
│   │   ├── base.html         # Base template
│   │   ├── index.html        # Homepage
│   │   ├── login.html        # Login page
│   │   ├── register.html     # Registration page
│   │   ├── dashboard.html    # User dashboard
│   │   ├── encrypt.html      # Encryption interface
│   │   ├── decrypt.html      # Decryption interface
│   │   ├── vault.html        # File vault
│   │   ├── profile.html      # User profile
│   │   ├── shared_files.html # Shared files
│   │   └── admin/            # Admin templates
│   │       ├── dashboard.html
│   │       ├── users.html
│   │       ├── files.html
│   │       └── settings.html
│   │
│   ├── uploads/              # User uploaded files
│   │   └── profiles/         # Profile pictures
│   └── vault/                # Encrypted file storage
│
└── instance/                 # Instance-specific files
    └── ciphersphere.db       # SQLite database
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the root directory:

```env
SECRET_KEY=your-secret-key-here
SQLALCHEMY_DATABASE_URI=sqlite:///ciphersphere.db
UPLOAD_FOLDER=ciphersphere/uploads
VAULT_FOLDER=ciphersphere/vault
MAX_CONTENT_LENGTH=52428800  # 50MB in bytes
```

### Supported File Types

- **Documents**: txt, pdf, doc, docx, xls, xlsx, ppt, pptx
- **Images**: jpg, jpeg, png, gif, bmp, webp, svg
- **Archives**: zip, rar, 7z, tar, gz
- **Media**: mp3, wav, mp4, avi, mkv, mov
- **Code**: json, xml, csv, log, md, py, js, css, html

## 🔐 Encryption Algorithms

### AES (Advanced Encryption Standard)
- **Type**: Symmetric encryption
- **Key Size**: 256-bit
- **Mode**: CBC with PKCS7 padding
- **Use Case**: Fast encryption for large files

### RSA (Rivest-Shamir-Adleman)
- **Type**: Asymmetric encryption
- **Key Size**: 4096-bit
- **Padding**: OAEP with SHA-256
- **Use Case**: Secure key exchange and small data

### Fernet
- **Type**: Symmetric encryption
- **Based on**: AES-128 with HMAC-SHA256
- **Features**: Built-in timestamp and authentication
- **Use Case**: General-purpose encryption with integrity

## 🛡️ Security Features

- **Password Security**: Bcrypt hashing with automatic salt generation
- **Session Management**: Secure session handling with Flask-Login
- **CSRF Protection**: Cross-site request forgery prevention
- **File Upload Security**: Secure filename handling and type validation
- **SQL Injection Prevention**: SQLAlchemy ORM protection
- **XSS Protection**: Template auto-escaping enabled

## 🎨 Themes

CipherSphere includes multiple visual themes:

1. **Default Theme** (`style.css`): Clean, professional design
2. **Tesla Theme** (`style_tesla.css`): Futuristic cyberpunk aesthetics
3. **New Theme** (`style_new.css`): Modern minimalist design

Switch themes by modifying the CSS import in `base.html`.

## 📱 API Endpoints

### Authentication
- `POST /login` - User login
- `POST /register` - User registration
- `GET /logout` - User logout
- `POST /forgot-password` - Password recovery

### Encryption
- `POST /encrypt` - Encrypt text/file
- `POST /decrypt` - Decrypt text/file
- `GET /vault` - View encrypted files
- `POST /upload` - Upload and encrypt file

### File Management
- `GET /download/<file_id>` - Download encrypted file
- `POST /share/<file_id>` - Share file with user
- `DELETE /delete/<file_id>` - Delete encrypted file

### Admin
- `GET /admin` - Admin dashboard
- `GET /admin/users` - User management
- `GET /admin/files` - File management
- `GET /admin/activity` - Activity logs

## 🧪 Testing

Run the application in development mode:

```bash
# Enable debug mode
export FLASK_ENV=development  # Linux/macOS
set FLASK_ENV=development     # Windows

python app.py
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request



## 🐛 Known Issues

- Large file uploads may timeout on slower connections
- Mobile responsiveness needs optimization for tablets
- File sharing permissions could be more granular

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Flask](https://flask.palletsprojects.com/) - Web framework
- [Cryptography](https://cryptography.io/) - Cryptographic library
- [Bootstrap](https://getbootstrap.com/) - CSS framework
- [Font Awesome](https://fontawesome.com/) - Icons
- [SQLAlchemy](https://www.sqlalchemy.org/) - Database ORM

## 🔗 Links

- [Live Demo](https://your-demo-url.com)
- [Documentation](https://your-docs-url.com)
- [Bug Reports](https://github.com/your-username/ciphersphere/issues)
- [Feature Requests](https://github.com/your-username/ciphersphere/discussions)

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/your-username">Your Name</a>
</p>

<p align="center">
  <strong>🔒 Secure. Simple. Sophisticated. 🔒</strong>
</p>
