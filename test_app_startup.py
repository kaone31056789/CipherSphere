#!/usr/bin/env python3
"""
Quick test to check if the Flask app starts without errors
"""
import sys
import os

# Add the project root to the path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

try:
    print("Testing Flask app import...")
    
    # Try to import the main components
    from flask import Flask
    from flask_wtf.csrf import CSRFProtect
    print("✓ Flask and CSRFProtect imports successful")
    
    # Try to import our models and forms
    from ciphersphere.models import db, User
    from ciphersphere.forms import DownloadForm
    print("✓ Models and forms import successful")
    
    # Try to import encryption
    from ciphersphere.encryption import EncryptionManager
    print("✓ Encryption manager import successful")
    
    print("\n✅ All imports successful! The app should start without errors.")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"❌ Unexpected error: {e}")
    sys.exit(1)
