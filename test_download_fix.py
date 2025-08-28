#!/usr/bin/env python3
"""
Test script to verify the download functionality
"""
import os
import sys

# Add the project root to the path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def test_temp_files():
    """Test if temp files exist and are accessible"""
    temp_dir = os.path.join(project_root, 'ciphersphere', 'uploads', 'temp')
    
    print(f"Testing temp directory: {temp_dir}")
    print(f"Directory exists: {os.path.exists(temp_dir)}")
    
    if os.path.exists(temp_dir):
        files = os.listdir(temp_dir)
        print(f"Files in temp directory: {files}")
        
        for file in files:
            file_path = os.path.join(temp_dir, file)
            file_size = os.path.getsize(file_path)
            print(f"  - {file}: {file_size} bytes")
    else:
        print("Temp directory does not exist!")

def test_upload_config():
    """Test upload configuration"""
    upload_folder = os.path.join(project_root, 'ciphersphere', 'uploads')
    print(f"Upload folder: {upload_folder}")
    print(f"Upload folder exists: {os.path.exists(upload_folder)}")

if __name__ == "__main__":
    print("=== CipherSphere Download Test ===")
    test_upload_config()
    print()
    test_temp_files()
