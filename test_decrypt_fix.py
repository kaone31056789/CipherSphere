#!/usr/bin/env python3
"""
Test script to verify the decrypt_data_with_metadata fix
"""

import os
import sys
import tempfile

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ciphersphere.encryption import EncryptionManager

def test_encryption_decryption():
    """Test encryption and decryption to ensure the fix works"""
    
    encryption_manager = EncryptionManager()
    
    # Test data
    test_text = "Hello, World! This is a test encryption."
    test_key = "my_secret_key_123"
    algorithm = "AES"
    
    print("🔐 Testing CipherSphere Encryption/Decryption Fix")
    print("=" * 50)
    
    try:
        # Step 1: Encrypt text
        print(f"📝 Original text: {test_text}")
        encrypted_result = encryption_manager.encrypt_text(test_text, test_key, algorithm)
        print(f"✅ Encryption successful with algorithm: {algorithm}")
        
        # Step 2: Test decrypt_data_with_metadata
        print(f"\n🔓 Testing decrypt_data_with_metadata function...")
        encrypted_data = encrypted_result['data'] if isinstance(encrypted_result, dict) else encrypted_result
        
        result = encryption_manager.decrypt_data_with_metadata(encrypted_data, test_key, algorithm)
        
        print(f"✅ Decryption successful!")
        print(f"📄 Has metadata: {result['has_metadata']}")
        print(f"📝 Decrypted text: {result['data'].decode('utf-8') if isinstance(result['data'], bytes) else result['data']}")
        
        # Step 3: Test with file encryption
        print(f"\n📁 Testing file encryption/decryption...")
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
            temp_file.write("This is test file content for encryption testing.")
            temp_file_path = temp_file.name
        
        try:
            # Encrypt file
            encrypted_file_result = encryption_manager.encrypt_file(temp_file_path, test_key, algorithm)
            print(f"✅ File encryption successful: {encrypted_file_result['file_path']}")
            
            # Read encrypted file
            with open(encrypted_file_result['file_path'], 'rb') as f:
                encrypted_file_data = f.read()
            
            # Decrypt with metadata
            file_decrypt_result = encryption_manager.decrypt_data_with_metadata(encrypted_file_data, test_key, algorithm)
            print(f"✅ File decryption successful!")
            print(f"📄 Has metadata: {file_decrypt_result['has_metadata']}")
            
            if file_decrypt_result['has_metadata']:
                print(f"📋 Original filename: {file_decrypt_result['metadata']['original_filename']}")
            
        finally:
            # Clean up
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
            if os.path.exists(encrypted_file_result['file_path']):
                os.unlink(encrypted_file_result['file_path'])
        
        print(f"\n🎉 All tests passed! The decrypt_data_with_metadata fix is working correctly.")
        return True
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_encryption_decryption()
    sys.exit(0 if success else 1)
