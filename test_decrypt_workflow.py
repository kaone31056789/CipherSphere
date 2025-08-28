"""
Test script to verify encryption/decryption workflow
"""

import sys
import os
sys.path.append('.')

from ciphersphere.encryption import EncryptionManager
import tempfile

def test_encryption_decryption():
    print("Testing Encryption/Decryption Workflow")
    print("=" * 50)
    
    encryption_manager = EncryptionManager()
    
    # Test data
    test_content = b"This is a test file for encryption and decryption"
    test_key = "mySecretKey123"
    algorithm = "AES"
    
    # Create a temporary test file
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.txt', delete=False) as temp_file:
        temp_file.write(test_content)
        temp_file_path = temp_file.name
    
    try:
        print(f"1. Original file: {os.path.basename(temp_file_path)}")
        print(f"   Content: {test_content.decode()}")
        print(f"   Size: {len(test_content)} bytes")
        
        # Encrypt the file
        print(f"\n2. Encrypting with {algorithm}...")
        encrypt_result = encryption_manager.encrypt_file(temp_file_path, test_key, algorithm)
        encrypted_file_path = encrypt_result['file_path']
        
        print(f"   Encrypted file: {os.path.basename(encrypted_file_path)}")
        print(f"   Original filename preserved: {encrypt_result['original_filename']}")
        print(f"   Encrypted size: {encrypt_result['encrypted_size']} bytes")
        
        # Now test decryption
        print(f"\n3. Decrypting...")
        
        # Read encrypted data
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Test decrypt_data_with_metadata method
        decrypt_result = encryption_manager.decrypt_data_with_metadata(encrypted_data, test_key, algorithm)
        
        print(f"   Has metadata: {decrypt_result['has_metadata']}")
        if decrypt_result['has_metadata']:
            print(f"   Original filename from metadata: {decrypt_result['metadata']['original_filename']}")
        
        # Verify content
        if decrypt_result['data'] == test_content:
            print(f"   ✅ Content matches original!")
        else:
            print(f"   ❌ Content mismatch!")
            print(f"   Expected: {test_content}")
            print(f"   Got: {decrypt_result['data']}")
        
        print(f"   Decrypted size: {len(decrypt_result['data'])} bytes")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Cleanup
        for file_path in [temp_file_path, temp_file_path + '.encrypted']:
            if os.path.exists(file_path):
                os.remove(file_path)
    
    print("\n" + "=" * 50)
    print("Test completed!")

if __name__ == "__main__":
    test_encryption_decryption()
