# Test script to demonstrate the new encrypted file format
import os
import sys
sys.path.append('.')

from ciphersphere.encryption import EncryptionManager

def test_file_format_preservation():
    print("Testing CipherSphere File Format Preservation")
    print("=" * 50)
    
    # Create test files
    test_files = {
        'test_document.txt': b'This is a test document with some content.',
        'test_image.jpg': b'\xFF\xD8\xFF\xE0JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00test_jpeg_data',
        'test_data.json': b'{"name": "test", "value": 123, "active": true}'
    }
    
    encryption_manager = EncryptionManager()
    
    for filename, content in test_files.items():
        print(f"\n📁 Testing file: {filename}")
        
        # Create test file
        with open(filename, 'wb') as f:
            f.write(content)
        
        try:
            # Encrypt the file
            result = encryption_manager.encrypt_file(filename, 'testkey123', 'AES')
            encrypted_file = result['file_path']
            print(f"✅ Encrypted: {encrypted_file}")
            print(f"   Original filename preserved: {result['original_filename']}")
            
            # Now decrypt it
            decrypt_result = encryption_manager.decrypt_file(encrypted_file, 'testkey123', 'AES')
            print(f"✅ Decrypted: {decrypt_result['file_path']}")
            print(f"   Original filename restored: {decrypt_result['original_filename']}")
            
            # Verify content
            with open(decrypt_result['file_path'], 'rb') as f:
                decrypted_content = f.read()
            
            if decrypted_content == content:
                print(f"✅ Content verified: MATCH")
            else:
                print(f"❌ Content verified: MISMATCH")
            
        except Exception as e:
            print(f"❌ Error: {e}")
        
        finally:
            # Cleanup
            for cleanup_file in [filename, filename + '.encrypted', filename.replace('.', '.decrypted.')]:
                if os.path.exists(cleanup_file):
                    os.remove(cleanup_file)
    
    print("\n" + "=" * 50)
    print("Test completed!")

if __name__ == "__main__":
    test_file_format_preservation()
