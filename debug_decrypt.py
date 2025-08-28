import os
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ciphersphere.encryption import EncryptionManager

def test_decrypt_data_with_metadata():
    """Test the decrypt_data_with_metadata function to identify the issue"""
    
    encryption_manager = EncryptionManager()
    
    # Test with a simple text encryption first
    test_text = "Hello, World!"
    test_key = "test_key_123"
    algorithm = "AES"
    
    print("Testing encryption...")
    # Encrypt first
    encrypted_result = encryption_manager.encrypt_text(test_text, test_key, algorithm)
    print(f"Encrypted result type: {type(encrypted_result)}")
    print(f"Encrypted result keys: {encrypted_result.keys() if isinstance(encrypted_result, dict) else 'Not a dict'}")
    
    # Now test decrypt_data_with_metadata
    print("\nTesting decrypt_data_with_metadata...")
    
    try:
        # Convert the encrypted text back to bytes for testing
        encrypted_data = encrypted_result['data'] if isinstance(encrypted_result, dict) else encrypted_result
        print(f"Encrypted data type: {type(encrypted_data)}")
        
        result = encryption_manager.decrypt_data_with_metadata(encrypted_data, test_key, algorithm)
        print(f"Decrypt successful: {result}")
        
    except Exception as e:
        print(f"Error during decryption: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_decrypt_data_with_metadata()
