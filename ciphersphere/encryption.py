import os
import base64
import secrets
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Cipher import AES as CryptoAES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib

class EncryptionManager:
    def __init__(self):
        self.algorithms = {
            'AES': self._aes_operations,
            'Fernet': self._fernet_operations,
            'RSA': self._rsa_operations
        }
    
    def encrypt_text(self, text, key, algorithm):
        """Encrypt text using specified algorithm"""
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        text_bytes = text.encode('utf-8')
        return self.algorithms[algorithm]('encrypt', text_bytes, key)
    
    def decrypt_text(self, encrypted_text, key, algorithm):
        """Decrypt text using specified algorithm"""
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Handle base64 encoded input
        if isinstance(encrypted_text, str):
            try:
                encrypted_bytes = base64.b64decode(encrypted_text)
            except:
                encrypted_bytes = encrypted_text.encode('utf-8')
        else:
            encrypted_bytes = encrypted_text
        
        result = self.algorithms[algorithm]('decrypt', encrypted_bytes, key)
        return {
            'data': result['data'].decode('utf-8') if isinstance(result['data'], bytes) else result['data'],
            'key': result.get('key', key)
        }
    
    def encrypt_file(self, file_path, key, algorithm):
        """Encrypt file using specified algorithm with metadata preservation"""
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Get original filename and extension
        original_filename = os.path.basename(file_path)
        
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Create metadata header
        metadata = {
            'original_filename': original_filename,
            'file_size': len(file_data),
            'algorithm': algorithm
        }
        
        # Convert metadata to JSON and encode
        metadata_json = json.dumps(metadata).encode('utf-8')
        metadata_length = len(metadata_json)
        
        # Create header: 4 bytes for metadata length + metadata + file data
        header = metadata_length.to_bytes(4, 'big') + metadata_json
        
        # Encrypt the header + file data together
        combined_data = header + file_data
        result = self.algorithms[algorithm]('encrypt', combined_data, key)
        
        # Save encrypted file with .encrypted extension
        encrypted_file_path = file_path + '.encrypted'
        with open(encrypted_file_path, 'wb') as f:
            f.write(result['data'])
        
        return {
            'file_path': encrypted_file_path,
            'key': result.get('key', key),
            'algorithm': algorithm,
            'original_filename': original_filename,
            'original_size': len(file_data),
            'encrypted_size': len(result['data'])
        }
    
    def decrypt_file(self, encrypted_file_path, key, algorithm):
        """Decrypt file using specified algorithm and restore original metadata"""
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()
        
        result = self.algorithms[algorithm]('decrypt', encrypted_data, key)
        decrypted_data = result['data']
        
        try:
            # Extract metadata
            metadata_length = int.from_bytes(decrypted_data[:4], 'big')
            metadata_json = decrypted_data[4:4+metadata_length]
            metadata = json.loads(metadata_json.decode('utf-8'))
            
            # Extract original file data
            original_file_data = decrypted_data[4+metadata_length:]
            original_filename = metadata.get('original_filename', 'decrypted_file')
            
        except (json.JSONDecodeError, KeyError, ValueError):
            # Fallback for files encrypted without metadata
            original_file_data = decrypted_data
            original_filename = os.path.basename(encrypted_file_path).replace('.encrypted', '')
            metadata = {
                'original_filename': original_filename,
                'file_size': len(original_file_data),
                'algorithm': algorithm
            }
        
        # Save decrypted file with original name
        decrypted_file_path = encrypted_file_path.replace('.encrypted', '.decrypted')
        with open(decrypted_file_path, 'wb') as f:
            f.write(original_file_data)
        
        return {
            'file_path': decrypted_file_path,
            'key': result.get('key', key),
            'algorithm': algorithm,
            'original_filename': metadata['original_filename'],
            'decrypted_size': len(original_file_data),
            'data': original_file_data
        }
    
    def encrypt_data(self, data, key, algorithm):
        """Encrypt raw data using specified algorithm"""
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        result = self.algorithms[algorithm]('encrypt', data, key)
        return result['data']
    
    def decrypt_data(self, encrypted_data, key, algorithm):
        """Decrypt raw data using specified algorithm"""
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        result = self.algorithms[algorithm]('decrypt', encrypted_data, key)
        return result['data']
    
    def decrypt_data_with_metadata(self, encrypted_data, key, algorithm):
        """Decrypt raw data and extract metadata if present"""
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        result = self.algorithms[algorithm]('decrypt', encrypted_data, key)
        decrypted_data = result['data']
        
        try:
            # Try to extract metadata
            metadata_length = int.from_bytes(decrypted_data[:4], 'big')
            metadata_json = decrypted_data[4:4+metadata_length]
            metadata = json.loads(metadata_json.decode('utf-8'))
            
            # Extract original file data
            original_file_data = decrypted_data[4+metadata_length:]
            
            return {
                'data': original_file_data,
                'metadata': metadata,
                'has_metadata': True
            }
            
        except (json.JSONDecodeError, KeyError, ValueError, IndexError):
            # No metadata found, return raw data
            return {
                'data': decrypted_data,
                'metadata': None,
                'has_metadata': False
            }
    
    def _aes_operations(self, operation, data, key):
        """AES encryption/decryption operations"""
        if operation == 'encrypt':
            # Generate a random salt and IV
            salt = get_random_bytes(16)
            iv = get_random_bytes(16)
            
            # Derive key from password using PBKDF2
            if isinstance(key, str):
                key_bytes = key.encode('utf-8')
            else:
                key_bytes = key
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            derived_key = kdf.derive(key_bytes)
            
            # Encrypt data
            cipher = CryptoAES.new(derived_key, CryptoAES.MODE_CBC, iv)
            padded_data = pad(data, CryptoAES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            
            # Combine salt + iv + encrypted_data
            result = salt + iv + encrypted_data
            
            return {
                'data': result,
                'key': key,
                'algorithm': 'AES'
            }
        
        elif operation == 'decrypt':
            # Extract salt, IV, and encrypted data
            salt = data[:16]
            iv = data[16:32]
            encrypted_data = data[32:]
            
            # Derive key from password
            if isinstance(key, str):
                key_bytes = key.encode('utf-8')
            else:
                key_bytes = key
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            derived_key = kdf.derive(key_bytes)
            
            # Decrypt data
            cipher = CryptoAES.new(derived_key, CryptoAES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(encrypted_data)
            decrypted_data = unpad(decrypted_padded, CryptoAES.block_size)
            
            return {
                'data': decrypted_data,
                'key': key,
                'algorithm': 'AES'
            }
    
    def _fernet_operations(self, operation, data, key):
        """Fernet encryption/decryption operations"""
        if operation == 'encrypt':
            # Generate or use provided key
            if not key or key == 'auto':
                fernet_key = Fernet.generate_key()
                key_str = base64.urlsafe_b64encode(fernet_key).decode('utf-8')
            else:
                if isinstance(key, str):
                    # Try to use the key as-is, or derive it
                    try:
                        fernet_key = base64.urlsafe_b64decode(key.encode('utf-8'))
                    except:
                        # Derive key from string
                        key_hash = hashlib.sha256(key.encode('utf-8')).digest()
                        fernet_key = base64.urlsafe_b64encode(key_hash)
                else:
                    fernet_key = key
                key_str = key
            
            f = Fernet(fernet_key)
            encrypted_data = f.encrypt(data)
            
            return {
                'data': encrypted_data,
                'key': key_str,
                'algorithm': 'Fernet'
            }
        
        elif operation == 'decrypt':
            if isinstance(key, str):
                try:
                    fernet_key = base64.urlsafe_b64decode(key.encode('utf-8'))
                except:
                    # Derive key from string
                    key_hash = hashlib.sha256(key.encode('utf-8')).digest()
                    fernet_key = base64.urlsafe_b64encode(key_hash)
            else:
                fernet_key = key
            
            f = Fernet(fernet_key)
            decrypted_data = f.decrypt(data)
            
            return {
                'data': decrypted_data,
                'key': key,
                'algorithm': 'Fernet'
            }
    
    def _rsa_operations(self, operation, data, key):
        """RSA encryption/decryption operations"""
        if operation == 'encrypt':
            # Generate RSA key pair for encryption
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            public_key = private_key.public_key()
            
            # For large data, use hybrid encryption (RSA + AES)
            if len(data) > 190:  # RSA 2048 can encrypt up to ~190 bytes
                # Generate AES key
                aes_key = get_random_bytes(32)
                
                # Encrypt data with AES
                aes_result = self._aes_operations('encrypt', data, aes_key)
                
                # Encrypt AES key with RSA
                encrypted_aes_key = public_key.encrypt(
                    aes_key,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Combine encrypted AES key + encrypted data
                result_data = encrypted_aes_key + aes_result['data']
                
                # Serialize private key for decryption
                private_key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                return {
                    'data': result_data,
                    'key': base64.b64encode(private_key_pem).decode('utf-8'),
                    'algorithm': 'RSA'
                }
            else:
                # Direct RSA encryption for small data
                encrypted_data = public_key.encrypt(
                    data,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                private_key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                return {
                    'data': encrypted_data,
                    'key': base64.b64encode(private_key_pem).decode('utf-8'),
                    'algorithm': 'RSA'
                }
        
        elif operation == 'decrypt':
            # Load private key
            try:
                private_key_pem = base64.b64decode(key.encode('utf-8'))
                private_key = serialization.load_pem_private_key(
                    private_key_pem,
                    password=None,
                )
            except:
                raise ValueError("Invalid RSA private key")
            
            # Check if this is hybrid encryption
            if len(data) > 256:  # Likely hybrid encryption
                # Extract encrypted AES key (first 256 bytes for RSA 2048)
                encrypted_aes_key = data[:256]
                encrypted_data = data[256:]
                
                # Decrypt AES key with RSA
                aes_key = private_key.decrypt(
                    encrypted_aes_key,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Decrypt data with AES
                decrypted_data = self._aes_operations('decrypt', encrypted_data, aes_key)['data']
            else:
                # Direct RSA decryption
                decrypted_data = private_key.decrypt(
                    data,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            
            return {
                'data': decrypted_data,
                'key': key,
                'algorithm': 'RSA'
            }
    
    def generate_key(self, algorithm):
        """Generate a key for the specified algorithm"""
        if algorithm == 'AES':
            return secrets.token_urlsafe(32)
        elif algorithm == 'Fernet':
            return base64.urlsafe_b64encode(Fernet.generate_key()).decode('utf-8')
        elif algorithm == 'RSA':
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            return base64.b64encode(private_key_pem).decode('utf-8')
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def get_algorithm_info(self, algorithm):
        """Get information about the algorithm"""
        info = {
            'AES': {
                'name': 'Advanced Encryption Standard',
                'type': 'Symmetric',
                'key_size': '256-bit',
                'description': 'Fast and secure symmetric encryption. Best for general-purpose encryption.',
                'pros': ['Fast encryption/decryption', 'Industry standard', 'Suitable for large files'],
                'cons': ['Requires secure key sharing', 'Same key for encryption and decryption']
            },
            'Fernet': {
                'name': 'Fernet Symmetric Encryption',
                'type': 'Symmetric',
                'key_size': '256-bit',
                'description': 'High-level symmetric encryption with built-in authentication.',
                'pros': ['Built-in authentication', 'Easy to use', 'Secure by design'],
                'cons': ['Requires secure key sharing', 'Python-specific implementation']
            },
            'RSA': {
                'name': 'RSA Asymmetric Encryption',
                'type': 'Asymmetric',
                'key_size': '2048-bit',
                'description': 'Public-key cryptography. Uses different keys for encryption and decryption.',
                'pros': ['No need to share secret keys', 'Digital signatures possible', 'Key exchange'],
                'cons': ['Slower than symmetric encryption', 'Limited message size without hybrid approach']
            }
        }
        return info.get(algorithm, {'name': 'Unknown', 'description': 'Algorithm not supported'})
