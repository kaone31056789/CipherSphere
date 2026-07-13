"""Authenticated encryption services used by CipherSphere.

Ciphertexts use a small binary envelope so corrupt data, wrong algorithms, and
future format versions fail explicitly.  All cryptographic primitives come
from ``cryptography``; no unauthenticated cipher modes are used.
"""

from __future__ import annotations

import base64
import hmac
import json
import secrets
import struct
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


_MAGIC = b"CSPH"
_VERSION = 1
_PREFIX = struct.Struct(">4sBB")
_ALGORITHM_IDS = {"AES": 1, "Fernet": 2, "RSA": 3}
_ID_TO_ALGORITHM = {value: key for key, value in _ALGORITHM_IDS.items()}

_SALT_SIZE = 16
_NONCE_SIZE = 12
_AES_KEY_SIZE = 32
_PBKDF2_ITERATIONS = 600_000
_GCM_TAG_SIZE = 16

_FERNET_DIRECT_KEY = 0
_FERNET_PASSWORD = 1

_METADATA_MAGIC = b"CSMD"
_METADATA_VERSION = 1
_METADATA_HEADER = struct.Struct(">4sBI")

_DECRYPTION_FAILED = "Decryption failed: wrong key or corrupted data"


class EncryptionManager:
    """Encrypt text, files, and raw bytes with authenticated algorithms."""

    def __init__(self) -> None:
        self.algorithms = {
            "AES": self._aes_operations,
            "Fernet": self._fernet_operations,
            "RSA": self._rsa_operations,
        }

    def encrypt_text(self, text: str, key: Any, algorithm: str) -> dict[str, Any]:
        """Encrypt UTF-8 text and return the ciphertext plus its usable key."""
        if not isinstance(text, str):
            raise TypeError("text must be a string")

        result = self._operate("encrypt", text.encode("utf-8"), key, algorithm)
        result["encoded_data"] = base64.b64encode(result["data"]).decode("ascii")
        result["success"] = True
        return result

    def decrypt_text(
        self, encrypted_text: str | bytes | bytearray | memoryview, key: Any, algorithm: str
    ) -> dict[str, Any]:
        """Decrypt ciphertext bytes or their base64 text representation."""
        encrypted_data = self._decode_text_ciphertext(encrypted_text)
        result = self._operate("decrypt", encrypted_data, key, algorithm)
        try:
            result["data"] = result["data"].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Decrypted payload is not valid UTF-8 text") from exc
        result["success"] = True
        return result

    def encrypt_data(
        self, data: bytes | bytearray | memoryview, key: Any, algorithm: str
    ) -> bytes:
        """Encrypt arbitrary bytes and return a versioned binary envelope."""
        return self._operate("encrypt", self._as_bytes(data), key, algorithm)["data"]

    def decrypt_data(
        self, encrypted_data: bytes | bytearray | memoryview, key: Any, algorithm: str
    ) -> bytes:
        """Decrypt a binary envelope to arbitrary bytes."""
        return self._operate("decrypt", self._as_bytes(encrypted_data), key, algorithm)["data"]

    def decrypt_data_with_metadata(
        self, encrypted_data: bytes | bytearray | memoryview, key: Any, algorithm: str
    ) -> dict[str, Any]:
        """Decrypt bytes and separate authenticated file metadata when present."""
        plaintext = self.decrypt_data(encrypted_data, key, algorithm)
        metadata, data = self._unpack_metadata(plaintext)
        return {
            "data": data,
            "metadata": metadata,
            "has_metadata": metadata is not None,
        }

    def generate_key(self, algorithm: str) -> str:
        """Generate a copy-and-paste-safe key for an algorithm."""
        normalized = self._normalize_algorithm(algorithm)
        if normalized == "AES":
            return secrets.token_urlsafe(_AES_KEY_SIZE)
        if normalized == "Fernet":
            return Fernet.generate_key().decode("ascii")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return self._serialize_private_key(private_key)

    def _operate(
        self,
        operation: str,
        data: bytes,
        key: Any,
        algorithm: str,
    ) -> dict[str, Any]:
        normalized = self._normalize_algorithm(algorithm)
        if operation not in {"encrypt", "decrypt"}:
            raise ValueError(f"Unsupported operation: {operation}")
        return self.algorithms[normalized](operation, data, key)

    def _aes_operations(
        self, operation: str, data: bytes, key: Any
    ) -> dict[str, Any]:
        if operation == "encrypt":
            actual_key = self._symmetric_encryption_key(key, "AES")
            salt = secrets.token_bytes(_SALT_SIZE)
            nonce = secrets.token_bytes(_NONCE_SIZE)
            prefix = self._prefix("AES")
            associated_data = prefix + salt + nonce
            derived_key = self._derive_password(actual_key, salt)
            ciphertext = AESGCM(derived_key).encrypt(nonce, data, associated_data)
            return {
                "data": associated_data + ciphertext,
                "key": actual_key,
                "algorithm": "AES",
            }

        envelope = self._validated_envelope(data, "AES")
        minimum = _PREFIX.size + _SALT_SIZE + _NONCE_SIZE + _GCM_TAG_SIZE
        if len(envelope) < minimum:
            raise ValueError("Invalid AES envelope")
        offset = _PREFIX.size
        salt = envelope[offset : offset + _SALT_SIZE]
        nonce = envelope[offset + _SALT_SIZE : offset + _SALT_SIZE + _NONCE_SIZE]
        ciphertext_offset = offset + _SALT_SIZE + _NONCE_SIZE
        associated_data = envelope[:ciphertext_offset]
        try:
            plaintext = AESGCM(self._derive_password(key, salt)).decrypt(
                nonce, envelope[ciphertext_offset:], associated_data
            )
        except (InvalidTag, TypeError, ValueError) as exc:
            raise ValueError(_DECRYPTION_FAILED) from exc
        return {"data": plaintext, "key": key, "algorithm": "AES"}

    def _fernet_operations(
        self, operation: str, data: bytes, key: Any
    ) -> dict[str, Any]:
        if operation == "encrypt":
            actual_key = self._symmetric_encryption_key(key, "Fernet")
            direct_key = self._valid_fernet_key(actual_key)
            prefix = self._prefix("Fernet")
            if direct_key is not None:
                header = prefix + bytes([_FERNET_DIRECT_KEY])
                fernet_key = direct_key
            else:
                salt = secrets.token_bytes(_SALT_SIZE)
                header = prefix + bytes([_FERNET_PASSWORD]) + salt
                fernet_key = base64.urlsafe_b64encode(
                    self._derive_password(actual_key, salt)
                )
            token = Fernet(fernet_key).encrypt(header + data)
            return {
                "data": header + token,
                "key": actual_key,
                "algorithm": "Fernet",
            }

        envelope = self._validated_envelope(data, "Fernet")
        if len(envelope) <= _PREFIX.size:
            raise ValueError("Invalid Fernet envelope")
        mode = envelope[_PREFIX.size]
        if mode == _FERNET_DIRECT_KEY:
            header_end = _PREFIX.size + 1
            fernet_key = self._valid_fernet_key(key)
            if fernet_key is None:
                raise ValueError(_DECRYPTION_FAILED)
        elif mode == _FERNET_PASSWORD:
            header_end = _PREFIX.size + 1 + _SALT_SIZE
            if len(envelope) <= header_end:
                raise ValueError("Invalid Fernet envelope")
            salt = envelope[_PREFIX.size + 1 : header_end]
            fernet_key = base64.urlsafe_b64encode(self._derive_password(key, salt))
        else:
            raise ValueError("Invalid Fernet envelope mode")

        header = envelope[:header_end]
        try:
            plaintext = Fernet(fernet_key).decrypt(envelope[header_end:])
        except (InvalidToken, TypeError, ValueError) as exc:
            raise ValueError(_DECRYPTION_FAILED) from exc
        if not hmac.compare_digest(plaintext[: len(header)], header):
            raise ValueError(_DECRYPTION_FAILED)
        return {"data": plaintext[len(header) :], "key": key, "algorithm": "Fernet"}

    def _rsa_operations(
        self, operation: str, data: bytes, key: Any
    ) -> dict[str, Any]:
        if operation == "encrypt":
            public_key, returned_key = self._rsa_encryption_key(key)
            content_key = AESGCM.generate_key(bit_length=256)
            wrapped_key = public_key.encrypt(
                content_key,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            if len(wrapped_key) > 65_535:
                raise ValueError("RSA key is too large for the envelope")
            nonce = secrets.token_bytes(_NONCE_SIZE)
            prefix = self._prefix("RSA")
            header = prefix + struct.pack(">H", len(wrapped_key)) + wrapped_key + nonce
            ciphertext = AESGCM(content_key).encrypt(nonce, data, header)
            return {
                "data": header + ciphertext,
                "key": returned_key,
                "algorithm": "RSA",
            }

        envelope = self._validated_envelope(data, "RSA")
        minimum = _PREFIX.size + 2 + _NONCE_SIZE + _GCM_TAG_SIZE
        if len(envelope) < minimum:
            raise ValueError("Invalid RSA envelope")
        wrapped_size = struct.unpack(">H", envelope[_PREFIX.size : _PREFIX.size + 2])[0]
        wrapped_start = _PREFIX.size + 2
        wrapped_end = wrapped_start + wrapped_size
        nonce_end = wrapped_end + _NONCE_SIZE
        if wrapped_size == 0 or len(envelope) < nonce_end + _GCM_TAG_SIZE:
            raise ValueError("Invalid RSA envelope")

        private_key = self._load_rsa_private_key(key)
        wrapped_key = envelope[wrapped_start:wrapped_end]
        nonce = envelope[wrapped_end:nonce_end]
        header = envelope[:nonce_end]
        try:
            content_key = private_key.decrypt(
                wrapped_key,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            plaintext = AESGCM(content_key).decrypt(nonce, envelope[nonce_end:], header)
        except (InvalidTag, TypeError, ValueError) as exc:
            raise ValueError(_DECRYPTION_FAILED) from exc
        return {"data": plaintext, "key": key, "algorithm": "RSA"}

    @staticmethod
    def _normalize_algorithm(algorithm: str) -> str:
        if not isinstance(algorithm, str):
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        normalized = {"aes": "AES", "fernet": "Fernet", "rsa": "RSA"}.get(
            algorithm.strip().lower()
        )
        if normalized is None:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        return normalized

    @staticmethod
    def _as_bytes(data: bytes | bytearray | memoryview) -> bytes:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        return bytes(data)

    @staticmethod
    def _key_material(key: Any) -> bytes:
        if isinstance(key, str):
            return key.encode("utf-8")
        if isinstance(key, (bytes, bytearray, memoryview)):
            return bytes(key)
        raise ValueError("Key must be text or bytes")

    def _symmetric_encryption_key(self, key: Any, algorithm: str) -> Any:
        if key is None or (isinstance(key, str) and key.strip().lower() in {"", "auto"}):
            return self.generate_key(algorithm)
        self._key_material(key)
        return key

    def _derive_password(self, key: Any, salt: bytes) -> bytes:
        material = self._key_material(key)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=_AES_KEY_SIZE,
            salt=salt,
            iterations=_PBKDF2_ITERATIONS,
        )
        return kdf.derive(material)

    def _valid_fernet_key(self, key: Any) -> bytes | None:
        try:
            material = self._key_material(key)
            Fernet(material)
        except (TypeError, ValueError):
            return None
        return material

    @staticmethod
    def _prefix(algorithm: str) -> bytes:
        return _PREFIX.pack(_MAGIC, _VERSION, _ALGORITHM_IDS[algorithm])

    def _validated_envelope(self, data: bytes, expected_algorithm: str) -> bytes:
        envelope = self._as_bytes(data)
        if len(envelope) < _PREFIX.size:
            raise ValueError("Invalid CipherSphere envelope")
        magic, version, algorithm_id = _PREFIX.unpack_from(envelope)
        if magic != _MAGIC:
            raise ValueError("Invalid CipherSphere envelope")
        if version != _VERSION:
            raise ValueError(f"Unsupported CipherSphere envelope version: {version}")
        actual_algorithm = _ID_TO_ALGORITHM.get(algorithm_id)
        if actual_algorithm is None:
            raise ValueError("Invalid CipherSphere envelope algorithm")
        if actual_algorithm != expected_algorithm:
            raise ValueError(
                f"Envelope uses {actual_algorithm}, not {expected_algorithm}"
            )
        return envelope

    def _decode_text_ciphertext(
        self, encrypted_text: str | bytes | bytearray | memoryview
    ) -> bytes:
        if isinstance(encrypted_text, str):
            encoded = encrypted_text.strip().encode("ascii")
            try:
                decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
            except (UnicodeEncodeError, ValueError) as exc:
                raise ValueError("Encrypted text must be a base64 CipherSphere envelope") from exc
            return self._validated_envelope_for_any_algorithm(decoded)

        data = self._as_bytes(encrypted_text)
        if data.startswith(_MAGIC):
            return data
        try:
            decoded = base64.b64decode(data, altchars=b"-_", validate=True)
        except ValueError as exc:
            raise ValueError("Invalid encrypted text") from exc
        return self._validated_envelope_for_any_algorithm(decoded)

    def _validated_envelope_for_any_algorithm(self, data: bytes) -> bytes:
        if len(data) < _PREFIX.size:
            raise ValueError("Invalid CipherSphere envelope")
        magic, version, algorithm_id = _PREFIX.unpack_from(data)
        if magic != _MAGIC or version != _VERSION or algorithm_id not in _ID_TO_ALGORITHM:
            raise ValueError("Invalid CipherSphere envelope")
        return data

    @staticmethod
    def _unpack_metadata(data: bytes) -> tuple[dict[str, Any] | None, bytes]:
        if not data.startswith(_METADATA_MAGIC):
            return None, data
        if len(data) < _METADATA_HEADER.size:
            raise ValueError("Invalid authenticated file metadata")
        magic, version, metadata_size = _METADATA_HEADER.unpack_from(data)
        if magic != _METADATA_MAGIC or version != _METADATA_VERSION:
            raise ValueError("Unsupported authenticated file metadata version")
        metadata_end = _METADATA_HEADER.size + metadata_size
        if metadata_size == 0 or metadata_end > len(data):
            raise ValueError("Invalid authenticated file metadata")
        try:
            metadata = json.loads(data[_METADATA_HEADER.size : metadata_end].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid authenticated file metadata") from exc
        payload = data[metadata_end:]
        if not isinstance(metadata, dict) or not isinstance(
            metadata.get("original_filename"), str
        ):
            raise ValueError("Invalid authenticated file metadata")
        if metadata.get("file_size") != len(payload):
            raise ValueError("Authenticated file size metadata does not match payload")
        return metadata, payload

    def _rsa_encryption_key(
        self, key: Any
    ) -> tuple[rsa.RSAPublicKey, Any]:
        if isinstance(key, rsa.RSAPrivateKey):
            return key.public_key(), key
        if isinstance(key, rsa.RSAPublicKey):
            return key, key

        if key is not None and not (
            isinstance(key, str)
            and key.strip().lower() in {"", "auto", "rsa_auto_generated"}
        ):
            loaded = self._load_rsa_key(key, required=False)
            if isinstance(loaded, rsa.RSAPrivateKey):
                return loaded.public_key(), key
            if isinstance(loaded, rsa.RSAPublicKey):
                return loaded, key

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return private_key.public_key(), self._serialize_private_key(private_key)

    def _load_rsa_private_key(self, key: Any) -> rsa.RSAPrivateKey:
        if isinstance(key, rsa.RSAPrivateKey):
            return key
        loaded = self._load_rsa_key(key, required=True)
        if not isinstance(loaded, rsa.RSAPrivateKey):
            raise ValueError("RSA decryption requires a private key")
        return loaded

    def _load_rsa_key(
        self, key: Any, *, required: bool
    ) -> rsa.RSAPrivateKey | rsa.RSAPublicKey | None:
        try:
            raw = self._key_material(key).strip()
        except ValueError:
            if required:
                raise ValueError("Invalid RSA key") from None
            return None

        candidates = [raw]
        try:
            decoded = base64.b64decode(raw, validate=True)
        except ValueError:
            decoded = b""
        if decoded:
            candidates.insert(0, decoded)

        loaders = (
            serialization.load_pem_private_key,
            serialization.load_pem_public_key,
            serialization.load_der_private_key,
            serialization.load_der_public_key,
        )
        for candidate in candidates:
            for loader in loaders:
                try:
                    if loader in {
                        serialization.load_pem_private_key,
                        serialization.load_der_private_key,
                    }:
                        loaded = loader(candidate, password=None)
                    else:
                        loaded = loader(candidate)
                except (TypeError, ValueError):
                    continue
                if isinstance(loaded, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
                    return loaded
        if required:
            raise ValueError("Invalid RSA key")
        return None

    @staticmethod
    def _serialize_private_key(private_key: rsa.RSAPrivateKey) -> str:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return base64.b64encode(pem).decode("ascii")
