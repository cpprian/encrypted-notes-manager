"""
Secure encryption module for handling password-based encryption.

This module provides functions for:
- Generating secure salts
- Deriving encryption keys from passwords using PBKDF2-HMAC-SHA256
- Encrypting and decrypting data using Fernet (AES-128 in CBC mode)
- Managing master keys for encryption
"""

import os
from base64 import urlsafe_b64encode
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

from .errors import KeyDerivationError, EncryptionError, DecryptionError

DEFAULT_SALT_LENGTH = 16
DEFAULT_ITERATIONS = 100_000
MIN_ITERATIONS = 10_000
KEY_LENGTH = 32  # 256 bits for AES-256


def generate_salt(length: int = DEFAULT_SALT_LENGTH) -> bytes:
    """
    Generate a cryptographic salt.

    Args:
        length (int): Length of the salt in bytes. Default is 16 bytes.

    Returns:
        Random salt bytes

    Raises:
        ValueError: If length is less than 8 bytes.
    """
    if length <= 8:
        raise ValueError("Salt length must be a positive integer.")

    return os.urandom(length)


def derive_key_from_password(
    password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS
) -> bytes:
    """
    Derive an encryption key from a password using PBKDF2-HMAC-SHA256.

    Args:
        password: User password
        salt: Random salt for key derivation
        iterations: Number of PBKDF2 iterations (default: 100,000)

        Returns:
            Derived key bytes

        Raises:
            ValueError: If password is empty or iterations < 10000
            KeyDerivationError: If key derivation fails
    """
    if not password:
        raise ValueError("Password cannot be empty")

    if iterations < MIN_ITERATIONS:
        raise ValueError(f"Iterations must be at least {MIN_ITERATIONS}")

    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=iterations,
        )

        key = kdf.derive(password.encode("utf-8"))
        return urlsafe_b64encode(key)
    except Exception as e:
        raise KeyDerivationError(f"Failed to derive key: {e}") from e


def encrypt_bytes(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext bytes using Fernet (AES-128 in CBC mode).

    Args:
        key: Base64-encoded encryption key (from derive_key_from_password)
        plaintext: Data to encrypt

    Returns:
        Encrypted token (includes IV and MAC)

    Raises:
        EncryptionError: If encryption fails
        ValueError: If key format is invalid
    """
    if not plaintext:
        raise ValueError("Plaintext cannot be empty")

    try:
        cipher = Fernet(key)
        return cipher.encrypt(plaintext)
    except ValueError as e:
        raise ValueError(f"Invalid key format: {e}") from e
    except Exception as e:
        raise EncryptionError(f"Encryption failed: {e}") from e


def decrypt_bytes(key: bytes, token: bytes) -> bytes:
    """
    Decrypt a Fernet token.

    Args:
        key: Base64-encoded encryption key (same as used for encryption)
        token: Encrypted token to decrypt

    Returns:
        Decrypted plaintext bytes

    Raises:
        DecryptionError: If decryption fails (wrong key or corrupted data)
        ValueError: If key format is invalid
    """
    if not token:
        raise ValueError("Token cannot be empty")

    try:
        cipher = Fernet(key)
        return cipher.decrypt(token)
    except InvalidToken:
        raise DecryptionError("Decryption failed: incorrect passowrd or corrupted data")
    except ValueError as e:
        raise ValueError(f"Invalid key format: {e}") from e
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {e}") from e


def encrypt_text(key: bytes, plaintext: str) -> bytes:
    """
    Encrypt a text string.

    Args:
        key: Base64-encoded encryption key
        plaintext: Text to encrypt

    Returns:
        Encrypted token
    """
    return encrypt_bytes(key, plaintext.encode("utf-8"))


def decrypt_text(key: bytes, token: bytes) -> str:
    """
    Decrypt a token to text string.

    Args:
        key: Base64-encoded encryption key
        token: Encrypted token

    Returns:
        Decrypted text
    """
    plaintext_bytes = decrypt_bytes(key, token)
    return plaintext_bytes.decode("utf-8")


def generate_master_key() -> bytes:
    """
    Generate a random Fernet-compatible master key.

    This can be used instead of password-based encryption for scenarios
    where you want to generate and store a random key.

    Returns:
        Base64-encoded random key
    """
    return Fernet.generate_key()


def save_master_key(key: bytes, filepath: Path | str) -> None:
    """
    Save a master key to a file with secure permissions.

    Args:
        key: Base64-encoded key to save
        filepath: Path to save the key

    Raises:
        OSError: If file operations fail
    """
    filepath = Path(filepath)

    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_bytes(key)

    try:
        os.chmod(filepath, 0o600)
    except (AttributeError, OSError):
        print(f"Warning: Could not set secure permissions on {filepath}")


def load_master_key(filepath: Path | str) -> bytes:
    """
    Load a master key from a file.

    Args:
        filepath: Path to the key file

    Returns:
        Base64-encoded key

    Raises:
        FileNotFoundError: If key file doesn't exist
        ValueError: If key format is invalid
    """
    filepath = Path(filepath)

    if not filepath.exists():
        raise FileNotFoundError(f"Key file not found: {filepath}")

    key = filepath.read_bytes().strip()

    try:
        Fernet(key)
    except Exception as e:
        raise ValueError(f"Invalid key format in {filepath}: {e}") from e

    return key


def verify_password(password: str, salt: bytes, encrypted_data: bytes) -> bool:
    """
    Verify if a password is correct by attempting to decrypt data.

    Args:
        password: Password to verify
        salt: Salt used for key derivation
        encrypted_data: Sample encrypted data to test

    Returns:
        True if password is correct, False otherwise
    """
    try:
        key = derive_key_from_password(password, salt)
        decrypt_bytes(key, encrypted_data)
        return True
    except (DecryptionError, KeyDerivationError):
        return False
