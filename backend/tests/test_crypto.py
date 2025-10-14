import pytest

from encrypted_notes.crypto import (
    generate_salt,
    derive_key_from_password,
    encrypt_bytes,
    decrypt_bytes,
    encrypt_text,
    decrypt_text,
    generate_master_key,
    verify_password,
    DEFAULT_SALT_LENGTH,
)
from encrypted_notes.errors import DecryptionError

DEFAULT_PASSWORD = "securepassword"
WRONG_PASSWORD = "wrongpassword"
PLAINTEXT_BYTES = b"Sensitive data"
PLAINTEXT_TEXT = "Sensitive text"
INVALID_SALT_LENGTH = 4
INVALID_ITERATIONS = 5000


def test_generate_salt():
    salt = generate_salt()
    assert len(salt) == DEFAULT_SALT_LENGTH
    assert isinstance(salt, bytes)

    with pytest.raises(ValueError):
        generate_salt(INVALID_SALT_LENGTH)


def test_derive_key_from_password():
    salt = generate_salt()
    key = derive_key_from_password(DEFAULT_PASSWORD, salt)
    assert isinstance(key, bytes)

    with pytest.raises(ValueError):
        derive_key_from_password("", salt)

    with pytest.raises(ValueError):
        derive_key_from_password(DEFAULT_PASSWORD, salt, iterations=INVALID_ITERATIONS)


def test_encrypt_decrypt_bytes():
    salt = generate_salt()
    key = derive_key_from_password(DEFAULT_PASSWORD, salt)

    encrypted = encrypt_bytes(key, PLAINTEXT_BYTES)
    assert encrypted != PLAINTEXT_BYTES

    decrypted = decrypt_bytes(key, encrypted)
    assert decrypted == PLAINTEXT_BYTES

    with pytest.raises(DecryptionError):
        decrypt_bytes(generate_master_key(), encrypted)


def test_encrypt_decrypt_text():
    salt = generate_salt()
    key = derive_key_from_password(DEFAULT_PASSWORD, salt)

    encrypted = encrypt_text(key, PLAINTEXT_TEXT)
    assert isinstance(encrypted, bytes)

    decrypted = decrypt_text(key, encrypted)
    assert decrypted == PLAINTEXT_TEXT


def test_generate_master_key():
    key = generate_master_key()
    assert isinstance(key, bytes)
    assert len(key) > 0


def test_verify_password():
    salt = generate_salt()
    key = derive_key_from_password(DEFAULT_PASSWORD, salt)
    encrypted = encrypt_bytes(key, PLAINTEXT_BYTES)

    assert verify_password(DEFAULT_PASSWORD, salt, encrypted) is True
    assert verify_password(WRONG_PASSWORD, salt, encrypted) is False
