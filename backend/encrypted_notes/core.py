"""
Core business logic layer for the encrypted notes manager.

This module provides high-level operations that combine:
- Encryption/decryption
- Storage operations
- Business rules and validation.

This layer is used by both CLI and API interfaces (FastAPI).
"""

import hashlib
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from .crypto import decrypt_text, derive_key_from_password, encrypt_text, generate_salt
from .errors import (
    DecryptionError,
    EncryptionError,
    InvalidPasswordError,
    KeyDerivationError,
    NoteNotFoundError,
    NoteOperationsError,
)
from .models import NoteCreate, NoteDetail, NoteMeta, NoteStatus
from .storage.file_storage import FileStorage
from .storage.storage import Storage


class NoteSession:
    """
    Session manager for working with encrypted notes.

    Manages the encryption key derived from password and provides
    high-level operations for notes.
    """

    def __init__(
        self,
        storage: Storage[NoteMeta],
        password: str,
        salt: Optional[bytes] = None,
        iterations: int = 100_000,
    ):
        """
        Initialize a note session.

        Args:
            storage: Storage backend to use
            password: Master password
            salt: Optional salt (if None, generates new one)
            iterations: PBKDF2 iterations

        Raises:
            KeyDerivationError: If key derivation fails
        """

        self.storage = storage
        self.salt = salt or generate_salt()
        self.iterations = iterations

        try:
            self.key = derive_key_from_password(password, self.salt, iterations)
        except Exception as e:
            raise KeyDerivationError(f"Failed to derive key: {e}") from e

    def get_salt_hex(self) -> str:
        """
        Get salt as hex string for storage.

        Returns:
            Hex string of the salt
        """

        return self.salt.hex()

    @classmethod
    def from_salt_hex(
        cls,
        storage: Storage[NoteMeta],
        password: str,
        salt_hex: str,
        iterations: int = 100_000,
    ) -> "NoteSession":
        """
        Create session from hex-encoded salt.

        Args:
            storage: Storage backend
            password: Master password
            salt_hex: Hex-encoded salt
            iterations: PBKDF2 iteraions
        """

        salt = bytes.fromhex(salt_hex)
        return cls(storage, password, salt, iterations)


def create_note(session: NoteSession, note_data: NoteCreate) -> NoteDetail:
    """
    Create a new encrypted note.

    Args:
        session: Active note session with encryption key
        note_data: Note creation data

    Returns:
        Created note with metadata

    Raises:
        EncryptionError: If encryption fails
        NoteOperationError: If storage operation fails
    """

    try:
        note_id = str(uuid4())
        filename = f"{note_id}.bin"

        encrypted_content = encrypt_text(session.key, note_data.content)

        content_hash = hashlib.sha256(encrypted_content).hexdigest()

        now = datetime.now(timezone.utc)
        note_meta = NoteMeta(
            id=note_id,
            title=note_data.title,
            filename=filename,
            created_at=now,
            updated_at=now,
            tags=note_data.tags,
            status=NoteStatus.ACTIVE,
            size_bytes=len(encrypted_content),
            content_hash=content_hash,
            favorite=note_data.favorite,
            color=note_data.color,
        )

        saved_meta = session.storage.add(note_meta)

        if isinstance(session.storage, FileStorage):
            session.storage.save_encrypted_content(note_id, encrypted_content)

        return NoteDetail(**saved_meta.model_dump(), content=note_data.content)
    except EncryptionError:
        raise
    except Exception as e:
        raise NoteOperationsError(f"Failed to create note: {e}") from e


def read_note(session: NoteSession, note_id: str) -> NoteDetail:
    """
    Read and decrypt a note.

    Args:
        session: Active note session with encryption key
        note_id: ID of note to read

    Returns:
        Decrypted note with full content

    Raises:
        NoteNotfoundError: If note doesn't exist
        DecryptionError: If decryption fails (wrong password)
        InvalidPasswordError: If password is incorrect
    """

    note_meta = session.storage.get(note_id)
    if not note_meta:
        raise NoteNotFoundError(f"Note with id {note_id} not found")

    try:
        if isinstance(session.storage, FileStorage):
            encrypted_content = session.storage.load_encrypted_content(note_id)
        else:
            raise NoteOperationsError("Storage type doesn't support content loading")

        try:
            decrypted_content = decrypt_text(session.key, encrypted_content)
        except DecryptionError:
            raise InvalidPasswordError("Incorrect password or corrupted data")

        if note_meta.content_hash:
            actual_hash = hashlib.sha256(encrypted_content).hexdigest()
            if actual_hash != note_meta.content_hash:
                raise NoteOperationsError("Content integrity check failed")

        return NoteDetail(**note_meta.model_dump(), content=decrypted_content)
    except (DecryptionError, InvalidPasswordError):
        raise
    except Exception as e:
        raise NoteOperationsError(f"Failed to read note: {e}") from e
