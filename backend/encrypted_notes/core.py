"""
Core business logic layer for the encrypted notes manager.

This module provides high-level operations that combine:
- Encryption/decryption
- Storage operations
- Business rules and validation.

This layer is used by both CLI and API interfaces (FastAPI).
"""

import hashlib
from pathlib import Path
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
from .models import (
    NoteCreate,
    NoteDetail,
    NoteMeta,
    NoteStatus,
    NoteUpdate,
    NoteRead,
    NoteFilter,
    NoteStatistics,
)
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


def update_note(
    session: NoteSession, note_id: str, update_data: NoteUpdate
) -> NoteDetail:
    """
    Update an existing note.

    Args:
        session: Active note session
        note_id: ID of note to update
        update_data: Update data

    Returns:
        Updated note

    Raises:
        NoteNotFoundError: If note doesn't exist
        NoteOperationError: If update fails
    """

    note_meta = session.storage.get(note_id)
    if not note_meta:
        raise NoteNotFoundError(f"Note with id {note_id} not found")

    try:
        if update_data.title is not None:
            note_meta.title = update_data.title

        if update_data.tags is not None:
            note_meta.tags = update_data.tags

        if update_data.color is not None:
            note_meta.color = update_data.color

        if update_data.favorite is not None:
            note_meta.favorite = update_data.favorite

        if update_data.status is not None:
            note_meta.status = update_data.status

        decrypted_content = None
        if update_data.content is not None:
            encrypted_content = encrypt_text(session.key, update_data.content)

            note_meta.content_hash = hashlib.sha256(encrypted_content).hexdigest()
            note_meta.size_bytes = len(encrypted_content)

            if isinstance(session.storage, FileStorage):
                session.storage.save_encrypted_content(note_id, encrypted_content)

            decrypted_content = update_data.content
        else:
            if isinstance(session.storage, FileStorage):
                encrypted_content = session.storage.load_encrypted_content(note_id)
                decrypted_content = decrypt_text(session.key, encrypted_content)

        note_meta.updated_at = datetime.now(timezone.utc)

        update_meta = session.storage.update(note_meta)

        return NoteDetail(**update_meta.model_dump(), content=decrypted_content)
    except Exception as e:
        raise NoteOperationsError(f"Failed to update note: {e}") from e


def delete_note(session: NoteSession, note_id: str, permament: bool = False) -> None:
    """
    Delete a note.

    Args:
        session: Active note session
        note_id: ID of note to delete
        permanent: If True, permanently delet; if False, mark as deleted

    Raises:
        NoteNofFoundError: If note doesn't exist
        NoteOperationError: If deleteion fails
    """

    note_meta = session.storage.get(note_id)
    if not note_meta:
        raise NoteNotFoundError(f"Note with id {note_id} not found")

    try:
        if permament:
            session.storage.delete(note_id)
        else:
            note_meta.status = NoteStatus.DELETED
            note_meta.updated_at = datetime.now(timezone.utc)
            session.storage.update(note_meta)
    except Exception as e:
        raise NoteOperationsError(f"Failed to delete note: {e}") from e


def restore_note(session: NoteSession, note_id: str) -> NoteRead:
    """
    Restore a soft-deleted note.

    Args:
        session: Active note session
        note_id: ID of note to restore

    Returns:
        Restored note metadata

    Raises:
        NoteNotFoundError: If note doesn't exist
    """

    note_meta = session.storage.get(note_id)
    if not note_meta:
        raise NoteNotFoundError(f"Note with id {note_id} not found")

    note_meta.status = NoteStatus.ACTIVE
    note_meta.updated_at = datetime.now(timezone.utc)
    updated = session.storage.update(note_meta)

    return NoteRead(**updated.model_dump())


def archived_note(session: NoteSession, note_id: str) -> NoteRead:
    """
    Archive a note.

    Args:
        session: Active note session
        note_id: ID of note to archive

    Returns:
        Archived note metadata
    """

    note_meta = session.storage.get(note_id)
    if not note_meta:
        raise NoteNotFoundError(f"Note with id {note_id} not found")

    note_meta.status = NoteStatus.ARCHIVED
    note_meta.updated_at = datetime.now(timezone.utc)
    updated = session.storage.update(note_meta)

    return NoteRead(**updated.model_dump)


def list_notes(
    session: NoteSession, filter: Optional[NoteFilter] = None
) -> list[NoteRead]:
    """
    List notes with optional filtering.

    Args:
        session: Active note session
        filter: Optional filter criteria

    Returns:
        List of note metadata (without decrypted content)
    """

    if filter:
        skip = (filter.page - 1) * filter.page_size
        notes = session.storage.list(filter=filter, skip=skip, limit=filter.page.size)
    else:
        notes = session.storage.list()

    return [NoteRead(**note.model_dump()) for note in notes]


def search_notes(
    session: NoteSession, query: str, search_content: bool = False
) -> list[NoteRead]:
    """
    Search notes by title (and optionaly content)

    Args:
        session: Active note session
        query: Search query
        search_content: If True, also search in decrypted content

    Returns:
        List of matching notes
    """

    filter = NoteFilter(search=query, status=NoteStatus.ACTIVE)
    results = session.storage.list(filter=filter)

    if search_content:
        all_notes = session.storage.list(
            filter=NoteFilter(status=NoteStatus.ACTIVE), limit=999999
        )

        query_lower = query.lower()
        content_matches = []

        for note in all_notes:
            try:
                detail = read_note(session, note.id())
                if query_lower in detail.content.lower():
                    if note.id not in [r.id for r in results]:
                        content_matches.append(note)
            except Exception:
                continue

            results.extend(content_matches)

    return [NoteRead(**note.model_dump()) for note in results]


def get_note_statistics(session: NoteSession) -> NoteStatistics:
    """
    Get statistics about notes.

    Args:
        session: Active note session

    Returns:
        Statistics object
    """

    all_notes = session.storage.list(limit=999999)

    active_count = sum(1 for n in all_notes if n.status == NoteStatus.ACTIVE)
    archived_count = sum(1 for n in all_notes if n.status == NoteStatus.ARCHIVED)
    deleted_count = sum(1 for n in all_notes if n.status == NoteStatus.DELETED)
    favorite_count = sum(1 for n in all_notes if n.favorite)
    total_size = sum(n.size_bytes for n in all_notes)

    tag_counts: dict[str, int] = {}
    for note in all_notes:
        for tag in note.tags:
            tag_counts[tag] = tag_counts.get(tag, 0) + 1

    most_used_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return NoteStatistics(
        total_notes=len(all_notes),
        active_notes=active_count,
        archived_notes=archived_count,
        deleted_notes=deleted_count,
        total_size_bytes=total_size,
        favorite_count=favorite_count,
        total_tags=len(tag_counts),
        most_used_tags=most_used_tags,
    )


def get_tags(session: NoteSession) -> list[str]:
    """
    Get all unique tags used in notes.

    Args:
        session: Active note session

    Returns:
        Sorted list of unique tags
    """

    all_notes = session.storage.list(limit=999999)
    tags = set()

    for note in all_notes:
        tags.update(note.tags)

    return sorted(tags)


def export_note_to_file(
    session: NoteSession, note_id: str, output_path: Path | str
) -> None:
    """
    Export a note to a file.

    Args:
        session: Active note session
        note_id: ID of note to export
        output_path: Destination file path

    Raises:
        NoteNotFoundError: If note doesn't exist
    """

    if not isinstance(session.storage, FileStorage):
        raise NoteOperationsError("Export only supported with FileStorage")

    if not session.storage.get(note_id):
        raise NoteNotFoundError(f"Note with id {note_id} not found")

    session.storage.export_note(note_id, output_path)


def import_note_from_file(
    session: NoteSession, import_path: Path | str, new_id: bool = True
) -> NoteDetail:
    """
    Import a note from a file.

    Args:
        session: Active note session
        import_path: Path to import file
        new_id: If True, generate new ID

    Returns:
        Imported note
    """

    if not isinstance(session.storage, FileStorage):
        raise NoteOperationsError("Import only supported with FileStorage")

    imported_meta = session.storage.import_note(import_path, new_id=new_id)

    return read_note(session, imported_meta.id)
