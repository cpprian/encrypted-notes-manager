"""
FileStorage implementation using JSON metadata + encrypted files
"""

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from encrypted_notes.json import EnumJSONDecoder, EnumJSONEncoder
from encrypted_notes.models import NoteFilter, NoteMeta

from .storage import Storage


class FileStorage(Storage[NoteMeta]):
    """
    File-based storage implementation.

    Structure:
    - {base_path}/metadata.json: All note metadata
    - {base_path}/data/{note_id}.bin: Encrypted note content
    - {base_path}/exports/: Exported notes
    """

    def __init__(self, base_path: Path | str = "storage"):
        """ "
        Initilize file storage.

        Args:
            base_path: Base directory for storage
        """
        self.base_path = Path(base_path)
        self.data_path = self.base_path / "data"
        self.export_path = self.base_path / "exports"
        self.metadata_file = self.base_path / "metadata.json"

        self.data_path.mkdir(parents=True, exist_ok=True)
        self.export_path.mkdir(parents=True, exist_ok=True)

        self._secure_directory(self.base_path)
        self._secure_directory(self.data_path)

        if not self.metadata_file.exists():
            self._save_metadata({})

        self._secure_file(self.metadata_file)

    @staticmethod
    def _secure_directory(path: Path) -> None:
        """
        Set secure permissions on directory (Unix only).
        """

        try:
            os.chmod(path, 0o700)
        except (AttributeError, OSError):
            pass  # Ignore on non-Unix systems

    @staticmethod
    def _secure_file(path: Path) -> None:
        """
        Set secure permissions on file (Unix only).
        """

        try:
            os.chmod(path, 0o600)
        except (AttributeError, OSError):
            pass  # Ignore on non-Unix systems

    def _load_metadata(self) -> dict[str, dict]:
        """
        Load metadata from JSON file.
        """

        with open(self.metadata_file, "r", encoding="utf-8") as f:
            return json.load(f, cls=EnumJSONDecoder)

    def _save_metadata(self, metadata: dict[str, dict]) -> None:
        """
        Save metadata to JSON file atomically.
        """

        temp_file = self.metadata_file.with_suffix(".tmp")

        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2, cls=EnumJSONEncoder)

        self._secure_file(temp_file)

        temp_file.replace(self.metadata_file)

    def _get_data_file(self, note_id: str) -> Path:
        """
        Get path to encrypted data file.
        """

        return self.data_path / f"{note_id}.bin"

    def add(self, item: NoteMeta) -> NoteMeta:
        """
        Add a new note.
        """

        metadata = self._load_metadata()

        if item.id in metadata:
            raise ValueError(f"Note with id {item.id} alread exists")

        metadata[item.id] = item.model_dump(mode="python")
        self._save_metadata(metadata)

        return item

    def get(self, id: str) -> Optional[NoteMeta]:
        """
        Retrieve a note by ID.
        """

        metadata = self._load_metadata()

        if id not in metadata:
            return None

        return NoteMeta(**metadata[id])

    def update(self, item: NoteMeta) -> NoteMeta:
        """
        Update an existign note.
        """

        metadata = self._load_metadata()

        if item.id not in metadata:
            raise ValueError(f"Note with id {item.id} not found")

        item.updated_at = datetime.now(timezone.utc)
        self._save_metadata(metadata)

        return item

    def delete(self, id: str) -> None:
        """
        Delete a note by ID.
        """

        metadata = self._load_metadata()

        if id not in metadata:
            raise ValueError(f"Note with id {id} not found")

        del metadata[id]
        self._save_metadata(metadata)

        data_file = self._get_data_file(id)
        if data_file.exists():
            data_file.unlink()

    def list(
        self, filter: Optional[NoteFilter] = None, skip: int = 0, limit: int = 100
    ) -> list[NoteMeta]:
        """
        List notes with filtering and pagination.
        """

        metadata = self._load_metadata()

        notes = [NoteMeta(**data) for data in metadata.values()]

        if filter:
            if filter.status:
                notes = [n for n in notes if n.status == filter.status]

            if filter.search:
                search_lower = filter.search.lower()
                notes = [n for n in notes if search_lower in n.title.lower()]

            if filter.tags:
                notes = [n for n in notes if all(tag in n.tags for tag in filter.tags)]

            if filter.favorite is not None:
                notes = [n for n in notes if n.favorite == filter.favorite]

            if filter.color:
                notes = [n for n in notes if n.color == filter.color]

            if filter.created_after:
                notes = [n for n in notes if n.created_at >= filter.created_after]

            if filter.created_before:
                notes = [n for n in notes if n.created_at <= filter.created_before]

            reverse = filter.sort_desc
            if filter.sort_by == "title":
                notes.sort(key=lambda n: n.title, reverse=reverse)
            elif filter.sort_by == "created_at":
                notes.sort(key=lambda n: n.created_at, reverse=reverse)
            else:
                notes.sort(key=lambda n: n.updated_at or n.created_at, reverse=reverse)
        else:
            notes.sort(key=lambda n: n.updated_at or n.created_at, reverse=True)

        return notes[skip : skip + limit]

    def count(self, filter: Optional[NoteFilter] = None) -> int:
        """
        Count notes matching filter criteria.
        """

        return len(self.list(filter=filter, skip=0, limit=999999))

    def save_encrypted_content(self, note_id: str, encrypted_data: bytes) -> None:
        """
        Save encrypted content to file.

        Args:
            note_id: Note ID
            encrypted_data: Encrypted content bytes
        """

        data_file = self._get_data_file(note_id)

        temp_file = data_file.with_suffix(".tmp")
        temp_file.write_bytes(encrypted_data)
        self._secure_file(temp_file)
        temp_file.replace(data_file)

        metadata = self._load_metadata()
        if note_id in metadata:
            metadata[note_id]["size_bytes"] = len(encrypted_data)
            metadata[note_id]["content_hash"] = hashlib.sha256(
                encrypted_data
            ).hexdigest()
            self._save_metadata(metadata)

    def load_encrypted_content(self, note_id: str) -> bytes:
        """
        Load encrypted content from file.

        Args:
            note_id: Note ID

        Returns:
            Encrypted content bytes

        Raises:
            FileNotFoundError: If content file doesn't exist
        """
        data_file = self._get_data_file(note_id)

        if not data_file.exists():
            raise FileNotFoundError(f"Content file not found for note {note_id}")

        return data_file.read_bytes()

    def export_note(self, note_id: str, output_path: Path | str) -> None:
        """
        Export a note (metadata + encrypted content) to a file.

        Args:
            note_id: Note ID to export
            output_path: Destination file path

        Raises:
            ValueError: If note doesn't exist
        """

        note = self.get(note_id)
        if not note:
            raise ValueError(f"Note {note_id} not found")

        output_path = Path(output_path)

        try:
            encrypted_content = self.load_encrypted_content(note_id)
        except FileNotFoundError:
            encrypted_content = b""

        export_data = {
            "version": "1.0",
            "metadata": note.model_dump(mode="python"),
            "content": encrypted_content.hex(),
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, default=str)

        self._secure_file(output_path)

    def import_note(self, import_path: Path | str, new_id: bool = True) -> NoteMeta:
        """
        Import a note from an exported file.

        Args:
            import_path: Path to exported note file
            new_id: If True, generate new ID; if False, keep original ID

        Returns:
            Imported NoteMeta object

        Raises:
            ValueError: If import file is invalid
        """

        import_path = Path(import_path)

        if not import_path.exists():
            raise FileNotFoundError(f"Import file not found: {import_path}")

        with open(import_path, "r", encoding="utf-8") as f:
            export_data = json.load(f, cls=EnumJSONDecoder)

        note = NoteMeta(**export_data["metadata"])

        if new_id:
            note.id = str(uuid4())
            note.filename = f"{note.id}.bin"
            note.created_at = datetime.now(timezone.utc)
            note.updated_at = None

        if self.get(note.id):
            raise ValueError(f"Note with id {note.id} already exists")

        encrypted_content = bytes.fromhex(export_data["content"])

        self.add(note)

        if encrypted_content:
            self.save_encrypted_content(note.id, encrypted_content)

        return note

    def backup(self, backup_path: Path | str) -> None:
        """
        Create a full backup of all notes.

        Args:
            backup_path: Path to backup directory
        """

        backup_path = Path(backup_path)
        backup_path.mkdir(parents=True, exists_ok=True)

        shutil.copy2(self.metadata_file, backup_path / "metadata.json")

        backup_data_path = backup_path / "data"
        backup_data_path.mkdir(exists_ok=True)

        for data_file in self.data_path.glob("*.bin"):
            shutil.copy2(data_file, backup_data_path / data_file.name)

        self._secure_directory(backup_path)
