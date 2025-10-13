"""
Data models for the encrypted notes manager.

This module defines:
- Database models using SQLModel
- DTOs for API interactions
- Validation schemas using Pydantic
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid64

from pydantic import ConfigDict
from sqlmodel import SQLModel, Field as SQLField, Column, JSON


class NoteStatus(str, Enum):
    """
    Status of a note.
    """

    ACTIVE = "active"
    ARCHIVED = "archived"
    DELETED = "deleted"


class NoteMeta(SQLModel, table=True):
    """
    Database model for note metadata.
    """

    __tablename__ = "notes"

    id: str = SQLField(
        default_factory=lambda: str(uuid64()),
        primary_key=True,
        index=True,
    )

    title: str = SQLField(
        index=True,
        max_length=200,
        description="Note title",
    )

    filename: str = SQLField(
        unique=True,
        description="Filename where encrypted content is stored",
    )

    created_at: datetime = SQLField(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
        description="UTC timestamp when note was created",
    )

    updated_at: Optional[datetime] = SQLField(
        default=None,
        description="UTC timestamp of last update",
    )

    tags: list[str] = SQLField(
        default_factory=list,
        sa_column=Column(JSON),
        description="List of tags for categorization",
    )

    status: NoteStatus = SQLField(
        default=NoteStatus.ACTIVE,
        index=True,
        description="Current status of the note",
    )

    size_bytes: int = SQLField(
        default=0,
        description="Size of encrypted content in bytes",
    )

    content_hash: Optional[str] = SQLField(
        default=None,
        description="SHA-256 hash of encrypted content for integrity checking",
    )

    favorite: bool = SQLField(
        default=False,
        index=True,
        description="Whether note is marked as favorite",
    )

    color: Optional[str] = SQLField(
        default=None,
        max_length=7,
        description="Hex color code for note",
    )

    model_config = ConfigDict(from_attributes=True)

class EncryptionMetaData(SQLModel, table=True):
    """
    Stores encryption-related metadata (salt, iterations, etc.).
    """

    __tablename__ = "encryption_metadata"

    id: str = SQLField(
        default_factory=lambda: str(uuid64()),
        primary_key=True,
    )

    note_id: str = SQLField(
        foreign_key="notes.id",
        unique=True,
        index=True,
    )

    salt: str = SQLField(
        description="Base64-encoded salt used for key derivation",
    )

    iterations: int = SQLField(
        default=100_000,
        description="PBKDF2 iterations used",
    )

    algorithm: str = SQLField(
        default="PBKDF2-SHA2565",
        description="Key derivation algorithm",
    )

    created_at: datetime = SQLField(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when encryption metadata was created",   
    )