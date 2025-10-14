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
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlmodel import JSON, Column
from sqlmodel import Field as SQLField
from sqlmodel import SQLModel


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
        default_factory=lambda: str(uuid4()),
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
        default_factory=lambda: str(uuid4()),
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


class NoteCreate(BaseModel):
    """
    Schema for creating a new note.
    """

    title: str = Field(
        min_length=1,
        max_length=200,
        description="Note title",
    )

    content: str = Field(
        description="Note content (will be encrypted)",
    )

    tags: list[str] = Field(
        default=list,
        description="List of tags",
    )

    color: Optional[str] = Field(
        default=None, pattern=r"^#[0-9A-Fa-f]{6}$", description="Hex color code"
    )

    favorite: bool = Field(
        default=False,
        description="Mark note as favorite",
    )

    @field_validator("title")
    @classmethod
    def validate_title(cls, title: str) -> str:
        title = title.strip()
        if not title:
            raise ValueError("Title cannot be empty or whitespace only")
        return title

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "title": "My Secret Note",
                "content": "This is a secret message",
                "tags": ["personal", "important"],
                "color": "#FF5733",
                "favorite": False,
            }
        }
    )


class NoteUpdate(BaseModel):
    """
    Schema for updating an existing note.
    """

    title: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=200,
        description="Note title",
    )

    content: Optional[str] = Field(
        default=None,
        description="Note content (will be encrypted)",
    )

    tags: Optional[list[str]] = Field(
        default=None,
        description="List of tags",
    )

    color: Optional[str] = Field(
        default=None, pattern=r"^#[0-9A-Fa-f]{6}$", description="Hex color code"
    )

    favorite: Optional[bool] = Field(
        default=None,
        description="Mark note as favorite",
    )

    status: Optional[NoteStatus] = Field(
        default=None,
        description="Update note status",
    )

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, tags: Optional[list[str]]) -> Optional[list[str]]:
        """
        Validate and normalize tags,
        """
        if tags is None:
            return None
        cleaned_tags = [tag.strip().lower() for tag in tags if tag.strip()]
        return list(dict.fromkeys(cleaned_tags))

    @field_validator("title")
    @classmethod
    def validate_title(cls, title: Optional[str]) -> Optional[str]:
        """
        Validate title.
        """
        if title is None:
            return None
        title = title.strip()
        if not title:
            raise ValueError("Ttitle cannot be empty or whitespace only")
        return title


class NoteRead(BaseModel):
    """
    Schema for reading note metadata (without decrypted content).
    """

    id: str
    title: str
    created_at: datetime
    updated_at: Optional[datetime]
    tags: list[str]
    status: NoteStatus
    size_bytes: int
    favorite: bool
    color: Optional[str]

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "title": "My Secret Note",
                "created_at": "2025-10-13T10:30:00Z",
                "updated_at": "2025-10-13T15:45:00Z",
                "tags": ["personal", "important"],
                "status": "active",
                "size_bytes": 1024,
                "favorite": True,
                "color": "#FF5733",
            }
        },
    )


class NoteDetail(NoteRead):
    """
    Schema for reading a note with its decrypted content.
    """

    content: str = Field(
        description="Decrypted note content",
    )

    content_hash: Optional[str] = Field(
        description="Hash for integrity verification",
    )

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "title": "My Secret Note",
                "content": "This is the decrypted secret message",
                "created_at": "2025-10-13T10:30:00Z",
                "updated_at": "2025-10-13T15:45:00Z",
                "tags": ["personal", "important"],
                "status": "active",
                "size_bytes": 1024,
                "favorite": True,
                "color": "#FF5733",
                "content_hash": "abc123...",
            }
        },
    )


class NoteListResponse(BaseModel):
    """
    Schema for paginated list of notes.
    """

    notes: list[NoteRead]
    total: int
    page: int
    page_size: int
    total_pages: int

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "notes": [],
                "total": 42,
                "page": 1,
                "page_size": 10,
                "total_pages": 5,
            }
        }
    )


class NoteFilter(BaseModel):
    """
    Schema for filtering and searching notes.
    """

    search: Optional[str] = Field(
        default=None,
        description="Search in title",
    )

    tags: Optional[list[str]] = Field(
        default=None,
        description="Filter by tags",
    )

    status: Optional[NoteStatus] = Field(
        default=NoteStatus.ACTIVE,
        description="Filter by status",
    )

    favorite: Optional[bool] = Field(
        default=None,
        description="Filter by favorites only",
    )

    color: Optional[bool] = Field(default=None, description="Filter by color")

    created_before: Optional[datetime] = Field(
        default=None, description="Filter notes created before this date"
    )

    created_after: Optional[datetime] = Field(
        default=None,
        description="Filter notes created after this date",
    )

    sort_by: str = Field(
        default="updated_at",
        pattern="^(created_at|updated_at|title)$",
        description="Sort field",
    )

    sort_desc: bool = Field(
        default=True,
        description="Sort descending",
    )

    page: int = Field(
        default=1,
        ge=1,
        description="Page number",
    )

    page_size: int = Field(default=20, ge=1, le=100, description="Items per page")


class NoteStatistics(BaseModel):
    """
    Statistics about the note collection.
    """

    total_notes: int
    active_notes: int
    archived_notes: int
    deleted_notes: int
    total_size_bytes: int
    favorite_count: int
    total_tags: int
    most_used_tags: list[tuple[str, int]] = Field(description="List of (tag, count)")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "total_notes": 100,
                "active_notes": 85,
                "archived_notes": 10,
                "deleted_notes": 5,
                "total_size_bytes": 1048576,
                "favorite_count": 15,
                "total_tags": 25,
                "most_used_tags": [("personal", 45), ("work", 30), ("ideas", 20)],
            }
        }
    )


class AuthRequest(BaseModel):
    """
    Schema for authentication request.
    """

    password: str = Field(
        min_length=8,
        description="Master password",
    )

    remember_me: bool = Field(
        default=False,
        description="Keep session alive longer",
    )


class AuthResponse(BaseModel):
    """
    Schema for authentication response.
    """

    success: bool
    message: str
    session_id: Optional[str] = None
    expires_at: Optional[datetime] = None


class MessageResponse(BaseModel):
    """
    Generic message response.
    """

    message: str
    success: bool = True


class ErrorResponse(BaseModel):
    """
    Error response.
    """

    detail: str
    error_code: Optional[str] = None
