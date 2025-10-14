"""
REST API for the encrypted notes manager

This module provides an interface that uses
the business logic from core.py. Suitable for web/mobile apps.

Security Notes:
- In production: There is a consideration to add JWT + HTTP/TLs
for now there is X-Master-Password for dev purpose.
"""

import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Optional

from fastapi import (
    FastAPI,
    Header,
    HTTPException,
    Depends,
    status,
    Query,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .core import (
    NoteSession,
    create_note as core_create_note,
    read_note as core_read_note,
    update_note as core_update_note,
    delete_note as core_delete_note,
    restore_note as core_restore_note,
    archive_note as core_archive_note,
    list_notes as core_list_notes,
    search_notes as core_search_notes,
    get_note_statistics as core_get_statistics,
    get_tags as core_get_tags,
    export_note_to_file as core_export_note,
    import_note_from_file as core_import_note,
    verify_password,
)
from .models import (
    NoteCreate,
    NoteUpdate,
    NoteRead,
    NoteDetail,
    NoteListResponse,
    NoteFilter,
    NoteStatistics,
    NoteStatus,
    MessageResponse,
)
from .errors import (
    NoteNotFoundError,
    InvalidPasswordError,
    NoteOperationError,
    AuthError,
)
from .storage.file_storage import FileStorage

CONFIG_DIR = Path.home() / ".config" / "encrypted-notes"
CONFIG_FILE = CONFIG_DIR / "config.json"
STORAGE_DIR = CONFIG_DIR / "storage"

app_state = {
    "storage": None,
    "salt_hex": None,
    "iterations": 100_000,
}


def load_config():
    """
    Load application configuration.
    """

    if not CONFIG_FILE.exists():
        raise RuntimeError(
            "Application not initialized! Run 'python3 -m encrypted_notes.cli init' first."
        )

    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)

    app_state["salt_hex"] = config.get("salt_hex")
    app_state["iterations"] = config.get("iterations", 100_000)

    storage_path = Path(config.get("storage_dir", STORAGE_DIR))
    app_state["storage"] = FileStorage(storage_path)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    """
    try:
        load_config()
        print("✓ Configuration loaded")
        print(f"✓ Storage initialized at: {STORAGE_DIR}")
    except Exception as e:
        print(f"✗ Failed to initialize: {e}")
        raise

    yield

    print("Shutting down...")


app = FastAPI(
    title="Encrypted Notes Manager API",
    description="""
    Secure encrypted notes manager with password-based encryption.
    
    ## Authentication
    
    All endpoints require the `X-Master-Password` header with your master password.
    
    ## Security Warning
    
    This API uses a simple password header for demo purposes.
    In production, use:
    - HTTPS/TLS for all connections
    - Proper authentication (JWT tokens, OAuth2)
    - Rate limiting on authentication
    - Session management
    
    ## Features
    
    * Create, read, update, delete encrypted notes
    * Search and filter notes
    * Tags and favorites
    * Import/export functionality
    * Statistics and analytics
    """,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",  # Vite dev server
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def get_session(
    x_master_password: Annotated[
        str,
        Header(
            description="Master password for encryption/decryption",
            examples="your_secure_password",
        ),
    ],
) -> NoteSession:
    """
    Dependency: Get authenticated session from password header.

    PLEASE DO NOT LOG THE PASSWORD!

    Args:
        x_master_password: Master password from header

    Returns:
        Authenticated NoteSession

    Raises:
        AuthError: If password is invalid or session creation fails
    """

    if not x_master_password:
        raise AuthError("Missing X-Master-Password header")

    try:
        session = NoteSession.from_salt_hex(
            app_state["storage"],
            x_master_password,
            app_state["salt_hex"],
            app_state["iterations"],
        )

        notes = core_list_notes(session)
        if notes:
            try:
                core_read_note(session, notes[0].id)
            except InvalidPasswordError:
                raise AuthError("Invalid password")

        return session
    except InvalidPasswordError:
        raise AuthError("Invalid passowrd")
    except Exception as e:
        raise AuthError(f"Authentication failed: {str(e)}")


SessionDep = Annotated[NoteSession, Depends(get_session)]


@app.exception_handler(NoteNotFoundError)
async def note_not_found_handler(request, exc: NoteNotFoundError):
    """
    Handle note not found errors.
    """

    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(exc)}
    )


@app.exception_handler(InvalidPasswordError)
async def invalid_password_handler(request, exc: InvalidPasswordError):
    """
    Handle invalid password errors.
    """

    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED, content={"detail": str(exc)}
    )


@app.exception_handler(NoteOperationError)
async def operation_error_handler(request, exc: NoteOperationError):
    """
    Handle note operation errors.
    """

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"detail": str(exc)}
    )


@app.get("/", tags=["Health"])
async def root():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "Encrypted Notes Manager API",
        "version": "1.0.0",
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """
    Detailed health check.
    """

    return {
        "status": "healthy",
        "storage": "connected" if app_state["storage"] else "disconnected",
        "config_loaded": app_state["salt_hex"] is not None,
    }


@app.post(
    "/notes",
    response_model=NoteDetail,
    status_code=status.HTTP_201_CREATED,
    tags=["Notes"],
    summary="Create a new note",
)
async def create_note(note: NoteCreate, session: SessionDep) -> NoteDetail:
    """
    Create a new encrypted note.
    """

    try:
        created = core_create_note(session, note)
        return created
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create a note: {str(e)}",
        )


@app.get(
    "/notes", response_model=NoteListResponse, tags=["Notes"], summary="List notes"
)
async def list_notes(
    session: SessionDep,
    status_filter: NoteStatus = Query(
        NoteStatus.ACTIVE, alias="status", description="Filter by status"
    ),
    search: Optional[str] = Query(None, description="Search in titles"),
    tags: Optional[str] = Query(None, description="Comma-separeted list of tags"),
    favorite: Optional[bool] = Query(None, description="Filter favorites"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    sort_by: str = Query(
        "updated_at",
        pattern="^(created_at|updated_at|title)$",
        description="Sort field",
    ),
    sort_desc: bool = Query(True, description="Sort descending"),
) -> NoteListResponse:
    """
    List notes with filtering, pagination, and sorting.

    Returns metadata only (no decrypted content).
    Use GET /notes/{id} to retrieve full note with content.
    """

    tag_list = [t.strip() for t in tags.split(",")] if tags else None

    note_filter = NoteFilter(
        status=status_filter,
        search=search,
        tags=tag_list,
        favorite=favorite,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_desc=sort_desc,
    )

    notes = core_list_notes(session, note_filter)
    total = session.storage.count(note_filter)
    total_pages = (total + page_size - 1) // page_size

    return NoteListResponse(
        notes=notes,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@app.get(
    "/notes/{note_id}", response_model=NoteDetail, tags=["Notes"], summary="Get a note"
)
async def get_note(note_id: str, session: SessionDep) -> NoteDetail:
    """
    Get a specific note with decrypted content.

    Requires valid password in X-Master-Password header.
    """

    try:
        note = core_read_note(session, note_id)
        return note
    except NoteNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Note {note_id} not found"
        )
    except InvalidPasswordError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password or corrupted data",
        )


@app.put(
    "/notes/{note_id}",
    response_model=NoteDetail,
    tags=["Notes"],
    summary="Update a note",
)
async def update_note(
    note_id: str, update: NoteUpdate, session: SessionDep
) -> NoteDetail:
    """
    Update an existing note.

    If content is updated, it will be re-encrypted.
    """

    try:
        updated = core_update_note(session, note_id, update)
        return updated
    except NoteNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Note {note_id} not found"
        )


@app.delete(
    "/notes/{note_id}",
    response_model=MessageResponse,
    tags=["Notes"],
    summary="Delete a note",
)
async def delete_note(
    session: SessionDep,
    note_id: str,
    permanent: bool = Query(
        False, description="Permanently delete (cannot be restored)"
    ),
) -> MessageResponse:
    """
    Delete a note.

    By default, performs soft delete (can be restored).
    Use permanent=true fro permanent deletion.
    """
    try:
        core_delete_note(session, note_id, permament=permanent)

        if permanent:
            return MessageResponse(message=f"Note {note_id} permanently deleted")
        else:
            return MessageResponse(message=f"Note {note_id} moved to trash")
    except NoteNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Note {note_id} not found"
        )


@app.post(
    "/notes/{note_id}/archive",
    response_model=NoteRead,
    tags=["Notes"],
    summary="Archive a note",
)
async def archive_note(note_id: str, session: SessionDep) -> NoteRead:
    """
    Archieve a note.
    """

    try:
        return core_archive_note(session, note_id)
    except NoteNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Note {note_id} not found"
        )


@app.post(
    "notes/{note_id}/restore",
    response_model=NoteRead,
    tags=["Notes"],
    summary="Restore a note",
)
async def restore_note(note_id: str, session: SessionDep) -> NoteRead:
    """
    Restore an archived or deleted note.
    """

    try:
        return core_restore_note(session, note_id)
    except NoteNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Note {note_id} not found"
        )


@app.get(
    "/search", response_model=list[NoteRead], tags=["Search"], summary="Search notes"
)
async def search_notes(
    session: SessionDep,
    query: str = Query(..., min_length=1, description="Search query"),
    search_content: bool = Query(
        False, description="Search in content (slower, decrypts all notes)"
    ),
) -> list[NoteRead]:
    """
    Search notes by title or content.

    By default, searched only titles (fast).
    Set search_content=true to search in decrypted content (slower).
    """

    results = core_search_notes(session, query, search_content=search_content)
    return results


@app.get("/tags", response_model=list[str], tags=["Tags"], summary="Get all tags")
async def get_tags(session: SessionDep) -> list[str]:
    """
    Get all unique tags used in notes.
    """

    tags = core_get_tags(session)
    return tags


@app.get(
    "/statistics",
    response_model=NoteStatistics,
    tags=["Statistics"],
    summary="Get statistics",
)
async def get_statistics(session: SessionDep) -> NoteStatistics:
    """
    Get statistics about notes collection.

    Includes:
    - Total, active, archived, deleted note counts
    - Storage usage
    - Tage usage statistics
    - Most used tags
    """

    return core_get_statistics(session)


@app.get("/notes/{note_id}/export", tags=["Import/Export"], summary="Export a note")
async def export_note(note_id: str, session: SessionDep):
    """
    Export a note as a downloadable JSON file.

    The exported file contains encrypted content and metadata.
    Can be imported later using the import endpoint.
    """

    try:
        from fastapi.responses import FileResponse
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            export_path = Path(tf.name)

        core_export_note(session, note_id, export_path)

        note = core_read_note(session, note_id)
        safe_title = "".join(
            c for c in note.title if c.isalnum() or c in (" ", "_", "-")
        )
        filename = f"note_{safe_title}_{note_id[:8]}.json"

        return FileResponse(
            path=export_path, filename=filename, media_type="application/json"
        )
    except NoteNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Note {note_id} not found"
        )


@app.get("/notes/{note_id}/import", tags=["Import/Export"], summary="Import a note")
async def import_note(
    session: SessionDep,
    import_path: Path = Query(..., description="Path to the note JSON file to import"),
):
    """
    Import a note from a JSON file.

    The imported note can be exported previously using the export endpoint.
    """

    try:
        from fastapi.responses import FileResponse

        imported_file = core_import_note(session, import_path, new_id=True)

        return FileResponse(
            path=imported_file,
            filename=imported_file.name,
            media_type="application/json",
        )

    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Path {import_path} not found",
        )


@app.post(
    "/admin/verify-password",
    response_model=MessageResponse,
    tags=["Admin"],
    summary="Verify password",
)
async def verify_password_endpoint(
    x_master_password: Annotated[str, Header()],
) -> MessageResponse:
    """
    Verify if the provided password is correct.
    """

    try:
        is_valid = verify_password(
            app_state["storage"],
            x_master_password,
            app_state["salt_hex"],
        )

        if is_valid:
            return MessageResponse(message="Password is valid")
        else:
            raise AuthError("Invalid password")

    except Exception as e:
        raise AuthError(f"Verification failed: {str(e)}")


if __name__ == "__main__":
    import uvicorn

    print(
        """
    🔐 Encrypted Notes Manager API Server

   📚 Access the docs at: http://localhost:8000/docs

    Make sure to run 'python3 -m encrypted_notes.cli init' first!

    🔒 Security Warning:
    - This API uses a simple password header for demo purposes.
    In production, use:
    - HTTPS/TLS for all connections
    - Proper authentication (JWT tokens, OAuth2)
    - Rate limiting on authentication
    - Session management

    Press Ctrl+C to stop the server      
    """
    )

    uvicorn.run(
        "encrypted_notes.api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
