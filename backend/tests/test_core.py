import pytest
from pathlib import Path
import shutil

from encrypted_notes.storage.file_storage import FileStorage
from encrypted_notes.core import (
    NoteSession,
    archived_note,
    create_note,
    delete_note,
    export_note_to_file,
    get_note_statistics,
    import_note_from_file,
    list_notes,
    read_note,
    restore_note,
    search_notes,
    update_note,
)
from encrypted_notes.models import NoteCreate, NoteUpdate
from encrypted_notes.errors import InvalidPasswordError


@pytest.fixture
def test_storage():
    test_dir = Path("test_core")
    if test_dir.exists():
        shutil.rmtree(test_dir)
    yield FileStorage(test_dir)
    shutil.rmtree(test_dir)


@pytest.fixture
def test_session(test_storage):
    password = "test_password_123"
    return NoteSession(test_storage, password)


def test_create_session(test_session):
    assert test_session.get_salt_hex() is not None


def test_create_note(test_session):
    note_data = NoteCreate(
        title="My Secret Note",
        content="This is secret content that will be encrypted!",
        tags=["personal", "test"],
        favorite=True,
        color="#FF5733",
    )
    created_note = create_note(test_session, note_data)
    assert created_note.title == note_data.title
    assert created_note.content is not None
    return created_note


def test_read_note(test_session):
    created_note = test_create_note(test_session)
    read_detail = read_note(test_session, created_note.id)
    assert read_detail.content == "This is secret content that will be encrypted!"


def test_update_note(test_session):
    created_note = test_create_note(test_session)
    update_data = NoteUpdate(
        title="Updated Title",
        content="Updated secret content!",
        tags=["personal", "test", "updated"],
    )
    updated_note = update_note(test_session, created_note.id, update_data)
    assert updated_note.title == "Updated Title"
    assert updated_note.content == "Updated secret content!"


def test_list_notes(test_session):
    test_create_note(test_session)
    notes_list = list_notes(test_session)
    assert len(notes_list) == 1


def test_search_notes(test_session):
    test_create_note(test_session)
    search_results = search_notes(test_session, "Updated", search_content=True)
    assert len(search_results) == 0  # No "Updated" content yet


def test_statistics(test_session):
    test_create_note(test_session)
    stats = get_note_statistics(test_session)
    assert stats.total_notes == 1
    assert stats.active_notes == 1


def test_archive_restore(test_session):
    created_note = test_create_note(test_session)
    archived = archived_note(test_session, created_note.id)
    assert archived.status == "archived"
    restored = restore_note(test_session, created_note.id)
    assert restored.status == "active"


def test_export_import(test_session):
    created_note = test_create_note(test_session)
    export_file = Path("test_core") / "exports" / "test_export.json"
    export_note_to_file(test_session, created_note.id, export_file)
    assert export_file.exists()

    delete_note(test_session, created_note.id, permament=True)
    imported = import_note_from_file(test_session, export_file, new_id=True)
    assert imported.id != created_note.id


def test_wrong_password(test_storage, test_session):
    created_note = test_create_note(test_session)
    wrong_session = NoteSession(test_storage, "wrong_password", salt=test_session.salt)
    with pytest.raises(InvalidPasswordError):
        read_note(wrong_session, created_note.id)
