import shutil
from pathlib import Path

import pytest
from encrypted_notes.models import NoteFilter, NoteMeta, NoteStatus
from encrypted_notes.storage.file_storage import FileStorage


@pytest.fixture
def file_storage():
    storage = FileStorage("test_storage")
    yield storage
    shutil.rmtree("test_storage")


def test_file_storage_add_and_retrieve(file_storage):
    note1 = NoteMeta(
        title="Test Note 1",
        filename="test1.bin",
        tags=["test", "storage"],
        status=NoteStatus.ACTIVE,
    )
    added_note = file_storage.add(note1)
    assert added_note.id is not None

    test_content = b"encrypted_test_data_12345"
    file_storage.save_encrypted_content(added_note.id, test_content)

    retrieved = file_storage.get(added_note.id)
    assert retrieved.title == "Test Note 1"

    loaded_content = file_storage.load_encrypted_content(added_note.id)
    assert loaded_content == test_content


def test_file_storage_update(file_storage):
    note1 = NoteMeta(
        title="Test Note 1",
        filename="test1.bin",
        tags=["test", "storage"],
        status=NoteStatus.ACTIVE,
    )
    added_note = file_storage.add(note1)

    retrieved = file_storage.get(added_note.id)
    retrieved.title = "Updated Title"
    retrieved.tags.append("updated")
    updated = file_storage.update(retrieved)

    assert updated.title == "Updated Title"
    assert "updated" in updated.tags


def test_file_storage_export_import(file_storage):
    note1 = NoteMeta(
        title="Test Note 1",
        filename="test1.bin",
        tags=["test", "storage"],
        status=NoteStatus.ACTIVE,
    )
    added_note = file_storage.add(note1)

    test_content = b"encrypted_test_data_12345"
    file_storage.save_encrypted_content(added_note.id, test_content)

    export_file = Path("test_storage/exports/export_test.json")
    file_storage.export_note(added_note.id, export_file)

    file_storage.delete(added_note.id)
    assert file_storage.get(added_note.id) is None

    imported = file_storage.import_note(export_file, new_id=True)
    imported_content = file_storage.load_encrypted_content(imported.id)
    assert imported_content == test_content


def test_file_storage_filtering(file_storage):
    for i in range(5):
        note = NoteMeta(
            title=f"Note {i}",
            filename=f"note{i}.bin",
            tags=["test"] if i % 2 == 0 else ["other"],
            favorite=i % 3 == 0,
        )
        file_storage.add(note)

    filter_tags = NoteFilter(tags=["test"])
    filtered = file_storage.list(filter=filter_tags)
    assert len(filtered) == 3

    filter_fav = NoteFilter(favorite=True)
    favorites = file_storage.list(filter=filter_fav)
    assert len(favorites) == 2

    total = file_storage.count()
    assert total == 5
