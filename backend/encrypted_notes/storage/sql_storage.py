"""
SQLStorage implementation using SQLModel + SQLite
"""

from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, Optional

from models import NoteFilter, NoteMeta
from sqlmodel import Session, SQLModel, create_engine, select
from storage import Storage


class SQLStorage(Storage[NoteMeta]):
    """
    SQLModel-based storage implementation using SQLite.

    Stores note metadata in SQLite database.
    Encrypted content is stored separately in files.
    """

    def __init__(self, database_url: str = "sqlite:///notes.db"):
        """
        Initialize SQL Storage.

        Args:
            database_url: SQLAlchemy database URL
        """
        self.engine = create_engine(
            database_url,
            echo=False,
            connect_args={"check_same_thread": False},  # SQLite specific
        )

        SQLModel.metadata.create_all(self.engine)

    @contextmanager
    def _get_session(self) -> Iterator[Session]:
        """
        Context manager for database sessions.
        """
        session = Session(self.engine)
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def add(self, item: NoteMeta) -> NoteMeta:
        """
        Add a new note to the database.
        """
        with self._get_session() as session:
            session.add(item)
            session.commit()
            session.refresh(item)
            return item

    def get(self, id: str) -> Optional[NoteMeta]:
        """
        Retrieve a note by ID.
        """
        with self._get_session() as session:
            statement = select(NoteMeta).where(NoteMeta.id == id)
            return session.exec(statement).first()

    def update(self, item: NoteMeta) -> NoteMeta:
        """
        Update an existing note.
        """

        with self._get_session() as session:
            existing = session.get(NoteMeta, item.id)
            if not existing:
                raise ValueError(f"Note with id {item.id} not found")

            for key, value in item.model_dump(exclude_unset=True).items():
                setattr(existing, key, value)

            existing.updated_at = datetime.now(timezone.utc)
            session.add(existing)
            session.commit()
            session.refresh(existing)
            return existing

    def delete(self, id: str) -> None:
        """
        Delete a note by ID.
        """

        with self._get_session() as session:
            note = session.get(NoteMeta, id)
            if not note:
                raise ValueError(f"Note with id {id} not found")

            session.delete(note)
            session.commit()

    def list(
        self, filter: Optional[NoteFilter] = None, skip: int = 0, limit: int = 100
    ) -> list[NoteMeta]:
        """
        List notes with filtering and pagination.
        """

        with self._get_session() as session:
            statement = select(NoteMeta)

            if filter:
                if filter.status:
                    statement = statement.where(NoteMeta.status == filter.status)

                if filter.search:
                    search_pattern = f"%{filter.search}%"
                    statement = statement.where(NoteMeta.title.like(search_pattern))

                if filter.tags:
                    for tag in filter.tags:
                        statement = statement.where(NoteMeta.tags.contains([tag]))

                if filter.favorite is not None:
                    statement = statement.where(NoteMeta.favorite == filter.favorite)

                if filter.color:
                    statement = statement.where(NoteMeta.color == filter.color)

                if filter.created_after:
                    statement = statement.where(
                        NoteMeta.created_at >= filter.created_after
                    )

                if filter.created_before:
                    statement = statement.where(
                        NoteMeta.created_at <= filter.created_before
                    )

                sort_column = getattr(NoteMeta, filter.sort_by)
                if filter.sort_desc:
                    statement = statement.order_by(sort_column.desc())
                else:
                    statement = statement.order_by(sort_column.asc())
            else:
                statement = statement.order_by(NoteMeta.updated_at.desc())

        statement = statement.offset(skip).limit(limit)

        return list(session.exec(statement).all())

    def count(self, filter: Optional[NoteFilter] = None) -> int:
        """
        Count notes matching filter criteria.
        """

        with self._get_session() as session:
            statement = select(NoteMeta)

            if filter:
                if filter.status:
                    statement = statement.where(NoteMeta.status == filter.status)

                if filter.search:
                    search_pattern = f"${filter.search}%"
                    statement = statement.where(NoteMeta.title.like(search_pattern))

                if filter.tags:
                    for tag in filter.tags:
                        statement = statement.where(NoteMeta.tags.contains([tag]))

                if filter.favorite is not None:
                    statement = statement.where(NoteMeta.favorite == filter.favorite)

                if filter.color:
                    statement = statement.where(NoteMeta.color == filter.color)
                if filter.created_after:
                    statement = statement.where(
                        NoteMeta.created_at >= filter.created_after
                    )
                if filter.created_before:
                    statement = statement.where(
                        NoteMeta.created_at <= filter.created_before
                    )

            return len(list(session.exec(statement).all()))
