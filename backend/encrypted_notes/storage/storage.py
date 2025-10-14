"""
Storage layer for the encrypted notes manager.

This module provides:
- Generic Storage protocol/interface
- Import/Export functionality for notes
- Atomic operations and secure file permissions
"""

from abc import abstractmethod
from typing import Generic, Optional, Protocol, TypeVar

from encrypted_notes.models import NoteFilter

T = TypeVar("T")
T_co = TypeVar("T_co", covariant=True)  # for return types


class Storage(Protocol, Generic[T]):
    """
    Generic storage interface for CRUD operations.

    This protocol defines the contract that all storage implementations must follow.
    """

    @abstractmethod
    def add(self, item: T) -> T:
        """
        Add a new item to storage.

        Args:
            item: Item to add

        Returns:
            The added item with any storage-assigned fields populated (e.g., ID).
        """
        ...

    @abstractmethod
    def get(self, id: str) -> Optional[T]:
        """
        Retrieve an item by its ID.

        Args:
            id: Unique identifier of the item.

        Returns:
            Item if found, None otherwise.
        """
        ...

    @abstractmethod
    def update(self, item: T) -> T:
        """
        Update an existing item in storage.

        Args:
            item: Item with updated fields

        Returns:
            Updated item

        Raises:
            ValueError: If item doesn't exist
        """
        ...

    @abstractmethod
    def delete(self, id: str) -> None:
        """
        Delete an itme by ID.

        Args:
            id: Unique identifier

        Raises:
            ValueError: If item doesn't exist
        """
        ...

    @abstractmethod
    def list(
        self, filter: Optional[NoteFilter] = None, skip: int = 0, limit: int = 100
    ) -> list[T]:
        """
        List items with optional filtering and pagination.

        Args:
            filter: Optional filter criteria
            skip: Number of items to skip (for pagination)
            limit: Maximum number of items to return

        Returns:
            List of items matching criteria
        """
        ...

    @abstractmethod
    def count(self, filter: Optional[NoteFilter] = None) -> int:
        """
        Count items mathicng filter criteria.

        Args:
            filter: Optional filter criteria

        Returns:
            Number of matching items
        """
        ...
