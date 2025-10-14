from fastapi import HTTPException, status


class EncryptionError(Exception):
    """Base class for encryption-related errors."""

    pass


class DecryptionError(EncryptionError):
    """Raised when decryption fails."""

    pass


class KeyDerivationError(EncryptionError):
    """Raised when key derivation fails."""

    pass


class NoteNotFoundError(Exception):
    """Raised when a note is not found."""

    pass


class InvalidPasswordError(Exception):
    """Raised when password is incorrect."""

    pass


class NoteOperationError(Exception):
    """Base exception for note operations."""

    pass


class AuthError(HTTPException):
    """Authentication error."""

    def __init__(self, detail: str = "Authentication failed"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "X-Master-Password"},
        )
