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


class NoteOperationsError(Exception):
    """Base exception for note operations."""

    pass
