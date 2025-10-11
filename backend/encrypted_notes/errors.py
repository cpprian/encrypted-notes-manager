class EncryptionError(Exception):
    """Base class for encryption-related errors."""

    pass


class DecryptionError(EncryptionError):
    """Raised when decryption fails."""

    pass


class KeyDerivationError(EncryptionError):
    """Raised when key derivation fails."""

    pass
