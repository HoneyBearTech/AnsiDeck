from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, MultiFernet

from app.config import get_settings

_password_hasher = PasswordHasher()


def hash_password(plain: str) -> str:
    return _password_hasher.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _password_hasher.verify(hashed, plain)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False


def fernet() -> MultiFernet:
    """Encrypts with the first CREDENTIAL_ENCRYPTION_KEY, decrypts with any of them."""
    return MultiFernet([Fernet(key) for key in get_settings().credential_encryption_keys])


def encrypt_secret(plaintext: bytes) -> bytes:
    return fernet().encrypt(plaintext)


def decrypt_secret(token: bytes) -> bytes:
    return fernet().decrypt(token)
