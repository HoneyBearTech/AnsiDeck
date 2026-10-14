"""TOTP (RFC 6238) second factor for password logins, plus the single-use recovery codes that
stand in for any second factor (TOTP or a passkey, app.passkeys; see app.second_factor)."""

import hashlib
import hmac
import re
import secrets
import time

import pyotp
import segno

from app.crypto import decrypt_secret, encrypt_secret
from app.models import User

ISSUER = "AnsiDeck"
_STEP_SECONDS = 30
_CODE = re.compile(r"[0-9]{6}")  # not \d: that also matches non-ASCII digits

RECOVERY_CODE_COUNT = 10
# 32 symbols without look-alikes (0/o, 1/l): 10 characters carry 50 bits.
_RECOVERY_ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789"
_RECOVERY_LENGTH = 10


def new_secret() -> str:
    return pyotp.random_base32()  # 160 bits, the RFC 4226 recommendation


def encrypt(secret: str) -> bytes:
    return encrypt_secret(secret.encode())


def decrypt(token: bytes) -> str:
    return decrypt_secret(token).decode()


def provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)


def qr_data_uri(uri: str) -> str:
    """An SVG data URI for an <img>, so the markup is never inserted into the page.
    Dark on white with a full quiet zone: authenticator apps scan that reliably."""
    return segno.make(uri, error="m").svg_data_uri(scale=5, border=4, dark="#000", light="#fff")


def looks_like_totp_code(code: str) -> bool:
    return _CODE.fullmatch(code.replace(" ", "")) is not None


def match_counter(
    secret: str, code: str, last_counter: int | None, now: float | None = None
) -> int | None:
    """The time step `code` belongs to (one step of clock drift either way), or None.
    Steps at or below `last_counter` were already used and never match again."""
    if not looks_like_totp_code(code):
        return None
    code = code.replace(" ", "")
    totp = pyotp.TOTP(secret)
    current = int((time.time() if now is None else now) // _STEP_SECONDS)
    for counter in (current - 1, current, current + 1):
        if counter < 0 or (last_counter is not None and counter <= last_counter):
            continue
        if hmac.compare_digest(totp.generate_otp(counter), code):
            return counter
    return None


def _normalize(code: str) -> str:
    return re.sub(r"[\s-]", "", code).lower()


def _hash(normalized: str) -> str:
    return hashlib.sha256(normalized.encode()).hexdigest()


def new_recovery_codes() -> tuple[list[str], list[str]]:
    """(codes to show once, formatted "xxxxx-xxxxx"; their hashes to store)."""
    raw = [
        "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(_RECOVERY_LENGTH))
        for _ in range(RECOVERY_CODE_COUNT)
    ]
    return [f"{c[:5]}-{c[5:]}" for c in raw], [_hash(c) for c in raw]


def use_second_factor(user: User, *, code: str | None, recovery_code: str | None) -> str | None:
    """Checks a TOTP code (for a user with TOTP) or a recovery code (for any user with a second
    factor) and records its use (the caller commits). Returns "totp" or "recovery_code", or None
    if it doesn't match."""
    if code is not None:
        if user.totp_secret is None:
            return None
        counter = match_counter(decrypt(user.totp_secret), code, user.totp_last_counter)
        if counter is None:
            return None
        user.totp_last_counter = counter
        return "totp"
    if recovery_code is not None:
        normalized = _normalize(recovery_code)
        if len(normalized) != _RECOVERY_LENGTH or not normalized.isascii():
            return None
        wanted = _hash(normalized)
        hashes = user.recovery_code_hashes or []
        if not user.two_factor_enabled or not any(hmac.compare_digest(h, wanted) for h in hashes):
            return None
        user.recovery_code_hashes = [h for h in hashes if h != wanted]
        return "recovery_code"
    return None


def enable(user: User, counter: int) -> list[str] | None:
    """Promotes the pending secret; returns the recovery codes to show once, when this is the
    user's first second factor (a user with passkeys keeps the codes they have)."""
    if user.totp_pending_secret is None:
        raise ValueError("there is no pending two-factor secret to enable")
    first = not user.two_factor_enabled
    user.totp_secret = user.totp_pending_secret
    user.totp_pending_secret = None
    user.totp_last_counter = counter
    if not first:
        return None
    codes, user.recovery_code_hashes = new_recovery_codes()
    return codes


def clear(user: User) -> None:
    """Turns TOTP off; the recovery codes go too when no passkey is left."""
    user.totp_secret = None
    user.totp_pending_secret = None
    user.totp_last_counter = None
    if not user.passkeys:
        user.recovery_code_hashes = None


def clear_all(user: User) -> dict[str, int | bool] | None:
    """Removes every second factor (TOTP, passkeys, recovery codes and anything half set up);
    returns what was there for the audit log, or None when there was nothing (the caller
    commits and ends the user's sessions)."""
    had = {"totp": user.totp_enabled, "passkeys": len(user.passkeys)}
    if not (
        had["totp"]
        or had["passkeys"]
        or user.totp_pending_secret is not None
        or user.recovery_code_hashes
        or user.webauthn_pending is not None
    ):
        return None
    user.passkeys.clear()
    user.webauthn_pending = None
    clear(user)
    return had
