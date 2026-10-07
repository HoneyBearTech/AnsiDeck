import hashlib
from datetime import datetime
from typing import Literal, NamedTuple

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.config import get_settings

SESSION_MAX_AGE_SECONDS = 60 * 60 * 8  # 8 hours


def timed_serializer(salt: str) -> URLSafeTimedSerializer:
    """Signs with HMAC-SHA-256. itsdangerous defaults to SHA-1, which is not broken as an HMAC but
    is not something to build new signing on. Changing the digest invalidates existing tokens."""
    return URLSafeTimedSerializer(
        get_settings().auth_secret_key, salt=salt, signer_kwargs={"digest_method": hashlib.sha256}
    )


def _serializer() -> URLSafeTimedSerializer:
    return timed_serializer("ansideck-session")


SignInMethod = Literal["password", "sso"]


class SessionInfo(NamedTuple):
    user_id: int
    session_version: int
    method: SignInMethod
    issued_at: datetime  # when this session's cookie was signed: the sign-in, for SSO


def create_session_token(
    user_id: int, session_version: int, method: SignInMethod = "password"
) -> str:
    return _serializer().dumps({"uid": user_id, "sv": session_version, "m": method})


def session_info(token: str) -> SessionInfo | None:
    """The session behind a valid, unexpired token (sessions from before the sign-in method was
    recorded count as password sessions)."""
    try:
        data, issued_at = _serializer().loads(
            token, max_age=SESSION_MAX_AGE_SECONDS, return_timestamp=True
        )
    except (BadSignature, SignatureExpired):
        return None
    user_id, session_version = data.get("uid"), data.get("sv")
    if not isinstance(user_id, int) or not isinstance(session_version, int):
        return None
    method = "sso" if data.get("m") == "sso" else "password"
    return SessionInfo(user_id, session_version, method, issued_at)


def _load_user_token(
    serializer: URLSafeTimedSerializer, token: str, max_age: int
) -> tuple[int, int] | None:
    try:
        data = serializer.loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None
    user_id, session_version = data.get("uid"), data.get("sv")
    if not isinstance(user_id, int) or not isinstance(session_version, int):
        return None
    return user_id, session_version


def verify_session_token(token: str) -> tuple[int, int] | None:
    """Returns (user_id, session_version) for a valid, unexpired token."""
    return _load_user_token(_serializer(), token, SESSION_MAX_AGE_SECONDS)


# Between a correct password and the second factor: proves the password step only.
MFA_MAX_AGE_SECONDS = 5 * 60


def create_mfa_token(user_id: int, session_version: int) -> str:
    return timed_serializer("ansideck-mfa").dumps({"uid": user_id, "sv": session_version})


def verify_mfa_token(token: str) -> tuple[int, int] | None:
    """Returns (user_id, session_version) for a valid, unexpired password-step token."""
    return _load_user_token(timed_serializer("ansideck-mfa"), token, MFA_MAX_AGE_SECONDS)
