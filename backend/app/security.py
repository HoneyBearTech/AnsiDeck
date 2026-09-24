import hashlib

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


def create_session_token(user_id: int, session_version: int) -> str:
    return _serializer().dumps({"uid": user_id, "sv": session_version})


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
