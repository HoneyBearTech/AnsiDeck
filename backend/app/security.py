from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.config import get_settings

SESSION_MAX_AGE_SECONDS = 60 * 60 * 8  # 8 hours


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(get_settings().auth_secret_key, salt="ansideck-session")


def create_session_token(user_id: int, session_version: int) -> str:
    return _serializer().dumps({"uid": user_id, "sv": session_version})


def verify_session_token(token: str) -> tuple[int, int] | None:
    """Returns (user_id, session_version) for a valid, unexpired token."""
    try:
        data = _serializer().loads(token, max_age=SESSION_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return None
    user_id, session_version = data.get("uid"), data.get("sv")
    if not isinstance(user_id, int) or not isinstance(session_version, int):
        return None
    return user_id, session_version
