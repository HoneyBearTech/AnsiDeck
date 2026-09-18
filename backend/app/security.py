from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.config import get_settings

SESSION_MAX_AGE_SECONDS = 60 * 60 * 8  # 8 hours


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(get_settings().auth_secret_key, salt="ansideck-session")


def create_session_token(username: str) -> str:
    return _serializer().dumps({"sub": username})


def verify_session_token(token: str) -> str | None:
    try:
        data = _serializer().loads(token, max_age=SESSION_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return None
    return data.get("sub")
