import pytest
from itsdangerous import BadSignature, URLSafeTimedSerializer

from app import sso_common
from app.config import get_settings
from app.security import create_session_token, verify_session_token

SESSION_SALT = "ansideck-session"


def _default_sha1(salt: str) -> URLSafeTimedSerializer:
    """What the app used before: itsdangerous' default digest (SHA-1)."""
    return URLSafeTimedSerializer(get_settings().auth_secret_key, salt=salt)


def test_session_tokens_round_trip() -> None:
    assert verify_session_token(create_session_token(7, 3)) == (7, 3)


def test_session_tokens_are_not_signed_with_sha1() -> None:
    # A SHA-1 signer with the same secret and salt must not accept the app's token.
    with pytest.raises(BadSignature):
        _default_sha1(SESSION_SALT).loads(create_session_token(7, 3))


def test_a_legacy_sha1_session_token_is_rejected() -> None:
    # The one-time cost of the change: sessions issued before it stop working.
    legacy = _default_sha1(SESSION_SALT).dumps({"uid": 7, "sv": 3})
    assert verify_session_token(legacy) is None


def test_sso_state_cookies_use_sha256_and_still_round_trip() -> None:
    cookie = sso_common.sign_state("oidc", {"s": "state", "v": "verifier"})
    assert sso_common.verify_state("oidc", cookie, "state")["v"] == "verifier"
    with pytest.raises(BadSignature):
        _default_sha1("ansideck-oidc-state").loads(cookie)
