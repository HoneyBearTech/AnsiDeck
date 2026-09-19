"""OpenID Connect sign-in (authorization code + PKCE + state + nonce).

Success ends in the app's normal session cookie, so RBAC, project scoping, revocation
and audit are unchanged. Accounts are pre-provisioned only: nothing is ever created here.
Every failure is an `SsoError`; the router shows the user a generic code and puts the
real reason only in the audit log.
"""

import secrets
import time
from urllib.parse import urlencode

import httpx
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import User
from app.sso_common import (
    SsoError,
    http_client,
    pkce_challenge,
    resolve_user,
    sign_state,
    verify_state,
)

FLOW = "oidc"
STATE_COOKIE_NAME = "ansideck_oidc"
STATE_COOKIE_PATH = "/api/auth/oidc"
CALLBACK_PATH = "/api/auth/oidc/callback"

# Asymmetric only. Never "none", never HS*: an HS256 token "signed" with the provider's
# public key must not verify.
ALLOWED_ALGORITHMS = [
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA",
]  # fmt: skip
_CLOCK_LEEWAY_SECONDS = 60
_METADATA_TTL_SECONDS = 3600

_metadata_cache: dict[str, tuple[float, dict]] = {}
_jwks_cache: dict[str, tuple[float, KeySet]] = {}


def clear_caches() -> None:
    _metadata_cache.clear()
    _jwks_cache.clear()


def redirect_uri(settings: Settings) -> str:
    return f"{settings.public_url}{CALLBACK_PATH}"


def _get_json(url: str) -> dict:
    try:
        with http_client() as client:
            response = client.get(url)
        response.raise_for_status()
        data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise SsoError("failed", f"could not fetch {url}: {type(exc).__name__}") from exc
    if not isinstance(data, dict):
        raise SsoError("failed", f"unexpected response from {url}")
    return data


def get_metadata(settings: Settings) -> dict:
    cached = _metadata_cache.get(settings.oidc_issuer)
    if cached and time.monotonic() - cached[0] < _METADATA_TTL_SECONDS:
        return cached[1]
    metadata = _get_json(settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration")
    # Must match exactly what we were configured with (mix-up defence).
    if metadata.get("issuer") != settings.oidc_issuer:
        raise SsoError("failed", "provider metadata issuer does not match OIDC_ISSUER")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not isinstance(metadata.get(field), str):
            raise SsoError("failed", f"provider metadata lacks {field}")
    _metadata_cache[settings.oidc_issuer] = (time.monotonic(), metadata)
    return metadata


def _get_keyset(metadata: dict, *, refresh: bool = False) -> KeySet:
    uri = metadata["jwks_uri"]
    cached = _jwks_cache.get(uri)
    if cached and not refresh and time.monotonic() - cached[0] < _METADATA_TTL_SECONDS:
        return cached[1]
    try:
        keyset = KeySet.import_key_set(_get_json(uri))
    except (JoseError, ValueError, KeyError) as exc:
        raise SsoError("failed", "provider JWKS is not usable") from exc
    _jwks_cache[uri] = (time.monotonic(), keyset)
    return keyset


def begin_login(settings: Settings) -> tuple[str, str]:
    """Returns (provider authorization URL, signed state-cookie value)."""
    metadata = get_metadata(settings)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    query = urlencode(
        {
            "response_type": "code",
            "client_id": settings.oidc_client_id,
            "redirect_uri": redirect_uri(settings),
            "scope": settings.oidc_scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
        }
    )
    separator = "&" if "?" in metadata["authorization_endpoint"] else "?"
    cookie = sign_state(FLOW, {"s": state, "n": nonce, "v": verifier})
    return f"{metadata['authorization_endpoint']}{separator}{query}", cookie


def _exchange_code(settings: Settings, metadata: dict, code: str, verifier: str) -> str:
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri(settings),
        "code_verifier": verifier,
    }
    methods = metadata.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
    auth: tuple[str, str] | None = None
    if "client_secret_basic" in methods:
        auth = (settings.oidc_client_id, settings.oidc_client_secret)
    else:
        form.update(client_id=settings.oidc_client_id, client_secret=settings.oidc_client_secret)
    try:
        with http_client() as client:
            response = client.post(metadata["token_endpoint"], data=form, auth=auth)
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise SsoError("failed", f"token request failed: {type(exc).__name__}") from exc
    id_token = payload.get("id_token") if isinstance(payload, dict) else None
    if response.status_code != 200 or not isinstance(id_token, str):
        raise SsoError("failed", f"token endpoint refused the code (HTTP {response.status_code})")
    return id_token


def _verify_id_token(settings: Settings, metadata: dict, id_token: str, nonce: str) -> dict:
    algorithms = ALLOWED_ALGORITHMS
    advertised = metadata.get("id_token_signing_alg_values_supported")
    if isinstance(advertised, list):
        algorithms = [alg for alg in ALLOWED_ALGORITHMS if alg in advertised] or algorithms
    token = None
    for refresh in (False, True):  # retry once with fresh keys to survive key rotation
        try:
            token = jwt.decode(
                id_token, _get_keyset(metadata, refresh=refresh), algorithms=algorithms
            )
            break
        except JoseError as exc:
            if refresh:
                raise SsoError(
                    "failed", f"ID token signature invalid: {type(exc).__name__}"
                ) from exc
    assert token is not None
    registry = jwt.JWTClaimsRegistry(
        leeway=_CLOCK_LEEWAY_SECONDS,
        iss={"essential": True, "value": settings.oidc_issuer},
        aud={"essential": True, "value": settings.oidc_client_id},
        exp={"essential": True},
        sub={"essential": True},
        nonce={"essential": True, "value": nonce},
    )
    try:
        registry.validate(token.claims)
    except JoseError as exc:
        raise SsoError("failed", f"ID token claims invalid: {type(exc).__name__}") from exc
    claims = token.claims
    audience = claims.get("aud")
    if (
        isinstance(audience, list)
        and len(audience) > 1
        and claims.get("azp") != settings.oidc_client_id
    ):
        raise SsoError("failed", "ID token has several audiences and a foreign azp")
    return claims


def complete_login(
    db: Session, settings: Settings, *, cookie: str, code: str, state: str
) -> tuple[User, bool]:
    data = verify_state(FLOW, cookie, state)
    try:
        nonce, verifier = data["n"], data["v"]
    except KeyError as exc:
        raise SsoError("failed", "state cookie missing, invalid or expired") from exc

    metadata = get_metadata(settings)
    claims = _verify_id_token(
        settings, metadata, _exchange_code(settings, metadata, code, verifier), nonce
    )
    email = claims.get("email")
    if not isinstance(email, str) or "@" not in email:
        raise SsoError("failed", "ID token has no email claim")
    if claims.get("email_verified") is not True:
        raise SsoError("not_linked", "provider did not verify the email", email=email)
    return resolve_user(db, settings, settings.oidc_issuer, str(claims["sub"]), [email.strip()])
