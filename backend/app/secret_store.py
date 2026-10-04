"""The secret store (Phase 4F): credentials and vault passwords that live in OpenBao or
HashiCorp Vault (KV v2) instead of AnsiDeck's database. A row holds only a reference (a path
and a key); the value is read when a run starts (or a git source syncs, or the Vault page
uses it) and never written anywhere by AnsiDeck.

Every project reads only its own subtree, <kv mount>/<path prefix>/<project id>/, which this
module builds from the row's own project at read time: a path is a short list of plain
segments (no "..", no empty or dot-led segments, nothing percent-encoded), and the request is
checked to go out exactly as built (httpx itself would collapse ".." before sending, and the
store redirects to cleaned paths: redirects are never followed). Optionally the store keeps
projects apart too: SECRETS_STORE_PROJECT_POLICY reads through a short-lived child token
limited to the project's own store policy.

AnsiDeck logs in with a token from a file (an Agent can keep it fresh) or AppRole (secret id
from a file); tokens and values never reach logs, errors or the database. One job's reads
share a deadline (SECRETS_STORE_TIMEOUT_SECONDS, at most 10 s): the worker gives up on a job
after 15 s.
"""

import contextlib
import logging
import os
import re
import ssl
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

import httpx

from app import metrics
from app.config import get_settings
from app.crypto import decrypt_secret

logger = logging.getLogger(__name__)

SEGMENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$")
MAX_SEGMENTS = 16
MAX_PATH = 400
CONNECT_TIMEOUT = 2.0
READ_TIMEOUT = 4.0
CHILD_TOKEN_TTL = "30s"
# None: the real network. Tests put an httpx.MockTransport here.
default_transport: httpx.BaseTransport | None = None

_KIND_TEXT = {
    "disabled": "no secret store is configured",
    "invalid": "invalid path or key: use up to 16 segments separated by '/', each of letters, "
    "digits, '.', '_' or '-' (not starting with '.' or '-')",
    "unreachable": "the secret store can't be reached",
    "tls": "the secret store's TLS certificate is not trusted",
    "sealed": "the secret store is sealed",
    "auth_failed": "AnsiDeck could not log in to the secret store",
    "denied": "permission denied by the secret store",
    "not_found": "no secret at that path",
    "missing_key": "the secret has no such key",
    "bad_value": "the value is not text",
    "bad_response": "unexpected answer from the secret store",
}
# Kinds that mean the store as a whole is unusable (an ops alert), not one bad reference.
OUTAGE_KINDS = frozenset({"unreachable", "tls", "sealed", "auth_failed"})


class SecretStoreError(Exception):
    """A read failed. `kind` is one of _KIND_TEXT; the message is safe to show (it never
    holds a token, a value or the store's own response)."""

    def __init__(self, kind: str, detail: str | None = None) -> None:
        self.kind = kind
        super().__init__(detail or _KIND_TEXT[kind])


def explain(kind: str) -> str:
    """What to tell a user about an error kind (a fixed text: no store response, path or
    value ever reaches them through it)."""
    return _KIND_TEXT.get(kind, _KIND_TEXT["bad_response"])


PATH_RULES = (
    "use up to 16 segments separated by '/', each of letters, digits, '.', '_' or '-' "
    "(not starting with '.' or '-')"
)


def reference_fields(row) -> dict:
    """The secret store fields of a credential or vault password, for API responses."""
    if row.store_path is None:
        return {"store": "ansideck", "store_path": None, "store_key": None, "store_location": None}
    return {
        "store": "external",
        "store_path": row.store_path,
        "store_key": row.store_key,
        "store_location": location(row.project_id, row.store_path, row.store_key),
    }


def check_path(path: str) -> list[str]:
    """The path's segments, or SecretStoreError("invalid")."""
    segments = (path or "").split("/")
    if (
        not path
        or len(path) > MAX_PATH
        or len(segments) > MAX_SEGMENTS
        or not all(SEGMENT.match(s) for s in segments)
    ):
        raise SecretStoreError("invalid")
    return segments


def check_key(key: str) -> str:
    if not SEGMENT.match(key or ""):
        raise SecretStoreError("invalid")
    return key


def base_path(project_id: int) -> str:
    """Where a project's references live, for display: e.g. secret/ansideck/7/."""
    settings = get_settings()
    return f"{settings.secrets_store_kv_mount}/{settings.secrets_store_path_prefix}/{project_id}/"


def location(project_id: int, path: str, key: str) -> str:
    return f"{base_path(project_id)}{path}#{key}"


def _api_path(*segments: str) -> str:
    return "/v1/" + "/".join(quote(segment, safe="") for segment in segments)


@dataclass
class _Token:
    value: str
    refresh_at: float  # monotonic; re-login (or re-read the file) after this


class _Client:
    """One per process. Login state is shared by the threads that build jobs and sync git."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._token: _Token | None = None
        self._token_file_mtime: float | None = None

    def forget_token(self) -> None:
        with self._lock:
            self._token = None
            self._token_file_mtime = None

    # --- transport ---------------------------------------------------------------------

    @contextlib.contextmanager
    def _http(self) -> Iterator[httpx.Client]:
        settings = get_settings()
        verify: ssl.SSLContext | bool = True
        if settings.secrets_store_ca_cert:
            verify = ssl.create_default_context(cafile=settings.secrets_store_ca_cert)
        with httpx.Client(
            base_url=settings.secrets_store_url.rstrip("/"),
            transport=default_transport,
            verify=verify,
            follow_redirects=False,
            trust_env=False,  # no proxy: the store is on a trusted network
        ) as client:
            yield client

    def _request(
        self,
        method: str,
        path: str,
        deadline: float,
        *,
        token: str | None = None,
        json: dict | None = None,
    ) -> httpx.Response:
        settings = get_settings()
        headers = {"X-Vault-Request": "true"}
        if token:
            headers["X-Vault-Token"] = token
        if settings.secrets_store_namespace:
            headers["X-Vault-Namespace"] = settings.secrets_store_namespace
        for attempt in range(2):
            remaining = deadline - time.monotonic()
            if remaining <= 0.05:
                budget = settings.secrets_store_timeout_seconds
                raise SecretStoreError(
                    "unreachable", f"the secret store didn't answer within {budget:g} s"
                )
            timeout = httpx.Timeout(
                min(READ_TIMEOUT, remaining), connect=min(CONNECT_TIMEOUT, remaining)
            )
            try:
                with self._http() as client:
                    request = client.build_request(
                        method, path, headers=headers, json=json, timeout=timeout
                    )
                    # Exactly as built: httpx itself would collapse "..".
                    expected = urlsplit(settings.secrets_store_url).path.rstrip("/") + path
                    if request.url.raw_path != expected.encode():
                        raise SecretStoreError("invalid")
                    return client.send(request)
            except httpx.ConnectError as exc:
                if isinstance(exc.__context__, ssl.SSLError) or "CERTIFICATE" in str(exc):
                    raise SecretStoreError("tls") from None
                if attempt == 0:
                    continue  # one retry: a restarting store or a dropped connection
                raise SecretStoreError("unreachable") from None
            except httpx.TimeoutException:
                raise SecretStoreError("unreachable") from None
            except httpx.HTTPError:
                raise SecretStoreError("unreachable") from None
        raise SecretStoreError("unreachable")

    @staticmethod
    def _fail(response: httpx.Response, *, forbidden: str = "denied") -> SecretStoreError:
        if response.status_code == 403:
            return SecretStoreError(forbidden)
        if response.status_code == 404:
            return SecretStoreError("not_found")
        if response.status_code == 503 and b"sealed" in response.content.lower():
            return SecretStoreError("sealed")
        if response.status_code == 503:
            return SecretStoreError("unreachable")
        return SecretStoreError(
            "bad_response", f"unexpected answer from the secret store (HTTP {response.status_code})"
        )

    # --- login ---------------------------------------------------------------------------

    def _token_from_file(self) -> str:
        path = get_settings().secrets_store_token_file
        try:
            mtime = os.stat(path).st_mtime
            if self._token is None or mtime != self._token_file_mtime:
                with open(path) as handle:
                    value = handle.read().strip()
                if not value:
                    raise SecretStoreError("auth_failed", "the secret store token file is empty")
                self._token = _Token(value, float("inf"))
                self._token_file_mtime = mtime
        except OSError as exc:
            raise SecretStoreError(
                "auth_failed", "the secret store token file can't be read"
            ) from exc
        return self._token.value

    def _approle_login(self, deadline: float) -> str:
        settings = get_settings()
        try:
            with open(settings.secrets_store_secret_id_file) as handle:
                secret_id = handle.read().strip()
        except OSError as exc:
            raise SecretStoreError(
                "auth_failed", "the AppRole secret id file can't be read"
            ) from exc
        response = self._request(
            "POST",
            _api_path("auth", settings.secrets_store_approle_mount, "login"),
            deadline,
            json={"role_id": settings.secrets_store_role_id, "secret_id": secret_id},
        )
        if response.status_code in (400, 403):
            raise SecretStoreError("auth_failed")
        if response.status_code != 200:
            raise self._fail(response, forbidden="auth_failed")
        try:
            auth = response.json()["auth"]
            token, ttl = str(auth["client_token"]), int(auth.get("lease_duration") or 0)
        except (ValueError, KeyError, TypeError):
            raise SecretStoreError("bad_response") from None
        # Log in again once two thirds of the token's life are gone (no renewal needed).
        refresh = time.monotonic() + (ttl * 2 / 3 if ttl > 0 else 3600)
        self._token = _Token(token, refresh)
        return token

    def token(self, deadline: float) -> str:
        with self._lock:
            if get_settings().secrets_store_auth == "token":
                return self._token_from_file()
            if self._token is not None and time.monotonic() < self._token.refresh_at:
                return self._token.value
            return self._approle_login(deadline)

    def _child_token(self, parent: str, project_id: int, deadline: float) -> str:
        policy = get_settings().secrets_store_project_policy.replace(
            "{project_id}", str(project_id)
        )
        response = self._request(
            "POST",
            _api_path("auth", "token", "create"),
            deadline,
            token=parent,
            json={
                "policies": [policy],
                "ttl": CHILD_TOKEN_TTL,
                "num_uses": 1,
                "no_default_policy": True,
                "renewable": False,
                "display_name": f"ansideck-project-{project_id}",
            },
        )
        if response.status_code == 400:  # a policy AnsiDeck's own token doesn't hold
            raise SecretStoreError(
                "denied", f"store policy {policy!r} is not available to AnsiDeck"
            )
        if response.status_code != 200:
            raise self._fail(response)
        try:
            return str(response.json()["auth"]["client_token"])
        except (ValueError, KeyError, TypeError):
            raise SecretStoreError("bad_response") from None

    # --- reading -------------------------------------------------------------------------

    def read(self, project_id: int, path: str, key: str, deadline: float) -> tuple[str, int]:
        """(value, version) of one key of a project's secret."""
        settings = get_settings()
        segments = check_path(path)
        check_key(key)
        api_path = _api_path(
            settings.secrets_store_kv_mount,
            "data",
            settings.secrets_store_path_prefix,
            str(int(project_id)),
            *segments,
        )
        for attempt in range(2):
            relogin = attempt == 0 and settings.secrets_store_auth == "approle"
            token = self.token(deadline)
            if settings.secrets_store_project_policy:
                try:
                    token = self._child_token(token, project_id, deadline)
                except SecretStoreError as exc:
                    # A revoked token (403), or one from before the role was given this
                    # project's policy (400): log in once more, as below.
                    if relogin and exc.kind == "denied":
                        self.forget_token()
                        continue
                    raise
            response = self._request("GET", api_path, deadline, token=token)
            if response.status_code == 403 and relogin:
                # A revoked or expired token looks like a denial: log in once more.
                self.forget_token()
                continue
            break
        if response.status_code != 200:
            raise self._fail(response)
        try:
            body = response.json()["data"]
            data = body.get("data")
            version = int((body.get("metadata") or {}).get("version") or 0)
        except (ValueError, KeyError, TypeError, AttributeError):
            raise SecretStoreError("bad_response") from None
        if data is None:  # a deleted or destroyed version
            raise SecretStoreError("not_found")
        if not isinstance(data, dict) or key not in data:
            raise SecretStoreError("missing_key")
        value = data[key]
        if not isinstance(value, str) or not value:
            raise SecretStoreError("bad_value")
        return value, version

    def health(self, deadline: float) -> dict:
        """For the probe: reachable, sealed, version, token TTL (seconds) or the error."""
        status: dict = {"reachable": False, "sealed": None, "version": None, "token_ttl": None}
        response = self._request("GET", "/v1/sys/health", deadline)
        status["reachable"] = True
        try:
            body = response.json()
            status["sealed"] = bool(body.get("sealed"))
            status["version"] = str(body.get("version") or "")[:40] or None
        except ValueError:
            pass
        if status["sealed"]:
            raise SecretStoreError("sealed")
        token = self.token(deadline)
        lookup = self._request(
            "GET", _api_path("auth", "token", "lookup-self"), deadline, token=token
        )
        if lookup.status_code == 403 and get_settings().secrets_store_auth == "approle":
            self.forget_token()
            token = self.token(deadline)
            lookup = self._request(
                "GET", _api_path("auth", "token", "lookup-self"), deadline, token=token
            )
        if lookup.status_code != 200:
            raise self._fail(lookup, forbidden="auth_failed")
        with contextlib.suppress(ValueError, KeyError, TypeError):
            status["token_ttl"] = int(lookup.json()["data"].get("ttl") or 0) or None
        return status


_client = _Client()


def enabled() -> bool:
    return get_settings().secrets_store_enabled


def _deadline() -> float:
    return time.monotonic() + get_settings().secrets_store_timeout_seconds


def read_secret(project_id: int, path: str, key: str, deadline: float | None = None) -> str:
    """One referenced value; SecretStoreError when it can't be had."""
    return read_versioned(project_id, path, key, deadline)[0]


def read_versioned(
    project_id: int, path: str, key: str, deadline: float | None = None
) -> tuple[str, int]:
    if not enabled():
        raise SecretStoreError("disabled")
    try:
        result = _client.read(project_id, path, key, deadline or _deadline())
    except SecretStoreError as exc:
        metrics.secret_store_read(exc.kind)
        raise
    metrics.secret_store_read("ok")
    return result


def resolve_credential(credential, deadline: float | None = None) -> str:
    """A credential's private key, from AnsiDeck's database or the secret store."""
    if credential.store_path is None:
        return decrypt_secret(credential.encrypted_private_key).decode()
    return read_secret(credential.project_id, credential.store_path, credential.store_key, deadline)


def resolve_vault_password(vault_password, deadline: float | None = None) -> str:
    if vault_password.store_path is None:
        return decrypt_secret(vault_password.encrypted_password).decode()
    return read_secret(
        vault_password.project_id, vault_password.store_path, vault_password.store_key, deadline
    )


def new_deadline() -> float:
    """One budget for every read a job needs."""
    return _deadline()


# --- the probe ----------------------------------------------------------------------------

_status_lock = threading.Lock()
_status: dict = {"enabled": False}


def probe() -> dict:
    """Checks the store (health, login, token) and records the result for the status API
    and the ops alert. Never raises."""
    settings = get_settings()
    result: dict = {
        "enabled": enabled(),
        "label": settings.secrets_store_label,
        "url": settings.secrets_store_url or None,
        "checked_at": time.time(),
        "ok": False,
        "error_kind": None,
        "error": None,
    }
    if enabled():
        try:
            result.update(_client.health(_deadline()))
            result["ok"] = True
        except SecretStoreError as exc:
            result["error_kind"], result["error"] = exc.kind, str(exc)
        metrics.secret_store_up(result["ok"])
    with _status_lock:
        previous_ok = _status.get("last_ok_at")
        result["last_ok_at"] = result["checked_at"] if result["ok"] else previous_ok
        _status.clear()
        _status.update(result)
    return dict(result)


def status() -> dict:
    with _status_lock:
        return dict(_status) if _status.get("checked_at") else {"enabled": enabled()}


def reset() -> None:
    """Forget login and probe state (tests, config changes)."""
    _client.forget_token()
    with _status_lock:
        _status.clear()
        _status["enabled"] = False
