"""Environment-variable credentials: named values (an API token, cloud keys) that inventory
plugins read from their environment. Stored encrypted here, or as a secret store path whose
every key becomes a variable. Only refresh jobs receive them, and their values are scrubbed
from what those jobs return."""

import json
import re

from app.crypto import decrypt_secret, encrypt_secret
from app.secret_store import SecretStoreError, read_all_versioned

NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
MAX_VARS = 32
MAX_VALUE_BYTES = 32 * 1024
NAME_RULES = "upper-case letters, digits and '_', starting with a letter (at most 64)"

# Variables that change how the worker, Python, ansible, TLS or the dynamic loader behave, or
# that the worker refuses to hold: an inventory plugin never needs one of these from a user.
_DENIED = frozenset(
    {
        # the process and its shell
        "PATH", "HOME", "TMPDIR", "TMP", "TEMP", "SHELL", "USER", "LOGNAME", "LANG",
        "TZ", "BASH_ENV", "ENV", "IFS", "GCONV_PATH", "GLIBC_TUNABLES", "OPENSSL_CONF",
        "OPENSSL_MODULES", "NODE_OPTIONS", "SSH_AUTH_SOCK", "HOSTALIASES", "NETRC",
        # TLS and proxies
        "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "AWS_CA_BUNDLE", "HTTP_PROXY", "HTTPS_PROXY",
        "NO_PROXY", "ALL_PROXY", "FTP_PROXY",
        # cloud metadata and files: a refresh never falls back to the host's own identity
        # (AWS_CONTAINER_*: an ECS task role) or reads credentials from the worker's files
        "AWS_EC2_METADATA_DISABLED", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        # AnsiDeck's own secrets (FORBIDDEN_ENV in app.worker.__main__)
        "CREDENTIAL_ENCRYPTION_KEY", "DATABASE_URL", "AUTH_SECRET_KEY",
        "SECRETS_STORE_TOKEN_FILE", "SECRETS_STORE_SECRET_ID_FILE", "SECRETS_STORE_ROLE_ID",
        "VAULT_TOKEN", "BAO_TOKEN",
    }
)  # fmt: skip
_DENIED_PREFIXES = (
    "LC_", "LD_", "PYTHON", "ANSIBLE_", "SSL_", "WORKER_", "ANSIDECK_", "DYLD_",
    "AWS_CONTAINER_", "GIT_", "KRB5",
)  # fmt: skip


def name_problem(name: str) -> str | None:
    """Why a variable name can't be used, or None."""
    if not NAME.fullmatch(name):
        return f"{name[:70]!r} is not a valid name ({NAME_RULES})"
    if name in _DENIED or name.startswith(_DENIED_PREFIXES):
        return f"{name} can't be set by a credential"
    return None


def env_problem(env: object) -> str | None:
    """What is wrong with these variables (never their values), or None."""
    if not isinstance(env, dict) or not env:
        return "give at least one variable"
    if len(env) > MAX_VARS:
        return f"at most {MAX_VARS} variables"
    for name, value in env.items():
        problem = name_problem(name) if isinstance(name, str) else "names must be text"
        if problem:
            return problem
        if not isinstance(value, str) or not value:
            return f"{name}: the value must be non-empty text"
        if "\x00" in value or len(value.encode()) > MAX_VALUE_BYTES:
            return f"{name}: the value is too long or contains a NUL byte"
    return None


def check_env(env: dict) -> dict[str, str]:
    """The variables, or ValueError saying what is wrong with them (never their values)."""
    if problem := env_problem(env):
        raise ValueError(problem)
    return dict(env)


def encrypt_env(env: dict[str, str]) -> bytes:
    return encrypt_secret(json.dumps(env, sort_keys=True).encode())


def resolve_env(credential, deadline: float | None = None) -> dict[str, str]:
    """An env credential's variables, from AnsiDeck's database or the secret store
    (SecretStoreError; a secret whose keys aren't usable names is a bad_value)."""
    if credential.store_path is None:
        return json.loads(decrypt_secret(credential.encrypted_env))
    data, _version = read_all_versioned(credential.project_id, credential.store_path, deadline)
    if problem := env_problem(data):
        raise SecretStoreError("bad_value", f"the secret's keys aren't usable: {problem}")
    return data
