"""Short-lived SSH certificates for runs: an "SSH certificate" credential holds no secret, only
the secret store's SSH engine mount, a project-local role name and the principals (the users
the certificate may log in as). When a run's job is built, the API makes a fresh ed25519 key
pair, has the store sign its public key with the role <path prefix>-<project id>-<role> for
the run's timeout plus GRACE_SECONDS, checks the certificate it gets back, and sends key and
certificate in the job. The run process puts the certificate next to ansible-runner's key so
that ssh-add loads both into the run's ssh-agent (app.run_worker). The key pair is never
stored; the run keeps the (public) certificate and its serial, which targets' sshd logs show.

The store refuses (doesn't cap) a TTL over the role's maximum: AnsiDeck then asks once more
for that maximum, and the run page says the certificate may expire before the run ends.
"""

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import secret_store
from app.config import get_settings
from app.secret_store import SecretStoreError, TtlTooLong

GRACE_SECONDS = 300  # past the run's timeout: the reaper's grace and a slow start fit in it
TEST_SECONDS = 60  # a credential's test certificate (the key is thrown away at once)
MIN_SECONDS = 60  # a role that caps certificates below this can't be used
MAX_PRINCIPALS = 16

# OpenBao role names start and end with a word character; principals are login names (no
# commas: the store splits valid_principals on them).
ROLE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,62}[A-Za-z0-9_])?$")
PRINCIPAL = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$")
ROLE_RULES = (
    "use up to 64 letters, digits, '.', '_' or '-' (starting and ending with a letter, digit "
    "or '_')"
)


def check_role(role: str) -> str:
    if not ROLE.fullmatch(role or ""):
        raise ValueError(f"Invalid SSH role name: {ROLE_RULES}")
    return role


def check_principals(principals: list[str]) -> list[str]:
    """Deduplicated (order kept); ValueError with a message for the user."""
    cleaned = list(dict.fromkeys(p.strip() for p in principals if p and p.strip()))
    if not cleaned:
        raise ValueError("Name at least one principal (a user the certificate may log in as)")
    if len(cleaned) > MAX_PRINCIPALS:
        raise ValueError(f"At most {MAX_PRINCIPALS} principals")
    for principal in cleaned:
        if not PRINCIPAL.fullmatch(principal):
            raise ValueError(
                f"Invalid principal {principal[:70]!r}: use letters, digits, '.', '_', '@' or '-'"
            )
    return cleaned


def check_mount(mount: str) -> str:
    """A mount listed in SECRETS_STORE_SSH_MOUNTS; ValueError otherwise."""
    settings = get_settings()
    mounts = settings.secrets_store_ssh_mount_list
    if not settings.secrets_store_enabled:
        raise ValueError("No secret store is configured")
    if not mounts:
        raise ValueError("SSH certificates aren't enabled: set SECRETS_STORE_SSH_MOUNTS")
    if mount not in mounts:
        raise ValueError(f"SSH engine mount {mount[:100]!r} isn't one of SECRETS_STORE_SSH_MOUNTS")
    return mount


def run_credential_problem(credential) -> str | None:
    """Why a run can't log in with this credential now (for the trigger and templates)."""
    if credential.kind not in ("ssh", "ssh_cert"):
        return "A run needs an SSH key or SSH certificate credential"
    if credential.kind == "ssh_cert":
        try:
            check_mount(credential.ssh_mount)
        except ValueError as exc:
            return f"Credential '{credential.name}' can't be used: {exc}"
    return None


def new_key_pair() -> tuple[str, str]:
    """(private key as OpenSSH PEM, public key line) of a fresh ed25519 key."""
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode()
    public = (
        key.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )
    return private, public


def _fingerprint(public_key) -> str:
    """OpenSSH's SHA256 fingerprint of a public key object."""
    line = public_key.public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    digest = hashlib.sha256(base64.b64decode(line.split()[1])).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def _iso(seconds: int) -> str:
    # OpenSSH uses 2**64 - 1 for "forever"; clamp to what datetime can hold.
    return datetime.fromtimestamp(min(seconds, 253402300799), UTC).isoformat()


def describe(certificate: str, public_key: str, principals: list[str]) -> dict:
    """What the run records about the store's certificate, after checking it is a user
    certificate of our key for exactly our principals, with a valid CA signature."""
    try:
        parsed = serialization.load_ssh_public_identity(certificate.strip().encode())
        ours = serialization.load_ssh_public_key(public_key.encode())
        if not isinstance(parsed, serialization.SSHCertificate):
            raise ValueError("not a certificate")
        if parsed.type != serialization.SSHCertificateType.USER:
            raise ValueError("not a user certificate")
        if _fingerprint(parsed.public_key()) != _fingerprint(ours):
            raise ValueError("another key")
        granted = sorted(p.decode() for p in parsed.valid_principals)
        if granted != sorted(principals):
            raise ValueError("other principals")
        parsed.verify_cert_signature()
    except (ValueError, TypeError, UnicodeDecodeError, InvalidSignature):
        raise SecretStoreError("bad_certificate") from None
    return {
        "serial": str(parsed.serial),  # decimal, as sshd logs it (it may exceed int64)
        "serial_hex": format(parsed.serial, "x"),
        "key_id": parsed.key_id.decode(errors="replace")[:200],
        "principals": [p.decode() for p in parsed.valid_principals],
        "valid_after": _iso(parsed.valid_after),
        "valid_before": _iso(parsed.valid_before),
        "ca_fingerprint": _fingerprint(parsed.signature_key()),
        "key_fingerprint": _fingerprint(ours),
    }


@dataclass
class Issued:
    private_key: str
    certificate: str
    info: dict


def issue(credential, seconds: int, deadline: float) -> Issued:
    """A fresh key pair and the store's certificate for it, valid for `seconds` (or the role's
    maximum, once, when that is shorter). SecretStoreError when the store won't sign."""
    if credential.kind != "ssh_cert":
        raise RuntimeError(f"credential {credential.id} is not an SSH certificate credential")
    principals = list(credential.ssh_principals or [])
    private_key, public_key = new_key_pair()
    requested, capped = int(seconds), False

    def sign(ttl: int) -> dict:
        return secret_store.sign_ssh_key(
            credential.project_id,
            credential.ssh_mount,
            credential.ssh_role,
            public_key,
            principals,
            ttl,
            deadline,
        )

    try:
        answer = sign(requested)
    except TtlTooLong as exc:
        if exc.maximum < MIN_SECONDS or exc.maximum >= requested:
            raise
        capped = True
        answer = sign(exc.maximum)
    certificate = answer["signed_key"].strip()
    info = describe(certificate, public_key, principals)
    info.update(
        {
            "location": secret_store.ssh_location(
                credential.project_id, credential.ssh_mount, credential.ssh_role
            ),
            "requested_seconds": requested,
            "capped": capped,
        }
    )
    return Issued(private_key, certificate, info)


def issue_for_run(credential, run, deadline: float) -> Issued:
    return issue(credential, run.timeout_seconds + GRACE_SECONDS, deadline)


def sign_test_certificate(credential) -> dict:
    """Signs a throwaway key (thrown away at once): what a credential's Test shows."""
    return issue(credential, TEST_SECONDS, secret_store.new_deadline()).info
