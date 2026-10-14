"""Passkeys (WebAuthn) as a second factor after the password, beside TOTP.

The relying party is PUBLIC_URL's host (Settings.passkey_rp): https, or http on localhost.
Attestation isn't asked for, and user verification is discouraged (the password was the first
factor). Each ceremony's challenge is kept on the user's row, used once and expires after five
minutes. The authenticator's signature counter is checked after the signature (the library
checks it first, and a forged assertion would then report a counter problem): a counter that
goes back means a cloned authenticator, and that sign-in is refused (synced passkeys count 0
and are never checked).
"""

import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import webauthn
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    parse_registration_credential_json,
)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.config import get_settings
from app.models import User, WebAuthnCredential

RP_NAME = "AnsiDeck"
CHALLENGE_TTL = timedelta(minutes=5)
TIMEOUT_MS = 120_000
MAX_PER_USER = 10
PURPOSES = ("register", "login", "step_up")


class PasskeyError(Exception):
    """A ceremony failed (the message is safe to show; `reason` is for the audit log)."""

    def __init__(self, message: str, reason: str = "bad second factor") -> None:
        super().__init__(message)
        self.reason = reason


class PasskeysUnavailable(PasskeyError):
    def __init__(self) -> None:
        super().__init__(
            "Passkeys need PUBLIC_URL to be an https:// address (or http://localhost)",
            "unavailable",
        )


@dataclass
class NewPasskey:
    credential_id: str
    public_key: str
    sign_count: int
    transports: list[str] | None
    aaguid: str | None
    backup_eligible: bool
    backed_up: bool


def relying_party() -> tuple[str, str]:
    rp = get_settings().passkey_rp
    if rp is None:
        raise PasskeysUnavailable
    return rp


def _descriptors(user: User) -> list[PublicKeyCredentialDescriptor]:
    descriptors = []
    for passkey in user.passkeys:
        transports = []
        for value in passkey.transports or []:
            try:
                transports.append(AuthenticatorTransport(value))
            except ValueError:
                continue
        descriptors.append(
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(passkey.credential_id), transports=transports or None
            )
        )
    return descriptors


def _store_challenge(user: User, challenge: bytes, purpose: str) -> None:
    user.webauthn_pending = {
        "challenge": bytes_to_base64url(challenge),
        "purpose": purpose,
        "expires": (datetime.now(UTC) + CHALLENGE_TTL).isoformat(),
    }


def _take_challenge(user: User, purpose: str) -> bytes:
    """The pending challenge for `purpose`, removed (used once, whatever the outcome)."""
    pending, user.webauthn_pending = user.webauthn_pending, None
    if (
        not isinstance(pending, dict)
        or pending.get("purpose") != purpose
        or datetime.fromisoformat(pending["expires"]) < datetime.now(UTC)
    ):
        raise PasskeyError("That took too long, or another sign-in started: try again", "expired")
    return base64url_to_bytes(pending["challenge"])


def registration_options(user: User) -> dict:
    """Options for navigator.credentials.create(); the caller commits (the challenge)."""
    rp_id, _ = relying_party()
    if len(user.passkeys) >= MAX_PER_USER:
        raise PasskeyError(f"You can have at most {MAX_PER_USER} passkeys", "too many")
    if user.webauthn_user_handle is None:
        user.webauthn_user_handle = bytes_to_base64url(secrets.token_bytes(32))
    options = webauthn.generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_name=user.username,
        user_id=base64url_to_bytes(user.webauthn_user_handle),
        user_display_name=user.username,
        timeout=TIMEOUT_MS,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.DISCOURAGED,
        ),
        exclude_credentials=_descriptors(user),
    )
    _store_challenge(user, options.challenge, "register")
    return json.loads(webauthn.options_to_json(options))


def authentication_options(user: User, purpose: str) -> dict:
    """Options for navigator.credentials.get() with the user's passkeys; the caller commits."""
    rp_id, _ = relying_party()
    if not user.passkeys:
        raise PasskeyError("You have no passkey", "no passkey")
    options = webauthn.generate_authentication_options(
        rp_id=rp_id,
        timeout=TIMEOUT_MS,
        allow_credentials=_descriptors(user),
        user_verification=UserVerificationRequirement.DISCOURAGED,
    )
    _store_challenge(user, options.challenge, purpose)
    return json.loads(webauthn.options_to_json(options))


def verify_registration(user: User, credential: dict) -> NewPasskey:
    """The new passkey from navigator.credentials.create()'s response (PasskeyError)."""
    rp_id, origin = relying_party()
    challenge = _take_challenge(user, "register")
    try:
        verified = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=False,
        )
        transports = parse_registration_credential_json(credential).response.transports
    except (WebAuthnException, ValueError, KeyError, TypeError):
        raise PasskeyError("The passkey couldn't be checked: try again") from None
    return NewPasskey(
        credential_id=bytes_to_base64url(verified.credential_id),
        public_key=bytes_to_base64url(verified.credential_public_key),
        sign_count=verified.sign_count,
        transports=[t.value for t in transports] if transports else None,
        aaguid=verified.aaguid or None,
        backup_eligible=verified.credential_device_type.value == "multi_device",
        backed_up=verified.credential_backed_up,
    )


def verify_assertion(user: User, credential: dict, purpose: str) -> WebAuthnCredential:
    """The user's passkey that signed this navigator.credentials.get() response, its counter
    and last use updated (the caller holds the user's row lock and commits; PasskeyError)."""
    rp_id, origin = relying_party()
    challenge = _take_challenge(user, purpose)
    raw_id = credential.get("rawId") or credential.get("id")
    passkey = next((p for p in user.passkeys if p.credential_id == raw_id), None)
    if passkey is None:
        raise PasskeyError("That passkey isn't one of yours", "unknown passkey")
    try:
        verified = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64url_to_bytes(passkey.public_key),
            credential_current_sign_count=0,  # checked below, after the signature
            require_user_verification=False,
        )
    except (WebAuthnException, ValueError, KeyError, TypeError):
        raise PasskeyError("That passkey was not accepted") from None
    count = verified.new_sign_count
    if (count or passkey.sign_count) and count <= passkey.sign_count:
        raise PasskeyError("That passkey was not accepted", "sign count went back")
    passkey.sign_count = count
    passkey.backed_up = verified.credential_backed_up
    passkey.last_used_at = datetime.now(UTC)
    return passkey
