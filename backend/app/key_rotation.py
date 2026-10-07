"""Re-encrypting stored secrets under the current CREDENTIAL_ENCRYPTION_KEY (a key rotation).

The setting lists the new key first and the old ones after it: the API then encrypts with the new
key and still reads what the old ones encrypted. `python -m app.cli reencrypt-secrets` rewrites
every encrypted value under the new key, after which the old keys can go."""

from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.crypto import fernet
from app.models import Credential, GitSource, NotificationChannel, User, VaultPassword

# Every column holding a Fernet token (tests check no LargeBinary column is missing here).
ENCRYPTED_COLUMNS = (
    (User, ("totp_secret", "totp_pending_secret")),
    (Credential, ("encrypted_private_key", "encrypted_env")),
    (VaultPassword, ("encrypted_password",)),
    (GitSource, ("encrypted_token",)),
    (NotificationChannel, ("config_encrypted",)),
)


class RotationFailed(Exception):
    pass


@dataclass
class RotationResult:
    reencrypted: int = 0
    current: int = 0  # already under the current key


def reencrypt_all(db: Session) -> RotationResult:
    """Rewrites every encrypted value under the current key, in the caller's transaction (rows
    locked as they are read). RotationFailed, naming the row, when no key can decrypt one."""
    keys = fernet()
    current = Fernet(get_settings().credential_encryption_keys[0])
    result = RotationResult()
    for model, columns in ENCRYPTED_COLUMNS:
        for row in db.scalars(select(model).order_by(model.id).with_for_update()):
            for column in columns:
                token = getattr(row, column)
                if token is None:
                    continue
                where = f"{model.__tablename__}.{column} (id {row.id})"
                try:
                    current.decrypt(token)
                except InvalidToken:
                    pass
                else:
                    result.current += 1
                    continue
                try:
                    setattr(row, column, keys.rotate(token))
                except InvalidToken:
                    raise RotationFailed(
                        f"{where}: none of the keys in CREDENTIAL_ENCRYPTION_KEY can decrypt it"
                    ) from None
                result.reencrypted += 1
    db.flush()
    return result
