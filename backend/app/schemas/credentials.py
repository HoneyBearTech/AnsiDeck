from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class CredentialCreate(BaseModel):
    """kind "ssh": either `private_key` (stored encrypted here) or a secret store reference,
    `store_path` under the project's own subtree and `store_key` in that secret.
    kind "env": either `env` (named variables, stored encrypted here) or `store_path`, a
    secret whose every key becomes a variable.
    kind "ssh_cert": no secret; `ssh_role` (project-local) and `ssh_principals`, and the
    secret store's SSH engine mount `ssh_mount` (default: the first of
    SECRETS_STORE_SSH_MOUNTS). Each run gets a new key and a certificate for it."""

    name: str
    description: str | None = None
    kind: Literal["ssh", "env", "ssh_cert"] = "ssh"
    private_key: str | None = None
    env: dict[str, str] | None = None
    store_path: str | None = Field(None, max_length=400)
    store_key: str | None = Field(None, max_length=100)
    ssh_mount: str | None = Field(None, max_length=100)
    ssh_role: str | None = Field(None, max_length=64)
    ssh_principals: list[str] | None = Field(None, max_length=16)
    project_id: int | None = None

    @model_validator(mode="after")
    def _one_source(self) -> "CredentialCreate":
        certificate_fields = (self.ssh_mount, self.ssh_role, self.ssh_principals)
        if self.kind == "ssh_cert":
            if any(
                v is not None for v in (self.private_key, self.env, self.store_path, self.store_key)
            ):
                raise ValueError(
                    "an SSH certificate credential holds ssh_mount, ssh_role and ssh_principals "
                    "only"
                )
            if not self.ssh_role or not self.ssh_principals:
                raise ValueError("an SSH certificate credential needs ssh_role and ssh_principals")
            return self
        if any(v is not None for v in certificate_fields):
            raise ValueError("ssh_mount, ssh_role and ssh_principals are for kind ssh_cert")
        value = self.private_key if self.kind == "ssh" else self.env
        other = self.env if self.kind == "ssh" else self.private_key
        if other is not None:
            raise ValueError("an ssh credential holds private_key, an env credential env")
        if (value is None) == (self.store_path is None):
            field = "private_key" if self.kind == "ssh" else "env"
            raise ValueError(f"give either {field} or store_path")
        if self.kind == "env":
            if self.store_key is not None:
                raise ValueError("an env credential reads the whole secret: no store_key")
        elif self.store_path is not None and not self.store_key:
            self.store_key = "private_key"
        return self


class CredentialOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    project_id: int
    created_at: datetime
    kind: Literal["ssh", "env", "ssh_cert"] = "ssh"
    # An env credential's variable names (never their values); None when they live in the
    # secret store (they are whatever keys the secret has).
    env_names: list[str] | None = None
    # "ansideck": encrypted in AnsiDeck's database; "external": in the secret store.
    store: Literal["ansideck", "external"] = "ansideck"
    store_path: str | None = None
    store_key: str | None = None
    store_location: str | None = None
    # An SSH certificate credential: the store's SSH engine mount, the project-local role name
    # and the store's role it stands for (<prefix>-<project id>-<role>), and the principals.
    ssh_mount: str | None = None
    ssh_role: str | None = None
    ssh_role_full: str | None = None
    ssh_principals: list[str] | None = None


class SshCertificateInfo(BaseModel):
    """An SSH certificate the secret store signed (for a run, or a credential's test)."""

    serial: str  # decimal, as targets' sshd logs it
    serial_hex: str
    key_id: str
    principals: list[str]
    valid_after: datetime
    valid_before: datetime
    ca_fingerprint: str
    key_fingerprint: str
    location: str
    requested_seconds: int
    # The role's maximum TTL was shorter than asked for: the certificate expires sooner.
    capped: bool = False


class SecretCheck(BaseModel):
    """Whether a stored secret can be read (never its value)."""

    ok: bool
    version: int | None = None
    # An env credential in the secret store: the variable names it holds now.
    env_names: list[str] | None = None
    # An SSH certificate credential: the test certificate the store signed (its key is gone).
    certificate: SshCertificateInfo | None = None
    error_kind: str | None = None
    error: str | None = None
