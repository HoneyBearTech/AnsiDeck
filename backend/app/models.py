from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class RunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


host_group = Table(
    "host_group",
    Base.metadata,
    Column("host_id", ForeignKey("inventory_hosts.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", ForeignKey("inventory_groups.id", ondelete="CASCADE"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Bumped on password change / role change / deactivation; a session token
    # carrying an older value is rejected, so those changes take effect at once.
    session_version: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str | None] = mapped_column(String(150), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # For SSO: an admin sets the email to pre-provision a user; the first SSO sign-in
    # binds (issuer, subject), which is what every later sign-in matches on.
    email: Mapped[str | None] = mapped_column(String(320), default=None)
    sso_issuer: Mapped[str | None] = mapped_column(String(500), default=None)
    sso_subject: Mapped[str | None] = mapped_column(String(255), default=None)

    @property
    def sso_linked(self) -> bool:
        return self.sso_subject is not None


# Unique (NULLs are distinct in SQLite). init_db() creates the same indexes on upgraded DBs.
Index("ux_users_email_lower", func.lower(User.email), unique=True)
Index("ux_users_sso_identity", User.sso_issuer, User.sso_subject, unique=True)


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    description: Mapped[str | None] = mapped_column(String(500), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ProjectMember(Base):
    """A user's role inside one project. Deleting the project or the user removes
    the membership at the DB level (ON DELETE CASCADE)."""

    __tablename__ = "project_members"

    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[str] = mapped_column(String(20))


class ApiKey(Base):
    """A project-owned credential for CI/CD. Only a SHA-256 of the token is stored;
    the plaintext is shown once, at creation. Revoking is a soft delete so the
    history (and audit trail) stays intact."""

    __tablename__ = "api_keys"
    __table_args__ = (UniqueConstraint("project_id", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(64))
    preset: Mapped[str] = mapped_column(String(20))
    prefix: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    token_hash: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(String(150))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    last_used_ip: Mapped[str | None] = mapped_column(String(64), default=None)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    revoked_by: Mapped[str | None] = mapped_column(String(150), default=None)


class Credential(Base):
    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    description: Mapped[str | None] = mapped_column(String(500), default=None)
    encrypted_private_key: Mapped[bytes] = mapped_column(LargeBinary)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class VaultPassword(Base):
    __tablename__ = "vault_passwords"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    description: Mapped[str | None] = mapped_column(String(500), default=None)
    encrypted_password: Mapped[bytes] = mapped_column(LargeBinary)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Playbook(Base):
    """Metadata only — YAML content lives on disk at {data_dir}/playbooks/{id}.yml."""

    __tablename__ = "playbooks"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Inventory(Base):
    __tablename__ = "inventories"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    description: Mapped[str | None] = mapped_column(String(500), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    groups: Mapped[list["InventoryGroup"]] = relationship(
        back_populates="inventory", cascade="all, delete-orphan"
    )
    hosts: Mapped[list["InventoryHost"]] = relationship(
        back_populates="inventory", cascade="all, delete-orphan"
    )


class InventoryGroup(Base):
    __tablename__ = "inventory_groups"
    __table_args__ = (UniqueConstraint("inventory_id", "name", name="uq_group_inventory_name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    inventory_id: Mapped[int] = mapped_column(ForeignKey("inventories.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(255))

    inventory: Mapped["Inventory"] = relationship(back_populates="groups")
    hosts: Mapped[list["InventoryHost"]] = relationship(
        secondary=host_group, back_populates="groups"
    )


class InventoryHost(Base):
    __tablename__ = "inventory_hosts"
    __table_args__ = (
        UniqueConstraint("inventory_id", "hostname", name="uq_host_inventory_hostname"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    inventory_id: Mapped[int] = mapped_column(ForeignKey("inventories.id", ondelete="CASCADE"))
    hostname: Mapped[str] = mapped_column(String(255))
    vars: Mapped[dict] = mapped_column(JSON, default=dict)

    inventory: Mapped["Inventory"] = relationship(back_populates="hosts")
    groups: Mapped[list["InventoryGroup"]] = relationship(
        secondary=host_group, back_populates="hosts"
    )


class Run(Base):
    """Audit/history record of a playbook run. FKs are nullable + SET NULL so
    deleting a playbook/inventory/credential later doesn't break history; the
    *_name columns snapshot the referenced name at trigger time so history
    stays meaningful after a rename or delete."""

    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Authoritative scope for history: the other FKs below are SET NULL.
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))

    playbook_id: Mapped[int | None] = mapped_column(ForeignKey("playbooks.id", ondelete="SET NULL"))
    playbook_name: Mapped[str] = mapped_column(String(255))

    inventory_id: Mapped[int | None] = mapped_column(
        ForeignKey("inventories.id", ondelete="SET NULL")
    )
    inventory_name: Mapped[str] = mapped_column(String(255))

    group_id: Mapped[int | None] = mapped_column(
        ForeignKey("inventory_groups.id", ondelete="SET NULL")
    )
    group_name: Mapped[str | None] = mapped_column(String(255), default=None)

    credential_id: Mapped[int | None] = mapped_column(
        ForeignKey("credentials.id", ondelete="SET NULL")
    )
    credential_name: Mapped[str] = mapped_column(String(150))

    vault_password_id: Mapped[int | None] = mapped_column(
        ForeignKey("vault_passwords.id", ondelete="SET NULL")
    )
    vault_password_name: Mapped[str | None] = mapped_column(String(150), default=None)

    become: Mapped[bool] = mapped_column(Boolean, default=False)
    check_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    diff_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    limit: Mapped[str | None] = mapped_column(String(500), default=None)
    extra_vars: Mapped[dict | None] = mapped_column(JSON, default=None)
    status: Mapped[str] = mapped_column(String(20), default=RunStatus.QUEUED.value)
    triggered_by: Mapped[str] = mapped_column(String(150))
    return_code: Mapped[int | None] = mapped_column(Integer, default=None)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class GalaxyInstall(Base):
    """History/audit record of an ansible-galaxy install. The requirements text
    is snapshotted so history survives later edits to the managed document."""

    __tablename__ = "galaxy_installs"

    id: Mapped[int] = mapped_column(primary_key=True)
    status: Mapped[str] = mapped_column(String(20), default=RunStatus.QUEUED.value)
    triggered_by: Mapped[str] = mapped_column(String(150))
    requirements_snapshot: Mapped[str] = mapped_column(Text)
    upgrade: Mapped[bool] = mapped_column(Boolean, default=False)
    return_code: Mapped[int | None] = mapped_column(Integer, default=None)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditEvent(Base):
    """Security-relevant event trail. Actor/target are snapshots with no FKs so the
    trail survives deleting users or resources. Never store secrets or bodies."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )
    actor_user_id: Mapped[int | None] = mapped_column(Integer, default=None)
    actor_username: Mapped[str | None] = mapped_column(String(150), default=None)
    project_id: Mapped[int | None] = mapped_column(Integer, default=None)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str | None] = mapped_column(String(50), default=None)
    target_id: Mapped[int | None] = mapped_column(Integer, default=None)
    target_name: Mapped[str | None] = mapped_column(String(255), default=None)
    outcome: Mapped[str] = mapped_column(String(20))
    ip: Mapped[str | None] = mapped_column(String(64), default=None)
    detail: Mapped[dict | None] = mapped_column(JSON, default=None)
