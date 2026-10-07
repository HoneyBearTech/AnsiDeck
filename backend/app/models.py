from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
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
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class RunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


# A run is "cancelling" while it is still running with cancel_requested_at set.
FINISHED_STATUSES = frozenset(
    {RunStatus.SUCCESS, RunStatus.FAILED, RunStatus.CANCELLED, RunStatus.TIMED_OUT}
)
DEFAULT_RUN_TIMEOUT_SECONDS = 2 * 60 * 60
MAX_RUN_TIMEOUT_SECONDS = 24 * 60 * 60


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
    # TOTP two-factor login (opt-in, password logins only). Secrets are Fernet-encrypted;
    # the pending one exists only between setup and the first valid code.
    totp_secret: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)
    totp_pending_secret: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)
    # Highest time step already accepted, so a code can't be used twice.
    totp_last_counter: Mapped[int | None] = mapped_column(Integer, default=None)
    # SHA-256 hex of each unused recovery code.
    totp_recovery_hashes: Mapped[list[str] | None] = mapped_column(JSON, default=None)

    @property
    def sso_linked(self) -> bool:
        return self.sso_subject is not None

    @property
    def totp_enabled(self) -> bool:
        return self.totp_secret is not None


# Unique; NULLs are distinct, so any number of users may have no email / no SSO identity.
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
    # The key works only while this user is active and may still manage the project's keys
    # (app.api_keys.creator_problem); NULL once they are deleted.
    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True, default=None
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    last_used_ip: Mapped[str | None] = mapped_column(String(64), default=None)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    revoked_by: Mapped[str | None] = mapped_column(String(150), default=None)


CREDENTIAL_KINDS = ("ssh", "env")


class Credential(Base):
    __tablename__ = "credentials"
    __table_args__ = (
        CheckConstraint("kind IN ('ssh', 'env')", name="kind"),
        CheckConstraint(
            "CASE kind"
            " WHEN 'ssh' THEN encrypted_env IS NULL"
            " AND (encrypted_private_key IS NULL) <> (store_path IS NULL)"
            " AND (store_path IS NULL) = (store_key IS NULL)"
            " WHEN 'env' THEN encrypted_private_key IS NULL AND store_key IS NULL"
            " AND (encrypted_env IS NULL) <> (store_path IS NULL)"
            " ELSE false END",
            name="secret_by_kind",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    description: Mapped[str | None] = mapped_column(String(500), default=None)
    # "ssh": a private key for runs and git deploy keys. "env": named variables (an API
    # token) for inventory plugins (app.env_credentials).
    kind: Mapped[str] = mapped_column(String(10), default="ssh", server_default="ssh")
    # Either encrypted here, or a reference into the secret store (app.secret_store): a path
    # under the project's own subtree and, for a key, the key in that secret (an env
    # credential takes every key). Never both (a CHECK constraint).
    encrypted_private_key: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)
    encrypted_env: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)
    # An env credential's variable names (not secret), for display.
    env_names: Mapped[list | None] = mapped_column(JSON, default=None)
    store_path: Mapped[str | None] = mapped_column(String(400), default=None)
    store_key: Mapped[str | None] = mapped_column(String(100), default=None)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class VaultPassword(Base):
    __tablename__ = "vault_passwords"
    __table_args__ = (
        CheckConstraint("(encrypted_password IS NULL) <> (store_path IS NULL)", name="one_secret"),
        CheckConstraint("(store_path IS NULL) = (store_key IS NULL)", name="store_ref"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    description: Mapped[str | None] = mapped_column(String(500), default=None)
    # Encrypted here, or a reference into the secret store (see Credential).
    encrypted_password: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)
    store_path: Mapped[str | None] = mapped_column(String(400), default=None)
    store_key: Mapped[str | None] = mapped_column(String(100), default=None)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Playbook(Base):
    """Metadata only — YAML content lives on disk at {data_dir}/playbooks/{id}.yml. A playbook
    with a source_id is synced from git (read-only here; the file on disk is a display copy
    of it at the source's current commit)."""

    __tablename__ = "playbooks"
    __table_args__ = (UniqueConstraint("source_id", "repo_path"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    source_id: Mapped[int | None] = mapped_column(
        ForeignKey("git_sources.id", ondelete="CASCADE"), index=True, default=None
    )
    repo_path: Mapped[str | None] = mapped_column(String(1024), default=None)
    # Set while the file is gone from the source's current commit (it comes back if it does).
    missing_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)


class GitSource(Base):
    """A git repository a project's playbooks are synced from (app.git_sync). Its token is
    encrypted and write-only; an SSH source uses one of the project's credentials as its
    deploy key, and syncs only once an admin trusted the server's host key."""

    __tablename__ = "git_sources"
    __table_args__ = (UniqueConstraint("project_id", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(100))
    url: Mapped[str] = mapped_column(String(500))
    branch: Mapped[str] = mapped_column(String(255), default="main")
    subdir: Mapped[str | None] = mapped_column(String(500), default=None)
    web_url: Mapped[str | None] = mapped_column(String(500), default=None)  # commit links
    playbook_globs: Mapped[list[str]] = mapped_column(JSON, default=list)
    auth_kind: Mapped[str] = mapped_column(String(20), default="none")
    credential_id: Mapped[int | None] = mapped_column(
        ForeignKey("credentials.id", ondelete="RESTRICT"), index=True, default=None
    )
    https_username: Mapped[str | None] = mapped_column(String(255), default=None)
    encrypted_token: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)
    ssh_known_hosts: Mapped[str | None] = mapped_column(Text, default=None)
    auto_sync_seconds: Mapped[int] = mapped_column(Integer, default=300)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    current_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("git_snapshots.id", ondelete="SET NULL", use_alter=True), default=None
    )
    sync_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    last_sync_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    last_sync_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    last_sync_status: Mapped[str | None] = mapped_column(String(10), default=None)
    last_sync_error: Mapped[str | None] = mapped_column(String(1000), default=None)
    created_by: Mapped[str] = mapped_column(String(150))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class GitSnapshot(Base):
    """One synced commit of a source: an immutable tar of its tree on disk
    ({data_dir}/git/snapshots/<source>/<commit>.tar) that runs execute in."""

    __tablename__ = "git_snapshots"
    __table_args__ = (UniqueConstraint("source_id", "commit"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(
        ForeignKey("git_sources.id", ondelete="CASCADE"), index=True
    )
    commit: Mapped[str] = mapped_column(String(64))
    commit_subject: Mapped[str] = mapped_column(String(255), default="")
    commit_author: Mapped[str] = mapped_column(String(255), default="")
    committed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    file_count: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    warnings: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # When a newer commit replaced it; pruned once no run needs it.
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)


class Inventory(Base):
    __tablename__ = "inventories"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    description: Mapped[str | None] = mapped_column(String(500), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # Dynamic sources (Phase 4G): refreshed every this many seconds (0: only on demand), and
    # the snapshot runs use now (the newest good refresh).
    refresh_interval_seconds: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    current_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("inventory_snapshots.id", ondelete="SET NULL", use_alter=True), default=None
    )

    groups: Mapped[list["InventoryGroup"]] = relationship(
        back_populates="inventory", cascade="all, delete-orphan"
    )
    sources: Mapped[list["InventorySource"]] = relationship(
        back_populates="inventory",
        cascade="all, delete-orphan",
        order_by="InventorySource.position",
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


class InventorySource(Base):
    """A dynamic inventory source: an inventory plugin's config (YAML with a `plugin:` key),
    run by ansible-inventory in an isolated worker when the inventory is refreshed."""

    __tablename__ = "inventory_sources"
    __table_args__ = (UniqueConstraint("inventory_id", "name", name="uq_inventory_source_name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    inventory_id: Mapped[int] = mapped_column(
        ForeignKey("inventories.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(100))
    plugin: Mapped[str] = mapped_column(String(200))  # from the config, for display
    config: Mapped[str] = mapped_column(Text)
    # An env credential (app.env_credentials) the plugin reads its API token from.
    credential_id: Mapped[int | None] = mapped_column(
        ForeignKey("credentials.id", ondelete="RESTRICT"), index=True, default=None
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    position: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_by: Mapped[str] = mapped_column(String(150))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    inventory: Mapped["Inventory"] = relationship(back_populates="sources")


class InventoryRefresh(Base):
    """One refresh of an inventory's sources: queued, claimed by a worker (like a run, with a
    lease and one-time tokens), and ended with a snapshot or an error."""

    __tablename__ = "inventory_refreshes"
    __table_args__ = (
        # One queued and one running refresh per inventory: repeated requests merge.
        Index(
            "ux_inventory_refreshes_queued",
            "inventory_id",
            unique=True,
            postgresql_where=text("status = 'queued'"),
        ),
        Index(
            "ux_inventory_refreshes_running",
            "inventory_id",
            unique=True,
            postgresql_where=text("status = 'running'"),
        ),
        Index(
            "ix_inventory_refreshes_queue",
            "queued_at",
            "id",
            postgresql_where=text("status = 'queued'"),
        ),
        Index(
            "ix_inventory_refreshes_lease",
            "lease_expires_at",
            postgresql_where=text("status = 'running'"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    inventory_id: Mapped[int] = mapped_column(
        ForeignKey("inventories.id", ondelete="CASCADE"), index=True
    )
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    status: Mapped[str] = mapped_column(String(20), default=RunStatus.QUEUED.value)
    # manual | schedule | sources_changed | static_changed
    trigger: Mapped[str] = mapped_column(String(20))
    requested_by: Mapped[str | None] = mapped_column(String(150), default=None)
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    timeout_seconds: Mapped[int] = mapped_column(Integer)
    worker_id: Mapped[str | None] = mapped_column(String(255), default=None)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    claim_token_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    job_token_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    job_token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    # What it ran: {"sources": [{"id", "name", "plugin", "sha256"}] (never the configs),
    # "static_hosts": [the inventory's own hosts it fed to the plugins]}.
    sources: Mapped[dict | None] = mapped_column(JSON, default=None)
    output_bytes: Mapped[int | None] = mapped_column(Integer, default=None)
    error: Mapped[str | None] = mapped_column(String(1000), default=None)
    snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("inventory_snapshots.id", ondelete="SET NULL"), default=None
    )


class InventorySnapshot(Base):
    """What a refresh found, normalised (app.inventory_sources.normalise): {"vars", "hosts",
    "groups", "static_hosts"}. Runs pin the current one when they are triggered."""

    __tablename__ = "inventory_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    inventory_id: Mapped[int] = mapped_column(
        ForeignKey("inventories.id", ondelete="CASCADE"), index=True
    )
    refresh_id: Mapped[int | None] = mapped_column(Integer, default=None)
    data: Mapped[dict] = mapped_column(JSON)
    sha256: Mapped[str] = mapped_column(String(64))
    host_count: Mapped[int] = mapped_column(Integer)
    group_count: Mapped[int] = mapped_column(Integer)
    warnings: Mapped[list[str]] = mapped_column(JSON, default=list)
    sources: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # When a newer refresh replaced it; pruned once no queued or running run pins it.
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)


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
    # Triggered by someone without runs:become: the job gets ansible_become: false, which outranks
    # the playbook's and the inventory's own become. Kept out of extra_vars, so the run's vars stay
    # as typed and "Run again" by someone who may become isn't held back.
    become_blocked: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    check_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    diff_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    limit: Mapped[str | None] = mapped_column(String(500), default=None)
    extra_vars: Mapped[dict | None] = mapped_column(JSON, default=None)
    status: Mapped[str] = mapped_column(String(20), default=RunStatus.QUEUED.value)
    triggered_by: Mapped[str] = mapped_column(String(150))
    # The API key that triggered it, if one did: a key may cancel only its own runs, checked by
    # id rather than by matching the "apikey:<name>" display string in triggered_by.
    triggered_by_api_key_id: Mapped[int | None] = mapped_column(
        ForeignKey("api_keys.id", ondelete="SET NULL"), default=None
    )
    return_code: Mapped[int | None] = mapped_column(Integer, default=None)

    # Lifecycle: queued (entered the queue; a retry re-queues) -> claimed (an executor
    # picked it up) -> started (ansible launched) -> finished. created_at never changes.
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # Which executor ran it ("host:pid") and which try this is.
    worker_id: Mapped[str | None] = mapped_column(String(255), default=None)
    attempt: Mapped[int] = mapped_column(Integer, default=1, server_default="1")

    # Hosts per outcome, from ansible's final PLAY RECAP; NULL if the playbook never got
    # that far. A host counts as failed/unreachable/changed if any of its tasks was;
    # ok = hosts with no failed or unreachable task.
    hosts_total: Mapped[int | None] = mapped_column(Integer, default=None)
    hosts_ok: Mapped[int | None] = mapped_column(Integer, default=None)
    hosts_changed: Mapped[int | None] = mapped_column(Integer, default=None)
    hosts_failed: Mapped[int | None] = mapped_column(Integer, default=None)
    hosts_unreachable: Mapped[int | None] = mapped_column(Integer, default=None)

    # The playbook as it was when the run was triggered: later edits don't change what a
    # queued run executes. NULL only for runs from before the job queue.
    playbook_snapshot: Mapped[str | None] = mapped_column(Text, default=None)
    # The inventory's own hosts and groups as they were when the run was triggered
    # (app.inventory_render.static_data), so edits while it waits don't change what it runs;
    # NULL for runs queued before 4G (rendered from the live inventory). The rendered
    # inventory's hash is recorded when the job is built.
    inventory_static: Mapped[dict | None] = mapped_column(JSON(none_as_null=True), default=None)
    inventory_sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    # The sources' snapshot it runs with (Phase 4G), pinned with the static data.
    inventory_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("inventory_snapshots.id", ondelete="SET NULL"), default=None
    )
    playbook_sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    timeout_seconds: Mapped[int] = mapped_column(
        Integer,
        default=DEFAULT_RUN_TIMEOUT_SECONDS,
        server_default=str(DEFAULT_RUN_TIMEOUT_SECONDS),
    )
    # Why it ended the way it did, when that isn't just ansible's own result.
    status_reason: Mapped[str | None] = mapped_column(String(500), default=None)

    # The claiming worker's lease, renewed by its heartbeats; always set from the DB's clock.
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    # SHA-256 of the claim token: every worker call after the claim must present it, so a
    # worker whose claim was taken away (reaped) can no longer write to the run.
    claim_token_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    # SHA-256 of the one-time token that fetches the job's secrets, and its expiry.
    job_token_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    job_token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    cancel_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    cancel_requested_by: Mapped[str | None] = mapped_column(String(150), default=None)

    # Runs of playbooks synced from git execute in the repository at this commit.
    git_source_id: Mapped[int | None] = mapped_column(
        ForeignKey("git_sources.id", ondelete="SET NULL"), default=None
    )
    git_source_name: Mapped[str | None] = mapped_column(String(100), default=None)
    git_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("git_snapshots.id", ondelete="SET NULL"), default=None
    )
    git_commit: Mapped[str | None] = mapped_column(String(64), default=None)
    playbook_path: Mapped[str | None] = mapped_column(String(1024), default=None)

    # Log appends are idempotent and crash-safe: the last event sequence number written and
    # the log file's committed length (anything past it is an unfinished write, cut off).
    log_seq: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    log_bytes: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")

    __table_args__ = (
        # One running run per inventory; the claim query also enforces this, the index makes
        # a race impossible rather than unlikely.
        Index(
            "ux_runs_running_inventory",
            "inventory_id",
            unique=True,
            postgresql_where=text("status = 'running'"),
        ),
        Index("ix_runs_queue", "queued_at", "id", postgresql_where=text("status = 'queued'")),
        Index("ix_runs_lease", "lease_expires_at", postgresql_where=text("status = 'running'")),
        # History by time range (the analytics views behind the Grafana dashboards).
        Index("ix_runs_finished_at", "finished_at"),
    )


class RunTemplate(Base):
    """A saved run: playbook, inventory (and target group), credential and options, started
    again in one step (Phase 5A). References are SET NULL when their item is deleted; a
    template with a missing reference can't be launched until it is edited."""

    __tablename__ = "run_templates"
    __table_args__ = (UniqueConstraint("project_id", "name", name="uq_run_template_name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str | None] = mapped_column(String(500), default=None)
    playbook_id: Mapped[int | None] = mapped_column(ForeignKey("playbooks.id", ondelete="SET NULL"))
    inventory_id: Mapped[int | None] = mapped_column(
        ForeignKey("inventories.id", ondelete="SET NULL")
    )
    group_name: Mapped[str | None] = mapped_column(String(255), default=None)
    credential_id: Mapped[int | None] = mapped_column(
        ForeignKey("credentials.id", ondelete="SET NULL")
    )
    vault_password_id: Mapped[int | None] = mapped_column(
        ForeignKey("vault_passwords.id", ondelete="SET NULL"), default=None
    )
    # Tells "no vault password" from "its vault password was deleted" (both leave the id NULL).
    uses_vault_password: Mapped[bool] = mapped_column(Boolean, default=False)
    become: Mapped[bool] = mapped_column(Boolean, default=False)
    check_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    diff_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    limit: Mapped[str | None] = mapped_column(String(500), default=None)
    extra_vars: Mapped[dict | None] = mapped_column(JSON(none_as_null=True), default=None)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=DEFAULT_RUN_TIMEOUT_SECONDS)
    created_by: Mapped[str] = mapped_column(String(150))
    updated_by: Mapped[str] = mapped_column(String(150))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class LintJob(Base):
    """A playbook check (Phase 5B): ansible-lint over an editor's text, or over a synced
    playbook in its repository at the source's current commit. Claimed by a worker like a
    refresh; its findings are private to whoever asked and pruned after an hour."""

    __tablename__ = "lint_jobs"
    __table_args__ = (
        # One queued check per person: a newer one replaces it.
        Index(
            "ux_lint_jobs_queued_user",
            "requested_by_user_id",
            unique=True,
            postgresql_where=text("status = 'queued'"),
        ),
        Index("ix_lint_jobs_queue", "queued_at", "id", postgresql_where=text("status = 'queued'")),
        Index(
            "ix_lint_jobs_lease", "lease_expires_at", postgresql_where=text("status = 'running'")
        ),
        Index("ix_lint_jobs_finished_at", "finished_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    requested_by_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    requested_by: Mapped[str] = mapped_column(String(150))
    playbook_id: Mapped[int | None] = mapped_column(
        ForeignKey("playbooks.id", ondelete="SET NULL"), default=None
    )
    # The file checked: "playbook.yml" for an editor's text, else its path in the repository.
    target: Mapped[str] = mapped_column(String(1024))
    # The editor's text, kept only until the check ends.
    content: Mapped[str | None] = mapped_column(Text, default=None)
    content_sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    git_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("git_snapshots.id", ondelete="SET NULL"), default=None
    )
    git_commit: Mapped[str | None] = mapped_column(String(64), default=None)
    status: Mapped[str] = mapped_column(String(20), default=RunStatus.QUEUED.value)
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    timeout_seconds: Mapped[int] = mapped_column(Integer)
    worker_id: Mapped[str | None] = mapped_column(String(255), default=None)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    claim_token_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    job_token_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    job_token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    findings: Mapped[list | None] = mapped_column(JSON, default=None)
    findings_total: Mapped[int | None] = mapped_column(Integer, default=None)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    # Findings in files outside the project (an installed collection), left out.
    external: Mapped[int] = mapped_column(Integer, default=0)
    # Whether the repository's own ansible-lint config was used.
    repo_config: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(String(1000), default=None)
    # A secret's value appeared in a finding and was redacted.
    scrubbed: Mapped[bool] = mapped_column(Boolean, default=False)
    ansible_lint_version: Mapped[str | None] = mapped_column(String(40), default=None)


class Worker(Base):
    """A worker process as it last reported in (every claim and heartbeat). Only feeds the
    admin Workers page and the "why is my run still queued" hints; claiming never reads it.
    Rows not seen for a day are pruned by the reaper."""

    __tablename__ = "workers"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)  # "host:pid"
    slots: Mapped[int] = mapped_column(Integer)
    # Whether its runs execute as per-slot users (app.run_isolation); None: not reported.
    isolated: Mapped[bool | None] = mapped_column(Boolean, default=None)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


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
    status_reason: Mapped[str | None] = mapped_column(String(500), default=None)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # Installs run in the API process; the lease is renewed while one runs, so an install
    # whose process died is failed by the reaper instead of blocking runs forever.
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)


class AuditEvent(Base):
    """Security-relevant event trail. Actor/target are snapshots with no FKs so the
    trail survives deleting users or resources. Never store secrets or bodies."""

    __tablename__ = "audit_events"
    # (action, created_at) serves the action-prefix filter and per-action time series;
    # created_at alone serves retention and time-range queries.
    __table_args__ = (Index("ix_audit_events_action_created_at", "action", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )
    actor_user_id: Mapped[int | None] = mapped_column(Integer, default=None)
    actor_username: Mapped[str | None] = mapped_column(String(150), default=None)
    project_id: Mapped[int | None] = mapped_column(Integer, default=None)
    action: Mapped[str] = mapped_column(String(64))
    target_type: Mapped[str | None] = mapped_column(String(50), default=None)
    target_id: Mapped[int | None] = mapped_column(Integer, default=None)
    target_name: Mapped[str | None] = mapped_column(String(255), default=None)
    outcome: Mapped[str] = mapped_column(String(20))
    ip: Mapped[str | None] = mapped_column(String(64), default=None)
    detail: Mapped[dict | None] = mapped_column(JSON, default=None)


class NotificationChannel(Base):
    """Where notifications go (app.notifications). Global when project_id is NULL (global
    admins; ops/security events, and run events of every project), else a project's own (its
    admins; that project's run events). Its URL, signing secret and
    recipients are one encrypted JSON blob: a webhook URL is itself a credential."""

    __tablename__ = "notification_channels"
    __table_args__ = (UniqueConstraint("project_id", "name", postgresql_nulls_not_distinct=True),)

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True, default=None
    )
    name: Mapped[str] = mapped_column(String(100))
    kind: Mapped[str] = mapped_column(String(20))
    config_encrypted: Mapped[bytes] = mapped_column(LargeBinary)
    events: Mapped[list[str]] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(150))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class NotificationDelivery(Base):
    """One event for one channel: an outbox row, written in the same transaction as what it
    reports and sent (with retries) by app.notifications.dispatch. The payload is metadata
    only, never secrets or run output."""

    __tablename__ = "notification_deliveries"
    __table_args__ = (
        UniqueConstraint("channel_id", "dedup_key"),
        Index(
            "ix_notification_deliveries_due",
            "next_attempt_at",
            postgresql_where=text("status IN ('pending', 'sending')"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    channel_id: Mapped[int] = mapped_column(
        ForeignKey("notification_channels.id", ondelete="CASCADE"), index=True
    )
    event: Mapped[str] = mapped_column(String(50))
    payload: Mapped[dict] = mapped_column(JSON)
    # At most one delivery per channel and key (events that must not repeat, e.g. 4D-2's).
    dedup_key: Mapped[str | None] = mapped_column(String(200), default=None)
    status: Mapped[str] = mapped_column(String(10), default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_status_code: Mapped[int | None] = mapped_column(Integer, default=None)
    last_error: Mapped[str | None] = mapped_column(String(300), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)


class NotificationAlert(Base):
    """An ops alert that is currently raised (a worker offline, the queue stuck): its row makes
    the alert fire once per episode and its deletion send exactly one all-clear, across
    restarts."""

    __tablename__ = "notification_alerts"

    key: Mapped[str] = mapped_column(String(200), primary_key=True)
    raised_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    data: Mapped[dict | None] = mapped_column(JSON, default=None)
