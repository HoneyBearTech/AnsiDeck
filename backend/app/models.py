from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Table,
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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Credential(Base):
    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    description: Mapped[str | None] = mapped_column(String(500), default=None)
    encrypted_private_key: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class VaultPassword(Base):
    __tablename__ = "vault_passwords"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    description: Mapped[str | None] = mapped_column(String(500), default=None)
    encrypted_password: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Playbook(Base):
    """Metadata only — YAML content lives on disk at {data_dir}/playbooks/{id}.yml."""

    __tablename__ = "playbooks"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Inventory(Base):
    __tablename__ = "inventories"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
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
