"""Access to the read-only `analytics` schema (migration 0008) for a Grafana database role.

AnsiDeck never creates database roles (they are cluster-wide, and a managed Postgres often
won't let the app create them): the operator creates a login role, these functions grant it
SELECT on the analytics views and nothing else, and check that it can't read or change
anything outside them. The views run with the app user's rights, so the role needs no
privilege on any table.
"""

from dataclasses import dataclass, field

from sqlalchemy import text
from sqlalchemy.orm import Session

SCHEMA = "analytics"


class AnalyticsError(Exception):
    pass


@dataclass
class CheckResult:
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def view_names(db: Session) -> list[str]:
    return list(
        db.execute(
            text("SELECT viewname FROM pg_views WHERE schemaname = :s ORDER BY viewname"),
            {"s": SCHEMA},
        ).scalars()
    )


def _quoted(db: Session, role: str) -> str:
    return db.get_bind().dialect.identifier_preparer.quote(role)


def _role(db: Session, role: str):
    row = db.execute(
        text(
            "SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, "
            "rolname = current_user, pg_has_role(rolname, current_user, 'MEMBER') "
            "FROM pg_roles WHERE rolname = :role"
        ),
        {"role": role},
    ).first()
    if row is None:
        raise AnalyticsError(
            f"There is no database role named {role!r}. Create it first (see the README)."
        )
    return row


def grant(db: Session, role: str) -> CheckResult:
    """Grants `role` read access to the analytics views (also to views added later), then
    checks it. Refuses roles that would see more than the views anyway."""
    superuser, _, _, bypassrls, is_app_user, member_of_app = _role(db, role)
    if superuser or bypassrls:  # (a superuser also counts as a member of every role)
        raise AnalyticsError(f"{role!r} is a superuser or bypasses row security. Use a plain role.")
    if is_app_user or member_of_app:
        raise AnalyticsError(
            f"{role!r} is (or is a member of) the app's own database user, which owns every "
            "table. Use a separate role."
        )
    if not view_names(db):
        raise AnalyticsError(f"The {SCHEMA} schema has no views: run the migrations first.")
    quoted = _quoted(db, role)
    db.execute(text(f"GRANT USAGE ON SCHEMA {SCHEMA} TO {quoted}"))
    db.execute(text(f"GRANT SELECT ON ALL TABLES IN SCHEMA {SCHEMA} TO {quoted}"))
    # Views a later migration (re)creates: the app's user creates them, so its defaults apply.
    db.execute(
        text(f"ALTER DEFAULT PRIVILEGES IN SCHEMA {SCHEMA} GRANT SELECT ON TABLES TO {quoted}")
    )
    db.commit()
    return check(db, role)


def revoke(db: Session, role: str) -> None:
    _role(db, role)
    quoted = _quoted(db, role)
    db.execute(
        text(f"ALTER DEFAULT PRIVILEGES IN SCHEMA {SCHEMA} REVOKE SELECT ON TABLES FROM {quoted}")  # noqa: S608 - constants and quoted identifiers only
    )
    db.execute(text(f"REVOKE ALL ON ALL TABLES IN SCHEMA {SCHEMA} FROM {quoted}"))
    db.execute(text(f"REVOKE ALL ON SCHEMA {SCHEMA} FROM {quoted}"))
    db.commit()


_OUTSIDE = text(
    """
    SELECT n.nspname || '.' || c.relname
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
      AND n.nspname NOT IN (:schema, 'pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg\\_%'
      AND (has_table_privilege(:role, c.oid,
               'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
           OR has_any_column_privilege(:role, c.oid, 'SELECT, INSERT, UPDATE, REFERENCES'))
    ORDER BY 1
    """
)
_WRITABLE_VIEWS = text(
    """
    SELECT c.relname
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = :schema
      AND has_table_privilege(:role, c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER')
    ORDER BY 1
    """
)
_UNREADABLE_VIEWS = text(
    """
    SELECT c.relname
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = :schema AND c.relkind = 'v'
      AND NOT has_table_privilege(:role, c.oid, 'SELECT')
    ORDER BY 1
    """
)
_CREATE_ON = text(
    """
    SELECT nspname FROM pg_namespace
    WHERE has_schema_privilege(:role, oid, 'CREATE')
      AND nspname NOT LIKE 'pg\\_%' AND nspname <> 'information_schema'
    ORDER BY 1
    """
)
_SETTINGS = text(
    """
    SELECT unnest(s.setconfig)
    FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole
    WHERE r.rolname = :role
      AND s.setdatabase IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()))
    """
)


def check(db: Session, role: str) -> CheckResult:
    """Problems: anything the role can read or change outside the analytics views, or a
    view it can't read. Warnings: hardening the docs recommend that isn't in place."""
    superuser, createrole, createdb, bypassrls, is_app_user, member_of_app = _role(db, role)
    result = CheckResult()
    params = {"role": role, "schema": SCHEMA}
    for flag, name in (
        (superuser, "SUPERUSER"),
        (createrole, "CREATEROLE"),
        (createdb, "CREATEDB"),
        (bypassrls, "BYPASSRLS"),
    ):
        if flag:
            result.problems.append(f"the role has {name}")
    if is_app_user or member_of_app:
        result.problems.append("the role is (or is a member of) the app's own database user")
    if not db.execute(
        text("SELECT has_schema_privilege(:role, :schema, 'USAGE')"), params
    ).scalar():
        result.problems.append(f"the role has no USAGE on the {SCHEMA} schema")
    for view in db.execute(_UNREADABLE_VIEWS, params).scalars():
        result.problems.append(f"the role can't read {SCHEMA}.{view}")
    for relation in db.execute(_OUTSIDE, params).scalars():
        result.problems.append(f"the role has privileges on {relation}")
    for view in db.execute(_WRITABLE_VIEWS, params).scalars():
        result.problems.append(f"the role may change {SCHEMA}.{view}")
    for schema in db.execute(_CREATE_ON, params).scalars():
        result.problems.append(f"the role may create objects in schema {schema}")

    settings = set(db.execute(_SETTINGS, params).scalars())
    if "default_transaction_read_only=on" not in settings:
        result.warnings.append(
            f"ALTER ROLE {_quoted(db, role)} SET default_transaction_read_only = on is not set"
        )
    if db.execute(
        text("SELECT has_database_privilege(:role, current_database(), 'TEMP')"), params
    ).scalar():
        result.warnings.append(
            "the role may create temporary objects (REVOKE TEMPORARY ON DATABASE ... FROM PUBLIC)"
        )
    db.rollback()
    return result
