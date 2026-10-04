"""Server-side maintenance commands, run inside the backend container:

    uv run python -m app.cli <command> ...    # dev image
    python -m app.cli <command> ...           # production (runtime) image

    migrate                          bring the database schema to the latest revision
                                     (the app also does this at startup)
    import-sqlite <path> [--check]   one-time import of a pre-Postgres ansideck.db
    reset-totp <username>            turn off a user's two-factor login
    analytics-grant <role>           let a (Grafana) database role read the analytics views
    analytics-check <role>           check such a role can read nothing else
    analytics-revoke <role>          take that access away again

reset-totp is the break-glass for a user who lost both their authenticator and their
recovery codes when no other admin can reset it from the Users page.
"""

import argparse
import sys
from pathlib import Path

from app import analytics, audit, totp
from app.db import get_sessionmaker, init_db
from app.models import User
from app.sqlite_import import ImportFailed, import_sqlite


def reset_totp(username: str) -> int:
    init_db()
    db = get_sessionmaker()()
    try:
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            print(f"No user named {username!r}.", file=sys.stderr)
            return 1
        if not user.totp_enabled and user.totp_pending_secret is None:
            print(f"{username} has no two-factor login; nothing to do.")
            return 0
        totp.clear(user)
        user.session_version += 1
        db.commit()
        audit.record(
            db,
            "user.totp_reset",
            actor_username="(server cli)",
            target_type="user",
            target_id=user.id,
            target_name=user.username,
        )
        print(f"Two-factor login turned off for {username}; their sessions were signed out.")
        return 0
    finally:
        db.close()


def migrate() -> int:
    init_db()
    print("The database schema is up to date.")
    return 0


def import_legacy(path: str, check: bool) -> int:
    try:
        counts = import_sqlite(Path(path), check=check)
    except ImportFailed as exc:
        print(f"Import stopped, nothing was written:\n{exc}", file=sys.stderr)
        return 1
    width = max(map(len, counts))
    for table, rows in counts.items():
        print(f"  {table:<{width}}  {rows}")
    if check:
        print("Check passed: everything above would be imported. Nothing was written.")
    else:
        print(f"Imported {sum(counts.values())} rows. {path} was not changed; keep it as a backup.")
    return 0


def _report(role: str, result: analytics.CheckResult) -> int:
    for warning in result.warnings:
        print(f"warning: {warning}")
    for problem in result.problems:
        print(f"problem: {problem}", file=sys.stderr)
    if not result.ok:
        print(f"{role} is not limited to reading the analytics views.", file=sys.stderr)
        return 1
    print(f"{role} can read the analytics views and nothing else.")
    return 0


def analytics_command(command: str, role: str) -> int:
    init_db()
    db = get_sessionmaker()()
    try:
        if command == "analytics-grant":
            return _report(role, analytics.grant(db, role))
        if command == "analytics-check":
            return _report(role, analytics.check(db, role))
        analytics.revoke(db, role)
        print(f"{role} can no longer read the analytics views.")
        return 0
    except analytics.AnalyticsError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        db.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="AnsiDeck maintenance")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("migrate", help="bring the database schema to the latest revision")
    importer = commands.add_parser("import-sqlite", help="import a pre-Postgres ansideck.db once")
    importer.add_argument("path")
    importer.add_argument(
        "--check", action="store_true", help="run the whole import, then roll it back"
    )
    reset = commands.add_parser("reset-totp", help="turn off a user's two-factor login")
    reset.add_argument("username")
    for name, about in (
        ("analytics-grant", "let a database role read the analytics views (for Grafana)"),
        ("analytics-check", "check a role can read the analytics views and nothing else"),
        ("analytics-revoke", "take a role's access to the analytics views away"),
    ):
        commands.add_parser(name, help=about).add_argument("role")
    args = parser.parse_args(argv)
    if args.command.startswith("analytics-"):
        return analytics_command(args.command, args.role)
    if args.command == "migrate":
        return migrate()
    if args.command == "import-sqlite":
        return import_legacy(args.path, args.check)
    return reset_totp(args.username)


if __name__ == "__main__":
    sys.exit(main())
