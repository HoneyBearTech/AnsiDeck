"""Server-side maintenance commands, run inside the backend container:

    uv run python -m app.cli reset-totp <username>    # dev image
    python -m app.cli reset-totp <username>           # production (runtime) image

reset-totp is the break-glass for a user who lost both their authenticator and their
recovery codes when no other admin can reset it from the Users page.
"""

import argparse
import sys

from app import audit, totp
from app.db import get_sessionmaker, init_db
from app.models import User


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="AnsiDeck maintenance")
    commands = parser.add_subparsers(dest="command", required=True)
    reset = commands.add_parser("reset-totp", help="turn off a user's two-factor login")
    reset.add_argument("username")
    args = parser.parse_args(argv)
    return reset_totp(args.username)


if __name__ == "__main__":
    sys.exit(main())
