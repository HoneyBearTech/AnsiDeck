"""Development only: set up the compose `openbao` profile's OpenBao (a dev-mode server) the way
the README's "Secret store" section describes, and print the .env lines that turn it on.

Run it in the backend container, which reaches OpenBao on the `secrets` network and keeps the
AppRole secret id on its own /data volume (the worker never mounts that part of it):

    docker compose --profile openbao up -d
    docker compose exec backend uv run python scripts/openbao_dev_setup.py

It is idempotent. Re-run it after OpenBao restarts (a dev server keeps everything in memory)
or after adding projects (each gets a policy for SECRETS_STORE_PROJECT_POLICY). Each run
writes a fresh secret id; AnsiDeck reads the file again at its next login. The role id is
fixed, so the .env lines never change.
"""

import argparse
import os
import pathlib
import sys

import httpx

ROLE = "ansideck"
ROLE_ID = "ansideck-dev"
BASE_POLICY = "ansideck"
PROJECT_POLICY = "ansideck-project-{project_id}"


def project_ids() -> list[int]:
    """Every project in AnsiDeck's database (the container's DATABASE_URL)."""
    from sqlalchemy import select

    from app.db import get_sessionmaker
    from app.models import Project

    db = get_sessionmaker()()
    try:
        return sorted(db.scalars(select(Project.id)))
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default="http://openbao:8200")
    parser.add_argument("--kv-mount", default="secret")
    parser.add_argument("--prefix", default="ansideck")
    parser.add_argument("--secret-id-file", default="/data/openbao/secret_id")
    parser.add_argument(
        "--projects",
        help="comma-separated project ids for per-project policies (default: all in the database)",
    )
    args = parser.parse_args()
    # The compose profile's dev root token, unless OPENBAO_ROOT_TOKEN says otherwise.
    root = os.environ.get("OPENBAO_ROOT_TOKEN", "dev-only-root-token")
    projects = (
        [int(p) for p in args.projects.split(",") if p.strip()] if args.projects else project_ids()
    )

    with httpx.Client(base_url=args.url, headers={"X-Vault-Token": root}, timeout=10) as bao:

        def call(method: str, path: str, **kwargs) -> httpx.Response:
            response = bao.request(method, f"/v1/{path}", **kwargs)
            if response.status_code >= 400:
                sys.exit(f"{method} {path}: HTTP {response.status_code}: {response.text[:300]}")
            return response

        if "approle/" not in call("GET", "sys/auth").json()["data"]:
            call("POST", "sys/auth/approle", json={"type": "approle"})
        mount_info = call("GET", f"sys/mounts/{args.kv_mount}").json()
        if mount_info.get("options", {}).get("version") != "2":
            sys.exit(f"{args.kv_mount}/ is not a KV version 2 mount")

        # Read-only on AnsiDeck's prefix, plus minting per-project child tokens.
        policies = {
            BASE_POLICY: (
                f'path "{args.kv_mount}/data/{args.prefix}/*" {{ capabilities = ["read"] }}\n'
                'path "auth/token/create" { capabilities = ["update"] }\n'
            )
        }
        for project_id in projects:
            policies[PROJECT_POLICY.format(project_id=project_id)] = (
                f'path "{args.kv_mount}/data/{args.prefix}/{project_id}/*" '
                '{ capabilities = ["read"] }\n'
            )
        for name, rules in policies.items():
            call("PUT", f"sys/policies/acl/{name}", json={"policy": rules})

        call(
            "POST",
            f"auth/approle/role/{ROLE}",
            json={"token_policies": list(policies), "token_ttl": "1h", "token_max_ttl": "4h"},
        )
        call("POST", f"auth/approle/role/{ROLE}/role-id", json={"role_id": ROLE_ID})
        secret_id = call("POST", f"auth/approle/role/{ROLE}/secret-id").json()["data"]["secret_id"]

    path = pathlib.Path(args.secret_id_file)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".new")
    temporary.unlink(missing_ok=True)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(secret_id + "\n")
    temporary.replace(path)  # AnsiDeck never reads a half-written file

    print(f"OpenBao at {args.url} is set up; the AppRole secret id is in {path}.")
    print(f"Per-project policies for projects: {', '.join(map(str, projects)) or 'none'}.")
    print("\nAdd these lines to .env, then: docker compose up -d backend\n")
    print(f"SECRETS_STORE_URL={args.url}")
    print("SECRETS_STORE_AUTH=approle")
    print(f"SECRETS_STORE_ROLE_ID={ROLE_ID}")
    print(f"SECRETS_STORE_SECRET_ID_FILE={path}")
    if args.kv_mount != "secret":
        print(f"SECRETS_STORE_KV_MOUNT={args.kv_mount}")
    if args.prefix != "ansideck":
        print(f"SECRETS_STORE_PATH_PREFIX={args.prefix}")
    print("# Optional: let OpenBao itself keep projects apart (a child token per read):")
    print(f"# SECRETS_STORE_PROJECT_POLICY={PROJECT_POLICY}")
    print(
        "\nStore a key (project 1, path web/ssh):\n"
        "  docker compose exec -T openbao bao kv put -mount=secret "
        f"{args.prefix}/1/web/ssh private_key=- < ~/.ssh/id_ed25519"
    )


if __name__ == "__main__":
    main()
