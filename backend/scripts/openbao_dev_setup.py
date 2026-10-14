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

It also sets up an SSH secrets engine for SSH certificate credentials (unless --no-ssh): a CA
(made once; never re-made, which would rotate it), a role "<prefix>-<project id>-dev" per
project and the policies to sign with them. Targets trust the CA's public key, written next to
the secret id, with sshd's TrustedUserCAKeys. A restarted dev server makes a new CA.
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
    parser.add_argument("--ssh-mount", default="ssh")
    parser.add_argument(
        "--ssh-principals",
        default="ansible,deploy",
        help="the users the dev roles' certificates may log in as",
    )
    parser.add_argument("--no-ssh", action="store_true", help="no SSH engine or roles")
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

        def call(method: str, path: str, ok: tuple[int, ...] = (), **kwargs) -> httpx.Response:
            response = bao.request(method, f"/v1/{path}", **kwargs)
            if response.status_code >= 400 and response.status_code not in ok:
                sys.exit(f"{method} {path}: HTTP {response.status_code}: {response.text[:300]}")
            return response

        if "approle/" not in call("GET", "sys/auth").json()["data"]:
            call("POST", "sys/auth/approle", json={"type": "approle"})
        mount_info = call("GET", f"sys/mounts/{args.kv_mount}").json()
        if mount_info.get("options", {}).get("version") != "2":
            sys.exit(f"{args.kv_mount}/ is not a KV version 2 mount")

        ca_public_key = None if args.no_ssh else set_up_ssh(call, args, projects)

        # Read-only on AnsiDeck's prefix, plus minting per-project child tokens (and signing
        # with its SSH roles).
        ssh_sign = f"{args.ssh_mount}/sign/{args.prefix}"
        policies = {
            BASE_POLICY: (
                f'path "{args.kv_mount}/data/{args.prefix}/*" {{ capabilities = ["read"] }}\n'
                'path "auth/token/create" { capabilities = ["update"] }\n'
            )
            + ("" if args.no_ssh else f'path "{ssh_sign}-*" {{ capabilities = ["update"] }}\n')
        }
        for project_id in projects:
            policies[PROJECT_POLICY.format(project_id=project_id)] = (
                f'path "{args.kv_mount}/data/{args.prefix}/{project_id}/*" '
                '{ capabilities = ["read"] }\n'
            ) + (
                ""
                if args.no_ssh
                else f'path "{ssh_sign}-{project_id}-*" {{ capabilities = ["update"] }}\n'
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
    if ca_public_key is not None:
        (path.parent / "ssh_ca.pub").write_text(ca_public_key + "\n")
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
    if ca_public_key is not None:
        print(f"SECRETS_STORE_SSH_MOUNTS={args.ssh_mount}")
    print("# Optional: let OpenBao itself keep projects apart (a child token per read):")
    print(f"# SECRETS_STORE_PROJECT_POLICY={PROJECT_POLICY}")
    print(
        "\nStore a key (project 1, path web/ssh):\n"
        "  docker compose exec -T openbao bao kv put -mount=secret "
        f"{args.prefix}/1/web/ssh private_key=- < ~/.ssh/id_ed25519"
    )
    if ca_public_key is not None:
        print(
            f"\nSSH certificates: a credential of kind 'SSH certificate' with mount "
            f"{args.ssh_mount}, role dev and principals from {args.ssh_principals} signs with "
            f"{args.prefix}-<project id>-dev. Targets trust the CA (also in "
            f"{path.parent / 'ssh_ca.pub'}) with sshd's TrustedUserCAKeys:\n  {ca_public_key}"
        )


def set_up_ssh(call, args, projects: list[int]) -> str:
    """The SSH engine, its CA and a dev role per project; returns the CA's public key."""
    mounts = call("GET", "sys/mounts").json()["data"]
    mount = mounts.get(f"{args.ssh_mount}/")
    if mount is None:
        call("POST", f"sys/mounts/{args.ssh_mount}", json={"type": "ssh"})
    elif mount.get("type") != "ssh":
        sys.exit(f"{args.ssh_mount}/ is not an SSH secrets engine")
    # Asking for a CA again would make a new one the default: only make one when none exists
    # (OpenBao answers 400 "no default issuer" until then).
    ca = call("GET", f"{args.ssh_mount}/public_key", ok=(400,))
    if ca.status_code == 400:
        call(
            "POST",
            f"{args.ssh_mount}/config/ca",
            json={"generate_signing_key": True, "key_type": "ed25519"},
        )
        ca = call("GET", f"{args.ssh_mount}/public_key")
    # A full replace each time (idempotent); 25 h covers the longest run timeout (24 h) plus
    # AnsiDeck's 5 minutes, so dev certificates are never capped.
    role = {
        "key_type": "ca",
        "allow_user_certificates": True,
        "allowed_users": args.ssh_principals,
        "default_extensions": {"permit-pty": ""},
        "allowed_extensions": "permit-pty",
        "allowed_user_key_lengths": {"ed25519": [0]},
        "ttl": "30m",
        "max_ttl": "25h",
    }
    for project_id in projects:
        call("POST", f"{args.ssh_mount}/roles/{args.prefix}-{project_id}-dev", json=role)
    return ca.text.strip()


if __name__ == "__main__":
    main()
