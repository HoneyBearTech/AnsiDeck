# AnsiDeck

[![CI](https://github.com/HoneyBearTech/AnsiDeck/actions/workflows/ci.yml/badge.svg)](https://github.com/HoneyBearTech/AnsiDeck/actions/workflows/ci.yml)
[![CodeQL](https://github.com/HoneyBearTech/AnsiDeck/actions/workflows/codeql.yml/badge.svg)](https://github.com/HoneyBearTech/AnsiDeck/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/HoneyBearTech/AnsiDeck/badge)](https://scorecard.dev/viewer/?uri=github.com/HoneyBearTech/AnsiDeck)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14718/badge)](https://www.bestpractices.dev/projects/14718)
[![OpenSSF Baseline](https://www.bestpractices.dev/projects/14718/baseline)](https://www.bestpractices.dev/projects/14718)

Self-hosted web UI for running Ansible playbooks against target systems, packaged in Docker.

## Getting started

AnsiDeck is two containers, a FastAPI backend and a React frontend, started with Docker Compose. You need
Docker with Compose.

1. Get the code and create your settings file:

   ```sh
   git clone https://github.com/HoneyBearTech/AnsiDeck.git
   cd AnsiDeck
   cp .env.example .env
   ```

2. Edit `.env`. For anything beyond a local try-out, set your own values for:
   - `AUTH_SECRET_KEY`: a long random string that signs session cookies.
   - `ADMIN_PASSWORD`: the first admin's password. It is only read on the very first start; change it later
     under **Account** (click your username in the header).
   - `CREDENTIAL_ENCRYPTION_KEY`: the key that encrypts stored SSH credentials. Generate one with
     `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.

3. Start it: `docker compose up --build`.
4. Open <http://localhost:5173> and sign in as `ADMIN_USERNAME` (default `admin`) with `ADMIN_PASSWORD`.
   The backend's interactive API docs are at <http://localhost:8000/docs>.

The bundled `docker-compose.yml` is the development stack (hot reload; data lives in the `backend-data`
volume, mounted at `/data`). The `runtime` targets of `backend/Dockerfile` and `frontend/Dockerfile` build the
production images: both run as a non-root user, the backend listens on port 8000, and the frontend serves the
UI on port 8080 and proxies `/api` to a host named `backend`.

## Using AnsiDeck

Content is grouped into projects, and a `Default` project exists on first start. A typical run:

1. **Credentials**: add the SSH private key AnsiDeck should use to connect. It is stored encrypted.
2. **Inventories**: define hosts and groups.
3. **Playbooks**: paste a playbook or import a YAML file.
4. **Runs → New Run**: pick the playbook, inventory, target and credential. Optionally add a vault password, a
   host limit, check or diff mode, and extra variables as JSON. The output streams live, and finished runs stay
   in the run history.

Other pages: **Vault** encrypts and decrypts values with Ansible Vault, **Galaxy** installs roles and
collections, **Projects** separate content and access, and admins manage **Users** (roles: admin, operator,
viewer, assigned per project) and read the **Audit** log.

## Running it securely

- Set `ENVIRONMENT=production`. The app then refuses to start while `AUTH_SECRET_KEY` or `ADMIN_PASSWORD` still
  hold their insecure defaults.
- Serve it over HTTPS through a reverse proxy, set `COOKIE_SECURE=true`, and make sure the proxy forwards
  WebSocket upgrades (live run output needs them). If the browser's origin differs from the `Host` the backend
  sees, add it to `CORS_ORIGINS`.
- AnsiDeck is not designed to be exposed directly to the public internet. See [SECURITY.md](SECURITY.md).
- Back up the data volume, and keep `CREDENTIAL_ENCRYPTION_KEY` backed up separately: losing it makes stored
  credentials and two-factor secrets unrecoverable, and leaking it exposes every stored key.
- Give people the least role they need. Anyone who can run a playbook can run commands on the targets, and
  runs are **not sandboxed** from the application's data directory. Details are in [SECURITY.md](SECURITY.md).
- Global admins cannot use single sign-on unless you set `SSO_ALLOW_ADMIN=true`, so password login stays your
  break-glass.
- Turn on two-factor login under **Account** (authenticator-app codes for password sign-ins; SSO and GitHub
  sign-ins rely on your provider's MFA). Keep the recovery codes it shows. An admin can reset someone else's
  under **Users**; if no admin can sign in, reset it on the server with
  `docker compose exec backend uv run python -m app.cli reset-totp <username>` (in the production image,
  which has no `uv`: `python -m app.cli reset-totp <username>`).
- The audit log records sign-ins, run activity and permission denials, and is kept for
  `AUDIT_RETENTION_DAYS` (365 by default).

## Triggering runs from CI

A project admin can create an API key under **Projects → API keys**. Keys belong to one project, are shown
once, and expire (30 days, 90 days or 1 year) or can be revoked at any time. There are two kinds:

- `trigger` — start runs and read run status and output in that project. Never runs as root, never edits
  anything.
- `read-only` — read run status and output only.

Send the key as a bearer token, over HTTPS only:

```sh
KEY=ansd_...   # keep it in your CI secret store
BASE=https://ansideck.example.com

# start a run (ids come from the UI)
RUN=$(curl -sf -X POST "$BASE/api/runs" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"playbook_id": 1, "inventory_id": 1, "credential_id": 1, "extra_vars": {"version": "1.4.2"}}' \
  | python3 -c 'import sys, json; print(json.load(sys.stdin)["id"])')

# poll until it finishes: status is "success" or "failed", return_code is the ansible exit code
curl -sf "$BASE/api/runs/$RUN" -H "Authorization: Bearer $KEY"
```

A key can only use the run endpoints (`GET/POST /api/runs`, `GET /api/runs/{id}`, and the run log WebSocket
`/api/runs/{id}/ws` with the same header); everything else answers `403`. Extra vars you send are not
readable back through a key. Keys are access control, not isolation: a `trigger` key can run any playbook in
its project, so scope keys per project and rotate them.

## Single sign-on (optional)

AnsiDeck can sign people in with any OpenID Connect provider (Google, Microsoft Entra, Keycloak,
Authentik, Dex, ...) and, separately, with GitHub. Password login stays available, and it is your
break-glass. Both can be enabled at once.

**OpenID Connect**

1. Register `<PUBLIC_URL>/api/auth/oidc/callback` as a redirect URI at the provider and create a client.
2. Set `PUBLIC_URL`, `OIDC_ISSUER`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` (see `.env.example`) and restart.
   The issuer must match the provider's `issuer` exactly. In production both URLs must be `https`.
3. In **Users**, create each person (or open an existing one) and set their **email**.

**GitHub**

1. Create an OAuth App (GitHub → Settings → Developer settings → OAuth Apps) whose callback URL is
   `<PUBLIC_URL>/api/auth/github/callback`.
2. Set `PUBLIC_URL`, `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` and restart. (GitHub Enterprise Server:
   also set `GITHUB_URL` and `GITHUB_API_URL`.)
3. In **Users**, set each person's **email** to a *verified* email on their GitHub account.

The first time someone signs in with SSO, they are linked to the user whose email matches an address the
provider has *verified* (for GitHub, any verified email on the account; a sign-in that would match two
different users is refused). From then on they are matched by the provider's stable subject id (GitHub's
numeric user id, not the renamable username), so a changed email or username can't hijack the account.
Nothing is ever created automatically: an identity with no matching user is refused. **Global admins cannot
sign in with SSO** unless you set `SSO_ALLOW_ADMIN=true`, and `SSO_ALLOWED_EMAIL_DOMAINS` can restrict which
email domains may sign in. Roles and project membership stay managed inside AnsiDeck (no group or
organisation mapping), and signing out ends only the AnsiDeck session.

Each user has one bound identity. Use **Unlink SSO** on a user if they move to a different account at the
provider, or to switch them from one provider to another.

GitHub specifics: AnsiDeck asks for the `read:user` and `user:email` scopes, uses the access token for two
reads and revokes it straight away (it is never stored; if the revoke call fails the token stays valid at
GitHub until the user revokes the app there). Trust in GitHub's email verification is the boundary for
first-time linking.

