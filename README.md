# AnsiDeck

[![CI](https://github.com/HoneyBearTech/AnsiDeck/actions/workflows/ci.yml/badge.svg)](https://github.com/HoneyBearTech/AnsiDeck/actions/workflows/ci.yml)
[![CodeQL](https://github.com/HoneyBearTech/AnsiDeck/actions/workflows/codeql.yml/badge.svg)](https://github.com/HoneyBearTech/AnsiDeck/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/HoneyBearTech/AnsiDeck/badge)](https://scorecard.dev/viewer/?uri=github.com/HoneyBearTech/AnsiDeck)
[![OpenSSF Baseline](https://www.bestpractices.dev/projects/14718/baseline)](https://www.bestpractices.dev/projects/14718)

Self-hosted web UI for running Ansible playbooks against target systems, packaged in Docker.

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

