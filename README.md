# AnsiDeck
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
Authentik, Dex, ...). Password login stays available, and it is your break-glass.

1. Register `<PUBLIC_URL>/api/auth/oidc/callback` as a redirect URI at the provider and create a client.
2. Set `PUBLIC_URL`, `OIDC_ISSUER`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` (see `.env.example`) and restart.
   The issuer must match the provider's `issuer` exactly. In production both URLs must be `https`.
3. In **Users**, create each person (or open an existing one) and set their **email**.

The first time someone signs in with SSO, they are linked to the user whose email matches the address the
provider has *verified*; from then on they are matched by the provider's stable subject id, so a changed
email can't hijack the account. Nothing is ever created automatically: an identity with no matching user is
refused. **Global admins cannot sign in with SSO** unless you set `OIDC_ALLOW_ADMIN=true`. Roles and project
membership stay managed inside AnsiDeck (no group mapping), and signing out ends only the AnsiDeck session.
Use **Unlink SSO** on a user if they move to a different account at the provider.

