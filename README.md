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
