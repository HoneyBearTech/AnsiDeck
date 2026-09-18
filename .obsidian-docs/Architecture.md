# Architecture (Working Draft)

Status: draft — update as real decisions get made. Log the *why* in [[Decisions-Log]], keep this file as the current-state summary.

## Suggested Stack
- **Backend:** Python (FastAPI recommended) — async support matters for streaming live playbook output over WebSocket.
- **Playbook execution:** [`ansible-runner`](https://ansible.readthedocs.io/projects/runner/) (the official Python library for exactly this use case) rather than shelling out to raw `ansible-playbook`. It gives structured event data, clean handling of inventories/credentials/env, and artifact directories per run — all things you'd otherwise hand-roll.
- **Ansible itself ships inside the backend image** — the full `ansible` PyPI package (not the minimal `ansible-core`) plus `openssh-client` at the OS level, both baked into `backend/Dockerfile`. AnsiDeck never shells out to, or depends on, an Ansible/SSH install on the host — the container is fully self-sufficient. Verified by running real playbooks over real SSH between throwaway containers, not just `--version`. See [[Decisions-Log]].
- **Frontend:** React or Vue + TypeScript. Talks to backend via REST for CRUD (playbooks, inventories, credentials) and WebSocket for live run output. Dark-mode-first, Tailwind + shadcn/ui (or Radix Vue) for a clean/futuristic theme — see [[UI-Design]] for the full direction.
- **Database:** start with SQLite for MVP (zero-ops, fine for single-user/homelab); revisit Postgres when multi-user/RBAC (Phase 3) lands.
- **Job execution:** in-process for MVP; move to a real queue (Celery/RQ/arq + Redis) in Phase 4 once concurrent runs and workers matter.
- **Containerization:** backend + frontend as separate services in `docker-compose.yml`, or frontend built and served as static assets by the backend — decide once frontend framework is picked.

## Core Components
1. **Playbook Store** — where uploaded/synced playbook YAML lives (filesystem volume to start; git-backed sync is Phase 4).
2. **Inventory Store** — hosts/groups, either static files or DB-backed records that get rendered to inventory format at run time.
3. **Credential Store** — encrypted SSH keys / vault passwords, decrypted only in-memory at run time, never written to logs.
4. **Run Engine** — wraps `ansible-runner`, manages one run's lifecycle (queued → running → complete/failed), captures stdout/events.
5. **Run History / Audit** — persisted record of every run: who triggered it, target, playbook version, vars used, output, result.
6. **Web UI** — playbook/inventory/credential management, run trigger, live log viewer, history browser.

## Data Flow (MVP)
```
User (browser)
  → Web UI
  → Backend API (REST: create/read playbooks, inventories, credentials)
  → Run Engine (on trigger) → ansible-runner → ansible-playbook subprocess
  → target hosts (SSH)
  ← structured events/output streamed back
  → WebSocket → Web UI (live log view)
  → Run record persisted to DB
```

## Deployment Shape
- Single `docker-compose.yml` for local/homelab use — this is the primary target audience (see repo description).
- Bind-mount or named volume for playbook storage so it survives container restarts.
- Execution happens in the same container as the API for now (decided — see [[Decisions-Log]]); revisit a separate "runner" container/sidecar for isolation once the core run loop exists, per [[Security-Considerations]].
