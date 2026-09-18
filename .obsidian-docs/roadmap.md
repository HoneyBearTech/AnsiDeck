# AnsiDeck Roadmap

> Self-hosted, Dockerized web UI for running Ansible playbooks against target systems — replacing WSL + CLI workflows.

Related: [[Architecture]] · [[Security-Considerations]] · [[Decisions-Log]] · [[UI-Design]]

---

## Design Direction
- [x] **Dark mode is the default theme** — not a Phase 5 toggle, a Phase 1 requirement. See [[UI-Design]] for the full direction (clean, smooth, futuristic).
- [x] Light mode is optional/deferred — dark-first, add light mode later only if there's demand.

---

## Phase 0 — Project Foundation
- [x] Repo scaffolding: `/backend`, `/frontend`, `/docker` (or monorepo layout — decide in [[Decisions-Log]]) — monorepo, decided [[Decisions-Log|2026-09-18]]
- [x] `docker-compose.yml` for local dev (hot reload for both backend + frontend)
- [x] Production `Dockerfile`(s), multi-stage build
- [x] Basic CI (lint + test on push/PR) — GitHub Actions
- [x] `.env.example` documenting required environment variables
- [x] Single-user auth stub (hardcoded/admin login) just to unblock UI work

## Phase 1 — MVP: Core Playbook Execution
- [x] Upload / browse / edit Ansible playbooks (YAML) through the UI
- [x] Manage inventories — went straight to structured hosts/groups (many-to-many), not raw file editing. See [[Decisions-Log]]
- [x] Manage SSH credentials (private keys) — stored encrypted, never logged — passphrase-protected keys not yet supported, see [[Decisions-Log]]
- [ ] Trigger a playbook run against a host/group — Pass B
- [ ] Live-streamed run output in the browser (WebSocket) — Pass B
- [ ] Run history: past runs, status, duration, exit code, full log — Pass B
- [x] Basic login/auth (real, not stub) — DB-backed, argon2-hashed, includes self-service password change

## Phase 2 — Core Ops Features
- [ ] Ansible Vault support (encrypt/decrypt vars, vault password handling in UI)
- [ ] Extra-vars UI (pass `--extra-vars` per run without editing playbook)
- [ ] Check mode / dry-run toggle (`--check`)
- [ ] Diff mode toggle (`--diff`)
- [ ] Limit targeting (`--limit` pattern picker instead of full group run)
- [ ] Role/collection management — install from `requirements.yml` via `ansible-galaxy`
- [ ] Job concurrency guard — prevent two runs hitting the same host at once

## Phase 3 — Multi-User & Access Control
- [ ] RBAC: admin / operator / viewer roles
- [ ] Per-project or per-team separation of playbooks & inventories
- [ ] Audit log — who ran what, against what, when, with what result
- [ ] API keys for triggering runs programmatically (CI/CD integration)
- [ ] Optional SSO / OAuth login

## Phase 4 — Scale & Reliability
- [ ] Real job queue + multiple execution workers (Celery/RQ/arq — decide in [[Decisions-Log]])
- [ ] Dynamic inventory sources (cloud provider plugins, etc.)
- [ ] Notifications on job complete/fail (Slack, email, generic webhook)
- [ ] Secrets manager integration (e.g. HashiCorp Vault) instead of storing raw keys in the DB
- [ ] Git-backed playbook sync — pull playbooks from a git remote instead of manual upload

## Phase 5 — Polish / Nice-to-Haves
- [ ] Playbook editor with syntax highlighting + inline `ansible-lint`
- [ ] Visual inventory / host group graph
- [ ] Saved "run templates" for common playbook + inventory + vars combos
- [ ] Mobile-responsive layout
- [ ] Exportable run logs / artifacts

---

## Icebox (ideas, unsorted)
- [ ] Multi-target diffing — compare last-run state across hosts
- [ ] Slack/Teams bot to trigger runs from chat
- [ ] Built-in terminal fallback (drop to raw `ansible-playbook` CLI in-browser for edge cases)

## Open Questions
- [x] ~~Monorepo vs separate frontend/backend repos?~~ Decided: monorepo. See [[Decisions-Log]].
- [x] ~~SQLite vs Postgres for the MVP DB?~~ Decided: SQLite via SQLAlchemy. See [[Decisions-Log]].
- [x] ~~How are target-system credentials scoped?~~ Decided: shared pool, not per-inventory. See [[Decisions-Log]].
