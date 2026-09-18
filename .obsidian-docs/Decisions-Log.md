# Decisions Log

Lightweight ADR-style log. One entry per decision: date, what was decided, why, alternatives considered.

---

### 2026-09-17 — Project name: AnsiDeck
Chosen over PlayOps and Dockible. Short, spellable, no collision with established players in this space (AWX, Semaphore, Rundeck).

### 2026-09-17 — License: MIT
Goal was maximizing adoption with minimal friction (permissive, allows use in closed-source products). Apache 2.0 (patent grant) and GPLv3 (copyleft) considered and set aside for now.

### 2026-09-18 — Stack: Python backend + JS/TS frontend
Python backend fits naturally since Ansible itself is Python (enables using `ansible-runner` directly rather than shelling out). Frontend framework (React vs Vue) not yet finalized — see [[Architecture]].

### 2026-09-18 — .gitignore: GitHub "Python" default template as base
Supplemented manually with Node/JS entries and Ansible-specific ignores (`*.retry`, vault password files, etc.) since GitHub's repo-creation flow only allows one template.

---

### 2026-09-18 — UI theme: dark mode default, clean/futuristic direction
Dark mode is not a Phase 5 nice-to-have; it's the app's default and only theme for now. Full visual direction (palette, typography, motion, component approach) captured in [[UI-Design]]. Light mode deferred, revisit only if there's demand.

### 2026-09-18 — Phase 0 scaffold: React confirmed, monorepo confirmed
Resolved two items previously left open. **Frontend: React + TypeScript** (not Vue) — pairs naturally with shadcn/ui + Radix as described in [[UI-Design]]. **Repo layout: monorepo** — single AnsiDeck repo with `/backend` and `/frontend` at root, resolving the roadmap's "monorepo vs separate repos" open question. Both confirmed by the project owner when kicking off Phase 0 implementation.

### 2026-09-18 — Dockerfiles co-located per-service, not a literal `/docker` folder
Roadmap phrased this as "`/docker` (or monorepo layout — decide in Decisions-Log)". Went with `backend/Dockerfile` and `frontend/Dockerfile` next to their own build context, with the frontend's nginx config at `frontend/docker/nginx.conf`. Keeps each service's Docker build self-contained rather than referencing files across directories.

### 2026-09-18 — Backend dependency management: `uv`
Chosen over pip/poetry for fast installs and a committed lockfile (`backend/uv.lock`). Also used directly in the Dockerfile's multi-stage build for layer-cached dependency installs.

### 2026-09-18 — Phase 0 auth stub: signed cookie via `itsdangerous`, not JWT
Deliberately minimal — this is the "hardcoded/admin login just to unblock UI work" item, not the real Phase 1 auth system. `itsdangerous` gives a signed, time-limited session token in an httponly cookie with far less code than a JWT setup, and gets fully replaced when Phase 1's real auth lands.

### 2026-09-18 — Frontend styling: Tailwind v4 CSS-first theming, hand-built UI primitives instead of the shadcn CLI
Tailwind v4's `@theme` block in `src/index.css` holds the full [[UI-Design]] palette (background/surface/primary/accent/status colors) as CSS variables — no `tailwind.config.js`. The `shadcn@latest` CLI has since become a much larger, opinionated app-generator (interactive theme-preset picker, monorepo prompts, Next.js-first defaults) that doesn't fit cleanly into an existing custom project non-interactively. Hand-built the small set of needed primitives (Button, Input, Label, Card, Badge) instead, using the same Radix + `class-variance-authority` + `cn()` pattern shadcn itself generates, wired directly to our own theme tokens. Revisit the CLI if/when it's a better fit, but for now components are added by hand following this same pattern.

### 2026-09-18 — Frontend linting: oxlint, not ESLint
The Vite `react-ts` template now scaffolds with `oxlint` (Rust-based, ESLint-compatible ruleset) by default instead of ESLint. Kept it rather than swapping in ESLint — it already had `react/rules-of-hooks` and `react/only-export-components` configured and is materially faster.

### 2026-09-18 — `.gitignore`: actually added the Node/JS and Ansible-specific entries
The 2026-09-18 `.gitignore` entry below claimed these were already added, but the committed file was still the unmodified GitHub Python template — caught and fixed while scaffolding the frontend. Added `node_modules/`, `dist/`, `.vite/`, `*.tsbuildinfo` for JS, and `*.retry`, `*vault_pass*`, `.vault_pass`, `*.vault-password`, `*.pem`, `*.key` for Ansible/SSH material, per the checklist in [[Security-Considerations]].

### 2026-09-18 — Added Dependabot, CodeQL, Docker build verification, and GHCR publish workflows
Rounded out `.github/` before starting Phase 1. `dependabot.yml` covers all four ecosystems in the repo (`uv`, `npm`, `docker` x2, `github-actions`) on a weekly cadence — implements [[Security-Considerations]]'s "pin dependency versions and keep a routine for updating them." `codeql.yml` adds scheduled + push/PR static analysis for Python and JS/TS, justified by this app's stated purpose of holding SSH credentials and running automation against real infra. `docker-build.yml` builds both services' dev *and* production Dockerfile targets on every push/PR with a smoke test against each runtime image — previously CI never touched Docker at all despite it being the entire deployment story. `docker-publish.yml` builds and pushes versioned images to GHCR on `v*.*.*` tags, dormant until an actual release is cut. Declined to enable GitHub's native secret-scanning/push-protection repo setting programmatically — no `gh` CLI available and the only GitHub credential on hand is a git-push-scoped keychain entry, not an admin-scoped token; left as a manual step for the repo owner (Settings → Code security → enable Secret scanning + Push protection).

### 2026-09-18 — Phase 1 split into two passes; Pass A scope and key decisions
Phase 1 (7 checklist items touching credential encryption, execution, and real auth) split into **Pass A** (real auth, playbook/inventory/credential management — this entry) and **Pass B** (run engine, `ansible-runner`, WebSocket log streaming, run history — separate future work), since it's the highest-risk part of the app and roughly 3-4x the size of Phase 0. Decisions made for Pass A:
- **DB: SQLite via SQLAlchemy 2.0**, sync `Session` (matches the existing sync route-handler pattern; FastAPI runs sync `def` handlers in its threadpool). No Alembic yet — `Base.metadata.create_all()` at startup. First real schema, project is pre-1.0/homelab-scale; formal migrations deferred until the schema needs to evolve under real data. Resolves the roadmap's SQLite-vs-Postgres open question.
- **Credential scoping: shared pool, not per-inventory.** Named credentials exist independently of inventories; a future run-trigger step (Pass B) picks which to use per run. Resolves the roadmap's credential-scoping open question.
- **Execution isolation: same container as the web app, for now.** Matches Architecture.md's "in-process for MVP." Revisit true sandboxing (separate runner container, gVisor, etc.) once the core run loop exists in Pass B.
- **Password hashing: argon2-cffi (Argon2id)**, not bcrypt/passlib — modern default, no input-length footgun.
- **Credential encryption: Fernet (`cryptography`)**, keyed by a new, separate, *required* `CREDENTIAL_ENCRYPTION_KEY` env var — deliberately not reusing `auth_secret_key` (different purpose, different blast radius if leaked). Unlike `auth_secret_key`'s insecure dev default, this field has no default in `config.py`, so the app fails fast at startup if it's unset rather than silently encrypting with a shared/guessable key.
- **No passphrase-protected SSH keys in Pass A.** Validated via `cryptography`'s `load_pem_private_key(data, password=None)` at upload time, rejected with a 400 if a passphrase is required. Sidesteps ssh-agent orchestration, which is a Pass B+ concern. Documented limitation, not a bug.
- **Playbooks stored on disk keyed by DB row id** (`{data_dir}/playbooks/{id}.yml`), never by user-supplied filename — eliminates path traversal structurally rather than via sanitization. The human-readable `name` is purely a DB column.
- **Inventory model: structured, true many-to-many hosts↔groups** (a host can belong to multiple groups, matching real Ansible semantics), not raw inventory-file editing. `InventoryHost.vars` is a flexible JSON blob for `ansible_host`/`ansible_port`/etc. without a rigid schema. No inventory-format rendering yet — only needed once Pass B actually executes a run.
- **Persistent data volume: `/data` inside the backend container**, independent of `/app` (source) — new `backend-data` named volume in `docker-compose.yml`; both Dockerfile targets ensure `/data` exists and (in `runtime`) is owned by the non-root `appuser`.
- **Frontend:** hand-built `Textarea`/`Dialog`/`Checkbox` primitives following the same Radix + `class-variance-authority` pattern as Phase 0's primitives (shadcn CLI still not a fit — see the earlier entry). Skipped the `tailwindcss-animate` plugin for dialog enter/exit transitions rather than add a dependency for it unused elsewhere; dialogs are functional but not animated for now.
- **Ruff config:** added `[tool.ruff.lint.flake8-bugbear] extend-immutable-calls` for `fastapi.Depends` and friends — FastAPI's dependency-injection pattern (`param: T = Depends(...)`) is the intended usage, not the mutable-default footgun B008 exists to catch.

### 2026-09-18 — Ansible bundled directly in the backend Docker image (full `ansible`, not `ansible-core`)
Locked in before Pass B (the run engine) starts: AnsiDeck must run fully self-contained, never relying on an Ansible or SSH install on the host. Added the full `ansible` PyPI package (not the minimal `ansible-core`) to `backend/pyproject.toml` — chosen over the minimal package so playbooks people already have (written against a normal Ansible install, using community collections like `community.general`/`ansible.posix`) work out of the box, rather than failing on missing collections until Phase 2's planned `ansible-galaxy` collection management lands. Added `openssh-client` at the OS level to both the `base` and `runtime` Dockerfile stages — Ansible's default connection plugin shells out to the system `ssh` binary, which `python:3.12-slim` doesn't include. Verified with more than `--version`: built a throwaway SSH-target container on a private Docker network, generated a real keypair, and ran both an ad-hoc `ansible ... -m ping` and a full `ansible-playbook` (with real fact-gathering) from the AnsiDeck backend's `runtime` image, as the non-root `appuser`, over real SSH — got `"pong"` and a successful play recap. Confirms the same image that will ship to users can actually reach and manage a remote host with zero host-side Ansible/SSH dependency.

<!-- Add new entries above this line, most recent first once the log grows -->
