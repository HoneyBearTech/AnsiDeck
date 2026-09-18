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

<!-- Add new entries above this line, most recent first once the log grows -->
