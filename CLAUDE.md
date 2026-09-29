# AnsiDeck — Project Context for Claude Code

Self-hosted, Dockerized web UI for running Ansible playbooks against target systems — replacing a WSL + CLI workflow.

## Before Making Structural Changes
Read the project's notes first. They live outside this repo, in the owner's Obsidian vault **Chronos** at `~/Chronos/Projects/AnsiDeck/` (every file is prefixed `ansideck-`):
- `ansideck-roadmap.md` — feature roadmap by phase (what's in scope now vs. later)
- `ansideck-Pass-Map.md` — pass-by-pass delivery log (what shipped in which commit, and which passes are planned); add a row when a pass ships
- `ansideck-Architecture.md` — current architecture decisions and suggested stack
- `ansideck-Security-Considerations.md` — credential handling, execution isolation, access control checklist (this app holds SSH keys and runs automation against real infra — treat security notes as load-bearing, not optional)
- `ansideck-Decisions-Log.md` — ADR-style log of why past decisions were made
- `ansideck-UI-Design.md` — visual/theme direction for the frontend (dark mode default, palette, typography, component approach)

Update these files (roadmap checkboxes, decisions log, architecture doc) as the project evolves — they're the source of truth for project direction, not just planning artifacts.

**The notes never go into this repo.** They were scrubbed from its git history on 2026-09-18 at the project owner's request and moved out of the repo into Chronos on 2026-09-29. Don't copy them back in. Chronos is versioned in its own private repo; only commit or push it when the owner asks. The old in-repo vault path `.obsidian-docs/` stays gitignored.

## Stack (see ansideck-Architecture.md for full detail)
- Backend: Python (FastAPI), dependency management via `uv`. `ansible-runner` integration lands in Phase 1 — Phase 0 is scaffolding + auth stub only.
- Frontend: React + TypeScript (Vite), Tailwind v4 (CSS-first `@theme` tokens in `src/index.css`), hand-built shadcn-style UI primitives (Radix + `class-variance-authority`) — see ansideck-Decisions-Log.
- Local dev/deploy: Docker Compose

## Conventions
- Frontend ships dark-mode-first per `ansideck-UI-Design.md` — don't default to a light theme or build light mode first "to add dark mode later."
- No secrets, private keys, or vault passwords committed — ever. `.gitignore` has Python + Ansible-specific entries; extend it rather than working around it.
- New architectural decisions get a dated entry in `ansideck-Decisions-Log.md`.
- Roadmap checkboxes in `ansideck-roadmap.md` should be checked off as features land, and new ideas added to the Icebox section rather than scope-creeping into whatever phase is active.

## Commands

### Local dev (whole stack)
- `cp .env.example .env` then edit as needed (first-time setup)
- `docker compose up --build` — starts backend (`:8000`) + frontend (`:5173`) with hot reload

### Backend (`/backend`)
- `uv sync --all-groups` — install deps (dev + runtime)
- `uv run fastapi dev app/main.py` — run standalone (outside Docker)
- `uv run pytest` — run tests
- `uv run ruff check .` / `uv run ruff format .` — lint / format

### Frontend (`/frontend`)
- `npm install` — install deps
- `npm run dev` — run standalone (outside Docker)
- `npm run lint` — oxlint
- `npm run typecheck` — `tsc -b --noEmit`
- `npm run build` — production build to `dist/`
