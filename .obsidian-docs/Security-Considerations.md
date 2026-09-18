# Security Considerations

AnsiDeck's whole job is holding SSH credentials and running arbitrary automation against real infrastructure. Treat this file as a running checklist, not a one-time read.

## Credentials & Secrets
- [x] SSH private keys stored encrypted at rest (not plaintext in the DB or filesystem) — Fernet, keyed by a dedicated `CREDENTIAL_ENCRYPTION_KEY` with no insecure default. See [[Decisions-Log]]
- [ ] Decrypt only in-memory, per-run, into a temp file with `0600` perms, deleted immediately after the run
- [ ] Ansible Vault passwords handled the same way — never logged, never returned in API responses
- [ ] Playbook output scrubbed for secrets before storage/display (respect `no_log: true`; consider a secondary regex-based scrubber as defense-in-depth)
- [x] `.gitignore` already excludes common secret patterns — double check vault password files, `*.retry`, and any local inventory files with embedded secrets are covered — done in Phase 0, see [[Decisions-Log]]

## Execution Isolation
- [x] Decide whether playbook execution runs in the same container as the web app or an isolated "runner" container/sidecar — decided: same container for the Phase 1 MVP, revisit true sandboxing later. See [[Decisions-Log]]. (No execution code exists yet — this is the decision only, implementation is Phase 1 Pass B.)
- [ ] Constrain the execution environment's network access to only the intended target hosts where feasible
- [ ] Don't run the execution process as root inside the container unless a specific playbook genuinely requires it

## Access Control
- [x] No auth = no MVP ship to anything but localhost. Even Phase 1 needs real login before this touches a network others can reach. — DB-backed argon2 auth landed in Phase 1 Pass A
- [ ] RBAC (Phase 3) before this is multi-user — a "viewer" should not be able to trigger runs or read credentials
- [ ] Audit log every run: who, what playbook, what target, what vars, what result — this is as much a safety net for the user as a security feature

## Input Handling
- [ ] Validate/sanitize inventory and extra-vars input from the UI before it reaches `ansible-runner`
- [ ] Rate-limit or queue runs to avoid accidentally hammering target systems from the UI

## Supply Chain
- [ ] Pin dependency versions (Python + JS) and keep a routine for updating them
- [ ] If supporting `ansible-galaxy` role/collection installs (Phase 2), be aware this pulls and executes third-party code — worth a warning in the UI
