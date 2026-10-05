# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities using [GitHub's private vulnerability reporting](https://github.com/HoneyBearTech/AnsiDeck/security/advisories/new) rather than a public issue.

Include what you found, how to reproduce it (a minimal setup, the requests or playbook involved), which version or commit you tested, and what an attacker gains. If you'd like to be credited under a particular name, or not at all, say so.

## How reports are handled

This is a personal project maintained by one person (see [GOVERNANCE.md](GOVERNANCE.md)), so these are targets rather than a contractual SLA:

1. **Acknowledge** the report within 7 days.
2. **Triage** it: reproduce the problem, decide whether it is a vulnerability in AnsiDeck (see "Scope" below), and agree its severity with you. If it isn't a vulnerability, you'll get an explanation, and the report may move to a public issue with your agreement.
3. **Fix** it privately in a [GitHub security advisory](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/about-repository-security-advisories), with a regression test, and invite you to review the fix if you want to.
4. **Release** the fix, then publish the advisory (requesting a CVE where it applies) with the affected and fixed versions and any workaround. The aim is to release fixes for critical and high-severity issues within 30 days of the report and others within 90 days, and to keep you updated at least every 14 days until then.
5. **Credit** the reporter in the advisory and the release notes, unless you ask to stay anonymous.

Please keep the details private until the advisory is published, or for 90 days after your report if no fix has been released by then; if you need a different timeline, say so in the report.

## Supported Versions

Security fixes go into `main` and the most recent release. Until the first tagged release exists, only `main` is supported. Older releases are not patched: upgrading to the latest release is the supported path, and the release notes say when an upgrade needs extra steps.

## Scope

AnsiDeck holds SSH keys and vault passwords and runs Ansible against real infrastructure, so treat a deployment as a sensitive system. It is designed to run on a trusted network behind a reverse proxy that terminates TLS, and it is **not** designed or tested to be exposed directly to the public internet.

What AnsiDeck does and doesn't protect against is described in [docs/security.md](docs/security.md) (its security requirements), and the reasoning behind it in [docs/assurance-case.md](docs/assurance-case.md) (threat model, trust boundaries and the defences against common weaknesses). Read them before you deploy or report.

Reports of authentication or authorization bypass, credential or secret exposure, cross-project access, or anything that breaks the boundaries described there are in scope. Issues that require an already-trusted operator to run a malicious playbook are expected behaviour, not vulnerabilities, unless the playbook breaks out of the run isolation described there.
