# Dependencies and vulnerability management

This page says how AnsiDeck chooses, obtains and tracks the software it depends on, and how findings from
dependency scanning (software composition analysis, SCA) and from static analysis of its own code (SAST)
are handled. Reporting a vulnerability in AnsiDeck itself is covered by [SECURITY.md](../SECURITY.md).

## Choosing a dependency

A new dependency is added only when it clearly beats writing and maintaining the code ourselves. Before
adding one, the pull request says why, and the dependency must:

- be actively maintained (recent releases, responsive to security reports) and widely used, or small
  enough to review;
- have a license on the allowlist below;
- come from the ecosystem's standard registry (PyPI, npm, Docker Hub official or verified publishers,
  GitHub Actions from their authors);
- not duplicate something already in the tree.

## Obtaining dependencies

Every dependency is declared in a manifest and pinned in a lockfile, and installed with the ecosystem's
standard tool; nothing is copied into the repository ("vendored").

| What | Declared in | Pinned by | Installed with |
| --- | --- | --- | --- |
| Backend (Python) | `backend/pyproject.toml` | `backend/uv.lock` (versions and hashes) | `uv sync --frozen` |
| Frontend (JavaScript) | `frontend/package.json` | `frontend/package-lock.json` (versions and integrity hashes) | `npm ci` |
| Container base images | `backend/Dockerfile`, `frontend/Dockerfile`, `docker-compose.yml`, `deploy/compose.yaml` | image digests (`@sha256:…`) | Docker |
| CI actions | `.github/workflows/*.yml` | full commit SHAs | GitHub Actions |

The runtime images also install OS packages from Debian and Alpine with `apt-get` and `apk`, and apply
their security updates at build time.

## Tracking dependencies

- **Dependabot** proposes updates weekly for every manifest above, and security updates as soon as an
  advisory appears. Patch and minor updates (other than Docker images) merge automatically once all checks
  pass; Docker images and major versions wait for the maintainer.
- **Every pull request** is checked, and blocked on a finding, by required status checks:
  - `pip-audit` against [OSV](https://osv.dev/) (backend), which covers known vulnerabilities and packages
    reported as malicious (OpenSSF `MAL-` entries), and `npm audit` (frontend), which covers known
    vulnerabilities and npm malware advisories; both run inside the required CI jobs on the whole locked
    dependency tree;
  - **dependency review**, which fails when the change adds or updates a dependency with a known
    vulnerability of moderate or higher severity, or with a license outside the allowlist.
- **Every release** scans both images with Trivy and stops if any HIGH or CRITICAL vulnerability has a
  fix available.
- **GitHub's dependency graph** and Dependabot security alerts watch the default branch between changes.
- The images carry an SBOM (SPDX) listing every package, see
  [verifying-releases.md](verifying-releases.md).

## Policy for vulnerabilities in dependencies

Severities are the advisory's CVSS rating. "Fixed" means the vulnerable version is no longer used on
`main` and, if a release is affected, a patched release is published.

| Severity | Remediation threshold |
| --- | --- |
| Critical | within 7 days of the finding |
| High | within 14 days |
| Moderate | within 30 days, or with the next release if sooner |
| Low | with the next regular dependency update |

- A finding can be closed without an upgrade only if the vulnerable code can't be reached in AnsiDeck.
  That decision is recorded in the [VEX document](#vex-vulnerabilities-that-dont-affect-ansideck), with
  the reason, and the scanners that support it honour it.
- If no fixed version exists, the maintainer mitigates (configuration, removing the feature that uses it,
  or replacing the dependency) within the same threshold, or records why it isn't exploitable.
- **Malicious packages** are removed at once; a release that contained one is withdrawn and announced.

## Policy for licenses

AnsiDeck's own code is MIT. Dependencies must use one of these licenses (SPDX identifiers):

- Permissive: `MIT`, `MIT-0`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `0BSD`, `Zlib`,
  `Unlicense`, `CC0-1.0`, `BlueOak-1.0.0`, `PSF-2.0`, `Python-2.0`;
- weak copyleft: `MPL-2.0`, `LGPL-2.1-only`, `LGPL-2.1-or-later`, `LGPL-3.0-only`, `LGPL-3.0-or-later`;
- fonts: `OFL-1.1`;
- `GPL-3.0-only` and `GPL-3.0-or-later`, **for Ansible and its collections only**: AnsiDeck exists to run
  Ansible, and the backend image ships it under its own license.

Any other license, a missing license, or a new GPL dependency other than Ansible is a violation: the
dependency review check fails, and the dependency isn't added until the maintainer has decided, in the
pull request, to replace it or to extend this list (with the reason).

## Before a release

A release is only published when, at the time of the release:

- `main` has no open dependency finding past its remediation threshold;
- the required CI checks, including the dependency audits, passed on the release commit;
- the release workflow's Trivy scan of both images finds no fixable HIGH or CRITICAL vulnerability (it
  stops the release otherwise).

## Policy for findings from static analysis (SAST)

AnsiDeck's own code is analysed on every pull request by CodeQL (Python and TypeScript, its security
queries) and by ruff's security rules (bandit) and oxlint, as part of the required checks.

| Finding | Threshold |
| --- | --- |
| CodeQL alert of high or critical severity | blocks the merge (code scanning protection) |
| Any other CodeQL alert on a pull request | fixed before merging, or dismissed with a written reason |
| ruff security rule or oxlint error | blocks the merge (CI fails) |

A finding is suppressed only when it's a false positive or can't be exploited, and only where it occurs:
a CodeQL dismissal with its reason, or a `# noqa: <rule> - <reason>` / `// oxlint-disable-next-line
<rule> -- <reason>` on that line. Alerts found on `main` by the weekly scan follow the dependency
thresholds above.

## VEX: vulnerabilities that don't affect AnsiDeck

[`.vex/ansideck.openvex.json`](../.vex/ansideck.openvex.json) is an [OpenVEX](https://openvex.dev/) document
listing vulnerabilities in components that scanners report but that don't affect AnsiDeck, each with its
status (for example `not_affected`) and justification. The release scan passes it to Trivy, so recorded
non-exploitable findings don't stop a release, and anyone scanning the images can use it too. It is empty
until such a finding exists.

## Published vulnerabilities

Vulnerabilities in AnsiDeck itself are published as
[GitHub security advisories](https://github.com/HoneyBearTech/AnsiDeck/security/advisories), with the
affected and fixed versions, how to tell whether you're affected, and how to fix or mitigate, as
described in [SECURITY.md](../SECURITY.md).
