# Governance

AnsiDeck is a personal open-source project with a single maintainer. This document says how decisions are
made, who does what, and how the project carries on if the maintainer can't.

## Decision model

AnsiDeck follows a "benevolent dictator" model: the maintainer makes the final call on every decision,
including what is in scope, which pull requests are merged, and when a release is made.

Decisions happen in the open wherever possible:

- **Bugs, features and questions** are discussed in [GitHub Issues](https://github.com/HoneyBearTech/AnsiDeck/issues).
  Anyone can open one or comment.
- **Changes** land only through pull requests to `main`, which is protected: every pull request must pass
  the required CI checks, and it is squash-merged. The pull request description records what changed and
  why.
- **Direction** is published in the [roadmap](docs/roadmap.md), including what the project does not
  intend to do. Larger design choices are explained in the pull requests that make them.
- **Security reports** are handled privately, as described in [SECURITY.md](SECURITY.md), until a fix is
  released.

If you disagree with a decision, say so in the issue or pull request. The maintainer will explain the
reasoning, and may change course. Because the code is MIT-licensed, you can always fork it.

## Roles and responsibilities

| Role | Who | Responsibilities |
| --- | --- | --- |
| Maintainer | Sean Stoube ([@HoneyBearTech](https://github.com/HoneyBearTech)) | Triage issues; review and merge pull requests; keep CI, dependencies and documentation current; respond to vulnerability reports as described in [SECURITY.md](SECURITY.md); cut and sign releases; enforce the [Code of Conduct](CODE_OF_CONDUCT.md); keep this document and the continuity arrangements below up to date. |
| Contributor | Anyone who opens an issue or pull request | Follow [CONTRIBUTING.md](CONTRIBUTING.md) (coding standards, tests, sign-off) and the [Code of Conduct](CODE_OF_CONDUCT.md); report vulnerabilities privately. |
| Security reporter | Anyone who reports a vulnerability | Report privately and allow time for a fix before disclosing, as described in [SECURITY.md](SECURITY.md). |

Automated tools also take part: Dependabot proposes dependency updates (patch and minor updates to
packages merge automatically once CI passes; Docker base images and major versions wait for the
maintainer), and CI, CodeQL, fuzzing and OpenSSF Scorecard check every change.

## Continuity

The project must be able to carry on, with issues opened and closed, changes accepted and releases made,
within a week of it being confirmed that the maintainer can no longer support it. To make that possible:

- The credentials needed to run the project are kept in a password manager, and a trusted person the
  maintainer has chosen is set up for **emergency access** to them. This covers the GitHub account that
  owns the repository and its two-factor recovery codes, and the SSH key that signs release tags. Release
  images are signed keylessly by GitHub Actions, so whoever controls the repository can keep publishing
  verifiable releases.
- A written succession note, kept with the maintainer's personal papers, gives that person the right to
  continue the project or to hand it to a new maintainer, and says how to reach them.
- Everything else needed to keep working on the project is in this repository: the code, the CI
  configuration, the release process and the documentation.

Names and credentials are deliberately not published here. If the maintainer becomes unable to continue,
the successor will announce it in a pinned issue and update this file.

This is still a one-person project, so its "bus factor" is 1: these arrangements keep the project from
being stranded, but they don't replace a second active maintainer. People who contribute regularly may be
invited to become maintainers; this document will be updated when that happens.
