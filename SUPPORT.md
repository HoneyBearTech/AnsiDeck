# Support

AnsiDeck is maintained by one person in their own time (see [GOVERNANCE.md](GOVERNANCE.md)), so this is a
best-effort policy, not a contract.

## Getting help

- **Questions, bugs and feature ideas**: [GitHub Issues](https://github.com/HoneyBearTech/AnsiDeck/issues).
  Say which version you run, how you deployed it, and what you expected.
- **Security vulnerabilities**: never in a public issue; see [SECURITY.md](SECURITY.md).
- **Documentation**: [docs/](docs/README.md), starting with the [user guide](docs/user-guide/README.md).

## Which versions are supported, and for how long

| Version | Supported with | Until |
| --- | --- | --- |
| The latest release (currently 0.5.x) | bug fixes and security fixes | the next release is published |
| An older release | nothing | it stopped being supported when the next release came out |
| `main` | bug fixes and security fixes | always (it's where fixes land first) |

- A fix is released as a new version (a patch release such as 0.2.1 for fixes only), never applied to an
  older release.
- **A release stops receiving security updates the moment the next release is published.** The release
  notes and [CHANGELOG.md](CHANGELOG.md) say what changed and whether upgrading needs steps; upgrading is
  described in [docs/upgrading.md](docs/upgrading.md).
- Before 1.0, a minor release (0.2.0) may change behaviour or need upgrade steps; they're listed in the
  changelog under "Upgrading".
- If a supported line will end differently (for example a 1.x line kept alive after 2.0), it will be
  announced in the release notes and in this table first.

Container images stay available on GitHub Container Registry after their support ends, so existing
deployments keep working, but they won't get fixes: run the latest release.
