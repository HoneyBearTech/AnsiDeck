"""Allowlisted environments for subprocesses that must never see the app's own secrets
(encryption key, auth key, admin password). Built from an allowlist, not os.environ:
anything not named here is dropped."""

import os
from collections.abc import Mapping

PASSTHROUGH_ENV = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
)


def clean_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {k: os.environ[k] for k in PASSTHROUGH_ENV if k in os.environ}
    if extra:
        env.update(extra)
    return env
