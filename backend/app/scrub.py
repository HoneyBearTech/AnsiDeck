"""Best-effort secret redaction for run output.

Defense-in-depth only: `no_log: true` and Ansible Vault remain the primary
controls. Never import ansible.cli here (blocking-IO crash); ansible.parsing
via app.vault is safe.
"""

import json
import re
from collections.abc import Callable, Iterable
from typing import Any

import yaml

from app.vault import VaultError, decrypt_vault_text

REDACTED = "[REDACTED]"

_SECRET_TOKENS = {
    "password",
    "passwd",
    "pass",
    "passphrase",
    "secret",
    "secrets",
    "token",
    "tokens",
    "key",
    "credential",
    "credentials",
    "private",
}
# A key ending in one of these names a location/identifier, not the secret itself.
_NON_SECRET_SUFFIXES = {"file", "path", "dir", "id", "name"}
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_KEY_SPLIT = re.compile(r"[_\-\s.]+")

_MIN_SECRET_LEN = 4
_PLAIN_SUBSTRING_LEN = 8
_MIN_LINE_LEN = 8
_VAULT_PREFIX = "$ANSIBLE_VAULT"


def is_secret_key(name: str) -> bool:
    tokens = [t.lower() for t in _KEY_SPLIT.split(_CAMEL_BOUNDARY.sub("_", name)) if t]
    if not tokens or tokens[-1] in _NON_SECRET_SUFFIXES:
        return False
    return any(t in _SECRET_TOKENS for t in tokens)


def mask_secret_keys(obj: Any, under_secret: bool = False) -> Any:
    if isinstance(obj, dict):
        return {
            k: mask_secret_keys(v, under_secret or is_secret_key(str(k))) for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [mask_secret_keys(v, under_secret) for v in obj]
    if under_secret and obj is not None and not isinstance(obj, bool):
        return REDACTED
    return obj


def _collect_named_values(
    obj: Any, out: set[str], under_secret: bool = False, seen: set | None = None
) -> None:
    # Untrusted YAML can share containers through aliases: visiting each once (per secret
    # context) keeps an alias bomb linear.
    if seen is None:
        seen = set()
    if isinstance(obj, (dict, list)):
        if (id(obj), under_secret) in seen:
            return
        seen.add((id(obj), under_secret))
    if isinstance(obj, dict):
        for k, v in obj.items():
            _collect_named_values(v, out, under_secret or is_secret_key(str(k)), seen)
    elif isinstance(obj, list):
        for v in obj:
            _collect_named_values(v, out, under_secret, seen)
    elif under_secret and obj is not None and not isinstance(obj, bool):
        out.add(str(obj))


class _VaultText(str):
    pass


class _PlaybookLoader(yaml.SafeLoader):
    pass


_PlaybookLoader.add_constructor(
    "!vault", lambda loader, node: _VaultText(loader.construct_scalar(node))
)


def _collect_vault_texts(obj: Any, out: list[str], seen: set[int] | None = None) -> None:
    # YAML aliases share containers; visiting each once keeps an alias bomb
    # ("billion laughs") linear instead of exponential.
    if seen is None:
        seen = set()
    if isinstance(obj, str):
        if isinstance(obj, _VaultText) or obj.lstrip().startswith(_VAULT_PREFIX):
            out.append(str(obj))
    elif isinstance(obj, (dict, list)):
        if id(obj) in seen:
            return
        seen.add(id(obj))
        for v in obj.values() if isinstance(obj, dict) else obj:
            _collect_vault_texts(v, out, seen)


def collect_secrets(
    *,
    ssh_key_pem: str,
    vault_password: str | None,
    playbook_text: str,
    extra_vars: dict | None,
    host_vars: Iterable[dict],
    repo_vars_texts: Iterable[str] = (),
) -> set[str]:
    """`repo_vars_texts`: a git run's variable files (group_vars, host_vars, vars, role vars
    and defaults). Their values under secret-looking keys count, their vaulted values too, and
    every value of a whole-file vault."""
    secrets: set[str] = {ssh_key_pem.strip()}
    if vault_password:
        secrets.add(vault_password)

    host_vars = list(host_vars)
    _collect_named_values(extra_vars, secrets)
    for hv in host_vars:
        _collect_named_values(hv, secrets)

    repo_vars: list[Any] = []
    for text in repo_vars_texts:
        if text.lstrip().startswith(_VAULT_PREFIX):
            if vault_password:
                try:
                    plain = decrypt_vault_text(text, vault_password)
                except VaultError:
                    continue
                _collect_named_values(_load_yaml(plain), secrets, under_secret=True)
            continue
        repo_vars.append(_load_yaml(text))
    for data in repo_vars:
        _collect_named_values(data, secrets)

    if vault_password:
        vaulted: list[str] = []
        _collect_vault_texts(_load_yaml(playbook_text), vaulted)
        _collect_vault_texts(extra_vars, vaulted)
        for hv in host_vars:
            _collect_vault_texts(hv, vaulted)
        for data in repo_vars:
            _collect_vault_texts(data, vaulted)
        for text in vaulted:
            try:
                secrets.add(decrypt_vault_text(text, vault_password))
            except VaultError:
                pass
    return secrets


def _load_yaml(text: str) -> Any:
    try:
        return yaml.load(text, Loader=_PlaybookLoader)  # noqa: S506 - SafeLoader subclass
    except (yaml.YAMLError, RecursionError):  # too deep to parse = unparsable
        return None


def _variants(secret: str) -> set[str]:
    secret = secret.strip("\r\n")
    variants = {secret, json.dumps(secret)[1:-1]}
    if "\n" in secret:
        for line in secret.splitlines():
            line = line.strip()
            if len(line) >= _MIN_LINE_LEN:
                variants.add(line)
                variants.add(json.dumps(line)[1:-1])
    return {v for v in variants if len(v) >= _MIN_SECRET_LEN}


def _exact_regex(secrets: Iterable[str]) -> re.Pattern[str] | None:
    variants: set[str] = set()
    for secret in secrets:
        variants |= _variants(secret)
    if not variants:
        return None
    parts = []
    for v in sorted(variants, key=len, reverse=True):
        escaped = re.escape(v)
        parts.append(escaped if len(v) >= _PLAIN_SUBSTRING_LEN else rf"(?<!\w){escaped}(?!\w)")
    return re.compile("|".join(parts))


def _keep_prefix(m: re.Match[str]) -> str:
    return m.group("pre") + REDACTED


def _redact_assignment(m: re.Match[str]) -> str:
    value = m.group("val")
    if REDACTED in value:
        return m.group(0)
    quote = value[0] if value[0] in "\"'" else ""
    return m.group("pre") + quote + REDACTED + quote


# (pattern, replacement) — each pattern scopes its own inline flags; a global
# (?i) inside a combined alternation raises re.PatternError.
_PATTERNS: list[tuple[re.Pattern[str], Callable[[re.Match[str]], str] | str]] = [
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?"
            r"(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)"
        ),
        REDACTED,
    ),
    (
        re.compile(
            r"(?P<pre>(?i:\bauthorization\b)\s*[=:]\s*(?i:bearer|basic)\s+)[A-Za-z0-9._~+/=-]+"
        ),
        _keep_prefix,
    ),
    (re.compile(r"(?P<pre>://[^\s/:@]+:)[^\s/@]+(?=@)"), _keep_prefix),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), REDACTED),
    (
        re.compile(
            r"""(?P<pre>(?i:\b(?:password|passwd|secret|token|api[_-]?key)\b)["']?\s*[=:]\s*)"""
            r"""(?P<val>"[^"\\]*"|'[^'\\]*'|[^\s"',}\\]+)"""
        ),
        _redact_assignment,
    ),
]


class Scrubber:
    def __init__(self, secrets: Iterable[str]) -> None:
        self._exact = _exact_regex(secrets)

    def scrub_text(self, text: str) -> str:
        if self._exact is not None:
            text = self._exact.sub(REDACTED, text)
        for pattern, repl in _PATTERNS:
            text = pattern.sub(repl, text)
        return text

    def _scrub_value(self, value: Any, key: str | None = None) -> Any:
        if isinstance(value, str):
            return self.scrub_text(value)
        if isinstance(value, dict):
            return self._scrub_dict(value)
        if isinstance(value, list):
            if (
                key is not None
                and key.endswith("_lines")
                and all(isinstance(i, str) for i in value)
            ):
                joined = "\n".join(value)
                scrubbed = self.scrub_text(joined)
                return value if scrubbed == joined else scrubbed.split("\n")
            return [self._scrub_value(v) for v in value]
        return value

    def _scrub_dict(self, value: dict) -> dict:
        # Keys can carry secrets too (e.g. a with_dict loop keyed by a token).
        # A redacted key gets a "#n" suffix when its new name is taken, so no
        # value is silently overwritten.
        out: dict = {}
        for k, v in value.items():
            new_k = self.scrub_text(k) if isinstance(k, str) else k
            if new_k != k:
                base, n = new_k, 2
                while new_k in out or new_k in value:
                    new_k, n = f"{base}#{n}", n + 1
            out[new_k] = self._scrub_value(v, k if isinstance(k, str) else None)
        return out

    def scrub_event(self, event: dict) -> dict:
        # Fail closed: a scrubbing error must never let the raw event through.
        try:
            return self._scrub_value(event)
        except Exception:  # noqa: BLE001
            return {
                "event": "redaction_error",
                "stdout": "[event withheld: output scrubber failed]",
                "uuid": event.get("uuid") if isinstance(event, dict) else None,
                "counter": event.get("counter") if isinstance(event, dict) else None,
            }


def scrub_exact(data: Any, secrets: Iterable[str]) -> tuple[Any, bool]:
    """`data` with every exact secret (and its variants) redacted in strings and keys, and
    whether anything was. No patterns: inventory data (URLs, assignments in descriptions)
    must stay as it is unless it holds one of the secrets themselves."""
    regex = _exact_regex(secrets)
    changed = False

    def text(value: str) -> str:
        nonlocal changed
        new = regex.sub(REDACTED, value)
        changed = changed or new != value
        return new

    def walk(value: Any) -> Any:
        if isinstance(value, str):
            return text(value)
        if isinstance(value, list):
            return [walk(v) for v in value]
        if isinstance(value, dict):
            out: dict = {}
            for k, v in value.items():
                new_k = text(k) if isinstance(k, str) else k
                base, n = new_k, 2
                while new_k in out:
                    new_k, n = f"{base}#{n}", n + 1
                out[new_k] = walk(v)
            return out
        return value

    if regex is None:
        return data, False
    return walk(data), changed


def build_scrubber(secrets: Iterable[str]) -> Callable[[dict], dict]:
    return Scrubber(secrets).scrub_event
