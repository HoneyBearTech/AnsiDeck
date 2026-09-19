"""Ansible Vault encrypt/decrypt helpers.

Never import ansible.cli / ansible.cli.vault here — importing them crashes with
"Ansible requires blocking IO on stdin/stdout/stderr" outside a real terminal.
ansible.parsing.vault is safe; the YAML-block formatter is hand-rolled below.
"""

from ansible.errors import AnsibleError
from ansible.parsing.vault import VaultLib, VaultSecret

_YAML_BLOCK_INDENT = 10


class VaultError(Exception):
    pass


def _lib(password: str) -> tuple[VaultLib, VaultSecret]:
    secret = VaultSecret(password.encode())
    return VaultLib(secrets=[("default", secret)]), secret


def encrypt_to_vault_envelope(plaintext: str, password: str) -> str:
    vault, secret = _lib(password)
    try:
        return vault.encrypt(plaintext, secret=secret).decode()
    except AnsibleError as exc:
        raise VaultError(str(exc)) from exc


def to_yaml_block(envelope: str, var_name: str | None = None) -> str:
    header = f"{var_name}: !vault |" if var_name else "!vault |"
    indent = " " * _YAML_BLOCK_INDENT
    return "\n".join([header, *(f"{indent}{line}" for line in envelope.splitlines())])


def decrypt_vault_text(vaulted_text: str, password: str) -> str:
    lines = [line.strip() for line in vaulted_text.strip().splitlines()]
    if lines and "!vault" in lines[0]:
        lines = lines[1:]
    envelope = "\n".join(line for line in lines if line)

    vault, _ = _lib(password)
    try:
        return vault.decrypt(envelope.encode()).decode()
    except AnsibleError as exc:
        raise VaultError(str(exc)) from exc
    except UnicodeDecodeError as exc:
        raise VaultError("Decrypted content is not valid UTF-8 text") from exc
