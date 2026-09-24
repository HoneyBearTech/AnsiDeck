import json

import pytest

from app.scrub import (
    REDACTED,
    Scrubber,
    build_scrubber,
    collect_secrets,
    is_secret_key,
    mask_secret_keys,
)
from app.vault import encrypt_to_vault_envelope, to_yaml_block


@pytest.mark.parametrize(
    "name",
    [
        "password",
        "db_password",
        "ansible_password",
        "ansible_become_pass",
        "ansible_ssh_pass",
        "api_key",
        "apiKey",
        "client-secret",
        "auth_token",
        "private_key",
        "credentials",
    ],
)
def test_is_secret_key_true(name: str) -> None:
    assert is_secret_key(name)


@pytest.mark.parametrize(
    "name",
    [
        "keyboard_layout",
        "bypass_cache",
        "monkey",
        "hostname",
        "marker_path",
        "ssh_key_file",
        "ansible_ssh_private_key_file",
        "key_id",
        "token_name",
        "",
    ],
)
def test_is_secret_key_false(name: str) -> None:
    assert not is_secret_key(name)


def test_mask_secret_keys_masks_leaves_under_secret_keys_only() -> None:
    masked = mask_secret_keys(
        {
            "db_password": "hunter2hunter2",
            "nested": {"api_key": ["a-long-key-1", "a-long-key-2"], "region": "us-east-1"},
            "greeting": "hello",
            "secret_flag": True,
            "count": 5,
            "empty_token": None,
            "ssh_key_path": "/home/u/.ssh/id",
        }
    )
    assert masked == {
        "db_password": REDACTED,
        "nested": {"api_key": [REDACTED, REDACTED], "region": "us-east-1"},
        "greeting": "hello",
        "secret_flag": True,
        "count": 5,
        "empty_token": None,
        "ssh_key_path": "/home/u/.ssh/id",
    }


def test_exact_secret_is_redacted() -> None:
    scrubber = Scrubber({"correct-horse-battery"})
    assert scrubber.scrub_text("pw is correct-horse-battery ok") == f"pw is {REDACTED} ok"


def test_longest_secret_wins_over_overlapping_shorter_one() -> None:
    scrubber = Scrubber({"hunter2hunter2", "hunter2h"})
    assert scrubber.scrub_text("x hunter2hunter2 y") == f"x {REDACTED} y"


def test_multiline_secret_lines_are_redacted_individually() -> None:
    scrubber = Scrubber({"first-line-secret\nsecond-line-secret"})
    out = scrubber.scrub_text("only second-line-secret leaked here")
    assert "second-line-secret" not in out
    assert REDACTED in out


def test_json_escaped_form_is_redacted() -> None:
    secret = 'pa"ss\nword-long'
    scrubber = Scrubber({secret})
    escaped = json.dumps(secret)[1:-1]
    assert secret not in scrubber.scrub_text(f"raw: {secret}")
    assert escaped not in scrubber.scrub_text(f"json: {escaped}")


def test_short_secrets_do_not_shred_output() -> None:
    scrubber = Scrubber({"abc", "yes"})
    text = "abc yes abcdef yesterday"
    assert scrubber.scrub_text(text) == text


def test_four_to_seven_char_secrets_only_match_whole_words() -> None:
    scrubber = Scrubber({"abcd"})
    assert scrubber.scrub_text("abcd abcde xabcd (abcd)") == f"{REDACTED} abcde xabcd ({REDACTED})"


def test_eight_plus_char_secret_matches_inside_words() -> None:
    scrubber = Scrubber({"12345678"})
    assert scrubber.scrub_text("id=x12345678y") == f"id=x{REDACTED}y"


def test_event_structure_is_preserved_and_all_string_fields_scrubbed() -> None:
    scrub = build_scrubber({"super-secret-value"})
    event = {
        "uuid": "u1",
        "counter": 7,
        "event": "runner_on_ok",
        "stdout": "ok => super-secret-value",
        "event_data": {
            "task": "t",
            "res": {
                "changed": False,
                "msg": "super-secret-value here",
                "cmd": ["echo", "super-secret-value"],
                "stdout_lines": ["fine", "super-secret-value"],
            },
        },
    }
    out = scrub(event)
    assert "super-secret-value" not in json.dumps(out)
    assert out["uuid"] == "u1" and out["counter"] == 7 and out["event"] == "runner_on_ok"
    assert out["event_data"]["res"]["changed"] is False
    assert out["event_data"]["res"]["stdout_lines"][0] == "fine"
    assert event["stdout"] == "ok => super-secret-value"  # input not mutated


def test_secret_dict_keys_are_redacted_without_dropping_values() -> None:
    scrub = build_scrubber({"tokentokentoken"})
    out = scrub({"res": {"tokentokentoken": 1, "[REDACTED]": 2, "other": 3, "[REDACTED]#2": 4}})
    assert out == {"res": {"[REDACTED]#3": 1, "[REDACTED]": 2, "other": 3, "[REDACTED]#2": 4}}


def test_secret_split_across_stdout_lines_is_caught() -> None:
    scrub = build_scrubber({"first-line-secret\nsecond-line-secret"})
    out = scrub({"res": {"stdout_lines": ["first-line-secret", "second-line-secret"]}})
    assert "first-line-secret" not in json.dumps(out)
    assert "second-line-secret" not in json.dumps(out)


def test_untouched_lists_are_left_alone() -> None:
    scrub = build_scrubber({"super-secret-value"})
    event = {"res": {"stdout_lines": ["a", "b"], "items": [1, 2, "c"]}}
    assert scrub(event) == event


@pytest.mark.parametrize(
    ("text", "leaked"),
    [
        (
            (
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEfakefakefake\nabcdefghij\n"
                "-----END RSA PRIVATE KEY-----"
            ),
            "MIIEfakefakefake",
        ),
        ("-----BEGIN OPENSSH PRIVATE KEY-----\ntruncatedbody", "truncatedbody"),
        ("Authorization: Bearer abcDEF123.tok-en_x", "abcDEF123"),
        ("authorization=basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("fetching https://deploy:s3cr3tpw@example.com/repo.git", "s3cr3tpw"),
        ("key AKIAABCDEFGHIJKLMNOP found", "AKIAABCDEFGHIJKLMNOP"),
        ("tok ghp_abcdefghijklmnopqrstuvwxyz0123 x", "ghp_abcdefghijklmnopqrstuvwxyz0123"),
        ("connect password=hunter2 now", "hunter2"),
        ('{"password": "hunter2 spaced"}', "hunter2"),
        ("API_KEY: abc123def", "abc123def"),
        ("secret='quoted value'", "quoted value"),
    ],
)
def test_patterns_catch_unknown_secrets(text: str, leaked: str) -> None:
    out = Scrubber(set()).scrub_text(text)
    assert leaked not in out
    assert REDACTED in out


def test_assignment_pattern_keeps_key_and_quotes() -> None:
    scrubber = Scrubber(set())
    assert scrubber.scrub_text("password=hunter2 next") == f"password={REDACTED} next"
    assert scrubber.scrub_text('"token": "abc123"') == f'"token": "{REDACTED}"'


@pytest.mark.parametrize(
    "text",
    [
        "tokens: 5",
        "keyboard_layout: us",
        "the passwords are stored elsewhere",
        "TASK [Gather facts] ***",
        "ok: [host] => changed=false",
        "$ANSIBLE_VAULT;1.1;AES256\n6162636465666768",
        "https://example.com/path",
        "user@example.com",
    ],
)
def test_patterns_leave_benign_text_alone(text: str) -> None:
    assert Scrubber(set()).scrub_text(text) == text


def test_already_redacted_assignment_is_not_double_processed() -> None:
    scrubber = Scrubber({"hunter2hunter2"})
    assert scrubber.scrub_text("password=hunter2hunter2") == f"password={REDACTED}"


def test_scrubber_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    scrubber = Scrubber({"super-secret-value"})

    def boom(*_args, **_kwargs):
        raise RuntimeError("scrubber broke")

    monkeypatch.setattr(scrubber, "_scrub_value", boom)
    out = scrubber.scrub_event({"uuid": "u9", "counter": 3, "stdout": "super-secret-value"})

    assert out["event"] == "redaction_error"
    assert out["uuid"] == "u9" and out["counter"] == 3
    assert "super-secret-value" not in json.dumps(out)


def test_no_secrets_is_a_passthrough_for_plain_events() -> None:
    event = {"event": "playbook_on_start", "stdout": "PLAY [all] ***", "counter": 1}
    assert build_scrubber(set())(event) == event


def test_collect_secrets_gathers_all_sources() -> None:
    vault_password = "vault-pw-for-test"
    block = to_yaml_block(
        encrypt_to_vault_envelope("playbook-vaulted-plaintext", vault_password), "vaulted"
    )
    playbook = "- hosts: all\n  vars:\n" + "\n".join("    " + line for line in block.splitlines())
    playbook += "\n  tasks: []\n"
    envelope = encrypt_to_vault_envelope("extra-vars-vaulted-plaintext", vault_password)

    secrets = collect_secrets(
        ssh_key_pem="-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n",
        vault_password=vault_password,
        playbook_text=playbook,
        extra_vars={
            "db_password": "extra-var-password",
            "nested": {"api_key": ["k-one-long", 12345678]},
            "sealed": envelope,
            "harmless": "not-a-secret-value",
            "flag_token": True,
        },
        host_vars=[{"ansible_password": "host-var-password", "marker_path": "/tmp/m"}],
    )

    assert vault_password in secrets
    assert "playbook-vaulted-plaintext" in secrets
    assert "extra-vars-vaulted-plaintext" in secrets
    assert "extra-var-password" in secrets
    assert "k-one-long" in secrets and "12345678" in secrets
    assert "host-var-password" in secrets
    assert any(s.startswith("-----BEGIN OPENSSH PRIVATE KEY-----") for s in secrets)
    assert "not-a-secret-value" not in secrets
    assert "/tmp/m" not in secrets
    assert "True" not in secrets


def test_collect_secrets_tolerates_bad_playbook_and_wrong_vault_password() -> None:
    envelope = encrypt_to_vault_envelope("whatever-plaintext", "right-password")
    secrets = collect_secrets(
        ssh_key_pem="key",
        vault_password="wrong-password",
        playbook_text="{ this: is: not: valid yaml",
        extra_vars={"sealed": envelope},
        host_vars=[],
    )
    assert "whatever-plaintext" not in secrets
    assert "wrong-password" in secrets
