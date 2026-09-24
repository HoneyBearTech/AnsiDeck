"""Property-based tests (Hypothesis) for the code that handles untrusted text:
the output scrubber, the vault helpers and the inventory renderer.

Each property is a plain Hypothesis test so a coverage-guided fuzzer can
reuse it later via `test_x.hypothesis.fuzz_one_input`.
"""

import re
import time

import pytest
import yaml
from ansible.parsing.yaml.loader import AnsibleLoader
from hypothesis import example, given, settings
from hypothesis import strategies as st

from app.inventory_render import render_inventory_yaml
from app.models import Inventory, InventoryGroup, InventoryHost
from app.scrub import REDACTED, Scrubber, _PlaybookLoader, collect_secrets
from app.vault import VaultError, decrypt_vault_text, encrypt_to_vault_envelope, to_yaml_block

# st.text() never yields lone surrogates; JSON parsed by the stdlib can.
any_text = st.text(st.one_of(st.characters(), st.characters(categories=["Cs"])))

# The redaction marker itself can combine with neighbouring text into a new
# occurrence of a secret that contains "[" or "]" (or is part of the marker),
# so the no-leak properties exclude those secrets.
marker_safe = st.text(min_size=8).filter(
    lambda s: "[" not in s and "]" not in s and s.strip("\r\n") not in REDACTED
)

plain_text = st.text()


def json_values(text: st.SearchStrategy[str] = plain_text) -> st.SearchStrategy:
    leaves = st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | text
    return st.recursive(
        leaves,
        lambda c: st.lists(c, max_size=3) | st.dictionaries(text, c, max_size=3),
        max_leaves=12,
    )


def _core(secret: str) -> str:
    return secret.strip("\r\n")


def _strings(obj: object) -> list[str]:
    """Every string in a JSON-like value, dict keys included."""
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for k, v in obj.items() for s in [*_strings(k), *_strings(v)]]
    if isinstance(obj, list):
        return [s for v in obj for s in _strings(v)]
    return []


def _same_shape(a: object, b: object) -> bool:
    """Same nesting and entry counts: scrubbing must never drop a value.

    `*_lines` lists are exempt: a secret spanning two lines collapses them.
    """
    if isinstance(a, dict):
        return (
            isinstance(b, dict)
            and len(a) == len(b)
            and all(
                str(k).endswith("_lines") or _same_shape(x, y)
                for (k, x), y in zip(a.items(), b.values(), strict=True)
            )
        )
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_same_shape(x, y) for x, y in zip(a, b, strict=True))
    return True


# --- scrubber -----------------------------------------------------------------


@given(st.lists(any_text, max_size=4), any_text)
@example(["\ud800abcdefgh"], "x\ud800abcdefghy")
def test_scrub_text_never_raises(secrets: list[str], text: str) -> None:
    Scrubber(secrets).scrub_text(text)


@given(st.lists(marker_safe, min_size=1, max_size=4), st.lists(st.text(), max_size=5), st.data())
def test_long_secrets_never_survive_scrubbing(
    secrets: list[str], filler: list[str], data: st.DataObject
) -> None:
    parts = list(filler)
    for secret in secrets:
        parts.insert(data.draw(st.integers(0, len(parts))), secret)

    out = Scrubber(secrets).scrub_text("".join(parts))

    for secret in secrets:
        if len(_core(secret)) >= 8:
            assert _core(secret) not in out


@given(
    st.text(st.characters(categories=["L", "N"]), min_size=4, max_size=7),
    st.lists(st.text(), max_size=4),
)
def test_short_secrets_never_survive_as_whole_words(secret: str, others: list[str]) -> None:
    text = " ".join([*others[:2], secret, *others[2:]])

    out = Scrubber([secret]).scrub_text(text)

    assert not re.search(rf"(?<!\w){re.escape(secret)}(?!\w)", out)


@given(st.lists(st.text(), max_size=3), st.text())
def test_scrub_text_is_idempotent(secrets: list[str], text: str) -> None:
    scrubber = Scrubber(secrets)
    once = scrubber.scrub_text(text)
    assert scrubber.scrub_text(once) == once


@st.composite
def events_with_secret(draw: st.DrawFn) -> tuple[str, dict]:
    secret = draw(marker_safe.filter(lambda s: len(_core(s)) >= 8))
    maybe_secret = st.builds(
        lambda pre, post, embed: pre + secret + post if embed else pre + post,
        st.text(max_size=5),
        st.text(max_size=5),
        st.booleans(),
    )
    event = draw(st.dictionaries(maybe_secret, json_values(maybe_secret), max_size=4))
    lines = draw(st.lists(maybe_secret, max_size=4))
    event["event_data"] = {"res": {"stdout_lines": lines, "stdout": "\n".join(lines)}}
    return secret, event


@given(events_with_secret())
@example(
    (
        "tokentokentoken",
        {"res": {"tokentokentoken": 1, "[REDACTED]": 2, "xtokentokentoken": 3, "[REDACTED]#2": 4}},
    )
)
def test_scrub_event_leaks_no_secret_in_keys_or_values_and_drops_nothing(
    case: tuple[str, dict],
) -> None:
    secret, event = case

    out = Scrubber([secret]).scrub_event(event)

    assert out.get("event") != "redaction_error"
    assert not any(_core(secret) in s for s in _strings(out))
    assert _same_shape(event, out)


@given(json_values(any_text))
def test_scrub_event_never_hits_the_fail_closed_path(event: object) -> None:
    out = Scrubber(["hunter2hunter2", "abcd"]).scrub_event({"event_data": event})
    assert out.get("event") != "redaction_error"


@pytest.mark.parametrize(
    "text",
    [
        "-----BEGIN RSA PRIVATE KEY-----" * 20_000,
        "://a:" * 100_000,
        "://a:" + "b" * 500_000,
        "ghp_" + "a" * 500_000 + "_",
        "password=" * 50_000,
        "authorization: bearer " * 30_000,
        "abcd" * 200_000,
        "hunter2hunterabc " * 50_000,
    ],
)
def test_scrub_text_stays_fast_on_pathological_input(text: str) -> None:
    scrubber = Scrubber(["hunter2hunter2", "abcd"])
    start = time.perf_counter()
    scrubber.scrub_text(text)
    assert time.perf_counter() - start < 2  # linear today: ~0.03 s each


@given(any_text)
@settings(deadline=None)
def test_collect_secrets_never_raises_on_any_playbook_text(playbook_text: str) -> None:
    collect_secrets(
        ssh_key_pem="k",
        vault_password="pw",
        playbook_text=playbook_text,
        extra_vars=None,
        host_vars=[],
    )


def test_collect_secrets_survives_deeply_nested_playbook() -> None:
    secrets = collect_secrets(
        ssh_key_pem="k",
        vault_password="pw",
        playbook_text="[" * 5000 + "]" * 5000,
        extra_vars=None,
        host_vars=[],
    )
    assert secrets == {"k", "pw"}


def test_collect_secrets_stays_fast_on_yaml_alias_bomb() -> None:
    # Each level references the previous one 10 times: 10**9 leaves if the
    # walk followed every alias instead of visiting each container once.
    playbook = "a: &a [x, x, x, x, x, x, x, x, x, x]\n"
    for i in range(8):
        prev, cur = chr(97 + i), chr(98 + i)
        playbook += f"{cur}: &{cur} [" + ", ".join([f"*{prev}"] * 10) + "]\n"

    start = time.perf_counter()
    collect_secrets(
        ssh_key_pem="k", vault_password="pw", playbook_text=playbook, extra_vars=None, host_vars=[]
    )
    assert time.perf_counter() - start < 2


# --- vault ----------------------------------------------------------------------

vault_envelopes = st.builds(
    lambda version, extra, body: f"$ANSIBLE_VAULT;{version};AES256{extra}\n{body}",
    st.sampled_from(["1.1", "1.2", "1.0", "2.0", "x"]),
    st.sampled_from(["", ";label", ";a;b"]),
    st.lists(st.text("0123456789abcdef", max_size=80) | st.text(max_size=20), max_size=6).map(
        "\n".join
    ),
)


@given(st.one_of(any_text, vault_envelopes), any_text)
@example("x", "\ud800")
@example("\ud800", "pw")
@settings(deadline=None)
def test_decrypt_raises_only_vault_error(text: str, password: str) -> None:
    try:
        decrypt_vault_text(text, password)
    except VaultError:
        pass


@given(any_text, any_text)
@example("x", "\ud800")
@example("\ud800", "pw")
@settings(max_examples=30, deadline=None)
def test_encrypt_raises_only_vault_error(plaintext: str, password: str) -> None:
    try:
        encrypt_to_vault_envelope(plaintext, password)
    except VaultError:
        pass


@given(
    st.text(),
    st.text(min_size=1),
    st.none() | st.from_regex(r"[a-z_][a-z0-9_]{0,15}", fullmatch=True),
)
@settings(max_examples=30, deadline=None)
def test_vault_round_trips_and_rejects_tampering(
    plaintext: str, password: str, var_name: str | None
) -> None:
    envelope = encrypt_to_vault_envelope(plaintext, password)
    block = to_yaml_block(envelope, var_name)

    assert decrypt_vault_text(envelope, password) == plaintext
    assert decrypt_vault_text(block, password) == plaintext
    if var_name is not None:
        # The block is also what collect_secrets finds in a playbook.
        loaded = yaml.load(block, Loader=_PlaybookLoader)  # noqa: S506
        assert decrypt_vault_text(loaded[var_name], password) == plaintext

    body = envelope.rstrip()
    tampered = body[:-1] + ("1" if body[-1] == "0" else "0")
    for bad_text, bad_password in [(tampered, password), (envelope, password + "x")]:
        with pytest.raises(VaultError):
            decrypt_vault_text(bad_text, bad_password)


# --- inventory renderer -----------------------------------------------------------


@given(
    st.dictionaries(st.text(), st.dictionaries(st.text(), json_values(), max_size=3), max_size=4),
    st.none() | st.text(),
)
def test_rendered_inventory_parses_back_to_exactly_the_input(
    hosts: dict[str, dict], group_name: str | None
) -> None:
    inventory = Inventory(id=1, name="inv")
    host_rows = [
        InventoryHost(id=i, inventory_id=1, hostname=h, vars=v)
        for i, (h, v) in enumerate(hosts.items())
    ]
    group = None
    if group_name is None:
        inventory.hosts = host_rows
    else:
        group = InventoryGroup(id=1, inventory_id=1, name=group_name)
        group.hosts = host_rows

    rendered = render_inventory_yaml(inventory, group)

    block = {h: (v or None) for h, v in hosts.items()}
    expected = (
        {"all": {"hosts": block}}
        if group is None
        else {"all": {"children": {group_name: {"hosts": block}}}}
    )
    # No hostname, group name or var can inject keys or structure: both the
    # plain YAML parser and Ansible's own loader read back exactly the input.
    assert yaml.safe_load(rendered) == expected
    assert AnsibleLoader(rendered).get_single_data() == expected
