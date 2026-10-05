"""Property-based tests (Hypothesis) for the code that handles untrusted text:
the output scrubber, the vault helpers and the inventory renderer.

Each property is a plain Hypothesis test so a coverage-guided fuzzer can
reuse it later via `test_x.hypothesis.fuzz_one_input`.
"""

import contextlib
import json
import re
import time

import pytest
import yaml
from ansible.parsing.yaml.loader import AnsibleLoader
from hypothesis import example, given, settings
from hypothesis import strategies as st

from app.inventory_render import hostname_problem, merge, render, target_hosts
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
        pytest.param("-----BEGIN RSA PRIVATE KEY-----" * 20_000, id="unterminated-keys"),
        pytest.param("://a:" * 100_000, id="url-userinfo-repeat"),
        pytest.param("://a:" + "b" * 500_000, id="url-userinfo-long"),
        pytest.param("ghp_" + "a" * 500_000 + "_", id="github-token-long"),
        pytest.param("password=" * 50_000, id="assignment-repeat"),
        pytest.param("authorization: bearer " * 30_000, id="bearer-repeat"),
        pytest.param("abcd" * 200_000, id="short-secret-run"),
        pytest.param("hunter2hunterabc " * 50_000, id="near-miss-secret"),
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
    with contextlib.suppress(VaultError):
        decrypt_vault_text(text, password)


@given(any_text, any_text)
@example("x", "\ud800")
@example("\ud800", "pw")
@settings(max_examples=30, deadline=None)
def test_encrypt_raises_only_vault_error(plaintext: str, password: str) -> None:
    with contextlib.suppress(VaultError):
        encrypt_to_vault_envelope(plaintext, password)


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


class _UnsafeAwareLoader(yaml.SafeLoader):
    pass


_UnsafeAwareLoader.add_constructor("!unsafe", lambda loader, node: loader.construct_scalar(node))


def _plain(value):
    """The merged inventory as plain data (Unsafe strings as str)."""
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return str(value) if isinstance(value, str) else value


def _expected_tree(graph: dict, target: str | None) -> dict:
    keep = target_hosts(graph, target) if target is not None else None
    block: dict = {}
    if graph["vars"]:
        block["vars"] = _plain(graph["vars"])
    hosts = {h: (_plain(v) or None) for h, v in graph["hosts"].items() if keep is None or h in keep}
    if hosts:
        block["hosts"] = hosts
    children = {}
    for name, group in graph["groups"].items():
        entry: dict = {}
        members = {h: None for h in group["hosts"] if keep is None or h in keep}
        if members:
            entry["hosts"] = members
        if group["children"]:
            entry["children"] = dict.fromkeys(group["children"])
        if group["vars"]:
            entry["vars"] = _plain(group["vars"])
        children[name] = entry or None
    if children:
        block["children"] = children
    return {"all": block or None}


_ANY_NAME = st.text()
_ANY_VALUE = json_values()


@st.composite
def inventories(draw, names=_ANY_NAME, values=_ANY_VALUE):
    """(static data, a source snapshot or None, a target group or None)."""
    host_names = draw(st.lists(names, max_size=4, unique=True))
    static_hosts = {h: draw(st.dictionaries(names, values, max_size=2)) for h in host_names}
    group_names = draw(st.lists(names, max_size=3, unique=True))
    static_groups = {
        g: draw(st.lists(st.sampled_from(host_names), unique=True)) if host_names else []
        for g in group_names
    }
    static = {"hosts": static_hosts, "groups": static_groups}
    snapshot = None
    if draw(st.booleans()):
        source_hosts = {
            h: draw(st.dictionaries(names, values, max_size=2))
            for h in draw(st.lists(names, max_size=4, unique=True))
        }
        source_group_names = draw(st.lists(names, max_size=3, unique=True))
        all_hosts = list(source_hosts)
        snapshot = {
            "vars": draw(st.dictionaries(names, values, max_size=2)),
            "static_hosts": draw(st.lists(st.sampled_from(host_names), unique=True))
            if host_names
            else [],
            "hosts": source_hosts,
            "groups": {
                g: {
                    "hosts": draw(st.lists(st.sampled_from(all_hosts), unique=True))
                    if all_hosts
                    else [],
                    # earlier groups only: no cycles
                    "children": draw(st.lists(st.sampled_from(source_group_names[:i]), unique=True))
                    if i
                    else [],
                    "vars": draw(st.dictionaries(names, values, max_size=2)),
                }
                for i, g in enumerate(source_group_names)
            },
        }
    graph = merge(static, snapshot)
    target = draw(st.none() | st.sampled_from(sorted(graph["groups"]))) if graph["groups"] else None
    return static, snapshot, target


@given(inventories())
def test_rendered_inventory_parses_back_to_exactly_the_merged_inventory(case) -> None:
    """Whatever the names and values (even ones the API refuses), the YAML holds exactly the
    merged inventory: nothing can inject keys or structure, for PyYAML or Ansible's loader."""
    static, snapshot, target = case
    graph = merge(static, snapshot)
    rendered = render(graph, target)
    expected = _expected_tree(graph, target)
    assert yaml.load(rendered, Loader=_UnsafeAwareLoader) == expected  # noqa: S506
    assert _plain(AnsibleLoader(rendered).get_single_data()) == expected


_HOST = st.from_regex(r"[a-z][a-z0-9]{0,6}", fullmatch=True).filter(lambda n: n != "all")
_SCALARS = st.none() | st.booleans() | st.integers() | st.text(max_size=12)


@settings(max_examples=40, deadline=None)
@given(case=inventories(names=_HOST.filter(lambda n: n != "ungrouped"), values=_SCALARS))
def test_ansible_sees_the_merged_inventory_and_never_templates_source_strings(
    case, tmp_path_factory
) -> None:
    from ansible._internal._datatag._tags import TrustedAsTemplate
    from ansible.inventory.manager import InventoryManager
    from ansible.parsing.dataloader import DataLoader

    static, snapshot, target = case
    graph = merge(static, snapshot)
    path = tmp_path_factory.mktemp("inv") / "hosts.yml"
    path.write_text(render(graph, target))
    inventory = InventoryManager(loader=DataLoader(), sources=[str(path)])
    keep = target_hosts(graph, target) if target is not None else set(graph["hosts"])

    assert {h.name for h in inventory.get_hosts()} == keep
    for name, group in graph["groups"].items():
        assert {h.name for h in inventory.groups[name].hosts} == set(group["hosts"]) & keep
    for name in keep:
        seen = inventory.get_host(name).vars
        for key, value in graph["hosts"][name].items():
            assert seen[key] == value
            if not isinstance(value, str):
                continue
            trusted = TrustedAsTemplate.is_tagged_on(seen[key])
            if key in static["hosts"].get(name, {}):
                assert trusted  # a static string stays a template
            elif "{" in value or value.startswith("#jinja2:"):
                assert not trusted  # a source string that could be one never is


@given(st.text(max_size=40) | st.from_regex(r"[a-z0-9.:\[\]%_-]{1,20}", fullmatch=True))
def test_an_accepted_hostname_is_exactly_one_host_to_ansible(name: str) -> None:
    from ansible.plugins.inventory import BaseInventoryPlugin

    if hostname_problem(name) is None:
        assert BaseInventoryPlugin()._expand_hostpattern(name) == ([name], None)


_PATH_PIECES = st.sampled_from(
    ["a", "web", "..", ".", "", "%2e", "-x", "_k", "ö", "a.b", "\x00", " "]
)


@given(
    st.one_of(
        st.text(max_size=120),
        st.lists(_PATH_PIECES, max_size=20).map("/".join),
    )
)
@example("../8/x")
@example("a/../../8")
@example("a//b")
def test_store_references_never_leave_their_project(path: str) -> None:
    """Any reference path is either refused, or read from under the project's own subtree
    with no dot or empty segments (which the store or httpx would collapse)."""
    from app import secret_store
    from app.secret_store import SecretStoreError

    try:
        segments = secret_store.check_path(path)
    except SecretStoreError:
        return
    built = secret_store._api_path("secret", "data", "ansideck", "7", *segments)
    assert built.startswith("/v1/secret/data/ansideck/7/")
    assert all(part not in ("", ".", "..") for part in built.split("/")[1:])
    assert "%" not in built  # nothing needed encoding: no way to smuggle a separator


# --- JSON nesting (untrusted inventory output) --------------------------------------


def _depth(value) -> int:
    if isinstance(value, dict):
        return 1 + max((_depth(v) for v in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_depth(v) for v in value), default=0)
    return 0


@given(json_values(any_text.filter(lambda t: not any(0xD800 <= ord(c) <= 0xDFFF for c in t))))
def test_the_nesting_scan_agrees_with_the_parsed_depth(value) -> None:
    """A linear scan, before json.loads ever recurses: brackets inside strings and escaped
    quotes never fool it."""
    from app.json_limits import nesting_depth

    for indent in (None, 2):
        assert nesting_depth(json.dumps(value, indent=indent).encode()) == _depth(value)
