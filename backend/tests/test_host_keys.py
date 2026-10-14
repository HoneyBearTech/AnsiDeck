"""app.host_keys (names, keys, known_hosts parsing, addresses, refused-key messages) and the
run process's side of it (app.run_worker: the files and ssh options a run gets)."""

import base64
import os
import shlex
import shutil
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import run_worker
from app.host_keys import (
    address_of,
    alias,
    check_key,
    fingerprint,
    host_addresses,
    host_key_problem,
    normalise_name,
    parse_known_hosts,
)


def _blob(key_type: str = "ssh-ed25519", body: bytes = b"\x01" * 32) -> str:
    raw = len(key_type).to_bytes(4, "big") + key_type.encode()
    return base64.b64encode(raw + len(body).to_bytes(4, "big") + body).decode()


ED = _blob()
OTHER = _blob(body=b"\x02" * 32)


def test_names_are_what_ssh_looks_hosts_up_by() -> None:
    assert alias("Web1.Example.COM") == "web1.example.com"
    assert alias("10.0.0.5", 22) == "10.0.0.5"
    assert alias("10.0.0.5", 2222) == "[10.0.0.5]:2222"
    assert alias("::1", 2222) == "[::1]:2222"
    assert normalise_name(" WEB1 ") == "web1"
    assert normalise_name("[web1]:22") == "web1"  # ssh looks port 22 up without brackets
    assert normalise_name("[web1]:2222") == "[web1]:2222"
    for refused in ("*.example.com", "web?", "!web1", "|1|abc=|def=", "a,b", "web 1", "",
                    "[web1]:0", "[web1]:70000", "@cert-authority", "x" * 301):  # fmt: skip
        assert normalise_name(refused) is None, refused


def test_keys_must_be_plain_host_keys_of_the_type_they_claim(tmp_path) -> None:
    assert check_key("ssh-ed25519", ED) == fingerprint(ED)
    with pytest.raises(ValueError, match="isn't a ssh-rsa key"):
        check_key("ssh-rsa", ED)
    with pytest.raises(ValueError, match="unsupported"):
        check_key("ssh-ed25519-cert-v01@openssh.com", _blob("ssh-ed25519-cert-v01@openssh.com"))
    with pytest.raises(ValueError, match="base64"):
        check_key("ssh-ed25519", "not base64!")
    with pytest.raises(ValueError, match="too short"):
        check_key("ssh-ed25519", "AAA=")


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="needs ssh-keygen")
def test_fingerprints_are_the_ones_ssh_keygen_shows(tmp_path) -> None:
    key = tmp_path / "key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    key_type, blob = key.with_suffix(".pub").read_text().split()[:2]
    shown = subprocess.run(
        ["ssh-keygen", "-lf", str(key.with_suffix(".pub"))],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()[1]
    assert check_key(key_type, blob) == shown


def test_known_hosts_text_gives_one_key_per_plain_name() -> None:
    text = "\n".join(
        [
            "# a comment",
            f"web1,10.0.0.5,[jump]:2222,*.example.com,|1|salt=|hash= ssh-ed25519 {ED} comment",
            f"@cert-authority *.example.com ssh-ed25519 {ED}",
            "garbage",
            f"web2 ssh-rsa {ED}",
            f"web1 ssh-ed25519 {OTHER}",  # a later line for the same name and type wins
        ]
    )
    keys, warnings = parse_known_hosts(text)
    assert {(k.name, k.key_b64) for k in keys} == {
        ("web1", OTHER),
        ("10.0.0.5", ED),
        ("[jump]:2222", ED),
    }
    assert [k.line for k in keys if k.name == "10.0.0.5"] == [f"10.0.0.5 ssh-ed25519 {ED}"]
    assert len(warnings) == 5
    assert any("hashed names" in w for w in warnings)
    assert any("@cert-authority" in w for w in warnings)
    _, warnings = parse_known_hosts(f"h ssh-ed25519 {ED}\n" * 5, max_lines=3)
    assert warnings == ["only the first 3 lines were read"]


def test_a_host_connects_where_ansible_would() -> None:
    assert address_of("web1", {}).name == "web1"
    assert address_of("web1", {"ansible_host": "10.0.0.5", "ansible_port": 22}).name == "10.0.0.5"
    both = {
        "ansible_host": "a",
        "ansible_ssh_host": "B",
        "ansible_port": "2200",
        "ansible_ssh_port": 2222,
    }
    assert address_of("web1", both).name == "[b]:2222"  # the ssh_ spellings win
    templated = address_of("web1", {"ansible_host": "{{ lookup('pipe', 'id') }}"})
    assert (templated.name, templated.checked) == (None, True)
    assert "template" in templated.reason
    assert address_of("web1", {"ansible_port": "ssh"}).name is None
    assert address_of("web1", {"ansible_port": 0}).name is None
    local = address_of("localhost", {"ansible_connection": "local"})
    assert (local.name, local.connection, local.checked) == (None, "local", False)
    assert address_of("sw1", {"ansible_connection": "network_cli"}).checked is False
    assert address_of("web1", {"ansible_connection": "smart"}).name == "web1"


def test_inventory_vars_combine_by_ansibles_rules() -> None:
    graph = {
        "vars": {"ansible_port": 2200},
        "hosts": {
            "a": {},
            "b": {"ansible_port": 2299},
            "c": {},
            "lonely": {},
        },
        "groups": {
            "web": {"hosts": ["a", "b", "c"], "children": ["prod"], "vars": {"ansible_port": 22}},
            "prod": {"hosts": ["c"], "children": [], "vars": {"ansible_port": 2201}},
            # a cycle ansible refuses too; it must not break the rest
            "loop": {"hosts": [], "children": ["loop2"], "vars": {}},
            "loop2": {"hosts": [], "children": ["loop"], "vars": {}},
        },
    }
    names = {host: address.name for host, address in host_addresses(graph).items()}
    assert names == {"a": "a", "b": "[b]:2299", "c": "[c]:2201", "lonely": "[lonely]:2200"}


CHANGED = (
    "Failed to connect to the host via ssh: "
    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n"
    "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n"
    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n"
    "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\r\n"
    "The fingerprint for the ED25519 key sent by the remote host is\n"
    "SHA256:lb3T+CbqsTi3pCqDEQBmfHd/c/jIK875yJAZ+F10Eyo.\r\n"
    "Please contact your system administrator.\r\n"
    "Host key for [10.0.0.5]:2222 has changed and you have requested strict checking.\r\n"
    "Host key verification failed."
)
UNKNOWN = (
    "Failed to connect to the host via ssh: No ED25519 host key is known for [10.0.0.5]:2222 "
    "and you have requested strict checking.\r\nHost key verification failed."
)


def _unreachable(msg: str, host: str = "web1") -> dict:
    return {"event": "runner_on_unreachable", "event_data": {"host": host, "res": {"msg": msg}}}


def test_refused_host_keys_are_recognised_in_unreachable_events() -> None:
    assert host_key_problem(_unreachable(CHANGED)) == {
        "host": "web1",
        "problem": "changed",
        "name": "[10.0.0.5]:2222",
        "key_type": "ED25519",
        "presented": "SHA256:lb3T+CbqsTi3pCqDEQBmfHd/c/jIK875yJAZ+F10Eyo",
    }
    assert host_key_problem(_unreachable(UNKNOWN)) == {
        "host": "web1",
        "problem": "unknown",
        "name": "[10.0.0.5]:2222",
        "key_type": "ED25519",
        "presented": None,
    }
    assert host_key_problem(_unreachable("Host key verification failed."))["problem"] == "failed"
    # Untrusted text is cut to safe characters.
    odd = host_key_problem(_unreachable(UNKNOWN, host="<b>web1</b>\n"))
    assert odd["host"] == "bweb1b"
    assert host_key_problem(_unreachable("Connection refused")) is None
    assert host_key_problem(_unreachable("<error censored due to no log>")) is None
    assert host_key_problem({"event": "runner_on_failed", "event_data": {"res": {}}}) is None
    assert host_key_problem({"event": "runner_on_unreachable"}) is None


# ------------------------------------------------------------------ the run process


PREFIX = f"ansideck-run-hk{os.getpid()}-"


@pytest.fixture
def _clean_tmp():
    yield
    for path in Path("/tmp").glob(f"{PREFIX}*"):
        shutil.rmtree(path, ignore_errors=True)


def _prepared(monkeypatch, host_keys, **extra) -> tuple[dict, Path]:
    for name in ("ANSIBLE_HOME", "ANSIBLE_SSH_CONTROL_PATH_DIR", "ANSIBLE_CALLBACK_RESULT_FORMAT",
                 "HOME", "TMPDIR"):  # fmt: skip
        monkeypatch.setenv(name, os.environ.get(name, "before"))
    job = {
        "files": {"playbook": "- hosts: all\n", "inventory": "all: {}\n"},
        "prefix": PREFIX,
        "extravars": {"keep": 1, "ansible_ssh_args": "-o StrictHostKeyChecking=no"},
        "host_keys": host_keys,
        **extra,
    }
    pdd = Path(run_worker.prepare(job))
    return job, pdd


@pytest.mark.usefixtures("_clean_tmp")
def test_a_run_without_checking_gets_nothing_extra(monkeypatch) -> None:
    job, pdd = _prepared(monkeypatch, None)
    assert job["extravars"] == {
        "keep": 1,
        "ansible_ssh_args": "-o StrictHostKeyChecking=no",
        "ansideck_artifacts_dir": str(pdd / "ansideck-artifacts"),
    }
    assert not (pdd / "known_hosts").exists()
    assert "host_keys" not in job


@pytest.mark.usefixtures("_clean_tmp")
@pytest.mark.parametrize("mode", ["accept_new", "strict"])
def test_a_checking_run_gets_its_files_and_our_ssh_options_first(monkeypatch, mode) -> None:
    job, pdd = _prepared(monkeypatch, {"mode": mode, "known_hosts": f"web1 ssh-ed25519 {ED}\n"})
    known = pdd / "known_hosts"
    assert known.read_text() == f"web1 ssh-ed25519 {ED}\n"
    assert stat.S_IMODE(known.stat().st_mode) == 0o600
    learned = pdd / "learned_known_hosts"
    assert learned.exists() == (mode == "accept_new")
    args = job["extravars"]["ansible_ssh_args"]
    assert job["extravars"]["ansible_ssh_executable"] == "ssh"
    assert job["extravars"]["keep"] == 1
    assert args.endswith("-C -o ControlMaster=auto -o ControlPersist=60s")  # ansible's default
    if shutil.which("ssh"):
        # What ssh makes of it with everything a host var could add after it.
        hostile = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                   "-o", "GlobalKnownHostsFile=/tmp/x", "-o", "CheckHostIP=yes"]  # fmt: skip
        out = subprocess.run(
            ["ssh", "-G", *shlex.split(args), *hostile, "web1"],
            check=True,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
        ).stdout.splitlines()
        config = dict(line.split(" ", 1) for line in out if " " in line)
        assert config["stricthostkeychecking"] == ("accept-new" if mode == "accept_new" else "true")
        files = [str(learned), str(known)] if mode == "accept_new" else [str(known)]
        assert config["userknownhostsfile"] == " ".join(files)
        assert config["globalknownhostsfile"] == "/dev/null"
        assert config["checkhostip"] == "no"


def test_a_repositorys_ssh_args_follow_ours(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "ansible.cfg").write_text("[ssh_connection]\nssh_args = -o ForwardAgent=yes\n")
    args = run_worker.host_key_ssh_args(tmp_path, "strict", run_worker._repo_ssh_args(project))
    assert args.startswith("-o StrictHostKeyChecking=yes ")
    assert args.endswith(" -o ForwardAgent=yes")
    (project / "ansible.cfg").write_text("[defaults]\nforks = 5\n")
    assert run_worker._repo_ssh_args(project) is None


@pytest.mark.usefixtures("_clean_tmp")
def test_jump_hosts_get_the_same_checks_through_the_slots_ssh_config(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setattr(run_worker.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=str(home)))
    _, pdd = _prepared(monkeypatch, {"mode": "accept_new", "known_hosts": ""}, own_home=True)
    config = home / ".ssh" / "config"
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert stat.S_IMODE((home / ".ssh").stat().st_mode) == 0o700
    text = config.read_text()
    assert text.startswith("Host *\n")
    assert "    StrictHostKeyChecking accept-new\n" in text
    assert f"    UserKnownHostsFile {pdd}/learned_known_hosts {pdd}/known_hosts\n" in text


def test_learned_lines_are_read_bounded(tmp_path) -> None:
    assert run_worker.read_learned(tmp_path) == []
    (tmp_path / "learned_known_hosts").write_text(
        "\n".join(f"h{n} ssh-ed25519 {ED}" for n in range(300)) + "\n\n"
    )
    lines = run_worker.read_learned(tmp_path)
    assert len(lines) == 200 and lines[0] == f"h0 ssh-ed25519 {ED}"
    (tmp_path / "learned_known_hosts").write_bytes(b"x" * (200 * 1024))
    assert len(run_worker.read_learned(tmp_path)[0]) == 64 * 1024


@pytest.mark.usefixtures("_clean_tmp")
def test_an_unknown_mode_is_refused_and_leaves_nothing_behind(monkeypatch) -> None:
    with pytest.raises(RuntimeError, match="unknown host key mode"):
        _prepared(monkeypatch, {"mode": "loose", "known_hosts": ""})
    assert list(Path("/tmp").glob(f"{PREFIX}*")) == []
