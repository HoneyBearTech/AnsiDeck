"""Per-slot run users for real: playbooks run through run_executor as ansideck-run<n>, from a
process with the worker's privileges (root with only SETUID, SETGID and KILL). Skipped
elsewhere; CI runs it in the backend image with the worker's compose settings:

    docker run --rm --user 0 --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN \\
      --cap-add KILL \\
      --security-opt no-new-privileges:true --read-only --tmpfs /tmp \\
      -e PYTHONDONTWRITEBYTECODE=1 -e ANSIDECK_REQUIRE_ISOLATION=1 \\
      -e PATH=/app/.venv/bin:/usr/local/bin:/usr/bin:/bin <backend dev image> \\
      python -m pytest --noconftest -p no:cacheprovider tests/test_isolation_root.py

Self-contained (no database, no conftest): it calls run_in_worker() the way the worker does.
"""

import os
import sys
import threading
import time
from pathlib import Path

import pytest

from app.run_executor import ExecutionHandle, processes_of, run_in_worker
from app.run_isolation import HOME_ROOT, check_available, identity_for_slot, prepare_homes
from app.subprocess_env import clean_env

_reason = check_available(2)
if _reason is not None:
    if os.environ.get("ANSIDECK_REQUIRE_ISOLATION") == "1":
        raise RuntimeError(f"isolation is required here but unavailable: {_reason}")
    pytestmark = pytest.mark.skip(reason=f"runs can't be isolated here: {_reason}")


@pytest.fixture(scope="module", autouse=True)
def _homes() -> None:
    prepare_homes(4)  # what the worker does at startup


INVENTORY = f"""\
all:
  hosts:
    localhost:
      ansible_connection: local
      ansible_python_interpreter: {sys.executable}
"""


def _play(*tasks: str) -> str:
    body = "".join(f"    - {task}\n" for task in tasks)
    return f"- hosts: all\n  gather_facts: false\n  tasks:\n{body}"


def _shell(command: str) -> str:
    return "ansible.builtin.shell: |\n        " + command  # a literal block: no escaping


def _run(
    playbook: str, slot: int, handle=None, run_id: int = 1, repository: bytes | None = None, **env
):
    events: list[dict] = []
    status, _rc = run_in_worker(
        {
            "files": {"playbook": playbook, "inventory": INVENTORY},
            "project": {"playbook": "site.yml"} if repository else None,
            "prefix": f"ansideck-run-{run_id}-",
            "own_home": True,
            "ssh_key": None,
            "cmdline": None,
            "limit": None,
            "extravars": {},
            "passwords": None,
        },
        clean_env(env),
        events.append,
        handle,
        identity_for_slot(slot),
        stdin_tail=repository,
    )
    stdout = [
        e["event_data"]["res"].get("stdout", "")
        for e in events
        if e.get("event") in ("runner_on_ok", "runner_on_failed")
    ]
    return status, stdout


def test_a_run_executes_as_its_slot_user_with_nothing_to_gain() -> None:
    status, [ids, caps, env] = _run(
        _play(
            _shell("id -u; id -g; id -G"),
            _shell("grep -E '^(CapEff|CapPrm|CapAmb|NoNewPrivs):' /proc/self/status"),
            _shell(
                "echo $HOME; echo $TMPDIR; echo $ANSIBLE_HOME; echo $ANSIBLE_SSH_CONTROL_PATH_DIR"
            ),
        ),
        slot=1,
    )
    assert status == "successful"
    assert ids.split() == ["20001", "20001", "20001"]  # no supplementary groups
    fields = dict(line.split(":\t") for line in caps.splitlines())
    assert fields == {
        "CapPrm": "0000000000000000",
        "CapEff": "0000000000000000",
        "CapAmb": "0000000000000000",
        "NoNewPrivs": "1",
    }
    home, tmpdir, ansible_home, control_dir = env.split()
    assert home == f"{HOME_ROOT}/run1"  # its passwd home: ansible's local tasks use that
    pdd = str(Path(tmpdir).parent)
    assert pdd.startswith("/tmp/ansideck-run-1-")
    assert (ansible_home, control_dir) == (f"{pdd}/ansible", f"{pdd}/ansible/cp")
    assert not Path(pdd).exists()  # gone with the run
    assert processes_of(20001) == []


def test_a_run_cannot_read_or_signal_the_worker() -> None:
    me = os.getpid()
    status, [environ, signal] = _run(
        _play(
            _shell(f"cat /proc/{me}/environ > /dev/null 2>&1; echo $?"),
            _shell(f"kill -0 {me} 2>/dev/null; echo $?"),
        ),
        slot=0,
    )
    assert status == "successful"
    assert environ != "0"
    assert signal != "0"


def test_concurrent_runs_cannot_see_each_other() -> None:
    """A run on slot 0 holds a secret in its files and environment; a run on slot 1 looks for
    it everywhere it might be."""
    holder = _play(
        _shell("echo held-secret-file > $HOME/secret"),
        "ansible.builtin.pause: {seconds: 6}",
    )
    results = {}
    thread = threading.Thread(
        target=lambda: results.update(a=_run(holder, slot=0, run_id=101, MARKER="held-secret-env"))
    )
    thread.start()
    time.sleep(3)  # run A is pausing, its files and processes in place
    status, [listing, files, environs] = _run(
        _play(
            _shell(f"ls /tmp/ansideck-run-101-*/ {HOME_ROOT}/run0/ 2>&1; true"),
            _shell(f"cat {HOME_ROOT}/run0/secret /tmp/ansideck-run-101-*/env/* 2>&1; true"),
            _shell(
                "for p in /proc/[0-9]*; do tr '\\0' '\\n' < $p/environ 2>/dev/null; done"
                " | grep -c held-secret; true"
            ),
        ),
        slot=1,
        run_id=102,
    )
    thread.join()
    assert results["a"][0] == "successful"
    assert status == "successful"
    assert listing.count("Permission denied") == 2
    assert "held-secret" not in files
    assert environs.strip() == "0"


def test_nothing_a_run_leaves_behind_survives_it() -> None:
    """A daemon that doesn't mention the run anywhere (so the unisolated cleanup, which looks
    for the private data dir in command lines, can't find it) and files outside the run's
    directory: the sweep ends and deletes them."""
    status, _ = _run(
        _play(
            _shell(
                f"setsid {sys.executable} -c 'import time; time.sleep(300)' "
                "> /dev/null 2>&1 < /dev/null & "
                "echo left > /tmp/left-behind; "
                "mkdir /dev/shm/left-dir; echo x > /dev/shm/left-dir/f"
            ),
        ),
        slot=2,
    )
    assert status == "successful"
    assert processes_of(20002) == []
    assert not Path("/tmp/left-behind").exists()
    assert not Path("/dev/shm/left-dir").exists()


def test_a_cancelled_isolated_run_stops_and_leaves_nothing() -> None:
    handle = ExecutionHandle()
    threading.Timer(3, handle.stop, args=("cancelled",)).start()
    started = time.monotonic()
    status, _ = _run(_play("ansible.builtin.pause: {seconds: 60}"), slot=3, handle=handle)
    assert status == "canceled"
    assert time.monotonic() - started < 20
    assert processes_of(20003) == []


def test_a_home_another_slot_planted_in_is_replaced() -> None:
    """A run may open up its own home; another slot's run then plants a directory in it that
    the home's user can't empty. The sweep after the first run notices, and the worker moves
    that home aside, so the slot's next run (maybe another project's) gets a clean one."""
    opener = _play(_shell("chmod 777 $HOME"), "ansible.builtin.pause: {seconds: 6}")
    planter = _play(
        _shell(
            f"mkdir -m 755 {HOME_ROOT}/run0/.config && echo x > {HOME_ROOT}/run0/.config/f; "
            f"echo y > {HOME_ROOT}/run0/planted-file"
        ),
        "ansible.builtin.pause: {seconds: 10}",
    )
    results = {}
    a = threading.Thread(target=lambda: results.update(a=_run(opener, slot=0, run_id=201)))
    b = threading.Thread(target=lambda: results.update(b=_run(planter, slot=1, run_id=202)))
    a.start()
    time.sleep(3)
    b.start()
    a.join()
    b.join()
    assert results["a"][0] == results["b"][0] == "successful"
    assert any(name.startswith(".stale-ansideck-run0-") for name in os.listdir(HOME_ROOT))

    status, [listing] = _run(_play(_shell("stat -c %a $HOME; ls -A $HOME")), slot=0)
    assert status == "successful"
    assert listing.split() == ["700", ".ansible"]  # this run's own ansible temp dir only


def _repository(files: dict[str, tuple[bytes, int]]) -> bytes:
    import io
    import tarfile

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, (data, mode) in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), mode
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_a_git_run_unpacks_its_repository_as_its_slot_user() -> None:
    """The run's own process unpacks the repository (owned by the slot's user, setuid
    stripped) and runs a playbook from it with the repository's role; nothing outlives it."""
    repository = _repository(
        {
            "site.yml": (_play("ansible.builtin.include_role: {name: probe}").encode(), 0o644),
            "roles/probe/tasks/main.yml": (
                ("- " + _shell("id -u; stat -c '%u %a' site.yml tool; pwd") + "\n").encode(),
                0o644,
            ),
            "tool": (b"#!/bin/sh\n", 0o4755),
        }
    )
    status, outputs = _run("", slot=3, run_id=3, repository=repository)
    assert status == "successful"
    uid, site, tool, cwd = outputs[-1].splitlines()  # (include_role reports first)
    assert uid == "20003"
    assert site == "20003 644"
    assert tool == "20003 755"  # setuid stripped
    assert cwd.startswith("/tmp/ansideck-run-3-") and cwd.endswith("/project")
    assert not Path(cwd).exists()
    assert processes_of(20003) == []
