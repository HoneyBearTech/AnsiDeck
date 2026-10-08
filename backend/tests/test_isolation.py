"""Per-slot run users (Phase 4C), the parts that run anywhere. The real thing, as root in the
worker image, is tests/test_isolation_root.py."""

import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import run_executor, run_isolation, run_worker
from app.run_isolation import RUN_UID_BASE, RunIdentity, check_available, identity_for_slot, wrap
from app.worker import __main__ as worker_main
from app.worker import runner
from app.worker.settings import WorkerSettings

ALL_FOUR = format(1 << 0 | 1 << 5 | 1 << 6 | 1 << 7, "016x")  # CHOWN, KILL, SETGID, SETUID


def _passwd(uid: int) -> SimpleNamespace:
    """The image's passwd entry of a run user."""
    return SimpleNamespace(pw_dir=f"/tmp/ansideck-home/run{uid - RUN_UID_BASE}")


# ------------------------------------------------------------------ run_isolation


def test_each_slot_has_a_user_of_its_own() -> None:
    assert identity_for_slot(0) == RunIdentity(
        20000, 20000, "ansideck-run0", "/tmp/ansideck-home/run0"
    )
    assert identity_for_slot(63, "/x").home == "/x/run63"
    for slot in (-1, 64):
        with pytest.raises(ValueError, match="out of range"):
            identity_for_slot(slot)


def test_effective_caps_are_read_from_proc_status() -> None:
    status = "Name:\tpython\nCapInh:\t0000000000000000\nCapEff:\t00000000000000e0\n"
    assert run_isolation.effective_caps(status) == 0xE0
    assert run_isolation.effective_caps("Name:\tpython\n") == 0


def test_wrap_drops_to_the_slot_user_with_nothing_to_gain(monkeypatch) -> None:
    monkeypatch.setattr(run_isolation.shutil, "which", lambda _name: "/usr/bin/setpriv")
    assert wrap(["python", "-m", "x"], identity_for_slot(2)) == [
        "/usr/bin/setpriv",
        "--reuid=20002",
        "--regid=20002",
        "--clear-groups",
        "--no-new-privs",
        "--inh-caps=-all",
        "--",
        "python",
        "-m",
        "x",
    ]


@pytest.fixture
def capable(monkeypatch, tmp_path):
    """Everything check_available() wants, faked; tests take one piece away."""
    status = tmp_path / "status"
    status.write_text(f"CapEff:\t{ALL_FOUR}\n")
    monkeypatch.setattr(run_isolation.sys, "platform", "linux")
    monkeypatch.setattr(run_isolation.os, "geteuid", lambda: 0)
    monkeypatch.setattr(run_isolation.shutil, "which", lambda _name: "/usr/bin/setpriv")
    import pwd

    monkeypatch.setattr(pwd, "getpwuid", _passwd)
    return status


def test_isolation_is_available_with_root_four_caps_setpriv_and_the_users(capable) -> None:
    assert check_available(4, str(capable)) is None


def test_isolation_needs_linux(capable, monkeypatch) -> None:
    monkeypatch.setattr(run_isolation.sys, "platform", "darwin")
    assert "only be isolated on Linux" in check_available(1, str(capable))


def test_isolation_needs_root(capable, monkeypatch) -> None:
    monkeypatch.setattr(run_isolation.os, "geteuid", lambda: 1000)
    assert "not running as root" in check_available(1, str(capable))


def test_isolation_names_the_missing_capabilities(capable) -> None:
    capable.write_text(f"CapEff:\t{1 << 5:016x}\n")  # KILL only
    assert check_available(1, str(capable)) == (
        "the worker lacks the CHOWN, SETGID, SETUID capabilities (compose: cap_add)"
    )


def test_isolation_needs_readable_capabilities(capable, tmp_path) -> None:
    assert "could not read" in check_available(1, str(tmp_path / "missing"))


def test_isolation_needs_setpriv(capable, monkeypatch) -> None:
    monkeypatch.setattr(run_isolation.shutil, "which", lambda _name: None)
    assert "setpriv" in check_available(1, str(capable))


def test_isolation_needs_a_user_per_slot(capable, monkeypatch) -> None:
    import pwd

    def getpwuid(uid: int):
        if uid >= RUN_UID_BASE + 2:
            raise KeyError(uid)
        return _passwd(uid)

    monkeypatch.setattr(pwd, "getpwuid", getpwuid)
    assert check_available(2, str(capable)) is None
    assert check_available(3, str(capable)) == "the image has no run user ansideck-run2 (uid 20002)"
    assert "only 64 run users" in check_available(65, str(capable))


def test_isolation_needs_the_homes_the_worker_creates(capable, monkeypatch) -> None:
    import pwd

    monkeypatch.setattr(pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir="/nonexistent"))
    assert check_available(1, str(capable)) == (
        "run user ansideck-run0 has home /nonexistent, not /tmp/ansideck-home/run0"
    )


def test_prepare_homes_makes_a_private_home_per_slot(monkeypatch, tmp_path) -> None:
    chowned = []
    monkeypatch.setattr(run_isolation.os, "chown", lambda *a: chowned.append(a))
    root = tmp_path / "homes"
    run_isolation.prepare_homes(2, str(root), root_uid=os.geteuid())
    assert root.stat().st_mode & 0o777 == 0o755
    for slot in (0, 1):
        assert (root / f"run{slot}").stat().st_mode & 0o777 == 0o700
    uid = RUN_UID_BASE
    assert chowned == [(str(root / "run0"), uid, uid), (str(root / "run1"), uid + 1, uid + 1)]


def test_prepare_homes_refuses_what_a_run_user_planted(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(run_isolation.os, "chown", lambda *a: None)
    root = tmp_path / "homes"
    root.mkdir()
    (root / "run0").symlink_to(tmp_path)
    with pytest.raises(RuntimeError, match="is not a directory of uid"):
        run_isolation.prepare_homes(1, str(root), root_uid=os.geteuid())


def test_replace_home_moves_a_poisoned_home_aside(monkeypatch, tmp_path) -> None:
    chowned = []
    monkeypatch.setattr(run_isolation.os, "chown", lambda *a: chowned.append(a))
    identity = identity_for_slot(0, str(tmp_path))
    Path(identity.home).mkdir()
    (Path(identity.home) / "planted").mkdir()
    run_isolation.replace_home(identity)
    assert list(Path(identity.home).iterdir()) == []
    [stale] = [p for p in tmp_path.iterdir() if p.name.startswith(".stale-ansideck-run0-")]
    assert (stale / "planted").is_dir()
    assert chowned == [(identity.home, identity.uid, identity.gid)]


# ------------------------------------------------------------------ run_worker


def test_the_sweep_threshold_matches_the_run_users() -> None:
    assert run_worker._RUN_UID_BASE == RUN_UID_BASE


def test_prepare_builds_the_private_data_dir_and_a_home_for_ansible(monkeypatch, tmp_path) -> None:
    for name in ("ANSIBLE_HOME", "ANSIBLE_SSH_CONTROL_PATH_DIR", "HOME", "TMPDIR"):
        monkeypatch.setenv(name, "before")
    home = tmp_path / "home"
    home.mkdir(mode=0o777)
    home.chmod(0o777)  # an earlier run opened it up
    monkeypatch.setattr(run_worker.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=str(home)))
    job = {
        "files": {"playbook": "- hosts: all\n", "inventory": "all: {}\n"},
        "prefix": "ansideck-run-7-",
        "own_home": True,
        "limit": None,
    }
    pdd = Path(run_worker.prepare(job))
    try:
        assert pdd.parent == Path("/tmp")  # short: SSH sockets live in here
        assert pdd.name.startswith("ansideck-run-7-")
        assert pdd.stat().st_mode & 0o777 == 0o700
        assert (pdd / "project" / "playbook.yml").read_text() == "- hosts: all\n"
        assert (pdd / "inventory" / "hosts.yml").read_text() == "all: {}\n"
        assert job == {
            "limit": None,
            "private_data_dir": str(pdd),
            "playbook": "playbook.yml",
            "inventory": str(pdd / "inventory" / "hosts.yml"),
        }
        assert os.environ["ANSIBLE_HOME"] == str(pdd / "ansible")
        assert os.environ["ANSIBLE_SSH_CONTROL_PATH_DIR"] == str(pdd / "ansible" / "cp")
        assert os.environ["HOME"] == str(home)
        assert home.stat().st_mode & 0o777 == 0o700
        assert os.environ["TMPDIR"] == str(pdd / "tmp")
        for name in ("ansible", "tmp"):
            assert (pdd / name).stat().st_mode & 0o777 == 0o700
    finally:
        import shutil

        shutil.rmtree(pdd)


def test_prepare_leaves_home_alone_unless_asked(monkeypatch) -> None:
    monkeypatch.setenv("HOME", "/home/someone")
    monkeypatch.setenv("ANSIBLE_HOME", "before")
    job = {"files": {"playbook": "", "inventory": ""}, "prefix": "ansideck-run-8-"}
    pdd = run_worker.prepare(job)
    try:
        assert os.environ["HOME"] == "/home/someone"
        assert os.environ["ANSIBLE_HOME"] == f"{pdd}/ansible"
    finally:
        import shutil

        shutil.rmtree(pdd)


def test_prepare_forces_json_results(monkeypatch) -> None:
    # YAML results fold long values across lines, out of the exact-value scrubber's reach;
    # the environment outranks whatever a repository's ansible.cfg sets.
    monkeypatch.setenv("ANSIBLE_CALLBACK_RESULT_FORMAT", "yaml")
    job = {"files": {"playbook": "", "inventory": ""}, "prefix": "ansideck-run-9-"}
    pdd = run_worker.prepare(job)
    try:
        assert os.environ["ANSIBLE_CALLBACK_RESULT_FORMAT"] == "json"
    finally:
        import shutil

        shutil.rmtree(pdd)


def test_a_run_refuses_a_home_that_holds_someone_elses_files(monkeypatch, tmp_path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / ".ansible").mkdir()
    monkeypatch.setattr(run_worker.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=str(home)))
    with pytest.raises(RuntimeError, match="holds files of another user"):
        run_worker._own_home()


def test_clear_home_closes_and_empties_it(tmp_path) -> None:
    home = tmp_path / "home"
    (home / ".ansible" / "tmp").mkdir(parents=True)
    (home / ".bash_history").write_text("x")
    (home / "link").symlink_to(tmp_path)
    home.chmod(0o777)
    assert run_worker.clear_home(str(home)) is True
    assert home.stat().st_mode & 0o777 == 0o700
    assert list(home.iterdir()) == []
    assert tmp_path.is_dir()  # the link was removed, not followed
    assert run_worker.clear_home(str(tmp_path / "missing")) is True


def test_clear_home_reports_what_it_could_not_remove(monkeypatch, tmp_path) -> None:
    (tmp_path / "planted").mkdir()

    def rmtree(path) -> None:
        raise PermissionError(path)

    monkeypatch.setattr(run_worker.shutil, "rmtree", rmtree)
    assert run_worker.clear_home(str(tmp_path)) is False


def test_the_sweep_reports_a_home_it_could_not_clear(monkeypatch) -> None:
    monkeypatch.setattr(run_worker.os, "getuid", lambda: RUN_UID_BASE + 1)
    monkeypatch.setattr(run_worker.pwd, "getpwuid", _passwd)
    monkeypatch.setattr(run_worker, "kill_own_processes", lambda: None)
    removed = []
    monkeypatch.setattr(run_worker, "remove_own_files", removed.append)
    monkeypatch.setattr(run_worker, "clear_home", lambda home: home == "/tmp/ansideck-home/run1")
    assert run_worker.sweep(["/tmp"]) == 0
    monkeypatch.setattr(run_worker, "clear_home", lambda home: False)
    assert run_worker.sweep(["/tmp"]) == run_worker.HOME_NOT_CLEAN
    assert removed == [["/tmp"], ["/tmp"]]


def test_the_sweep_refuses_to_run_as_anyone_but_a_run_user(monkeypatch) -> None:
    killed = []
    monkeypatch.setattr(run_worker.os, "getuid", lambda: 1000)
    monkeypatch.setattr(run_worker.os, "kill", lambda *a: killed.append(a))
    with pytest.raises(SystemExit):
        run_worker.sweep(["/tmp"])
    assert killed == []


def test_kill_own_processes_signals_everything_until_nothing_is_left(monkeypatch) -> None:
    calls = []

    def kill(pid: int, sig: int) -> None:
        calls.append((pid, sig))
        if len(calls) == 3:
            raise ProcessLookupError

    monkeypatch.setattr(run_worker.os, "kill", kill)
    run_worker.kill_own_processes()
    assert calls == [(-1, signal.SIGKILL)] * 3


def test_remove_own_files_deletes_what_the_user_owns_without_following_links(tmp_path) -> None:
    root = tmp_path / "shared"
    (root / "run" / "deep").mkdir(parents=True)
    (root / "run" / "deep" / "key").write_text("x")
    (root / "loose.txt").write_text("x")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    (root / "link-to-dir").symlink_to(outside)
    (root / "link-to-file").symlink_to(outside / "keep.txt")

    run_worker.remove_own_files([str(root), str(tmp_path / "missing")])

    assert list(root.iterdir()) == []
    assert (outside / "keep.txt").read_text() == "keep"  # links removed, not followed


# ------------------------------------------------------------------ run_executor


def test_the_reported_private_data_dir_must_look_like_one() -> None:
    job = {"prefix": "ansideck-run-5-"}
    assert run_executor._checked_dir("/tmp/ansideck-run-5-abc", job) == "/tmp/ansideck-run-5-abc"
    assert run_executor._checked_dir("/", job) is None
    assert run_executor._checked_dir("/tmp/ansideck-run-6-abc", job) is None
    assert run_executor._checked_dir("ansideck-run-5-abc", job) is None


def test_sweep_runs_as_the_slot_user_and_checks_nothing_is_left(monkeypatch) -> None:
    commands = []
    left = [[123], []]
    monkeypatch.setattr(run_isolation.shutil, "which", lambda _name: "/usr/bin/setpriv")
    monkeypatch.setattr(run_executor, "_sweep_once", lambda cmd: commands.append(cmd) or 0)
    monkeypatch.setattr(run_executor, "processes_of", lambda uid: left.pop(0))
    monkeypatch.setattr(run_executor, "ipc_objects", lambda uid: [])
    monkeypatch.setattr(run_executor.time, "sleep", lambda _s: None)

    assert run_executor.sweep(identity_for_slot(1)) is True
    assert len(commands) == 2  # the first sweep left a process: it tried again
    assert commands[0][:2] == ["/usr/bin/setpriv", "--reuid=20001"]
    assert commands[0][-7:] == [
        "-m", "app.run_worker", "--sweep", "/tmp", "/var/tmp", "/dev/shm", "/dev/mqueue",
    ]  # fmt: skip


def test_sweep_is_not_clean_while_ipc_objects_are_left(monkeypatch) -> None:
    left = [[("shm", 5)], [("shm", 5)], [("shm", 5)]]
    monkeypatch.setattr(run_executor, "_sweep_once", lambda cmd: 0)
    monkeypatch.setattr(run_executor, "processes_of", lambda uid: [])
    monkeypatch.setattr(run_executor, "ipc_objects", lambda uid: left.pop(0))
    monkeypatch.setattr(run_executor.time, "sleep", lambda _s: None)
    assert run_executor.sweep(identity_for_slot(1)) is False
    assert left == []  # every attempt checked


def test_ipc_objects_finds_what_a_user_owns_or_created(tmp_path) -> None:
    (tmp_path / "shm").write_text(
        "       key      shmid perms   size  cpid  lpid nattch   uid   gid  cuid  cgid\n"
        "         1          7   666   4096    10    10      0 20001 20001 20001 20001\n"
        "         2          8   600   4096    11    11      0  1000  1000  1000  1000\n"
    )
    (tmp_path / "msg").write_text(
        "       key      msqid perms  cbytes  qnum lspid lrpid   uid   gid  cuid  cgid\n"
        "         3          9   666      10     1    10     0  1000  1000 20001 20001\n"
    )
    (tmp_path / "sem").write_text("       key      semid perms  nsems   uid   gid  cuid  cgid\n")
    assert run_isolation.ipc_objects(20001, str(tmp_path)) == [("shm", 7), ("msg", 9)]
    assert run_isolation.ipc_objects(20002, str(tmp_path)) == []
    assert run_isolation.ipc_objects(20001, str(tmp_path / "missing")) == []


def test_sweep_replaces_a_home_the_user_could_not_clear(monkeypatch) -> None:
    replaced = []
    monkeypatch.setattr(run_executor, "_sweep_once", lambda cmd: run_worker.HOME_NOT_CLEAN)
    monkeypatch.setattr(run_executor, "processes_of", lambda uid: [])
    monkeypatch.setattr(run_executor, "ipc_objects", lambda uid: [])
    monkeypatch.setattr(run_executor, "replace_home", replaced.append)
    assert run_executor._HOME_NOT_CLEAN == run_worker.HOME_NOT_CLEAN
    assert run_executor.sweep(identity_for_slot(0)) is True
    assert replaced == [identity_for_slot(0)]


def test_sweep_reports_a_user_it_could_not_empty(monkeypatch) -> None:
    monkeypatch.setattr(run_executor, "_sweep_once", lambda cmd: 0)
    monkeypatch.setattr(run_executor, "processes_of", lambda uid: [123])
    monkeypatch.setattr(run_executor, "ipc_objects", lambda uid: [])
    monkeypatch.setattr(run_executor.time, "sleep", lambda _s: None)
    assert run_executor.sweep(identity_for_slot(0)) is False


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")
def test_processes_of_finds_live_processes_by_uid() -> None:
    assert os.getpid() in run_executor.processes_of(os.getuid())
    assert run_executor.processes_of(RUN_UID_BASE + 63) == []


def test_an_isolated_run_executes_as_the_slot_user(monkeypatch) -> None:
    """The command and the cleanup, with the process itself faked."""
    seen = {}
    swept = []

    class FakeProc:
        pid = 4242
        returncode = 0

        def __init__(self, command, **kwargs) -> None:
            seen["command"] = command
            self.stdin = open(os.devnull, "wb")  # noqa: SIM115
            fd = kwargs["pass_fds"][0]
            with os.fdopen(os.dup(fd), "w") as out:
                out.write(json.dumps({"type": "started", "private_data_dir": "/tmp/x"}) + "\n")
                out.write(json.dumps({"type": "result", "status": "successful", "rc": 0}) + "\n")

        def wait(self, timeout=None) -> int:
            return 0

        def poll(self) -> int:
            return 0

    monkeypatch.setattr(run_isolation.shutil, "which", lambda _name: "/usr/bin/setpriv")
    monkeypatch.setattr(run_executor.subprocess, "Popen", FakeProc)
    monkeypatch.setattr(run_executor, "sweep", lambda identity: swept.append(identity) or True)
    monkeypatch.setattr(run_executor, "kill_leftovers", lambda marker: pytest.fail("not isolated"))

    identity = identity_for_slot(3)
    result = run_executor.run_in_worker(
        {"prefix": "ansideck-run-1-"}, {}, lambda e: None, None, identity
    )
    assert result == ("successful", 0)
    assert seen["command"][:2] == ["/usr/bin/setpriv", "--reuid=20003"]
    assert seen["command"][-3:] == run_executor._WORKER_COMMAND
    assert swept == [identity]


def test_a_run_process_sending_an_overlong_line_is_stopped(monkeypatch) -> None:
    """One message line past the limit and the run process is stopped and the run fails,
    rather than the worker reading it all (a line with no end would take every slot)."""
    monkeypatch.setattr(run_executor, "_MAX_MESSAGE_BYTES", 1000)
    script = (
        "import json, os, sys, time; job = json.loads(sys.stdin.readline());"
        "out = os.fdopen(job['event_fd'], 'w');"
        "out.write(json.dumps({'type': 'event', 'event': {'stdout': 'fine'}}) + '\\n');"
        "out.write('x' * 5000); out.flush(); time.sleep(60)"
    )
    monkeypatch.setattr(run_executor, "_WORKER_COMMAND", [sys.executable, "-c", script])
    events: list[dict] = []
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="over 1000 bytes in one line"):
        run_executor.run_in_worker({"prefix": "ansideck-run-1-"}, {}, events.append)
    assert events == [{"stdout": "fine"}]
    assert time.monotonic() - started < 30  # stopped, not waited for


def test_the_worker_reads_lines_as_long_as_the_run_process_may_send() -> None:
    assert run_executor._MAX_MESSAGE_BYTES == run_worker.MAX_MESSAGE_BYTES


def test_an_event_too_large_to_send_is_left_out_not_cut(monkeypatch) -> None:
    """The run process never cuts text: the worker scrubs secrets afterwards, and half a
    secret would get past it. A huge event goes without its content."""
    monkeypatch.setattr(run_worker, "_MAX_EVENT_BYTES", 1000)
    event = {"event": "runner_on_ok", "uuid": "u", "counter": 7, "stdout": "secret" * 200}
    small = run_worker.bounded_event(event)
    assert (small["event"], small["uuid"], small["counter"]) == ("runner_on_ok", "u", 7)
    assert small["stdout"] == "[AnsiDeck: event left out, it exceeded 1000 bytes]"
    assert run_worker.bounded_event({"stdout": "fine"}) == {"stdout": "fine"}


def test_a_sweep_that_runs_too_long_is_killed(monkeypatch) -> None:
    monkeypatch.setattr(run_executor, "_SWEEP_TIMEOUT_SECONDS", 0.2)
    assert run_executor._sweep_once([sys.executable, "-c", "import sys; sys.exit(3)"]) == 3
    assert run_executor._sweep_once([sys.executable, "-c", "import time; time.sleep(30)"]) is None
    assert run_executor._children == set()


def _wait_until_exited(pid: int) -> None:
    deadline = time.monotonic() + 10
    while os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
        assert time.monotonic() < deadline
        time.sleep(0.01)


def test_the_reaper_leaves_the_workers_own_children_alone() -> None:
    """The worker (PID 1) collects orphans, but never a status subprocess is waiting for:
    a stolen one reads as 0, so a sweep's HOME_NOT_CLEAN passed for a clean home."""
    own = run_executor._start([sys.executable, "-c", "import sys; sys.exit(3)"])
    _wait_until_exited(own.pid)
    worker_main.reap_once()
    assert own.wait() == 3
    run_executor._forget(own)

    orphan = subprocess.Popen([sys.executable, "-c", "pass"])  # not registered
    _wait_until_exited(orphan.pid)
    worker_main.reap_once()
    with pytest.raises(ChildProcessError):  # collected by the reaper
        os.waitid(os.P_PID, orphan.pid, os.WEXITED | os.WNOHANG)
    assert orphan.wait() == 0  # what subprocess makes of a status it lost


# ------------------------------------------------------------------ worker


class _IdleClient:
    """Answers every claim with "nothing to run"."""

    def __init__(self) -> None:
        self.claims: list[dict] = []

    def post(self, path: str, body: dict, **_kwargs):
        if path == "/internal/claim":
            self.claims.append(body)
        return type("R", (), {"status_code": 204})()


def test_an_isolated_slot_sweeps_its_user_before_claiming(monkeypatch, tmp_path) -> None:
    sweeps = []
    monkeypatch.setattr(runner, "sweep", lambda identity: sweeps.append(identity) or True)
    client = _IdleClient()
    worker = runner.Worker(
        client, worker_id="w", slots=2, galaxy_dir=tmp_path, isolated=True, claim_wait_seconds=0
    )
    worker.start()
    deadline = time.monotonic() + 5
    while len(client.claims) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    worker.stop()
    assert {identity.name for identity in sweeps} == {"ansideck-run0", "ansideck-run1"}
    assert client.claims[0]["isolated"] is True


def test_a_slot_whose_user_cannot_be_emptied_claims_nothing(monkeypatch, tmp_path) -> None:
    clean = threading.Event()
    monkeypatch.setattr(runner, "sweep", lambda identity: clean.is_set())
    monkeypatch.setattr(runner, "_DIRTY_SLOT_RETRY_SECONDS", 0.05)
    client = _IdleClient()
    worker = runner.Worker(
        client, worker_id="w", slots=1, galaxy_dir=tmp_path, isolated=True, claim_wait_seconds=0
    )
    worker.start()
    time.sleep(0.3)
    assert client.claims == []
    clean.set()  # the stuck process finally died
    deadline = time.monotonic() + 5
    while not client.claims and time.monotonic() < deadline:
        time.sleep(0.01)
    worker.stop()
    assert client.claims


def test_an_unisolated_worker_never_sweeps(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(runner, "sweep", lambda identity: pytest.fail("swept"))
    client = _IdleClient()
    worker = runner.Worker(
        client, worker_id="w", slots=1, galaxy_dir=tmp_path, claim_wait_seconds=0
    )
    worker.start()
    deadline = time.monotonic() + 5
    while not client.claims and time.monotonic() < deadline:
        time.sleep(0.01)
    worker.stop()
    assert client.claims[0]["isolated"] is False


def _settings(**values) -> WorkerSettings:
    return WorkerSettings(worker_token="t" * 40, **values)


def test_a_worker_that_can_isolate_prepares_the_homes(monkeypatch) -> None:
    prepared = []
    monkeypatch.setattr(worker_main, "check_available", lambda slots: None)
    monkeypatch.setattr(worker_main, "prepare_homes", prepared.append)
    assert worker_main.check_isolation(_settings(environment="production", worker_slots=3))
    assert prepared == [3]


def test_a_production_worker_that_cannot_isolate_refuses_to_start(monkeypatch) -> None:
    monkeypatch.setattr(worker_main, "check_available", lambda slots: "no caps")
    with pytest.raises(SystemExit, match=r"can't be isolated \(no caps\)"):
        worker_main.check_isolation(_settings(environment="production"))


def test_a_development_worker_that_cannot_isolate_warns(monkeypatch, caplog) -> None:
    monkeypatch.setattr(worker_main, "check_available", lambda slots: "no caps")
    assert worker_main.check_isolation(_settings()) is False
    assert "runs are NOT isolated (no caps)" in caplog.text
