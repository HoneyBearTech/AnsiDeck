"""Runs each worker slot's playbooks as a Linux user of their own (Phase 4C).

Slot n runs as ansideck-run<n> (uid/gid RUN_UID_BASE + n, created in the image): no
capabilities, no_new_privs, no supplementary groups. Such a run can't read the worker's
memory or environment (WORKER_TOKEN), signal it, or touch another slot's files and
processes. After each run, sweep() kills everything the slot's uid still runs (ansible's
setsid() task workers, SSH ControlPersist masters, anything a playbook daemonized) and
deletes the files it left in the shared temp dirs, so the slot's next run, possibly another
project's, starts clean. The worker itself never touches a run's files.

Each run user has a fixed home, HOME_ROOT/run<n>, which the worker creates at startup
(prepare_homes) and the sweep empties after every run: ansible's local tasks (connection:
local, delegate_to: localhost) put their temp files in the passwd home, not $HOME.

Switching users needs root with CAP_SETUID/CAP_SETGID, creating the homes CAP_CHOWN, and
stopping runs CAP_KILL: the worker container runs as uid 0 with only those four capabilities
(docker-compose.yml). Imports only the standard library, like run_executor.
"""

import os
import shutil
import stat
import sys
from dataclasses import dataclass

RUN_UID_BASE = 20000
MAX_SLOTS = 64  # the image has this many run users; WorkerSettings caps WORKER_SLOTS to it
# Where a run can leave files behind: the shared writable temp dirs (the worker's root
# filesystem is read-only). Its private data dir lives under /tmp, so it is swept too.
SWEEP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")  # noqa: S108 - fixed paths in the container
# Root-owned, so no run user can create (squat) another slot's home. The image's passwd
# entries point here (backend/Dockerfile).
HOME_ROOT = "/tmp/ansideck-home"  # noqa: S108 - fixed paths in the container
# Bit numbers in the capability sets (linux/capability.h).
REQUIRED_CAPS = {"CHOWN": 0, "KILL": 5, "SETGID": 6, "SETUID": 7}
SETPRIV_FALLBACK = "/usr/bin/setpriv"


@dataclass(frozen=True)
class RunIdentity:
    uid: int
    gid: int
    name: str
    home: str


def identity_for_slot(slot: int, home_root: str = HOME_ROOT) -> RunIdentity:
    if not 0 <= slot < MAX_SLOTS:
        raise ValueError(f"slot {slot} is out of range (0-{MAX_SLOTS - 1})")
    uid = RUN_UID_BASE + slot
    return RunIdentity(uid=uid, gid=uid, name=f"ansideck-run{slot}", home=f"{home_root}/run{slot}")


def effective_caps(status_text: str) -> int:
    """The CapEff bitmask from /proc/<pid>/status text (0 if it isn't there)."""
    for line in status_text.splitlines():
        if line.startswith("CapEff:"):
            return int(line.split()[1], 16)
    return 0


def check_available(slots: int, status_path: str = "/proc/self/status") -> str | None:
    """None if this process can run `slots` slots isolated, else why not (for the log and
    the production refusal)."""
    if not sys.platform.startswith("linux"):
        return "runs can only be isolated on Linux"
    if os.geteuid() != 0:
        return 'the worker is not running as root (compose: user: "0")'
    try:
        with open(status_path, encoding="ascii") as status:
            caps = effective_caps(status.read())
    except OSError as exc:
        return f"could not read the worker's capabilities ({exc})"
    missing = [name for name, bit in REQUIRED_CAPS.items() if not caps >> bit & 1]
    if missing:
        return f"the worker lacks the {', '.join(missing)} capabilities (compose: cap_add)"
    if shutil.which("setpriv") is None:
        return "setpriv (util-linux) is not installed"
    if slots > MAX_SLOTS:
        return f"WORKER_SLOTS is {slots}, but the image has only {MAX_SLOTS} run users"
    import pwd  # Unix only

    for slot in range(slots):
        identity = identity_for_slot(slot)
        try:
            entry = pwd.getpwuid(identity.uid)
        except KeyError:
            return f"the image has no run user {identity.name} (uid {identity.uid})"
        if entry.pw_dir != identity.home:
            return f"run user {identity.name} has home {entry.pw_dir}, not {identity.home}"
    return None


def prepare_homes(slots: int, home_root: str = HOME_ROOT, root_uid: int = 0) -> None:
    """Creates HOME_ROOT (root's, 0755) and each slot user's home in it (theirs, 0700). Raises
    if something else is in the way: a run user may have planted it."""
    _ensure_dir(home_root, uid=root_uid, gid=root_uid, mode=0o755)
    for slot in range(slots):
        identity = identity_for_slot(slot, home_root)
        _ensure_dir(identity.home, uid=identity.uid, gid=identity.gid, mode=0o700)


def _ensure_dir(path: str, *, uid: int, gid: int, mode: int) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        os.mkdir(path, mode)
        os.chmod(path, mode)  # mkdir applies the umask; chown would forbid this afterwards
        if uid != os.geteuid():
            os.chown(path, uid, gid)
        return
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid:
        raise RuntimeError(f"{path} exists but is not a directory of uid {uid}")
    if info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) != mode:
        os.chmod(path, mode)


def replace_home(identity: RunIdentity) -> None:
    """Moves a home its user couldn't empty (another slot planted a directory in it while a
    run had opened it up) out of the way, and creates a fresh one. The worker owns HOME_ROOT,
    so it may rename entries in it; the old home is the user's, and later sweeps empty what
    they can of it."""
    parent = os.path.dirname(identity.home)
    os.rename(identity.home, os.path.join(parent, f".stale-{identity.name}-{os.urandom(4).hex()}"))
    _ensure_dir(identity.home, uid=identity.uid, gid=identity.gid, mode=0o700)


def wrap(command: list[str], identity: RunIdentity) -> list[str]:
    """`command`, run as `identity` with no capabilities and no way to gain any (setpriv
    execs it, so the process id stays the command's own)."""
    return [
        shutil.which("setpriv") or SETPRIV_FALLBACK,
        f"--reuid={identity.uid}",
        f"--regid={identity.gid}",
        "--clear-groups",
        "--no-new-privs",
        "--inh-caps=-all",
        "--",
        *command,
    ]
