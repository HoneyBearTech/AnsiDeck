"""Keeps playbook runs from reading this process's memory and environment. Used by the API
and by the worker, so it imports nothing from app.*."""

import ctypes
import logging
import sys

logger = logging.getLogger(__name__)

_PR_SET_DUMPABLE = 4


def disable_process_inspection() -> bool:
    """Marks this process non-dumpable (Linux), which makes /proc/<pid>/environ, mem and
    friends unreadable to other processes of the same user. Playbook runs execute as the
    app's own user, so without this a playbook could read the app's original environment
    (encryption key, auth key) straight out of /proc even though runs are spawned with a
    clean environment. execve resets the flag, so the spawned worker/ansible are unaffected.
    Returns whether it took effect; a no-op (False) off Linux."""
    if not sys.platform.startswith("linux"):
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE) failed")
    except (OSError, AttributeError):
        logger.warning(
            "Could not mark the process non-dumpable; playbook runs may be able to read "
            "the app's environment via /proc",
            exc_info=True,
        )
        return False
    return True
