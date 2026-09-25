"""In-process wake-ups: "something changed on topic X" (e.g. "run:12" when a run's log grew
or its status changed). Notifications carry no data, so a listener re-reads the source of
truth (the log file, the database) when it wakes; a missed one costs only a listener's
timeout, never correctness.

Loop-agnostic: notify() may be called from any thread, and each listener is woken on its
own event loop. An entry exists only while someone listens, so nothing accumulates. Only
this process is notified (one API replica); a pg_notify bridge could be added here without
changing callers.
"""

import asyncio
import contextlib
import threading
from collections.abc import Iterator


class Listener:
    def __init__(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._event = asyncio.Event()

    def _wake(self) -> None:
        with contextlib.suppress(RuntimeError):  # the listener's loop has already closed
            self._loop.call_soon_threadsafe(self._event.set)

    async def wait(self, timeout: float) -> bool:
        """True if notified since the previous wait() (or since listening began), False on
        timeout. Notifications that arrive while the caller is busy are not lost."""
        try:
            async with asyncio.timeout(timeout):
                await self._event.wait()
        except TimeoutError:
            return False
        self._event.clear()
        return True


class Notifier:
    def __init__(self) -> None:
        self._listeners: dict[str, set[Listener]] = {}
        self._lock = threading.Lock()

    @contextlib.contextmanager
    def listen(self, topic: str) -> Iterator[Listener]:
        """Must be entered inside a running event loop."""
        listener = Listener()
        with self._lock:
            self._listeners.setdefault(topic, set()).add(listener)
        try:
            yield listener
        finally:
            with self._lock:
                listeners = self._listeners.get(topic)
                if listeners is not None:
                    listeners.discard(listener)
                    if not listeners:
                        del self._listeners[topic]

    def notify(self, topic: str) -> None:
        with self._lock:
            listeners = list(self._listeners.get(topic, ()))
        for listener in listeners:
            listener._wake()

    def topics(self) -> set[str]:
        with self._lock:
            return set(self._listeners)


notifier = Notifier()


def run_topic(run_id: int) -> str:
    return f"run:{run_id}"
