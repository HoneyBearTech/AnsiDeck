"""python -m app.worker: see app.worker. Meant to be PID 1 of its container, without an init
(`docker run --init`) or other wrapper: whatever process holds the container's environment
(WORKER_TOKEN included) must be non-dumpable, or a playbook could read it from /proc."""

import logging
import os
import signal
import sys
import threading
import time
from collections.abc import Callable

import httpx
from pydantic import ValidationError

from app.process_hardening import disable_process_inspection
from app.worker.client import ApiClient, ApiUnavailable
from app.worker.runner import Worker
from app.worker.settings import WorkerSettings

logger = logging.getLogger("app.worker")

# The worker gets secrets only per run, from the API. Finding the API's own secrets in its
# environment means it was deployed wrong (e.g. with the API's env_file), and playbooks run
# as the worker's user, so it refuses to start rather than expose them.
FORBIDDEN_ENV = ("CREDENTIAL_ENCRYPTION_KEY", "DATABASE_URL", "AUTH_SECRET_KEY")
_API_WAIT_SECONDS = 120.0


def forbidden_env() -> list[str]:
    return [name for name in FORBIDDEN_ENV if name in os.environ]


def load_settings() -> WorkerSettings:
    if forbidden := forbidden_env():
        sys.exit(f"Refusing to start: {', '.join(forbidden)} must not be set for a worker.")
    try:
        settings = WorkerSettings()
    except ValidationError as exc:
        sys.exit(f"Invalid worker settings: {exc}")
    # Playbooks run as this user; don't leave the token where a child could inherit it.
    for name in [n for n in os.environ if n.upper() == "WORKER_TOKEN"]:
        del os.environ[name]
    return settings


def wait_for_api(client: ApiClient, timeout: float = _API_WAIT_SECONDS) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            response = client.post("/internal/ping", {}, timeout=5)
        except ApiUnavailable as exc:
            if "HTTP 401" in str(exc):
                raise SystemExit("The API refused WORKER_TOKEN (it must match the API's).") from exc
            if time.monotonic() > deadline:
                raise SystemExit(f"The API is not reachable: {exc}") from exc
            logger.info("waiting for the API (%s)", exc)
            time.sleep(2)
            continue
        if response.status_code == 200:
            return
        raise SystemExit(f"Unexpected answer from the API's ping: HTTP {response.status_code}")


def reap_orphans(own_pids: Callable[[], set[int]]) -> None:
    """As PID 1, collects exited processes that were orphaned to it (e.g. ssh helpers of a
    stopped playbook), leaving the worker's own children to subprocess."""
    while True:
        time.sleep(1)
        while True:
            try:
                info = os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError:
                break
            if info is None or info.si_pid in own_pids():
                break
            try:
                os.waitpid(info.si_pid, 0)
            except ChildProcessError:
                pass


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)  # not every heartbeat and poll
    disable_process_inspection()
    settings = load_settings()

    http = httpx.Client(
        base_url=settings.ansideck_api_url,
        headers={"Authorization": f"Bearer {settings.worker_token}"},
    )
    client = ApiClient(http)
    wait_for_api(client)

    worker = Worker(
        client,
        worker_id=settings.worker_id,
        slots=settings.worker_slots,
        galaxy_dir=settings.galaxy_dir,
    )
    if os.getpid() == 1:
        threading.Thread(target=reap_orphans, args=(worker.active_pids,), daemon=True).start()

    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    worker.start()
    logger.info(
        "worker %s ready: %s slot(s), API %s",
        settings.worker_id,
        settings.worker_slots,
        settings.ansideck_api_url,
    )
    while not stop.wait(1):
        pass
    logger.info(
        "stopping: letting running runs finish for up to %.0f s", settings.worker_drain_seconds
    )
    worker.stop(drain_seconds=settings.worker_drain_seconds)
    logger.info("stopped")


if __name__ == "__main__":
    main()
