"""Executes claimed runs: one thread per slot (claim -> job -> ansible -> events -> complete)
and one heartbeat thread for the whole worker (lease renewal, cancel, timeout, self-fencing).
"""

import json
import logging
import shutil
import tempfile
import threading
import time
from collections import deque
from pathlib import Path

from app.run_executor import ExecutionHandle, format_duration, host_counts, run_in_worker
from app.scrub import build_scrubber
from app.subprocess_env import clean_env
from app.worker.client import ApiClient, ApiUnavailable

logger = logging.getLogger(__name__)

# Keep one request well under the internal API's 4 MiB body limit.
MAX_EVENT_BYTES = 1024 * 1024
MAX_BATCH_BYTES = 1024 * 1024
_TRUNCATED_STDOUT_CHARS = 64 * 1024
_BATCH_DELAY_SECONDS = 0.2
_FLUSH_TIMEOUT_SECONDS = 60.0

# Stop reasons (ExecutionHandle.stop_reason) and what they become.
CANCELLED = "cancelled"
TIMED_OUT = "timed_out"
LEASE_LOST = "lease lost"
SHUTDOWN = "shutdown"
GONE = "gone"  # the API ended our claim: stop quietly, report nothing


def _bounded(event: dict) -> dict:
    """An oversized event (a task that printed megabytes) is cut down rather than lost."""
    if len(json.dumps(event)) <= MAX_EVENT_BYTES:
        return event
    stdout = str(event.get("stdout", ""))[:_TRUNCATED_STDOUT_CHARS]
    return {
        "event": event.get("event"),
        "uuid": event.get("uuid"),
        "counter": event.get("counter"),
        "stdout": f"{stdout}\n[AnsiDeck: event truncated, it exceeded {MAX_EVENT_BYTES} bytes]",
    }


class RunTask:
    def __init__(self, run_id: int, claim_token: str) -> None:
        self.run_id = run_id
        self.claim_token = claim_token
        self.handle = ExecutionHandle()
        self.renewed = time.monotonic()  # the claim itself set the lease
        self.deadline: float | None = None
        self.timeout_seconds = 0

    def stop(self, reason: str) -> None:
        if self.handle.stop(reason):
            logger.info("run %s: stopping (%s)", self.run_id, reason)


class EventSender:
    """Numbers events 1, 2, 3... and sends them in batches from a thread of its own, so a
    slow API never stalls ansible. Unacknowledged events are kept and resent, and the API
    skips the ones it already has, so nothing is lost or written twice."""

    def __init__(self, client: ApiClient, task: RunTask) -> None:
        self._client = client
        self._task = task
        self._pending: deque[tuple[int, dict, int]] = deque()
        self._next_seq = 1
        self._closed = False
        self._abandoned = False
        self._cond = threading.Condition()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    @property
    def last_seq(self) -> int:
        return self._next_seq - 1

    def add(self, event: dict) -> None:
        with self._cond:
            size = len(json.dumps(event))
            self._pending.append((self._next_seq, event, size))
            self._next_seq += 1
            self._cond.notify()

    def close(self) -> bool:
        """Waits until every event is acknowledged; False if that didn't happen in time."""
        with self._cond:
            self._closed = True
            self._cond.notify()
        self._thread.join(_FLUSH_TIMEOUT_SECONDS)
        with self._cond:
            self._abandoned = True  # stops the thread if it is still retrying
            return not self._pending

    def _batch(self) -> tuple[int, list[dict]] | None:
        with self._cond:
            while not self._pending and not self._closed:
                self._cond.wait()
            if not self._pending or self._abandoned or self._task.handle.stop_reason == GONE:
                return None
            events, size = [], 0
            for _seq, event, event_size in self._pending:
                if events and size + event_size > MAX_BATCH_BYTES:
                    break
                events.append(event)
                size += event_size
            return self._pending[0][0], events

    def _drop_through(self, seq: int) -> None:
        with self._cond:
            while self._pending and self._pending[0][0] <= seq:
                self._pending.popleft()

    def _loop(self) -> None:
        delay = 0.5
        while True:
            if not self._closed:
                time.sleep(_BATCH_DELAY_SECONDS)
            batch = self._batch()
            if batch is None:
                return
            first_seq, events = batch
            try:
                response = self._client.post(
                    f"/internal/runs/{self._task.run_id}/events",
                    {"first_seq": first_seq, "events": events},
                    claim_token=self._task.claim_token,
                )
            except ApiUnavailable as exc:
                logger.warning(
                    "run %s: sending output failed (%s); retrying", self._task.run_id, exc
                )
                time.sleep(delay)
                delay = min(delay * 2, 5.0)
                continue
            delay = 0.5
            if response.status_code == 200:
                ack = response.json()
                self._drop_through(ack["acked_seq"])
                if ack.get("cancel"):
                    self._task.stop(CANCELLED)
            elif response.status_code == 409:
                expected = response.json()["expected_seq"]
                if expected <= first_seq:  # the API lost events it had acknowledged
                    logger.error("run %s: output out of sync; giving up", self._task.run_id)
                    with self._cond:
                        self._pending.clear()
                    return
                self._drop_through(expected - 1)
            elif response.status_code == 410:
                self._task.stop(GONE)
                with self._cond:
                    self._pending.clear()
                return
            else:
                logger.error(
                    "run %s: output refused (HTTP %s); dropping %s events",
                    self._task.run_id,
                    response.status_code,
                    len(events),
                )
                self._drop_through(first_seq + len(events) - 1)


class Worker:
    def __init__(
        self,
        client: ApiClient,
        *,
        worker_id: str,
        slots: int = 1,
        galaxy_dir: str | Path = "/data/galaxy",
        claim_wait_seconds: float = 25.0,
        heartbeat_seconds: float = 5.0,
        fence_seconds: float = 45.0,
    ) -> None:
        self.client = client
        self.worker_id = worker_id
        self.slots = slots
        self.galaxy_dir = Path(galaxy_dir)
        self.claim_wait_seconds = claim_wait_seconds
        self.heartbeat_seconds = heartbeat_seconds
        self.fence_seconds = fence_seconds
        self._tasks: dict[int, RunTask] = {}
        self._lock = threading.Lock()
        self._stopping = threading.Event()
        self._heartbeat_stop = threading.Event()
        self._slot_threads: list[threading.Thread] = []
        self._heartbeat_thread: threading.Thread | None = None

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> None:
        for n in range(self.slots):
            thread = threading.Thread(target=self._slot, name=f"slot-{n}", daemon=True)
            thread.start()
            self._slot_threads.append(thread)
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, name="heartbeat", daemon=True
        )
        self._heartbeat_thread.start()

    def stop(self, drain_seconds: float = 0.0) -> None:
        """Stops claiming, lets running runs finish for up to drain_seconds, then stops them
        (they end as failed, "worker shut down"), and waits for every thread."""
        self._stopping.set()
        deadline = time.monotonic() + drain_seconds
        while self.active_run_ids() and time.monotonic() < deadline:
            time.sleep(0.2)
        for task in self._snapshot():
            task.stop(SHUTDOWN)
        for thread in self._slot_threads:
            thread.join()
        self._heartbeat_stop.set()
        if self._heartbeat_thread is not None:
            self._heartbeat_thread.join()

    def active_run_ids(self) -> list[int]:
        with self._lock:
            return list(self._tasks)

    def active_pids(self) -> set[int]:
        return {pid for task in self._snapshot() if (pid := task.handle.pid)}

    def _snapshot(self) -> list[RunTask]:
        with self._lock:
            return list(self._tasks.values())

    # ------------------------------------------------------------------ slots

    def _slot(self) -> None:
        delay = 1.0
        while not self._stopping.is_set():
            try:
                response = self.client.post(
                    "/internal/claim",
                    {"worker_id": self.worker_id, "wait_seconds": self.claim_wait_seconds},
                    timeout=self.claim_wait_seconds + 15,
                )
            except ApiUnavailable as exc:
                logger.warning("claim failed (%s); retrying in %.0f s", exc, delay)
                self._stopping.wait(delay)
                delay = min(delay * 2, 10.0)
                continue
            delay = 1.0
            if response.status_code == 204:
                continue
            if response.status_code != 200:
                logger.error("claim refused: HTTP %s", response.status_code)
                self._stopping.wait(5)
                continue
            claim = response.json()
            task = RunTask(claim["run_id"], claim["claim_token"])
            with self._lock:
                self._tasks[task.run_id] = task
            if self._stopping.is_set():  # claimed while shutting down: end it at once
                task.stop(SHUTDOWN)
            try:
                self._execute(task, claim["job_token"])
            except Exception:  # noqa: BLE001 - one run's failure must not end the slot
                logger.exception("run %s: the worker failed", task.run_id)
            finally:
                with self._lock:
                    self._tasks.pop(task.run_id, None)

    def _fetch_job(self, task: RunTask, job_token: str) -> dict | None:
        for delay in (1, 2, 4, 8, 16, None):
            try:
                response = self.client.post(
                    f"/internal/runs/{task.run_id}/job",
                    {"job_token": job_token},
                    claim_token=task.claim_token,
                )
            except ApiUnavailable as exc:
                if delay is None or task.handle.stop_reason:
                    logger.error("run %s: could not fetch the job (%s)", task.run_id, exc)
                    return None
                time.sleep(delay)
                continue
            if response.status_code == 200:
                return response.json()
            logger.warning("run %s: job refused (HTTP %s)", task.run_id, response.status_code)
            return None
        return None

    def _galaxy_env(self) -> dict[str, str]:
        return {
            "ANSIBLE_COLLECTIONS_PATH": str(self.galaxy_dir / "collections"),
            "ANSIBLE_ROLES_PATH": str(self.galaxy_dir / "roles"),
        }

    def _execute(self, task: RunTask, job_token: str) -> None:
        job = self._fetch_job(task, job_token)
        if job is None:
            return  # the lease runs out and the reaper ends the run, unless the API did
        task.timeout_seconds = job["timeout_seconds"]
        task.deadline = time.monotonic() + task.timeout_seconds
        logger.info("run %s: starting", task.run_id)

        scrub = build_scrubber(job["secrets"])
        sender = EventSender(self.client, task)
        recap: dict[str, int] = {}

        def on_event(event: dict) -> None:
            if event.get("event") == "playbook_on_stats":
                recap.update(host_counts(event.get("event_data")))  # before scrubbing
            sender.add(_bounded(scrub(event)))

        status: str | None = None
        return_code: int | None = None
        crashed = False
        pdd = tempfile.mkdtemp(prefix=f"ansideck-run-{task.run_id}-")
        try:
            project_dir = Path(pdd) / "project"
            project_dir.mkdir()
            (project_dir / "playbook.yml").write_text(job["playbook"])
            inventory_dir = Path(pdd) / "inventory"
            inventory_dir.mkdir()
            inventory_path = inventory_dir / "hosts.yml"
            inventory_path.write_text(job["inventory"])
            vault_password = job["vault_password"]
            status, return_code = run_in_worker(
                {
                    "private_data_dir": pdd,
                    "playbook": "playbook.yml",
                    "inventory": str(inventory_path),
                    "ssh_key": job["ssh_key"],
                    "cmdline": job["cmdline"],
                    "limit": job["limit"],
                    "extravars": job["extravars"],
                    "passwords": (
                        {r"Vault password:\s*?$": vault_password}
                        if vault_password is not None
                        else None
                    ),
                },
                clean_env(self._galaxy_env()),
                on_event,
                task.handle,
            )
        except Exception:  # noqa: BLE001 - reported as a failed run below
            if task.handle.stop_reason is None:
                logger.exception("run %s: could not run the playbook", task.run_id)
            crashed = True  # (a stopped run's last, cut-off output line can land here)
        finally:
            del job
            shutil.rmtree(pdd, ignore_errors=True)

        flushed = sender.close()
        reason = task.handle.stop_reason
        if reason == GONE:
            logger.info("run %s: the API ended this claim; not reporting", task.run_id)
            return
        if not flushed:
            logger.error("run %s: output could not be delivered; not reporting", task.run_id)
            return
        outcome, why = self._outcome(task, reason, status, crashed)
        self._complete(task, sender.last_seq, outcome, why, return_code, recap)

    @staticmethod
    def _outcome(
        task: RunTask, reason: str | None, status: str | None, crashed: bool
    ) -> tuple[str, str | None]:
        if reason == CANCELLED:
            return "cancelled", "cancelled"
        if reason == TIMED_OUT:
            return "timed_out", f"timed out after {format_duration(task.timeout_seconds)}"
        if reason == LEASE_LOST:
            return "failed", "stopped: the worker could not reach the API to renew its lease"
        if reason == SHUTDOWN:
            return "failed", "stopped: the worker shut down"
        if crashed:
            return "failed", "the worker could not run the playbook"
        if status is None:
            return "failed", "the run process ended without reporting a result"
        return ("success", None) if status == "successful" else ("failed", None)

    def _complete(
        self,
        task: RunTask,
        last_seq: int,
        outcome: str,
        reason: str | None,
        return_code: int | None,
        recap: dict[str, int],
    ) -> None:
        body = {
            "last_seq": last_seq,
            "status": outcome,
            "return_code": return_code,
            "reason": reason,
            "host_counts": recap or None,
        }
        deadline = time.monotonic() + _FLUSH_TIMEOUT_SECONDS
        delay = 0.5
        while time.monotonic() < deadline:
            try:
                response = self.client.post(
                    f"/internal/runs/{task.run_id}/complete", body, claim_token=task.claim_token
                )
            except ApiUnavailable as exc:
                logger.warning("run %s: reporting failed (%s); retrying", task.run_id, exc)
                time.sleep(delay)
                delay = min(delay * 2, 5.0)
                continue
            if response.status_code == 200:
                logger.info("run %s: %s", task.run_id, outcome)
            else:
                logger.error("run %s: result refused (HTTP %s)", task.run_id, response.status_code)
            return
        logger.error("run %s: could not report the result in time", task.run_id)

    # ------------------------------------------------------------------ heartbeat

    def _heartbeat_loop(self) -> None:
        while not self._heartbeat_stop.wait(self.heartbeat_seconds):
            try:
                self.beat()
            except Exception:  # noqa: BLE001 - the heartbeat must keep going
                logger.exception("heartbeat failed")

    def beat(self) -> None:
        tasks = self._snapshot()
        if not tasks:
            return
        now = time.monotonic()
        for task in tasks:
            if task.deadline is not None and now > task.deadline:
                task.stop(TIMED_OUT)
        by_id = {task.run_id: task for task in tasks}
        try:
            response = self.client.post(
                "/internal/heartbeat",
                {
                    "worker_id": self.worker_id,
                    "runs": [{"run_id": t.run_id, "claim_token": t.claim_token} for t in tasks],
                },
                timeout=max(self.heartbeat_seconds, 2.0),
            )
        except ApiUnavailable as exc:
            logger.warning("heartbeat failed (%s)", exc)
        else:
            if response.status_code == 200:
                for answer in response.json()["runs"]:
                    task = by_id.get(answer["run_id"])
                    if task is None:
                        continue
                    if answer["state"] == "gone":
                        task.stop(GONE)
                        continue
                    task.renewed = now
                    if answer["state"] == "cancel":
                        task.stop(CANCELLED)
        # Self-fencing: a run whose lease we couldn't renew may already be failed and its
        # inventory handed to another worker, so it must not keep changing hosts.
        for task in tasks:
            if time.monotonic() - task.renewed > self.fence_seconds:
                task.stop(LEASE_LOST)
