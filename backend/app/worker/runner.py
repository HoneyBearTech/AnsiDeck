"""Executes claimed runs: one thread per slot (claim -> job -> ansible -> events -> complete)
and one heartbeat thread for the whole worker (lease renewal, cancel, timeout, self-fencing).
"""

import hashlib
import json
import logging
import re
import threading
import time
from collections import deque
from pathlib import Path

from app.json_limits import loads_bounded
from app.run_executor import (
    ExecutionHandle,
    RunRefused,
    format_duration,
    host_counts,
    inventory_in_worker,
    run_in_worker,
    sweep,
)
from app.run_isolation import RunIdentity, identity_for_slot
from app.scrub import Scrubber, build_scrubber, scrub_exact
from app.subprocess_env import clean_env
from app.worker.client import ApiClient, ApiRefused, ApiUnavailable

logger = logging.getLogger(__name__)

# Keep one request well under the internal API's 4 MiB body limit.
MAX_EVENT_BYTES = 1024 * 1024
MAX_BATCH_BYTES = 1024 * 1024
_TRUNCATED_STDOUT_CHARS = 64 * 1024
_BATCH_DELAY_SECONDS = 0.2
_FLUSH_TIMEOUT_SECONDS = 60.0
_DIRTY_SLOT_RETRY_SECONDS = 30.0
# A refresh's output goes up in chunks, well under the internal API's 4 MiB body limit.
_REFRESH_CHUNK_BYTES = 2 * 1024 * 1024
# Deeper output is refused by the API anyway (app.inventory_sources.normalise).
_MAX_OUTPUT_DEPTH = 64
# "[WARNING]: Failed to parse inventory with 'auto' plugin: <why>" carries the reason, the
# "[ERROR]: Completely failed to parse inventory source <file>" after it the file.
_PLUGIN_FAILED = re.compile(r"^\[WARNING\]: Failed to parse inventory with '([^']+)' plugin: (.*)$")
_SOURCE_FAILED = re.compile(r"^\[ERROR\]: Completely failed to parse inventory source (.*)$")
_REFRESH_PATHS = re.compile(r"/\S*?/ansideck-refresh-\d+-[^/\s]*/inventory/")

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


def refresh_error(stderr: str, secrets: list[str], rc: int | None) -> str:
    """Why ansible-inventory failed, from its stderr: its error lines (the config files named
    without their temporary directory), scrubbed of the credentials' values."""
    text = _REFRESH_PATHS.sub("", stderr)
    errors: list[str] = []
    reasons: list[str] = []
    for line in text.splitlines():
        if failed := _PLUGIN_FAILED.match(line):
            if failed.group(1) != "yaml":  # "not YAML inventory": it was a plugin config
                reasons.append(failed.group(2))
        elif source := _SOURCE_FAILED.match(line):
            errors.append(f"{source.group(1)}: {'; '.join(reasons) or 'could not be parsed'}")
            reasons = []
        elif line.startswith("[ERROR]: "):
            errors.append(line.removeprefix("[ERROR]: "))
    summary = "\n".join(errors) if errors else text.strip()[-800:]
    summary = Scrubber(secrets).scrub_text(summary).strip()
    return (summary or f"ansible-inventory failed (exit code {rc})")[-1000:]


class RunTask:
    """A claimed run, or (kind "refresh") an inventory refresh: run_id is then its id."""

    def __init__(self, run_id: int, claim_token: str, kind: str = "run") -> None:
        self.run_id = run_id
        self.claim_token = claim_token
        self.kind = kind
        self.handle = ExecutionHandle()
        self.renewed = time.monotonic()  # the claim itself set the lease
        self.deadline: float | None = None
        self.timeout_seconds = 0

    @property
    def key(self) -> tuple[str, int]:
        return (self.kind, self.run_id)

    @property
    def label(self) -> str:
        return f"{self.kind} {self.run_id}"

    def stop(self, reason: str) -> None:
        if self.handle.stop(reason):
            logger.info("%s: stopping (%s)", self.label, reason)


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
        isolated: bool = False,
        claim_wait_seconds: float = 25.0,
        heartbeat_seconds: float = 5.0,
        fence_seconds: float = 45.0,
    ) -> None:
        self.client = client
        self.worker_id = worker_id
        self.slots = slots
        self.galaxy_dir = Path(galaxy_dir)
        # Each slot runs its playbooks as a user of its own (app.run_isolation).
        self.isolated = isolated
        self.claim_wait_seconds = claim_wait_seconds
        self.heartbeat_seconds = heartbeat_seconds
        self.fence_seconds = fence_seconds
        self._tasks: dict[tuple[str, int], RunTask] = {}
        self._lock = threading.Lock()
        self._stopping = threading.Event()
        self._heartbeat_stop = threading.Event()
        self._slot_threads: list[threading.Thread] = []
        self._heartbeat_thread: threading.Thread | None = None

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> None:
        for n in range(self.slots):
            identity = identity_for_slot(n) if self.isolated else None
            thread = threading.Thread(
                target=self._slot, args=(identity,), name=f"slot-{n}", daemon=True
            )
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
        while self._snapshot() and time.monotonic() < deadline:
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
            return [run_id for kind, run_id in self._tasks if kind == "run"]

    def active_pids(self) -> set[int]:
        return {pid for task in self._snapshot() if (pid := task.handle.pid)}

    def _snapshot(self) -> list[RunTask]:
        with self._lock:
            return list(self._tasks.values())

    # ------------------------------------------------------------------ slots

    def _sweep_until_clean(self, identity: RunIdentity) -> bool:
        """Never hand a run a slot whose user still has processes (a previous run's, maybe
        another project's): keep sweeping, not claiming, until it is clean. False if the
        worker is stopping first."""
        while not sweep(identity):
            logger.error(
                "slot user %s still has processes; not running anything on this slot "
                "(retrying in %.0f s)",
                identity.name,
                _DIRTY_SLOT_RETRY_SECONDS,
            )
            if self._stopping.wait(_DIRTY_SLOT_RETRY_SECONDS):
                return False
        return True

    def _slot(self, identity: RunIdentity | None = None) -> None:
        delay = 1.0
        dirty = identity is not None  # whatever an earlier worker left behind
        while not self._stopping.is_set():
            if dirty:
                if identity is not None and not self._sweep_until_clean(identity):
                    break
                dirty = False
            try:
                response = self.client.post(
                    "/internal/claim",
                    {
                        "worker_id": self.worker_id,
                        "slots": self.slots,
                        "isolated": self.isolated,
                        "wait_seconds": self.claim_wait_seconds,
                        "kinds": ["run", "refresh"],
                    },
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
            task = RunTask(claim["run_id"], claim["claim_token"], claim.get("kind", "run"))
            with self._lock:
                self._tasks[task.key] = task
            if self._stopping.is_set():  # claimed while shutting down: end it at once
                task.stop(SHUTDOWN)
            try:
                if task.kind == "refresh":
                    self._execute_refresh(task, claim["job_token"], identity)
                else:
                    self._execute(task, claim["job_token"], identity)
            except Exception:  # noqa: BLE001 - one job's failure must not end the slot
                logger.exception("%s: the worker failed", task.label)
            finally:
                dirty = True
                with self._lock:
                    self._tasks.pop(task.key, None)
        if identity is not None and dirty:
            sweep(identity)

    def _fetch_job(self, task: RunTask, job_token: str) -> dict | None:
        path = "refreshes" if task.kind == "refresh" else "runs"
        for delay in (1, 2, 4, 8, 16, None):
            try:
                response = self.client.post(
                    f"/internal/{path}/{task.run_id}/job",
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

    def _fetch_snapshot(self, task: RunTask, project: dict) -> bytes | None:
        """The run's repository tar, exactly as its job describes it (size and sha256)."""
        expected = int(project["bytes"])
        for delay in (1, 2, 4, 8, None):
            try:
                data = self.client.download(
                    f"/internal/runs/{task.run_id}/snapshot",
                    {},
                    claim_token=task.claim_token,
                    max_bytes=expected,
                )
            except ApiUnavailable as exc:
                if delay is None or task.handle.stop_reason:
                    logger.error("run %s: could not fetch the repository (%s)", task.run_id, exc)
                    return None
                time.sleep(delay)
                continue
            except ApiRefused as exc:
                logger.error("run %s: repository refused (%s)", task.run_id, exc)
                return None
            if len(data) != expected or hashlib.sha256(data).hexdigest() != project["sha256"]:
                logger.error("run %s: the repository doesn't match its job", task.run_id)
                return None
            return data
        return None

    def _galaxy_env(self) -> dict[str, str]:
        return {
            "ANSIBLE_COLLECTIONS_PATH": str(self.galaxy_dir / "collections"),
            "ANSIBLE_ROLES_PATH": str(self.galaxy_dir / "roles"),
        }

    def _execute(self, task: RunTask, job_token: str, identity: RunIdentity | None = None) -> None:
        job = self._fetch_job(task, job_token)
        if job is None:
            return  # the lease runs out and the reaper ends the run, unless the API did
        task.timeout_seconds = job["timeout_seconds"]
        task.deadline = time.monotonic() + task.timeout_seconds
        logger.info("run %s: starting", task.run_id)

        scrub = build_scrubber(job["secrets"])
        sender = EventSender(self.client, task)
        recap: dict[str, int] = {}

        # A playbook synced from git runs inside its repository at the run's commit.
        snapshot: bytes | None = None
        if job.get("project"):
            snapshot = self._fetch_snapshot(task, job["project"])
            if snapshot is None:
                sender.close()
                self._complete(
                    task, sender.last_seq, "failed", "could not fetch the repository", None, {}
                )
                return

        def on_event(event: dict) -> None:
            if event.get("event") == "playbook_on_stats":
                recap.update(host_counts(event.get("event_data")))  # before scrubbing
            sender.add(_bounded(scrub(event)))

        status: str | None = None
        return_code: int | None = None
        crashed = False
        refused: str | None = None
        try:
            vault_password = job["vault_password"]
            # The run's process writes these files itself, as the slot's user.
            status, return_code = run_in_worker(
                {
                    "files": {"playbook": job["playbook"], "inventory": job["inventory"]},
                    "project": {"playbook": job["project"]["playbook"]} if snapshot else None,
                    "prefix": f"ansideck-run-{task.run_id}-",
                    "own_home": identity is not None,
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
                identity,
                stdin_tail=snapshot,
            )
        except RunRefused as exc:
            refused = str(exc)
        except Exception:  # noqa: BLE001 - reported as a failed run below
            if task.handle.stop_reason is None:
                logger.exception("run %s: could not run the playbook", task.run_id)
            crashed = True  # (a stopped run's last, cut-off output line can land here)
        finally:
            del job

        flushed = sender.close()
        reason = task.handle.stop_reason
        if reason == GONE:
            logger.info("run %s: the API ended this claim; not reporting", task.run_id)
            return
        if not flushed:
            logger.error("run %s: output could not be delivered; not reporting", task.run_id)
            return
        outcome, why = self._outcome(task, reason, status, crashed)
        if refused is not None and reason is None:
            outcome, why = "failed", f"not run: {refused}"
        self._complete(task, sender.last_seq, outcome, why, return_code, recap)

    # ------------------------------------------------------------------ refreshes

    def _execute_refresh(
        self, task: RunTask, job_token: str, identity: RunIdentity | None = None
    ) -> None:
        """An inventory refresh: ansible-inventory in the slot's run process, its output
        scrubbed of the credentials' values, uploaded in chunks, then the outcome."""
        job = self._fetch_job(task, job_token)
        if job is None:
            return
        task.timeout_seconds = job["timeout_seconds"]
        task.deadline = time.monotonic() + task.timeout_seconds
        secrets = job["secrets"]
        logger.info("%s: starting", task.label)
        rc: int | None = None
        output, stderr, refused = "", "", None
        try:
            rc, output, stderr = inventory_in_worker(
                {
                    "files": job["files"],
                    "env": job["env"],
                    "prefix": f"ansideck-refresh-{task.run_id}-",
                    "own_home": identity is not None,
                    "max_output_bytes": job["max_output_bytes"],
                },
                clean_env(self._galaxy_env()),
                task.handle,
                identity,
            )
        except RunRefused as exc:
            refused = str(exc)
        except Exception:  # noqa: BLE001 - reported as a failed refresh below
            if task.handle.stop_reason is None:
                logger.exception("%s: could not run ansible-inventory", task.label)
        finally:
            del job

        reason = task.handle.stop_reason
        if reason == GONE:
            return
        if reason is not None:
            outcome, why = self._outcome(task, reason, None, False)
            self._complete_refresh(task, {"status": outcome, "error": why})
        elif refused is not None:
            self._complete_refresh(task, {"status": "failed", "error": f"not run: {refused}"})
        elif rc != 0:
            self._complete_refresh(
                task, {"status": "failed", "error": refresh_error(stderr, secrets, rc)}
            )
        else:
            self._upload_refresh(task, output, secrets)

    def _upload_refresh(self, task: RunTask, output: str, secrets: list[str]) -> None:
        try:
            data = loads_bounded(output, _MAX_OUTPUT_DEPTH)
        except (ValueError, RecursionError):
            self._complete_refresh(
                task, {"status": "failed", "error": "ansible-inventory's output is not JSON"}
            )
            return
        data, scrubbed = scrub_exact(data, secrets)
        body = json.dumps(data).encode()
        offset = 0
        deadline = time.monotonic() + _FLUSH_TIMEOUT_SECONDS
        while offset < len(body) and time.monotonic() < deadline:
            if task.handle.stop_reason:
                return
            try:
                response = self.client.post_bytes(
                    f"/internal/refreshes/{task.run_id}/output",
                    body[offset : offset + _REFRESH_CHUNK_BYTES],
                    claim_token=task.claim_token,
                    headers={"X-Offset": str(offset)},
                )
            except ApiUnavailable as exc:
                logger.warning("%s: upload failed (%s); retrying", task.label, exc)
                time.sleep(1)
                continue
            if response.status_code == 200:
                offset = response.json()["offset"]
            elif response.status_code == 409:
                offset = response.json()["expected_offset"]
            else:
                logger.error("%s: output refused (HTTP %s)", task.label, response.status_code)
                return
        if offset < len(body):
            logger.error("%s: could not upload the output in time", task.label)
            return
        self._complete_refresh(
            task,
            {
                "status": "success",
                "bytes": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
                "scrubbed": scrubbed,
            },
        )

    def _complete_refresh(self, task: RunTask, body: dict) -> None:
        deadline = time.monotonic() + _FLUSH_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            try:
                response = self.client.post(
                    f"/internal/refreshes/{task.run_id}/complete",
                    body,
                    claim_token=task.claim_token,
                )
            except ApiUnavailable as exc:
                logger.warning("%s: reporting failed (%s); retrying", task.label, exc)
                time.sleep(1)
                continue
            logger.info("%s: %s (HTTP %s)", task.label, body["status"], response.status_code)
            return
        logger.error("%s: could not report the result in time", task.label)

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
        # Sent even with no runs: it also tells the API this worker is online.
        tasks = self._snapshot()
        now = time.monotonic()
        for task in tasks:
            if task.deadline is not None and now > task.deadline:
                task.stop(TIMED_OUT)
        by_key = {task.key: task for task in tasks}
        try:
            response = self.client.post(
                "/internal/heartbeat",
                {
                    "worker_id": self.worker_id,
                    "slots": self.slots,
                    "isolated": self.isolated,
                    "runs": [
                        {"run_id": t.run_id, "claim_token": t.claim_token}
                        for t in tasks
                        if t.kind == "run"
                    ],
                    "refreshes": [
                        {"refresh_id": t.run_id, "claim_token": t.claim_token}
                        for t in tasks
                        if t.kind == "refresh"
                    ],
                },
                timeout=max(self.heartbeat_seconds, 2.0),
            )
        except ApiUnavailable as exc:
            logger.warning("heartbeat failed (%s)", exc)
        else:
            if response.status_code == 200:
                answers = response.json()
                for answer in answers.get("refreshes", []):
                    answer["run_id"] = answer["refresh_id"]
                    answer["kind"] = "refresh"
                for answer in [*answers["runs"], *answers.get("refreshes", [])]:
                    task = by_key.get((answer.get("kind", "run"), answer["run_id"]))
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
