"""Appends to a run's JSONL log, which is the single source of truth for its output.

Callers hold the run's row lock and commit right after. The file is first cut back to the
committed length (runs.log_bytes), so the leftovers of a write whose commit never happened
disappear, and the new lines are fsynced before the commit, so the committed length is never
longer than what is on disk.
"""

import json
import os

from app.models import Run
from app.scrub import Scrubber
from app.storage import run_log_path

# Workers scrub every event with the run's own secrets before sending it; the API only knows
# the patterns (private keys, bearer tokens, password=...), applied again as a second layer.
_pattern_scrubber = Scrubber(())


def append_events(run: Run, events: list[dict]) -> None:
    data = b"".join(
        (json.dumps(_pattern_scrubber.scrub_event(event)) + "\n").encode() for event in events
    )
    fd = os.open(run_log_path(run.id), os.O_WRONLY | os.O_CREAT, 0o644)
    with os.fdopen(fd, "wb") as log:
        log.truncate(run.log_bytes)
        log.seek(run.log_bytes)
        log.write(data)
        log.flush()
        os.fsync(log.fileno())
    run.log_bytes += len(data)


def append_status_line(run: Run, text: str) -> None:
    """A line from AnsiDeck itself (not ansible), e.g. why the reaper ended the run. It takes
    the next sequence number, so a worker that still thinks it owns the run can't reuse it."""
    run.log_seq += 1
    append_events(run, [{"event": "ansideck_status", "counter": run.log_seq, "stdout": text}])
