"""Child-process entry point that actually runs ansible-runner (python -m app.run_worker).

ansible-runner seeds the playbook's environment from os.environ with no way to opt out,
so run_executor spawns this module with an allowlisted environment instead of running
ansible-runner in the app process. Deliberately imports nothing from app.* — in
particular not app.config, which would load the app's secrets.

Protocol: one JSON job (ansible_runner.run kwargs plus "event_fd") on stdin; one JSON
line per message on the inherited event_fd — {"type": "event", "event": {...}} for each
ansible-runner event, then a final {"type": "result", "status": ..., "rc": ...}.
SIGTERM is turned into a clean ansible-runner cancel by ansible-runner itself (it
installs the handler when running in the main thread).
"""

import json
import os
import sys

import ansible_runner


def main() -> None:
    job = json.load(sys.stdin)
    event_fd = job.pop("event_fd")
    # Not inherited by anything the playbook spawns, so it can't forge results.
    os.set_inheritable(event_fd, False)
    events = os.fdopen(event_fd, "w", encoding="utf-8")

    def emit(message: dict) -> None:
        events.write(json.dumps(message) + "\n")
        events.flush()

    # Must return None: ansible-runner writes its own unscrubbed job_events when the
    # handler returns truthy. Scrubbing happens in the parent, before anything is stored.
    def on_event(event: dict) -> None:
        emit({"type": "event", "event": event})

    runner = ansible_runner.run(event_handler=on_event, **job)
    emit({"type": "result", "status": runner.status, "rc": runner.rc})


if __name__ == "__main__":
    main()
    # Hard exit: on failure paths ansible-runner can leave a non-daemon thread behind,
    # and a normal interpreter shutdown would then wait on it forever. Every message
    # has already been flushed by emit().
    os._exit(0)
