import asyncio
import threading

from app.notify import Notifier
from app.routers.runs import _LogTail


def test_a_notification_from_another_thread_wakes_the_listener() -> None:
    notifier = Notifier()

    async def scenario() -> tuple[bool, bool]:
        with notifier.listen("run:1") as listener:
            threading.Timer(0.05, notifier.notify, args=("run:1",)).start()
            woken = await listener.wait(5)
            timed_out = not await listener.wait(0.05)  # consumed: the next wait times out
        return woken, timed_out

    assert asyncio.run(scenario()) == (True, True)
    assert notifier.topics() == set()  # nothing left behind once no one listens


def test_a_notification_while_busy_is_not_lost_and_topics_are_separate() -> None:
    notifier = Notifier()

    async def scenario() -> tuple[bool, bool]:
        with notifier.listen("run:1") as one, notifier.listen("run:2") as two:
            notifier.notify("run:1")  # before anyone waits
            notifier.notify("run:3")  # no listener: a no-op
            await asyncio.sleep(0)
            return await one.wait(1), await two.wait(0.05)

    assert asyncio.run(scenario()) == (True, False)
    assert notifier.topics() == set()


def test_notifying_a_listener_whose_loop_has_closed_is_harmless() -> None:
    notifier = Notifier()
    ready, release = threading.Event(), threading.Event()

    def stranded() -> None:
        async def listen() -> None:
            ctx = notifier.listen("run:1")
            ctx.__enter__()  # deliberately never exited: its loop closes underneath it
            ready.set()

        asyncio.run(listen())
        release.set()

    threading.Thread(target=stranded).start()
    assert ready.wait(5) and release.wait(5)
    notifier.notify("run:1")


def test_log_tail_returns_complete_lines_and_resumes(tmp_path) -> None:
    log = tmp_path / "1.jsonl"
    tail = _LogTail(log, skip_lines=1)
    assert tail.read() == []  # no log yet (a queued run)

    log.write_bytes(b'{"n": 1}\n\n{"n": 2}\n{"n": 3')
    assert tail.read() == ['{"n": 2}']  # the first is skipped, blanks ignored, the partial held
    assert tail.read() == []
    with log.open("ab") as f:
        f.write(b"}\n")
    assert tail.read() == ['{"n": 3}']
