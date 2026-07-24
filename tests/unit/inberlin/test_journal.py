"""run_journaled cancellation behavior (gemini round 10 HIGH).

Client disconnect cancels the request task. Under anyio's level-based
cancellation (starlette/uvicorn), EVERY await inside the cancelled scope
re-raises CancelledError — an inline `await capture.mark_uncertain()` in the
exception path would itself be cancelled before the DB write lands, leaving
the intent row pending. The tests emulate level cancellation by re-cancelling
the task at every checkpoint until it finishes.
"""

import asyncio
import sqlite3

import pytest

from powerdns_api_proxy.inberlin import journal
from powerdns_api_proxy.inberlin.journal import run_journaled


class StubCapture:
    """Duck-typed JournalCapture tracking the row state; every settle method
    has an await checkpoint before the state write, like the real to_thread
    store calls."""

    def __init__(self):
        self.row = None
        self.finalize_gate: asyncio.Event | None = None

    async def intent(self, rollback_of=None):
        self.row = "pending"

    async def mark_uncertain(self):
        await asyncio.sleep(0)
        if self.row in ("pending", "uncertain"):
            self.row = "uncertain"

    async def finalize(self, status_code):
        if self.finalize_gate is not None:
            await self.finalize_gate.wait()
        await asyncio.sleep(0)
        if self.row in ("pending", "uncertain"):
            self.row = "committed"


async def _cancel_until_done(task: asyncio.Task) -> None:
    """Level-cancellation emulation: cancel at every checkpoint."""
    while not task.done():
        task.cancel()
        await asyncio.sleep(0)


async def _drain_background():
    await journal.drain_settles()


def test_cancel_during_forward_settles_uncertain():
    async def main():
        capture = StubCapture()
        started = asyncio.Event()

        async def forward():
            started.set()
            await asyncio.Event().wait()  # blocks until cancelled

        task = asyncio.create_task(
            run_journaled(capture, asyncio.Lock(), forward, status_of=lambda r: 204)
        )
        await started.wait()
        await _cancel_until_done(task)
        with pytest.raises(asyncio.CancelledError):
            task.result()
        await _drain_background()
        # the mutation may have reached pdns: the row must never stay pending
        assert capture.row == "uncertain"

    asyncio.run(main())


def test_cancel_during_intent_settles_row():
    # hy3 round 11b: the intent INSERT runs in a threadpool and cannot be
    # cancelled — a client disconnect while awaiting it leaves the row written
    # but the request path gone. It must still settle.
    async def main():
        capture = StubCapture()
        intent_started = asyncio.Event()

        async def slow_intent(rollback_of=None):
            intent_started.set()
            await asyncio.sleep(0.01)  # emulates the uncancellable to_thread
            capture.row = "pending"

        capture.intent = slow_intent

        async def forward():
            return object()

        task = asyncio.create_task(
            run_journaled(capture, asyncio.Lock(), forward, status_of=lambda r: 204)
        )
        await intent_started.wait()
        await _cancel_until_done(task)
        with pytest.raises(asyncio.CancelledError):
            task.result()
        await _drain_background()
        assert capture.row == "uncertain"

    asyncio.run(main())


def test_finalize_error_settles_row():
    # hy3 round 11b: a finalize DB error (not a cancellation) must not
    # propagate leaving the row pending
    async def main():
        capture = StubCapture()

        async def boom(status_code):
            raise sqlite3.OperationalError("database is locked")

        capture.finalize = boom

        async def forward():
            return object()

        with pytest.raises(sqlite3.OperationalError):
            await run_journaled(
                capture, asyncio.Lock(), forward, status_of=lambda r: 204
            )
        await _drain_background()
        assert capture.row == "uncertain"

    asyncio.run(main())


def test_status_of_error_settles_row():
    # hy3 round 11b: status_of() raising after a successful forward left the
    # row pending — the mutation already reached pdns
    async def main():
        capture = StubCapture()

        def boom(resp):
            raise ValueError("no status")

        async def forward():
            return object()

        with pytest.raises(ValueError):
            await run_journaled(capture, asyncio.Lock(), forward, status_of=boom)
        await _drain_background()
        assert capture.row == "uncertain"

    asyncio.run(main())


def test_cancel_during_finalize_settles_row():
    async def main():
        capture = StubCapture()
        capture.finalize_gate = asyncio.Event()
        in_finalize = asyncio.Event()

        orig_finalize = capture.finalize

        async def finalize(status_code):
            in_finalize.set()
            await orig_finalize(status_code)

        capture.finalize = finalize

        async def forward():
            return object()

        task = asyncio.create_task(
            run_journaled(capture, asyncio.Lock(), forward, status_of=lambda r: 204)
        )
        await in_finalize.wait()
        capture.finalize_gate.set()
        await _cancel_until_done(task)
        with pytest.raises(asyncio.CancelledError):
            task.result()
        await _drain_background()
        # forward succeeded, then the client walked away mid-finalize: the row
        # must settle (uncertain via the background path, or committed if the
        # finalize write already landed) — never pending
        assert capture.row in ("uncertain", "committed")

    asyncio.run(main())
