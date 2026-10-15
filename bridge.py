"""Runs an asyncio loop on a background thread and delivers results back to
the Qt GUI thread safely (never touch widgets from the loop thread)."""
from __future__ import annotations

import asyncio
import threading
from typing import Any, Callable, Coroutine

from PySide6.QtCore import QObject, Signal, Slot


class AsyncBridge(QObject):
    _done = Signal(object, object, object)

    def __init__(self) -> None:
        super().__init__()
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, name="rea-asyncio", daemon=True)
        self._thread.start()
        self._done.connect(self._dispatch)

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def submit(self, coro: Coroutine, callback: Callable[[Any, BaseException | None], None] | None = None):
        """Run coro on the loop; callback(result, error) runs on the GUI thread."""
        fut = asyncio.run_coroutine_threadsafe(coro, self.loop)

        def finished(f):
            try:
                res, err = f.result(), None
            except BaseException as e:  # noqa: BLE001
                res, err = None, e
            if callback is not None:
                self._done.emit(callback, res, err)

        fut.add_done_callback(finished)
        return fut

    @Slot(object, object, object)
    def _dispatch(self, callback, result, error) -> None:
        callback(result, error)

    def run_sync(self, coro: Coroutine, timeout: float = 10.0):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def shutdown(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
