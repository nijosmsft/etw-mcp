"""High-level wrapper around ``OpenTraceW``/``ProcessTrace``/``CloseTrace``.

Usage::

    from etw_analyzer.native.consumer import EtwConsumer

    def on_event(record):
        # record is an EVENT_RECORD ctypes pointer-dereferenced reference;
        # do not retain it past the callback — the buffer it points into
        # is reused by ETW on every call.
        ...

    with EtwConsumer([Path("trace.etl")], on_event) as cons:
        stats = cons.run()
        print(stats.event_count, stats.elapsed_seconds)

The consumer always sets ``PROCESS_TRACE_MODE_EVENT_RECORD`` (so we get
the modern ``EVENT_RECORD`` callback rather than the legacy ``EVENT_TRACE``
shape) and ``PROCESS_TRACE_MODE_RAW_TIMESTAMP`` (so timestamps remain in
QPC units rather than being converted to ``FILETIME`` — matching the
behaviour of every kernel-event timestamp join we want to do in Phase N2).

The class is a context manager: handles are released in ``__exit__`` even
if ``run()`` raises. ``run()`` itself is idempotent — calling it a second
time after the trace has finished raises ``NativeConsumerError``.
"""

from __future__ import annotations

import ctypes
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Optional

from .bindings.types import (
    EVENT_RECORD,
    EVENT_RECORD_CALLBACK,
    EVENT_TRACE_LOGFILEW,
)


class NativeConsumerError(RuntimeError):
    """Raised when the underlying ETW consumer APIs fail."""


@dataclass
class ConsumerStats:
    """Stats from a single :meth:`EtwConsumer.run` invocation."""

    event_count: int
    bytes_processed: int
    elapsed_seconds: float
    events_lost: int
    process_trace_rc: int


# Event callback signature exposed to callers. Receives a *dereferenced*
# EVENT_RECORD reference — i.e. ``record_ptr.contents`` — so handler code
# doesn't have to know about ctypes pointer mechanics. The pointer is
# stored on the consumer to keep a reference alive while ETW is calling
# the callback.
EventCallback = Callable[[EVENT_RECORD], None]


def _resolve_paths(etl_paths: Iterable[Path | str]) -> List[Path]:
    paths: List[Path] = []
    for p in etl_paths:
        path = Path(p)
        if not path.exists():
            raise NativeConsumerError(f"ETL file not found: {path}")
        if path.is_dir():
            raise NativeConsumerError(f"Expected a file, got directory: {path}")
        paths.append(path)
    if not paths:
        raise NativeConsumerError("At least one ETL path is required")
    return paths


class EtwConsumer:
    """Wraps an ``OpenTrace``/``ProcessTrace``/``CloseTrace`` cycle.

    Parameters
    ----------
    etl_paths:
        One or more ``.etl`` files. The feasibility experiments showed
        that ``ProcessTrace`` accepts multiple handles in a single call
        (one per file); we hold the door open for that by accepting a
        list, but currently always run the files sequentially through a
        single ``ProcessTrace`` invocation with a one-handle array. Phase
        N5 may revisit for ``compare_traces``.
    callback:
        A Python callable invoked once per event. Receives the *dereferenced*
        ``EVENT_RECORD`` reference (i.e. ``record_ptr.contents``). Must
        not retain the record beyond the callback's return — the buffer
        is reused. Callback exceptions are caught and surfaced via the
        ``last_exception`` attribute; they do not propagate into ETW
        (which would otherwise corrupt the trace iteration).
    raw_timestamp:
        Defaults to ``True`` so timestamps stay in raw QPC units, which
        is required for the stack/sample-event timestamp join described
        in §4 of the design doc. Set ``False`` only for diagnostics.
    """

    def __init__(
        self,
        etl_paths: Iterable[Path | str],
        callback: EventCallback,
        *,
        raw_timestamp: bool = True,
    ) -> None:
        # Bindings are imported lazily inside __init__ so that constructing
        # the class on a non-Windows host raises a clean OSError at the
        # right moment rather than blowing up at module import time.
        from .bindings import advapi32  # noqa: WPS433 (intentional local import)

        self._advapi32 = advapi32
        self._etl_paths: List[Path] = _resolve_paths(etl_paths)
        self._user_callback = callback
        self._raw_timestamp = raw_timestamp

        # Per-file ETW resources. Parallel lists keep handle / logfile
        # struct / wrapped callback alive for the duration of run().
        self._handles: List[int] = []
        self._logfiles: List[EVENT_TRACE_LOGFILEW] = []
        self._wrapped_callbacks: List[EVENT_RECORD_CALLBACK] = []

        # Exception capture from inside the callback. ETW calls our callback
        # via WINFUNCTYPE so raising would unwind through C code. We capture
        # the first exception and stop counting; ``run()`` re-raises it.
        self.last_exception: Optional[BaseException] = None

        # Event counter incremented by the callback wrapper. Lives on the
        # instance so the WINFUNCTYPE closure can bump it directly.
        self._event_count: int = 0

        # Whether run() has already been invoked. ProcessTrace cannot be
        # called twice on the same handle once the trace has been fully
        # consumed; we defend against that.
        self._has_run = False
        self._closed = False

        self._open()

    # -- context manager ------------------------------------------------
    def __enter__(self) -> "EtwConsumer":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # -- internal helpers ----------------------------------------------
    def _open(self) -> None:
        """Open every ETL file via ``OpenTraceW``.

        Failure on any file closes the partially-opened ones to avoid
        leaking trace handles, then raises ``NativeConsumerError``. The
        resulting state is consistent: either every file is open or none
        are.

        The callback we register here must survive until ``CloseTrace`` —
        ETW reads the function pointer from the ``EVENT_TRACE_LOGFILEW``
        struct each time it dispatches an event, so the WINFUNCTYPE
        wrapper, the closure it captures, and the struct itself all have
        to be kept alive on ``self``.
        """

        mode = self._advapi32.PROCESS_TRACE_MODE_EVENT_RECORD
        if self._raw_timestamp:
            mode |= self._advapi32.PROCESS_TRACE_MODE_RAW_TIMESTAMP

        for path in self._etl_paths:
            logfile = EVENT_TRACE_LOGFILEW()
            logfile.LogFileName = str(path)
            logfile.LoggerName = None
            logfile.ProcessTraceMode = mode

            # The wrapper captures ``self`` so it can bump the event
            # counter and route exceptions into ``last_exception``.
            consumer_ref = self
            user_cb = self._user_callback

            @EVENT_RECORD_CALLBACK
            def _cb(record_ptr, _self=consumer_ref, _user=user_cb):
                if _self.last_exception is not None:
                    return
                _self._event_count += 1
                try:
                    _user(record_ptr.contents)
                except BaseException as e:  # noqa: BLE001 — see comment
                    _self.last_exception = e

            # Keep the WINFUNCTYPE callback alive as long as ETW might
            # call it.
            self._wrapped_callbacks.append(_cb)
            logfile.EventCallback = ctypes.cast(_cb, ctypes.c_void_p).value

            handle = self._advapi32.OpenTraceW(ctypes.byref(logfile))
            if handle == self._advapi32.INVALID_PROCESSTRACE_HANDLE:
                err = ctypes.get_last_error()
                # Roll back any partially-opened handles.
                self._close_handles()
                raise NativeConsumerError(
                    f"OpenTraceW failed for {path}: GetLastError={err}"
                )

            self._handles.append(handle)
            self._logfiles.append(logfile)

    def _close_handles(self) -> None:
        """Close every open trace handle; safe to call multiple times."""

        if not self._handles:
            return
        for h in self._handles:
            try:
                self._advapi32.CloseTrace(h)
            except OSError:
                # CloseTrace returns an error code rather than raising;
                # this except is defensive against ctypes weirdness.
                pass
        self._handles.clear()
        self._logfiles.clear()
        # Drop callback refs only after handles are closed.
        self._wrapped_callbacks.clear()

    # -- public API ----------------------------------------------------
    def run(self) -> ConsumerStats:
        """Block until every ETL file has been fully processed.

        Returns
        -------
        ConsumerStats
            Aggregated stats across all handles. ``event_count`` counts
            callback invocations. ``bytes_processed`` sums each ETL's
            on-disk size — a reasonable proxy for "data analysed" that
            we can report against wall-clock time without consulting
            ``TRACE_LOGFILE_HEADER`` per file.
        """

        if self._closed:
            raise NativeConsumerError("Consumer is already closed")
        if self._has_run:
            raise NativeConsumerError("Consumer.run() can only be called once")
        if not self._handles:
            raise NativeConsumerError("Consumer has no open handles")

        self._has_run = True

        handle_array = (ctypes.c_ulonglong * len(self._handles))(*self._handles)

        start = time.perf_counter()
        rc = self._advapi32.ProcessTrace(
            handle_array, len(self._handles), None, None
        )
        elapsed = time.perf_counter() - start

        # Surface any exception captured inside the callback.
        if self.last_exception is not None:
            err = self.last_exception
            self.last_exception = None
            raise err

        bytes_processed = sum(p.stat().st_size for p in self._etl_paths)
        events_lost = sum(lf.LogfileHeader.EventsLost for lf in self._logfiles)

        return ConsumerStats(
            event_count=self._event_count,
            bytes_processed=bytes_processed,
            elapsed_seconds=elapsed,
            events_lost=events_lost,
            process_trace_rc=int(rc),
        )

    def close(self) -> None:
        """Release every trace handle. Safe to call more than once."""

        if self._closed:
            return
        self._close_handles()
        self._closed = True


def is_available(etl_path: Optional[Path | str] = None) -> bool:
    """Return ``True`` when the native consumer can be used on this host.

    Checks performed:
        * ``advapi32`` and ``tdh`` bindings import cleanly (Windows-only).
        * If ``etl_path`` is supplied, ``OpenTraceW`` succeeds against it
          and is immediately closed. This exercises the full handle path
          without spending time on ``ProcessTrace``.

    The result is intended for the ``mode="auto"`` resolution path in
    ``load_trace``. Failures are treated as "fall back to xperf" — we do
    not raise.
    """

    try:
        from .bindings import advapi32, tdh  # noqa: F401 (import for side-effect)
    except (ImportError, OSError):
        return False

    if etl_path is None:
        return True

    path = Path(etl_path)
    if not path.exists():
        return False

    # Smoke test: open + close. Use a no-op callback so we never need
    # ProcessTrace.
    def _noop(_rec):
        return

    try:
        # Note: we explicitly do *not* call run() — opening the trace
        # without consuming it is enough to know the runtime is healthy.
        cons = EtwConsumer([path], _noop)
    except (NativeConsumerError, OSError):
        return False
    cons.close()
    return True


__all__ = [
    "EtwConsumer",
    "ConsumerStats",
    "NativeConsumerError",
    "EventCallback",
    "is_available",
]
