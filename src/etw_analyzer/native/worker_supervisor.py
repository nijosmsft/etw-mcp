"""Parent-side native worker supervision and cache promotion."""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from . import cache as native_cache
from . import telemetry as _telemetry
from .config import (
    DOTNET_SIDECAR_ENV,
    DOTNET_SIDECAR_EXE,
    find_dotnet_sidecar,
)


NATIVE_WORKER_ENV = "WPR_MCP_NATIVE_WORKER"
NATIVE_WORKER_SYMBOL_ENV = "WPR_MCP_NATIVE_WORKER_SYMBOL_PATH"
NATIVE_WORKER_TIMEOUT_ENV = "WPR_MCP_NATIVE_WORKER_TIMEOUT_SECONDS"
NATIVE_WORKER_STALE_ENV = "WPR_MCP_NATIVE_WORKER_STALE_SECONDS"
NATIVE_WORKER_MEMORY_MB_ENV = "WPR_MCP_NATIVE_WORKER_MEMORY_MB"
NATIVE_WORKER_DISABLE_JOB_ENV = "WPR_MCP_NATIVE_WORKER_DISABLE_JOB"
NATIVE_STREAMING_ENV = "WPR_MCP_NATIVE_STREAMING"
NATIVE_STREAMING_PROFILE_ENV = "WPR_MCP_NATIVE_STREAMING_PROFILE"

DEFAULT_TIMEOUT_SECONDS = 3600.0
DEFAULT_STALE_SECONDS = 120.0
DEFAULT_JOB_MEMORY_MB = 4096.0
STDERR_TAIL_BYTES = 16 * 1024
STDOUT_TAIL_BYTES = 16 * 1024
INVALID_STDOUT_TAIL_BYTES = 8 * 1024
MAX_PROGRESS_EVENTS = 100

STREAMING_PROFILE_SUMMARY = "summary"
STREAMING_PROFILE_ALL = "all"
STREAMING_PROFILE_VALUES = frozenset({STREAMING_PROFILE_SUMMARY, STREAMING_PROFILE_ALL})

STREAMING_SUMMARY_EVENT_CLASSES = frozenset({
    "SampledProfile",
    "PerfInfo/DPC",
    "PerfInfo/ThreadedDPC",
    "PerfInfo/TimerDPC",
    "PerfInfo/ISR",
})

STREAMING_DETAIL_EVENT_CLASSES = frozenset({
    "CSwitch",
    "ReadyThread",
})


@dataclass
class NativeWorkerResult:
    """Result returned by the native worker supervisor."""

    ok: bool
    message: str
    failure_kind: str | None = None
    returncode: int | None = None
    request_path: Path | None = None
    staging_dir: Path | None = None
    export_dir: Path | None = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    invalid_stdout_tail: str = ""
    progress: list[dict[str, Any]] = field(default_factory=list)
    result: dict[str, Any] | None = None
    job_isolated: bool = False
    job_memory_limit_bytes: int | None = None
    aggregation_warnings: list[str] = field(default_factory=list)


class NativeWorkerSupervisorError(RuntimeError):
    """Raised for parent-side worker setup and promotion failures."""


class JobObjectError(NativeWorkerSupervisorError):
    """Raised when Windows Job Object setup fails."""


class _BoundedTextTail:
    def __init__(self, max_bytes: int) -> None:
        self._max_bytes = max(1, int(max_bytes))
        self._chunks: deque[str] = deque()
        self._bytes = 0

    def append(self, text: str) -> None:
        if not text:
            return
        encoded = text.encode("utf-8", errors="replace")
        if len(encoded) > self._max_bytes:
            text = encoded[-self._max_bytes:].decode("utf-8", errors="replace")
            encoded = text.encode("utf-8", errors="replace")
        self._chunks.append(text)
        self._bytes += len(encoded)
        while self._bytes > self._max_bytes and self._chunks:
            dropped = self._chunks.popleft()
            self._bytes -= len(dropped.encode("utf-8", errors="replace"))

    def get(self) -> str:
        return "".join(self._chunks)


def native_worker_enabled() -> bool:
    """Return True when native extraction should run in a child process."""

    return os.environ.get(NATIVE_WORKER_ENV) == "1"


def native_streaming_enabled() -> bool:
    """Return True when the worker should write chunked native event-store data."""

    return os.environ.get(NATIVE_STREAMING_ENV) == "1"


def native_streaming_profile() -> str:
    """Return the requested streaming capture profile.

    ``summary`` intentionally skips high-volume detail streams such as CSwitch.
    Those datasets are useful for later drilldowns, but they can dominate CPU
    traces and prevent the initial large-file CPU/DPC/process path from
    completing in reasonable time.
    """

    raw = os.environ.get(NATIVE_STREAMING_PROFILE_ENV, STREAMING_PROFILE_SUMMARY)
    profile = raw.strip().lower()
    if profile not in STREAMING_PROFILE_VALUES:
        raise ValueError(
            f"{NATIVE_STREAMING_PROFILE_ENV} must be one of "
            f"{sorted(STREAMING_PROFILE_VALUES)}, got {raw!r}."
        )
    return profile


def select_streaming_event_classes(
    requested_event_classes: Iterable[str],
) -> list[str]:
    """Apply the streaming profile to the worker event-class request."""

    requested = list(dict.fromkeys(requested_event_classes))
    if not native_streaming_enabled():
        return requested
    if native_streaming_profile() == STREAMING_PROFILE_ALL:
        return list(dict.fromkeys([
            *requested,
            *sorted(STREAMING_DETAIL_EVENT_CLASSES),
        ]))
    return sorted(STREAMING_SUMMARY_EVENT_CLASSES)


def build_worker_command(request_path: Path) -> list[str]:
    """Build the worker command line without embedding sensitive values."""

    return [
        sys.executable,
        "-m",
        "etw_analyzer.native.worker",
        "--request",
        str(request_path),
    ]


def build_worker_request(
    *,
    etl_path: Path,
    export_dir: Path,
    staging_dir: Path,
    trace_id: str,
    requested_event_classes: Iterable[str],
    symbol_path_env_key: str | None = NATIVE_WORKER_SYMBOL_ENV,
) -> dict[str, Any]:
    """Return the JSON request consumed by ``native.worker``."""

    strategy = (
        native_cache.STREAMING_EVENT_STORE_STRATEGY
        if native_streaming_enabled()
        else native_cache.MATERIALIZED_SMALL_STRATEGY
    )
    selected_event_classes = select_streaming_event_classes(requested_event_classes)
    return {
        "etl_path": str(etl_path.resolve()),
        "export_dir": str(export_dir.resolve()),
        "staging_dir": str(staging_dir.resolve()),
        "trace_id": trace_id,
        "mode": "native",
        "strategy": strategy,
        "schema_version": native_cache.SCHEMA_VERSION,
        "symbol_path_env_key": symbol_path_env_key,
        "streaming_profile": (
            native_streaming_profile() if strategy == native_cache.STREAMING_EVENT_STORE_STRATEGY else None
        ),
        "requested_event_classes": selected_event_classes,
    }


def run_native_worker_extraction(
    *,
    etl_path: Path,
    export_dir: Path,
    trace_id: str,
    symbol_path: str | None,
    requested_event_classes: Iterable[str],
    timeout_seconds: float | None = None,
    stale_heartbeat_seconds: float | None = None,
    process_runner: Callable[..., NativeWorkerResult] | None = None,
) -> NativeWorkerResult:
    """Run the native worker into staging, validate, then promote to final cache."""

    etl_path = etl_path.resolve()
    export_dir = export_dir.resolve()
    staging_dir = export_dir.parent / (
        f"{export_dir.name}.worker-{trace_id}-{uuid.uuid4().hex}"
    )
    request_path = staging_dir / "request.json"
    runner = process_runner or run_worker_process

    try:
        if staging_dir.exists():
            shutil.rmtree(staging_dir)
        staging_dir.mkdir(parents=True)
        request = build_worker_request(
            etl_path=etl_path,
            export_dir=export_dir,
            staging_dir=staging_dir,
            trace_id=trace_id,
            requested_event_classes=requested_event_classes,
            symbol_path_env_key=NATIVE_WORKER_SYMBOL_ENV if symbol_path else None,
        )
        request_path.write_text(
            json.dumps(request, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        result = runner(
            request_path,
            symbol_path=symbol_path,
            timeout_seconds=timeout_seconds,
            stale_heartbeat_seconds=stale_heartbeat_seconds,
        )
        result.request_path = request_path
        result.staging_dir = staging_dir
        if not result.ok:
            _remove_dir(staging_dir)
            return result

        try:
            manifest = native_cache.read_manifest(staging_dir)
            if manifest is None:
                raise native_cache.NativeCacheError(
                    "native worker did not write a v2 cache manifest"
                )
            native_cache.validate_manifest(
                manifest,
                staging_dir,
                etl_path,
                mode="native",
            )
            payload = result.result or {}
            payload_trace_id = payload.get("trace_id")
            if payload_trace_id and payload_trace_id != trace_id:
                raise native_cache.NativeCacheError(
                    "native worker result trace_id does not match request"
                )
        except Exception as exc:
            _remove_dir(staging_dir)
            return NativeWorkerResult(
                ok=False,
                message=f"native worker produced an invalid cache: {exc}",
                failure_kind="invalid-cache",
                request_path=request_path,
                staging_dir=staging_dir,
                stdout_tail=result.stdout_tail,
                stderr_tail=result.stderr_tail,
                invalid_stdout_tail=result.invalid_stdout_tail,
                progress=result.progress,
                result=result.result,
                job_isolated=result.job_isolated,
                job_memory_limit_bytes=result.job_memory_limit_bytes,
            )

        try:
            _promote_staging_cache(staging_dir, export_dir)
        except Exception as exc:
            _remove_dir(staging_dir)
            return NativeWorkerResult(
                ok=False,
                message=f"native worker cache promotion failed: {exc}",
                failure_kind="promotion",
                request_path=request_path,
                staging_dir=staging_dir,
                stdout_tail=result.stdout_tail,
                stderr_tail=result.stderr_tail,
                invalid_stdout_tail=result.invalid_stdout_tail,
                progress=result.progress,
                result=result.result,
                job_isolated=result.job_isolated,
                job_memory_limit_bytes=result.job_memory_limit_bytes,
            )

        result.export_dir = export_dir
        result.staging_dir = staging_dir
        return result
    except Exception as exc:
        _remove_dir(staging_dir)
        return NativeWorkerResult(
            ok=False,
            message=str(exc),
            failure_kind="supervisor",
            request_path=request_path,
            staging_dir=staging_dir,
        )


def run_worker_process(
    request_path: Path,
    *,
    symbol_path: str | None,
    timeout_seconds: float | None = None,
    stale_heartbeat_seconds: float | None = None,
    popen_factory: Callable[..., subprocess.Popen] = subprocess.Popen,
    enforce_job: bool = True,
) -> NativeWorkerResult:
    """Launch and supervise the native worker subprocess."""

    timeout = _float_env(
        NATIVE_WORKER_TIMEOUT_ENV,
        timeout_seconds,
        DEFAULT_TIMEOUT_SECONDS,
    )
    stale = _float_env(
        NATIVE_WORKER_STALE_ENV,
        stale_heartbeat_seconds,
        DEFAULT_STALE_SECONDS,
    )
    command = build_worker_command(request_path)
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    if symbol_path:
        env[NATIVE_WORKER_SYMBOL_ENV] = symbol_path

    stdout_tail = _BoundedTextTail(STDOUT_TAIL_BYTES)
    stderr_tail = _BoundedTextTail(STDERR_TAIL_BYTES)
    invalid_tail = _BoundedTextTail(INVALID_STDOUT_TAIL_BYTES)
    progress: deque[dict[str, Any]] = deque(maxlen=MAX_PROGRESS_EVENTS)
    events: "queue.Queue[tuple[str, str]]" = queue.Queue()
    result_payload: dict[str, Any] | None = None
    last_heartbeat = time.monotonic()
    job: _WindowsJob | None = None

    try:
        proc = popen_factory(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            shell=False,
        )
    except Exception as exc:
        return NativeWorkerResult(
            ok=False,
            message=f"failed to launch native worker: {exc}",
            failure_kind="launch",
            request_path=request_path,
        )

    try:
        if _should_use_windows_job(enforce_job):
            try:
                job = _assign_windows_job(proc, _job_memory_limit_bytes())
            except Exception as exc:
                _terminate_process(proc)
                return NativeWorkerResult(
                    ok=False,
                    message=f"native worker isolation setup failed: {exc}",
                    failure_kind="isolation",
                    returncode=_safe_returncode(proc),
                    request_path=request_path,
                )

        stdout_thread = threading.Thread(
            target=_reader_thread,
            args=("stdout", proc.stdout, events),
            daemon=True,
            name="native-worker-stdout",
        )
        stderr_thread = threading.Thread(
            target=_reader_thread,
            args=("stderr", proc.stderr, events),
            daemon=True,
            name="native-worker-stderr",
        )
        stdout_thread.start()
        stderr_thread.start()

        start = time.monotonic()
        failure_kind: str | None = None
        failure_message: str | None = None

        while True:
            while True:
                try:
                    stream_name, line = events.get_nowait()
                except queue.Empty:
                    break
                if stream_name == "stdout":
                    parsed, heartbeat = _handle_stdout_line(
                        line,
                        stdout_tail,
                        invalid_tail,
                        progress,
                    )
                    if parsed is not None and parsed.get("type") == "result":
                        result_payload = parsed
                    if heartbeat:
                        last_heartbeat = time.monotonic()
                elif stream_name == "stderr":
                    stderr_tail.append(line)

            returncode = proc.poll()
            now = time.monotonic()
            if returncode is not None:
                break
            if now - start > timeout:
                failure_kind = "timeout"
                failure_message = (
                    f"native worker exceeded wall-clock timeout of {timeout:.1f}s"
                )
                _terminate_process(proc)
                break
            if now - last_heartbeat > stale:
                failure_kind = "stale-heartbeat"
                failure_message = (
                    f"native worker produced no heartbeat for {stale:.1f}s"
                )
                _terminate_process(proc)
                break
            time.sleep(0.05)

        stdout_thread.join(timeout=1.0)
        stderr_thread.join(timeout=1.0)
        while True:
            try:
                stream_name, line = events.get_nowait()
            except queue.Empty:
                break
            if stream_name == "stdout":
                parsed, heartbeat = _handle_stdout_line(
                    line,
                    stdout_tail,
                    invalid_tail,
                    progress,
                )
                if parsed is not None and parsed.get("type") == "result":
                    result_payload = parsed
                if heartbeat:
                    last_heartbeat = time.monotonic()
            elif stream_name == "stderr":
                stderr_tail.append(line)

        returncode = _safe_returncode(proc)
        common = {
            "returncode": returncode,
            "request_path": request_path,
            "stdout_tail": stdout_tail.get(),
            "stderr_tail": stderr_tail.get(),
            "invalid_stdout_tail": invalid_tail.get(),
            "progress": list(progress),
            "result": result_payload,
            "job_isolated": job is not None,
            "job_memory_limit_bytes": job.memory_limit_bytes if job else None,
        }
        if failure_kind is not None:
            return NativeWorkerResult(
                ok=False,
                message=failure_message or failure_kind,
                failure_kind=failure_kind,
                **common,
            )
        if result_payload and result_payload.get("ok") is True and returncode == 0:
            return NativeWorkerResult(
                ok=True,
                message=str(result_payload.get("message") or "native worker completed"),
                **common,
            )
        if result_payload and result_payload.get("ok") is False:
            return NativeWorkerResult(
                ok=False,
                message=str(result_payload.get("error") or "native worker failed"),
                failure_kind="worker-error",
                **common,
            )
        return NativeWorkerResult(
            ok=False,
            message=(
                f"native worker exited with code {returncode} without a "
                "successful result record"
            ),
            failure_kind="crash",
            **common,
        )
    finally:
        if job is not None:
            job.close()


def _reader_thread(
    stream_name: str,
    stream,
    events: "queue.Queue[tuple[str, str]]",
) -> None:
    if stream is None:
        return
    try:
        for line in stream:
            events.put((stream_name, line))
    except Exception as exc:
        events.put((stream_name, f"[reader error: {exc}]\n"))


def _handle_stdout_line(
    line: str,
    stdout_tail: _BoundedTextTail,
    invalid_tail: _BoundedTextTail,
    progress: deque[dict[str, Any]],
) -> tuple[dict[str, Any] | None, bool]:
    stdout_tail.append(line)
    stripped = line.strip()
    if not stripped:
        return None, False
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        invalid_tail.append(line)
        return None, False
    if not isinstance(parsed, dict):
        invalid_tail.append(line)
        return None, False
    progress.append(parsed)
    return parsed, parsed.get("type") in {"heartbeat", "progress", "result"}


def _float_env(name: str, value: float | None, default: float) -> float:
    raw = os.environ.get(name)
    chosen: float
    if raw is not None and raw.strip():
        try:
            chosen = float(raw)
        except ValueError as exc:
            raise NativeWorkerSupervisorError(
                f"{name} must be a positive number, got {raw!r}"
            ) from exc
    elif value is not None:
        chosen = float(value)
    else:
        chosen = default
    if chosen <= 0:
        raise NativeWorkerSupervisorError(
            f"{name} must be a positive number, got {chosen!r}"
        )
    return chosen


def _job_memory_limit_bytes() -> int | None:
    raw = os.environ.get(NATIVE_WORKER_MEMORY_MB_ENV)
    if raw is None or raw.strip() == "":
        mb = DEFAULT_JOB_MEMORY_MB
    else:
        try:
            mb = float(raw)
        except ValueError as exc:
            raise JobObjectError(
                f"{NATIVE_WORKER_MEMORY_MB_ENV} must be a non-negative number of MB, "
                f"got {raw!r}"
            ) from exc
    if mb < 0:
        raise JobObjectError(
            f"{NATIVE_WORKER_MEMORY_MB_ENV} must be a non-negative number of MB, "
            f"got {raw!r}"
        )
    if mb == 0:
        # Explicit opt-out for test hosts that run inside restrictive jobs.
        return None
    return int(mb * 1024 * 1024)


def _should_use_windows_job(enforce_job: bool) -> bool:
    return (
        enforce_job
        and os.name == "nt"
        and os.environ.get(NATIVE_WORKER_DISABLE_JOB_ENV) != "1"
    )


@dataclass
class _WindowsJob:
    handle: int
    memory_limit_bytes: int | None

    def close(self) -> None:
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle(self.handle)


def _assign_windows_job(proc: subprocess.Popen, memory_limit_bytes: int | None) -> _WindowsJob:
    """Assign the child to a Windows Job Object with kill-on-close.

    The memory limit is a process-memory cap when ``memory_limit_bytes`` is not
    None. Set ``WPR_MCP_NATIVE_WORKER_MEMORY_MB=0`` to test only the lifecycle
    wrapper; do not interpret that mode as memory isolation.
    """

    import ctypes
    from ctypes import wintypes

    JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JobObjectExtendedLimitInformation = 9
    SIZE_T = ctypes.c_size_t

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", SIZE_T),
            ("MaximumWorkingSetSize", SIZE_T),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", SIZE_T),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", SIZE_T),
            ("JobMemoryLimit", SIZE_T),
            ("PeakProcessMemoryUsed", SIZE_T),
            ("PeakJobMemoryUsed", SIZE_T),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise JobObjectError(f"CreateJobObjectW failed: {ctypes.get_last_error()}")

    assigned = False
    try:
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if memory_limit_bytes is not None:
            flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY
            info.ProcessMemoryLimit = int(memory_limit_bytes)
        info.BasicLimitInformation.LimitFlags = flags
        ok = kernel32.SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not ok:
            raise JobObjectError(
                f"SetInformationJobObject failed: {ctypes.get_last_error()}"
            )
        process_handle = getattr(proc, "_handle", None)
        if process_handle is None:
            raise JobObjectError("subprocess handle is unavailable")
        ok = kernel32.AssignProcessToJobObject(
            job,
            wintypes.HANDLE(int(process_handle)),
        )
        if not ok:
            raise JobObjectError(
                f"AssignProcessToJobObject failed: {ctypes.get_last_error()}"
            )
        assigned = True
        return _WindowsJob(handle=int(job), memory_limit_bytes=memory_limit_bytes)
    finally:
        if not assigned:
            kernel32.CloseHandle(job)


def _terminate_process(proc: subprocess.Popen, grace_seconds: float = 5.0) -> None:
    try:
        if proc.poll() is None:
            proc.terminate()
    except Exception:
        pass
    try:
        proc.wait(timeout=grace_seconds)
        return
    except Exception:
        pass
    try:
        if proc.poll() is None:
            proc.kill()
    except Exception:
        pass
    try:
        proc.wait(timeout=grace_seconds)
    except Exception:
        pass


def _safe_returncode(proc: subprocess.Popen) -> int | None:
    try:
        return proc.poll()
    except Exception:
        return getattr(proc, "returncode", None)


def _promote_staging_cache(staging_dir: Path, export_dir: Path) -> None:
    backup_dir: Path | None = None
    if export_dir.exists():
        backup_dir = export_dir.parent / (
            f"{export_dir.name}.worker-backup-{uuid.uuid4().hex}"
        )
        export_dir.rename(backup_dir)
    try:
        staging_dir.rename(export_dir)
    except Exception:
        if backup_dir is not None and backup_dir.exists() and not export_dir.exists():
            backup_dir.rename(export_dir)
        raise
    if backup_dir is not None:
        _remove_dir(backup_dir)


def _remove_dir(path: Path) -> None:
    try:
        if path.exists():
            shutil.rmtree(path)
    except Exception:
        pass


__all__ = [
    "DOTNET_REQUEST_VERSION",
    "NATIVE_WORKER_ENV",
    "NATIVE_WORKER_SYMBOL_ENV",
    "NativeWorkerResult",
    "build_dotnet_request",
    "build_worker_command",
    "build_worker_request",
    "native_worker_enabled",
    "run_dotnet_worker_extraction",
    "run_native_worker_extraction",
    "run_worker_process",
]


# ---------------------------------------------------------------------------
# .NET sidecar invocation — Track B of the hybrid migration. The protocol is
# spike-contract.md v1: one --request <path> argument, stdout reserved for
# JSONL ({heartbeat,progress,result}), exit code 0 for success / 1 for
# structured failure / 2 for crash. We REUSE the existing _reader_thread,
# _handle_stdout_line, _BoundedTextTail, and _terminate_process helpers so
# the protocol implementation lives in one place.
# ---------------------------------------------------------------------------

DOTNET_REQUEST_VERSION = 1
DEFAULT_DOTNET_HEARTBEAT_INTERVAL_MS = 1000
DEFAULT_DOTNET_MAX_ETL_MB = 8192  # generous default; agent overrides per-call.


def build_dotnet_request(
    *,
    trace_id: str,
    etl_path: Path,
    staging_dir: Path,
    requested_event_classes: Iterable[str],
    strategy: str = native_cache.MATERIALIZED_SMALL_STRATEGY,
    symbol_path: str | None = None,
    max_etl_mb: int = DEFAULT_DOTNET_MAX_ETL_MB,
    heartbeat_interval_ms: int = DEFAULT_DOTNET_HEARTBEAT_INTERVAL_MS,
    log_level: str = "info",
    include_tracelogging: bool = True,
) -> dict[str, Any]:
    """Build the request JSON consumed by ``wpr-mcp-extract.exe``.

    Matches the schema in ``dotnet/src/Request.cs`` exactly. The version
    field is locked to 1 per ``spike-contract.md`` §3.1.
    """

    payload: dict[str, Any] = {
        "version": DOTNET_REQUEST_VERSION,
        "trace_id": trace_id,
        "etl_path": str(etl_path.resolve()),
        "staging_dir": str(staging_dir.resolve()),
        "strategy": strategy,
        "requested_event_classes": list(dict.fromkeys(requested_event_classes)),
        "symbol_path": symbol_path,
        "max_etl_mb": int(max_etl_mb),
        "heartbeat_interval_ms": int(heartbeat_interval_ms),
        "log_level": log_level,
        "include_tracelogging": bool(include_tracelogging),
    }
    return payload


def build_dotnet_command(sidecar_path: Path, request_path: Path) -> list[str]:
    """Build the sidecar command line. Only ``--request <path>`` is required."""

    return [str(sidecar_path), "--request", str(request_path)]


def run_dotnet_worker_extraction(
    *,
    etl_path: Path,
    export_dir: Path,
    trace_id: str,
    symbol_path: str | None,
    requested_event_classes: Iterable[str],
    strategy: str = native_cache.MATERIALIZED_SMALL_STRATEGY,
    sidecar_path: Path | None = None,
    timeout_seconds: float | None = None,
    stale_heartbeat_seconds: float | None = None,
    process_runner: Callable[..., NativeWorkerResult] | None = None,
    aggregation_runner: Callable[..., Any] | None = None,
) -> NativeWorkerResult:
    """Run the .NET sidecar into staging, run aggregators, then promote.

    Pipeline:

    1. Locate the sidecar binary via :func:`find_dotnet_sidecar` (or use
       the caller-supplied ``sidecar_path``).
    2. Write a ``request.json`` matching the spike-contract schema.
    3. Spawn ``wpr-mcp-extract.exe --request <path>``; stream stdout
       line-by-line through the same JSONL handler used for the native
       worker (heartbeat/progress/result).
    4. Validate the sidecar's manifest in staging.
    5. Run :func:`aggregation_worker.run_aggregation_worker` to produce
       the Python-side aggregates.
    6. Atomic promote ``staging_dir`` → ``export_dir``.

    On any failure: log to stderr, leave staging intact for debugging,
    return ``ok=False`` with a structured ``failure_kind``.
    """

    resolved_sidecar = sidecar_path or find_dotnet_sidecar()
    if resolved_sidecar is None:
        raise ValueError(
            f".NET sidecar binary {DOTNET_SIDECAR_EXE} could not be located. "
            f"Set {DOTNET_SIDECAR_ENV} to the absolute path of the built "
            "binary, publish it under dotnet/publish/win-x64/, or add it "
            "to PATH."
        )
    if not resolved_sidecar.is_file():
        raise ValueError(
            f".NET sidecar path {resolved_sidecar} is not a file. "
            f"Check {DOTNET_SIDECAR_ENV}."
        )

    etl_path = etl_path.resolve()
    export_dir = export_dir.resolve()
    staging_dir = export_dir.parent / (
        f"{export_dir.name}.dotnet-{trace_id}-{uuid.uuid4().hex}"
    )
    request_path = staging_dir / "request.json"
    runner = process_runner or run_dotnet_process

    try:
        if staging_dir.exists():
            shutil.rmtree(staging_dir)
        staging_dir.mkdir(parents=True)
        request = build_dotnet_request(
            trace_id=trace_id,
            etl_path=etl_path,
            staging_dir=staging_dir,
            requested_event_classes=requested_event_classes,
            strategy=strategy,
            symbol_path=symbol_path,
        )
        request_path.write_text(
            json.dumps(request, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        _telemetry.emit_with(
            _telemetry.EVENT_DOTNET_SPAWN,
            mode="dotnet",
            trace_id=trace_id,
            sidecar_path=resolved_sidecar,
            staging_dir=staging_dir,
            strategy=strategy,
            event_classes=len(request.get("requested_event_classes", [])),
        )
        _dotnet_spawn_monotonic = time.monotonic()

        sidecar_result = runner(
            resolved_sidecar,
            request_path,
            timeout_seconds=timeout_seconds,
            stale_heartbeat_seconds=stale_heartbeat_seconds,
        )
        sidecar_result.request_path = request_path
        sidecar_result.staging_dir = staging_dir

        _dotnet_wall_s = time.monotonic() - _dotnet_spawn_monotonic
        _result_payload = sidecar_result.result or {}
        _perf = _result_payload.get("performance") or {}
        _telemetry.emit_with(
            _telemetry.EVENT_DOTNET_CHILD_EXIT,
            mode="dotnet",
            trace_id=trace_id,
            ok=sidecar_result.ok,
            returncode=sidecar_result.returncode,
            failure_kind=sidecar_result.failure_kind,
            wall_seconds=_dotnet_wall_s,
        )
        if sidecar_result.ok and _perf:
            _telemetry.emit_with(
                _telemetry.EVENT_DOTNET_RESULT,
                mode="dotnet",
                trace_id=trace_id,
                sidecar_wall_seconds=_perf.get("wall_seconds"),
                events_per_second=_perf.get("events_per_second"),
                peak_rss_mb=_perf.get("peak_rss_mb"),
                event_classes=len((_result_payload.get("event_counts") or {})),
            )
        if not sidecar_result.ok:
            # Leave staging intact for debugging — same contract as
            # rust-hybrid-migration-plan v3 §11 phase 0.
            return sidecar_result

        # Validate the sidecar manifest before running aggregators.
        try:
            manifest = native_cache.read_manifest(staging_dir)
            if manifest is None:
                raise native_cache.NativeCacheError(
                    "dotnet sidecar did not write a cache manifest"
                )
            native_cache.validate_manifest(
                manifest,
                staging_dir,
                etl_path,
                mode="native",
            )
        except Exception as exc:
            _telemetry.emit_with(
                _telemetry.EVENT_DOTNET_CACHE_VALIDATE,
                mode="dotnet",
                trace_id=trace_id,
                ok=False,
                error=str(exc),
            )
            return NativeWorkerResult(
                ok=False,
                message=f"dotnet sidecar produced an invalid cache: {exc}",
                failure_kind="invalid-cache",
                request_path=request_path,
                staging_dir=staging_dir,
                stdout_tail=sidecar_result.stdout_tail,
                stderr_tail=sidecar_result.stderr_tail,
                invalid_stdout_tail=sidecar_result.invalid_stdout_tail,
                progress=sidecar_result.progress,
                result=sidecar_result.result,
            )
        _telemetry.emit_with(
            _telemetry.EVENT_DOTNET_CACHE_VALIDATE,
            mode="dotnet",
            trace_id=trace_id,
            ok=True,
            datasets=len(manifest.datasets),
            schema_version=manifest.schema_version,
            producer=manifest.producer,
        )

        # Run the Python-side aggregators against the sidecar's outputs.
        agg_run = aggregation_runner or _default_aggregation_runner
        _telemetry.emit_with(
            _telemetry.EVENT_DOTNET_AGGREGATION_START,
            mode="dotnet",
            trace_id=trace_id,
            staging_dir=staging_dir,
        )
        _agg_start_monotonic = time.monotonic()
        try:
            agg_result = agg_run(staging_dir, etl_path, trace_id)
        except Exception as exc:
            _telemetry.emit_with(
                _telemetry.EVENT_DOTNET_AGGREGATION_DONE,
                mode="dotnet",
                trace_id=trace_id,
                ok=False,
                error=str(exc),
                wall_seconds=time.monotonic() - _agg_start_monotonic,
            )
            return NativeWorkerResult(
                ok=False,
                message=f"aggregation worker raised: {exc}",
                failure_kind="aggregation",
                request_path=request_path,
                staging_dir=staging_dir,
                stdout_tail=sidecar_result.stdout_tail,
                stderr_tail=sidecar_result.stderr_tail,
                invalid_stdout_tail=sidecar_result.invalid_stdout_tail,
                progress=sidecar_result.progress,
                result=sidecar_result.result,
            )
        if not agg_result.ok:
            _telemetry.emit_with(
                _telemetry.EVENT_DOTNET_AGGREGATION_DONE,
                mode="dotnet",
                trace_id=trace_id,
                ok=False,
                error=agg_result.message,
                wall_seconds=time.monotonic() - _agg_start_monotonic,
            )
            return NativeWorkerResult(
                ok=False,
                message=f"aggregation worker failed: {agg_result.message}",
                failure_kind="aggregation",
                request_path=request_path,
                staging_dir=staging_dir,
                stdout_tail=sidecar_result.stdout_tail,
                stderr_tail=sidecar_result.stderr_tail,
                invalid_stdout_tail=sidecar_result.invalid_stdout_tail,
                progress=sidecar_result.progress,
                result=sidecar_result.result,
            )
        _telemetry.emit_with(
            _telemetry.EVENT_DOTNET_AGGREGATION_DONE,
            mode="dotnet",
            trace_id=trace_id,
            ok=True,
            datasets_written=len(agg_result.datasets_written),
            warnings=len(agg_result.warnings),
            wall_seconds=time.monotonic() - _agg_start_monotonic,
        )

        try:
            _promote_staging_cache(staging_dir, export_dir)
        except Exception as exc:
            _telemetry.emit_with(
                _telemetry.EVENT_DOTNET_CACHE_PROMOTE,
                mode="dotnet",
                trace_id=trace_id,
                ok=False,
                error=str(exc),
            )
            return NativeWorkerResult(
                ok=False,
                message=f"dotnet cache promotion failed: {exc}",
                failure_kind="promotion",
                request_path=request_path,
                staging_dir=staging_dir,
                stdout_tail=sidecar_result.stdout_tail,
                stderr_tail=sidecar_result.stderr_tail,
                invalid_stdout_tail=sidecar_result.invalid_stdout_tail,
                progress=sidecar_result.progress,
                result=sidecar_result.result,
            )

        sidecar_result.export_dir = export_dir
        sidecar_result.message = (
            f"dotnet sidecar completed: {agg_result.message}"
        )
        if agg_result.warnings:
            sidecar_result.aggregation_warnings = list(agg_result.warnings)
        _telemetry.emit_with(
            _telemetry.EVENT_DOTNET_CACHE_PROMOTE,
            mode="dotnet",
            trace_id=trace_id,
            ok=True,
            export_dir=export_dir,
        )
        return sidecar_result
    except KeyboardInterrupt:
        # The sidecar may still be running; terminate it before propagating.
        # The reader threads are daemons so they will be torn down with the
        # interpreter.
        # Staging dir is preserved for forensic inspection.
        raise
    except Exception as exc:
        return NativeWorkerResult(
            ok=False,
            message=str(exc),
            failure_kind="supervisor",
            request_path=request_path,
            staging_dir=staging_dir,
        )


def _default_aggregation_runner(
    staging_dir: Path,
    etl_path: Path,
    trace_id: str,
):
    """Lazy import wrapper — avoid pulling in aggregation_worker at import time."""

    from . import aggregation_worker

    return aggregation_worker.run_aggregation_worker(
        staging_dir,
        etl_path,
        trace_id,
        producer="dotnet",
    )


def run_dotnet_process(
    sidecar_path: Path,
    request_path: Path,
    *,
    timeout_seconds: float | None = None,
    stale_heartbeat_seconds: float | None = None,
    popen_factory: Callable[..., subprocess.Popen] = subprocess.Popen,
) -> NativeWorkerResult:
    """Launch and supervise the .NET sidecar subprocess.

    Reuses the same heartbeat-watchdog + bounded-tail logic as
    :func:`run_worker_process`. The .NET protocol is byte-compatible: each
    stdout line is a JSON object with ``type`` in
    ``{heartbeat, progress, result}``; the ``result`` line is the source
    of truth for ok/failure.
    """

    timeout = _float_env(
        NATIVE_WORKER_TIMEOUT_ENV,
        timeout_seconds,
        DEFAULT_TIMEOUT_SECONDS,
    )
    stale = _float_env(
        NATIVE_WORKER_STALE_ENV,
        stale_heartbeat_seconds,
        DEFAULT_STALE_SECONDS,
    )
    command = build_dotnet_command(sidecar_path, request_path)
    env = os.environ.copy()
    # The sidecar reads its own env for log routing; nothing else needed.

    stdout_tail = _BoundedTextTail(STDOUT_TAIL_BYTES)
    stderr_tail = _BoundedTextTail(STDERR_TAIL_BYTES)
    invalid_tail = _BoundedTextTail(INVALID_STDOUT_TAIL_BYTES)
    progress: deque[dict[str, Any]] = deque(maxlen=MAX_PROGRESS_EVENTS)
    events: "queue.Queue[tuple[str, str]]" = queue.Queue()
    result_payload: dict[str, Any] | None = None
    last_heartbeat = time.monotonic()

    try:
        proc = popen_factory(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            shell=False,
        )
    except Exception as exc:
        return NativeWorkerResult(
            ok=False,
            message=f"failed to launch dotnet sidecar: {exc}",
            failure_kind="launch",
            request_path=request_path,
        )

    stdout_thread = threading.Thread(
        target=_reader_thread,
        args=("stdout", proc.stdout, events),
        daemon=True,
        name="dotnet-sidecar-stdout",
    )
    stderr_thread = threading.Thread(
        target=_reader_thread,
        args=("stderr", proc.stderr, events),
        daemon=True,
        name="dotnet-sidecar-stderr",
    )
    stdout_thread.start()
    stderr_thread.start()

    start = time.monotonic()
    failure_kind: str | None = None
    failure_message: str | None = None

    try:
        while True:
            while True:
                try:
                    stream_name, line = events.get_nowait()
                except queue.Empty:
                    break
                if stream_name == "stdout":
                    parsed, heartbeat = _handle_stdout_line(
                        line,
                        stdout_tail,
                        invalid_tail,
                        progress,
                    )
                    if parsed is not None and parsed.get("type") == "result":
                        result_payload = parsed
                    if heartbeat:
                        last_heartbeat = time.monotonic()
                elif stream_name == "stderr":
                    stderr_tail.append(line)

            returncode = proc.poll()
            now = time.monotonic()
            if returncode is not None:
                break
            if now - start > timeout:
                failure_kind = "timeout"
                failure_message = (
                    f"dotnet sidecar exceeded wall-clock timeout of {timeout:.1f}s"
                )
                _terminate_process(proc)
                break
            if now - last_heartbeat > stale:
                failure_kind = "stale-heartbeat"
                failure_message = (
                    f"dotnet sidecar produced no heartbeat for {stale:.1f}s"
                )
                _terminate_process(proc)
                break
            time.sleep(0.05)
    except KeyboardInterrupt:
        _terminate_process(proc)
        raise

    stdout_thread.join(timeout=1.0)
    stderr_thread.join(timeout=1.0)
    while True:
        try:
            stream_name, line = events.get_nowait()
        except queue.Empty:
            break
        if stream_name == "stdout":
            parsed, heartbeat = _handle_stdout_line(
                line,
                stdout_tail,
                invalid_tail,
                progress,
            )
            if parsed is not None and parsed.get("type") == "result":
                result_payload = parsed
            if heartbeat:
                last_heartbeat = time.monotonic()
        elif stream_name == "stderr":
            stderr_tail.append(line)

    returncode = _safe_returncode(proc)
    common = {
        "returncode": returncode,
        "request_path": request_path,
        "stdout_tail": stdout_tail.get(),
        "stderr_tail": stderr_tail.get(),
        "invalid_stdout_tail": invalid_tail.get(),
        "progress": list(progress),
        "result": result_payload,
    }
    if failure_kind is not None:
        return NativeWorkerResult(
            ok=False,
            message=failure_message or failure_kind,
            failure_kind=failure_kind,
            **common,
        )
    # spike-contract §2.3: the JSONL result line is authoritative, not the
    # exit code. exit 2 (crash) should still surface a structured result
    # via the trap; treat absence of result as a hard crash.
    if result_payload and result_payload.get("ok") is True:
        return NativeWorkerResult(
            ok=True,
            message="dotnet sidecar completed",
            **common,
        )
    if result_payload and result_payload.get("ok") is False:
        kind = str(result_payload.get("failure_kind") or "worker-error")
        return NativeWorkerResult(
            ok=False,
            message=str(result_payload.get("error") or "dotnet sidecar failed"),
            failure_kind=kind,
            **common,
        )
    return NativeWorkerResult(
        ok=False,
        message=(
            f"dotnet sidecar exited with code {returncode} without emitting "
            "a result record"
        ),
        failure_kind="no-result",
        **common,
    )
