"""In-process async load jobs and on-disk extraction status markers."""

from __future__ import annotations

import json
import os
import shutil
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


EXTRACTING_MARKER = "extracting.json"
FAILED_MARKER = "failed.json"
MARKER_SCHEMA_VERSION = 1
DEFAULT_LOAD_WAIT_SECONDS = 20.0
DEFAULT_STALE_SECONDS = 120.0
DEFAULT_HEARTBEAT_SECONDS = 1.0
DEFAULT_EXTRACT_MBPS = 22.0

LOAD_WAIT_ENV = "ETW_MCP_LOAD_WAIT"
STALE_ENV = "ETW_MCP_LOAD_STALE_SECONDS"
HEARTBEAT_ENV = "ETW_MCP_LOAD_HEARTBEAT_SECONDS"
EXTRACT_MBPS_ENV = "ETW_MCP_EXTRACT_MBPS"

_HOST = socket.gethostname()
_jobs: dict[str, "LoadJob"] = {}
_jobs_lock = threading.RLock()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def seconds_since(value: str | None) -> float | None:
    dt = parse_iso(value)
    if dt is None:
        return None
    return max(0.0, (datetime.now(timezone.utc) - dt).total_seconds())


def float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def load_wait_seconds(value: float | int | None) -> float:
    if value is not None:
        try:
            return max(0.0, float(value))
        except (TypeError, ValueError):
            return DEFAULT_LOAD_WAIT_SECONDS
    return float_env(LOAD_WAIT_ENV, DEFAULT_LOAD_WAIT_SECONDS)


def stale_seconds() -> float:
    return float_env(STALE_ENV, DEFAULT_STALE_SECONDS)


def heartbeat_seconds() -> float:
    return float_env(HEARTBEAT_ENV, DEFAULT_HEARTBEAT_SECONDS)


def extract_mbps() -> float:
    return float_env(EXTRACT_MBPS_ENV, DEFAULT_EXTRACT_MBPS)


def estimate_eta_seconds(size_bytes: int, pct: float = 0.0, elapsed_seconds: float | None = None) -> int:
    pct = min(max(float(pct or 0.0), 0.0), 99.0)
    remaining_fraction = max(0.0, 1.0 - (pct / 100.0))
    if elapsed_seconds is not None and pct > 1.0:
        total_estimate = elapsed_seconds / (pct / 100.0)
        return max(0, int(total_estimate - elapsed_seconds))
    size_mb = max(0.0, size_bytes / (1024 * 1024))
    return max(0, int((size_mb * remaining_fraction) / extract_mbps()))


def marker_path(export_dir: Path) -> Path:
    return export_dir / EXTRACTING_MARKER


def failed_marker_path(export_dir: Path) -> Path:
    return export_dir / FAILED_MARKER


def write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.parent / f"{path.name}.tmp.{os.getpid()}.{uuid.uuid4().hex}"
    try:
        with temp.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(data, indent=2, sort_keys=True))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except Exception:
            pass


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def read_extracting_marker(export_dir: Path) -> dict[str, Any] | None:
    return read_json(marker_path(export_dir))


def read_failed_marker(export_dir: Path) -> dict[str, Any] | None:
    return read_json(failed_marker_path(export_dir))


def pid_alive(pid: int | None) -> bool:
    if pid is None or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False
    except Exception:
        return True


def marker_is_fresh(marker: dict[str, Any]) -> bool:
    age = seconds_since(str(marker.get("heartbeat_ts") or ""))
    if age is None or age > stale_seconds():
        return False
    host = str(marker.get("host") or "")
    if host.lower() == _HOST.lower():
        try:
            pid = int(marker.get("pid") or 0)
        except (TypeError, ValueError):
            pid = 0
        return pid_alive(pid)
    return True


def reclaim_cache_dir(export_dir: Path) -> None:
    if export_dir.exists():
        shutil.rmtree(export_dir, ignore_errors=True)


def _etl_identity(etl_path: Path) -> dict[str, Any]:
    stat = etl_path.stat()
    resolved = etl_path.resolve()
    return {
        "path": str(resolved),
        "name": resolved.name,
        "size": int(stat.st_size),
        "mtime_ns": int(stat.st_mtime_ns),
    }


def marker_to_status(marker: dict[str, Any]) -> dict[str, Any]:
    started_at = str(marker.get("started_at") or "")
    heartbeat_ts = str(marker.get("heartbeat_ts") or "")
    elapsed = seconds_since(started_at)
    status = str(marker.get("status") or "extracting")
    result = {
        "trace_id": marker.get("trace_id"),
        "job_id": marker.get("job_id") or marker.get("trace_id"),
        "status": status,
        "mode": marker.get("mode"),
        "pct": float(marker.get("pct") or 0.0),
        "current_dataset": marker.get("current_dataset"),
        "current_phase": marker.get("current_phase"),
        "eta_seconds": marker.get("eta_seconds"),
        "started_at": started_at or None,
        "heartbeat_ts": heartbeat_ts or None,
        "elapsed": elapsed,
        "pid": marker.get("pid"),
        "host": marker.get("host"),
        "cache_dir": marker.get("cache_dir"),
        "staging_dir": marker.get("staging_dir"),
        "etl_path": (marker.get("etl_identity") or {}).get("path"),
        "size_bytes": (marker.get("etl_identity") or {}).get("size"),
        "error": marker.get("error"),
        "failure_kind": marker.get("failure_kind"),
    }
    return result


@dataclass
class LoadJob:
    trace_id: str
    etl_path: Path
    export_dir: Path
    mode: str
    loader: Callable[[Callable[[dict[str, Any]], None]], str]
    size_bytes: int
    started_at: str = field(default_factory=utc_now_iso)
    pct: float = 0.0
    current_dataset: str | None = None
    current_phase: str | None = "queued"
    eta_seconds: int | None = None
    staging_dir: str | None = None
    result: str | None = None
    error: str | None = None
    failure_kind: str | None = None
    status: str = "extracting"
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)
    _done: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    _stop_heartbeat: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def start(self) -> "LoadJob":
        self.eta_seconds = estimate_eta_seconds(self.size_bytes, self.pct)
        self.write_marker()
        self._thread = threading.Thread(
            target=self._run,
            name=f"etw-load-{self.trace_id}",
            daemon=True,
        )
        self._thread.start()
        return self

    def wait(self, seconds: float) -> bool:
        return self._done.wait(max(0.0, seconds))

    def done(self) -> bool:
        return self._done.is_set()

    def update_progress(self, payload: dict[str, Any]) -> None:
        with self._lock:
            phase = payload.get("phase") or payload.get("current_phase")
            if phase:
                self.current_phase = str(phase)
            dataset = payload.get("dataset") or payload.get("current_dataset")
            if dataset:
                self.current_dataset = str(dataset)
            if payload.get("staging_dir"):
                self.staging_dir = str(payload.get("staging_dir"))
            pct = payload.get("pct", payload.get("percent"))
            if pct is None:
                bytes_processed = payload.get("bytes_processed")
                bytes_total = payload.get("bytes_total") or self.size_bytes
                try:
                    if bytes_processed is not None and float(bytes_total) > 0:
                        pct = (float(bytes_processed) / float(bytes_total)) * 100.0
                except (TypeError, ValueError):
                    pct = None
            if pct is not None:
                try:
                    self.pct = min(99.0, max(self.pct, float(pct)))
                except (TypeError, ValueError):
                    pass
            elif payload.get("type") == "progress":
                self.pct = min(95.0, max(self.pct + 1.0, 5.0))
            elapsed = seconds_since(self.started_at)
            self.eta_seconds = estimate_eta_seconds(self.size_bytes, self.pct, elapsed)
            self.write_marker()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return marker_to_status(self._marker_payload())

    def write_marker(self) -> None:
        write_json_atomic(marker_path(self.export_dir), self._marker_payload())

    def _marker_payload(self) -> dict[str, Any]:
        now = utc_now_iso()
        return {
            "schema_version": MARKER_SCHEMA_VERSION,
            "job_id": self.trace_id,
            "trace_id": self.trace_id,
            "status": self.status,
            "mode": self.mode,
            "pid": os.getpid(),
            "host": _HOST,
            "started_at": self.started_at,
            "heartbeat_ts": now,
            "pct": round(float(self.pct or 0.0), 2),
            "current_phase": self.current_phase,
            "current_dataset": self.current_dataset,
            "eta_seconds": self.eta_seconds,
            "etl_identity": _etl_identity(self.etl_path),
            "cache_dir": str(self.export_dir.resolve()),
            "staging_dir": self.staging_dir,
            "error": self.error,
            "failure_kind": self.failure_kind,
        }

    def _heartbeat_loop(self) -> None:
        interval = heartbeat_seconds()
        while not self._stop_heartbeat.wait(interval):
            with self._lock:
                elapsed = seconds_since(self.started_at)
                self.eta_seconds = estimate_eta_seconds(self.size_bytes, self.pct, elapsed)
                try:
                    self.write_marker()
                except Exception:
                    pass

    def _run(self) -> None:
        heartbeat = threading.Thread(
            target=self._heartbeat_loop,
            name=f"etw-load-heartbeat-{self.trace_id}",
            daemon=True,
        )
        heartbeat.start()
        try:
            self.update_progress({"type": "progress", "phase": "extracting", "pct": max(self.pct, 1.0)})
            result = self.loader(self.update_progress)
            self._stop_heartbeat.set()
            with self._lock:
                self.result = result
                if "**Trace ID:**" in result and "Trace loaded" in result:
                    self.status = "ready"
                    self.pct = 100.0
                    self.eta_seconds = 0
                    self.error = None
                    self.failure_kind = None
                    try:
                        marker_path(self.export_dir).unlink(missing_ok=True)
                        failed_marker_path(self.export_dir).unlink(missing_ok=True)
                    except Exception:
                        pass
                else:
                    self.status = "failed"
                    self.error = result
                    self.failure_kind = "load-error"
                    write_json_atomic(failed_marker_path(self.export_dir), self._marker_payload())
                    try:
                        marker_path(self.export_dir).unlink(missing_ok=True)
                    except Exception:
                        pass
        except Exception as exc:
            self._stop_heartbeat.set()
            with self._lock:
                self.status = "failed"
                self.error = str(exc)
                self.failure_kind = type(exc).__name__
                self.result = f"Load failed: {exc}"
                write_json_atomic(failed_marker_path(self.export_dir), self._marker_payload())
                try:
                    marker_path(self.export_dir).unlink(missing_ok=True)
                except Exception:
                    pass
        finally:
            self._stop_heartbeat.set()
            self._done.set()


def active_job(trace_id: str) -> LoadJob | None:
    with _jobs_lock:
        job = _jobs.get(trace_id)
        if job is not None and not job.done():
            return job
        return None


def job_by_id(trace_id: str) -> LoadJob | None:
    with _jobs_lock:
        return _jobs.get(trace_id)


def list_jobs() -> list[LoadJob]:
    with _jobs_lock:
        return list(_jobs.values())


def start_job(
    *,
    trace_id: str,
    etl_path: Path,
    export_dir: Path,
    mode: str,
    loader: Callable[[Callable[[dict[str, Any]], None]], str],
) -> LoadJob:
    with _jobs_lock:
        existing = _jobs.get(trace_id)
        if existing is not None and not existing.done():
            return existing
        size_bytes = etl_path.stat().st_size
        job = LoadJob(
            trace_id=trace_id,
            etl_path=etl_path.resolve(),
            export_dir=export_dir.resolve(),
            mode=mode,
            loader=loader,
            size_bytes=size_bytes,
        )
        _jobs[trace_id] = job
        return job.start()


def clear_jobs() -> None:
    with _jobs_lock:
        _jobs.clear()
