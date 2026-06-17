from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer import load_jobs
from etw_analyzer.trace_state import clear_traces, make_trace_id
from etw_analyzer.tools import trace_mgmt


@pytest.fixture(autouse=True)
def _clean_load_jobs(monkeypatch):
    clear_traces()
    load_jobs.clear_jobs()
    monkeypatch.setenv("ETW_MCP_LOAD_HEARTBEAT_SECONDS", "0.01")
    monkeypatch.setenv("ETW_MCP_LOAD_STALE_SECONDS", "0.05")
    monkeypatch.setenv("ETW_MCP_EXTRACT_MBPS", "100000")
    monkeypatch.setattr(trace_mgmt, "find_xperf", lambda: Path(r"C:\xperf.exe"))
    monkeypatch.setattr(trace_mgmt, "_resolve_mode_for_load", lambda mode, path: ("xperf", None))
    yield
    load_jobs.clear_jobs()
    clear_traces()


def _etl(tmp_path: Path, name: str = "sample.etl") -> Path:
    path = tmp_path / name
    path.write_bytes(b"synthetic etl")
    return path


def _summary(path: Path) -> str:
    return f"**Trace loaded:** `{path.name}`\n**Trace ID:** `{make_trace_id(path)}`\n"


def _json(text: str) -> dict:
    return json.loads(text)


def test_load_trace_inline_wait_returns_ready_for_fast_extraction(monkeypatch, tmp_path):
    etl = _etl(tmp_path)
    monkeypatch.setattr(trace_mgmt, "_load_from_cache", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        trace_mgmt,
        "_load_trace_blocking",
        lambda etl_path, **kwargs: _summary(Path(etl_path)),
    )

    result = trace_mgmt.load_trace(str(etl), wait_seconds=1)

    assert "**Trace loaded:**" in result
    assert f"`{make_trace_id(etl)}`" in result


def test_slow_extraction_reports_extracting_then_ready(monkeypatch, tmp_path):
    etl = _etl(tmp_path)
    started = threading.Event()

    def fake_loader(etl_path: str, **kwargs) -> str:
        progress = kwargs["progress_callback"]
        started.set()
        progress({"type": "progress", "phase": "decoding", "pct": 25.0})
        time.sleep(0.08)
        progress({"type": "progress", "phase": "aggregating", "pct": 75.0})
        return _summary(Path(etl_path))

    monkeypatch.setattr(trace_mgmt, "_load_from_cache", lambda *args, **kwargs: None)
    monkeypatch.setattr(trace_mgmt, "_load_trace_blocking", fake_loader)

    result = _json(trace_mgmt.load_trace(str(etl), wait_seconds=0.001))

    assert result["status"] == "extracting"
    assert result["trace_id"] == make_trace_id(etl)
    assert started.wait(1)
    status = _json(trace_mgmt.get_load_status(etl_path=str(etl)))
    assert status["status"] in {"extracting", "ready"}
    assert status["pct"] >= 1.0

    deadline = time.time() + 2
    while time.time() < deadline:
        status = _json(trace_mgmt.get_load_status(etl_path=str(etl)))
        if status["status"] == "ready":
            break
        time.sleep(0.02)

    assert status["status"] == "ready"
    assert status["pct"] == 100.0


def test_finalized_cache_fast_returns_ready(monkeypatch, tmp_path):
    etl = _etl(tmp_path)
    export_dir = etl.parent / f".etw-export-{etl.stem}"
    export_dir.mkdir()
    (export_dir / "wpr-mcp-cache-manifest.json").write_text(
        json.dumps({"complete": True, "finalized": True}),
        encoding="utf-8",
    )
    called = {"loader": 0}

    def fake_cache(cache_dir: Path, path: Path, mode: str = "xperf"):
        manifest = json.loads((cache_dir / "wpr-mcp-cache-manifest.json").read_text())
        if manifest.get("complete") and manifest.get("finalized"):
            return {"cpu_sampling": pd.DataFrame({"CPU": [0]})}
        return None

    def fake_register(path, export_dir, sym_path, resolved_mode, cached, notices, *, from_cache):
        return _summary(path).replace("**Trace loaded:**", "**Trace loaded (from cache):**")

    def fake_loader(*args, **kwargs):
        called["loader"] += 1
        return _summary(etl)

    monkeypatch.setattr(trace_mgmt, "_load_from_cache", fake_cache)
    monkeypatch.setattr(trace_mgmt, "_register_cached_trace", fake_register)
    monkeypatch.setattr(trace_mgmt, "_load_trace_blocking", fake_loader)

    result = trace_mgmt.load_trace(str(etl), wait_seconds=0)

    assert "**Trace loaded (from cache):**" in result
    assert called["loader"] == 0


def test_non_finalized_cache_rebuilds(monkeypatch, tmp_path):
    etl = _etl(tmp_path)
    export_dir = etl.parent / f".etw-export-{etl.stem}"
    export_dir.mkdir()
    (export_dir / "wpr-mcp-cache-manifest.json").write_text(
        json.dumps({"complete": True, "finalized": False}),
        encoding="utf-8",
    )
    called = {"loader": 0}

    def fake_cache(cache_dir: Path, path: Path, mode: str = "xperf"):
        manifest = json.loads((cache_dir / "wpr-mcp-cache-manifest.json").read_text())
        if manifest.get("complete") and manifest.get("finalized"):
            return {"cpu_sampling": pd.DataFrame({"CPU": [0]})}
        return None

    def fake_loader(etl_path: str, **kwargs):
        called["loader"] += 1
        return _summary(Path(etl_path))

    monkeypatch.setattr(trace_mgmt, "_load_from_cache", fake_cache)
    monkeypatch.setattr(trace_mgmt, "_load_trace_blocking", fake_loader)

    result = trace_mgmt.load_trace(str(etl), wait_seconds=1)

    assert "**Trace loaded:**" in result
    assert called["loader"] == 1


def test_repeat_load_reuses_running_job(monkeypatch, tmp_path):
    etl = _etl(tmp_path)
    started = threading.Event()
    release = threading.Event()
    calls = {"count": 0}

    def fake_loader(etl_path: str, **kwargs):
        calls["count"] += 1
        started.set()
        release.wait(1)
        return _summary(Path(etl_path))

    monkeypatch.setattr(trace_mgmt, "_load_from_cache", lambda *args, **kwargs: None)
    monkeypatch.setattr(trace_mgmt, "_load_trace_blocking", fake_loader)

    first = _json(trace_mgmt.load_trace(str(etl), wait_seconds=0))
    assert first["status"] == "extracting"
    assert started.wait(1)
    second = _json(trace_mgmt.load_trace(str(etl), wait_seconds=0))
    release.set()

    assert second["status"] == "extracting"
    assert second["trace_id"] == first["trace_id"]
    assert calls["count"] == 1


def test_stale_lock_is_reclaimed_and_extraction_restarts(monkeypatch, tmp_path):
    etl = _etl(tmp_path)
    export_dir = etl.parent / f".etw-export-{etl.stem}"
    export_dir.mkdir()
    (export_dir / "partial.parquet").write_text("partial", encoding="utf-8")
    old = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat().replace("+00:00", "Z")
    load_jobs.write_json_atomic(
        load_jobs.marker_path(export_dir),
        {
            "schema_version": 1,
            "trace_id": make_trace_id(etl),
            "job_id": make_trace_id(etl),
            "status": "extracting",
            "pid": 999999,
            "host": load_jobs._HOST,
            "started_at": old,
            "heartbeat_ts": old,
            "pct": 10,
            "etl_identity": {"path": str(etl), "size": etl.stat().st_size},
            "cache_dir": str(export_dir),
        },
    )
    calls = {"count": 0}
    started = threading.Event()

    def fake_loader(etl_path: str, **kwargs):
        calls["count"] += 1
        started.set()
        time.sleep(0.02)
        return _summary(Path(etl_path))

    monkeypatch.setattr(trace_mgmt, "_load_from_cache", lambda *args, **kwargs: None)
    monkeypatch.setattr(trace_mgmt, "_load_trace_blocking", fake_loader)

    result = _json(trace_mgmt.load_trace(str(etl), wait_seconds=0))

    assert result["status"] == "extracting"
    assert started.wait(1)
    assert calls["count"] == 1
    assert not (export_dir / "partial.parquet").exists()


def test_get_load_status_not_found_and_failed(monkeypatch, tmp_path):
    missing = tmp_path / "missing.etl"
    assert _json(trace_mgmt.get_load_status(etl_path=str(missing)))["status"] == "not_found"

    etl = _etl(tmp_path)

    def fake_loader(etl_path: str, **kwargs):
        raise RuntimeError("simulated extractor error")

    monkeypatch.setattr(trace_mgmt, "_load_from_cache", lambda *args, **kwargs: None)
    monkeypatch.setattr(trace_mgmt, "_load_trace_blocking", fake_loader)

    result = trace_mgmt.load_trace(str(etl), wait_seconds=1)
    assert "simulated extractor error" in result
    status = _json(trace_mgmt.get_load_status(etl_path=str(etl)))
    assert status["status"] == "failed"
    assert "simulated extractor error" in status["error"]
