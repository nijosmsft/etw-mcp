from __future__ import annotations

import re
from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer.native import worker_supervisor
import etw_analyzer.native.config as native_config
import etw_analyzer.parsing.wpa_exporter as wpa_exporter
import etw_analyzer.tools.trace_mgmt as trace_mgmt
from etw_analyzer.trace_state import clear_traces, get_trace, list_loaded_trace_ids


@pytest.fixture(autouse=True)
def isolate_traces():
    clear_traces()
    native_config.reset_auto_cache()
    yield
    clear_traces()
    native_config.reset_auto_cache()


def _make_etl(tmp_path: Path) -> Path:
    etl = tmp_path / "sample.etl"
    etl.write_bytes(b"synthetic etl")
    return etl


def _trace_id(result: str) -> str:
    match = re.search(r"Trace ID:\*\* `([^`]+)`", result)
    assert match, result
    return match.group(1)


def _cpu_sampling(cache: Path, weight: int) -> pd.DataFrame:
    cache.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame({
        "Process Name": ["proc.exe"],
        "PID": [1234],
        "Weight": [weight],
        "% Weight": [100.0],
        "Module": ["mod.dll"],
        "Function": ["func"],
    })
    df.to_parquet(cache / "cpu_sampling.parquet", index=False)
    return df


def _write_native_cache(cache: Path, etl: Path, weight: int) -> None:
    df = _cpu_sampling(cache, weight)
    for _, stem in trace_mgmt._DUMPER_EVENT_CLASSES.values():
        pd.DataFrame().to_parquet(cache / f"{stem}.parquet", index=False)
    trace_mgmt._write_cache_manifest(cache, etl, "native", {"cpu_sampling": df})


def test_load_trace_native_worker_success_loads_promoted_cache(
    monkeypatch,
    tmp_path: Path,
):
    etl = _make_etl(tmp_path)
    export_dir = etl.parent / f".etw-export-{etl.stem}"

    monkeypatch.setenv(worker_supervisor.NATIVE_WORKER_ENV, "1")
    monkeypatch.setattr(native_config, "resolve_mode", lambda mode, etl_path=None: "native")
    monkeypatch.setattr(native_config, "_etl_size_mb", lambda etl_path: 0.1)
    monkeypatch.setattr(trace_mgmt, "find_xperf", lambda: None)

    def fake_worker(**kwargs):
        assert kwargs["export_dir"] == export_dir
        _write_native_cache(export_dir, etl, weight=77)
        return worker_supervisor.NativeWorkerResult(
            ok=True,
            message="ok",
            result={"ok": True, "trace_id": kwargs["trace_id"]},
        )

    monkeypatch.setattr(worker_supervisor, "run_native_worker_extraction", fake_worker)

    result = trace_mgmt.load_trace(str(etl), mode="native")

    trace = get_trace(_trace_id(result))
    assert trace is not None
    assert trace.mode == "native"
    assert trace.raw_csv["cpu_sampling"]["Weight"].tolist() == [77]


def test_auto_native_worker_failure_falls_back_to_xperf(
    monkeypatch,
    tmp_path: Path,
):
    etl = _make_etl(tmp_path)

    monkeypatch.setenv(worker_supervisor.NATIVE_WORKER_ENV, "1")
    monkeypatch.setattr(native_config, "resolve_mode", lambda mode, etl_path=None: "native")
    monkeypatch.setattr(native_config, "_etl_size_mb", lambda etl_path: 0.1)
    monkeypatch.setattr(trace_mgmt, "find_xperf", lambda: Path(r"C:\fake\xperf.exe"))
    monkeypatch.setattr(wpa_exporter, "_run_xperf", lambda *args, **kwargs: "")
    monkeypatch.setattr(trace_mgmt, "_start_background_dumper", lambda trace: None)

    def fail_worker(**kwargs):
        return worker_supervisor.NativeWorkerResult(
            ok=False,
            message="synthetic worker failure",
            failure_kind="crash",
        )

    def fake_export_all_profiles(etl_path, export_dir, symbol_path=None, timeout_seconds=300):
        _cpu_sampling(export_dir, weight=12)
        (export_dir / "profile-detail.txt").write_text("xperf", encoding="utf-8")
        return {"cpu_sampling": export_dir / "cpu_sampling.parquet"}

    monkeypatch.setattr(worker_supervisor, "run_native_worker_extraction", fail_worker)
    monkeypatch.setattr(trace_mgmt, "export_all_profiles", fake_export_all_profiles)

    result = trace_mgmt.load_trace(str(etl), mode="auto")

    assert "Native worker failed; falling back to mode='xperf'" in result
    trace = get_trace(_trace_id(result))
    assert trace is not None
    assert trace.mode == "xperf"
    assert trace.raw_csv["cpu_sampling"]["Weight"].tolist() == [12]


def test_explicit_native_worker_failure_does_not_fallback_or_register(
    monkeypatch,
    tmp_path: Path,
):
    etl = _make_etl(tmp_path)

    monkeypatch.setenv(worker_supervisor.NATIVE_WORKER_ENV, "1")
    monkeypatch.setattr(native_config, "resolve_mode", lambda mode, etl_path=None: "native")
    monkeypatch.setattr(native_config, "_etl_size_mb", lambda etl_path: 0.1)
    monkeypatch.setattr(trace_mgmt, "find_xperf", lambda: Path(r"C:\fake\xperf.exe"))

    def fail_worker(**kwargs):
        return worker_supervisor.NativeWorkerResult(
            ok=False,
            message="synthetic worker failure",
            failure_kind="timeout",
            stderr_tail="bounded stderr",
        )

    monkeypatch.setattr(worker_supervisor, "run_native_worker_extraction", fail_worker)
    monkeypatch.setattr(
        trace_mgmt,
        "export_all_profiles",
        lambda *args, **kwargs: pytest.fail("xperf fallback should not run"),
    )

    result = trace_mgmt.load_trace(str(etl), mode="native")

    assert "Native ETW worker extraction failed" in result
    assert "timeout: synthetic worker failure" in result
    assert "bounded stderr" in result
    assert list_loaded_trace_ids() == []
