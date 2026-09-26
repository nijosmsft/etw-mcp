from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer import load_jobs
from etw_analyzer.tools import compare
from etw_analyzer.trace_state import TraceData, clear_traces, register_trace


@pytest.fixture(autouse=True)
def _clean_state():
    clear_traces()
    load_jobs.clear_jobs()
    yield
    clear_traces()
    load_jobs.clear_jobs()


def _trace(path: Path) -> TraceData:
    trace = TraceData(
        trace_id=compare.make_trace_id(path),
        etl_path=path,
        export_dir=path.parent / f".etw-export-{path.stem}",
        raw_csv={
            "cpu_sampling": pd.DataFrame([
                {
                    "Module": "tcpip.sys",
                    "Function": "UdpSend",
                    "Weight": 10,
                },
            ]),
        },
    )
    register_trace(trace)
    return trace


def test_compare_starts_missing_loads_without_blocking(monkeypatch, tmp_path):
    baseline = tmp_path / "baseline.etl"
    test = tmp_path / "test.etl"
    baseline.write_bytes(b"etl")
    test.write_bytes(b"etl")
    calls: list[str] = []

    def fake_load_trace(etl_path: str, **kwargs) -> str:
        calls.append(etl_path)
        return json.dumps({
            "trace_id": compare.make_trace_id(Path(etl_path)),
            "status": "extracting",
            "pct": 5,
        })

    monkeypatch.setattr(compare, "load_trace", fake_load_trace)
    monkeypatch.setattr(
        compare,
        "get_load_status",
        lambda etl_path: json.dumps({
            "trace_id": compare.make_trace_id(Path(etl_path)),
            "status": "extracting",
            "pct": 5,
            "current_phase": "extracting",
        }),
    )

    output = compare.compare_traces(
        str(baseline),
        str(test),
        load_mode="native",
    )

    assert calls == [str(baseline), str(test)]
    assert "waiting for background loads" in output
    assert "- **Baseline:** `extracting`" in output
    assert "- **Test:** `extracting`" in output


def test_compare_uses_registered_traces_without_loading(monkeypatch, tmp_path):
    baseline = tmp_path / "baseline.etl"
    test = tmp_path / "test.etl"
    baseline.write_bytes(b"etl")
    test.write_bytes(b"etl")
    _trace(baseline)
    _trace(test)

    monkeypatch.setattr(
        compare,
        "load_trace",
        lambda *args, **kwargs: pytest.fail("load_trace should not be called"),
    )

    output = compare.compare_traces(
        str(baseline),
        str(test),
        mode="modules",
        modules="all",
    )

    assert "Trace Comparison" in output
    assert "tcpip.sys" in output


def test_compare_does_not_use_partially_registered_loading_trace(
    monkeypatch,
    tmp_path,
):
    baseline = tmp_path / "baseline.etl"
    test = tmp_path / "test.etl"
    baseline.write_bytes(b"etl")
    test.write_bytes(b"etl")
    _trace(baseline)
    _trace(test)

    class _Active:
        status = "extracting"

        def snapshot(self):
            return {
                "status": "extracting",
                "pct": 50,
                "current_phase": "aggregating",
            }

    baseline_id = compare.make_trace_id(baseline)
    monkeypatch.setattr(
        compare.load_jobs,
        "active_job",
        lambda trace_id: _Active() if trace_id == baseline_id else None,
    )
    monkeypatch.setattr(compare.load_jobs, "job_by_id", lambda _trace_id: None)

    output = compare.compare_traces(str(baseline), str(test))

    assert "waiting for background loads" in output
    assert "- **Baseline:** `extracting`" in output
    assert "- **Test:** `ready`" in output


def test_compare_surfaces_immediate_load_rejection(monkeypatch, tmp_path):
    baseline = tmp_path / "baseline.etl"
    test = tmp_path / "test.etl"
    baseline.write_bytes(b"etl")
    test.write_bytes(b"etl")

    monkeypatch.setattr(
        compare,
        "load_trace",
        lambda **_kwargs: "Unsupported mode: broken",
    )
    monkeypatch.setattr(
        compare,
        "get_load_status",
        lambda **_kwargs: json.dumps({"status": "not_found"}),
    )

    output = compare.compare_traces(
        str(baseline),
        str(test),
        load_mode="broken",
    )

    assert "could not load both traces" in output
    assert "`failed`" in output
    assert "Unsupported mode: broken" in output
