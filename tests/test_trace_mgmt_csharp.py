"""Integration tests for load_trace dispatch into the C# sidecar path.

Mirrors tests/test_trace_mgmt_worker.py for the native worker. Stubs the
sidecar supervisor (worker_supervisor.run_dotnet_worker_extraction) and
asserts that load_trace correctly:

* dispatches to the csharp worker when ``mode="dotnet"`` (or
  ``WPR_MCP_mode=dotnet``) is in effect,
* registers the loaded trace with ``trace.mode == "dotnet"`` and the
  expected raw_csv contents,
* falls back along the documented ``csharp → native → xperf`` chain when
  the csharp pipeline fails under auto resolution, and
* fails fast (no fallback, no registration) when csharp is forced.
"""

from __future__ import annotations

import re
from pathlib import Path

import pandas as pd
import pytest

import etw_analyzer.native.config as native_config
import etw_analyzer.parsing.wpa_exporter as wpa_exporter
import etw_analyzer.tools.trace_mgmt as trace_mgmt
from etw_analyzer.native import cache as native_cache
from etw_analyzer.native import worker_supervisor
from etw_analyzer.trace_state import clear_traces, get_trace, list_loaded_trace_ids


@pytest.fixture(autouse=True)
def isolate_traces():
    clear_traces()
    native_config.reset_auto_cache()
    yield
    clear_traces()
    native_config.reset_auto_cache()


def _make_etl(tmp_path: Path) -> Path:
    etl = tmp_path / "csharp-sample.etl"
    etl.write_bytes(b"synthetic etl for csharp dispatch test")
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


def _write_csharp_cache(cache: Path, etl: Path, weight: int) -> None:
    """Write a v3 manifest with producer='dotnet' alongside fake parquets.

    The csharp sidecar emits all canonical dumper stems even when empty, so
    we mirror that here. cpu_sampling carries the weight value the assertion
    checks for.
    """
    df = _cpu_sampling(cache, weight)
    datasets: list[native_cache.CacheDataset] = [
        native_cache.CacheDataset(
            name="cpu_sampling",
            kind="parquet",
            path="cpu_sampling.parquet",
            row_count=len(df),
            materialize_on_load=True,
        ),
    ]
    for _, stem in trace_mgmt._DUMPER_EVENT_CLASSES.values():
        pd.DataFrame().to_parquet(cache / f"{stem}.parquet", index=False)
        datasets.append(
            native_cache.CacheDataset(
                name=stem,
                kind="dumper-parquet",
                path=f"{stem}.parquet",
                row_count=0,
                materialize_on_load=False,
            )
        )

    manifest = native_cache.CacheManifest.materialized_small(
        etl,
        datasets,
        producer="dotnet",
    )
    native_cache.write_manifest(cache, manifest)


def _fake_csharp_sidecar_path(tmp_path: Path) -> Path:
    """Create a fake (empty) sidecar binary the resolver will accept."""
    fake = tmp_path / "wpr-mcp-extract.exe"
    fake.write_bytes(b"MZ")
    return fake


def test_load_trace_csharp_worker_success_loads_promoted_cache(
    monkeypatch,
    tmp_path: Path,
):
    etl = _make_etl(tmp_path)
    export_dir = etl.parent / f".etw-export-{etl.stem}"

    monkeypatch.setenv(
        native_config.DOTNET_SIDECAR_ENV,
        str(_fake_csharp_sidecar_path(tmp_path)),
    )
    native_config.reset_dotnet_cache()
    monkeypatch.setattr(trace_mgmt, "find_xperf", lambda: None)

    def fake_worker(**kwargs):
        assert kwargs["export_dir"] == export_dir
        assert kwargs["etl_path"] == etl
        _write_csharp_cache(export_dir, etl, weight=91)
        return worker_supervisor.NativeWorkerResult(
            ok=True,
            message="ok",
            result={"ok": True, "trace_id": kwargs["trace_id"]},
        )

    monkeypatch.setattr(
        worker_supervisor, "run_dotnet_worker_extraction", fake_worker
    )

    result = trace_mgmt.load_trace(str(etl), mode="dotnet")

    trace = get_trace(_trace_id(result))
    assert trace is not None, result
    assert trace.mode == "dotnet"
    assert trace.raw_csv["cpu_sampling"]["Weight"].tolist() == [91]


def test_load_trace_auto_picks_csharp_when_sidecar_is_configured(
    monkeypatch,
    tmp_path: Path,
):
    etl = _make_etl(tmp_path)
    export_dir = etl.parent / f".etw-export-{etl.stem}"

    monkeypatch.setenv(
        native_config.DOTNET_SIDECAR_ENV,
        str(_fake_csharp_sidecar_path(tmp_path)),
    )
    native_config.reset_dotnet_cache()
    monkeypatch.delenv("WPR_MCP_MODE", raising=False)
    monkeypatch.setattr(trace_mgmt, "find_xperf", lambda: None)

    def fake_worker(**kwargs):
        _write_csharp_cache(export_dir, etl, weight=42)
        return worker_supervisor.NativeWorkerResult(
            ok=True,
            message="ok",
            result={"ok": True, "trace_id": kwargs["trace_id"]},
        )

    def refuse_native(**kwargs):
        pytest.fail(
            "native worker must not be invoked when csharp wins auto-resolution"
        )

    monkeypatch.setattr(
        worker_supervisor, "run_dotnet_worker_extraction", fake_worker
    )
    monkeypatch.setattr(
        worker_supervisor, "run_native_worker_extraction", refuse_native
    )

    result = trace_mgmt.load_trace(str(etl))

    trace = get_trace(_trace_id(result))
    assert trace is not None, result
    assert trace.mode == "dotnet"


def test_auto_csharp_failure_falls_back_to_native_worker(
    monkeypatch,
    tmp_path: Path,
):
    etl = _make_etl(tmp_path)
    export_dir = etl.parent / f".etw-export-{etl.stem}"

    monkeypatch.setenv(
        native_config.DOTNET_SIDECAR_ENV,
        str(_fake_csharp_sidecar_path(tmp_path)),
    )
    native_config.reset_dotnet_cache()
    monkeypatch.delenv("WPR_MCP_MODE", raising=False)
    monkeypatch.setenv(worker_supervisor.NATIVE_WORKER_ENV, "1")
    monkeypatch.setattr(native_config, "_etl_size_mb", lambda etl_path: 0.1)
    monkeypatch.setattr(trace_mgmt, "find_xperf", lambda: None)

    def fail_csharp(**kwargs):
        return worker_supervisor.NativeWorkerResult(
            ok=False,
            message="synthetic csharp sidecar failure",
            failure_kind="sidecar-crash",
        )

    def fake_native(**kwargs):
        # Native worker writes a producer="native" cache the loader picks up.
        cache_dir: Path = kwargs["export_dir"]
        df = _cpu_sampling(cache_dir, weight=33)
        datasets = [native_cache.CacheDataset(
            name="cpu_sampling",
            kind="parquet",
            path="cpu_sampling.parquet",
            row_count=len(df),
            materialize_on_load=True,
        )]
        for _, stem in trace_mgmt._DUMPER_EVENT_CLASSES.values():
            pd.DataFrame().to_parquet(cache_dir / f"{stem}.parquet", index=False)
            datasets.append(native_cache.CacheDataset(
                name=stem,
                kind="dumper-parquet",
                path=f"{stem}.parquet",
                row_count=0,
                materialize_on_load=False,
            ))
        native_cache.write_manifest(
            cache_dir,
            native_cache.CacheManifest.materialized_small(
                etl, datasets, producer="native",
            ),
        )
        return worker_supervisor.NativeWorkerResult(
            ok=True,
            message="ok",
            result={"ok": True, "trace_id": kwargs["trace_id"]},
        )

    monkeypatch.setattr(
        worker_supervisor, "run_dotnet_worker_extraction", fail_csharp
    )
    monkeypatch.setattr(
        worker_supervisor, "run_native_worker_extraction", fake_native
    )

    result = trace_mgmt.load_trace(str(etl))

    assert ".NET sidecar failed; falling back to mode='native'" in result
    trace = get_trace(_trace_id(result))
    assert trace is not None
    assert trace.mode == "native"
    assert trace.raw_csv["cpu_sampling"]["Weight"].tolist() == [33]


def test_explicit_csharp_failure_does_not_fallback_or_register(
    monkeypatch,
    tmp_path: Path,
):
    etl = _make_etl(tmp_path)

    monkeypatch.setenv(
        native_config.DOTNET_SIDECAR_ENV,
        str(_fake_csharp_sidecar_path(tmp_path)),
    )
    native_config.reset_dotnet_cache()
    monkeypatch.setattr(trace_mgmt, "find_xperf", lambda: Path(r"C:\fake\xperf.exe"))

    def fail_csharp(**kwargs):
        return worker_supervisor.NativeWorkerResult(
            ok=False,
            message="synthetic csharp sidecar failure",
            failure_kind="timeout",
            stderr_tail="bounded stderr",
        )

    monkeypatch.setattr(
        worker_supervisor, "run_dotnet_worker_extraction", fail_csharp
    )
    monkeypatch.setattr(
        worker_supervisor,
        "run_native_worker_extraction",
        lambda **kwargs: pytest.fail("native fallback must not run when csharp is forced"),
    )
    monkeypatch.setattr(
        trace_mgmt,
        "export_all_profiles",
        lambda *args, **kwargs: pytest.fail("xperf fallback must not run when csharp is forced"),
    )

    result = trace_mgmt.load_trace(str(etl), mode="dotnet")

    assert ".NET sidecar ETW worker extraction failed" in result
    assert "timeout: synthetic csharp sidecar failure" in result
    assert "bounded stderr" in result
    # Producer-aware fallback hints must name both alternative pipelines so
    # the caller can recover without guessing.
    assert "mode='native'" in result
    assert "mode='xperf'" in result
    assert list_loaded_trace_ids() == []
