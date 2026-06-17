from __future__ import annotations

import json
import re
from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer.native import cache as native_cache
from etw_analyzer.native.schemas import EVENT_SCHEMA_VERSION
import etw_analyzer.native.config as native_config
import etw_analyzer.parsing.wpa_exporter as wpa_exporter
import etw_analyzer.tools.trace_mgmt as trace_mgmt
from etw_analyzer.trace_state import (
    TraceData,
    clear_traces,
    get_trace,
    list_loaded_trace_ids,
)


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


def _cache_dir(etl: Path) -> Path:
    cache = etl.parent / f".etw-export-{etl.stem}"
    cache.mkdir(parents=True, exist_ok=True)
    return cache


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


def _write_native_dumper_cache(cache: Path) -> None:
    for _, stem in trace_mgmt._DUMPER_EVENT_CLASSES.values():
        pd.DataFrame().to_parquet(cache / f"{stem}.parquet", index=False)


def _trace_id(result: str) -> str:
    match = re.search(r"Trace ID:\*\* `([^`]+)`", result)
    assert match, result
    return match.group(1)


def test_native_v2_manifest_cache_reloads_materialized_small(tmp_path: Path):
    etl = _make_etl(tmp_path)
    cache = _cache_dir(etl)
    native_df = _cpu_sampling(cache, weight=13)
    _write_native_dumper_cache(cache)

    trace_mgmt._write_cache_manifest(cache, etl, "native", {"cpu_sampling": native_df})

    manifest = trace_mgmt._read_cache_manifest(cache)
    assert manifest is not None
    assert manifest["schema_version"] == native_cache.SCHEMA_VERSION
    assert manifest["mode"] == "native"
    assert manifest["strategy"] == native_cache.MATERIALIZED_SMALL_STRATEGY
    assert manifest["complete"] is True
    assert manifest["finalized"] is True
    assert manifest["event_schema_version"] == EVENT_SCHEMA_VERSION
    assert manifest["etl"]["name"] == etl.name
    assert manifest["etl"]["size"] == etl.stat().st_size
    assert manifest["etl"]["mtime_ns"] == etl.stat().st_mtime_ns
    assert manifest["native_store"]["generation_id"] == "flat"
    assert manifest["native_store"]["path"] == "."

    datasets = {item["name"]: item for item in manifest["datasets"]}
    assert datasets["cpu_sampling"]["kind"] == "parquet"
    assert datasets["cpu_sampling"]["path"] == "cpu_sampling.parquet"
    assert datasets["cpu_sampling"]["row_count"] == 1
    assert datasets["cpu_sampling"]["materialize_on_load"] is True
    assert datasets["sampled_profile"]["kind"] == "dumper-parquet"
    assert datasets["sampled_profile"]["materialize_on_load"] is False

    cached = trace_mgmt._load_from_cache(cache, etl, mode="native")

    assert cached is not None
    assert cached["cpu_sampling"]["Weight"].tolist() == [13]


def test_native_v2_incomplete_manifest_rejected(tmp_path: Path):
    etl = _make_etl(tmp_path)
    cache = _cache_dir(etl)
    manifest = native_cache.CacheManifest.materialized_small(
        etl,
        [
            native_cache.CacheDataset(
                name="cpu_sampling",
                kind="parquet",
                path="cpu_sampling.parquet",
                row_count=1,
                materialize_on_load=True,
            )
        ],
        complete=False,
    )
    native_cache.write_manifest(cache, manifest)

    assert trace_mgmt._load_from_cache(cache, etl, mode="native") is None
    assert list_loaded_trace_ids() == []


def test_native_v2_mode_mismatch_rejected(tmp_path: Path):
    etl = _make_etl(tmp_path)
    cache = _cache_dir(etl)
    (cache / "cpu_sampling.parquet").write_bytes(b"parquet")
    manifest = native_cache.CacheManifest.materialized_small(
        etl,
        [
            native_cache.CacheDataset(
                name="cpu_sampling",
                kind="parquet",
                path="cpu_sampling.parquet",
                row_count=1,
                materialize_on_load=True,
            )
        ],
    )
    native_cache.write_manifest(cache, manifest)

    assert trace_mgmt._load_from_cache(cache, etl, mode="xperf") is None
    assert list_loaded_trace_ids() == []


def test_native_v2_stale_etl_identity_rejected(tmp_path: Path):
    etl = _make_etl(tmp_path)
    cache = _cache_dir(etl)
    (cache / "cpu_sampling.parquet").write_bytes(b"parquet")
    manifest = native_cache.CacheManifest.materialized_small(
        etl,
        [
            native_cache.CacheDataset(
                name="cpu_sampling",
                kind="parquet",
                path="cpu_sampling.parquet",
                row_count=1,
                materialize_on_load=True,
            )
        ],
    )
    native_cache.write_manifest(cache, manifest)
    etl.write_bytes(b"synthetic etl with a different size")

    assert trace_mgmt._load_from_cache(cache, etl, mode="native") is None
    assert list_loaded_trace_ids() == []


def test_xperf_load_ignores_native_manifest_cache(monkeypatch, tmp_path: Path):
    etl = _make_etl(tmp_path)
    cache = _cache_dir(etl)
    native_df = _cpu_sampling(cache, weight=1)
    _write_native_dumper_cache(cache)
    trace_mgmt._write_cache_manifest(cache, etl, "native", {"cpu_sampling": native_df})

    monkeypatch.setattr(trace_mgmt, "find_xperf", lambda: Path(r"C:\fake\xperf.exe"))
    monkeypatch.setattr(wpa_exporter, "_run_xperf", lambda *args, **kwargs: "")
    monkeypatch.setattr(trace_mgmt, "_start_background_dumper", lambda trace: None)

    exported = {"called": False}

    def fake_export_all_profiles(etl_path, export_dir, symbol_path=None, timeout_seconds=300):
        exported["called"] = True
        _cpu_sampling(export_dir, weight=99)
        (export_dir / "profile-detail.txt").write_text("xperf", encoding="utf-8")
        return {"cpu_sampling": export_dir / "cpu_sampling.parquet"}

    monkeypatch.setattr(trace_mgmt, "export_all_profiles", fake_export_all_profiles)

    result = trace_mgmt.load_trace(str(etl), mode="xperf")

    assert exported["called"] is True
    trace = get_trace(_trace_id(result))
    assert trace is not None
    assert trace.mode == "xperf"
    assert trace.raw_csv["cpu_sampling"]["Weight"].tolist() == [99]


def test_xperf_manifest_cache_reloads_without_export(monkeypatch, tmp_path: Path):
    etl = _make_etl(tmp_path)
    cache = _cache_dir(etl)
    df = _cpu_sampling(cache, weight=7)
    (cache / "profile-detail.txt").write_text("xperf", encoding="utf-8")
    trace_mgmt._write_cache_manifest(cache, etl, "xperf", {"cpu_sampling": df})

    monkeypatch.setattr(trace_mgmt, "find_xperf", lambda: Path(r"C:\fake\xperf.exe"))
    monkeypatch.setattr(trace_mgmt, "_start_background_dumper", lambda trace: None)
    monkeypatch.setattr(
        trace_mgmt,
        "export_all_profiles",
        lambda *args, **kwargs: pytest.fail("xperf export should not run"),
    )

    result = trace_mgmt.load_trace(str(etl), mode="xperf")

    assert "**Trace loaded (from cache):**" in result
    trace = get_trace(_trace_id(result))
    assert trace is not None
    assert trace.mode == "xperf"
    assert trace.raw_csv["cpu_sampling"]["Weight"].tolist() == [7]


def test_legacy_xperf_cache_without_manifest_still_loads(tmp_path: Path):
    etl = _make_etl(tmp_path)
    cache = _cache_dir(etl)
    _cpu_sampling(cache, weight=5)
    (cache / "profile-detail.txt").write_text("legacy xperf", encoding="utf-8")

    cached = trace_mgmt._load_from_cache(cache, etl, mode="xperf")

    assert cached is not None
    assert cached["cpu_sampling"]["Weight"].tolist() == [5]
    assert trace_mgmt._load_from_cache(cache, etl, mode="native") is None


def test_legacy_v1_manifest_without_event_schema_version_rejected(tmp_path: Path):
    """M2: a flat native manifest that lacks event_schema_version is treated as
    stale and must NOT rehydrate.  This enforces that caches written before the
    image-identity schema bump (PdbGuid/PdbAge/PdbName/TimeDateStamp) are
    re-extracted rather than silently loaded with missing identity columns.
    """
    etl = _make_etl(tmp_path)
    cache = _cache_dir(etl)
    _cpu_sampling(cache, weight=17)
    _write_native_dumper_cache(cache)
    required_stems = sorted(stem for _, stem in trace_mgmt._DUMPER_EVENT_CLASSES.values())
    # Deliberately omit event_schema_version to simulate a pre-M2 cache.
    manifest = {
        "schema_version": trace_mgmt._CACHE_SCHEMA_VERSION,
        "mode": "native",
        "complete": True,
        **trace_mgmt._etl_cache_identity(etl),
        "datasets": ["cpu_sampling"],
        "dumper_datasets": required_stems,
        "required_datasets": [],
        "required_dumper_datasets": required_stems,
    }
    trace_mgmt._cache_manifest_path(cache).write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    cached = trace_mgmt._load_from_cache(cache, etl, mode="native")

    assert cached is None, (
        "pre-M2 cache lacking event_schema_version must be rejected and "
        "trigger re-extraction; got a non-None result"
    )


def test_dumper_cache_stems_are_manifest_mode_scoped(tmp_path: Path):
    etl = _make_etl(tmp_path)
    cache = _cache_dir(etl)
    native_df = _cpu_sampling(cache, weight=3)
    _write_native_dumper_cache(cache)
    trace_mgmt._write_cache_manifest(cache, etl, "native", {"cpu_sampling": native_df})

    xperf_trace = TraceData(
        trace_id="trace_xperf",
        etl_path=etl,
        export_dir=cache,
        mode="xperf",
        raw_csv={"cpu_sampling": native_df},
    )
    native_trace = TraceData(
        trace_id="trace_native",
        etl_path=etl,
        export_dir=cache,
        mode="native",
        raw_csv={"cpu_sampling": native_df},
    )

    assert trace_mgmt._cached_dumper_stems_for_trace(xperf_trace) == frozenset()
    assert trace_mgmt._cached_dumper_stems_for_trace(native_trace) == frozenset(
        stem for _, stem in trace_mgmt._DUMPER_EVENT_CLASSES.values()
    )

    trace_mgmt._write_cache_manifest(
        cache,
        etl,
        "xperf",
        {"cpu_sampling": native_df},
        dumper_stems=frozenset(),
    )
    assert trace_mgmt._cached_dumper_stems_for_trace(xperf_trace) == frozenset()


def test_auto_large_native_falls_back_to_xperf(monkeypatch, tmp_path: Path):
    etl = _make_etl(tmp_path)

    monkeypatch.setenv("ETW_MCP_NATIVE_MAX_ETL_MB", "1")
    monkeypatch.setattr(native_config, "resolve_mode", lambda mode, etl_path=None: "native")
    monkeypatch.setattr(native_config, "_etl_size_mb", lambda etl_path: 2.0)
    monkeypatch.setattr(trace_mgmt, "find_xperf", lambda: Path(r"C:\fake\xperf.exe"))
    monkeypatch.setattr(wpa_exporter, "_run_xperf", lambda *args, **kwargs: "")
    monkeypatch.setattr(trace_mgmt, "_start_background_dumper", lambda trace: None)

    def fake_export_all_profiles(etl_path, export_dir, symbol_path=None, timeout_seconds=300):
        _cpu_sampling(export_dir, weight=11)
        (export_dir / "profile-detail.txt").write_text("xperf", encoding="utf-8")
        return {"cpu_sampling": export_dir / "cpu_sampling.parquet"}

    monkeypatch.setattr(trace_mgmt, "export_all_profiles", fake_export_all_profiles)

    result = trace_mgmt.load_trace(str(etl), mode="auto")

    assert "Falling back to mode='xperf'" in result
    trace = get_trace(_trace_id(result))
    assert trace is not None
    assert trace.mode == "xperf"


def test_explicit_native_large_fails_without_override(monkeypatch, tmp_path: Path):
    etl = _make_etl(tmp_path)

    monkeypatch.setenv("ETW_MCP_NATIVE_MAX_ETL_MB", "1")
    monkeypatch.setattr(native_config, "resolve_mode", lambda mode, etl_path=None: "native")
    monkeypatch.setattr(native_config, "_etl_size_mb", lambda etl_path: 2.0)

    result = trace_mgmt.load_trace(str(etl), mode="native")

    assert "above the native safety limit" in result
    assert "ETW_MCP_NATIVE_ALLOW_LARGE=1" in result
    assert list_loaded_trace_ids() == []


def test_native_large_override_allows_load(monkeypatch, tmp_path: Path):
    etl = _make_etl(tmp_path)

    monkeypatch.setenv("ETW_MCP_NATIVE_MAX_ETL_MB", "1")
    monkeypatch.setenv("ETW_MCP_NATIVE_ALLOW_LARGE", "1")
    monkeypatch.setattr(native_config, "resolve_mode", lambda mode, etl_path=None: "native")
    monkeypatch.setattr(native_config, "_etl_size_mb", lambda etl_path: 2.0)

    def complete_background_dumper(trace):
        trace.raw_csv["cpu_sampling"] = pd.DataFrame({
            "Process Name": ["proc.exe"],
            "PID": [1234],
            "Weight": [1],
            "% Weight": [100.0],
            "Module": ["mod.dll"],
            "Function": ["func"],
        })

    monkeypatch.setattr(trace_mgmt, "_start_background_dumper", complete_background_dumper)

    result = trace_mgmt.load_trace(str(etl), mode="native")

    assert "above the native safety limit" not in result
    trace = get_trace(_trace_id(result))
    assert trace is not None
    assert trace.mode == "native"


def test_native_dumper_error_unregisters_partial_trace(monkeypatch, tmp_path: Path):
    etl = _make_etl(tmp_path)

    monkeypatch.setattr(native_config, "resolve_mode", lambda mode, etl_path=None: "native")
    monkeypatch.setattr(native_config, "_etl_size_mb", lambda etl_path: 0.1)

    def fail_background_dumper(trace):
        trace._dumper_error = "synthetic native failure"

    monkeypatch.setattr(trace_mgmt, "_start_background_dumper", fail_background_dumper)

    result = trace_mgmt.load_trace(str(etl), mode="native")

    assert "Native ETW extraction failed: synthetic native failure" in result
    assert list_loaded_trace_ids() == []


def test_native_rejects_non_default_timeout(monkeypatch, tmp_path: Path):
    etl = _make_etl(tmp_path)

    monkeypatch.setattr(native_config, "resolve_mode", lambda mode, etl_path=None: "native")
    monkeypatch.setattr(native_config, "_etl_size_mb", lambda etl_path: 0.1)

    result = trace_mgmt.load_trace(str(etl), mode="native", timeout_seconds=10)

    assert "timeout_seconds is only supported for mode='xperf'" in result
    assert list_loaded_trace_ids() == []


# ---------------------------------------------------------------------------
# M2: event_schema_version invalidation tests
# ---------------------------------------------------------------------------

def test_native_v2_manifest_without_event_schema_version_rejected(tmp_path: Path):
    """M2: a native v2/v3 manifest that lacks event_schema_version (field absent
    or value 0) must be treated as stale and cause _load_from_cache to return
    None.  This validates that caches written before the PDB-identity schema
    bump are rejected and trigger re-extraction.
    """
    etl = _make_etl(tmp_path)
    cache = _cache_dir(etl)
    _cpu_sampling(cache, weight=55)
    _write_native_dumper_cache(cache)
    datasets = [
        native_cache.CacheDataset(
            name="cpu_sampling",
            kind="parquet",
            path="cpu_sampling.parquet",
            row_count=1,
            materialize_on_load=True,
        )
    ]
    for _, stem in trace_mgmt._DUMPER_EVENT_CLASSES.values():
        datasets.append(native_cache.CacheDataset(
            name=stem,
            kind="dumper-parquet",
            path=f"{stem}.parquet",
            row_count=0,
            materialize_on_load=False,
        ))
    # Write a valid v3 manifest, then remove event_schema_version to simulate
    # a pre-M2 cache (CacheManifest.from_dict defaults missing field to 0).
    manifest = native_cache.CacheManifest.materialized_small(etl, datasets)
    native_cache.write_manifest(cache, manifest)
    # Patch the written JSON: remove event_schema_version.
    import json as _json
    manifest_path = native_cache.manifest_path(cache)
    data = _json.loads(manifest_path.read_text(encoding="utf-8"))
    data.pop("event_schema_version", None)
    manifest_path.write_text(_json.dumps(data, indent=2), encoding="utf-8")

    cached = trace_mgmt._load_from_cache(cache, etl, mode="native")

    assert cached is None, (
        "native v2/v3 manifest without event_schema_version must be rejected"
    )


def test_native_v2_manifest_with_correct_event_schema_version_loads(tmp_path: Path):
    """M2: a native manifest that includes the correct EVENT_SCHEMA_VERSION is
    accepted and data rehydrates successfully.
    """
    etl = _make_etl(tmp_path)
    cache = _cache_dir(etl)
    df = _cpu_sampling(cache, weight=77)
    _write_native_dumper_cache(cache)
    trace_mgmt._write_cache_manifest(cache, etl, "native", {"cpu_sampling": df})

    # Verify the written manifest carries the current event_schema_version.
    import json as _json
    data = _json.loads(trace_mgmt._cache_manifest_path(cache).read_text(encoding="utf-8"))
    assert data.get("event_schema_version") == EVENT_SCHEMA_VERSION, (
        f"manifest must carry event_schema_version={EVENT_SCHEMA_VERSION}, "
        f"got {data.get('event_schema_version')!r}"
    )

    cached = trace_mgmt._load_from_cache(cache, etl, mode="native")

    assert cached is not None, "valid manifest with correct event_schema_version must load"
    assert cached["cpu_sampling"]["Weight"].tolist() == [77]


def test_finalized_manifest_fast_path_loads(tmp_path: Path):
    etl = _make_etl(tmp_path)
    cache = _cache_dir(etl)
    df = _cpu_sampling(cache, weight=88)
    _write_native_dumper_cache(cache)
    trace_mgmt._write_cache_manifest(cache, etl, "native", {"cpu_sampling": df})

    cached = trace_mgmt._load_from_cache(cache, etl, mode="native")

    assert cached is not None
    assert cached["cpu_sampling"]["Weight"].tolist() == [88]


def test_non_finalized_manifest_triggers_rebuild(tmp_path: Path):
    etl = _make_etl(tmp_path)
    cache = _cache_dir(etl)
    _cpu_sampling(cache, weight=23)
    _write_native_dumper_cache(cache)
    datasets = [
        native_cache.CacheDataset(
            name="cpu_sampling",
            kind="parquet",
            path="cpu_sampling.parquet",
            row_count=1,
            materialize_on_load=True,
        )
    ]
    for _, stem in trace_mgmt._DUMPER_EVENT_CLASSES.values():
        datasets.append(native_cache.CacheDataset(
            name=stem,
            kind="dumper-parquet",
            path=f"{stem}.parquet",
            row_count=0,
            materialize_on_load=False,
        ))
    manifest = native_cache.CacheManifest.materialized_small(
        etl,
        datasets,
        complete=False,
        finalized=False,
    )
    native_cache.write_manifest(cache, manifest)

    assert trace_mgmt._load_from_cache(cache, etl, mode="native") is None


def test_schema_mismatch_manifest_triggers_rebuild(tmp_path: Path):
    etl = _make_etl(tmp_path)
    cache = _cache_dir(etl)
    _cpu_sampling(cache, weight=24)
    _write_native_dumper_cache(cache)
    datasets = [
        {
            "name": "cpu_sampling",
            "kind": "parquet",
            "path": "cpu_sampling.parquet",
            "schema_version": 1,
            "row_count": 1,
            "materialize_on_load": True,
        }
    ]
    for _, stem in trace_mgmt._DUMPER_EVENT_CLASSES.values():
        datasets.append({
            "name": stem,
            "kind": "dumper-parquet",
            "path": f"{stem}.parquet",
            "schema_version": 1,
            "row_count": 0,
            "materialize_on_load": False,
        })
    manifest = {
        "schema_version": native_cache.SCHEMA_VERSION - 1,
        "mode": "native",
        "producer": "native",
        "strategy": native_cache.MATERIALIZED_SMALL_STRATEGY,
        "complete": True,
        "finalized": True,
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "etl": {
            "path": str(etl.resolve()),
            "name": etl.name,
            "size": etl.stat().st_size,
            "mtime_ns": etl.stat().st_mtime_ns,
        },
        "datasets": datasets,
        "native_store": {"generation_id": "flat", "path": "."},
    }
    (cache / native_cache.MANIFEST_FILENAME).write_text(
        json.dumps(manifest), encoding="utf-8"
    )

    assert trace_mgmt._load_from_cache(cache, etl, mode="native") is None


def test_complete_manifest_with_missing_listed_dataset_triggers_rebuild(
    tmp_path: Path,
):
    """Regression for observed bug: complete manifest before later parquets."""

    etl = _make_etl(tmp_path)
    cache = _cache_dir(etl)
    # Deliberately do NOT write cpu_sampling.parquet.
    _write_native_dumper_cache(cache)
    datasets = [
        {
            "name": "cpu_sampling",
            "kind": "parquet",
            "path": "cpu_sampling.parquet",
            "schema_version": 1,
            "row_count": 1,
            "materialize_on_load": True,
        }
    ]
    for _, stem in trace_mgmt._DUMPER_EVENT_CLASSES.values():
        datasets.append({
            "name": stem,
            "kind": "dumper-parquet",
            "path": f"{stem}.parquet",
            "schema_version": 1,
            "row_count": 0,
            "materialize_on_load": False,
        })
    manifest = {
        "schema_version": native_cache.SCHEMA_VERSION,
        "mode": "native",
        "producer": "native",
        "strategy": native_cache.MATERIALIZED_SMALL_STRATEGY,
        "complete": True,
        "finalized": True,
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "etl": {
            "path": str(etl.resolve()),
            "name": etl.name,
            "size": etl.stat().st_size,
            "mtime_ns": etl.stat().st_mtime_ns,
        },
        "datasets": datasets,
        "native_store": {"generation_id": "flat", "path": "."},
    }
    (cache / native_cache.MANIFEST_FILENAME).write_text(
        json.dumps(manifest), encoding="utf-8"
    )

    assert trace_mgmt._load_from_cache(cache, etl, mode="native") is None
