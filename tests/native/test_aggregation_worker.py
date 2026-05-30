"""Tests for the post-sidecar aggregation worker.

The aggregation worker is invoked AFTER the C# sidecar has written its
layer-1/2 parquets and a v3 manifest into a staging directory. It runs
the Python-side aggregators against those inputs and rewrites the manifest
in place. These tests verify the orchestration mechanics with synthetic
data; the real-fixture end-to-end test lives in tests/manual/.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer.native import aggregation_worker
from etw_analyzer.native import cache as native_cache


def _make_etl(tmp_path: Path) -> Path:
    etl = tmp_path / "sample.etl"
    etl.write_bytes(b"synthetic etl")
    return etl


def _seed_sidecar_staging(staging_dir: Path, etl: Path) -> None:
    """Write a minimal sidecar-style staging dir (parquets + v3 manifest)."""

    staging_dir.mkdir(parents=True, exist_ok=True)

    # SampledProfile — the only dataset the cpu_sampling synthesis needs.
    sampled = pd.DataFrame({
        "Process Name": ["echo_server.exe", "echo_server.exe", "idle.exe"],
        "PID": [1234, 1234, 0],
        "TID": [11, 12, 0],
        "CPU": [0, 1, 0],
        "Module": ["echo_server.exe", "echo_server.exe", "ntoskrnl.exe"],
        "Function": ["main", "worker", "KiIdleLoop"],
        "Weight": [10, 20, 5],
        "TimeStamp": [100, 200, 300],
        "Stack": [None, None, None],
    })
    sampled.to_parquet(staging_dir / "sampled_profile.parquet", index=False)

    # Aux: process table for PID → name lookups.
    process = pd.DataFrame({
        "PID": [1234, 0],
        "Process Name": ["echo_server.exe", "idle.exe"],
        "StartTime": [0, 0],
    })
    process.to_parquet(staging_dir / "process.parquet", index=False)

    # sysconfig text passthrough.
    (staging_dir / "sysconfig.txt").write_text(
        "Test sysconfig\nCPU Count: 8\n", encoding="utf-8"
    )

    datasets = [
        native_cache.CacheDataset(
            name="sampled_profile",
            kind="parquet",
            path="sampled_profile.parquet",
            row_count=len(sampled),
            materialize_on_load=True,
        ),
        native_cache.CacheDataset(
            name="process",
            kind="parquet",
            path="process.parquet",
            row_count=len(process),
            materialize_on_load=True,
        ),
        native_cache.CacheDataset(
            name="sysconfig",
            kind="text",
            path="sysconfig.txt",
            row_count=1,
            materialize_on_load=True,
        ),
    ]
    manifest = native_cache.CacheManifest.materialized_small(
        etl,
        datasets,
        producer="dotnet",
    )
    native_cache.write_manifest(staging_dir, manifest)


def test_run_aggregation_worker_against_dotnet_staging(tmp_path: Path):
    etl = _make_etl(tmp_path)
    staging = tmp_path / "staging"
    _seed_sidecar_staging(staging, etl)

    result = aggregation_worker.run_aggregation_worker(
        staging,
        etl,
        trace_id="trace_test_dotnet",
    )
    assert result.ok is True, f"failed: {result.message}; warnings={result.warnings}"
    # Manifest must still be valid v3 with the dotnet producer stamp.
    loaded = native_cache.read_manifest(staging)
    assert loaded is not None
    assert loaded.schema_version == 3
    assert loaded.producer == "dotnet"
    assert loaded.complete is True
    # The sidecar-original datasets must still be there.
    names = {d.name for d in loaded.datasets}
    assert "sampled_profile" in names
    assert "process" in names
    assert "sysconfig" in names


def test_run_aggregation_worker_synthesizes_cpu_sampling(tmp_path: Path):
    """Even with a tiny SampledProfile DataFrame, cpu_sampling must appear."""

    etl = _make_etl(tmp_path)
    staging = tmp_path / "staging"
    _seed_sidecar_staging(staging, etl)

    result = aggregation_worker.run_aggregation_worker(
        staging,
        etl,
        trace_id="trace_test_synth",
    )
    assert result.ok is True
    cpu_sampling = staging / "cpu_sampling.parquet"
    assert cpu_sampling.exists()
    # The aggregated frame should preserve the input weight totals.
    df = pd.read_parquet(cpu_sampling)
    assert df["Weight"].sum() == 35
    # Process Name column must be populated.
    assert set(df["Process Name"]) == {"echo_server.exe", "idle.exe"}


def test_run_aggregation_worker_missing_staging_dir(tmp_path: Path):
    etl = _make_etl(tmp_path)
    result = aggregation_worker.run_aggregation_worker(
        tmp_path / "nope",
        etl,
        trace_id="trace_missing",
    )
    assert result.ok is False
    assert "does not exist" in result.message


def test_run_aggregation_worker_missing_manifest(tmp_path: Path):
    etl = _make_etl(tmp_path)
    staging = tmp_path / "staging"
    staging.mkdir()
    # Drop a parquet but no manifest — the worker must refuse rather than
    # guess what the sidecar produced.
    pd.DataFrame({"x": [1]}).to_parquet(staging / "sampled_profile.parquet")

    result = aggregation_worker.run_aggregation_worker(
        staging,
        etl,
        trace_id="trace_no_manifest",
    )
    assert result.ok is False
    assert "manifest" in result.message.lower()


def test_run_aggregation_worker_preserves_dotnet_producer_in_rewrite(tmp_path: Path):
    """The rewritten manifest must keep producer='dotnet' when that's input."""

    etl = _make_etl(tmp_path)
    staging = tmp_path / "staging"
    _seed_sidecar_staging(staging, etl)

    result = aggregation_worker.run_aggregation_worker(
        staging,
        etl,
        trace_id="trace_producer_check",
        producer="dotnet",
    )
    assert result.ok is True

    raw = json.loads(
        (staging / native_cache.MANIFEST_FILENAME).read_text("utf-8")
    )
    assert raw["producer"] == "dotnet"
    assert raw["schema_version"] == 3


def test_run_aggregation_worker_handles_garbage_parquet_in_aux(tmp_path: Path):
    """A corrupt aux parquet must be warned-about, not fail the whole run."""

    etl = _make_etl(tmp_path)
    staging = tmp_path / "staging"
    _seed_sidecar_staging(staging, etl)
    # Overwrite process.parquet with non-parquet bytes.
    (staging / "process.parquet").write_bytes(b"NOT PARQUET")

    result = aggregation_worker.run_aggregation_worker(
        staging,
        etl,
        trace_id="trace_corrupt",
    )
    assert result.ok is True
    assert any("process.parquet" in w for w in result.warnings)
