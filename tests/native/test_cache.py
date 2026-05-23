from __future__ import annotations

from pathlib import Path

import pytest

from etw_analyzer.native import cache as native_cache


def _make_etl(tmp_path: Path) -> Path:
    etl = tmp_path / "sample.etl"
    etl.write_bytes(b"synthetic etl")
    return etl


def test_native_v2_manifest_round_trips_materialized_small_generation(tmp_path: Path):
    etl = _make_etl(tmp_path)
    export_dir = tmp_path / ".etw-export-sample"
    generation_dir = export_dir / "generation-001"
    generation_dir.mkdir(parents=True)

    manifest = native_cache.CacheManifest.materialized_small(
        etl,
        [
            native_cache.CacheDataset(
                name="cpu_sampling",
                kind="parquet",
                path="cpu_sampling.parquet",
                row_count=42,
                materialize_on_load=True,
            )
        ],
        native_store=native_cache.NativeStoreGeneration(
            generation_id="generation-001",
            path="generation-001",
        ),
    )

    native_cache.write_manifest(export_dir, manifest)
    loaded = native_cache.read_manifest(export_dir)

    assert loaded is not None
    assert loaded.schema_version == native_cache.SCHEMA_VERSION
    assert loaded.mode == "native"
    assert loaded.strategy == native_cache.MATERIALIZED_SMALL_STRATEGY
    assert loaded.complete is True
    assert loaded.etl.name == etl.name
    assert loaded.etl.size == etl.stat().st_size
    assert loaded.etl.mtime_ns == etl.stat().st_mtime_ns
    assert loaded.native_store is not None
    assert loaded.native_store.generation_id == "generation-001"
    assert loaded.datasets[0].name == "cpu_sampling"
    assert loaded.datasets[0].row_count == 42

    native_cache.validate_manifest(loaded, export_dir, etl)
    assert native_cache.resolve_dataset_path(
        export_dir,
        loaded,
        loaded.datasets[0],
    ) == (generation_dir / "cpu_sampling.parquet").resolve()


def test_native_v2_manifest_rejects_dataset_path_escape_generation(tmp_path: Path):
    etl = _make_etl(tmp_path)
    export_dir = tmp_path / ".etw-export-sample"
    manifest = native_cache.CacheManifest.materialized_small(
        etl,
        [
            native_cache.CacheDataset(
                name="cpu_sampling",
                kind="parquet",
                path="..\\cpu_sampling.parquet",
                row_count=1,
                materialize_on_load=True,
            )
        ],
        native_store=native_cache.NativeStoreGeneration(
            generation_id="generation-001",
            path="generation-001",
        ),
    )

    with pytest.raises(native_cache.NativeCacheError):
        native_cache.validate_manifest_shape(manifest, export_dir)
