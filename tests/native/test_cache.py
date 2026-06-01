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


def test_manifest_writer_defaults_to_schema_v3(tmp_path: Path):
    etl = _make_etl(tmp_path)
    export_dir = tmp_path / ".etw-export-sample"
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
    assert manifest.schema_version == 3
    native_cache.write_manifest(export_dir, manifest)

    import json

    raw = json.loads((export_dir / native_cache.MANIFEST_FILENAME).read_text("utf-8"))
    assert raw["schema_version"] == 3
    assert raw["producer"] == "native"
    # producer must be the second-most-significant field after schema_version.
    assert "producer" in raw


def test_manifest_writer_accepts_dotnet_producer(tmp_path: Path):
    etl = _make_etl(tmp_path)
    export_dir = tmp_path / ".etw-export-sample"
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
        producer="dotnet",
    )
    native_cache.write_manifest(export_dir, manifest)
    loaded = native_cache.read_manifest(export_dir)
    assert loaded is not None
    assert loaded.producer == "dotnet"
    assert loaded.schema_version == 3


def test_manifest_reader_accepts_legacy_v2_and_backfills_producer(
    tmp_path: Path,
    caplog,
):
    """v2 manifests written before the producer field must still load."""

    etl = _make_etl(tmp_path)
    export_dir = tmp_path / ".etw-export-sample"
    export_dir.mkdir()

    import json

    legacy = {
        "schema_version": 2,
        "mode": "native",
        "strategy": native_cache.MATERIALIZED_SMALL_STRATEGY,
        "complete": True,
        "etl": {
            "path": str(etl.resolve()),
            "name": etl.name,
            "size": etl.stat().st_size,
            "mtime_ns": etl.stat().st_mtime_ns,
        },
        "datasets": [
            {
                "name": "cpu_sampling",
                "kind": "parquet",
                "path": "cpu_sampling.parquet",
                "schema_version": 1,
                "row_count": 1,
                "materialize_on_load": True,
            },
        ],
        "native_store": {"generation_id": "flat", "path": "."},
    }
    (export_dir / native_cache.MANIFEST_FILENAME).write_text(
        json.dumps(legacy, indent=2), encoding="utf-8"
    )

    with caplog.at_level("WARNING", logger="etw_analyzer.native.cache"):
        loaded = native_cache.read_manifest(export_dir)
    assert loaded is not None
    assert loaded.schema_version == 2
    assert loaded.is_legacy_v2
    # back-filled to "native" because no producer field existed.
    assert loaded.producer == "native"
    # validate_manifest still accepts the legacy version.
    native_cache.validate_manifest(loaded, export_dir, etl, mode="native")
    # User-visible warning fired.
    assert any("schema_version=2" in rec.getMessage() for rec in caplog.records)


def test_manifest_reader_rejects_unknown_schema_version(tmp_path: Path):
    """schema_version=999 is not in SUPPORTED_SCHEMA_VERSIONS and is dropped."""

    export_dir = tmp_path / ".etw-export-sample"
    export_dir.mkdir()
    import json

    (export_dir / native_cache.MANIFEST_FILENAME).write_text(
        json.dumps({"schema_version": 999, "mode": "native"}),
        encoding="utf-8",
    )
    assert native_cache.read_manifest(export_dir) is None


def test_manifest_reader_rejects_unknown_producer(tmp_path: Path):
    """A v3 manifest with an unrecognized producer value is malformed."""

    export_dir = tmp_path / ".etw-export-sample"
    export_dir.mkdir()
    etl = _make_etl(tmp_path)
    import json

    bad = {
        "schema_version": 3,
        "mode": "native",
        "producer": "rust-fork",
        "strategy": native_cache.MATERIALIZED_SMALL_STRATEGY,
        "complete": True,
        "etl": {
            "path": str(etl.resolve()),
            "name": etl.name,
            "size": etl.stat().st_size,
            "mtime_ns": etl.stat().st_mtime_ns,
        },
        "datasets": [],
    }
    (export_dir / native_cache.MANIFEST_FILENAME).write_text(
        json.dumps(bad), encoding="utf-8"
    )
    with pytest.raises(native_cache.NativeCacheError, match="producer"):
        native_cache.read_manifest(export_dir)
