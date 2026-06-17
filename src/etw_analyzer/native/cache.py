"""Native cache v2 manifest helpers."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from etw_analyzer.native.schemas import EVENT_SCHEMA_VERSION


# NOTE: The on-disk filename intentionally retains the "wpr-mcp-" prefix
# even after the v0.4 etw-mcp rename. Renaming it would silently
# invalidate every user's existing on-disk extracted-parquet cache —
# their next load_trace would miss the cache and re-extract from scratch.
# The same string is written by the C# sidecar's ManifestEmitter and
# read by trace_mgmt.py's _CACHE_MANIFEST_FILENAME constant.
MANIFEST_FILENAME = "wpr-mcp-cache-manifest.json"
SCHEMA_VERSION = 4
LEGACY_SCHEMA_VERSIONS = frozenset({2, 3})
SUPPORTED_SCHEMA_VERSIONS = frozenset({4})
DATASET_SCHEMA_VERSION = 1
MATERIALIZED_SMALL_STRATEGY = "materialized-small"
STREAMING_EVENT_STORE_STRATEGY = "event-store-streaming"
DEFAULT_GENERATION_ID = "flat"
DEFAULT_GENERATION_PATH = "."

# Allowed values for the schema-v4 ``producer`` field. Anything else is
# treated as a malformed manifest and rejected.
VALID_PRODUCERS = frozenset({"dotnet", "native", "xperf"})
DEFAULT_LEGACY_PRODUCER = "native"


class NativeCacheError(ValueError):
    """Raised when a native cache manifest is invalid or unsafe."""


@dataclass(frozen=True)
class EtlIdentity:
    path: str
    name: str
    size: int
    mtime_ns: int

    @classmethod
    def from_path(cls, etl_path: Path) -> "EtlIdentity":
        stat = etl_path.stat()
        resolved = etl_path.resolve()
        return cls(
            path=str(resolved),
            name=resolved.name,
            size=int(stat.st_size),
            mtime_ns=int(stat.st_mtime_ns),
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EtlIdentity":
        return cls(
            path=str(data.get("path", "")),
            name=str(data.get("name", "")),
            size=int(data.get("size", -1)),
            mtime_ns=int(data.get("mtime_ns", -1)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "name": self.name,
            "size": self.size,
            "mtime_ns": self.mtime_ns,
        }

    def matches(self, etl_path: Path) -> bool:
        try:
            current = EtlIdentity.from_path(etl_path)
        except OSError:
            return False
        return (
            self.name == current.name
            and self.size == current.size
            and self.mtime_ns == current.mtime_ns
        )


@dataclass(frozen=True)
class NativeStoreGeneration:
    generation_id: str
    path: str

    @classmethod
    def flat(cls) -> "NativeStoreGeneration":
        return cls(
            generation_id=DEFAULT_GENERATION_ID,
            path=DEFAULT_GENERATION_PATH,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NativeStoreGeneration":
        return cls(
            generation_id=str(data.get("generation_id", "")),
            path=str(data.get("path", DEFAULT_GENERATION_PATH)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "generation_id": self.generation_id,
            "path": self.path,
        }


@dataclass(frozen=True)
class CacheDataset:
    name: str
    kind: str
    path: str
    schema_version: int = DATASET_SCHEMA_VERSION
    row_count: int | None = None
    materialize_on_load: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CacheDataset":
        row_count = data.get("row_count")
        materialize = data.get("materialize_on_load", True)
        if not isinstance(materialize, bool):
            raise NativeCacheError(
                f"native cache dataset {data.get('name', '')!r} has non-boolean "
                "materialize_on_load"
            )
        return cls(
            name=str(data.get("name", "")),
            kind=str(data.get("kind", "")),
            path=str(data.get("path", "")),
            schema_version=int(data.get("schema_version", DATASET_SCHEMA_VERSION)),
            row_count=None if row_count is None else int(row_count),
            materialize_on_load=materialize,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "path": self.path,
            "schema_version": self.schema_version,
            "row_count": self.row_count,
            "materialize_on_load": self.materialize_on_load,
        }


@dataclass(frozen=True)
class CacheManifest:
    schema_version: int
    mode: str
    strategy: str
    complete: bool
    etl: EtlIdentity
    datasets: list[CacheDataset] = field(default_factory=list)
    native_store: NativeStoreGeneration | None = None
    # Schema v3 added the producer field. Schema v4 keeps it and adds the
    # finalized completion gate.
    producer: str = DEFAULT_LEGACY_PRODUCER
    # M2: event_schema_version tracks the native image-parquet schema so
    # _load_native_v2_from_cache can reject caches written before M2 (which
    # lack PdbGuid/PdbAge/PdbName/TimeDateStamp columns).  Defaults to the
    # current EVENT_SCHEMA_VERSION so every CacheManifest built in-process
    # carries the correct value automatically; old on-disk manifests that
    # were written without this field default to 0 on read (see from_dict)
    # and are therefore treated as stale by the cache loader.
    event_schema_version: int = EVENT_SCHEMA_VERSION
    finalized: bool = True
    finalized_at: str | None = None
    finalizer: str | None = "python"

    @classmethod
    def materialized_small(
        cls,
        etl_path: Path,
        datasets: list[CacheDataset],
        *,
        complete: bool = True,
        finalized: bool | None = None,
        native_store: NativeStoreGeneration | None = None,
        producer: str = DEFAULT_LEGACY_PRODUCER,
        finalizer: str | None = "python",
    ) -> "CacheManifest":
        return cls(
            schema_version=SCHEMA_VERSION,
            mode="native",
            strategy=MATERIALIZED_SMALL_STRATEGY,
            complete=complete,
            etl=EtlIdentity.from_path(etl_path),
            datasets=datasets,
            native_store=native_store or NativeStoreGeneration.flat(),
            producer=producer,
            finalized=complete if finalized is None else finalized,
            finalizer=finalizer,
        )

    @classmethod
    def event_store_streaming(
        cls,
        etl_path: Path,
        datasets: list[CacheDataset],
        *,
        complete: bool = True,
        finalized: bool | None = None,
        native_store: NativeStoreGeneration | None = None,
        producer: str = DEFAULT_LEGACY_PRODUCER,
        finalizer: str | None = "python",
    ) -> "CacheManifest":
        return cls(
            schema_version=SCHEMA_VERSION,
            mode="native",
            strategy=STREAMING_EVENT_STORE_STRATEGY,
            complete=complete,
            etl=EtlIdentity.from_path(etl_path),
            datasets=datasets,
            native_store=native_store or NativeStoreGeneration.flat(),
            producer=producer,
            finalized=complete if finalized is None else finalized,
            finalizer=finalizer,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CacheManifest":
        etl = data.get("etl")
        if not isinstance(etl, dict):
            raise NativeCacheError("native cache manifest is missing ETL identity")
        datasets = data.get("datasets", [])
        if not isinstance(datasets, list):
            raise NativeCacheError("native cache manifest datasets must be a list")
        parsed_datasets: list[CacheDataset] = []
        for item in datasets:
            if not isinstance(item, dict):
                raise NativeCacheError("native cache manifest dataset must be an object")
            parsed_datasets.append(CacheDataset.from_dict(item))
        complete = data.get("complete", False)
        if not isinstance(complete, bool):
            raise NativeCacheError("native cache manifest complete must be a boolean")
        finalized = data.get("finalized", False)
        if not isinstance(finalized, bool):
            raise NativeCacheError("native cache manifest finalized must be a boolean")
        finalized_at = data.get("finalized_at")
        if finalized_at is not None and not isinstance(finalized_at, str):
            raise NativeCacheError("native cache manifest finalized_at must be a string")
        finalizer = data.get("finalizer")
        if finalizer is not None and not isinstance(finalizer, str):
            raise NativeCacheError("native cache manifest finalizer must be a string")
        native_store = data.get("native_store")
        schema_version = int(data.get("schema_version", -1))
        # v2 manifests have no producer field — back-fill it to "native"
        # so from_dict remains tolerant. Supported v4 manifests MUST carry
        # a recognized producer value.
        raw_producer = data.get("producer")
        if raw_producer is None:
            producer = DEFAULT_LEGACY_PRODUCER
        else:
            if not isinstance(raw_producer, str):
                raise NativeCacheError(
                    "native cache manifest producer must be a string"
                )
            if raw_producer not in VALID_PRODUCERS:
                raise NativeCacheError(
                    f"native cache manifest producer {raw_producer!r} is not one of "
                    f"{sorted(VALID_PRODUCERS)}"
                )
            producer = raw_producer
        return cls(
            schema_version=schema_version,
            mode=str(data.get("mode", "")),
            strategy=str(data.get("strategy", "")),
            complete=complete,
            etl=EtlIdentity.from_dict(etl),
            datasets=parsed_datasets,
            native_store=(
                NativeStoreGeneration.from_dict(native_store)
                if isinstance(native_store, dict)
                else None
            ),
            producer=producer,
            # Old manifests lack this field; default 0 means "unknown/pre-M2"
            # so the cache loader treats them as stale.
            event_schema_version=int(data.get("event_schema_version", 0)),
            finalized=finalized,
            finalized_at=finalized_at,
            finalizer=finalizer,
        )

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "producer": self.producer,
            "strategy": self.strategy,
            "complete": self.complete,
            "finalized": self.finalized,
            "event_schema_version": self.event_schema_version,
            "etl": self.etl.to_dict(),
            "datasets": [dataset.to_dict() for dataset in self.datasets],
            "dataset_count": len(self.datasets),
        }
        if self.finalized and self.finalized_at is None:
            data["finalized_at"] = datetime.now(timezone.utc).isoformat()
        elif self.finalized_at is not None:
            data["finalized_at"] = self.finalized_at
        if self.finalizer is not None:
            data["finalizer"] = self.finalizer
        if self.native_store is not None:
            data["native_store"] = self.native_store.to_dict()
        return data

    @property
    def is_legacy_v2(self) -> bool:
        """True when this manifest was produced under schema_version=2."""

        return self.schema_version in LEGACY_SCHEMA_VERSIONS


def manifest_path(export_dir: Path) -> Path:
    return export_dir / MANIFEST_FILENAME


def read_manifest(export_dir: Path) -> CacheManifest | None:
    path = manifest_path(export_dir)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise NativeCacheError(f"native cache manifest is unreadable: {exc}") from exc
    if not isinstance(data, dict):
        raise NativeCacheError("native cache manifest must be a JSON object")
    schema = data.get("schema_version")
    if schema not in SUPPORTED_SCHEMA_VERSIONS:
        return None
    manifest = CacheManifest.from_dict(data)
    return manifest


def write_manifest(export_dir: Path, manifest: CacheManifest) -> None:
    validate_manifest_shape(manifest, export_dir)
    if manifest.complete and manifest.finalized:
        validate_manifest_datasets_exist(manifest, export_dir)
    export_dir.mkdir(parents=True, exist_ok=True)
    final_path = manifest_path(export_dir)
    temp_path = export_dir / (
        f"{MANIFEST_FILENAME}.tmp.{os.getpid()}.{uuid.uuid4().hex}"
    )
    try:
        with temp_path.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(manifest.to_dict(), indent=2, sort_keys=True))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, final_path)
    finally:
        temp_path.unlink(missing_ok=True)


def validate_manifest_shape(
    manifest: CacheManifest,
    export_dir: Path,
) -> None:
    if manifest.schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise NativeCacheError(
            f"unsupported native cache schema_version {manifest.schema_version!r}"
        )
    if manifest.mode != "native":
        raise NativeCacheError("native cache manifest mode must be 'native'")
    if manifest.producer not in VALID_PRODUCERS:
        raise NativeCacheError(
            f"native cache manifest producer {manifest.producer!r} is not one of "
            f"{sorted(VALID_PRODUCERS)}"
        )
    if not manifest.strategy:
        raise NativeCacheError("native cache manifest is missing strategy")
    if manifest.native_store is not None:
        if not manifest.native_store.generation_id:
            raise NativeCacheError("native cache manifest is missing generation_id")
        resolve_generation_dir(export_dir, manifest.native_store)
    names: set[str] = set()
    for dataset in manifest.datasets:
        if not dataset.name:
            raise NativeCacheError("native cache dataset is missing name")
        if dataset.name in names:
            raise NativeCacheError(f"duplicate native cache dataset {dataset.name!r}")
        names.add(dataset.name)
        if not dataset.kind:
            raise NativeCacheError(
                f"native cache dataset {dataset.name!r} is missing kind"
            )
        if not dataset.path:
            raise NativeCacheError(
                f"native cache dataset {dataset.name!r} is missing path"
            )
        if dataset.schema_version <= 0:
            raise NativeCacheError(
                f"native cache dataset {dataset.name!r} has invalid schema_version"
            )
        resolve_dataset_path(export_dir, manifest, dataset)


def validate_manifest_datasets_exist(
    manifest: CacheManifest,
    export_dir: Path,
) -> None:
    for dataset in manifest.datasets:
        path = resolve_dataset_path(export_dir, manifest, dataset)
        if not path.exists():
            raise NativeCacheError(
                f"native cache dataset {dataset.name!r} is listed but missing: {path}"
            )


def validate_manifest(
    manifest: CacheManifest,
    export_dir: Path,
    etl_path: Path,
    *,
    mode: str = "native",
    require_complete: bool = True,
    require_current_event_schema: bool = True,
    require_dataset_files: bool = True,
) -> None:
    validate_manifest_shape(manifest, export_dir)
    if manifest.mode != mode:
        raise NativeCacheError(
            f"native cache manifest mode {manifest.mode!r} does not match {mode!r}"
        )
    if require_complete:
        if manifest.complete is not True:
            raise NativeCacheError("native cache manifest is incomplete")
        if manifest.finalized is not True:
            raise NativeCacheError("native cache manifest is not finalized")
    if (
        require_current_event_schema
        and manifest.event_schema_version != EVENT_SCHEMA_VERSION
    ):
        raise NativeCacheError(
            "native cache manifest event_schema_version "
            f"{manifest.event_schema_version!r} does not match "
            f"{EVENT_SCHEMA_VERSION!r}"
        )
    # All producers (dotnet, native, xperf) emit Unix-epoch ``st_mtime_ns``
    # so the identity check is uniform — the strict three-field match
    # catches both content swaps and in-place edits.
    if not manifest.etl.matches(etl_path):
        raise NativeCacheError("native cache manifest ETL identity is stale")
    if require_dataset_files:
        validate_manifest_datasets_exist(manifest, export_dir)


def resolve_generation_dir(
    export_dir: Path,
    native_store: NativeStoreGeneration | None,
) -> Path:
    relative = native_store.path if native_store is not None else DEFAULT_GENERATION_PATH
    if _unsafe_relative_path(relative):
        raise NativeCacheError(f"unsafe native cache generation path: {relative!r}")
    root = export_dir.resolve()
    generation = (export_dir / relative).resolve()
    if not _is_relative_to(generation, root):
        raise NativeCacheError("native cache generation path escapes export_dir")
    return generation


def resolve_dataset_path(
    export_dir: Path,
    manifest: CacheManifest,
    dataset: CacheDataset,
) -> Path:
    if _unsafe_relative_path(dataset.path):
        raise NativeCacheError(
            f"unsafe path for native cache dataset {dataset.name!r}: {dataset.path!r}"
        )
    generation = resolve_generation_dir(export_dir, manifest.native_store)
    path = (generation / dataset.path).resolve()
    if not _is_relative_to(path, generation):
        raise NativeCacheError(
            f"native cache dataset {dataset.name!r} escapes its generation"
        )
    return path


def _unsafe_relative_path(value: str) -> bool:
    path = Path(value)
    return path.is_absolute() or any(part == ".." for part in path.parts)


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
    except ValueError:
        return False
    return True
