"""Native cache v2 manifest helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


MANIFEST_FILENAME = "wpr-mcp-cache-manifest.json"
SCHEMA_VERSION = 2
DATASET_SCHEMA_VERSION = 1
MATERIALIZED_SMALL_STRATEGY = "materialized-small"
STREAMING_EVENT_STORE_STRATEGY = "event-store-streaming"
DEFAULT_GENERATION_ID = "flat"
DEFAULT_GENERATION_PATH = "."


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

    @classmethod
    def materialized_small(
        cls,
        etl_path: Path,
        datasets: list[CacheDataset],
        *,
        complete: bool = True,
        native_store: NativeStoreGeneration | None = None,
    ) -> "CacheManifest":
        return cls(
            schema_version=SCHEMA_VERSION,
            mode="native",
            strategy=MATERIALIZED_SMALL_STRATEGY,
            complete=complete,
            etl=EtlIdentity.from_path(etl_path),
            datasets=datasets,
            native_store=native_store or NativeStoreGeneration.flat(),
        )

    @classmethod
    def event_store_streaming(
        cls,
        etl_path: Path,
        datasets: list[CacheDataset],
        *,
        complete: bool = True,
        native_store: NativeStoreGeneration | None = None,
    ) -> "CacheManifest":
        return cls(
            schema_version=SCHEMA_VERSION,
            mode="native",
            strategy=STREAMING_EVENT_STORE_STRATEGY,
            complete=complete,
            etl=EtlIdentity.from_path(etl_path),
            datasets=datasets,
            native_store=native_store or NativeStoreGeneration.flat(),
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
        native_store = data.get("native_store")
        return cls(
            schema_version=int(data.get("schema_version", -1)),
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
        )

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "strategy": self.strategy,
            "complete": self.complete,
            "etl": self.etl.to_dict(),
            "datasets": [dataset.to_dict() for dataset in self.datasets],
        }
        if self.native_store is not None:
            data["native_store"] = self.native_store.to_dict()
        return data


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
    if data.get("schema_version") != SCHEMA_VERSION:
        return None
    return CacheManifest.from_dict(data)


def write_manifest(export_dir: Path, manifest: CacheManifest) -> None:
    validate_manifest_shape(manifest, export_dir)
    export_dir.mkdir(parents=True, exist_ok=True)
    manifest_path(export_dir).write_text(
        json.dumps(manifest.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )


def validate_manifest_shape(
    manifest: CacheManifest,
    export_dir: Path,
) -> None:
    if manifest.schema_version != SCHEMA_VERSION:
        raise NativeCacheError(
            f"unsupported native cache schema_version {manifest.schema_version!r}"
        )
    if manifest.mode != "native":
        raise NativeCacheError("native cache manifest mode must be 'native'")
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


def validate_manifest(
    manifest: CacheManifest,
    export_dir: Path,
    etl_path: Path,
    *,
    mode: str = "native",
) -> None:
    validate_manifest_shape(manifest, export_dir)
    if manifest.mode != mode:
        raise NativeCacheError(
            f"native cache manifest mode {manifest.mode!r} does not match {mode!r}"
        )
    if manifest.complete is not True:
        raise NativeCacheError("native cache manifest is incomplete")
    if not manifest.etl.matches(etl_path):
        raise NativeCacheError("native cache manifest ETL identity is stale")


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
