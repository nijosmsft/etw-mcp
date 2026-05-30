"""Native cache v2 manifest helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


MANIFEST_FILENAME = "wpr-mcp-cache-manifest.json"
SCHEMA_VERSION = 3
LEGACY_SCHEMA_VERSIONS = frozenset({2})
SUPPORTED_SCHEMA_VERSIONS = frozenset({2, 3})
DATASET_SCHEMA_VERSION = 1
MATERIALIZED_SMALL_STRATEGY = "materialized-small"
STREAMING_EVENT_STORE_STRATEGY = "event-store-streaming"
DEFAULT_GENERATION_ID = "flat"
DEFAULT_GENERATION_PATH = "."

# Allowed values for the schema-v3 ``producer`` field. Anything else is
# treated as a malformed manifest and rejected.
VALID_PRODUCERS = frozenset({"csharp", "native", "xperf"})
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

    def matches_loose(self, etl_path: Path) -> bool:
        """Identity match ignoring ``mtime_ns``.

        The C# sidecar currently encodes ``mtime_ns`` as .NET ``Ticks * 100``
        (nanoseconds since year 0001) rather than Python's ``st_mtime_ns``
        (nanoseconds since Unix epoch 1970). The two will never line up.

        Until the C# emitter is fixed, csharp-producer manifests use the
        loose check — same filename + same size — which is enough to catch
        the "ETL was replaced by a different file" case without breaking
        on the cross-runtime epoch mismatch. Same-size in-place edits will
        return a stale cache; this is an accepted POC trade-off.
        """

        try:
            current = EtlIdentity.from_path(etl_path)
        except OSError:
            return False
        return self.name == current.name and self.size == current.size


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
    # Schema v3 adds the producer field. For legacy v2 manifests this
    # is back-filled to "native" (the only producer that wrote v2).
    producer: str = DEFAULT_LEGACY_PRODUCER

    @classmethod
    def materialized_small(
        cls,
        etl_path: Path,
        datasets: list[CacheDataset],
        *,
        complete: bool = True,
        native_store: NativeStoreGeneration | None = None,
        producer: str = DEFAULT_LEGACY_PRODUCER,
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
        )

    @classmethod
    def event_store_streaming(
        cls,
        etl_path: Path,
        datasets: list[CacheDataset],
        *,
        complete: bool = True,
        native_store: NativeStoreGeneration | None = None,
        producer: str = DEFAULT_LEGACY_PRODUCER,
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
        schema_version = int(data.get("schema_version", -1))
        # v2 manifests have no producer field — back-fill it to "native"
        # so downstream consumers can branch on it uniformly. v3 manifests
        # MUST carry a recognized producer value.
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
        )

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "producer": self.producer,
            "strategy": self.strategy,
            "complete": self.complete,
            "etl": self.etl.to_dict(),
            "datasets": [dataset.to_dict() for dataset in self.datasets],
        }
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
    if manifest.is_legacy_v2:
        # Surface a soft signal to operators that this cache predates the
        # producer field. We don't rewrite it — that would invalidate the
        # operator's existing ETL-identity match — but we do flag it.
        import logging

        logging.getLogger(__name__).warning(
            "loaded legacy schema_version=2 native cache manifest at %s; "
            "producer field defaulted to %r. Use force=True to regenerate "
            "with schema_version=%d.",
            path,
            DEFAULT_LEGACY_PRODUCER,
            SCHEMA_VERSION,
        )
    return manifest


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
    # csharp-produced manifests carry an mtime_ns encoded in .NET ticks
    # rather than Python's st_mtime_ns. Fall back to size + name matching
    # for those until the C# sidecar emitter is harmonised. Native- and
    # xperf-written manifests still get the strict three-field check.
    if manifest.producer == "csharp":
        identity_ok = manifest.etl.matches_loose(etl_path)
    else:
        identity_ok = manifest.etl.matches(etl_path)
    if not identity_ok:
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
