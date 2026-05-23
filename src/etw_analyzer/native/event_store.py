"""Chunked native event-store manifest, writer, and scanner."""

from __future__ import annotations

import json
import math
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from etw_analyzer.parsing.aggregator import parse_cpu_filter

from .schemas import (
    EVENT_SCHEMA_VERSION,
    canonical_event_class,
    empty_table,
    schema_for_event_class,
)
from .sinks import (
    DEFAULT_MAX_BYTES_PER_PART,
    DEFAULT_MAX_ROWS_PER_PART,
    ParquetBatchWriter,
    WrittenPart,
)


STORE_SCHEMA_VERSION = 1
MANIFEST_FILENAME = "native-event-store-manifest.json"
NATIVE_STORE_ROOT = "native-store"
GENERATIONS_DIR = "generations"
STAGING_DIR = "staging"
EVENTS_DIR = "events"
NATIVE_EVENT_STORE_DATASET_KIND = "native-event-store"


class NativeEventStoreError(ValueError):
    """Raised when a native event-store manifest or dataset is invalid."""


@dataclass(frozen=True)
class EventStoreTimebase:
    """QPC timebase used to expose logical relative timestamps."""

    qpc_origin: int | None = None
    perf_freq: float | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "EventStoreTimebase":
        if not isinstance(data, dict):
            return cls()
        qpc_origin = data.get("qpc_origin")
        perf_freq = data.get("perf_freq")
        return cls(
            qpc_origin=None if qpc_origin is None else int(qpc_origin),
            perf_freq=None if perf_freq is None else float(perf_freq),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "qpc_origin": self.qpc_origin,
            "perf_freq": self.perf_freq,
        }

    def has_qpc_mapping(self) -> bool:
        return self.qpc_origin is not None and bool(self.perf_freq and self.perf_freq > 0)

    def start_seconds_to_qpc(self, seconds: float | None) -> int | None:
        if seconds is None or not self.has_qpc_mapping():
            return None
        return int(math.ceil(float(self.qpc_origin) + float(seconds) * float(self.perf_freq)))

    def end_seconds_to_qpc(self, seconds: float | None) -> int | None:
        if seconds is None or not self.has_qpc_mapping():
            return None
        return int(math.floor(float(self.qpc_origin) + float(seconds) * float(self.perf_freq)))


@dataclass(frozen=True)
class EventFilters:
    """Filters accepted by :meth:`NativeEventStore.scan`.

    ``start_time`` and ``end_time`` are seconds relative to trace start.
    When the store manifest includes ``qpc_origin`` and ``perf_freq`` they
    are converted to raw QPC for part pruning and row filtering.
    """

    cpu_filter: str | Iterable[int] | None = None
    start_time: float | None = None
    end_time: float | None = None
    start_qpc: int | None = None
    end_qpc: int | None = None

    def cpu_set(self) -> set[int] | None:
        if self.cpu_filter is None:
            return None
        if isinstance(self.cpu_filter, str):
            values = parse_cpu_filter(self.cpu_filter)
            return set(values or [])
        return {int(value) for value in self.cpu_filter}

    def qpc_range(self, timebase: EventStoreTimebase) -> tuple[int | None, int | None]:
        start = self.start_qpc
        end = self.end_qpc
        if start is None:
            start = timebase.start_seconds_to_qpc(self.start_time)
        if end is None:
            end = timebase.end_seconds_to_qpc(self.end_time)
        return start, end


@dataclass(frozen=True)
class EventPartRef:
    """Manifest reference to one parquet part."""

    path: str
    row_count: int
    min_qpc: int | None = None
    max_qpc: int | None = None
    byte_size: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EventPartRef":
        return cls(
            path=str(data.get("path", "")),
            row_count=int(data.get("row_count", 0)),
            min_qpc=_optional_int(data.get("min_qpc")),
            max_qpc=_optional_int(data.get("max_qpc")),
            byte_size=_optional_int(data.get("byte_size")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "row_count": self.row_count,
            "min_qpc": self.min_qpc,
            "max_qpc": self.max_qpc,
            "byte_size": self.byte_size,
        }


@dataclass(frozen=True)
class EventDatasetManifest:
    """Manifest metadata for one canonical event class."""

    name: str
    schema_version: int
    row_count: int
    parts: list[EventPartRef] = field(default_factory=list)
    min_qpc: int | None = None
    max_qpc: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EventDatasetManifest":
        parts = data.get("parts", [])
        if not isinstance(parts, list):
            raise NativeEventStoreError("event-store dataset parts must be a list")
        return cls(
            name=canonical_event_class(str(data.get("name", ""))),
            schema_version=int(data.get("schema_version", -1)),
            row_count=int(data.get("row_count", 0)),
            min_qpc=_optional_int(data.get("min_qpc")),
            max_qpc=_optional_int(data.get("max_qpc")),
            parts=[
                EventPartRef.from_dict(item)
                for item in parts
                if isinstance(item, dict)
            ],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "schema_version": self.schema_version,
            "row_count": self.row_count,
            "min_qpc": self.min_qpc,
            "max_qpc": self.max_qpc,
            "parts": [part.to_dict() for part in self.parts],
        }


@dataclass(frozen=True)
class EventStoreManifest:
    """Top-level native event-store manifest."""

    schema_version: int
    run_id: str
    timebase: EventStoreTimebase
    datasets: dict[str, EventDatasetManifest] = field(default_factory=dict)
    created_utc: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EventStoreManifest":
        raw_datasets = data.get("datasets", [])
        if not isinstance(raw_datasets, list):
            raise NativeEventStoreError("event-store manifest datasets must be a list")
        datasets: dict[str, EventDatasetManifest] = {}
        for item in raw_datasets:
            if not isinstance(item, dict):
                raise NativeEventStoreError("event-store dataset must be an object")
            dataset = EventDatasetManifest.from_dict(item)
            if dataset.name in datasets:
                raise NativeEventStoreError(f"duplicate event-store dataset {dataset.name!r}")
            datasets[dataset.name] = dataset
        return cls(
            schema_version=int(data.get("schema_version", -1)),
            run_id=str(data.get("run_id", "")),
            created_utc=(
                str(data.get("created_utc"))
                if data.get("created_utc") is not None
                else None
            ),
            timebase=EventStoreTimebase.from_dict(data.get("timebase")),
            datasets=datasets,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "created_utc": self.created_utc,
            "timebase": self.timebase.to_dict(),
            "datasets": [
                self.datasets[name].to_dict()
                for name in sorted(self.datasets)
            ],
        }


class NativeEventStore:
    """Read and validate chunked native event-store generations."""

    def __init__(
        self,
        *,
        export_dir: Path,
        generation_dir: Path,
        manifest: EventStoreManifest,
    ) -> None:
        self.export_dir = export_dir
        self.generation_dir = generation_dir
        self.manifest = manifest
        self.validate()

    @property
    def manifest_path(self) -> Path:
        return self.generation_dir / MANIFEST_FILENAME

    @property
    def timebase(self) -> EventStoreTimebase:
        return self.manifest.timebase

    @property
    def row_count(self) -> int:
        return sum(dataset.row_count for dataset in self.manifest.datasets.values())

    @classmethod
    def open(cls, generation_dir: Path | str, *, export_dir: Path | str | None = None) -> "NativeEventStore":
        generation_path = Path(generation_dir).resolve()
        manifest_path = generation_path / MANIFEST_FILENAME
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise NativeEventStoreError(f"event-store manifest is unreadable: {exc}") from exc
        if not isinstance(data, dict):
            raise NativeEventStoreError("event-store manifest must be a JSON object")
        root = Path(export_dir).resolve() if export_dir is not None else _infer_export_dir(generation_path)
        return cls(
            export_dir=root,
            generation_dir=generation_path,
            manifest=EventStoreManifest.from_dict(data),
        )

    @classmethod
    def open_generation(
        cls,
        export_dir: Path | str,
        run_id: str,
    ) -> "NativeEventStore":
        root = Path(export_dir).resolve()
        return cls.open(
            root / NATIVE_STORE_ROOT / GENERATIONS_DIR / run_id,
            export_dir=root,
        )

    @classmethod
    def open_from_cache_manifest(
        cls,
        export_dir: Path,
        cache_manifest: Any,
    ) -> "NativeEventStore | None":
        """Open the event-store dataset referenced by a native cache manifest."""

        from etw_analyzer.native import cache as native_cache

        for dataset in getattr(cache_manifest, "datasets", []):
            if dataset.kind != NATIVE_EVENT_STORE_DATASET_KIND:
                continue
            manifest_path = native_cache.resolve_dataset_path(
                export_dir,
                cache_manifest,
                dataset,
            )
            generation_dir = manifest_path if manifest_path.is_dir() else manifest_path.parent
            return cls.open(generation_dir, export_dir=export_dir)
        return None

    def cache_dataset(self):
        """Return a cache-v2 manifest dataset reference for this store."""

        from etw_analyzer.native import cache as native_cache

        rel = self.manifest_path.resolve().relative_to(self.export_dir.resolve())
        return native_cache.CacheDataset(
            name="native_event_store",
            kind=NATIVE_EVENT_STORE_DATASET_KIND,
            path=str(rel),
            schema_version=STORE_SCHEMA_VERSION,
            row_count=self.row_count,
            materialize_on_load=False,
        )

    def validate(self) -> None:
        """Validate manifest shape, part existence, part counts, and schemas."""

        manifest = self.manifest
        if manifest.schema_version != STORE_SCHEMA_VERSION:
            raise NativeEventStoreError(
                f"unsupported event-store schema_version {manifest.schema_version!r}"
            )
        if not manifest.run_id:
            raise NativeEventStoreError("event-store manifest is missing run_id")

        for dataset in manifest.datasets.values():
            expected_schema = schema_for_event_class(dataset.name)
            if dataset.schema_version != expected_schema.version:
                raise NativeEventStoreError(
                    f"event-store dataset {dataset.name!r} has unsupported "
                    f"schema_version {dataset.schema_version!r}"
                )
            listed_paths: set[Path] = set()
            row_count = 0
            for part in dataset.parts:
                part_path = _resolve_relative(self.generation_dir, part.path)
                listed_paths.add(part_path)
                if not part_path.exists():
                    raise NativeEventStoreError(
                        f"event-store part is missing: {part.path}"
                    )
                try:
                    parquet = pq.ParquetFile(part_path)
                except Exception as exc:
                    raise NativeEventStoreError(
                        f"event-store part is unreadable: {part.path}: {exc}"
                    ) from exc
                if int(parquet.metadata.num_rows) != part.row_count:
                    raise NativeEventStoreError(
                        f"event-store part row_count mismatch: {part.path}"
                    )
                _validate_arrow_schema(dataset.name, parquet.schema_arrow)
                row_count += part.row_count

            if row_count != dataset.row_count:
                raise NativeEventStoreError(
                    f"event-store dataset {dataset.name!r} row_count mismatch"
                )

            event_dir = self.generation_dir / EVENTS_DIR / dataset.name
            if event_dir.exists():
                extra = {
                    path.resolve()
                    for path in event_dir.glob("part-*.parquet")
                } - listed_paths
                if extra:
                    raise NativeEventStoreError(
                        f"event-store dataset {dataset.name!r} has unmanifested parts"
                    )

    def scan(
        self,
        event_class: str,
        *,
        filters: EventFilters | None = None,
        columns: list[str] | None = None,
        include_time: bool = True,
    ) -> pd.DataFrame:
        """Read an event dataset with optional CPU/time filters.

        Physical parquet files store raw QPC as ``TimeStampQpc``. When the
        manifest has a QPC origin and frequency, the returned DataFrame also
        includes logical ``TimeStamp`` in relative microseconds.
        """

        cname = canonical_event_class(event_class)
        event_filters = filters or EventFilters()
        start_qpc, end_qpc = event_filters.qpc_range(self.timebase)
        dataset = self.manifest.datasets.get(cname)
        schema = schema_for_event_class(cname).schema
        requested_columns = list(columns) if columns is not None else None

        if dataset is None or dataset.row_count == 0:
            df = empty_table(cname).to_pandas()
            return _finalize_scan_frame(
                df,
                schema,
                self.timebase,
                event_filters,
                start_qpc,
                end_qpc,
                requested_columns,
                include_time,
            )

        physical_columns = _physical_columns(schema, requested_columns, include_time)
        tables: list[pa.Table] = []
        for part in dataset.parts:
            if _part_excluded_by_qpc(part, start_qpc, end_qpc):
                continue
            part_path = _resolve_relative(self.generation_dir, part.path)
            table = pq.read_table(
                part_path,
                columns=physical_columns or None,
            )
            tables.append(table)

        if not tables:
            df = empty_table(cname).to_pandas()
        elif len(tables) == 1:
            df = tables[0].to_pandas()
        else:
            df = pa.concat_tables(tables, promote_options="default").to_pandas()

        return _finalize_scan_frame(
            df,
            schema,
            self.timebase,
            event_filters,
            start_qpc,
            end_qpc,
            requested_columns,
            include_time,
        )

    def iter_batches(
        self,
        event_class: str,
        *,
        filters: EventFilters | None = None,
        columns: list[str] | None = None,
        include_time: bool = True,
        batch_size: int = 65_536,
    ) -> Iterator[pd.DataFrame]:
        """Yield event rows as filtered pandas batches.

        This is the memory-bounded counterpart to :meth:`scan`: callers that
        build aggregate outputs can stream each parquet part without
        materializing the whole event class.
        """

        cname = canonical_event_class(event_class)
        event_filters = filters or EventFilters()
        start_qpc, end_qpc = event_filters.qpc_range(self.timebase)
        dataset = self.manifest.datasets.get(cname)
        if dataset is None or dataset.row_count == 0:
            return
        schema = schema_for_event_class(cname).schema
        requested_columns = list(columns) if columns is not None else None
        physical_columns = _physical_columns(schema, requested_columns, include_time)
        safe_batch_size = max(1, int(batch_size or 65_536))

        for part in dataset.parts:
            if _part_excluded_by_qpc(part, start_qpc, end_qpc):
                continue
            part_path = _resolve_relative(self.generation_dir, part.path)
            parquet = pq.ParquetFile(part_path)
            for record_batch in parquet.iter_batches(
                batch_size=safe_batch_size,
                columns=physical_columns or None,
            ):
                df = pa.Table.from_batches([record_batch]).to_pandas()
                df = _finalize_scan_frame(
                    df,
                    schema,
                    self.timebase,
                    event_filters,
                    start_qpc,
                    end_qpc,
                    requested_columns,
                    include_time,
                )
                if not df.empty:
                    yield df.reset_index(drop=True)


class NativeEventStoreWriter:
    """Build one chunked native event-store generation."""

    def __init__(
        self,
        export_dir: Path | str,
        *,
        run_id: str | None = None,
        timebase: EventStoreTimebase | None = None,
        event_classes: Iterable[str] | None = None,
        staging: bool = True,
        max_rows_per_part: int = DEFAULT_MAX_ROWS_PER_PART,
        max_bytes_per_part: int = DEFAULT_MAX_BYTES_PER_PART,
    ) -> None:
        self.export_dir = Path(export_dir).resolve()
        self.run_id = run_id or uuid.uuid4().hex
        self.timebase = timebase or EventStoreTimebase()
        self.staging = staging
        self.max_rows_per_part = max_rows_per_part
        self.max_bytes_per_part = max_bytes_per_part
        self.final_generation_dir = (
            self.export_dir / NATIVE_STORE_ROOT / GENERATIONS_DIR / self.run_id
        )
        self.work_generation_dir = (
            self.export_dir / NATIVE_STORE_ROOT / STAGING_DIR / self.run_id
            if staging
            else self.final_generation_dir
        )
        if self.work_generation_dir.exists():
            shutil.rmtree(self.work_generation_dir)
        self.work_generation_dir.mkdir(parents=True, exist_ok=True)
        self._writers: dict[str, ParquetBatchWriter] = {}
        self._closed = False
        for event_class in event_classes or ():
            self.ensure_dataset(event_class)

    def ensure_dataset(self, event_class: str) -> None:
        cname = canonical_event_class(event_class)
        if cname in self._writers:
            return
        self._writers[cname] = ParquetBatchWriter(
            event_class=cname,
            output_dir=self.work_generation_dir / EVENTS_DIR / cname,
            max_rows=self.max_rows_per_part,
            max_bytes=self.max_bytes_per_part,
        )

    def append(self, event_class: str, row: dict[str, Any]) -> None:
        if self._closed:
            raise NativeEventStoreError("cannot append to a closed event-store writer")
        self.ensure_dataset(event_class)
        self._writers[canonical_event_class(event_class)].append(row)

    def append_many(self, event_class: str, rows: Iterable[dict[str, Any]]) -> None:
        for row in rows:
            self.append(event_class, row)

    def commit(self) -> NativeEventStore:
        """Flush all buffers, write the manifest, promote staging, and open it."""

        if self._closed:
            return NativeEventStore.open(self.final_generation_dir, export_dir=self.export_dir)
        datasets: dict[str, EventDatasetManifest] = {}
        for cname, writer in sorted(self._writers.items()):
            parts = writer.close()
            datasets[cname] = _dataset_manifest(
                self.work_generation_dir,
                cname,
                parts,
            )

        manifest = EventStoreManifest(
            schema_version=STORE_SCHEMA_VERSION,
            run_id=self.run_id,
            created_utc=datetime.now(timezone.utc).isoformat(),
            timebase=self.timebase,
            datasets=datasets,
        )
        _write_store_manifest(self.work_generation_dir, manifest)

        if self.staging:
            self.final_generation_dir.parent.mkdir(parents=True, exist_ok=True)
            if self.final_generation_dir.exists():
                raise NativeEventStoreError(
                    f"event-store generation already exists: {self.final_generation_dir}"
                )
            self.work_generation_dir.replace(self.final_generation_dir)

        self._closed = True
        return NativeEventStore.open(self.final_generation_dir, export_dir=self.export_dir)


def _dataset_manifest(
    generation_dir: Path,
    name: str,
    parts: list[WrittenPart],
) -> EventDatasetManifest:
    refs: list[EventPartRef] = []
    min_values: list[int] = []
    max_values: list[int] = []
    for part in parts:
        if part.min_qpc is not None:
            min_values.append(part.min_qpc)
        if part.max_qpc is not None:
            max_values.append(part.max_qpc)
        refs.append(
            EventPartRef(
                path=str(part.path.resolve().relative_to(generation_dir.resolve())),
                row_count=part.row_count,
                min_qpc=part.min_qpc,
                max_qpc=part.max_qpc,
                byte_size=part.byte_size,
            )
        )
    return EventDatasetManifest(
        name=name,
        schema_version=EVENT_SCHEMA_VERSION,
        row_count=sum(part.row_count for part in parts),
        min_qpc=min(min_values) if min_values else None,
        max_qpc=max(max_values) if max_values else None,
        parts=refs,
    )


def _write_store_manifest(generation_dir: Path, manifest: EventStoreManifest) -> None:
    path = generation_dir / MANIFEST_FILENAME
    tmp = generation_dir / f".{MANIFEST_FILENAME}.tmp"
    tmp.write_text(
        json.dumps(manifest.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    tmp.replace(path)


def _validate_arrow_schema(name: str, actual: pa.Schema) -> None:
    expected = schema_for_event_class(name).schema
    actual_fields = {field.name: field.type for field in actual}
    for field in expected:
        if field.name not in actual_fields:
            raise NativeEventStoreError(
                f"event-store dataset {name!r} is missing column {field.name!r}"
            )
        if actual_fields[field.name] != field.type:
            raise NativeEventStoreError(
                f"event-store dataset {name!r} column {field.name!r} has "
                f"type {actual_fields[field.name]!r}, expected {field.type!r}"
            )


def _physical_columns(
    schema: pa.Schema,
    requested_columns: list[str] | None,
    include_time: bool,
) -> list[str] | None:
    if requested_columns is None:
        return None
    names = set(schema.names)
    columns = [name for name in requested_columns if name in names]
    if include_time and "TimeStampQpc" in names and "TimeStampQpc" not in columns:
        columns.append("TimeStampQpc")
    return columns


def _finalize_scan_frame(
    df: pd.DataFrame,
    schema: pa.Schema,
    timebase: EventStoreTimebase,
    filters: EventFilters,
    start_qpc: int | None,
    end_qpc: int | None,
    requested_columns: list[str] | None,
    include_time: bool,
) -> pd.DataFrame:
    df = _apply_row_filters(df, filters, start_qpc, end_qpc)
    _normalize_list_columns(df, schema)
    if include_time and timebase.has_qpc_mapping() and "TimeStampQpc" in df.columns:
        qpc = pd.to_numeric(df["TimeStampQpc"], errors="coerce")
        converted = ((qpc - int(timebase.qpc_origin)) * 1_000_000.0 / float(timebase.perf_freq)).round()
        if converted.notna().all():
            df["TimeStamp"] = converted.astype("int64")
        else:
            df["TimeStamp"] = converted
    if requested_columns is not None:
        keep = [name for name in requested_columns if name in df.columns]
        if include_time and "TimeStamp" in df.columns and "TimeStamp" not in keep:
            keep.append("TimeStamp")
        df = df[keep]
    return df.reset_index(drop=True)


def _apply_row_filters(
    df: pd.DataFrame,
    filters: EventFilters,
    start_qpc: int | None,
    end_qpc: int | None,
) -> pd.DataFrame:
    if df.empty:
        return df
    mask = pd.Series(True, index=df.index)
    if "TimeStampQpc" in df.columns:
        qpc = pd.to_numeric(df["TimeStampQpc"], errors="coerce")
        if start_qpc is not None:
            mask &= qpc >= start_qpc
        if end_qpc is not None:
            mask &= qpc <= end_qpc
    cpu_set = filters.cpu_set()
    if cpu_set and "CPU" in df.columns:
        mask &= df["CPU"].isin(cpu_set)
    return df[mask].copy()


def _normalize_list_columns(df: pd.DataFrame, schema: pa.Schema) -> None:
    for field in schema:
        if not pa.types.is_list(field.type) or field.name not in df.columns:
            continue
        df[field.name] = df[field.name].map(_to_python_uint64_list)


def _to_python_uint64_list(value: Any) -> list[int] | None:
    if value is None:
        return None
    if isinstance(value, list):
        return [int(item) for item in value]
    if isinstance(value, tuple):
        return [int(item) for item in value]
    if hasattr(value, "tolist"):
        converted = value.tolist()
        if isinstance(converted, list):
            return [int(item) for item in converted]
    return None


def _part_excluded_by_qpc(
    part: EventPartRef,
    start_qpc: int | None,
    end_qpc: int | None,
) -> bool:
    if start_qpc is not None and part.max_qpc is not None and part.max_qpc < start_qpc:
        return True
    if end_qpc is not None and part.min_qpc is not None and part.min_qpc > end_qpc:
        return True
    return False


def _resolve_relative(root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        raise NativeEventStoreError(f"unsafe event-store path: {relative!r}")
    resolved = (root / path).resolve()
    root_resolved = root.resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise NativeEventStoreError(
            f"event-store path escapes generation: {relative!r}"
        ) from exc
    return resolved


def _infer_export_dir(generation_dir: Path) -> Path:
    parts = generation_dir.parts
    if len(parts) >= 3 and parts[-3] == NATIVE_STORE_ROOT and parts[-2] == GENERATIONS_DIR:
        return generation_dir.parents[2]
    return generation_dir.parent


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)


__all__ = [
    "STORE_SCHEMA_VERSION",
    "MANIFEST_FILENAME",
    "NATIVE_STORE_ROOT",
    "GENERATIONS_DIR",
    "STAGING_DIR",
    "EVENTS_DIR",
    "NATIVE_EVENT_STORE_DATASET_KIND",
    "NativeEventStoreError",
    "EventStoreTimebase",
    "EventFilters",
    "EventPartRef",
    "EventDatasetManifest",
    "EventStoreManifest",
    "NativeEventStore",
    "NativeEventStoreWriter",
]
