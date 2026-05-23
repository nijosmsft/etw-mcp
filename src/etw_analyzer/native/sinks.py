"""Bounded parquet sinks for native event-store chunks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import pyarrow.parquet as pq

from .schemas import canonical_event_class, rows_to_table, schema_for_event_class


DEFAULT_MAX_ROWS_PER_PART = 250_000
DEFAULT_MAX_BYTES_PER_PART = 64 * 1024 * 1024


@dataclass(frozen=True)
class WrittenPart:
    """Metadata for one completed parquet part file."""

    path: Path
    row_count: int
    min_qpc: int | None
    max_qpc: int | None
    byte_size: int
    schema_version: int


class ParquetBatchWriter:
    """Buffer rows for one event class and write bounded parquet part files."""

    def __init__(
        self,
        *,
        event_class: str,
        output_dir: Path,
        max_rows: int = DEFAULT_MAX_ROWS_PER_PART,
        max_bytes: int = DEFAULT_MAX_BYTES_PER_PART,
        compression: str = "zstd",
    ) -> None:
        self.event_class = canonical_event_class(event_class)
        self.output_dir = output_dir
        self.max_rows = max(1, int(max_rows))
        self.max_bytes = max(1, int(max_bytes))
        self.compression = compression
        self.schema = schema_for_event_class(self.event_class)
        self.parts: list[WrittenPart] = []
        self._rows: list[dict[str, Any]] = []
        self._approx_bytes = 0
        self._part_index = 0

    @property
    def buffered_row_count(self) -> int:
        return len(self._rows)

    def append(self, row: dict[str, Any]) -> None:
        """Append one row and flush if row or byte thresholds are reached."""

        self._rows.append(row)
        self._approx_bytes += _approx_row_bytes(row)
        if len(self._rows) >= self.max_rows or self._approx_bytes >= self.max_bytes:
            self.flush()

    def append_many(self, rows: Iterable[dict[str, Any]]) -> None:
        for row in rows:
            self.append(row)

    def flush(self) -> WrittenPart | None:
        """Write buffered rows to a complete parquet part, if any."""

        if not self._rows:
            return None

        rows = self._rows
        self._rows = []
        self._approx_bytes = 0

        table = rows_to_table(self.event_class, rows)
        qpc_values = [
            int(value)
            for value in table.column(self.schema.qpc_column).to_pylist()
            if value is not None
        ] if self.schema.qpc_column in table.column_names else []

        self.output_dir.mkdir(parents=True, exist_ok=True)
        final_path = self.output_dir / f"part-{self._part_index:06d}.parquet"
        tmp_path = self.output_dir / f".part-{self._part_index:06d}.parquet.tmp"
        self._part_index += 1

        try:
            pq.write_table(table, tmp_path, compression=self.compression)
            tmp_path.replace(final_path)
        except Exception:
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass
            raise

        part = WrittenPart(
            path=final_path,
            row_count=table.num_rows,
            min_qpc=min(qpc_values) if qpc_values else None,
            max_qpc=max(qpc_values) if qpc_values else None,
            byte_size=int(final_path.stat().st_size),
            schema_version=self.schema.version,
        )
        self.parts.append(part)
        return part

    def close(self) -> list[WrittenPart]:
        """Flush remaining rows and return all written part metadata."""

        self.flush()
        return list(self.parts)


def _approx_row_bytes(row: dict[str, Any]) -> int:
    total = 0
    for value in row.values():
        total += _approx_value_bytes(value)
    return max(total, 1)


def _approx_value_bytes(value: Any) -> int:
    if value is None:
        return 1
    if isinstance(value, (int, float, bool)):
        return 8
    if isinstance(value, str):
        return len(value.encode("utf-8", errors="replace"))
    if isinstance(value, bytes):
        return len(value)
    if isinstance(value, (list, tuple)):
        return sum(_approx_value_bytes(item) for item in value)
    try:
        return len(value) * 8
    except Exception:
        return 16


__all__ = [
    "DEFAULT_MAX_ROWS_PER_PART",
    "DEFAULT_MAX_BYTES_PER_PART",
    "WrittenPart",
    "ParquetBatchWriter",
]
