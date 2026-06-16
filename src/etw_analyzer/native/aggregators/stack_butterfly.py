"""Aggregator: ``stacks`` — replacement for ``xperf -a stack -butterfly``.

Output DataFrame schema mirrors :func:`parsing.wpa_exporter._parse_stack_butterfly_html`::

    Module, Function, Inclusive, Exclusive, Weight, Total %

Algorithm
---------
For every SampledProfile row with a paired ``Stack`` (set by the Phase
N2 stack-pairing buffer):

* The leaf frame (index 0) is the *executing* function — contributes
  to its Exclusive count.
* Every frame in the stack contributes to its own Inclusive count.

We symbolize every unique address across every stack via
``trace.symbolizer.bulk_resolve``, group by (module, function), and
compute Total % against the sum of Exclusive counts (matches xperf's
denominator).

The caller/callee table (``stacks_callers``) is wired in
:func:`aggregate_stack_callers` and emits ``self``, ``caller``, and
``callee`` rows from adjacent frames in each sampled stack.
"""

from __future__ import annotations

import re
import ntpath
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

import pandas as pd

if TYPE_CHECKING:
    from etw_analyzer.trace_state import TraceData


_DEFAULT_BATCH_SIZE = 65_536
_DEFAULT_MAX_UNIQUE_FRAMES = 250_000
_DEFAULT_MAX_UNIQUE_EDGES = 1_000_000
_DEFAULT_MAX_SYMBOL_ADDRESSES = 100_000

_SYM_RE = re.compile(r"^([^!]+)!([^+]+)(?:\+0x[0-9a-fA-F]+)?$")
_SYM_FALLBACK_RE = re.compile(r"^([^+]+)\+0x[0-9a-fA-F]+$")


@dataclass
class StackAggregateData:
    """Paired stack aggregate outputs plus explicit build warnings."""

    stacks: pd.DataFrame | None = None
    callers: pd.DataFrame | None = None
    warnings: list[str] = field(default_factory=list)


def _split_label(label: str) -> tuple[str, str]:
    if not label:
        return "unknown", ""
    m = _SYM_RE.match(label)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    m = _SYM_FALLBACK_RE.match(label)
    if m:
        return m.group(1).strip(), ""
    return label, ""


def _normalize_stack(stack: object) -> tuple[int, ...]:
    """Normalize tuple/list/ndarray stack cells to a tuple of addresses."""
    if stack is None:
        return ()
    if isinstance(stack, tuple):
        values = stack
    elif isinstance(stack, list):
        values = stack
    elif hasattr(stack, "tolist"):
        values = stack.tolist()
        if not isinstance(values, (list, tuple)):
            values = [values]
    else:
        return ()

    out: list[int] = []
    for addr in values:
        if addr is None:
            continue
        try:
            if pd.isna(addr):
                continue
        except (TypeError, ValueError):
            pass
        try:
            out.append(int(addr))
        except (TypeError, ValueError, OverflowError):
            continue
    return tuple(out)


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _positive_weight(value: Any) -> int | None:
    number = _safe_int(value)
    return number if number is not None and number > 0 else None


def _stack_weight(row_weight: Any) -> int:
    return _positive_weight(row_weight) or 1


@dataclass(frozen=True)
class _ImageInterval:
    base: int
    end: int
    file_name: str
    module: str


class _ImageIndex:
    def __init__(self) -> None:
        self._intervals: list[_ImageInterval] = []
        self._starts: list[int] = []

    def add(self, base: Any, size: Any, file_name: Any) -> None:
        base_i = _safe_int(base)
        size_i = _safe_int(size)
        if base_i is None or size_i is None or base_i <= 0 or size_i <= 0:
            return
        module = _module_basename(file_name)
        if not module:
            return
        self._intervals.append(_ImageInterval(
            base=base_i,
            end=base_i + size_i,
            file_name=str(file_name or ""),
            module=module,
        ))

    def finalize(self) -> None:
        self._intervals.sort(key=lambda item: item.base)
        self._starts = [item.base for item in self._intervals]

    @property
    def has_data(self) -> bool:
        return bool(self._intervals)

    @property
    def intervals(self) -> list[_ImageInterval]:
        return self._intervals

    def module_for(self, address: int | None) -> str:
        if address is None or not self._intervals:
            return "unknown"
        import bisect

        addr = int(address)
        index = bisect.bisect_right(self._starts, addr) - 1
        while index >= 0:
            item = self._intervals[index]
            if item.base <= addr < item.end:
                return item.module
            index -= 1
        return "unknown"


def _module_basename(file_name: Any) -> str:
    if file_name is None:
        return ""
    try:
        if pd.isna(file_name):
            return ""
    except (TypeError, ValueError):
        pass
    return ntpath.basename(str(file_name or "").strip("\x00").strip()).lower()


def _iter_frame_stacks(df: pd.DataFrame) -> Iterator[tuple[tuple[int, ...], int]]:
    if df is None or df.empty or "Stack" not in df.columns:
        return
    weight_col = "Weight" if "Weight" in df.columns else None
    weights: Iterable[Any]
    if weight_col:
        weights = df[weight_col].tolist()
    else:
        weights = [1] * len(df)
    for stack, weight in zip(df["Stack"].tolist(), weights):
        normalized = _normalize_stack(stack)
        if normalized:
            yield normalized, _stack_weight(weight)


def _build_image_index_from_event_store(
    trace: "TraceData",
    *,
    batch_size: int = _DEFAULT_BATCH_SIZE,
) -> _ImageIndex:
    image_index = _ImageIndex()
    try:
        from etw_analyzer.native.accessors import iter_event_batches
    except Exception:
        return image_index

    try:
        batches = iter_event_batches(
            trace,
            "image",
            columns=["ImageBase", "ImageSize", "FileName"],
            include_time=False,
            batch_size=batch_size,
        )
        for batch in batches:
            if batch.empty:
                continue
            for base, size, file_name in zip(
                batch.get("ImageBase", pd.Series(dtype="object")),
                batch.get("ImageSize", pd.Series(dtype="object")),
                batch.get("FileName", pd.Series(dtype="object")),
            ):
                image_index.add(base, size, file_name)
    except Exception:
        return _ImageIndex()
    image_index.finalize()
    return image_index


def _ensure_symbolizer_from_image_index(
    trace: "TraceData",
    image_index: _ImageIndex,
) -> None:
    if getattr(trace, "symbolizer", None) is not None or not image_index.has_data:
        return
    try:
        from etw_analyzer.native import Symbolizer

        symbolizer = Symbolizer(symbol_path=trace.symbol_path)
    except Exception:
        return
    seen_bases: set[int] = set()
    for item in image_index.intervals:
        if item.base in seen_bases:
            continue
        seen_bases.add(item.base)
        try:
            symbolizer.add_module(
                item.base,
                item.end - item.base,
                item.file_name,
                pdb_guid=item.pdb_guid,
                pdb_age=item.pdb_age,
                pdb_name=item.pdb_name,
                time_date_stamp=item.time_date_stamp,
            )
        except Exception:
            continue
    trace.symbolizer = symbolizer


def _iter_event_store_stacks(
    trace: "TraceData",
    *,
    batch_size: int = _DEFAULT_BATCH_SIZE,
) -> Iterator[tuple[tuple[int, ...], int]]:
    from etw_analyzer.native.accessors import iter_event_batches

    for batch in iter_event_batches(
        trace,
        "sampled_profile",
        columns=["Stack", "Weight"],
        include_time=False,
        batch_size=batch_size,
    ):
        yield from _iter_frame_stacks(batch)


class _StackCounterOverflow(ValueError):
    """Raised when exact stack aggregation would exceed configured bounds."""


@dataclass
class _StackCounters:
    inclusive: Counter[int]
    exclusive: Counter[int]
    caller_edges: Counter[tuple[int, int]]
    stack_count: int = 0


def _count_stacks_by_address(
    stacks_with_weight: Iterable[tuple[tuple[int, ...], int]],
    *,
    max_unique_frames: int = _DEFAULT_MAX_UNIQUE_FRAMES,
    max_unique_edges: int = _DEFAULT_MAX_UNIQUE_EDGES,
) -> _StackCounters:
    counters = _StackCounters(Counter(), Counter(), Counter())
    for stack, weight in stacks_with_weight:
        if not stack:
            continue
        counters.stack_count += 1
        leaf = int(stack[0])
        counters.exclusive[leaf] += int(weight)

        seen_in_stack: set[int] = set()
        for addr in stack:
            addr_i = int(addr)
            if addr_i in seen_in_stack:
                continue
            seen_in_stack.add(addr_i)
            counters.inclusive[addr_i] += int(weight)
            if len(counters.inclusive) > max_unique_frames:
                raise _StackCounterOverflow(
                    "Native streaming stack aggregation exceeded the "
                    f"unique-frame safety cap ({max_unique_frames:,}); "
                    "stacks/stacks_callers were not materialized rather than "
                    "silently truncating counts."
                )

        for idx in range(len(stack) - 1):
            target = int(stack[idx])
            caller = int(stack[idx + 1])
            counters.caller_edges[(target, caller)] += int(weight)
            if len(counters.caller_edges) > max_unique_edges:
                raise _StackCounterOverflow(
                    "Native streaming stack caller aggregation exceeded the "
                    f"unique-edge safety cap ({max_unique_edges:,}); "
                    "stacks/stacks_callers were not materialized rather than "
                    "silently truncating counts."
                )
    return counters


def _resolve_address_pairs(
    trace: "TraceData",
    addresses: Iterable[int],
    image_index: _ImageIndex | None,
    warnings: list[str],
    *,
    max_symbol_addresses: int = _DEFAULT_MAX_SYMBOL_ADDRESSES,
) -> dict[int, tuple[str, str]]:
    unique = sorted({int(addr) for addr in addresses if addr})
    if not unique:
        return {}

    labels: dict[int, str] = {}
    symbolizer = getattr(trace, "symbolizer", None)
    if symbolizer is not None:
        to_symbolize = unique[:max_symbol_addresses]
        try:
            labels = symbolizer.bulk_resolve(to_symbolize)
        except Exception:
            labels = {}
        if len(unique) > max_symbol_addresses:
            warnings.append(
                "Native streaming stack symbolization reached the safety cap "
                f"({max_symbol_addresses:,} unique addresses); remaining "
                "addresses use image-module attribution only."
            )

    pairs: dict[int, tuple[str, str]] = {}
    label_to_pair: dict[str, tuple[str, str]] = {}
    for addr in unique:
        label = labels.get(addr, "")
        if label:
            pair = label_to_pair.get(label)
            if pair is None:
                pair = _split_label(label)
                label_to_pair[label] = pair
        else:
            pair = ("unknown", "")
        if (not pair[0] or pair[0] == "unknown") and image_index is not None:
            module = image_index.module_for(addr)
            if module and module != "unknown":
                pair = (module, pair[1])
        pairs[addr] = (pair[0] or "unknown", pair[1] or "")
    return pairs


def _dataframes_from_counters(
    trace: "TraceData",
    counters: _StackCounters,
    *,
    image_index: _ImageIndex | None = None,
    require_symbolizer: bool = False,
    max_symbol_addresses: int = _DEFAULT_MAX_SYMBOL_ADDRESSES,
) -> StackAggregateData:
    warnings: list[str] = []
    if counters.stack_count <= 0 or not counters.inclusive:
        return StackAggregateData(warnings=[
            "No SampledProfile stack lists were available for native stack aggregation."
        ])

    if require_symbolizer and getattr(trace, "symbolizer", None) is None:
        return StackAggregateData()
    if getattr(trace, "symbolizer", None) is None and not (image_index and image_index.has_data):
        return StackAggregateData(warnings=[
            "Native stack samples were present, but no symbolizer or image "
            "rundown data was available for module attribution."
        ])

    addresses: set[int] = set(counters.inclusive) | set(counters.exclusive)
    for target, caller in counters.caller_edges:
        addresses.add(target)
        addresses.add(caller)
    addr_to_pair = _resolve_address_pairs(
        trace,
        addresses,
        image_index,
        warnings,
        max_symbol_addresses=max_symbol_addresses,
    )
    if not addr_to_pair:
        return StackAggregateData(warnings=warnings)

    inclusive_by_pair: Counter[tuple[str, str]] = Counter()
    exclusive_by_pair: Counter[tuple[str, str]] = Counter()
    edge_by_pair: Counter[tuple[tuple[str, str], tuple[str, str]]] = Counter()

    for addr, weight in counters.inclusive.items():
        inclusive_by_pair[addr_to_pair.get(addr, ("unknown", ""))] += int(weight)
    for addr, weight in counters.exclusive.items():
        exclusive_by_pair[addr_to_pair.get(addr, ("unknown", ""))] += int(weight)
    for (target, caller), weight in counters.caller_edges.items():
        edge_by_pair[(
            addr_to_pair.get(target, ("unknown", "")),
            addr_to_pair.get(caller, ("unknown", "")),
        )] += int(weight)

    stacks = _stacks_dataframe_from_pairs(inclusive_by_pair, exclusive_by_pair)
    callers = _callers_dataframe_from_pairs(inclusive_by_pair, exclusive_by_pair, edge_by_pair)
    return StackAggregateData(stacks=stacks, callers=callers, warnings=warnings)


def _stacks_dataframe_from_pairs(
    inclusive: Counter[tuple[str, str]],
    exclusive: Counter[tuple[str, str]],
) -> pd.DataFrame | None:
    total_exclusive = sum(exclusive.values()) or 1
    rows: list[dict[str, Any]] = []
    for module, function in set(inclusive) | set(exclusive):
        incl = int(inclusive.get((module, function), 0))
        excl = int(exclusive.get((module, function), 0))
        rows.append({
            "Module": module,
            "Function": function,
            "Inclusive": incl,
            "Exclusive": excl,
            "Weight": incl,
            "Total %": round(excl / total_exclusive * 100.0, 2),
        })
    if not rows:
        return None
    return (
        pd.DataFrame(rows)
        .sort_values("Inclusive", ascending=False)
        .reset_index(drop=True)
    )


def _callers_dataframe_from_pairs(
    inclusive: Counter[tuple[str, str]],
    exclusive: Counter[tuple[str, str]],
    caller_edges: Counter[tuple[tuple[str, str], tuple[str, str]]],
) -> pd.DataFrame | None:
    rows: list[dict[str, Any]] = []
    grand_total = sum(exclusive.values()) or 1

    for (tm, tf), weight in inclusive.items():
        rows.append({
            "Target_Module": tm,
            "Target_Function": tf,
            "Direction": "self",
            "Caller_Module": tm,
            "Caller_Function": tf,
            "Weight": int(weight),
            "Total %": round(float(weight) / grand_total * 100.0, 2),
            "Parent %": 100.0,
            "Exclusive": int(exclusive.get((tm, tf), 0)),
        })

    for (target, caller), weight in caller_edges.items():
        tm, tf = target
        cm, cf = caller
        target_total = inclusive.get(target, weight) or weight
        rows.append({
            "Target_Module": tm,
            "Target_Function": tf,
            "Direction": "caller",
            "Caller_Module": cm,
            "Caller_Function": cf,
            "Weight": int(weight),
            "Total %": round(float(weight) / grand_total * 100.0, 2),
            "Parent %": round(float(weight) / target_total * 100.0, 2),
            "Exclusive": int(exclusive.get(target, 0)),
        })

        caller_total = inclusive.get(caller, weight) or weight
        rows.append({
            "Target_Module": cm,
            "Target_Function": cf,
            "Direction": "callee",
            "Caller_Module": tm,
            "Caller_Function": tf,
            "Weight": int(weight),
            "Total %": round(float(weight) / grand_total * 100.0, 2),
            "Parent %": round(float(weight) / caller_total * 100.0, 2),
            "Exclusive": int(exclusive.get(caller, 0)),
        })

    if not rows:
        return None
    return (
        pd.DataFrame(rows)
        .sort_values("Weight", ascending=False)
        .reset_index(drop=True)
    )


def _aggregate_stack_rows(
    trace: "TraceData",
    stacks_with_weight: Iterable[tuple[tuple[int, ...], int]],
    *,
    image_index: _ImageIndex | None = None,
    require_symbolizer: bool = False,
    max_unique_frames: int = _DEFAULT_MAX_UNIQUE_FRAMES,
    max_unique_edges: int = _DEFAULT_MAX_UNIQUE_EDGES,
    max_symbol_addresses: int = _DEFAULT_MAX_SYMBOL_ADDRESSES,
) -> StackAggregateData:
    try:
        counters = _count_stacks_by_address(
            stacks_with_weight,
            max_unique_frames=max_unique_frames,
            max_unique_edges=max_unique_edges,
        )
    except _StackCounterOverflow as exc:
        return StackAggregateData(warnings=[str(exc)])
    return _dataframes_from_counters(
        trace,
        counters,
        image_index=image_index,
        require_symbolizer=require_symbolizer,
        max_symbol_addresses=max_symbol_addresses,
    )


def aggregate_stack_butterfly(
    trace: "TraceData",
    *,
    max_stacks: int = 200_000,
) -> Optional[pd.DataFrame]:
    """Build the ``stacks`` DataFrame from native SampledProfile + StackWalk.

    Parameters
    ----------
    trace:
        Trace with ``dumper_df`` populated; rows whose ``Stack`` column
        is a non-empty tuple/list/array contribute frames.
    max_stacks:
        Legacy API cap retained for compatibility. Counting now stays
        bounded by unique frame/edge counts instead of silently truncating
        after a sample count.

    Returns ``None`` when no stacks have been paired or the trace lacks
    a symbolizer (in which case nothing can be attributed by symbol).
    """
    dumper = trace.dumper_df
    if dumper is None or dumper.empty or "Stack" not in dumper.columns:
        return None
    result = _aggregate_stack_rows(
        trace,
        _iter_frame_stacks(dumper),
        require_symbolizer=True,
    )
    _record_stack_warnings(trace, result.warnings)
    return result.stacks


def aggregate_stack_callers(
    trace: "TraceData",
    *,
    max_stacks: int = 200_000,
) -> Optional[pd.DataFrame]:
    """Build a ``stacks_callers`` DataFrame.

    Columns match :func:`parsing.wpa_exporter.parse_stack_butterfly_callers`::

        Target_Module, Target_Function, Direction, Caller_Module,
        Caller_Function, Weight, Total %, Parent %, Exclusive

    Emits ``Direction='self'`` rows for each observed frame plus
    ``Direction='caller'`` and ``Direction='callee'`` rows for adjacent
    stack frames. Stack cells may come from in-memory extraction as tuples
    or from parquet cache as lists/arrays.
    """
    dumper = trace.dumper_df
    if dumper is None or dumper.empty or "Stack" not in dumper.columns:
        return None
    result = _aggregate_stack_rows(
        trace,
        _iter_frame_stacks(dumper),
        require_symbolizer=True,
    )
    _record_stack_warnings(trace, result.warnings)
    return result.callers


def aggregate_stack_data_from_event_store(
    trace: "TraceData",
    *,
    batch_size: int = _DEFAULT_BATCH_SIZE,
    max_unique_frames: int = _DEFAULT_MAX_UNIQUE_FRAMES,
    max_unique_edges: int = _DEFAULT_MAX_UNIQUE_EDGES,
    max_symbol_addresses: int = _DEFAULT_MAX_SYMBOL_ADDRESSES,
) -> StackAggregateData:
    """Build ``stacks`` and ``stacks_callers`` from sampled_profile chunks."""

    store = getattr(trace, "event_store", None)
    if store is None:
        return StackAggregateData(warnings=[
            "No native event store is attached; stack aggregates cannot be built lazily."
        ])
    try:
        from etw_analyzer.native.accessors import has_event_store_dataset
    except Exception:
        return StackAggregateData(warnings=[
            "Native event-store accessors are unavailable; stack aggregates cannot be built."
        ])
    if not has_event_store_dataset(trace, "sampled_profile"):
        return StackAggregateData(warnings=[
            "Native event store has no sampled_profile dataset for stack aggregation."
        ])

    image_index = _build_image_index_from_event_store(trace, batch_size=batch_size)
    _ensure_symbolizer_from_image_index(trace, image_index)
    return _aggregate_stack_rows(
        trace,
        _iter_event_store_stacks(trace, batch_size=batch_size),
        image_index=image_index,
        require_symbolizer=False,
        max_unique_frames=max_unique_frames,
        max_unique_edges=max_unique_edges,
        max_symbol_addresses=max_symbol_addresses,
    )


def ensure_stack_aggregates(
    trace: "TraceData",
    *,
    include_callers: bool = True,
    persist: bool = True,
) -> StackAggregateData:
    """Populate missing stack aggregates from the event store when possible."""

    existing = StackAggregateData(
        stacks=_existing_stacks(trace),
        callers=_existing_callers(trace),
        warnings=_stack_warnings(trace),
    )
    need_stacks = existing.stacks is None
    missing_callers = existing.callers is None
    need_callers = include_callers and existing.callers is None
    if not need_stacks and not need_callers:
        return existing
    if getattr(trace, "_native_stack_aggregate_attempted", False):
        return existing
    if getattr(trace, "event_store", None) is None:
        return existing

    with trace.lock:
        existing = StackAggregateData(
            stacks=_existing_stacks(trace),
            callers=_existing_callers(trace),
            warnings=_stack_warnings(trace),
        )
        need_stacks = existing.stacks is None
        need_callers = include_callers and existing.callers is None
        if not need_stacks and not need_callers:
            return existing
        if getattr(trace, "_native_stack_aggregate_attempted", False):
            return existing

        trace._native_stack_aggregate_attempted = True
        result = aggregate_stack_data_from_event_store(trace)
        _record_stack_warnings(trace, result.warnings)

        if result.stacks is not None and not result.stacks.empty and need_stacks:
            trace.raw_csv["stacks"] = result.stacks
            if persist:
                _persist_lazy_stack_dataframe(trace, "stacks", result.stacks)
        if result.callers is not None and not result.callers.empty and missing_callers:
            trace.raw_csv["stacks_callers"] = result.callers
            if persist:
                _persist_lazy_stack_dataframe(trace, "stacks_callers", result.callers)

        return StackAggregateData(
            stacks=_existing_stacks(trace),
            callers=_existing_callers(trace),
            warnings=_stack_warnings(trace),
        )


def _existing_stacks(trace: "TraceData") -> pd.DataFrame | None:
    for key in ("stacks", "stack_butterfly"):
        df = getattr(trace, "raw_csv", {}).get(key)
        if isinstance(df, pd.DataFrame) and not df.empty and "Module" in df.columns:
            return df.copy()
    return None


def _existing_callers(trace: "TraceData") -> pd.DataFrame | None:
    df = getattr(trace, "raw_csv", {}).get("stacks_callers")
    if isinstance(df, pd.DataFrame) and not df.empty:
        return df.copy()
    return None


def _record_stack_warnings(trace: "TraceData", warnings: list[str]) -> None:
    if not warnings:
        return
    current = _stack_warnings(trace)
    for warning in warnings:
        if warning not in current:
            current.append(warning)
    trace._native_stack_aggregate_warnings = current
    export_errors = getattr(trace, "export_errors", None)
    if isinstance(export_errors, list):
        for warning in warnings:
            if warning not in export_errors:
                export_errors.append(warning)


def _stack_warnings(trace: "TraceData") -> list[str]:
    return list(getattr(trace, "_native_stack_aggregate_warnings", []) or [])


def _persist_lazy_stack_dataframe(
    trace: "TraceData",
    name: str,
    df: pd.DataFrame,
) -> None:
    try:
        trace.export_dir.mkdir(parents=True, exist_ok=True)
        df.to_parquet(trace.export_dir / f"{name}.parquet", index=False)
    except Exception as exc:
        _record_stack_warnings(
            trace,
            [f"Built {name} lazily but could not write {name}.parquet: {exc}"],
        )


__all__ = [
    "StackAggregateData",
    "aggregate_stack_butterfly",
    "aggregate_stack_callers",
    "aggregate_stack_data_from_event_store",
    "ensure_stack_aggregates",
]
