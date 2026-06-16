"""Streaming aggregate builders over :class:`NativeEventStore` chunks.

The materialized native path builds xperf-compatible outputs from in-memory
event DataFrames.  Large ETLs use a chunked event store instead; this module
scans those parquet chunks in bounded batches and emits only the small root
aggregate outputs that existing tools load from cache.
"""

from __future__ import annotations

import bisect
from collections import defaultdict
from dataclasses import dataclass, field
import math
import ntpath
from typing import TYPE_CHECKING, Any

import pandas as pd

from etw_analyzer.native.aggregators.dpcisr import (
    _bucket_for,
    _module_from_label,
)
from etw_analyzer.native.aggregators.profile_detail import _split_resolved
from etw_analyzer.native.aggregators.sysconfig import build_sysconfig_text
from etw_analyzer.native.aggregators.tracestats import build_tracestats_text

if TYPE_CHECKING:
    from etw_analyzer.native.event_store import NativeEventStore
    from etw_analyzer.trace_state import TraceData


_DEFAULT_BATCH_SIZE = 65_536
_DEFAULT_SAMPLE_RATE_HZ = 1_000
_MAX_SYMBOL_ADDRESSES = 100_000


@dataclass
class StreamingAggregateResult:
    """Small aggregate outputs produced from a streaming event store."""

    dataframes: dict[str, pd.DataFrame] = field(default_factory=dict)
    texts: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


@dataclass
class _ImageInterval:
    base: int
    end: int
    file_name: str
    module: str
    # M2: PDB identity carried for M3's exact-GUID dbghelp load path.
    # All four may be None for rows where the sidecar found no matching
    # RSDS event (user-mode images, or native-mode captures before M5).
    pdb_guid: str | None
    pdb_age: int | None
    pdb_name: str | None
    time_date_stamp: int | None


class _ImageIndex:
    def __init__(self) -> None:
        self._intervals: list[_ImageInterval] = []
        self._starts: list[int] = []
        # M2: per-ImageBase PDB identity dict for M3 to consume at
        # add_module call sites.  Key: ImageBase (int), value: dict with
        # keys pdb_guid, pdb_age, pdb_name, time_date_stamp.
        self.pdb_identity: dict[int, dict] = {}

    def add(
        self,
        base: int,
        size: int,
        file_name: str,
        *,
        pdb_guid: str | None = None,
        pdb_age: int | None = None,
        pdb_name: str | None = None,
        time_date_stamp: int | None = None,
    ) -> None:
        if base <= 0 or size <= 0:
            return
        module = _module_basename(file_name)
        if not module:
            return
        base_i = int(base)
        self._intervals.append(
            _ImageInterval(
                base=base_i,
                end=base_i + int(size),
                file_name=str(file_name or ""),
                module=module,
                pdb_guid=pdb_guid,
                pdb_age=pdb_age,
                pdb_name=pdb_name,
                time_date_stamp=time_date_stamp,
            )
        )
        # Stash identity for M3's add_module call site.  First-seen base wins
        # (DCStart and Load for the same module share the same identity).
        if base_i not in self.pdb_identity and any(
            v is not None for v in (pdb_guid, pdb_age, pdb_name, time_date_stamp)
        ):
            self.pdb_identity[base_i] = {
                "pdb_guid": pdb_guid,
                "pdb_age": pdb_age,
                "pdb_name": pdb_name,
                "time_date_stamp": time_date_stamp,
            }

    def finalize(self) -> None:
        self._intervals.sort(key=lambda item: item.base)
        self._starts = [item.base for item in self._intervals]

    @property
    def intervals(self) -> list[_ImageInterval]:
        return self._intervals

    def module_for(self, address: int | None) -> str:
        if address is None or not self._intervals:
            return "unknown"
        addr = int(address)
        index = bisect.bisect_right(self._starts, addr) - 1
        while index >= 0:
            item = self._intervals[index]
            if item.base <= addr < item.end:
                return item.module
            index -= 1
        return "unknown"


@dataclass
class _Dimensions:
    process_table: pd.DataFrame | None
    pid_to_name: dict[int, str]
    tid_to_pid: dict[int, int]
    image_index: _ImageIndex


class _AddressResolver:
    def __init__(
        self,
        trace: "TraceData",
        image_index: _ImageIndex,
        warnings: list[str],
        *,
        max_symbol_addresses: int = _MAX_SYMBOL_ADDRESSES,
    ) -> None:
        self.symbolizer = getattr(trace, "symbolizer", None)
        self.image_index = image_index
        self.warnings = warnings
        self.max_symbol_addresses = max_symbol_addresses
        # _pairs maps address -> (module, function). _sources maps
        # address -> symbol source string ("pdb" | "export" | "unknown")
        # mirroring the v0.6 dataframe aggregator path so the streaming
        # cpu_sampling output can populate SymbolSource for item 63.
        self._pairs: dict[int, tuple[str, str]] = {}
        self._sources: dict[int, str] = {}
        self._warned_cap = False

    def prepare(self, addresses: list[int | None]) -> None:
        missing = sorted({
            int(addr)
            for addr in addresses
            if addr is not None and int(addr) not in self._pairs
        })
        if not missing:
            return

        labels: dict[int, str] = {}
        sources: dict[int, str] = {}
        if self.symbolizer is not None:
            if len(self._pairs) + len(missing) <= self.max_symbol_addresses:
                try:
                    # Prefer the v0.6 source-aware API; older Symbolizer
                    # implementations (or mocks) only expose bulk_resolve,
                    # so fall back transparently.
                    if hasattr(self.symbolizer, "bulk_resolve_with_source"):
                        pairs = self.symbolizer.bulk_resolve_with_source(missing)
                        labels = {k: v[0] for k, v in pairs.items()}
                        sources = {k: v[1] for k, v in pairs.items()}
                    else:
                        labels = self.symbolizer.bulk_resolve(missing)
                except Exception:
                    labels = {}
                    sources = {}
            elif not self._warned_cap:
                self.warnings.append(
                    "Streaming symbolization reached the safety cap; "
                    "remaining addresses use image-module attribution only."
                )
                self._warned_cap = True

        for addr in missing:
            label = labels.get(addr, "")
            module, function = _split_resolved(label) if label else ("unknown", "")
            if not module or module == "unknown":
                module = self.image_index.module_for(addr)
            self._pairs[addr] = (module or "unknown", function or "")
            self._sources[addr] = sources.get(addr, "" if label else "unknown")

    def pair_for(self, address: int | None) -> tuple[str, str]:
        if address is None:
            return "unknown", ""
        addr = int(address)
        if addr not in self._pairs:
            self.prepare([addr])
        return self._pairs.get(addr, ("unknown", ""))

    def source_for(self, address: int | None) -> str:
        """Return the SymbolSource for ``address`` ("pdb"/"export"/"unknown"/"")."""
        if address is None:
            return ""
        addr = int(address)
        if addr not in self._pairs:
            self.prepare([addr])
        return self._sources.get(addr, "")

    def module_for(self, address: int | None) -> str:
        module, _function = self.pair_for(address)
        if module == "unknown":
            return self.image_index.module_for(address)
        return _module_from_label(module)


def build_streaming_aggregates(
    trace: "TraceData",
    store: "NativeEventStore",
    *,
    batch_size: int = _DEFAULT_BATCH_SIZE,
) -> StreamingAggregateResult:
    """Build low-risk xperf-compatible aggregates from event-store chunks."""

    result = StreamingAggregateResult()
    trace.event_store = store
    for name, dataset in store.manifest.datasets.items():
        trace.event_counts[f"event_store:{name}"] = dataset.row_count

    _apply_store_metadata(trace, store)
    dimensions = _load_dimensions(store, batch_size=batch_size)
    if dimensions.process_table is not None and not dimensions.process_table.empty:
        result.dataframes["process"] = dimensions.process_table
        trace.raw_csv["process"] = dimensions.process_table

    _build_symbolizer_from_images(trace, dimensions.image_index)
    resolver = _AddressResolver(trace, dimensions.image_index, result.warnings)

    cpu_timeline, max_sample_cpu = _build_cpu_timeline(
        trace,
        store,
        batch_size=batch_size,
    )
    if cpu_timeline is not None and not cpu_timeline.empty:
        result.dataframes["cpu_timeline"] = cpu_timeline
        trace.raw_csv["cpu_timeline"] = cpu_timeline

    cpu_sampling = _build_cpu_sampling(
        store,
        dimensions,
        resolver,
        batch_size=batch_size,
    )
    if cpu_sampling is not None and not cpu_sampling.empty:
        cpu_sampling = _normalize_cpu_sampling_capacity(
            cpu_sampling,
            cpu_timeline,
            trace,
        )
        result.dataframes["cpu_sampling"] = cpu_sampling
        trace.raw_csv["cpu_sampling"] = cpu_sampling

    dpc_isr, dpc_per_cpu, max_dpc_cpu = _build_dpc_aggregates(
        trace,
        store,
        resolver,
        batch_size=batch_size,
    )
    if dpc_isr is not None and not dpc_isr.empty:
        result.dataframes["dpc_isr"] = dpc_isr
        trace.raw_csv["dpc_isr"] = dpc_isr
    if dpc_per_cpu is not None and not dpc_per_cpu.empty:
        result.dataframes["dpc_isr_per_cpu"] = dpc_per_cpu
        trace.raw_csv["dpc_isr_per_cpu"] = dpc_per_cpu

    observed_max_cpu = max(
        value
        for value in (max_sample_cpu, max_dpc_cpu)
        if value is not None
    ) if any(value is not None for value in (max_sample_cpu, max_dpc_cpu)) else None
    _apply_store_metadata(trace, store, observed_max_cpu=observed_max_cpu)

    process_text = _build_process_info_text(dimensions.process_table)
    if process_text:
        result.texts["process_info"] = process_text

    sysconfig_text = build_sysconfig_text(trace)
    if sysconfig_text:
        result.texts["sysconfig"] = sysconfig_text

    tracestats_text = build_tracestats_text(trace)
    if tracestats_text:
        result.texts["tracestats"] = tracestats_text

    return result


def _normalize_cpu_sampling_capacity(
    cpu_sampling: pd.DataFrame,
    cpu_timeline: pd.DataFrame | None,
    trace: "TraceData",
) -> pd.DataFrame:
    """Normalize anomalous native profile weights to xperf capacity semantics.

    Most traces encode xperf-equivalent ``ProfileWeight`` directly in the
    SampledProfile payload. Some CPU profiles instead emit a large per-sample
    relative weight; summing those rows can exceed the trace's total CPU
    capacity by orders of magnitude. In that case, use the sampled timeline to
    estimate active CPU time, scale non-idle samples to that active budget, and
    synthesize the xperf-style low-power idle bucket for the remaining capacity.
    """

    if cpu_sampling is None or cpu_sampling.empty or "Weight" not in cpu_sampling.columns:
        return cpu_sampling

    expected_capacity = _trace_capacity_us(trace)
    if expected_capacity is None or expected_capacity <= 0:
        return _recompute_cpu_sampling_percent(cpu_sampling)

    weights = pd.to_numeric(cpu_sampling["Weight"], errors="coerce").fillna(0.0)
    current_total = float(weights.sum())
    if current_total <= 0:
        return _recompute_cpu_sampling_percent(cpu_sampling)

    # If the decoded ProfileWeight already looks like xperf's total CPU
    # capacity, preserve it. This is the common path and keeps small-trace
    # parity exact.
    profile_weight_time_scaled = bool(cpu_sampling.attrs.get("profile_weight_time_scaled", False))

    if current_total <= expected_capacity * 1.5:
        normalized = cpu_sampling.copy()
        if (
            profile_weight_time_scaled
            and current_total < expected_capacity
            and not _has_synthetic_idle_row(normalized)
        ):
            idle_weight = int(round(expected_capacity - current_total))
            if idle_weight > 0:
                idle_row = {
                    "Process Name": "Idle",
                    "PID": 0,
                    "Weight": idle_weight,
                    "Module": "<Heuristic Low Power State>",
                    "Function": "<C3>",
                    "SymbolSource": "",
                }
                normalized = pd.concat([normalized, pd.DataFrame([idle_row])], ignore_index=True)
        return _recompute_cpu_sampling_percent(normalized)

    active_target = _timeline_busy_us(cpu_timeline)
    if active_target is None or active_target <= 0:
        active_target = expected_capacity
    active_target = min(active_target, expected_capacity)
    idle_target = max(expected_capacity - active_target, 0.0)

    normalized = cpu_sampling.copy()
    scale = active_target / current_total if current_total > 0 else 1.0
    normalized["Weight"] = (weights * scale).round().astype("int64")
    if active_target > 0 and int(normalized["Weight"].sum()) == 0 and not normalized.empty:
        normalized.loc[normalized.index[0], "Weight"] = int(round(active_target))

    active_delta = int(round(active_target)) - int(normalized["Weight"].sum())
    if active_delta and not normalized.empty:
        top_index = normalized["Weight"].astype("int64").idxmax()
        normalized.loc[top_index, "Weight"] = int(normalized.loc[top_index, "Weight"]) + active_delta

    if idle_target >= 1.0:
        idle_row = {
            "Process Name": "Idle",
            "PID": 0,
            "Weight": int(round(idle_target)),
            "Module": "<Heuristic Low Power State>",
            "Function": "<C3>",
            "SymbolSource": "",
        }
        normalized = pd.concat([normalized, pd.DataFrame([idle_row])], ignore_index=True)

    return _recompute_cpu_sampling_percent(normalized)


def _has_synthetic_idle_row(cpu_sampling: pd.DataFrame) -> bool:
    required = {"Process Name", "Module", "Function"}
    if not required.issubset(cpu_sampling.columns):
        return False
    return (
        cpu_sampling["Process Name"].astype(str).eq("Idle")
        & cpu_sampling["Module"].astype(str).eq("<Heuristic Low Power State>")
        & cpu_sampling["Function"].astype(str).eq("<C3>")
    ).any()


def _recompute_cpu_sampling_percent(cpu_sampling: pd.DataFrame) -> pd.DataFrame:
    df = cpu_sampling.copy()
    weights = pd.to_numeric(df["Weight"], errors="coerce").fillna(0).astype("int64")
    df["Weight"] = weights
    total = float(weights.sum()) or 1.0
    df["% Weight"] = (weights / total) * 100.0
    columns = ["Process Name", "PID", "Weight", "% Weight", "Module", "Function"]
    present = [col for col in columns if col in df.columns]
    rest = [col for col in df.columns if col not in present]
    return df[present + rest].sort_values("Weight", ascending=False).reset_index(drop=True)


def _trace_capacity_us(trace: "TraceData") -> float | None:
    duration = _trace_duration_seconds(trace)
    cpu_count = _trace_cpu_count(trace)
    if duration is None or duration <= 0 or cpu_count is None or cpu_count <= 0:
        return None
    return float(duration) * float(cpu_count) * 1_000_000.0


def _timeline_busy_us(cpu_timeline: pd.DataFrame | None) -> float | None:
    if cpu_timeline is None or cpu_timeline.empty:
        return None
    cpu_cols = [col for col in cpu_timeline.columns if str(col).lower().startswith("cpu ")]
    if not cpu_cols or "StartTime" not in cpu_timeline.columns or "EndTime" not in cpu_timeline.columns:
        return None
    start = pd.to_numeric(cpu_timeline["StartTime"], errors="coerce")
    end = pd.to_numeric(cpu_timeline["EndTime"], errors="coerce")
    widths = (end - start).clip(lower=0)
    if widths.dropna().empty:
        return None
    total = 0.0
    for col in cpu_cols:
        pct = pd.to_numeric(cpu_timeline[col], errors="coerce").fillna(0.0).clip(lower=0.0, upper=100.0)
        total += float((widths * pct / 100.0).sum())
    return total


def _load_dimensions(store: "NativeEventStore", *, batch_size: int) -> _Dimensions:
    process_rows: list[dict[str, Any]] = []
    pid_to_name: dict[int, str] = {}
    tid_to_pid: dict[int, int] = {}
    image_index = _ImageIndex()

    process_cols = [
        "TimeStamp", "ProcessId", "ParentId", "SessionId",
        "ImageFileName", "CommandLine", "Type",
    ]
    for batch in store.iter_batches(
        "process",
        columns=process_cols,
        include_time=True,
        batch_size=batch_size,
    ):
        if batch.empty:
            continue
        for row in batch.to_dict(orient="records"):
            pid = _safe_int(row.get("ProcessId"))
            if pid is None:
                continue
            image = _clean_text(row.get("ImageFileName"))
            if image:
                pid_to_name[pid] = image
            process_rows.append(row)

    thread_cols = ["TimeStamp", "ProcessId", "ThreadId", "ThreadName", "Type"]
    for batch in store.iter_batches(
        "thread",
        columns=thread_cols,
        include_time=True,
        batch_size=batch_size,
    ):
        if batch.empty or "ThreadId" not in batch.columns or "ProcessId" not in batch.columns:
            continue
        for tid_value, pid_value in zip(batch["ThreadId"], batch["ProcessId"]):
            tid = _safe_int(tid_value)
            pid = _safe_int(pid_value)
            if tid is None or pid is None or tid <= 0 or pid < 0:
                continue
            tid_to_pid.setdefault(tid, pid)

    # M2: include the 4 identity columns so PDB GUID/Age/Name and
    # TimeDateStamp survive from parquet to the _ImageIndex.  These are
    # nullable (old caches / native-mode rows may lack them); iter_batches
    # returns None for absent values.
    image_cols = [
        "ImageBase", "ImageSize", "FileName", "Type", "ProcessId",
        "TimeDateStamp", "PdbGuid", "PdbAge", "PdbName",
    ]
    for batch in store.iter_batches(
        "image",
        columns=image_cols,
        include_time=False,
        batch_size=batch_size,
    ):
        if batch.empty:
            continue
        # zip over the core columns; pull identity columns per-row below.
        for base, size, file_name in zip(
            batch.get("ImageBase", pd.Series(dtype="object")),
            batch.get("ImageSize", pd.Series(dtype="object")),
            batch.get("FileName", pd.Series(dtype="object")),
        ):
            base_i = _safe_int(base)
            size_i = _safe_int(size)
            if base_i is None or size_i is None:
                continue
            image_index.add(base_i, size_i, _clean_text(file_name))
        # Second pass: populate pdb_identity for rows that have GUID data.
        # Iterating over records is simpler than indexing four optional columns.
        for row in batch.to_dict(orient="records"):
            base_i = _safe_int(row.get("ImageBase"))
            if base_i is None or base_i <= 0:
                continue
            if base_i in image_index.pdb_identity:
                continue  # already recorded from a DCStart row
            pdb_guid = row.get("PdbGuid") or None
            pdb_age = _safe_int(row.get("PdbAge"))
            pdb_name = row.get("PdbName") or None
            tds = _safe_int(row.get("TimeDateStamp"))
            if any(v is not None for v in (pdb_guid, pdb_age, pdb_name, tds)):
                image_index.pdb_identity[base_i] = {
                    "pdb_guid": str(pdb_guid) if pdb_guid else None,
                    "pdb_age": pdb_age,
                    "pdb_name": str(pdb_name) if pdb_name else None,
                    "time_date_stamp": tds,
                }
    image_index.finalize()

    process_table = _process_table_from_rows(process_rows)
    return _Dimensions(
        process_table=process_table,
        pid_to_name=pid_to_name,
        tid_to_pid=tid_to_pid,
        image_index=image_index,
    )


def _process_table_from_rows(rows: list[dict[str, Any]]) -> pd.DataFrame | None:
    if not rows:
        return None
    df = pd.DataFrame(rows)
    if df.empty or "ProcessId" not in df.columns:
        return None
    if "TimeStamp" in df.columns:
        df = df.sort_values("TimeStamp", kind="stable")
    keep = [
        "ProcessId", "ParentId", "SessionId", "ImageFileName",
        "CommandLine", "TimeStamp", "Type",
    ]
    cols = [col for col in keep if col in df.columns]
    df = df[cols].drop_duplicates(subset=["ProcessId"], keep="last")
    return df.reset_index(drop=True)


def _build_cpu_timeline(
    trace: "TraceData",
    store: "NativeEventStore",
    *,
    batch_size: int,
    bucket_seconds: float = 1.0,
    sample_rate_hz: int = _DEFAULT_SAMPLE_RATE_HZ,
) -> tuple[pd.DataFrame | None, int | None]:
    bucket_counts: dict[tuple[int, int], int] = defaultdict(int)
    max_bucket: int | None = None
    max_cpu: int | None = None
    max_seen_us: float | None = None

    for batch in store.iter_batches(
        "sampled_profile",
        columns=["TimeStamp", "CPU"],
        include_time=True,
        batch_size=batch_size,
    ):
        if batch.empty or "CPU" not in batch.columns:
            continue
        time_us = _relative_time_us(batch, store)
        cpus = pd.to_numeric(batch["CPU"], errors="coerce")
        valid = time_us.notna() & cpus.notna()
        if not valid.any():
            continue
        work = pd.DataFrame({
            "Bucket": (time_us[valid] / (bucket_seconds * 1_000_000.0))
            .clip(lower=0)
            .astype("int64"),
            "CPU": cpus[valid].astype("int64"),
        })
        if work.empty:
            continue
        grouped = work.groupby(["Bucket", "CPU"], dropna=False).size()
        for (bucket, cpu), count in grouped.items():
            bucket_i = int(bucket)
            cpu_i = int(cpu)
            bucket_counts[(bucket_i, cpu_i)] += int(count)
            max_bucket = bucket_i if max_bucket is None else max(max_bucket, bucket_i)
            max_cpu = cpu_i if max_cpu is None else max(max_cpu, cpu_i)
        batch_max_us = float(time_us[valid].max())
        max_seen_us = batch_max_us if max_seen_us is None else max(max_seen_us, batch_max_us)

    if not bucket_counts:
        return None, max_cpu

    duration_s = _trace_duration_seconds(trace)
    if duration_s is None and max_seen_us is not None:
        duration_s = max_seen_us / 1_000_000.0
    if duration_s is None or duration_s <= 0:
        duration_s = float((max_bucket or 0) + 1) * bucket_seconds

    cpu_count = _trace_cpu_count(trace)
    if (cpu_count is None or cpu_count <= 0) and max_cpu is not None:
        cpu_count = max_cpu + 1
    if cpu_count is None or cpu_count <= 0:
        return None, max_cpu

    bucket_count = max(
        int(math.ceil(duration_s / bucket_seconds)),
        int(max_bucket or 0) + 1,
        1,
    )
    rows: list[dict[str, Any]] = []
    for bucket in range(bucket_count):
        start_us = int(round(bucket * bucket_seconds * 1_000_000.0))
        end_us = int(round(min((bucket + 1) * bucket_seconds, duration_s) * 1_000_000.0))
        if end_us <= start_us:
            end_us = int(round((bucket + 1) * bucket_seconds * 1_000_000.0))
        width_s = (end_us - start_us) / 1_000_000.0
        if width_s <= 0:
            width_s = bucket_seconds
        row: dict[str, Any] = {"StartTime": start_us, "EndTime": end_us}
        max_samples = max(float(sample_rate_hz) * width_s, 1.0)
        for cpu in range(int(cpu_count)):
            samples = bucket_counts.get((bucket, cpu), 0)
            row[f"Cpu {cpu}"] = round(min(samples / max_samples * 100.0, 100.0), 2)
        rows.append(row)
    return pd.DataFrame(rows), max_cpu


def _build_cpu_sampling(
    store: "NativeEventStore",
    dimensions: _Dimensions,
    resolver: _AddressResolver,
    *,
    batch_size: int,
) -> pd.DataFrame | None:
    weights: dict[tuple[str, int, str, str, str], int] = defaultdict(int)
    profile_weight_time_scaled = False

    columns = [
        "ProcessId", "ThreadId", "PayloadThreadId", "InstructionPointer",
        "Weight", "ProfileWeight",
    ]
    for batch in store.iter_batches(
        "sampled_profile",
        columns=columns,
        include_time=False,
        batch_size=batch_size,
    ):
        if batch.empty:
            continue
        ips = [_safe_int(value) for value in batch.get("InstructionPointer", [])]
        resolver.prepare(ips)
        proc_ids = list(batch.get("ProcessId", []))
        tids = list(batch.get("ThreadId", []))
        payload_tids = list(batch.get("PayloadThreadId", []))
        base_weights = list(batch.get("Weight", []))
        profile_weights = list(batch.get("ProfileWeight", []))

        for idx, ip in enumerate(ips):
            pid = _resolved_sample_pid(
                _value_at(proc_ids, idx),
                _value_at(payload_tids, idx),
                _value_at(tids, idx),
                dimensions.tid_to_pid,
            )
            process_name = dimensions.pid_to_name.get(pid, "Unknown")
            weight = _positive_int(_value_at(profile_weights, idx))
            base_weight = _positive_int(_value_at(base_weights, idx))
            if weight is not None and base_weight is not None and weight > base_weight:
                profile_weight_time_scaled = True
            if weight is None:
                weight = base_weight or 1
            module, function = resolver.pair_for(ip)
            symbol_source = resolver.source_for(ip)
            weights[(process_name, pid, module, function, symbol_source)] += int(weight)

    if not weights:
        return None
    rows = [
        {
            "Process Name": process_name,
            "PID": pid,
            "Weight": weight,
            "Module": module,
            "Function": function,
            "SymbolSource": symbol_source,
        }
        for (process_name, pid, module, function, symbol_source), weight in weights.items()
    ]
    df = pd.DataFrame(rows)
    total = float(df["Weight"].sum()) or 1.0
    df["% Weight"] = df["Weight"].astype(float) / total * 100.0
    df = df[["Process Name", "PID", "Weight", "% Weight", "Module", "Function", "SymbolSource"]]
    df = df.sort_values("Weight", ascending=False).reset_index(drop=True)
    df.attrs["profile_weight_time_scaled"] = profile_weight_time_scaled
    return df


def _build_dpc_aggregates(
    trace: "TraceData",
    store: "NativeEventStore",
    resolver: _AddressResolver,
    *,
    batch_size: int,
) -> tuple[pd.DataFrame | None, pd.DataFrame | None, int | None]:
    bucket_counts: dict[tuple[str, int, int], int] = defaultdict(int)
    per_cpu: dict[tuple[str, int], list[float]] = defaultdict(lambda: [0.0, 0.0])
    max_cpu: int | None = None

    for event_class in ("dpc", "isr"):
        for batch in store.iter_batches(
            event_class,
            columns=[
                "CPU", "Routine", "DurationUs",
                "TimeStampQpc", "InitialTimeQpc",
            ],
            include_time=False,
            batch_size=batch_size,
        ):
            if batch.empty:
                continue
            routines = [_safe_int(value) for value in batch.get("Routine", [])]
            resolver.prepare(routines)
            cpus = [_safe_int(value) for value in batch.get("CPU", [])]
            durations = _duration_us_values(batch, store)
            for routine, cpu, duration in zip(routines, cpus, durations):
                if duration is None:
                    continue
                module = resolver.module_for(routine)
                duration_i = int(max(round(float(duration)), 0))
                low, high = _bucket_for(duration_i)
                bucket_counts[(module, low, high)] += 1
                if cpu is not None and cpu >= 0:
                    max_cpu = cpu if max_cpu is None else max(max_cpu, cpu)
                    slot = per_cpu[(module, cpu)]
                    slot[0] += float(duration_i)
                    slot[1] += 1.0

    dpc_df = _dpc_histogram_dataframe(bucket_counts)
    per_cpu_df = _dpc_per_cpu_dataframe(trace, store, per_cpu)
    return dpc_df, per_cpu_df, max_cpu


def _dpc_histogram_dataframe(
    bucket_counts: dict[tuple[str, int, int], int],
) -> pd.DataFrame | None:
    if not bucket_counts:
        return None
    module_totals: dict[str, int] = defaultdict(int)
    all_buckets: dict[tuple[int, int], int] = defaultdict(int)
    for (module, low, high), count in bucket_counts.items():
        module_totals[module] += count
        all_buckets[(low, high)] += count

    rows: list[dict[str, Any]] = []
    for (module, low, high), count in bucket_counts.items():
        total = module_totals.get(module, 0)
        rows.append({
            "Module": module,
            "Bucket_Low_us": low,
            "Bucket_High_us": high,
            "Count": count,
            "Pct": round(count / total * 100.0, 2) if total else 0.0,
        })

    all_total = sum(all_buckets.values())
    for (low, high), count in all_buckets.items():
        rows.append({
            "Module": "(all)",
            "Bucket_Low_us": low,
            "Bucket_High_us": high,
            "Count": count,
            "Pct": round(count / all_total * 100.0, 2) if all_total else 0.0,
        })
    return (
        pd.DataFrame(rows)
        .sort_values(["Module", "Bucket_Low_us"])
        .reset_index(drop=True)
    )


def _dpc_per_cpu_dataframe(
    trace: "TraceData",
    store: "NativeEventStore",
    per_cpu: dict[tuple[str, int], list[float]],
) -> pd.DataFrame | None:
    if not per_cpu:
        return None
    duration_s = _trace_duration_seconds(trace) or _store_duration_seconds(store) or 1.0
    duration_us = max(float(duration_s) * 1_000_000.0, 1.0)
    rows = []
    for (module, cpu), (dpc_us, count) in per_cpu.items():
        rows.append({
            "Module": module,
            "CPU": int(cpu),
            "DPC_us": int(round(dpc_us)),
            "Count": int(count),
            "Pct": float(dpc_us) / duration_us * 100.0,
        })
    return (
        pd.DataFrame(rows)
        .sort_values(["Module", "CPU"])
        .reset_index(drop=True)
    )


def _duration_us_values(batch: pd.DataFrame, store: "NativeEventStore") -> list[float | None]:
    duration_col = batch.get("DurationUs")
    if duration_col is None:
        duration = pd.Series([math.nan] * len(batch), index=batch.index)
    else:
        duration = pd.to_numeric(duration_col, errors="coerce")
    values = duration.astype("float64")
    missing = values.isna() | (values < 0)
    if missing.any() and store.timebase.perf_freq:
        ts = pd.to_numeric(batch.get("TimeStampQpc"), errors="coerce")
        initial = pd.to_numeric(batch.get("InitialTimeQpc"), errors="coerce")
        converted = (ts - initial) * 1_000_000.0 / float(store.timebase.perf_freq)
        values = values.where(~missing, converted)
    return [
        None if pd.isna(value) else max(float(value), 0.0)
        for value in values.tolist()
    ]


def _relative_time_us(batch: pd.DataFrame, store: "NativeEventStore") -> pd.Series:
    if "TimeStamp" in batch.columns:
        return pd.to_numeric(batch["TimeStamp"], errors="coerce")
    qpc = pd.to_numeric(batch.get("TimeStampQpc"), errors="coerce")
    if store.timebase.has_qpc_mapping():
        return ((qpc - int(store.timebase.qpc_origin)) * 1_000_000.0 / float(store.timebase.perf_freq)).round()
    return qpc


def _build_process_info_text(process_table: pd.DataFrame | None) -> str | None:
    if process_table is None or process_table.empty:
        return None
    lines = ["Process records", "==="]
    for _, row in process_table.iterrows():
        typ = _clean_text(row.get("Type")) or "Process"
        cls = typ if typ.startswith("Process") else f"Process/{typ}"
        pid = _safe_int(row.get("ProcessId")) or 0
        parent = _safe_int(row.get("ParentId")) or 0
        session = _safe_int(row.get("SessionId")) or 0
        ts = _safe_int(row.get("TimeStamp")) or 0
        image = _clean_text(row.get("ImageFileName"))
        cmd = _clean_text(row.get("CommandLine"))
        lines.append(
            f"{cls} TimeStamp={ts} PID={pid} Parent={parent} Session={session} "
            f"Image={image!r} CmdLine={cmd!r}"
        )
    lines.append("")
    return "\n".join(lines) + "\n"


def _build_symbolizer_from_images(trace: "TraceData", image_index: _ImageIndex) -> None:
    if getattr(trace, "symbolizer", None) is not None:
        return
    if not image_index.intervals:
        return
    try:
        from etw_analyzer.native.symbolizer import Symbolizer
        symbolizer = Symbolizer(symbol_path=trace.symbol_path)
    except Exception:
        return

    # M2: stash the per-base PDB identity dict on the trace so M3 can pass
    # pdb_guid/pdb_age/pdb_name/time_date_stamp to the extended add_module.
    # Seam: trace.pdb_identity[ImageBase] = {pdb_guid, pdb_age, pdb_name,
    # time_date_stamp}.  M2 does NOT change the add_module call yet.
    if image_index.pdb_identity:
        trace.pdb_identity = dict(image_index.pdb_identity)

    seen_bases: set[int] = set()
    for item in image_index.intervals:
        if item.base in seen_bases:
            continue
        seen_bases.add(item.base)
        try:
            # M3 will extend this call to pass pdb_guid/pdb_age/pdb_name/
            # time_date_stamp from trace.pdb_identity[item.base] (or
            # directly from item.pdb_guid etc.) once add_module grows the
            # keyword-only identity params.
            symbolizer.add_module(item.base, item.end - item.base, item.file_name)
        except Exception:
            continue
    trace.symbolizer = symbolizer


def _apply_store_metadata(
    trace: "TraceData",
    store: "NativeEventStore",
    *,
    observed_max_cpu: int | None = None,
) -> None:
    existing = trace.raw_csv.get("trace_metadata")
    if existing is not None and not existing.empty:
        _apply_existing_metadata(trace, existing)

    if trace.timestamp_frequency is None and store.timebase.perf_freq:
        trace.timestamp_frequency = float(store.timebase.perf_freq)
    if trace.duration_seconds is None:
        duration = _store_duration_seconds(store)
        if duration is not None and duration > 0:
            trace.duration_seconds = duration
    if trace.cpu_count is None and observed_max_cpu is not None and observed_max_cpu >= 0:
        trace.cpu_count = int(observed_max_cpu) + 1

    if existing is None or existing.empty:
        row: dict[str, Any] = {}
        if trace.cpu_count:
            row["NumberOfProcessors"] = int(trace.cpu_count)
        if trace.duration_seconds:
            row["DurationSeconds"] = float(trace.duration_seconds)
        if trace.timestamp_frequency:
            row["PerfFreq"] = int(trace.timestamp_frequency)
        start_qpc = _store_min_qpc(store)
        end_qpc = _store_max_qpc(store)
        if start_qpc is not None:
            row["StartTime"] = int(start_qpc)
        if end_qpc is not None:
            row["EndTime"] = int(end_qpc)
        if row:
            trace.raw_csv["trace_metadata"] = pd.DataFrame([row])
    else:
        # Preserve the original metadata row, but fill common blanks so
        # cache reloads expose the values discovered during streaming.
        df = existing.copy()
        if trace.cpu_count and "NumberOfProcessors" not in df.columns:
            df["NumberOfProcessors"] = int(trace.cpu_count)
        if trace.duration_seconds and "DurationSeconds" not in df.columns:
            df["DurationSeconds"] = float(trace.duration_seconds)
        if trace.timestamp_frequency and "PerfFreq" not in df.columns:
            df["PerfFreq"] = int(trace.timestamp_frequency)
        trace.raw_csv["trace_metadata"] = df


def _apply_existing_metadata(trace: "TraceData", df: pd.DataFrame) -> None:
    cpu = _metadata_value(df, "NumberOfProcessors")
    if trace.cpu_count is None and cpu is not None and cpu > 0:
        trace.cpu_count = int(cpu)
    duration = _metadata_value(df, "DurationSeconds")
    if trace.duration_seconds is None and duration is not None and duration > 0:
        trace.duration_seconds = float(duration)
    freq = _metadata_value(df, "PerfFreq")
    if trace.timestamp_frequency is None and freq is not None and freq > 0:
        trace.timestamp_frequency = float(freq)


def _metadata_value(df: pd.DataFrame, column: str) -> float | None:
    if df is None or df.empty or column not in df.columns:
        return None
    values = pd.to_numeric(df[column], errors="coerce").dropna()
    if values.empty:
        return None
    return float(values.iloc[0])


def _store_duration_seconds(store: "NativeEventStore") -> float | None:
    start = _store_min_qpc(store)
    end = _store_max_qpc(store)
    if start is None or end is None or end <= start:
        return None
    if not store.timebase.perf_freq:
        return None
    return (float(end) - float(start)) / float(store.timebase.perf_freq)


def _store_min_qpc(store: "NativeEventStore") -> int | None:
    values = [
        dataset.min_qpc
        for dataset in store.manifest.datasets.values()
        if dataset.min_qpc is not None
    ]
    return min(values) if values else None


def _store_max_qpc(store: "NativeEventStore") -> int | None:
    values = [
        dataset.max_qpc
        for dataset in store.manifest.datasets.values()
        if dataset.max_qpc is not None
    ]
    return max(values) if values else None


def _trace_duration_seconds(trace: "TraceData") -> float | None:
    value = getattr(trace, "duration_seconds", None)
    if value and value > 0:
        return float(value)
    df = trace.raw_csv.get("trace_metadata")
    value = _metadata_value(df, "DurationSeconds") if df is not None else None
    return float(value) if value and value > 0 else None


def _trace_cpu_count(trace: "TraceData") -> int | None:
    value = getattr(trace, "cpu_count", None)
    if value and value > 0:
        return int(value)
    df = trace.raw_csv.get("trace_metadata")
    value = _metadata_value(df, "NumberOfProcessors") if df is not None else None
    return int(value) if value and value > 0 else None


def _resolved_sample_pid(
    process_id: Any,
    payload_thread_id: Any,
    thread_id: Any,
    tid_to_pid: dict[int, int],
) -> int:
    pid = _safe_int(process_id)
    needs_resolution = pid is None or pid <= 0 or pid == 0xFFFFFFFF
    if needs_resolution:
        for candidate in (_safe_int(payload_thread_id), _safe_int(thread_id)):
            if candidate is None:
                continue
            mapped = tid_to_pid.get(candidate)
            if mapped is not None:
                return int(mapped)
    if pid == 0xFFFFFFFF:
        return -1
    return int(pid or 0)


def _value_at(values: list[Any], index: int) -> Any:
    return values[index] if index < len(values) else None


def _positive_int(value: Any) -> int | None:
    number = _safe_int(value)
    return number if number is not None and number > 0 else None


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


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    return str(value or "").strip("\x00").strip()


def _module_basename(file_name: str) -> str:
    value = _clean_text(file_name)
    if not value:
        return ""
    return ntpath.basename(value).lower()


__all__ = [
    "StreamingAggregateResult",
    "build_streaming_aggregates",
]
