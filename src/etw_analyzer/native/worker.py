"""Child-process entry point for native ETW cache generation."""

from __future__ import annotations

import argparse
import json
import os
import threading
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from etw_analyzer.native import cache as native_cache
from etw_analyzer.trace_state import TraceData


HEARTBEAT_INTERVAL_SECONDS = 5.0
RESULT_FILENAME = "worker-result.json"


@dataclass(frozen=True)
class NativeWorkerRequest:
    etl_path: Path
    export_dir: Path
    staging_dir: Path
    trace_id: str
    mode: str
    strategy: str
    schema_version: int
    symbol_path_env_key: str | None
    requested_event_classes: list[str]

    @classmethod
    def from_file(cls, path: Path) -> "NativeWorkerRequest":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ValueError(f"failed to read worker request: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("worker request must be a JSON object")

        etl_path = _absolute_path(data, "etl_path")
        export_dir = _absolute_path(data, "export_dir")
        staging_dir = _absolute_path(data, "staging_dir")
        trace_id = str(data.get("trace_id") or "")
        if not trace_id:
            raise ValueError("worker request is missing trace_id")
        mode = str(data.get("mode") or "")
        if mode != "native":
            raise ValueError(f"worker request mode must be 'native', got {mode!r}")
        strategy = str(data.get("strategy") or "")
        valid_strategies = {
            native_cache.MATERIALIZED_SMALL_STRATEGY,
            native_cache.STREAMING_EVENT_STORE_STRATEGY,
        }
        if strategy not in valid_strategies:
            raise ValueError(
                "worker request strategy must be one of "
                f"{sorted(valid_strategies)!r}"
            )
        schema_version = int(data.get("schema_version", -1))
        if schema_version != native_cache.SCHEMA_VERSION:
            raise ValueError(
                f"worker request schema_version must be {native_cache.SCHEMA_VERSION}"
            )
        raw_classes = data.get("requested_event_classes", [])
        if not isinstance(raw_classes, list) or not all(
            isinstance(item, str) for item in raw_classes
        ):
            raise ValueError("worker request requested_event_classes must be a string list")
        symbol_key = data.get("symbol_path_env_key")
        if symbol_key is not None and not isinstance(symbol_key, str):
            raise ValueError("worker request symbol_path_env_key must be a string")
        return cls(
            etl_path=etl_path,
            export_dir=export_dir,
            staging_dir=staging_dir,
            trace_id=trace_id,
            mode=mode,
            strategy=strategy,
            schema_version=schema_version,
            symbol_path_env_key=symbol_key,
            requested_event_classes=list(dict.fromkeys(raw_classes)),
        )


class JsonlWriter:
    def __init__(self) -> None:
        self._lock = threading.Lock()

    def write(self, payload: dict[str, Any]) -> None:
        payload.setdefault("time", time.time())
        with self._lock:
            print(json.dumps(payload, sort_keys=True), flush=True)

    def heartbeat(self, phase: str) -> None:
        self.write({"type": "heartbeat", "phase": phase})

    def progress(self, phase: str, **fields: Any) -> None:
        payload = {"type": "progress", "phase": phase}
        payload.update(fields)
        self.write(payload)

    def result(self, payload: dict[str, Any]) -> None:
        payload = dict(payload)
        payload["type"] = "result"
        self.write(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    args = parser.parse_args(argv)

    writer = JsonlWriter()
    stop_heartbeat = threading.Event()
    heartbeat_thread = threading.Thread(
        target=_heartbeat_loop,
        args=(writer, stop_heartbeat),
        daemon=True,
        name="native-worker-heartbeat",
    )
    heartbeat_thread.start()

    try:
        writer.progress("reading-request")
        request = NativeWorkerRequest.from_file(Path(args.request))
        writer.progress("building-cache", trace_id=request.trace_id)
        payload = build_native_cache(request, writer)
        _write_result_file(request.staging_dir, payload)
        writer.result(payload)
        return 0
    except Exception as exc:
        payload = {
            "ok": False,
            "error": str(exc),
            "error_type": type(exc).__name__,
            "traceback_tail": traceback.format_exc(limit=20),
        }
        writer.result(payload)
        return 1
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=1.0)


def build_native_cache(
    request: NativeWorkerRequest,
    writer: JsonlWriter | None = None,
) -> dict[str, Any]:
    """Build a native v2 cache in staging using the requested strategy."""

    writer = writer or JsonlWriter()
    if not request.etl_path.exists():
        raise FileNotFoundError(f"ETL not found: {request.etl_path}")
    request.staging_dir.mkdir(parents=True, exist_ok=True)

    if request.strategy == native_cache.STREAMING_EVENT_STORE_STRATEGY:
        return build_streaming_event_store_cache(request, writer)

    # Reuse the existing native extraction/aggregation path. This imports the
    # tool module inside the child process only; it does not start the MCP
    # server, and it keeps worker output schema identical to in-process native.
    import etw_analyzer.tools.trace_mgmt as trace_mgmt
    from etw_analyzer.native import ExtractStats, extract_events

    requested = set(request.requested_event_classes or trace_mgmt._DUMPER_EVENT_CLASSES)
    wanted_with_aux = set(requested)
    wanted_with_aux.update({
        "Image/Load", "Image/DCStart",
        "PerfInfo/DPC", "PerfInfo/ThreadedDPC",
        "PerfInfo/TimerDPC", "PerfInfo/ISR",
        "Process/Start", "Process/End",
        "Process/DCStart", "Process/DCEnd",
        "Process/Defunct",
        "Thread/Start", "Thread/End",
        "Thread/DCStart", "Thread/DCEnd",
        "DiskIo/Read", "DiskIo/Write", "DiskIo/FlushBuffers",
        "EventTrace/Header", "SystemConfig",
    })

    symbol_path = (
        os.environ.get(request.symbol_path_env_key)
        if request.symbol_path_env_key
        else None
    )
    trace = TraceData(
        trace_id=request.trace_id,
        etl_path=request.etl_path,
        export_dir=request.staging_dir,
        symbol_path=symbol_path,
        mode="native",
        raw_csv={},
    )

    writer.progress(
        "extracting-events",
        requested_event_classes=sorted(requested),
        event_class_count=len(wanted_with_aux),
    )
    stats_sink: list[ExtractStats] = []
    results = extract_events(
        request.etl_path,
        event_classes=wanted_with_aux,
        stats_sink=stats_sink,
    )
    if stats_sink:
        trace._native_extract_stats = stats_sink[-1]
        trace_mgmt._apply_native_metadata(trace)

    writer.progress("building-symbolizer")
    trace_mgmt._build_symbolizer_from_images(trace, results)

    for name in (
        "PerfInfo/DPC", "PerfInfo/ThreadedDPC", "PerfInfo/TimerDPC",
        "PerfInfo/ISR", "Process/Start", "Process/End",
        "Process/DCStart", "Process/DCEnd", "Process/Defunct",
        "Thread/Start", "Thread/End", "Thread/DCStart", "Thread/DCEnd",
        "DiskIo/Read", "DiskIo/Write", "DiskIo/FlushBuffers",
        "EventTrace/Header", "SystemConfig",
    ):
        df = results.get(name)
        if df is not None and not df.empty:
            trace.raw_csv[name] = df

    writer.progress("persisting-event-cache")
    persisted_stems: list[str] = []
    for canonical, (attr, stem) in trace_mgmt._DUMPER_EVENT_CLASSES.items():
        if canonical not in results:
            continue
        df = results[canonical]
        if df is None:
            continue
        setattr(trace, attr, df)
        trace_mgmt._persist_dumper_parquet(
            df,
            request.staging_dir / f"{stem}.parquet",
        )
        persisted_stems.append(stem)

    writer.progress("running-aggregators")
    trace_mgmt._run_native_aggregators(trace)
    if "cpu_sampling" not in trace.raw_csv:
        trace_mgmt._synthesize_native_cpu_sampling(trace)
    trace_mgmt._populate_metadata(trace)

    writer.progress("writing-manifest")
    trace_mgmt._write_cache_manifest(
        request.staging_dir,
        request.etl_path,
        "native",
        trace.raw_csv,
        dumper_stems=set(persisted_stems),
    )
    manifest = native_cache.read_manifest(request.staging_dir)
    if manifest is None:
        raise native_cache.NativeCacheError("native worker did not write manifest")
    native_cache.validate_manifest(
        manifest,
        request.staging_dir,
        request.etl_path,
        mode="native",
    )

    if trace.symbolizer is not None:
        try:
            trace.symbolizer.close()
        except Exception:
            pass

    return {
        "ok": True,
        "message": "native worker completed",
        "trace_id": request.trace_id,
        "staging_dir": str(request.staging_dir),
        "export_dir": str(request.export_dir),
        "manifest": native_cache.MANIFEST_FILENAME,
        "datasets": sorted(trace.raw_csv),
        "dumper_datasets": sorted(persisted_stems),
        "event_counts": dict(trace.event_counts),
    }


def build_streaming_event_store_cache(
    request: NativeWorkerRequest,
    writer: JsonlWriter | None = None,
) -> dict[str, Any]:
    """Stream ProcessTrace output into a chunked event-store v2 cache."""

    writer = writer or JsonlWriter()

    import etw_analyzer.tools.trace_mgmt as trace_mgmt
    from etw_analyzer.native import ExtractStats, extract_events_to_store
    from etw_analyzer.native.event_store import NATIVE_EVENT_STORE_DATASET_KIND

    requested = set(request.requested_event_classes or trace_mgmt._DUMPER_EVENT_CLASSES)
    wanted_with_aux = set(requested)
    wanted_with_aux.update({
        "SampledProfile",
        "Image/Load", "Image/Unload", "Image/DCStart", "Image/DCEnd",
        "PerfInfo/DPC", "PerfInfo/ThreadedDPC",
        "PerfInfo/TimerDPC", "PerfInfo/ISR",
        "Process/Start", "Process/End",
        "Process/DCStart", "Process/DCEnd", "Process/Defunct",
        "Thread/Start", "Thread/End",
        "Thread/DCStart", "Thread/DCEnd", "Thread/SetName",
    })
    if "CSwitch" in requested:
        wanted_with_aux.add("CSwitch")
    if "ReadyThread" in requested:
        wanted_with_aux.add("ReadyThread")

    symbol_path = (
        os.environ.get(request.symbol_path_env_key)
        if request.symbol_path_env_key
        else None
    )
    trace = TraceData(
        trace_id=request.trace_id,
        etl_path=request.etl_path,
        export_dir=request.staging_dir,
        symbol_path=symbol_path,
        mode="native",
        raw_csv={},
    )

    writer.progress(
        "streaming-events",
        requested_event_classes=sorted(requested),
        event_class_count=len(wanted_with_aux),
    )
    stats_sink: list[ExtractStats] = []
    store = extract_events_to_store(
        request.etl_path,
        request.staging_dir,
        event_classes=wanted_with_aux,
        stats_sink=stats_sink,
        capture_stacks=bool({"CSwitch", "ReadyThread"} & requested),
    )
    trace.event_store = store
    if stats_sink:
        trace._native_extract_stats = stats_sink[-1]
        trace_mgmt._apply_native_metadata(trace)

    writer.progress("building-streaming-aggregates")
    from etw_analyzer.native.aggregators.streaming import build_streaming_aggregates

    aggregate_result = build_streaming_aggregates(trace, store)

    datasets: list[native_cache.CacheDataset] = []
    materialized_frames: dict[str, Any] = {}
    metadata = trace.raw_csv.get("trace_metadata")
    if metadata is not None and not metadata.empty:
        materialized_frames["trace_metadata"] = metadata
    materialized_frames.update(aggregate_result.dataframes)

    for name, df in sorted(materialized_frames.items()):
        if df is None or getattr(df, "empty", True):
            continue
        path = request.staging_dir / f"{name}.parquet"
        df.to_parquet(path, index=False)
        datasets.append(native_cache.CacheDataset(
            name=name,
            kind="parquet",
            path=f"{name}.parquet",
            row_count=len(df),
            materialize_on_load=True,
        ))

    text_filenames = {
        "dpc_isr_raw": "dpcisr.txt",
        "cswitch_raw": "cswitch.txt",
        "tracestats": "tracestats.txt",
        "sysconfig": "sysconfig.txt",
        "process_info": "process_info.txt",
        "diskio": "diskio.txt",
    }
    for name, text in sorted(aggregate_result.texts.items()):
        if not text:
            continue
        filename = text_filenames.get(name, f"{name}.txt")
        (request.staging_dir / filename).write_text(text, encoding="utf-8")
        datasets.append(native_cache.CacheDataset(
            name=name,
            kind="text",
            path=filename,
            row_count=1,
            materialize_on_load=True,
        ))

    datasets.append(store.cache_dataset())

    writer.progress(
        "writing-streaming-manifest",
        event_store_rows=store.row_count,
        event_store_datasets=sorted(store.manifest.datasets),
    )
    native_cache.write_manifest(
        request.staging_dir,
        native_cache.CacheManifest.event_store_streaming(
            request.etl_path,
            datasets,
        ),
    )
    manifest = native_cache.read_manifest(request.staging_dir)
    if manifest is None:
        raise native_cache.NativeCacheError("native worker did not write manifest")
    native_cache.validate_manifest(
        manifest,
        request.staging_dir,
        request.etl_path,
        mode="native",
    )

    return {
        "ok": True,
        "message": "native streaming worker completed",
        "trace_id": request.trace_id,
        "staging_dir": str(request.staging_dir),
        "export_dir": str(request.export_dir),
        "manifest": native_cache.MANIFEST_FILENAME,
        "strategy": native_cache.STREAMING_EVENT_STORE_STRATEGY,
        "datasets": sorted(dataset.name for dataset in datasets),
        "aggregate_warnings": list(aggregate_result.warnings),
        "event_store_kind": NATIVE_EVENT_STORE_DATASET_KIND,
        "event_store_rows": store.row_count,
        "event_store_datasets": {
            name: {
                "row_count": dataset.row_count,
                "parts": len(dataset.parts),
                "min_qpc": dataset.min_qpc,
                "max_qpc": dataset.max_qpc,
            }
            for name, dataset in sorted(store.manifest.datasets.items())
        },
    }


def _heartbeat_loop(writer: JsonlWriter, stop_event: threading.Event) -> None:
    while not stop_event.wait(HEARTBEAT_INTERVAL_SECONDS):
        writer.heartbeat("running")


def _absolute_path(data: dict[str, Any], key: str) -> Path:
    raw = data.get(key)
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"worker request is missing {key}")
    path = Path(raw)
    if not path.is_absolute():
        raise ValueError(f"worker request {key} must be absolute")
    return path


def _write_result_file(staging_dir: Path, payload: dict[str, Any]) -> None:
    (staging_dir / RESULT_FILENAME).write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
