"""Post-sidecar aggregator runner.

The C# sidecar (``etw-extract.exe``) writes ETW Layer-1 (raw decoded
events) and Layer-2 (per-class parquets) into a staging directory. This
module runs the Python-side aggregators (Layer 3 — ``cpu_sampling``,
``dpc_isr``, ``stacks``, ``cpu_timeline``, ``sysconfig``, ``process_info``,
``diskio``, ``tracestats``) against those inputs so the Python tool surface
returns the same shape regardless of which producer extracted the trace.

Architectural split (per ``rust-hybrid-migration-plan.md`` §4 and
``spike-contract.md``):

* ``worker.py``      — legacy in-process native extractor + aggregators.
                       Still used for ``mode="native"`` (no sidecar).
* ``aggregation_worker.py`` (this file) — runs aggregators *only*, against
                       a pre-existing staging dir produced by the sidecar.
                       Used for ``mode="dotnet"``.

The contract is intentionally narrow:

* Input  — ``staging_dir`` with the sidecar's parquets + manifest.
* Output — additional aggregate parquets written into the same dir, and
           a refreshed manifest. The supervisor handles atomic promotion
           to the final cache dir.

Failure mode is best-effort: individual aggregator exceptions are logged
but do not fail the whole run, mirroring the legacy native path. The
manifest is rewritten only if every step succeeded; on failure the staging
dir is left intact for debugging.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

from etw_analyzer.native import cache as native_cache
from etw_analyzer.native import aggregation_worker_adapters as dotnet_adapters
from etw_analyzer.native import telemetry as _telemetry
from etw_analyzer.trace_state import TraceData


LOGGER = logging.getLogger(__name__)


# Sidecar parquet stems (per dotnet/src/Program.cs) → (TraceData attribute,
# canonical event-class name from trace_mgmt._DUMPER_EVENT_CLASSES). Kept
# locally so aggregation_worker doesn't import trace_mgmt at module top —
# trace_mgmt imports the whole tool surface and is heavyweight.
_SIDECAR_STEM_TO_ATTR: dict[str, tuple[str, str]] = {
    "sampled_profile":   ("dumper_df",           "SampledProfile"),
    "cswitch_events":    ("cswitch_events_df",   "CSwitch"),
    "tcpip_recv":        ("tcpip_recv_df",       "TcpIp/Recv"),
    "tcpip_send":        ("tcpip_send_df",       "TcpIp/Send"),
    "tcpip_retransmit":  ("tcpip_retransmit_df", "TcpIp/Retransmit"),
    "tcpip_connect":     ("tcpip_connect_df",    "TcpIp/Connect"),
    "tcpip_accept":      ("tcpip_accept_df",     "TcpIp/Accept"),
    "udp_recv":          ("udp_recv_df",         "UdpIp/Recv"),
    "udp_send":          ("udp_send_df",         "UdpIp/Send"),
    "afd_recv":          ("afd_recv_df",         "AFD/Recv"),
    "afd_send":          ("afd_send_df",         "AFD/Send"),
    "afd_connect":       ("afd_connect_df",      "AFD/Connect"),
    "afd_accept":        ("afd_accept_df",       "AFD/Accept"),
    "afd_close":         ("afd_close_df",        "AFD/Close"),
    "ndis_drops":        ("ndis_drops_df",       "NdisDrop"),
    "packet_capture":    ("packet_capture_df",   "NdisPacketCapture"),
    "http_recv":         ("http_recv_df",        "HttpService/Recv"),
    "http_deliver":      ("http_deliver_df",     "HttpService/Deliver"),
    "http_send":         ("http_send_df",        "HttpService/Send"),
    "http_close":        ("http_close_df",       "HttpService/Close"),
    "quic_conn_created": ("quic_conn_created_df", "Quic/ConnectionCreated"),
    "quic_conn_closed":  ("quic_conn_closed_df",  "Quic/ConnectionClosed"),
    "quic_packet_recv":  ("quic_packet_recv_df",  "Quic/PacketRecv"),
    "quic_packet_send":  ("quic_packet_send_df",  "Quic/PacketSend"),
    "quic_ack_recv":     ("quic_ack_recv_df",     "Quic/AckReceived"),
    # Phase B (dotnet sidecar): per-opcode kernel-meta parquets. Stems
    # mirror trace_mgmt._DUMPER_EVENT_CLASSES so _rewrite_manifest
    # creates dumper-parquet placeholders for classes the sidecar
    # skipped (zero-event classes). Adapters in this module promote the
    # rows into raw_csv[<canonical>] for the native aggregators.
    "perfinfo_dpc":          ("perfinfo_dpc_df",          "PerfInfo/DPC"),
    "perfinfo_threaded_dpc": ("perfinfo_threaded_dpc_df", "PerfInfo/ThreadedDPC"),
    "perfinfo_timer_dpc":    ("perfinfo_timer_dpc_df",    "PerfInfo/TimerDPC"),
    "perfinfo_isr":          ("perfinfo_isr_df",          "PerfInfo/ISR"),
    "process_start":         ("process_start_df",         "Process/Start"),
    "process_end":           ("process_end_df",           "Process/End"),
    "process_dcstart":       ("process_dcstart_df",       "Process/DCStart"),
    "process_dcend":         ("process_dcend_df",         "Process/DCEnd"),
    "process_defunct":       ("process_defunct_df",       "Process/Defunct"),
    "thread_start":          ("thread_start_df",          "Thread/Start"),
    "thread_end":            ("thread_end_df",            "Thread/End"),
    "thread_dcstart":        ("thread_dcstart_df",        "Thread/DCStart"),
    "thread_dcend":          ("thread_dcend_df",          "Thread/DCEnd"),
    "diskio_read":           ("diskio_read_df",           "DiskIo/Read"),
    "diskio_write":          ("diskio_write_df",          "DiskIo/Write"),
    "diskio_flushbuffers":   ("diskio_flushbuffers_df",   "DiskIo/FlushBuffers"),
    "image_load":            ("image_load_df",            "Image/Load"),
    "image_dcstart":         ("image_dcstart_df",         "Image/DCStart"),
    "image_dcend":           ("image_dcend_df",           "Image/DCEnd"),
    "eventtrace_header":     ("eventtrace_header_df",     "EventTrace/Header"),
}


# Auxiliary parquets the sidecar emits that are not in _DUMPER_EVENT_CLASSES
# but are still useful to downstream aggregators. They land in ``raw_csv``
# under the canonical event-class name so the existing aggregators find them.
_SIDECAR_AUX_STEMS: dict[str, str] = {
    "process":    "Process/DCStart",
    "image":      "Image/DCStart",
    "diskio":     "DiskIo/Read",
    "dpc_isr":    "PerfInfo/DPC",
    # ReadyThread events feed both the cpu_timeline and the lock-contention
    # aggregators. The sidecar emits an empty parquet today (the test
    # fixture had no ReadyThread events) but the schema is correct; map
    # it under the canonical native event-class name so any consumer that
    # looks in raw_csv finds the (possibly empty) DataFrame.
    "readythread": "ReadyThread",
}


@dataclass
class AggregationResult:
    """Outcome of running aggregators against a sidecar staging dir."""

    ok: bool
    message: str
    staging_dir: Path
    datasets_written: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    manifest_path: Path | None = None


def run_aggregation_worker(
    staging_dir: Path,
    etl_path: Path,
    trace_id: str,
    *,
    producer: str = "dotnet",
) -> AggregationResult:
    """Run the Python aggregators against a sidecar staging directory.

    Parameters
    ----------
    staging_dir:
        Directory the sidecar wrote its layer-1/2 parquets and manifest into.
        Aggregator output is written alongside those files.
    etl_path:
        Original ETL path — needed for manifest re-write (ETL identity
        round-trip is part of the cache match check).
    trace_id:
        Echoed back for symmetry with the rest of the worker protocol.
    producer:
        Producer name to stamp on the rewritten manifest. Defaults to
        ``"dotnet"`` because that's the only sidecar that exists today,
        but kept parameterized for future Rust / other producers.

    Returns
    -------
    :class:`AggregationResult` describing what was written. Best-effort:
    individual aggregator failures are recorded under ``warnings`` and do
    not flip ``ok`` to False; only manifest-rewrite failures or an absent
    sidecar manifest are fatal.
    """

    staging_dir = staging_dir.resolve()
    if not staging_dir.exists():
        return AggregationResult(
            ok=False,
            message=f"staging dir does not exist: {staging_dir}",
            staging_dir=staging_dir,
        )

    try:
        sidecar_manifest = native_cache.read_manifest(staging_dir)
    except native_cache.NativeCacheError as exc:
        return AggregationResult(
            ok=False,
            message=f"sidecar manifest unreadable: {exc}",
            staging_dir=staging_dir,
        )
    if sidecar_manifest is None:
        return AggregationResult(
            ok=False,
            message=(
                "sidecar wrote no cache manifest at "
                f"{staging_dir / native_cache.MANIFEST_FILENAME}"
            ),
            staging_dir=staging_dir,
        )

    result = AggregationResult(
        ok=True,
        message="aggregation completed",
        staging_dir=staging_dir,
    )

    trace = _build_trace_from_staging(
        staging_dir=staging_dir,
        etl_path=etl_path,
        trace_id=trace_id,
        sidecar_manifest=sidecar_manifest,
        warnings=result.warnings,
    )

    # Run aggregators. Import lazily so this module stays importable from
    # the supervisor even when the legacy worker is not loaded.
    try:
        import etw_analyzer.tools.trace_mgmt as trace_mgmt
    except Exception as exc:
        return AggregationResult(
            ok=False,
            message=f"failed to import trace_mgmt: {exc}",
            staging_dir=staging_dir,
        )

    # Derive header-equivalent metadata from the sidecar parquets +
    # manifest BEFORE the aggregators run, so cpu_timeline /
    # trace_metadata / tracestats have what they need.
    try:
        # Phase B: when the sidecar emitted EventTrace/Header, that
        # row is authoritative — use it instead of the QPC-range
        # heuristic. ``eventtrace_header_to_metadata`` returns None
        # when the parquet is absent or missing required columns,
        # which falls through to the heuristic path below.
        header_df = trace.raw_csv.get("EventTrace/Header")
        derived = dotnet_adapters.eventtrace_header_to_metadata(header_df)
        if derived is None:
            derived = dotnet_adapters.derive_metadata_from_sidecar(
                trace, sidecar_manifest
            )
        dotnet_adapters.apply_metadata_to_trace(trace, derived)
        # Pre-populate the trace_metadata DataFrame so the existing
        # ``_native_metadata_dataframe`` path (which only kicks in when
        # ``_native_extract_stats`` is populated) can be skipped — the
        # sidecar produces neither logfile_metadata nor extract_stats.
        if "trace_metadata" not in trace.raw_csv:
            trace.raw_csv["trace_metadata"] = (
                dotnet_adapters.build_trace_metadata_dataframe(
                    derived, sidecar_manifest,
                    eventtrace_header_df=header_df,
                )
            )
        # Seed event_counts from the manifest so build_tracestats_text
        # has provider-equivalent rows to render even though we have no
        # ExtractStats under dotnet mode.
        dotnet_adapters.populate_event_counts_from_manifest(
            trace, sidecar_manifest
        )
    except Exception as exc:
        result.warnings.append(f"dotnet metadata derivation failed: {exc}")
        LOGGER.warning(
            "aggregation_worker: dotnet metadata derivation failed: %s",
            exc,
            exc_info=True,
        )

    try:
        trace_mgmt._run_native_aggregators(trace)
    except Exception as exc:
        # _run_native_aggregators is already best-effort internally; if it
        # raises here the failure is structural (e.g. import error) and we
        # surface it but keep going so the manifest still gets rewritten
        # with whatever we DID produce.
        result.warnings.append(f"native aggregators raised: {exc}")
        LOGGER.warning("aggregation_worker: %s", exc, exc_info=True)

    # cpu_sampling synthesis is its own step (the legacy worker.py calls it
    # only when the aggregator failed to produce a cpu_sampling DataFrame).
    if "cpu_sampling" not in trace.raw_csv:
        try:
            trace_mgmt._synthesize_native_cpu_sampling(trace)
        except Exception as exc:
            result.warnings.append(f"cpu_sampling synthesis failed: {exc}")

    try:
        trace_mgmt._populate_metadata(trace)
    except Exception as exc:
        result.warnings.append(f"metadata population failed: {exc}")

    # Persist any aggregator outputs back to disk as parquets so the cache
    # rehydration path picks them up. We skip dumper stems and the
    # auxiliary keys (canonical event-class names with slashes) — those
    # are already on disk from the sidecar.
    written = _persist_aggregator_outputs(staging_dir, trace, result.warnings)
    result.datasets_written = written

    # Rewrite the manifest in place. We start from the sidecar's manifest
    # so the existing dumper datasets are preserved, and add the
    # aggregator outputs as additional CacheDataset entries.
    try:
        new_manifest = _rewrite_manifest(
            staging_dir=staging_dir,
            etl_path=etl_path,
            sidecar_manifest=sidecar_manifest,
            trace=trace,
            aggregator_stems=written,
            producer=producer,
        )
        result.manifest_path = staging_dir / native_cache.MANIFEST_FILENAME
    except Exception as exc:
        result.ok = False
        result.message = f"manifest rewrite failed: {exc}"
        LOGGER.error("aggregation_worker: manifest rewrite failed: %s", exc)
        return result

    if trace.symbolizer is not None:
        try:
            trace.symbolizer.close()
        except Exception:
            pass

    result.message = (
        f"aggregation completed: {len(written)} aggregator parquets written, "
        f"{len(new_manifest.datasets)} datasets in manifest"
    )
    return result


def _read_phase_b_parquet(
    staging_dir: Path, stem: str, warnings: list[str]
) -> pd.DataFrame | None:
    """Load a Phase B per-opcode parquet, or return None if absent.

    Missing files are not warnings — the sidecar legitimately skips
    classes with zero events (matches the documented Phase B behaviour).
    Read errors ARE recorded so we can debug schema drift.
    """
    parquet = staging_dir / f"{stem}.parquet"
    if not parquet.exists():
        return None
    try:
        return pd.read_parquet(parquet)
    except Exception as exc:
        warnings.append(f"failed to read {stem}.parquet: {exc}")
        return None


def _load_phase_b_dpc_isr(
    staging_dir: Path,
    trace: TraceData,
    warnings: list[str],
) -> None:
    """Promote Phase B perfinfo_* parquets into raw_csv[<canonical>].

    The sidecar emits one parquet per (PerfInfo, opcode) pair. The
    in-tree DPC aggregator iterates the canonical class names
    ``PerfInfo/DPC``, ``PerfInfo/ThreadedDPC``, ``PerfInfo/TimerDPC``,
    ``PerfInfo/ISR`` looking for matching DataFrames in ``raw_csv``
    (``_gather_dpc_events`` fallback). We adapt each parquet and write
    it to the matching canonical key, replacing any combined-buffer
    DataFrame the auxiliary loader may have placed there earlier.

    Adapter synthesises an ``InitialTime`` column from
    ``ElapsedMicros`` so the aggregator's standard duration-from-QPC
    code path works unchanged.
    """
    # Use perf_freq from EventTrace/Header (Phase B authoritative) or
    # trace_metadata (set if a prior aggregation populated it), in that
    # order. Falls back to 10 MHz (QPC default) when neither is
    # available. The eventtrace_header loader runs before this one in
    # _build_trace_from_staging, so the header path is the common case
    # when the sidecar emitted EventTrace/Header.
    perf_freq = 10_000_000.0
    header_df = trace.raw_csv.get("EventTrace/Header")
    if header_df is not None and not header_df.empty and "PerfFreq" in header_df.columns:
        try:
            freq = float(header_df["PerfFreq"].iloc[0])
            if freq > 0:
                perf_freq = freq
        except (TypeError, ValueError):
            pass
    if perf_freq == 10_000_000.0:
        metadata_df = trace.raw_csv.get("trace_metadata")
        if metadata_df is not None and not metadata_df.empty and "PerfFreq" in metadata_df.columns:
            try:
                freq = float(metadata_df["PerfFreq"].iloc[0])
                if freq > 0:
                    perf_freq = freq
            except (TypeError, ValueError):
                pass

    for stem, canonical in dotnet_adapters.PHASE_B_DPC_STEMS.items():
        df = _read_phase_b_parquet(staging_dir, stem, warnings)
        if df is None or df.empty:
            continue
        df = dotnet_adapters.adapt_dotnet_dpc_dataframe(df, perf_freq_hz=perf_freq)
        if df is not None and not df.empty:
            trace.raw_csv[canonical] = df


def _load_phase_b_process(
    staging_dir: Path,
    trace: TraceData,
    warnings: list[str],
) -> None:
    """Promote Phase B process_* parquets into raw_csv[<canonical>].

    The native ``process_info`` aggregator's ``_gather_process_events``
    fallback iterates ``Process/Start``, ``Process/End``,
    ``Process/DCStart``, ``Process/DCEnd``, ``Process/Defunct`` looking
    for matching DataFrames in raw_csv. Phase B writes one parquet per
    opcode with PID / ParentPID columns; the adapter renames those to
    the aggregator-expected ProcessId / ParentId and adds a SessionId=0
    column (the sidecar doesn't decode SessionId — a documented Phase
    B limitation).
    """

    from etw_analyzer.native import aggregation_worker_adapters as adapters

    for stem, canonical in adapters.PHASE_B_PROCESS_STEMS.items():
        df = _read_phase_b_parquet(staging_dir, stem, warnings)
        if df is None or df.empty:
            continue
        df = adapters.adapt_dotnet_process_dataframe(df)
        if df is not None and not df.empty:
            trace.raw_csv[canonical] = df


def _load_phase_b_thread(
    staging_dir: Path,
    trace: TraceData,
    warnings: list[str],
) -> None:
    """Promote Phase B thread_* parquets into raw_csv[<canonical>].

    The ``cpu_sampling`` / ``stacks`` aggregator chain depends on a
    TID→PID map built by
    ``profile_detail._build_tid_to_pid_map_from_raw_csv``, which scans
    ``Thread/Start`` and ``Thread/DCStart`` rows for ``ProcessId`` and
    ``ThreadId`` columns. The sidecar emits ``PID``/``TID`` (matching
    its process schema), so without this loader the map comes out
    empty and every SampledProfile row collapses into
    ``Process Name='unknown', PID=0``.
    See ``manager-log/sampledprofile-attribution-finding.md``.
    """

    from etw_analyzer.native import aggregation_worker_adapters as adapters

    for stem, canonical in adapters.PHASE_B_THREAD_STEMS.items():
        df = _read_phase_b_parquet(staging_dir, stem, warnings)
        if df is None or df.empty:
            continue
        df = adapters.adapt_dotnet_thread_dataframe(df)
        if df is not None and not df.empty:
            trace.raw_csv[canonical] = df


def _load_phase_b_diskio(
    staging_dir: Path,
    trace: TraceData,
    warnings: list[str],
) -> None:
    """Promote Phase B diskio_* parquets into raw_csv[<canonical>].

    The Phase B sidecar gates DiskIo emission on the combined buffer
    being non-empty — traces with zero disk events (e.g. the real
    spike-fixture lab ETL) have NO diskio_*.parquet files at all.
    ``_read_phase_b_parquet`` returns None for absent files and this
    loop simply does nothing in that case. The downstream
    ``build_diskio_text`` aggregator returns None when no DiskIo
    canonical keys are populated, and the persist hook skips None
    silently — no diskio.txt is written, which is the documented
    "zero events" behaviour.
    """

    from etw_analyzer.native import aggregation_worker_adapters as adapters

    for stem, canonical in adapters.PHASE_B_DISKIO_STEMS.items():
        df = _read_phase_b_parquet(staging_dir, stem, warnings)
        if df is None or df.empty:
            continue
        df = adapters.adapt_dotnet_diskio_dataframe(df)
        if df is not None and not df.empty:
            trace.raw_csv[canonical] = df


def _load_phase_b_images(
    staging_dir: Path,
    trace: TraceData,
    warnings: list[str],
) -> None:
    """Promote Phase B image_* parquets into raw_csv and build a symbolizer.

    Reads image_load.parquet and image_dcstart.parquet, lands them in
    raw_csv under Image/Load and Image/DCStart, then calls
    ``build_symbolizer_from_dotnet_images`` so the stacks aggregators
    can resolve addresses. Missing parquets are silent no-ops; a
    failed symbolizer build (no native bindings, no rows) is also
    silent — the existing dotnet test path already gracefully falls
    through when no symbolizer is available.
    """

    from etw_analyzer.native import aggregation_worker_adapters as adapters

    for stem, canonical in adapters.PHASE_B_IMAGE_STEMS.items():
        df = _read_phase_b_parquet(staging_dir, stem, warnings)
        if df is None or df.empty:
            continue
        df = adapters.adapt_dotnet_image_dataframe(df)
        if df is not None and not df.empty:
            trace.raw_csv[canonical] = df

    try:
        adapters.build_symbolizer_from_dotnet_images(trace)
    except Exception as exc:
        warnings.append(f"dotnet symbolizer build failed: {exc}")


def _load_phase_b_eventtrace_header(
    staging_dir: Path,
    trace: TraceData,
    warnings: list[str],
) -> None:
    """Load the eventtrace_header parquet into raw_csv['EventTrace/Header'].

    Single-row parquet from the sidecar carrying the authoritative
    ETL kernel header (PerfFreq, NumberOfProcessors, StartTime100Ns,
    EndTime100Ns, ...). The metadata derivation in
    ``run_aggregation_worker`` reads this BEFORE the heuristic-based
    derive_metadata_from_sidecar and uses it to drive the trace_metadata
    DataFrame.
    """
    df = _read_phase_b_parquet(staging_dir, "eventtrace_header", warnings)
    if df is None or df.empty:
        return
    trace.raw_csv["EventTrace/Header"] = df


def _build_trace_from_staging(
    *,
    staging_dir: Path,
    etl_path: Path,
    trace_id: str,
    sidecar_manifest: native_cache.CacheManifest,
    warnings: list[str],
) -> TraceData:
    """Hydrate a ``TraceData`` from the sidecar's parquet outputs."""

    trace = TraceData(
        trace_id=trace_id,
        etl_path=etl_path,
        export_dir=staging_dir,
        symbol_path=None,
        mode="native",
        raw_csv={},
    )

    # Index sidecar datasets by stem (filename without extension).
    sidecar_datasets = {
        Path(dataset.path).stem: dataset
        for dataset in sidecar_manifest.datasets
        if dataset.kind in {"parquet"}
    }

    for stem, (attr, canonical) in _SIDECAR_STEM_TO_ATTR.items():
        parquet = staging_dir / f"{stem}.parquet"
        if not parquet.exists():
            continue
        try:
            df = pd.read_parquet(parquet)
        except Exception as exc:
            warnings.append(f"failed to read {stem}.parquet: {exc}")
            continue
        # sampled_profile carries Phase B camelCase ``ProcessId`` from
        # the sidecar, but the cpu_sampling / stacks aggregators read
        # ``PID``. Apply the adapter before binding to either slot so
        # ``trace.dumper_df`` and ``trace.raw_csv['SampledProfile']``
        # point at the same already-adapted DataFrame.
        if stem == "sampled_profile":
            df = dotnet_adapters.adapt_dotnet_sampled_profile_dataframe(df)
        setattr(trace, attr, df)
        # Also expose under the canonical event-class name so aggregators
        # that look in raw_csv find the rows.
        trace.raw_csv[canonical] = df

    for stem, canonical in _SIDECAR_AUX_STEMS.items():
        parquet = staging_dir / f"{stem}.parquet"
        if not parquet.exists():
            continue
        try:
            df = pd.read_parquet(parquet)
        except Exception as exc:
            warnings.append(f"failed to read {stem}.parquet: {exc}")
            continue
        trace.raw_csv[canonical] = df

    # Phase B per-opcode parquets. These take precedence over the
    # combined-buffer parquets above: when present they carry the same
    # rows with cleaner per-class boundaries, and the existing
    # aggregator fallback path iterates _DPC_CLASSES /
    # _PROCESS_CLASSES / _DISKIO_CLASSES looking for canonical keys, so
    # we just need to land them there. Adapters do the column-rename /
    # column-synthesis work first.
    #
    # Order matters: eventtrace_header populates trace_metadata's
    # PerfFreq, which _load_phase_b_dpc_isr reads when synthesising
    # InitialTime. Load the header first so the DPC loader sees the
    # authoritative perf frequency rather than the 10 MHz default.
    _load_phase_b_eventtrace_header(staging_dir, trace, warnings)
    _load_phase_b_dpc_isr(staging_dir, trace, warnings)
    _load_phase_b_process(staging_dir, trace, warnings)
    _load_phase_b_thread(staging_dir, trace, warnings)
    _load_phase_b_diskio(staging_dir, trace, warnings)
    _load_phase_b_images(staging_dir, trace, warnings)

    # sysconfig.txt — preserve as raw text so the text aggregator finds it.
    sysconfig_path = staging_dir / "sysconfig.txt"
    if sysconfig_path.exists():
        try:
            trace.raw_csv["sysconfig"] = pd.DataFrame(
                {"text": [sysconfig_path.read_text(encoding="utf-8", errors="replace")]}
            )
        except Exception as exc:
            warnings.append(f"failed to read sysconfig.txt: {exc}")

    # Normalize dotnet-sidecar column names so the native aggregators
    # (which were written against the in-process worker's ``TimeStamp``
    # column) see the layout they expect. No-op for non-dotnet inputs.
    try:
        dotnet_adapters.normalize_dotnet_trace(trace)
    except Exception as exc:
        warnings.append(f"dotnet column normalization failed: {exc}")

    return trace


# Datasets we never want to overwrite back to disk — they came in from the
# sidecar already, and re-writing them with possibly-trimmed in-memory
# versions would corrupt the cache.
_NEVER_PERSIST = frozenset(_SIDECAR_STEM_TO_ATTR.values())


def _persist_aggregator_outputs(
    staging_dir: Path,
    trace: TraceData,
    warnings: list[str],
) -> list[str]:
    """Write aggregator-produced parquets next to the sidecar's outputs."""

    skip_keys = {canonical for _, canonical in _SIDECAR_STEM_TO_ATTR.values()}
    skip_keys.update(_SIDECAR_AUX_STEMS.values())
    skip_keys.add("sysconfig")  # Already a text dataset.
    # Aggregator outputs that are written as `.txt` files by
    # `_run_native_aggregators._persist_text`. They're also stashed in
    # ``raw_csv`` as a single-row DataFrame around ``raw_text`` so the
    # tools surface can return them; persisting them again as parquet
    # would just duplicate the text on disk.
    skip_keys.update({
        "dpc_isr_raw", "cswitch_raw", "tracestats",
        "process_info", "diskio",
    })

    written: list[str] = []
    for name, df in list(trace.raw_csv.items()):
        if name in skip_keys:
            continue
        if not isinstance(df, pd.DataFrame) or df.empty:
            continue
        # Skip pseudo-private entries the aggregators stash for internal use.
        if name.startswith("_"):
            continue
        path = staging_dir / f"{name}.parquet"
        try:
            df.to_parquet(path, index=False)
            written.append(name)
        except Exception as exc:
            warnings.append(f"failed to persist {name}.parquet: {exc}")
    return written


def _rewrite_manifest(
    *,
    staging_dir: Path,
    etl_path: Path,
    sidecar_manifest: native_cache.CacheManifest,
    trace: TraceData,
    aggregator_stems: list[str],
    producer: str,
) -> native_cache.CacheManifest:
    """Build and write the post-aggregation manifest.

    Sidecar datasets are remapped to the kinds ``trace_mgmt`` expects on
    the native rehydrate path: dumper event-class parquets become
    ``kind="dumper-parquet"`` with ``materialize_on_load=False`` so the
    cache loader can stream them without buffering. Aux parquets and
    the sysconfig text are preserved as the sidecar wrote them.
    """

    # Stems trace_mgmt recognizes as dumper parquets — these must use
    # ``dumper-parquet`` kind + ``materialize_on_load=False`` for the
    # native-cache loader to find them.
    dumper_stems = {stem for stem, _ in _SIDECAR_STEM_TO_ATTR.items()}

    datasets: list[native_cache.CacheDataset] = []
    existing_names: set[str] = set()
    for dataset in sidecar_manifest.datasets:
        # Remap dumper datasets from the sidecar's flat ``parquet`` kind
        # to the ``dumper-parquet`` kind trace_mgmt rehydrates.
        if dataset.name in dumper_stems and dataset.kind == "parquet":
            dataset = native_cache.CacheDataset(
                name=dataset.name,
                kind="dumper-parquet",
                path=dataset.path,
                schema_version=dataset.schema_version,
                row_count=dataset.row_count,
                materialize_on_load=False,
            )
        datasets.append(dataset)
        existing_names.add(dataset.name)

    # The sidecar may not emit every dumper stem (e.g. an empty UDP recv
    # parquet is skipped). trace_mgmt needs every stem present for the
    # ``_required_dumper_stems_for_mode("native")`` check to pass, so
    # synthesise zero-row parquets for the missing ones.
    for stem in dumper_stems:
        if stem in existing_names:
            continue
        parquet = staging_dir / f"{stem}.parquet"
        if not parquet.exists():
            try:
                pd.DataFrame().to_parquet(parquet, index=False)
            except Exception:
                continue
        datasets.append(native_cache.CacheDataset(
            name=stem,
            kind="dumper-parquet",
            path=f"{stem}.parquet",
            schema_version=native_cache.DATASET_SCHEMA_VERSION,
            row_count=0,
            materialize_on_load=False,
        ))
        existing_names.add(stem)

    for stem in aggregator_stems:
        if stem in existing_names:
            continue
        parquet = staging_dir / f"{stem}.parquet"
        if not parquet.exists():
            continue
        df = trace.raw_csv.get(stem)
        row_count = int(len(df)) if isinstance(df, pd.DataFrame) else None
        datasets.append(native_cache.CacheDataset(
            name=stem,
            kind="parquet",
            path=f"{stem}.parquet",
            row_count=row_count,
            materialize_on_load=True,
        ))

    # Register text aggregator outputs (dpc_isr_raw, tracestats,
    # process_info, diskio, sysconfig). These were written to .txt by
    # `_run_native_aggregators._persist_text` and need explicit
    # ``kind="text"`` entries so the cache rehydrate path finds them
    # via _TEXT_DATASETS rather than the dynamic parquet glob.
    text_outputs = {
        "dpc_isr_raw":  "dpcisr.txt",
        "tracestats":   "tracestats.txt",
        "process_info": "process_info.txt",
        "diskio":       "diskio.txt",
        # sysconfig is already registered by the sidecar — skip it
        # to avoid a duplicate entry, but keep the others.
    }
    for name, filename in text_outputs.items():
        if name in existing_names:
            continue
        text_path = staging_dir / filename
        if not text_path.exists():
            continue
        datasets.append(native_cache.CacheDataset(
            name=name,
            kind="text",
            path=filename,
            row_count=1,
            materialize_on_load=True,
        ))
        existing_names.add(name)

    manifest = native_cache.CacheManifest(
        schema_version=native_cache.SCHEMA_VERSION,
        mode="native",
        strategy=sidecar_manifest.strategy,
        complete=True,
        finalized=True,
        etl=native_cache.EtlIdentity.from_path(etl_path),
        datasets=datasets,
        native_store=sidecar_manifest.native_store,
        producer=producer,
        finalizer="python-aggregation-worker",
    )
    native_cache.write_manifest(staging_dir, manifest)
    return manifest


def main(argv: list[str] | None = None) -> int:
    """CLI entry point — for ad-hoc debugging only.

    Production callers should import :func:`run_aggregation_worker` directly
    from :mod:`etw_analyzer.native.worker_supervisor`. The CLI is useful
    when iterating on aggregator changes against an existing staging dir:

    .. code-block:: bash

        python -m etw_analyzer.native.aggregation_worker \\
            --staging-dir <path> --etl <path> --trace-id <id>
    """

    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staging-dir", required=True, type=Path)
    parser.add_argument("--etl", required=True, type=Path)
    parser.add_argument("--trace-id", required=True)
    parser.add_argument("--producer", default="dotnet")
    args = parser.parse_args(argv)

    result = run_aggregation_worker(
        args.staging_dir,
        args.etl,
        args.trace_id,
        producer=args.producer,
    )
    print(json.dumps({
        "ok": result.ok,
        "message": result.message,
        "datasets_written": result.datasets_written,
        "warnings": result.warnings,
    }, indent=2))
    return 0 if result.ok else 1


__all__ = [
    "AggregationResult",
    "run_aggregation_worker",
]


if __name__ == "__main__":
    raise SystemExit(main())
