"""Phase 4 packet-capture tools.

Tools over the ``packet_capture_df`` populated by the background dumper
extraction (see :func:`etw_analyzer.tools.trace_mgmt._start_background_dumper`
and :func:`etw_analyzer.parsing.wpa_exporter._handle_ndis_packet_capture`).

Each row in ``packet_capture_df`` carries a hex string of the captured
frame bytes; layer-by-layer decode is done lazily here via
:func:`etw_analyzer.parsing.packet_decode.decode_packet_headers` so we
never pay the decode cost for traces that just want the trace_id stored.

All four tools follow the project conventions: ``@mcp.tool()``,
``trace_id`` first, markdown-string return. When the trace was collected
without ``Microsoft-Windows-NDIS-PacketCapture`` enabled (the common case
for ``xdptrace.wprp`` traces), the tools return a friendly explanation
pointing at ``udp-perf/scripts/networking.wprp``.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator
import heapq
import json
from pathlib import Path
import re
import struct
import subprocess
from typing import Any

import pandas as pd

from etw_analyzer.app import mcp
from etw_analyzer.formatting.markdown import format_table
from etw_analyzer.native.accessors import iter_event_batches
from etw_analyzer.parsing.packet_decode import decode_packet_headers
from etw_analyzer.trace_state import TraceData, require_trace


_NO_PACKET_CAPTURE_MSG = (
    "*No packet-capture data in this trace.*\n\n"
    "For WPR traces, re-collect with `udp-perf/scripts/networking.wprp` — "
    "the `Microsoft-Windows-NDIS-PacketCapture` provider must be enabled "
    "to record frame bytes. For pktmon traces, collect with "
    "`pktmon start --capture --pkt-size 0` so pktmon can emit packet "
    "headers for summary analysis."
)
_PKTMON_TEXT_FILENAME = "pktmon.etl2txt.txt"
_PKTMON_PCAPNG_FILENAME = "pktmon.etl2pcap.pcapng"
_PKTMON_BOUNDARY_PARQUET_FILENAME = "pktmon.boundary.parquet"
_PKTMON_LAYER_PARQUET_FILENAME = "pktmon.layer.parquet"
_PKTMON_COMPONENTS_FILENAME = "pktmon.components.txt"
_PKTMON_CONVERT_TIMEOUT_SECONDS = 120
_PKTMON_COMPONENT_TIMEOUT_SECONDS = 30
_PKTMON_LAYER_WINDOW_US = 50_000
_PKTMON_TX_PATH = ((12, 1), (4, 1), (4, 2), (6, 1), (6, 2), (2, 1), (9, 1), (1, 1))
_PKTMON_RX_PATH = ((1, 1), (9, 1), (2, 1), (6, 2), (6, 1), (4, 2), (4, 1), (12, 1))
_PKTMON_PATH_INDEX = {
    "Send": {stage: index for index, stage in enumerate(_PKTMON_TX_PATH)},
    "Recv": {stage: index for index, stage in enumerate(_PKTMON_RX_PATH)},
}
_PKTMON_HEADER_RE = re.compile(
    r"^(?P<ts>\d\d:\d\d:\d\d\.\d+) "
    r"(?P<drop>Drop: )?PktGroupId (?P<group>\d+), "
    r"PktNumber (?P<number>\d+), "
    r"Appearance (?P<appearance>\d+), "
    r"Direction\s+(?P<direction>Tx|Rx)\s*, "
    r"Type\s+(?P<type>\w+)\s*, "
    r"Component\s+(?P<component>\d+)"
    r"(?:,\s*Edge\s+(?P<edge>\d+))?.*?"
    r"OriginalSize\s+(?P<size>\d+),\s*LoggedSize\s+(?P<logged>\d+)",
)
_PKTMON_FLOW_RE = re.compile(
    r"(?P<family>IPv4|IPv6), length (?P<iplen>\d+): "
    r"(?P<src>.+)\.(?P<srcport>\d+) > "
    r"(?P<dst>.+)\.(?P<dstport>\d+): "
    r"(?P<proto>tcp|udp)\b",
    re.IGNORECASE,
)

_PACKET_BATCH_SIZE = 65_536
_PACKET_COLUMNS = [
    "TimeStamp",
    "Direction",
    "MiniportName",
    "PacketBytes",
    "Size",
    "Process Name",
    "PID",
    "ThreadID",
    "CPU",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ensure_dumper_ready(trace: TraceData) -> None:
    trace.wait_for_dumper()


def _decode_row(packet_hex: str) -> dict[str, Any]:
    """Decode the PacketBytes hex string for one row, swallowing errors.

    Returns ``{}`` for unparseable rows so the caller can filter them out
    cleanly. A malformed hex blob in a real-world trace shouldn't take
    down a whole report.
    """
    if not isinstance(packet_hex, str) or not packet_hex:
        return {}
    try:
        return decode_packet_headers(bytes.fromhex(packet_hex))
    except (ValueError, TypeError):
        return {}


def _packet_capture_ready(df: pd.DataFrame | None) -> bool:
    """True if ``df`` looks usable (non-empty, has PacketBytes column)."""
    if df is None or df.empty:
        return False
    return "PacketBytes" in df.columns


def _project_packet_columns(
    df: pd.DataFrame,
    columns: list[str] | None,
) -> pd.DataFrame:
    if columns is None:
        return df.reset_index(drop=True)
    keep = [column for column in columns if column in df.columns]
    if "TimeStamp" in df.columns and "TimeStamp" not in keep:
        keep.append("TimeStamp")
    return df[keep].reset_index(drop=True)


def _event_store_packet_capture_row_count(trace: TraceData) -> int:
    store = getattr(trace, "event_store", None)
    datasets = getattr(getattr(store, "manifest", None), "datasets", None)
    if not isinstance(datasets, dict):
        return 0
    dataset = datasets.get("packet_capture")
    if dataset is None:
        return 0
    return int(getattr(dataset, "row_count", 0) or 0)


def _packet_capture_batches(
    trace: TraceData,
    *,
    columns: list[str] | None = None,
    batch_size: int = _PACKET_BATCH_SIZE,
    sort_by_time: bool = False,
) -> Iterator[pd.DataFrame]:
    """Yield packet-capture rows without forcing event-store materialization."""

    materialized = trace.packet_capture_df
    if _packet_capture_ready(materialized):
        df = _project_packet_columns(materialized, columns)
        if sort_by_time and "TimeStamp" in df.columns and not df.empty:
            ts = pd.to_numeric(df["TimeStamp"], errors="coerce")
            df = df.assign(_sort_ts=ts).sort_values("_sort_ts").drop(columns=["_sort_ts"])
        safe_batch_size = max(1, int(batch_size or _PACKET_BATCH_SIZE))
        for start in range(0, len(df), safe_batch_size):
            yield df.iloc[start:start + safe_batch_size].reset_index(drop=True)
        return

    if _event_store_packet_capture_row_count(trace) > 0:
        yielded = False
        for batch in iter_event_batches(
            trace,
            "packet_capture",
            columns=columns,
            batch_size=batch_size,
        ):
            yielded = yielded or not batch.empty
            if sort_by_time and "TimeStamp" in batch.columns and not batch.empty:
                ts = pd.to_numeric(batch["TimeStamp"], errors="coerce")
                batch = batch.assign(_sort_ts=ts).sort_values("_sort_ts").drop(columns=["_sort_ts"])
            yield batch.reset_index(drop=True)
        if yielded:
            return

    pktmon_df, _error = _pktmon_packet_capture_df(trace, boundary_only=True)
    if pktmon_df is None or pktmon_df.empty:
        return
    df = _project_packet_columns(pktmon_df, columns)
    if sort_by_time and "TimeStamp" in df.columns and not df.empty:
        ts = pd.to_numeric(df["TimeStamp"], errors="coerce")
        df = df.assign(_sort_ts=ts).sort_values("_sort_ts").drop(columns=["_sort_ts"])
    safe_batch_size = max(1, int(batch_size or _PACKET_BATCH_SIZE))
    for start in range(0, len(df), safe_batch_size):
        yield df.iloc[start:start + safe_batch_size].reset_index(drop=True)


def _ndis_packet_capture_available(trace: TraceData) -> bool:
    materialized = trace.packet_capture_df
    if isinstance(materialized, pd.DataFrame):
        return _packet_capture_ready(materialized)
    return _event_store_packet_capture_row_count(trace) > 0


def _packet_capture_available(trace: TraceData) -> bool:
    if _ndis_packet_capture_available(trace):
        return True
    pktmon_df, _error = _pktmon_packet_capture_df(trace, boundary_only=True)
    return pktmon_df is not None and not pktmon_df.empty


def _pktmon_text_path(trace: TraceData) -> Path:
    return trace.export_dir / _PKTMON_TEXT_FILENAME


def _cache_file_current(cache_path: Path, source_path: Path) -> bool:
    if not cache_path.exists() or not source_path.exists():
        return False
    meta_path = _cache_metadata_path(cache_path)
    if not meta_path.exists():
        return False
    try:
        metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return metadata == _source_identity(source_path)


def _source_identity(source_path: Path) -> dict[str, int]:
    stat = source_path.stat()
    return {"size": int(stat.st_size), "mtime_ns": int(stat.st_mtime_ns)}


def _cache_metadata_path(cache_path: Path) -> Path:
    return cache_path.with_name(cache_path.name + ".meta.json")


def _write_cache_metadata(cache_path: Path, source_path: Path) -> None:
    _cache_metadata_path(cache_path).write_text(
        json.dumps(_source_identity(source_path), sort_keys=True),
        encoding="utf-8",
    )


def _remove_stale_cache(cache_path: Path) -> tuple[bool, str | None]:
    try:
        if cache_path.exists():
            cache_path.unlink()
        meta_path = _cache_metadata_path(cache_path)
        if meta_path.exists():
            meta_path.unlink()
    except OSError as exc:
        return False, f"could not remove stale pktmon cache file {cache_path}: {exc}"
    return True, None


def _read_pktmon_text(path: Path) -> str:
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        encodings = ("utf-16", "utf-8-sig", "utf-8")
    elif raw.startswith(b"\xef\xbb\xbf"):
        encodings = ("utf-8-sig", "utf-8", "utf-16")
    else:
        encodings = ("utf-8", "utf-8-sig", "utf-16")
    for encoding in encodings:
        try:
            return raw.decode(encoding)
        except UnicodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _ensure_pktmon_text(trace: TraceData) -> tuple[Path | None, str | None]:
    text_path = _pktmon_text_path(trace)
    if _cache_file_current(text_path, trace.etl_path):
        return text_path, None

    try:
        trace.export_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return None, f"could not create pktmon export directory: {exc}"
    removed, remove_error = _remove_stale_cache(text_path)
    if not removed:
        return None, remove_error

    cmd = [
        "pktmon", "etl2txt", str(trace.etl_path),
        "--out", str(text_path),
        "--brief", "--timestamp",
    ]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_PKTMON_CONVERT_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return None, "`pktmon.exe` was not found on PATH"
    except subprocess.TimeoutExpired:
        return None, "pktmon ETL-to-text conversion timed out"
    except OSError as exc:
        return None, f"pktmon ETL-to-text conversion failed to start: {exc}"

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        if detail:
            detail = detail.splitlines()[-1]
            return None, f"pktmon ETL-to-text conversion failed: {detail}"
        return None, "pktmon ETL-to-text conversion failed"
    if not text_path.exists():
        return None, "pktmon ETL-to-text conversion did not produce an output file"
    _write_cache_metadata(text_path, trace.etl_path)
    return text_path, None


def _pktmon_pcapng_path(trace: TraceData) -> Path:
    return trace.export_dir / _PKTMON_PCAPNG_FILENAME


def _ensure_pktmon_pcapng(trace: TraceData) -> tuple[Path | None, str | None]:
    pcapng_path = _pktmon_pcapng_path(trace)
    if _cache_file_current(pcapng_path, trace.etl_path):
        return pcapng_path, None

    try:
        trace.export_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return None, f"could not create pktmon export directory: {exc}"
    removed, remove_error = _remove_stale_cache(pcapng_path)
    if not removed:
        return None, remove_error

    cmd = ["pktmon", "etl2pcap", str(trace.etl_path), "--out", str(pcapng_path)]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_PKTMON_CONVERT_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return None, "`pktmon.exe` was not found on PATH"
    except subprocess.TimeoutExpired:
        return None, "pktmon ETL-to-PCAPNG conversion timed out"
    except OSError as exc:
        return None, f"pktmon ETL-to-PCAPNG conversion failed to start: {exc}"

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        if detail:
            detail = detail.splitlines()[-1]
            return None, f"pktmon ETL-to-PCAPNG conversion failed: {detail}"
        return None, "pktmon ETL-to-PCAPNG conversion failed"
    if not pcapng_path.exists():
        return None, "pktmon ETL-to-PCAPNG conversion did not produce an output file"
    _write_cache_metadata(pcapng_path, trace.etl_path)
    return pcapng_path, None


def _pktmon_component_sidecar_paths(trace: TraceData) -> list[Path]:
    return [
        trace.export_dir / _PKTMON_COMPONENTS_FILENAME,
        trace.etl_path.with_name(f"{trace.etl_path.stem}.components.txt"),
    ]


def _parse_pktmon_component_list(text: str) -> dict[int, str]:
    components: dict[int, str] = {}
    current_table = ""
    pending_name = ""
    pending_id: int | None = None

    def _label(name: str, driver: str = "") -> str:
        name = name.strip()
        driver = driver.strip()
        if name and driver:
            return f"{name} ({driver})"
        return name or driver

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            current_table = ""
            continue

        if stripped.startswith("NIC: "):
            pending_name = stripped.removeprefix("NIC: ").strip()
            pending_id = None
            current_table = ""
            continue
        if stripped.startswith("vSwitch: "):
            pending_name = stripped.removeprefix("vSwitch: ").strip()
            pending_id = None
            current_table = ""
            continue
        if stripped in {"HTTP Message", "IPSEC", "Unregistered Miniport"}:
            pending_name = stripped
            pending_id = None
            current_table = ""
            continue
        if stripped.startswith("Id: ") and pending_name:
            try:
                pending_id = int(stripped.split(":", 1)[1].strip())
                components[pending_id] = pending_name
            except ValueError:
                pending_id = None
            continue
        if stripped.startswith("Driver: ") and pending_id is not None:
            driver = stripped.split(":", 1)[1].strip()
            components[pending_id] = _label(pending_name, driver)
            continue
        if stripped in {"Filter Drivers:", "Protocols:", "Application Protocols:"}:
            current_table = stripped.rstrip(":")
            continue
        if stripped.startswith("Id ") or stripped.startswith("-- "):
            continue

        if current_table:
            parts = [part.strip() for part in re.split(r"\s{2,}", stripped) if part.strip()]
            row_match = (
                re.match(r"^(\d+)\s+(\S+\.sys)\s+(.+)$", stripped, re.IGNORECASE)
                or re.match(r"^(\d+)\s+(\S+)\s{2,}(.+)$", stripped)
            )
            if len(parts) < 2 and row_match:
                parts = [row_match.group(1), row_match.group(2), row_match.group(3).strip()]
            if len(parts) < 2:
                continue
            try:
                component_id = int(parts[0])
            except ValueError:
                if row_match:
                    parts = [row_match.group(1), row_match.group(2), row_match.group(3).strip()]
                    component_id = int(parts[0])
                else:
                    continue
            if current_table == "Filter Drivers" and len(parts) >= 3:
                components[component_id] = _label(parts[2], parts[1])
            elif current_table == "Protocols":
                if len(parts) >= 4:
                    components[component_id] = _label(parts[2], parts[1])
                elif len(parts) >= 2:
                    components[component_id] = _label(parts[1])
            elif current_table == "Application Protocols" and len(parts) >= 3:
                components[component_id] = _label(parts[2], parts[1])

    return components


def _pktmon_component_map(trace: TraceData) -> tuple[dict[int, str], str | None]:
    for path in _pktmon_component_sidecar_paths(trace):
        if path.exists():
            return _parse_pktmon_component_list(_read_pktmon_text(path)), str(path)

    cache_path = trace.export_dir / _PKTMON_COMPONENTS_FILENAME
    try:
        trace.export_dir.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            ["pktmon", "comp", "list", "--all"],
            capture_output=True,
            text=True,
            timeout=_PKTMON_COMPONENT_TIMEOUT_SECONDS,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return {}, None

    if completed.returncode != 0 or not completed.stdout.strip():
        return {}, None
    try:
        cache_path.write_text(completed.stdout, encoding="utf-8")
    except OSError:
        pass
    return _parse_pktmon_component_list(completed.stdout), "`pktmon comp list --all` on analysis host"


def _pcapng_padded_length(length: int) -> int:
    return (length + 3) & ~3


def _parse_pcapng_tsresol(value: bytes) -> float:
    if not value:
        return 1e-6
    raw = value[0]
    base = 2 if raw & 0x80 else 10
    exponent = raw & 0x7F
    return base ** -exponent


def _iter_pcapng_options(data: bytes, endian: str, offset: int, end: int) -> Iterator[tuple[int, bytes]]:
    cursor = offset
    while cursor + 4 <= end:
        code, length = struct.unpack_from(endian + "HH", data, cursor)
        cursor += 4
        if code == 0:
            break
        value = data[cursor:cursor + length]
        cursor += _pcapng_padded_length(length)
        yield code, value


def _read_pcapng_packets(path: Path) -> tuple[list[dict[str, Any]] | None, str | None]:
    data = path.read_bytes()
    packets: list[dict[str, Any]] = []
    interfaces: list[dict[str, Any]] = []
    endian = "<"
    offset = 0

    while offset + 12 <= len(data):
        block_type, block_length = struct.unpack_from(endian + "II", data, offset)
        if block_length < 12 or offset + block_length > len(data):
            return None, f"invalid PCAPNG block at offset {offset}"

        body_offset = offset + 8
        body_end = offset + block_length - 4

        if block_type == 0x0A0D0D0A:
            magic = data[body_offset:body_offset + 4]
            if magic == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif magic == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                return None, "invalid PCAPNG byte-order magic"
            interfaces = []
        elif block_type == 0x00000001:
            if body_offset + 8 > body_end:
                return None, "truncated PCAPNG interface block"
            link_type, _reserved, snaplen = struct.unpack_from(endian + "HHI", data, body_offset)
            tsresol = 1e-6
            for code, value in _iter_pcapng_options(data, endian, body_offset + 8, body_end):
                if code == 9:
                    tsresol = _parse_pcapng_tsresol(value)
            interfaces.append({"link_type": link_type, "snaplen": snaplen, "tsresol": tsresol})
        elif block_type == 0x00000006:
            if body_offset + 20 > body_end:
                return None, "truncated PCAPNG enhanced packet block"
            interface_id, ts_high, ts_low, captured_len, original_len = struct.unpack_from(
                endian + "IIIII",
                data,
                body_offset,
            )
            packet_offset = body_offset + 20
            packet_end = packet_offset + captured_len
            if packet_end > body_end:
                return None, "truncated PCAPNG packet data"
            if interface_id >= len(interfaces):
                return None, f"PCAPNG packet references unknown interface {interface_id}"
            raw_timestamp = (ts_high << 32) | ts_low
            tsresol = float(interfaces[interface_id].get("tsresol", 1e-6))
            packets.append({
                "timestamp_us": int(round(raw_timestamp * tsresol * 1_000_000)),
                "captured_len": int(captured_len),
                "original_len": int(original_len),
                "packet_bytes": data[packet_offset:packet_end],
            })

        trailing_length = struct.unpack_from(endian + "I", data, offset + block_length - 4)[0]
        if trailing_length != block_length:
            return None, f"invalid PCAPNG trailing block length at offset {offset}"
        offset += block_length

    if offset != len(data):
        return None, "trailing bytes after final PCAPNG block"
    return packets, None


def _is_pktmon_boundary_packet(
    direction: str,
    packet_type: str,
    component: int,
    edge: int,
) -> bool:
    if packet_type != "Ethernet":
        return False
    return (
        (direction == "Tx" and component == 12 and edge == 1)
        or (direction == "Rx" and component == 1 and edge == 1)
    )


def _pktmon_text_rows(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    pending: dict[str, str] | None = None

    for line in text.splitlines():
        header = _PKTMON_HEADER_RE.match(line)
        if header:
            direction = header.group("direction")
            packet_type = header.group("type")
            component = int(header.group("component"))
            edge = int(header.group("edge") or -1)
            is_drop = bool(header.group("drop"))
            pending = (
                header.groupdict()
                if not is_drop and _is_pktmon_boundary_packet(direction, packet_type, component, edge)
                else None
            )
            continue

        if pending is None:
            continue
        if not line.startswith("\t"):
            pending = None
            continue

        flow = _PKTMON_FLOW_RE.search(line)
        if flow is None:
            pending = None
            continue

        proto = flow.group("proto").lower()
        rows.append({
            "Direction": "Send" if pending["direction"] == "Tx" else "Recv",
            "5-Tuple": (
                f"{flow.group('src')}:{flow.group('srcport')} -> "
                f"{flow.group('dst')}:{flow.group('dstport')}/{proto}"
            ),
            "Size": int(pending["size"]),
        })
        pending = None

    return rows


def _pktmon_text_appearances(text: str) -> list[dict[str, Any]]:
    appearances: list[dict[str, Any]] = []
    pending: dict[str, str] | None = None

    for line in text.splitlines():
        header = _PKTMON_HEADER_RE.match(line)
        if header:
            is_drop = bool(header.group("drop"))
            pending = (
                header.groupdict()
                if not is_drop and header.group("type") == "Ethernet"
                else None
            )
            continue

        if pending is None:
            continue
        if not line.startswith("\t"):
            pending = None
            continue

        direction = "Send" if pending["direction"] == "Tx" else "Recv"
        component = int(pending["component"])
        edge = int(pending["edge"] or -1)
        appearances.append({
            "PktmonTime": pending["ts"],
            "Direction": direction,
            "PktmonDirection": pending["direction"],
            "Component": component,
            "Edge": edge,
            "PktGroupId": int(pending["group"]),
            "PktNumber": int(pending["number"]),
            "Appearance": int(pending["appearance"]),
            "OriginalSize": int(pending["size"]),
            "LoggedSize": int(pending["logged"]),
            "PktmonDetail": line.strip(),
            "Boundary": _is_pktmon_boundary_packet(pending["direction"], pending["type"], component, edge),
            "PathIndex": _PKTMON_PATH_INDEX.get(direction, {}).get((component, edge), -1),
        })
        pending = None

    return appearances


def _pktmon_cache_path(trace: TraceData, *, boundary_only: bool) -> Path:
    name = _PKTMON_BOUNDARY_PARQUET_FILENAME if boundary_only else _PKTMON_LAYER_PARQUET_FILENAME
    return trace.export_dir / name


def _pktmon_packet_capture_df(
    trace: TraceData,
    *,
    boundary_only: bool,
) -> tuple[pd.DataFrame | None, str | None]:
    if not trace.etl_path.exists():
        return None, f"trace ETL file does not exist: {trace.etl_path}"

    cache_path = _pktmon_cache_path(trace, boundary_only=boundary_only)
    if _cache_file_current(cache_path, trace.etl_path):
        return pd.read_parquet(cache_path), None

    text_path, text_error = _ensure_pktmon_text(trace)
    if text_error is not None:
        return None, text_error
    pcapng_path, pcapng_error = _ensure_pktmon_pcapng(trace)
    if pcapng_error is not None:
        return None, pcapng_error
    if text_path is None or pcapng_path is None:
        return None, "pktmon conversion did not return text and PCAPNG output paths"

    appearances = _pktmon_text_appearances(_read_pktmon_text(text_path))
    packets, packet_error = _read_pcapng_packets(pcapng_path)
    if packet_error is not None:
        return None, packet_error
    if packets is None:
        return None, "pktmon PCAPNG parsing did not return packets"
    if len(appearances) != len(packets):
        return (
            None,
            "pktmon text/PCAPNG packet count mismatch: "
            f"{len(appearances):,} text appearances vs {len(packets):,} PCAPNG packets",
        )

    rows: list[dict[str, Any]] = []
    first_timestamp = packets[0]["timestamp_us"] if packets else 0
    size_mismatches: list[str] = []
    for index, (appearance, packet) in enumerate(zip(appearances, packets, strict=True)):
        captured_len = int(packet["captured_len"])
        if captured_len != int(appearance["LoggedSize"]) and len(size_mismatches) < 5:
            size_mismatches.append(
                f"#{index}: text logged={appearance['LoggedSize']} pcap captured={captured_len}"
            )
        if boundary_only and not bool(appearance["Boundary"]):
            continue
        rows.append({
            "TimeStamp": int(packet["timestamp_us"]) - int(first_timestamp),
            "Direction": appearance["Direction"],
            "MiniportName": "pktmon",
            "PacketBytes": packet["packet_bytes"].hex(),
            "Size": int(appearance["OriginalSize"]),
            "CapturedSize": captured_len,
            "Process Name": "",
            "PID": 0,
            "ThreadID": 0,
            "CPU": 0,
            "Source": "pktmon",
            "PktmonTime": appearance["PktmonTime"],
            "PktGroupId": appearance["PktGroupId"],
            "PktNumber": appearance["PktNumber"],
            "Appearance": appearance["Appearance"],
            "Component": appearance["Component"],
            "Edge": appearance["Edge"],
            "Boundary": bool(appearance["Boundary"]),
            "PathIndex": appearance["PathIndex"],
            "PktmonDetail": appearance["PktmonDetail"],
        })

    if size_mismatches:
        return None, "pktmon text/PCAPNG size mismatch: " + "; ".join(size_mismatches)

    df = pd.DataFrame(rows)
    trace.export_dir.mkdir(parents=True, exist_ok=True)
    df.to_parquet(cache_path, index=False)
    _write_cache_metadata(cache_path, trace.etl_path)
    return df, None


def _pktmon_capture_summary_df(trace: TraceData) -> tuple[pd.DataFrame | None, str | None]:
    text_path, error = _ensure_pktmon_text(trace)
    if error is not None:
        return None, error
    if text_path is None:
        return None, "pktmon ETL-to-text conversion did not return an output path"

    text = _read_pktmon_text(text_path)
    rows = _pktmon_text_rows(text)
    if not rows:
        return None, None

    aggregates: dict[str, dict[str, Any]] = {}
    for row in rows:
        five_tuple = row["5-Tuple"]
        entry = aggregates.setdefault(
            five_tuple,
            {
                "5-Tuple": five_tuple,
                "Recv Pkts": 0,
                "Send Pkts": 0,
                "Total Pkts": 0,
                "Total Bytes": 0,
            },
        )
        direction = row["Direction"]
        if direction == "Recv":
            entry["Recv Pkts"] += 1
        elif direction == "Send":
            entry["Send Pkts"] += 1
        entry["Total Pkts"] += 1
        entry["Total Bytes"] += int(row["Size"])

    return (
        pd.DataFrame(list(aggregates.values()))
        .sort_values("Total Bytes", ascending=False)
        .reset_index(drop=True),
        None,
    )


def _apply_process_filter(df: pd.DataFrame, process_filter: str | None) -> pd.DataFrame:
    """Case-insensitive substring filter on Process Name."""
    if not process_filter or df.empty or "Process Name" not in df.columns:
        return df
    mask = df["Process Name"].astype(str).str.contains(
        process_filter, case=False, na=False
    )
    return df[mask]


def _decoded_with_five_tuple(df: pd.DataFrame) -> pd.DataFrame:
    """Return a copy of ``df`` augmented with decoded header columns.

    Adds: ``_src``, ``_dst``, ``_src_port``, ``_dst_port``, ``_proto`` (as a
    short string: tcp / udp / icmp / icmpv6 / proto-N / other) and
    ``_five_tuple`` (canonical "src:port -> dst:port/proto"). Rows whose
    packet bytes don't decode to at least an IP layer get blank tuple
    fields and the literal string ``"undecoded"`` for ``_five_tuple`` so
    summaries still surface them.
    """
    out = df.copy()
    srcs: list[str] = []
    dsts: list[str] = []
    sports: list[int] = []
    dports: list[int] = []
    protos: list[str] = []
    tuples: list[str] = []

    for _, row in out.iterrows():
        decoded = _decode_row(row.get("PacketBytes", ""))
        src, dst, sport, dport, proto, five = _decoded_tuple_fields(decoded)

        srcs.append(src)
        dsts.append(dst)
        sports.append(sport)
        dports.append(dport)
        protos.append(proto)
        tuples.append(five)

    out["_src"] = srcs
    out["_dst"] = dsts
    out["_src_port"] = sports
    out["_dst_port"] = dports
    out["_proto"] = protos
    out["_five_tuple"] = tuples
    return out


def _decoded_tuple_fields(decoded: dict[str, Any]) -> tuple[str, str, int, int, str, str]:
    src = decoded.get("ip.src", "")
    dst = decoded.get("ip.dst", "")
    proto_num = decoded.get("ip.proto")
    if proto_num == 6:
        proto = "tcp"
        sport = int(decoded.get("tcp.src_port", 0))
        dport = int(decoded.get("tcp.dst_port", 0))
    elif proto_num == 17:
        proto = "udp"
        sport = int(decoded.get("udp.src_port", 0))
        dport = int(decoded.get("udp.dst_port", 0))
    elif proto_num == 1:
        proto = "icmp"
        sport = 0
        dport = 0
    elif proto_num == 58:
        proto = "icmpv6"
        sport = 0
        dport = 0
    elif proto_num is not None:
        proto = f"proto-{int(proto_num)}"
        sport = 0
        dport = 0
    else:
        proto = "other"
        sport = 0
        dport = 0

    if src and dst:
        five = f"{src}:{sport} -> {dst}:{dport}/{proto}"
    else:
        five = "undecoded"
    return str(src), str(dst), int(sport), int(dport), proto, five


def _parse_five_tuple_query(query: str) -> dict[str, Any] | None:
    """Parse a flexible 5-tuple query string.

    Accepted forms:
      * ``src:sport -> dst:dport/proto`` (canonical, from get_packet_capture_summary)
      * ``src:sport -> dst:dport`` (proto inferred from data)
      * ``src:sport-dst:dport``
      * ``src:sport dst:dport`` (whitespace separated)

    Returns a dict with keys ``src``, ``dst``, ``src_port``, ``dst_port``,
    ``proto`` (any of which may be ``None`` / 0 when not provided). Returns
    ``None`` if the query can't be split into two endpoints.
    """
    if not query:
        return None
    q = query.strip()
    proto = None
    if "/" in q:
        q, proto_tail = q.rsplit("/", 1)
        proto = proto_tail.strip().lower() or None
        q = q.strip()

    # Normalize separators between the two endpoints.
    for sep in ("->", "<->", "<-"):
        if sep in q:
            left, right = q.split(sep, 1)
            break
    else:
        if " " in q.strip():
            left, right = q.split(None, 1)
        else:
            # "src:sport-dst:dport" — assume the last single '-' is the
            # separator. Be careful: IPv6 addresses contain ':' but no '-'.
            # We only split on '-' that's preceded by a digit and followed
            # by a digit/letter (heuristic to avoid splitting MAC addresses
            # that might have been passed in).
            if "-" in q:
                parts = q.rsplit("-", 1)
                if len(parts) == 2:
                    left, right = parts
                else:
                    return None
            else:
                return None

    def _split_endpoint(endpoint: str) -> tuple[str, int]:
        endpoint = endpoint.strip()
        # IPv6 in brackets: [::1]:5000
        if endpoint.startswith("["):
            close = endpoint.find("]")
            if close < 0:
                return endpoint.strip("[]"), 0
            ip = endpoint[1:close]
            tail = endpoint[close + 1:].lstrip(":")
            try:
                return ip, int(tail) if tail else 0
            except ValueError:
                return ip, 0
        # IPv4 or hostname: last ':' is port (IPv6 without brackets is ambiguous)
        if ":" in endpoint:
            # If the address contains more than one colon, treat as IPv6 without port.
            if endpoint.count(":") > 1:
                return endpoint, 0
            ip, _, port = endpoint.rpartition(":")
            try:
                return ip, int(port)
            except ValueError:
                return endpoint, 0
        return endpoint, 0

    src, src_port = _split_endpoint(left)
    dst, dst_port = _split_endpoint(right)

    return {
        "src": src,
        "dst": dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": proto,
    }


def _five_tuples_match(row, query: dict[str, Any]) -> bool:
    """Return True if a row from ``_decoded_with_five_tuple`` matches.

    Direction-agnostic: a query of ``A -> B`` matches packets with either
    A→B or B→A so a single timeline shows both halves of a conversation.
    """
    src, dst = row["_src"], row["_dst"]
    sport, dport = row["_src_port"], row["_dst_port"]
    proto = row["_proto"]

    if query.get("proto") and proto != query["proto"]:
        return False

    q_src = query["src"]
    q_dst = query["dst"]
    q_sport = query["src_port"]
    q_dport = query["dst_port"]

    def _ip_matches(a: str, b: str) -> bool:
        return (not a) or (not b) or a == b

    def _port_matches(a: int, b: int) -> bool:
        return (not a) or (not b) or int(a) == int(b)

    forward = (
        _ip_matches(q_src, src) and _ip_matches(q_dst, dst)
        and _port_matches(q_sport, sport) and _port_matches(q_dport, dport)
    )
    backward = (
        _ip_matches(q_src, dst) and _ip_matches(q_dst, src)
        and _port_matches(q_sport, dport) and _port_matches(q_dport, sport)
    )
    return forward or backward


def _ip_payload_length(decoded: dict[str, Any]) -> int:
    version = int(decoded.get("ip.version", 0) or 0)
    if version == 4:
        return max(0, int(decoded.get("ip.total_length", 0) or 0) - int(decoded.get("ip.header_len", 0) or 0))
    if version == 6:
        return max(0, int(decoded.get("ip.payload_length", 0) or 0))
    return 0


def _tcp_payload_length(decoded: dict[str, Any]) -> int:
    return max(0, _ip_payload_length(decoded) - int(decoded.get("tcp.header_len", 0) or 0))


def _packet_fingerprint(decoded: dict[str, Any], size: int) -> tuple[tuple[Any, ...] | None, str]:
    src = decoded.get("ip.src")
    dst = decoded.get("ip.dst")
    proto_num = decoded.get("ip.proto")
    if not src or not dst or proto_num is None:
        return None, "other"

    ip_id = decoded.get("ip.id", -1)
    if proto_num == 6 and "tcp.src_port" in decoded and "tcp.dst_port" in decoded:
        return (
            (
                "tcp", src, dst,
                int(decoded.get("tcp.src_port", 0) or 0),
                int(decoded.get("tcp.dst_port", 0) or 0),
                int(decoded.get("tcp.seq", 0) or 0),
                int(decoded.get("tcp.ack", 0) or 0),
                int(decoded.get("tcp.flags_raw", 0) or 0),
                _tcp_payload_length(decoded),
                int(ip_id or -1),
                int(size),
            ),
            "tcp",
        )
    if proto_num == 17 and "udp.src_port" in decoded and "udp.dst_port" in decoded:
        return (
            (
                "udp", src, dst,
                int(decoded.get("udp.src_port", 0) or 0),
                int(decoded.get("udp.dst_port", 0) or 0),
                int(decoded.get("udp.length", 0) or 0),
                int(ip_id or -1),
                int(size),
            ),
            "udp",
        )

    return (
        (
            "ip", src, dst, int(proto_num),
            int(ip_id or -1),
            _ip_payload_length(decoded),
            int(size),
        ),
        f"proto-{int(proto_num)}",
    )


def _journey_confidence(proto: str, complete: bool) -> str:
    if proto == "tcp":
        return "high" if complete else "medium"
    if proto == "udp":
        return "medium" if complete else "low"
    return "low"


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((pct / 100.0) * (len(ordered) - 1)))))
    return float(ordered[index])


def _stage_name(component: int, edge: int) -> str:
    return f"{component}/{edge}"


def _component_label(component: int, component_map: dict[int, str]) -> str:
    return component_map.get(int(component), f"Component {int(component)}")


def _friendly_stage_name(component: int, edge: int, component_map: dict[int, str]) -> str:
    return f"{_component_label(component, component_map)} edge {int(edge)}"


def _friendly_hop(
    before: dict[str, Any],
    after: dict[str, Any],
    component_map: dict[int, str],
) -> str:
    before_component = int(before["Component"])
    after_component = int(after["Component"])
    before_edge = int(before["Edge"])
    after_edge = int(after["Edge"])
    if before_component == after_component:
        return (
            f"{_component_label(before_component, component_map)}: "
            f"edge {before_edge} -> edge {after_edge}"
        )
    return (
        f"{_friendly_stage_name(before_component, before_edge, component_map)} -> "
        f"{_friendly_stage_name(after_component, after_edge, component_map)}"
    )


def _safe_int(value: Any, default: int = -1) -> int:
    try:
        if pd.isna(value):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _group_pktmon_journeys(
    df: pd.DataFrame,
    *,
    five_tuple: str | None,
    direction_filter: str | None,
) -> list[dict[str, Any]]:
    query = _parse_five_tuple_query(five_tuple) if five_tuple else None
    direction_filter_normalized = None
    if direction_filter:
        value = direction_filter.strip().lower()
        if value in ("tx", "send"):
            direction_filter_normalized = "Send"
        elif value in ("rx", "recv", "receive"):
            direction_filter_normalized = "Recv"

    journeys: list[dict[str, Any]] = []
    active: dict[tuple[str, tuple[Any, ...]], list[dict[str, Any]]] = {}
    next_id = 1

    if df.empty:
        return journeys
    ordered = df.copy()
    ts = pd.to_numeric(ordered["TimeStamp"], errors="coerce")
    ordered = ordered.assign(_sort_ts=ts).dropna(subset=["_sort_ts"]).sort_values("_sort_ts")

    for _, row in ordered.iterrows():
        direction = str(row.get("Direction", ""))
        if direction_filter_normalized and direction != direction_filter_normalized:
            continue
        path_index = _safe_int(row.get("PathIndex", -1))
        if path_index < 0:
            continue
        decoded = _decode_row(row.get("PacketBytes", ""))
        src, dst, sport, dport, proto, five = _decoded_tuple_fields(decoded)
        match_row = {
            "_src": src,
            "_dst": dst,
            "_src_port": sport,
            "_dst_port": dport,
            "_proto": proto,
        }
        if query is not None and not _five_tuples_match(match_row, query):
            continue
        fingerprint, fingerprint_proto = _packet_fingerprint(decoded, int(row.get("Size", 0) or 0))
        if fingerprint is None:
            continue

        row_ts = float(row.get("TimeStamp", 0) or 0)
        key = (direction, fingerprint)
        candidates = [
            journey for journey in active.get(key, [])
            if path_index > int(journey["stages"][-1]["PathIndex"])
            and row_ts - float(journey["stages"][-1]["TimeStamp"]) <= _PKTMON_LAYER_WINDOW_US
        ]
        if candidates:
            journey = max(
                candidates,
                key=lambda item: (
                    int(item["stages"][-1]["PathIndex"]),
                    float(item["stages"][-1]["TimeStamp"]),
                ),
            )
        else:
            journey = {
                "Journey": next_id,
                "Direction": direction,
                "Protocol": fingerprint_proto,
                "5-Tuple": five,
                "stages": [],
            }
            next_id += 1
            active.setdefault(key, []).append(journey)
            journeys.append(journey)

        journey["stages"].append({
            "TimeStamp": row_ts,
            "Component": _safe_int(row.get("Component", -1)),
            "Edge": _safe_int(row.get("Edge", -1)),
            "PathIndex": path_index,
            "PktmonTime": row.get("PktmonTime", ""),
        })

        expected_path_len = len(_PKTMON_TX_PATH if direction == "Send" else _PKTMON_RX_PATH)
        if path_index == expected_path_len - 1:
            active[key] = [item for item in active.get(key, []) if item is not journey]

    for journey in journeys:
        stages = journey["stages"]
        direction = journey["Direction"]
        expected_path_len = len(_PKTMON_TX_PATH if direction == "Send" else _PKTMON_RX_PATH)
        path_indices = {int(stage["PathIndex"]) for stage in stages}
        complete = 0 in path_indices and expected_path_len - 1 in path_indices
        journey["Complete"] = complete
        journey["Confidence"] = _journey_confidence(str(journey["Protocol"]), complete)
        journey["TotalLatencyUs"] = (
            max(float(stage["TimeStamp"]) for stage in stages)
            - min(float(stage["TimeStamp"]) for stage in stages)
            if len(stages) > 1 else 0.0
        )

    return journeys


def _layer_latency_tables(
    journeys: list[dict[str, Any]],
    component_map: dict[int, str],
) -> tuple[pd.DataFrame, pd.DataFrame]:
    hop_values: dict[tuple[str, str, str, str, str], list[float]] = {}
    for journey in journeys:
        stages = journey["stages"]
        if len(stages) < 2:
            continue
        for before, after in zip(stages, stages[1:]):
            if int(after["PathIndex"]) <= int(before["PathIndex"]):
                continue
            hop = (
                f"{_stage_name(before['Component'], before['Edge'])} -> "
                f"{_stage_name(after['Component'], after['Edge'])}"
            )
            friendly_hop = _friendly_hop(before, after, component_map)
            key = (
                str(journey["Direction"]),
                str(journey["Protocol"]),
                hop,
                friendly_hop,
                str(journey["Confidence"]),
            )
            hop_values.setdefault(key, []).append(float(after["TimeStamp"]) - float(before["TimeStamp"]))

    hop_rows = []
    for (direction, proto, hop, friendly_hop, confidence), values in hop_values.items():
        hop_rows.append({
            "Direction": direction,
            "Protocol": proto,
            "Hop": hop,
            "Component Hop": friendly_hop,
            "Confidence": confidence,
            "Samples": len(values),
            "p50 us": round(_percentile(values, 50), 1),
            "p95 us": round(_percentile(values, 95), 1),
            "p99 us": round(_percentile(values, 99), 1),
            "Max us": round(max(values), 1),
        })

    slow_rows = []
    for journey in sorted(journeys, key=lambda item: float(item.get("TotalLatencyUs", 0)), reverse=True)[:10]:
        stages = journey["stages"]
        if len(stages) < 2:
            continue
        slow_rows.append({
            "Journey": journey["Journey"],
            "Direction": journey["Direction"],
            "Protocol": journey["Protocol"],
            "Confidence": journey["Confidence"],
            "Stages": len(stages),
            "Total us": round(float(journey["TotalLatencyUs"]), 1),
            "5-Tuple": journey["5-Tuple"],
            "Path": " -> ".join(_stage_name(stage["Component"], stage["Edge"]) for stage in stages),
            "Friendly Path": " -> ".join(
                _friendly_stage_name(stage["Component"], stage["Edge"], component_map)
                for stage in stages
            ),
        })

    hop_df = pd.DataFrame(hop_rows)
    if not hop_df.empty:
        hop_df = hop_df.sort_values(["Max us", "Samples"], ascending=[False, False]).reset_index(drop=True)
    slow_df = pd.DataFrame(slow_rows)
    return hop_df, slow_df


# ---------------------------------------------------------------------------
# Tool: get_packet_capture_summary
# ---------------------------------------------------------------------------


@mcp.tool()
def get_packet_capture_summary(
    trace_id: str,
    top_n: int = 50,
    process_filter: str | None = None,
) -> str:
    """Per-5-tuple packet/byte counts derived from decoded packet headers.

    Decodes the captured frame bytes for every row in ``packet_capture_df``
    on the fly (Ethernet → IP → L4) and groups by 5-tuple. If the trace has
    no NDIS PacketCapture rows, pktmon ETLs are summarized by converting
    them with ``pktmon etl2txt`` and reading boundary packet observations.
    One row per 5-tuple with packet count split by Direction (Recv / Send)
    and total bytes. Sorted by total bytes descending.

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 50.
        process_filter: Case-insensitive substring filter on Process Name.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    if not _ndis_packet_capture_available(trace):
        if process_filter:
            return (
                "*Process filtering is not available for pktmon text fallback.*\n\n"
                "This trace has no `Microsoft-Windows-NDIS-PacketCapture` "
                "frame-byte dataset, and pktmon ETL text does not include "
                "process names. Re-collect with NDIS PacketCapture enabled "
                "to filter packets by process."
            )
        pktmon_df, pktmon_error = _pktmon_capture_summary_df(trace)
        if pktmon_df is not None and not pktmon_df.empty:
            lines = [
                "**Packet Capture Summary**",
                "",
                "Source: pktmon ETL text fallback",
                f"5-tuples observed: {len(pktmon_df):,}",
                f"Total packets: {int(pktmon_df['Total Pkts'].sum()):,}",
                "",
                format_table(pktmon_df, max_rows=top_n),
            ]
            return "\n".join(lines)
        if pktmon_error:
            return f"{_NO_PACKET_CAPTURE_MSG}\n\nPktmon fallback was unavailable: {pktmon_error}."
        return _NO_PACKET_CAPTURE_MSG

    aggregates: dict[str, dict[str, Any]] = {}
    saw_packets = False
    saw_after_filter = False
    columns = [
        "Direction", "PacketBytes", "Size", "Process Name",
    ]
    for batch in _packet_capture_batches(trace, columns=columns):
        if not _packet_capture_ready(batch):
            continue
        saw_packets = saw_packets or not batch.empty
        batch = _apply_process_filter(batch, process_filter)
        if batch.empty:
            continue
        saw_after_filter = True
        for _, row in batch.iterrows():
            decoded = _decode_row(row.get("PacketBytes", ""))
            *_unused, five_tuple = _decoded_tuple_fields(decoded)
            entry = aggregates.setdefault(
                five_tuple,
                {
                    "5-Tuple": five_tuple,
                    "Recv Pkts": 0,
                    "Send Pkts": 0,
                    "Total Pkts": 0,
                    "Total Bytes": 0,
                },
            )
            direction = str(row.get("Direction", ""))
            if direction == "Recv":
                entry["Recv Pkts"] += 1
            elif direction == "Send":
                entry["Send Pkts"] += 1
            entry["Total Pkts"] += 1
            try:
                entry["Total Bytes"] += int(row.get("Size", 0) or 0)
            except (TypeError, ValueError):
                pass

    if not saw_packets:
        return _NO_PACKET_CAPTURE_MSG
    if not saw_after_filter:
        return f"*No packets match process filter `{process_filter}`.*"

    if not aggregates:
        return _NO_PACKET_CAPTURE_MSG

    result_df = pd.DataFrame(list(aggregates.values())).sort_values(
        "Total Bytes", ascending=False
    ).reset_index(drop=True)

    lines = [
        "**Packet Capture Summary**",
        "",
        f"5-tuples observed: {len(result_df):,}",
        f"Total packets: {int(result_df['Total Pkts'].sum()):,}",
    ]
    if process_filter:
        lines.append(f"Process filter: `{process_filter}`")
    lines.append("")
    lines.append(format_table(result_df, max_rows=top_n))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool: get_packet_timeline
# ---------------------------------------------------------------------------


@mcp.tool()
def get_packet_timeline(
    trace_id: str,
    five_tuple: str,
    max_packets: int = 100,
) -> str:
    """All packets for a given 5-tuple, in chronological order.

    Filters ``packet_capture_df`` to packets whose decoded 5-tuple matches
    ``five_tuple`` (direction-agnostic — both halves of the conversation
    are shown). Each row shows the decoded headers relevant to the L4
    protocol: ``Seq``, ``Ack``, ``Flags`` for TCP, ``Length`` for UDP,
    plus the raw captured size.

    Args:
        trace_id: ID returned by load_trace.
        five_tuple: 5-tuple selector. Accepted forms:
          ``"src:sport -> dst:dport/proto"`` (canonical, copy-pasteable
          from ``get_packet_capture_summary``); ``"src:sport - dst:dport"``;
          ``"src:sport dst:dport"``. Proto suffix is optional.
        max_packets: Cap on rows returned. Default: 100.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    if not _packet_capture_available(trace):
        return _NO_PACKET_CAPTURE_MSG

    query = _parse_five_tuple_query(five_tuple)
    if query is None:
        return (
            "*Could not parse 5-tuple. Expected a form like "
            "`10.0.0.1:5000 -> 10.0.0.2:6000/udp` or "
            "`10.0.0.1:5000-10.0.0.2:6000`.*"
        )

    rows: list[dict[str, Any]] = []
    columns = ["TimeStamp", "Direction", "PacketBytes", "Size"]
    for batch in _packet_capture_batches(trace, columns=columns):
        if not _packet_capture_ready(batch):
            continue
        for _, row in batch.iterrows():
            decoded_row = _decode_row(row.get("PacketBytes", ""))
            src, dst, sport, dport, proto, _five = _decoded_tuple_fields(decoded_row)
            match_row = {
                "_src": src,
                "_dst": dst,
                "_src_port": sport,
                "_dst_port": dport,
                "_proto": proto,
            }
            if not _five_tuples_match(match_row, query):
                continue
            if proto == "tcp":
                flags = decoded_row.get("tcp.flags", [])
                l4_fields = (
                    f"seq={decoded_row.get('tcp.seq', 0)} "
                    f"ack={decoded_row.get('tcp.ack', 0)} "
                    f"flags={'+'.join(flags) if flags else '-'}"
                )
            elif proto == "udp":
                l4_fields = f"length={decoded_row.get('udp.length', 0)}"
            elif proto in ("icmp", "icmpv6"):
                prefix = proto
                l4_fields = (
                    f"type={decoded_row.get(f'{prefix}.type', 0)} "
                    f"code={decoded_row.get(f'{prefix}.code', 0)}"
                )
            else:
                l4_fields = ""

            rows.append({
                "TimeStamp": row.get("TimeStamp", 0),
                "Direction": row.get("Direction", ""),
                "Proto": proto,
                "Src": f"{src}:{sport}",
                "Dst": f"{dst}:{dport}",
                "L4 Fields": l4_fields,
                "Size": int(row.get("Size", 0) or 0),
            })

    if not rows:
        return f"*No packets match 5-tuple `{five_tuple}`.*"

    timeline_df = pd.DataFrame(rows).sort_values("TimeStamp").reset_index(drop=True)
    lines = [
        f"**Packet Timeline:** `{five_tuple}`",
        "",
        f"Matched packets: {len(timeline_df):,}",
        "",
        format_table(timeline_df, max_rows=max_packets),
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool: get_send_recv_latency
# ---------------------------------------------------------------------------


# Maximum allowed gap between a matched Send→Recv pair, in microseconds.
# Larger gaps are almost certainly unrelated packets that happened to share
# the same IPID or seqno. 10 ms is generous for loopback, conservative for
# WAN, and a non-issue for the typical project usage (loopback echo tests).
_MATCH_WINDOW_US = 10_000


def _matching_key(row, decoded: dict[str, Any]) -> tuple | None:
    """Build a matching key for Send/Recv latency.

    Strategy:
      * TCP — match by (src_ip, dst_ip, src_port, dst_port, seq).
      * UDP / other IP protocols — match by (src_ip, dst_ip, src_port,
        dst_port, ip.id). IPID is not guaranteed unique across a long
        trace but is a good signal over a short ~10 ms window.

    Returns ``None`` when we lack enough fields to form a key, in which
    case the row is excluded from the latency analysis.
    """
    src = decoded.get("ip.src")
    dst = decoded.get("ip.dst")
    if not src or not dst:
        return None

    proto = decoded.get("ip.proto")
    if proto == 6:  # TCP
        seq = decoded.get("tcp.seq")
        sport = decoded.get("tcp.src_port")
        dport = decoded.get("tcp.dst_port")
        if seq is None or sport is None or dport is None:
            return None
        return ("tcp", src, dst, sport, dport, seq)
    if proto == 17:  # UDP
        ip_id = decoded.get("ip.id")
        sport = decoded.get("udp.src_port")
        dport = decoded.get("udp.dst_port")
        if ip_id is None or sport is None or dport is None:
            return None
        return ("udp", src, dst, sport, dport, ip_id)
    # IPv6 has no IPID; bail unless TCP path covered it above.
    return None


def _flow_label(src: str, dst: str, sport: int, dport: int, proto: str) -> str:
    return f"{src}:{sport} -> {dst}:{dport}/{proto}"


def _packet_timestamp(row) -> int | None:
    try:
        value = row.get("TimeStamp", 0)
    except AttributeError:
        return None
    try:
        if pd.isna(value):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


@mcp.tool()
def get_send_recv_latency(trace_id: str, top_n: int = 20) -> str:
    """Match Send → Recv packet pairs and report per-flow latency percentiles.

    For each Send packet we look up the next Recv packet with the same
    matching key (5-tuple + TCP sequence number, or 5-tuple + IPID for
    UDP) and compute the elapsed microseconds. Pairs separated by more
    than ~10 ms are dropped.

    **Heuristic, with caveats:**

    * On **loopback**, the latency floor is meaningful — the kernel is
      both sender and receiver and the timestamps come from the same
      clock, so anything sub-microsecond is real.
    * On a **two-NIC test setup with synchronized clocks** (e.g. PTP),
      the floor is meaningful but offset by clock skew.
    * On a **multi-NIC system with unsynchronized clocks** the floor is
      essentially clock skew, not network latency — treat distributions
      as a relative signal across flows, not as absolute one-way latency.

    The matching by IPID is also approximate: NICs and stacks may reuse
    IPIDs over long timescales, but within the ~10 ms match window
    collisions are rare for the project's loopback / 100 GbE setups.

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 20.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    if not _packet_capture_available(trace):
        return _NO_PACKET_CAPTURE_MSG

    # Stream in timestamp order. Keep only unmatched sends whose expiry is
    # inside the bounded matching window, and match them when the corresponding
    # recv arrives. Materialized xperf traces are globally sorted first; native
    # event-store chunks are sorted per batch and can undercount if chunks are
    # globally out of order.
    pending_sends: dict[tuple, deque[tuple[int, dict[str, Any]]]] = {}
    expiry_heap: list[tuple[int, tuple, int]] = []
    per_flow_latencies: dict[str, list[int]] = {}
    saw_send = False
    saw_recv = False

    def _evict_expired(now_ts: int) -> None:
        while expiry_heap and expiry_heap[0][0] < now_ts:
            _expires_at, key, send_ts = heapq.heappop(expiry_heap)
            queue = pending_sends.get(key)
            if not queue:
                continue
            while queue and queue[0][0] < now_ts - _MATCH_WINDOW_US:
                queue.popleft()
            if not queue:
                pending_sends.pop(key, None)

    columns = ["TimeStamp", "Direction", "PacketBytes"]
    for batch in _packet_capture_batches(trace, columns=columns, sort_by_time=True):
        if not _packet_capture_ready(batch):
            continue
        if "Direction" not in batch.columns or "TimeStamp" not in batch.columns:
            continue
        for _, row in batch.iterrows():
            ts = _packet_timestamp(row)
            if ts is None:
                continue
            _evict_expired(ts)
            decoded = _decode_row(row.get("PacketBytes", ""))
            if not decoded:
                continue
            key = _matching_key(row, decoded)
            if key is None:
                continue
            direction = str(row.get("Direction", "")).lower()
            if direction == "send":
                saw_send = True
                pending_sends.setdefault(key, deque()).append((ts, decoded))
                heapq.heappush(expiry_heap, (ts + _MATCH_WINDOW_US, key, ts))
                continue
            if direction != "recv":
                continue
            saw_recv = True
            candidates = pending_sends.get(key)
            if not candidates:
                continue
            while candidates and ts - candidates[0][0] > _MATCH_WINDOW_US:
                candidates.popleft()
            if not candidates:
                pending_sends.pop(key, None)
                continue
            send_ts, send_decoded = candidates.popleft()
            if not candidates:
                pending_sends.pop(key, None)
            if send_ts > ts:
                continue
            latency_us = ts - send_ts
            proto_str = "tcp" if key[0] == "tcp" else "udp"
            if proto_str == "tcp":
                sport = send_decoded.get("tcp.src_port", 0)
                dport = send_decoded.get("tcp.dst_port", 0)
            else:
                sport = send_decoded.get("udp.src_port", 0)
                dport = send_decoded.get("udp.dst_port", 0)
            flow_label = _flow_label(
                send_decoded.get("ip.src", ""), send_decoded.get("ip.dst", ""),
                int(sport or 0), int(dport or 0), proto_str,
            )
            per_flow_latencies.setdefault(flow_label, []).append(latency_us)

    if not saw_send or not saw_recv:
        return (
            "*No matched Send/Recv pairs in packet capture data.*\n\n"
            "Either the trace contains only one direction, or the matching "
            "fields (TCP seqno / IPID + 5-tuple) are not consistent between "
            "send and recv (common on a multi-NIC setup where the IPID is "
            "rewritten in transit)."
        )

    if not per_flow_latencies:
        return (
            "*No Send → Recv pairs found within the matching window.*\n\n"
            "On multi-NIC systems with unsynchronized clocks the timestamps "
            "may differ by more than the 10 ms window we use to match a "
            "send to its echo; this can produce zero pairs even when the "
            "raw capture contains both directions."
        )

    rows: list[dict[str, Any]] = []
    for flow, latencies in per_flow_latencies.items():
        s = pd.Series(latencies, dtype="float64")
        rows.append({
            "Flow": flow,
            "Pairs": len(s),
            "p50 (us)": round(float(s.quantile(0.50)), 2),
            "p99 (us)": round(float(s.quantile(0.99)), 2),
            "p999 (us)": round(float(s.quantile(0.999)), 2),
            "min (us)": int(s.min()),
            "max (us)": int(s.max()),
        })

    result_df = pd.DataFrame(rows).sort_values(
        "Pairs", ascending=False
    ).reset_index(drop=True)

    lines = [
        "**Send → Recv Latency (Heuristic)**",
        "",
        f"Flows with matched pairs: {len(result_df):,}",
        f"Match window: {_MATCH_WINDOW_US / 1000:.0f} ms",
        "",
        "*Latency is one-way Send→Recv elapsed microseconds. Meaningful on "
        "loopback and PTP-synced two-NIC setups; on unsynchronized multi-NIC "
        "systems the floor is dominated by clock skew.*",
        "",
        "*Native event-store scans use bounded timestamp-order matching and "
        "evict candidates after the match window. If packet-capture chunks are "
        "globally out of order, pair counts can be under-reported; xperf/"
        "materialized traces are sorted before matching.*",
        "",
        format_table(result_df, max_rows=top_n),
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool: decode_packet
# ---------------------------------------------------------------------------


def _format_decoded_packet(decoded: dict[str, Any]) -> str:
    """Render a decoded-headers dict as a hierarchical markdown block."""
    if not decoded:
        return "*Packet bytes failed to decode (truncated or non-Ethernet).*"

    lines = ["**Ethernet:**"]
    lines.append(f"- src: `{decoded.get('eth.src', '?')}`")
    lines.append(f"- dst: `{decoded.get('eth.dst', '?')}`")
    et = decoded.get("eth.ethertype")
    if et is not None:
        lines.append(f"- ethertype: `0x{int(et):04x}`")
    if "eth.vlan_ethertype" in decoded:
        lines.append(
            f"- inner ethertype (VLAN): `0x{int(decoded['eth.vlan_ethertype']):04x}`"
        )

    if "ip.version" in decoded:
        version = decoded["ip.version"]
        lines.append("")
        lines.append(f"**IPv{int(version)}:**")
        if version == 4:
            lines.append(f"- src: `{decoded.get('ip.src', '?')}`")
            lines.append(f"- dst: `{decoded.get('ip.dst', '?')}`")
            lines.append(f"- proto: `{decoded.get('ip.proto', '?')}`")
            lines.append(f"- ttl: `{decoded.get('ip.ttl', '?')}`")
            lines.append(f"- id: `{decoded.get('ip.id', '?')}`")
            lines.append(f"- total_length: `{decoded.get('ip.total_length', '?')}`")
        else:
            lines.append(f"- src: `{decoded.get('ip.src', '?')}`")
            lines.append(f"- dst: `{decoded.get('ip.dst', '?')}`")
            lines.append(f"- next_header: `{decoded.get('ip.next_header', '?')}`")
            lines.append(f"- hop_limit: `{decoded.get('ip.hop_limit', '?')}`")
            lines.append(f"- payload_length: `{decoded.get('ip.payload_length', '?')}`")

    if "tcp.src_port" in decoded:
        lines.append("")
        lines.append("**TCP:**")
        lines.append(f"- src_port: `{decoded.get('tcp.src_port', '?')}`")
        lines.append(f"- dst_port: `{decoded.get('tcp.dst_port', '?')}`")
        lines.append(f"- seq: `{decoded.get('tcp.seq', '?')}`")
        lines.append(f"- ack: `{decoded.get('tcp.ack', '?')}`")
        flags = decoded.get("tcp.flags")
        if flags is not None:
            lines.append(f"- flags: `{'+'.join(flags) if flags else '-'}`")
        lines.append(f"- window: `{decoded.get('tcp.window', '?')}`")
    elif "udp.src_port" in decoded:
        lines.append("")
        lines.append("**UDP:**")
        lines.append(f"- src_port: `{decoded.get('udp.src_port', '?')}`")
        lines.append(f"- dst_port: `{decoded.get('udp.dst_port', '?')}`")
        lines.append(f"- length: `{decoded.get('udp.length', '?')}`")
    elif "icmp.type" in decoded:
        lines.append("")
        lines.append("**ICMP:**")
        lines.append(f"- type: `{decoded.get('icmp.type', '?')}`")
        lines.append(f"- code: `{decoded.get('icmp.code', '?')}`")
    elif "icmpv6.type" in decoded:
        lines.append("")
        lines.append("**ICMPv6:**")
        lines.append(f"- type: `{decoded.get('icmpv6.type', '?')}`")
        lines.append(f"- code: `{decoded.get('icmpv6.code', '?')}`")

    if "_truncated_at" in decoded:
        lines.append("")
        lines.append(f"*Packet truncated at layer: `{decoded['_truncated_at']}`.*")
    return "\n".join(lines)


@mcp.tool()
def decode_packet(trace_id: str, timestamp_us: float) -> str:
    """Decode the single packet whose timestamp is closest to ``timestamp_us``.

    Useful for "show me what packet fired at time X". The result lays out
    the Ethernet, IP, and L4 layers field-by-field.

    Args:
        trace_id: ID returned by load_trace.
        timestamp_us: Target timestamp in microseconds (matches the
            dumper's TimeStamp column).
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    if not _packet_capture_available(trace):
        return _NO_PACKET_CAPTURE_MSG

    best_row: dict[str, Any] | None = None
    best_delta: float | None = None
    target = float(timestamp_us)
    columns = ["TimeStamp", "Direction", "MiniportName", "PacketBytes", "Size"]
    for batch in _packet_capture_batches(trace, columns=columns):
        if not _packet_capture_ready(batch) or "TimeStamp" not in batch.columns:
            continue
        for _, row in batch.iterrows():
            ts = _packet_timestamp(row)
            if ts is None:
                continue
            delta = abs(float(ts) - target)
            if best_delta is None or delta < best_delta:
                best_delta = delta
                best_row = row.to_dict()

    if best_row is None:
        return "*No packets with parseable timestamps in this trace.*"

    packet_hex = best_row.get("PacketBytes", "")
    decoded = _decode_row(packet_hex)
    actual_ts = int(best_row.get("TimeStamp", 0) or 0)
    direction = best_row.get("Direction", "")
    miniport = best_row.get("MiniportName", "")
    size = int(best_row.get("Size", 0) or 0)

    lines = [
        "**Decoded Packet**",
        "",
        f"- Trace timestamp: `{actual_ts} us` (queried `{target:.1f} us`, "
        f"delta `{actual_ts - target:.1f} us`)",
        f"- Direction: `{direction}`",
        f"- Miniport: `{miniport}`",
        f"- Captured size: `{size}` bytes",
        "",
        _format_decoded_packet(decoded),
    ]
    return "\n".join(lines)


@mcp.tool()
def get_pktmon_layer_latency(
    trace_id: str,
    five_tuple: str | None = None,
    direction: str | None = None,
    max_rows: int = 30,
) -> str:
    """Estimate pktmon per-layer traversal latency by component/edge hop.

    Uses pktmon text metadata plus PCAPNG packet bytes to group appearances
    from the same packet journey. TCP journeys use a strong packet
    fingerprint (5-tuple, seq/ack/flags, payload length, IP ID, size). UDP
    and IP-only journeys use weaker fingerprints and are marked with lower
    confidence. This tool requires a pktmon ETL collected with
    ``pktmon start --capture --pkt-size 0``.

    Args:
        trace_id: ID returned by load_trace.
        five_tuple: Optional flow selector such as
            ``"10.0.0.1:5000 -> 10.0.0.2:6000/tcp"``. Matching is
            direction-agnostic.
        direction: Optional ``"tx"``/``"send"`` or ``"rx"``/``"recv"``
            filter.
        max_rows: Maximum hop rows to return. Default: 30.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    df, error = _pktmon_packet_capture_df(trace, boundary_only=False)
    if df is None or df.empty:
        if error:
            return f"*No pktmon packet-layer data available.*\n\nPktmon fallback was unavailable: {error}."
        return "*No pktmon packet-layer data available.*"

    component_map, component_source = _pktmon_component_map(trace)
    journeys = _group_pktmon_journeys(df, five_tuple=five_tuple, direction_filter=direction)
    hop_df, slow_df = _layer_latency_tables(journeys, component_map)
    if hop_df.empty:
        return "*No pktmon packet journeys could be grouped for layer-latency analysis.*"

    complete_count = sum(1 for journey in journeys if journey.get("Complete"))
    lines = [
        "**Pktmon Layer Latency**",
        "",
        f"Journeys grouped: {len(journeys):,}",
        f"Complete journeys: {complete_count:,}",
        f"Grouping window: {_PKTMON_LAYER_WINDOW_US:,} us",
        (
            f"Component names: {component_source}"
            if component_source
            else "Component names: unavailable; showing raw component IDs"
        ),
    ]
    if five_tuple:
        lines.append(f"5-tuple filter: `{five_tuple}`")
    if direction:
        lines.append(f"Direction filter: `{direction}`")
    lines.extend([
        "",
        format_table(hop_df, max_rows=max_rows),
    ])
    if not slow_df.empty:
        lines.extend([
            "",
            "**Slowest grouped journeys**",
            "",
            format_table(slow_df, max_rows=min(10, max_rows)),
        ])
    return "\n".join(lines)


__all__ = [
    "decode_packet",
    "get_packet_capture_summary",
    "get_packet_timeline",
    "get_pktmon_layer_latency",
    "get_send_recv_latency",
]
