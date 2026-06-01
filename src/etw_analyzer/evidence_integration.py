"""Evidence-store federation hook for etw-trace-analyzer.

This module wires loaded traces into a shared per-machine
``evidence.duckdb`` so the federation MCP (``evidence-query``) can
correlate ETW samples with crash-dump frames for the same Module on
the same Machine.

Gating contract (G3 in ``evidence-mcp-poc-plan.md`` §1.1):

1. ``evidence-store`` is an **optional** extras dependency. The import
   is wrapped in ``try/except ImportError`` so a default
   ``uv sync`` install (without ``--extra evidence``) does NOT pull
   the library and this module still imports cleanly.
2. Registration is **opt-in** via the ``WPR_MCP_EVIDENCE_PATH``
   environment variable. When unset, :func:`register_entities_from_trace`
   is a no-op. With it set, the library writes to
   ``$WPR_MCP_EVIDENCE_PATH/<machine_id>/evidence.duckdb``.
3. Any failure inside :func:`register_entities_from_trace` is logged
   and swallowed by the call site — load_trace must never break
   because of evidence wiring.

The two gates are independent — the library can be installed but
inactive (no env var), the env var can be set but ineffective (library
missing). Both must hold for entities to be written.
"""

from __future__ import annotations

import logging

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from etw_analyzer.trace_state import TraceData

logger = logging.getLogger(__name__)

# G3: import is guarded. ``EvidenceStore`` stays ``None`` when the
# library is absent so callers can branch on ``_EVIDENCE_AVAILABLE``.
try:
    from evidence_store import EvidenceStore  # type: ignore[import-not-found]

    _EVIDENCE_AVAILABLE = True
except ImportError:
    EvidenceStore = None  # type: ignore[assignment,misc]
    _EVIDENCE_AVAILABLE = False


from .native.env_compat import getenv as _compat_getenv

ENV_VAR = "ETW_MCP_EVIDENCE_PATH"


def is_available() -> bool:
    """Return True when the evidence-store library is importable."""
    return _EVIDENCE_AVAILABLE


def is_configured() -> bool:
    """Return True when the env var is set (regardless of library)."""
    return bool(_compat_getenv(ENV_VAR))


def evidence_root() -> Path | None:
    """Return the configured evidence root, or ``None`` if unset."""
    value = _compat_getenv(ENV_VAR)
    if not value:
        return None
    return Path(value)


def db_path_for(machine_id: str) -> Path | None:
    """Compute the per-machine DuckDB path for a given machine_id."""
    root = evidence_root()
    if root is None:
        return None
    return root / machine_id / "evidence.duckdb"


# --- Trace → identity extraction --------------------------------------------

_HOSTNAME_PATTERNS = (
    re.compile(r"^\s*Computer\s*Name\s*[:=]\s*(\S+)", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*Host\s*Name\s*[:=]\s*(\S+)", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*HostName\s*[:=]\s*(\S+)", re.MULTILINE | re.IGNORECASE),
)

_OS_BUILD_PATTERNS = (
    re.compile(r"OSVersion\s*[:=]\s*([0-9.]+)", re.IGNORECASE),
    re.compile(r"Windows\s+build\s+([0-9.]+)", re.IGNORECASE),
    re.compile(r"BuildNumber\s*[:=]\s*([0-9]+)", re.IGNORECASE),
)


def _sysconfig_text(trace: "TraceData") -> str:
    raw = trace.raw_csv.get("sysconfig")
    if raw is None or raw.empty or "raw_text" not in raw.columns:
        return ""
    return str(raw.iloc[0].get("raw_text") or "")


def _extract_hostname(trace: "TraceData") -> str:
    text = _sysconfig_text(trace)
    for pat in _HOSTNAME_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(1).strip().lower()
    # Fallback: ETL filename stem is at least stable per-machine when the
    # operator follows the project's "<host>-<date>.etl" naming convention.
    return trace.etl_path.stem.lower()


def _extract_os_build(trace: "TraceData") -> str | None:
    text = _sysconfig_text(trace)
    for pat in _OS_BUILD_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(1).strip()
    return None


def _extract_architecture(trace: "TraceData") -> str | None:
    df = trace.raw_csv.get("trace_metadata")
    if df is None or df.empty or "PointerSize" not in df.columns:
        return None
    try:
        ps = int(df.iloc[0]["PointerSize"])
    except (TypeError, ValueError):
        return None
    return {4: "x86", 8: "x64"}.get(ps)


# --- Module registration ----------------------------------------------------

def _iter_modules(trace: "TraceData") -> list[dict[str, Any]]:
    """Yield ``{name, version, path, base_addr, load_time}`` rows from Image/Load events.

    Module identity in evidence-store is ``(machine, name_lower, version)``
    — see ``evidence-store`` identifiers.py. We pack ``TimeDateStamp`` +
    ``ImageSize`` into the version string so two MCPs registering the
    same on-disk binary collapse into one Module entity even when they
    have no human-readable version handy.

    ``base_addr`` and ``load_time`` come from the same row and travel
    with the module so the caller can write a ModuleLoad observation
    per (module, load-site) — see ``register_entities_from_trace`` for
    the wire-up. Multiple Image/Load rows for the same (name, version)
    are still deduped at the Module entity level, but each distinct
    (name, version, base_addr) keeps its own load observation so the
    consumer side can correlate per-process loads.
    """
    by_key: dict[tuple[str, str, int], dict[str, Any]] = {}
    for key in ("Image/Load", "Image/DCStart"):
        df = trace.raw_csv.get(key)
        if df is None or df.empty:
            continue
        cols = df.columns
        if "FileName" not in cols:
            continue
        for _, row in df.iterrows():
            file_name = str(row.get("FileName") or "").strip("\x00").strip()
            if not file_name:
                continue
            name = file_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
            if not name:
                continue
            try:
                tds = int(row.get("TimeDateStamp", 0) or 0)
            except (TypeError, ValueError):
                tds = 0
            try:
                size = int(row.get("ImageSize", 0) or 0)
            except (TypeError, ValueError):
                size = 0
            try:
                base_addr = int(row.get("ImageBase", 0) or 0)
            except (TypeError, ValueError):
                base_addr = 0
            try:
                load_time = int(row.get("TimeStamp", 0) or 0)
            except (TypeError, ValueError):
                load_time = 0
            version = f"tds={tds:08x};size={size}"
            dedup_key = (name, version, base_addr)
            if dedup_key in by_key:
                continue
            by_key[dedup_key] = {
                "name": name,
                "version": version,
                "path": file_name,
                "base_addr": base_addr,
                "load_time": load_time,
                "image_size": size,
                "source_kind": key,  # "Image/Load" vs "Image/DCStart"
            }
    return list(by_key.values())


def _iter_processes(trace: "TraceData") -> list[dict[str, Any]]:
    """Yield ``{pid, start_time, image_name, command_line}`` rows."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    df = trace.raw_csv.get("process")
    if df is None or df.empty:
        # Native pipeline also stashes a backup under _native_process_events.
        df = trace.raw_csv.get("_native_process_events")
    if df is None or df.empty:
        return out
    for _, row in df.iterrows():
        try:
            pid = int(row.get("ProcessId", 0) or 0)
        except (TypeError, ValueError):
            continue
        if pid <= 0:
            continue
        image = str(row.get("ImageFileName", "") or "").strip("\x00").strip()
        cmd = str(row.get("CommandLine", "") or "").strip("\x00").strip() or None
        ts = row.get("TimeStamp", 0) or 0
        # The store uses start_time as part of identity — keep it as a
        # canonical string so the same (pid, ts) pair from a re-load
        # collapses.
        start_time = str(int(ts)) if isinstance(ts, (int, float)) else str(ts)
        key = (pid, start_time)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "pid": pid,
                "start_time": start_time,
                "image_name": image or None,
                "command_line": cmd,
            }
        )
    return out


# --- Public entry point -----------------------------------------------------

def register_entities_from_trace(
    trace: "TraceData",
    *,
    hostname_override: str | None = None,
) -> str | None:
    """Register entities for ``trace`` in the configured evidence store.

    Returns the registered ``machine_id``, or ``None`` if either G3
    gate is not satisfied (library missing OR env var unset).

    ``hostname_override`` is for tests + cross-tool identity proofs that
    need to pin a known hostname without writing a fake sysconfig
    DataFrame.
    """
    if not _EVIDENCE_AVAILABLE:
        return None
    if not is_configured():
        return None
    assert EvidenceStore is not None  # for pyright after the gate

    hostname = hostname_override or _extract_hostname(trace)
    if not hostname:
        logger.warning("evidence: could not determine hostname for %s", trace.etl_path)
        return None

    os_build = _extract_os_build(trace)
    architecture = _extract_architecture(trace)

    from evidence_store import machine_id as derive_machine_id  # type: ignore[import-not-found]

    machine_id = derive_machine_id(hostname)
    path = db_path_for(machine_id)
    if path is None:
        return None

    source_path = str(trace.etl_path)
    store = EvidenceStore.open(path)
    try:
        store.register_machine(
            hostname=hostname, os_build=os_build, architecture=architecture
        )

        # Pre-resolve EvidenceRef per Image/* source kind so identical
        # rows collapse to a single evidence row in the DB (the store
        # dedups by (kind, path, locator)).
        from evidence_store import EvidenceRef  # type: ignore[import-not-found]

        load_refs: dict[str, EvidenceRef] = {
            "Image/Load": EvidenceRef(
                kind="etl_row", path=source_path, locator="Image/Load"
            ),
            "Image/DCStart": EvidenceRef(
                kind="etl_row", path=source_path, locator="Image/DCStart"
            ),
        }

        for mod in _iter_modules(trace):
            try:
                module_eid = store.register_module(
                    machine_id=machine_id,
                    name=mod["name"],
                    version=mod["version"],
                    path=mod.get("path"),
                )
            except Exception:
                logger.debug(
                    "evidence: register_module failed for %r",
                    mod.get("name"), exc_info=True,
                )
                continue

            # Write one ModuleLoad observation per (module, base_addr)
            # so the evidence-query ``ModuleLoad`` view (v2 schema)
            # can join against this trace. This is the bridge that
            # makes the cross-tool ``correlate_trace_and_dump`` query
            # work — without it, the consumer side sees Module
            # entities but no load events and the "in_dump" column
            # stays empty for everything.
            try:
                ref = load_refs.get(mod.get("source_kind", "Image/Load"),
                                    load_refs["Image/Load"])
                payload: dict[str, Any] = {
                    "base_addr": int(mod.get("base_addr", 0) or 0),
                    "load_time": int(mod.get("load_time", 0) or 0),
                    "image_size": int(mod.get("image_size", 0) or 0),
                    "path": mod.get("path"),
                }
                store.add_observation(
                    kind="ModuleLoad",
                    entity_ids=[module_eid],
                    timestamp_utc=int(mod.get("load_time", 0) or 0) or None,
                    payload=payload,
                    source=ref,
                )
            except Exception:
                logger.debug(
                    "evidence: add ModuleLoad observation failed for %r",
                    mod.get("name"), exc_info=True,
                )

        for proc in _iter_processes(trace):
            try:
                store.register_process(
                    machine_id=machine_id,
                    pid=proc["pid"],
                    start_time=proc["start_time"],
                    image_name=proc.get("image_name"),
                    command_line=proc.get("command_line"),
                )
            except Exception:
                logger.debug("evidence: register_process failed for pid=%s",
                             proc.get("pid"), exc_info=True)

        # NIC registration is intentionally minimal in this POC. The
        # native sysconfig aggregator does not surface NIC LUID /
        # friendly_name as structured fields yet (see plan §3.4). When
        # the upstream aggregator grows those columns this is the right
        # hook point.
        return machine_id
    finally:
        store.close()


def safe_register_entities_from_trace(trace: "TraceData") -> str | None:
    """Like :func:`register_entities_from_trace` but never raises.

    The call site (``_run_native_aggregators``) wants a strict no-op on
    any failure so a broken evidence install cannot regress trace
    loading.
    """
    try:
        return register_entities_from_trace(trace)
    except Exception:
        logger.warning("evidence: registration failed", exc_info=True)
        return None


__all__ = [
    "EvidenceStore",
    "ENV_VAR",
    "is_available",
    "is_configured",
    "evidence_root",
    "db_path_for",
    "register_entities_from_trace",
    "safe_register_entities_from_trace",
]
