"""MCP tools for the evidence-store federation hook.

Exposes two tools:

- :func:`get_evidence_status` — whether the optional ``evidence-store``
  library is installed and whether the ``ETW_MCP_EVIDENCE_PATH`` env
  var is set. Useful for the operator to diagnose why
  :func:`get_entities` returns no rows.
- :func:`get_entities` — list entities registered for a loaded trace,
  optionally filtered by entity_type and a substring filter.

Both tools degrade gracefully when the library is missing or the
env var is unset: they return a friendly message rather than raising.
This preserves the G3 guarantee — a default ``uv sync`` install can
still call the tool without ImportError.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from etw_analyzer.app import mcp
from etw_analyzer.evidence_integration import (
    ENV_VAR,
    db_path_for,
    evidence_root,
    is_available,
    is_configured,
    register_entities_from_trace,
)
from etw_analyzer.formatting.markdown import format_table
from etw_analyzer.trace_state import require_trace


_VALID_ENTITY_TYPES = (
    "machine",
    "module",
    "process",
    "thread",
    "driver",
    "service",
    "nic",
)


@mcp.tool()
def get_evidence_status() -> str:
    """Show whether the evidence-store federation hook is available.

    Two independent gates must both be on for entities to be written:
    the optional ``evidence-store`` library must be installed
    (``uv sync --extra evidence``) AND the ``ETW_MCP_EVIDENCE_PATH``
    environment variable must point at a directory.
    """
    lines = ["**Evidence federation status**", ""]
    lines.append(f"- Library installed: **{is_available()}**")
    lines.append(f"- `{ENV_VAR}` set: **{is_configured()}**")
    root = evidence_root()
    if root is not None:
        lines.append(f"- Evidence root: `{root}`")
    if not is_available():
        lines.append("")
        lines.append(
            "Install with `uv sync --extra evidence` to enable entity "
            "registration."
        )
    if is_available() and not is_configured():
        lines.append("")
        lines.append(
            f"Set `{ENV_VAR}=<dir>` and reload traces to register "
            "entities."
        )
    return "\n".join(lines)


@mcp.tool()
def get_entities(
    trace_id: str,
    entity_type: str = "module",
    filter: str | None = None,
    max_rows: int = 50,
) -> str:
    """List evidence-store entities registered for a loaded trace.

    Args:
        trace_id: ID returned by ``load_trace``.
        entity_type: One of ``"machine"``, ``"module"``, ``"process"``,
            ``"thread"``, ``"driver"``, ``"service"``, ``"nic"``. Default
            ``"module"``.
        filter: Optional case-insensitive substring filter applied to
            the entity's primary name column (``hostname`` for
            machines, ``name`` for modules / services, ``image_name``
            for processes).
        max_rows: Truncate the table to this many rows. Default 50.

    Returns a markdown table. Returns a friendly message when the
    evidence-store library is unavailable or ``ETW_MCP_EVIDENCE_PATH``
    is unset (G3 — neither condition is an error).
    """
    trace = require_trace(trace_id)

    if not is_available():
        return (
            "Evidence store is not installed. Install with "
            "`uv sync --extra evidence` to enable this tool."
        )
    if not is_configured():
        return (
            f"Evidence store is installed but `{ENV_VAR}` is unset; "
            "no entities have been recorded for this process."
        )

    et = entity_type.lower().strip()
    if et not in _VALID_ENTITY_TYPES:
        valid = ", ".join(_VALID_ENTITY_TYPES)
        return f"Unknown entity_type `{entity_type}`. Valid: {valid}."

    # Determine machine_id by re-deriving from the trace. Same logic the
    # registration call uses, so a tool call after a fresh load (with
    # the env var set both times) will land on the same DB file.
    machine_id = register_entities_from_trace(trace)
    if machine_id is None:
        return (
            "Evidence registration returned no machine_id for this "
            "trace. Check that `sysconfig` is populated or set the "
            "hostname manually before calling load_trace."
        )

    path = db_path_for(machine_id)
    if path is None or not path.exists():
        return f"No evidence DB at `{path}` for machine `{machine_id}`."

    # Re-open the store read-only for the query. We bring in the
    # library lazily — we already know it is installed because
    # ``is_available()`` returned True above.
    from evidence_store import EvidenceStore  # type: ignore[import-not-found]

    store = EvidenceStore.open(path)
    try:
        df = _query_entities(store, et, filter, machine_id, max_rows)
    finally:
        store.close()

    if df.empty:
        return f"*No `{et}` entities for machine `{machine_id}`.*"

    header = (
        f"**{et.capitalize()} entities** for machine `{machine_id}` "
        f"(db: `{path}`)\n\n"
    )
    return header + format_table(df, max_rows=max_rows)


def _query_entities(
    store: Any,
    entity_type: str,
    filter_substr: str | None,
    machine_id: str,
    max_rows: int,
) -> pd.DataFrame:
    """Run a per-entity-type SELECT and apply optional filter."""
    cols_and_table = {
        "machine": ("entity_id, hostname, os_build, architecture", "Machine",
                    "hostname", False),
        "module": ("entity_id, name, version, path", "Module", "name", True),
        "process": ("entity_id, pid, start_time, image_name, command_line",
                    "Process", "image_name", True),
        "thread": ("entity_id, pid, tid, start_time", "Thread", None, True),
        "driver": ("entity_id, service_name, display_name, path", "Driver",
                   "service_name", True),
        "service": ("entity_id, name, display_name", "Service", "name", True),
        "nic": ("entity_id, friendly_name, mac_address, description", "NIC",
                "friendly_name", True),
    }
    cols, table, name_col, machine_scoped = cols_and_table[entity_type]
    where: list[str] = []
    params: list[Any] = []
    if machine_scoped:
        where.append("machine_id = ?")
        params.append(machine_id)
    elif entity_type == "machine":
        where.append("entity_id = ?")
        params.append(machine_id)
    if filter_substr and name_col:
        where.append(f"LOWER({name_col}) LIKE ?")
        params.append(f"%{filter_substr.lower()}%")
    sql = f"SELECT {cols} FROM {table}"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += f" LIMIT {int(max_rows) + 1}"
    table_arrow = store.query(sql, params)
    return table_arrow.to_pandas()
