"""Tests for the evidence-store federation hook.

Covers both code paths required by ``evidence-mcp-poc-plan.md`` §1.1 G3:

1. The module imports cleanly even when ``evidence-store`` is absent
   (we simulate this by patching the module-level flag).
2. ``register_entities_from_trace`` returns ``None`` when the env var
   is unset.
3. With both gates on, it returns a stable ``machine_id`` and
   re-registration is idempotent (same id, no row duplication).
4. ``get_entities`` renders the expected markdown.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd
import pytest

from etw_analyzer import evidence_integration
from etw_analyzer.trace_state import TraceData


# ---------------------------------------------------------------------------
# Fixture: a minimal in-memory TraceData with enough raw_csv to drive
# the extractor without spinning up xperf / native.
# ---------------------------------------------------------------------------

def _make_trace(tmp_path: Path, hostname: str = "test-host-01") -> TraceData:
    etl_path = tmp_path / "fake.etl"
    etl_path.write_bytes(b"")
    export_dir = tmp_path / ".etw-export-fake"
    export_dir.mkdir()

    sysconfig = pd.DataFrame(
        [{"raw_text": f"Computer Name: {hostname}\nOSVersion: 10.0.22621\n"}]
    )
    trace_metadata = pd.DataFrame(
        [{"NumberOfProcessors": 8, "PointerSize": 8, "DurationSeconds": 12.5}]
    )
    image_load = pd.DataFrame(
        [
            {
                "FileName": r"\Windows\System32\ntoskrnl.exe",
                "TimeDateStamp": 0xDEADBEEF,
                "ImageSize": 16_000_000,
                "ImageBase": 0xFFFFF80000000000,
                "ProcessId": 4,
            },
            {
                "FileName": r"C:\Windows\System32\drivers\tcpip.sys",
                "TimeDateStamp": 0xCAFEBABE,
                "ImageSize": 4_000_000,
                "ImageBase": 0xFFFFF80001000000,
                "ProcessId": 4,
            },
            # Duplicate of ntoskrnl from a DCStart batch — must collapse
            # to the same Module entity.
            {
                "FileName": r"\Windows\System32\ntoskrnl.exe",
                "TimeDateStamp": 0xDEADBEEF,
                "ImageSize": 16_000_000,
                "ImageBase": 0xFFFFF80000000000,
                "ProcessId": 4,
            },
        ]
    )
    processes = pd.DataFrame(
        [
            {
                "ProcessId": 1234,
                "ImageFileName": "echo_server.exe",
                "CommandLine": "echo_server.exe --port 5000",
                "TimeStamp": 1_700_000_000,
            },
            {
                "ProcessId": 5678,
                "ImageFileName": "echo_client.exe",
                "CommandLine": "echo_client.exe --server 10.0.0.1",
                "TimeStamp": 1_700_000_001,
            },
        ]
    )

    return TraceData(
        trace_id="trace_fake0000001",
        etl_path=etl_path,
        export_dir=export_dir,
        raw_csv={
            "sysconfig": sysconfig,
            "trace_metadata": trace_metadata,
            "Image/Load": image_load,
            "process": processes,
        },
    )


@pytest.fixture
def evidence_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Set WPR_MCP_EVIDENCE_PATH for the duration of the test."""
    root = tmp_path / "evidence"
    monkeypatch.setenv(evidence_integration.ENV_VAR, str(root))
    return root


# ---------------------------------------------------------------------------
# G3 gate behaviour
# ---------------------------------------------------------------------------

def test_module_imports_without_evidence_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The integration module must import successfully even when the
    optional library is not installed. We simulate by flipping the
    module-level flag — the try/except in evidence_integration.py is
    what gives us the import-time safety net."""
    monkeypatch.setattr(evidence_integration, "_EVIDENCE_AVAILABLE", False)
    assert evidence_integration.is_available() is False
    # Reload-safe: the public helpers must short-circuit cleanly.
    trace = _make_trace(tmp_path)
    assert evidence_integration.register_entities_from_trace(trace) is None
    assert evidence_integration.safe_register_entities_from_trace(trace) is None


def test_register_returns_none_when_env_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(evidence_integration.ENV_VAR, raising=False)
    trace = _make_trace(tmp_path)
    # Library is genuinely installed in this test environment
    # (uv sync --extra evidence). The gate that fires is the env var.
    assert evidence_integration.is_configured() is False
    assert evidence_integration.register_entities_from_trace(trace) is None


def test_register_writes_machine_when_both_gates_on(
    tmp_path: Path, evidence_root: Path
) -> None:
    pytest.importorskip("evidence_store")
    trace = _make_trace(tmp_path, hostname="ProjectBox-A")
    machine_id = evidence_integration.register_entities_from_trace(trace)
    assert machine_id is not None
    assert machine_id.startswith("machine_")
    db_path = evidence_root / machine_id / "evidence.duckdb"
    assert db_path.exists()


def test_reregistration_is_idempotent(
    tmp_path: Path, evidence_root: Path
) -> None:
    """Two calls on the same TraceData must produce the same machine_id
    and not duplicate Module rows — this is the federation contract."""
    pytest.importorskip("evidence_store")
    from evidence_store import EvidenceStore

    trace = _make_trace(tmp_path)
    mid1 = evidence_integration.register_entities_from_trace(trace)
    mid2 = evidence_integration.register_entities_from_trace(trace)
    assert mid1 == mid2

    store = EvidenceStore.open(evidence_root / mid1 / "evidence.duckdb")
    try:
        modules = store.query(
            "SELECT name FROM Module WHERE machine_id = ?", [mid1]
        ).to_pandas()
        # Two distinct modules even though Image/Load has 3 rows (one
        # duplicate). De-dup happens in _iter_modules + ON CONFLICT.
        assert sorted(modules["name"].tolist()) == ["ntoskrnl.exe", "tcpip.sys"]
        machines = store.query(
            "SELECT entity_id FROM Machine WHERE entity_id = ?", [mid1]
        ).to_pandas()
        assert len(machines) == 1
    finally:
        store.close()


def test_processes_registered_with_correct_count(
    tmp_path: Path, evidence_root: Path
) -> None:
    pytest.importorskip("evidence_store")
    from evidence_store import EvidenceStore

    trace = _make_trace(tmp_path)
    mid = evidence_integration.register_entities_from_trace(trace)
    assert mid is not None

    store = EvidenceStore.open(evidence_root / mid / "evidence.duckdb")
    try:
        procs = store.query(
            "SELECT pid, image_name FROM Process WHERE machine_id = ? "
            "ORDER BY pid",
            [mid],
        ).to_pandas()
        assert procs["pid"].tolist() == [1234, 5678]
        assert procs["image_name"].tolist() == ["echo_server.exe", "echo_client.exe"]
    finally:
        store.close()


def test_safe_register_swallows_exception(
    tmp_path: Path, evidence_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """safe_register_entities_from_trace must never raise."""
    def _boom(*_a: Any, **_kw: Any) -> None:
        raise RuntimeError("synthetic")

    monkeypatch.setattr(
        evidence_integration, "register_entities_from_trace", _boom
    )
    trace = _make_trace(tmp_path)
    assert evidence_integration.safe_register_entities_from_trace(trace) is None


# ---------------------------------------------------------------------------
# MCP tool surface
# ---------------------------------------------------------------------------

def test_get_evidence_status_reports_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from etw_analyzer.tools import evidence as evidence_tool

    monkeypatch.delenv(evidence_integration.ENV_VAR, raising=False)
    out = evidence_tool.get_evidence_status()
    assert "Library installed" in out
    assert "WPR_MCP_EVIDENCE_PATH" in out


def test_get_entities_returns_markdown_table(
    tmp_path: Path, evidence_root: Path
) -> None:
    pytest.importorskip("evidence_store")
    from etw_analyzer.tools import evidence as evidence_tool
    from etw_analyzer.trace_state import (
        clear_traces,
        register_trace,
    )

    trace = _make_trace(tmp_path, hostname="entities-host")
    try:
        register_trace(trace)
        out = evidence_tool.get_entities(trace.trace_id, "module")
        # First call also triggers registration via the tool itself.
        assert "ntoskrnl.exe" in out
        assert "tcpip.sys" in out
        # Filter narrows the result.
        out_filtered = evidence_tool.get_entities(
            trace.trace_id, "module", filter="ntos"
        )
        assert "ntoskrnl.exe" in out_filtered
        assert "tcpip.sys" not in out_filtered
        # Machine and process tables also wire up.
        out_machine = evidence_tool.get_entities(trace.trace_id, "machine")
        assert "entities-host" in out_machine
        out_proc = evidence_tool.get_entities(trace.trace_id, "process")
        assert "echo_server.exe" in out_proc
    finally:
        clear_traces()


def test_get_entities_rejects_unknown_type(
    tmp_path: Path, evidence_root: Path
) -> None:
    pytest.importorskip("evidence_store")
    from etw_analyzer.tools import evidence as evidence_tool
    from etw_analyzer.trace_state import clear_traces, register_trace

    trace = _make_trace(tmp_path)
    try:
        register_trace(trace)
        out = evidence_tool.get_entities(trace.trace_id, "galaxy")
        assert "Unknown entity_type" in out
    finally:
        clear_traces()


def test_get_entities_friendly_when_env_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(evidence_integration.ENV_VAR, raising=False)
    from etw_analyzer.tools import evidence as evidence_tool
    from etw_analyzer.trace_state import clear_traces, register_trace

    trace = _make_trace(tmp_path)
    try:
        register_trace(trace)
        out = evidence_tool.get_entities(trace.trace_id, "module")
        assert "WPR_MCP_EVIDENCE_PATH" in out
    finally:
        clear_traces()
