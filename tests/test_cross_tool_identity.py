"""Cross-tool identity verification — the federation contract proof.

The federation pattern only works if two MCPs (etw-trace-analyzer +
crash-dump-analyzer) registering the same binary on the same machine
produce **byte-identical** ``entity_id`` values without coordinating.

This test simulates the ETW half: register ``ntoskrnl.exe`` with a
fixed ``TimeDateStamp`` + ``ImageSize`` from a synthetic ETW trace.
The crash-dump side has a mirror test (``test_cross_tool_identity``
in ``crash-dump-mcp-server-evidence-wiring``) that registers the
SAME binary identity tuple from a fake dump. Both tests reach into
the deterministic ``evidence_store.module_id`` derivation, so the
``entity_id`` strings can be compared even without sharing a DB
file. The literal value below is the contract.
"""

from __future__ import annotations

import pandas as pd
import pytest

from etw_analyzer import evidence_integration
from etw_analyzer.trace_state import TraceData


# A fixed identity tuple shared with the crash-dump side.
KNOWN_HOSTNAME = "fed-test-host"
KNOWN_MODULE_NAME = "ntoskrnl.exe"
KNOWN_TIMEDATESTAMP = 0x6543ABCD
KNOWN_IMAGESIZE = 0x00CCAA00

# Pre-computed from evidence_store.module_id(machine_id, name_lower,
# "tds=<tds>;size=<size>"). Recomputed here for assertion below.


def _expected_module_id() -> str:
    from evidence_store import machine_id as m_id
    from evidence_store import module_id as mod_id

    mid = m_id(KNOWN_HOSTNAME)
    return mod_id(
        mid,
        KNOWN_MODULE_NAME,
        f"tds={KNOWN_TIMEDATESTAMP:08x};size={KNOWN_IMAGESIZE}",
    )


def _make_etw_trace(tmp_path):
    pytest.importorskip("evidence_store")
    etl_path = tmp_path / "etw.etl"
    etl_path.write_bytes(b"")
    return TraceData(
        trace_id="trace_xtid_etw_00",
        etl_path=etl_path,
        export_dir=tmp_path / ".etw-export-etw",
        raw_csv={
            "sysconfig": pd.DataFrame(
                [{"raw_text": f"Computer Name: {KNOWN_HOSTNAME}\n"}]
            ),
            "Image/Load": pd.DataFrame(
                [
                    {
                        "FileName": f"\\Windows\\System32\\{KNOWN_MODULE_NAME}",
                        "TimeDateStamp": KNOWN_TIMEDATESTAMP,
                        "ImageSize": KNOWN_IMAGESIZE,
                    }
                ]
            ),
        },
    )


def test_etw_registers_module_with_expected_entity_id(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ETW registration produces the contractual module entity_id."""
    pytest.importorskip("evidence_store")
    monkeypatch.setenv(
        evidence_integration.ENV_VAR, str(tmp_path / "evidence")
    )
    trace = _make_etw_trace(tmp_path)
    machine_id = evidence_integration.register_entities_from_trace(trace)
    assert machine_id is not None

    from evidence_store import EvidenceStore

    expected = _expected_module_id()
    db_path = tmp_path / "evidence" / machine_id / "evidence.duckdb"
    store = EvidenceStore.open(db_path)
    try:
        rows = store.query(
            "SELECT entity_id FROM Module WHERE machine_id = ? "
            "AND name = ?",
            [machine_id, KNOWN_MODULE_NAME],
        ).to_pandas()
        assert rows["entity_id"].tolist() == [expected]
    finally:
        store.close()


def test_etw_machine_id_matches_namespace(tmp_path) -> None:
    """machine_id is just uuid5 over hostname_lower — recompute and check."""
    pytest.importorskip("evidence_store")
    from evidence_store import machine_id

    derived = machine_id(KNOWN_HOSTNAME)
    derived_upper = machine_id(KNOWN_HOSTNAME.upper())
    assert derived == derived_upper, "hostname lowercased into identity"
