"""Regression tests for dotnet/native datapath surfacing of stacks + cswitch.

The dotnet sidecar persists per-sample stack frames (``list<uint64>`` Stack
column) and CSwitch events to parquet, but the load defers symbolization and
those parquets are excluded from raw_csv. These tests pin the on-demand
fallbacks that surface them:

- ``get_hot_stacks`` / ``butterfly_chain`` rebuild the butterfly from
  ``sampled_profile.parquet`` reading the Stack column losslessly via pyarrow
  (pandas coerces the nullable uint64 list to float64 and corrupts addresses).
- ``get_lock_contention`` surfaces native ``cswitch_events.parquet`` and shows
  a WaitReason breakdown when no readying stacks are present.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

import etw_analyzer.tools.trace_mgmt as trace_mgmt
from etw_analyzer.trace_state import clear_traces


@pytest.fixture(autouse=True)
def _isolate():
    clear_traces()
    yield
    clear_traces()


_BASE = 0xFFFFF80012340000  # kernel module base; low bits matter for the float64 bug.


class _FakeSymbolizer:
    def __init__(self, symbol_path=None):
        self.symbol_path = symbol_path
        self._mods = [(_BASE, 0x10000, "tcpip.sys")]

    def add_module(self, base, size, file_name, **_):
        self._mods.append((int(base), int(size), str(file_name)))

    def _find_module_for_address(self, addr):
        for b, s, n in self._mods:
            if b <= int(addr) < b + s:
                return {"FileName": n}
        return None

    def bulk_resolve(self, addrs):
        out = {}
        for a in addrs:
            a = int(a)
            if _BASE <= a < _BASE + 0x10000:
                fn = "UdpSend" if (a - _BASE) < 0x8000 else "UdpRecv"
                out[a] = f"tcpip.sys!{fn}+0x10"
            else:
                out[a] = f"unknown+0x{a:x}"
        return out

    def bulk_resolve_with_source(self, addrs):
        return {a: (lab, "pdb" if "!" in lab else "unknown")
                for a, lab in self.bulk_resolve(addrs).items()}


def _write_sampled_profile_with_stacks(path: Path) -> None:
    # Two leaf frames each with a caller, exact uint64 addresses whose low bits
    # would be lost if read back through float64.
    send_leaf = _BASE + 0x0577     # tcpip.sys!UdpSend
    send_caller = _BASE + 0x0A33   # tcpip.sys!UdpSend (same range)
    recv_leaf = _BASE + 0x9123     # tcpip.sys!UdpRecv
    stacks = [[send_leaf, send_caller]] * 6 + [[recv_leaf, send_caller]] * 4
    arr = pa.array(stacks, type=pa.list_(pa.uint64()))
    table = pa.table({
        "InstructionPointer": pa.array([s[0] for s in stacks], type=pa.uint64()),
        "Weight": pa.array([1] * len(stacks), type=pa.int64()),
        "Stack": arr,
    })
    pq.write_table(table, path)


def _make_trace(tmp_path: Path, *, with_symbolizer: bool) -> trace_mgmt.TraceData:
    etl = tmp_path / "t.etl"
    etl.write_bytes(b"x")
    export_dir = tmp_path / ".export"
    export_dir.mkdir(parents=True, exist_ok=True)
    trace = trace_mgmt.TraceData(
        trace_id="trace_ds", etl_path=etl, export_dir=export_dir,
        symbol_path="srv*C:\\symbols*https://msdl.microsoft.com/download/symbols",
        mode="dotnet",
    )
    # Deferred-load placeholder stacks dataset (1 unknown row).
    trace.raw_csv["stacks"] = pd.DataFrame([{
        "Module": "unknown", "Function": "", "Inclusive": 10,
        "Exclusive": 10, "Weight": 10, "Total %": 100.0,
    }])
    if with_symbolizer:
        trace.symbolizer = _FakeSymbolizer()
    trace_mgmt.register_trace(trace)
    return trace


def test_pyarrow_preserves_stack_uint64_addresses(tmp_path: Path):
    # The on-demand stack builder reads the Stack column via pyarrow because
    # pandas can coerce the nullable uint64 list to float64 and corrupt the low
    # bits. Guard that pyarrow returns the exact uint64 frame address.
    p = tmp_path / "sp.parquet"
    _write_sampled_profile_with_stacks(p)
    arrow_first = pq.read_table(p, columns=["Stack"]).column("Stack").to_pylist()[0][0]
    assert arrow_first == _BASE + 0x0577  # exact, low bits intact


def test_get_hot_stacks_resolves_from_sampled_parquet(tmp_path: Path):
    from etw_analyzer.tools.stack_analysis import get_hot_stacks
    trace = _make_trace(tmp_path, with_symbolizer=True)
    _write_sampled_profile_with_stacks(trace.export_dir / "sampled_profile.parquet")
    out = get_hot_stacks("trace_ds", max_rows=10)
    assert "tcpip.sys" in out
    assert "UdpSend" in out or "UdpRecv" in out


def test_butterfly_chain_resolves_from_sampled_parquet(tmp_path: Path):
    from etw_analyzer.tools.stack_analysis import butterfly_chain
    trace = _make_trace(tmp_path, with_symbolizer=True)
    _write_sampled_profile_with_stacks(trace.export_dir / "sampled_profile.parquet")
    out = butterfly_chain("trace_ds", "UdpSend")
    assert "UdpSend" in out
    assert "No stack node found" not in out


def test_stacks_no_symbolizer_falls_through(tmp_path: Path):
    # Without a symbolizer the on-demand build must not crash; placeholder stays.
    from etw_analyzer.tools.stack_analysis import get_hot_stacks
    trace = _make_trace(tmp_path, with_symbolizer=False)
    _write_sampled_profile_with_stacks(trace.export_dir / "sampled_profile.parquet")
    out = get_hot_stacks("trace_ds", max_rows=10)
    assert isinstance(out, str)  # no exception


# --------------------------------------------------------------------------
# CSwitch / lock contention
# --------------------------------------------------------------------------


def _write_cswitch_events(path: Path) -> None:
    n = 100
    pd.DataFrame({
        "EventSequence": list(range(n)),
        "TimeStamp": list(range(n)),
        "CPU": [i % 4 for i in range(n)],
        "NewTID": [10] * n,
        "OldTID": [20] * n,
        "NewPID": [1] * n,
        "OldPID": [2] * n,
        "WaitReason": (["Executive"] * 60) + (["UserRequest"] * 40),
        "Stack": [None] * n,
    }).to_parquet(path, index=False)


def _make_cswitch_trace(tmp_path: Path) -> trace_mgmt.TraceData:
    etl = tmp_path / "t.etl"
    etl.write_bytes(b"x")
    export_dir = tmp_path / ".export"
    export_dir.mkdir(parents=True, exist_ok=True)
    trace = trace_mgmt.TraceData(
        trace_id="trace_cs", etl_path=etl, export_dir=export_dir,
        symbol_path=None, mode="dotnet",
    )
    # Empty readythread placeholder (sidecar wrote 0 rows) must be skipped.
    trace.raw_csv["readythread"] = pd.DataFrame(
        columns=["EventSequence", "CPU", "ThreadId", "Stack"]
    )
    trace_mgmt.register_trace(trace)
    return trace


def test_get_lock_contention_surfaces_native_cswitch_waitreason(tmp_path: Path):
    from etw_analyzer.tools.context_switch import get_lock_contention
    trace = _make_cswitch_trace(tmp_path)
    _write_cswitch_events(trace.export_dir / "cswitch_events.parquet")
    out = get_lock_contention("trace_cs")
    assert "Context Switch Summary" in out
    assert "Total context switches: 100" in out
    assert "Wait Reason" in out
    assert "Executive" in out


def test_load_native_cswitch_prefers_attribute(tmp_path: Path):
    from etw_analyzer.tools.context_switch import _load_native_cswitch_df
    trace = _make_cswitch_trace(tmp_path)
    df = pd.DataFrame({"CPU": [0], "WaitReason": ["Executive"]})
    trace.cswitch_events_df = df
    out = _load_native_cswitch_df(trace)
    assert out is not None and len(out) == 1


# --------------------------------------------------------------------------
# Issue #17 — parameterized native/dotnet CSwitch schema regression test.
#
# The native (xperf/wpaexporter) CSwitch schema carries OldProcessName /
# NewProcessName columns; the dotnet sidecar schema does not (issue #12).
# get_lock_contention must surface a per-process Context Switch Summary on
# BOTH schemas — directly for native, and by synthesizing process names from
# the PID->name map for dotnet.
# --------------------------------------------------------------------------


def _write_native_schema_cswitch(path: Path) -> None:
    """xperf/wpaexporter-style CSwitch: process-name columns already present."""
    n = 100
    pd.DataFrame({
        "EventSequence": list(range(n)),
        "TimeStamp": list(range(n)),
        "CPU": [i % 4 for i in range(n)],
        "NewTID": [10] * n,
        "OldTID": [20] * n,
        "NewPID": [1] * n,
        "OldPID": [2] * n,
        "NewProcessName": ["myapp.exe"] * n,
        "OldProcessName": ["System"] * n,
        "WaitReason": (["Executive"] * 60) + (["UserRequest"] * 40),
        "Stack": [None] * n,
    }).to_parquet(path, index=False)


def _add_process_table(trace: trace_mgmt.TraceData) -> None:
    """Provide a PID->name source so the dotnet schema can synthesize names."""
    trace.raw_csv["_native_process_events"] = pd.DataFrame({
        "ProcessId": [1, 2],
        "ImageFileName": ["myapp.exe", "System"],
    })


@pytest.mark.parametrize("schema", ["native", "dotnet"])
def test_get_lock_contention_cswitch_schema_parity(tmp_path: Path, schema: str):
    from etw_analyzer.tools.context_switch import get_lock_contention
    trace = _make_cswitch_trace(tmp_path)
    parquet = trace.export_dir / "cswitch_events.parquet"
    if schema == "native":
        _write_native_schema_cswitch(parquet)
    else:
        # dotnet schema: no process-name columns; synthesized from PID map.
        _write_cswitch_events(parquet)
        _add_process_table(trace)

    out = get_lock_contention("trace_cs")

    # Both schemas surface the same summary + WaitReason breakdown.
    assert "Context Switch Summary" in out
    assert "Total context switches: 100" in out
    assert "Executive" in out
    # Process-level grouping must work on both schemas (issue #12): the
    # process name is present natively and synthesized for dotnet.
    assert "Context Switches by Process" in out
    assert "myapp.exe" in out


def test_ensure_cswitch_process_names_synthesizes_for_dotnet(tmp_path: Path):
    from etw_analyzer.tools.context_switch import _ensure_cswitch_process_names
    trace = _make_cswitch_trace(tmp_path)
    _add_process_table(trace)
    df = pd.DataFrame({"NewPID": [1, 2], "OldPID": [2, 1], "CPU": [0, 1]})
    out = _ensure_cswitch_process_names(trace, df)
    assert "NewProcessName" in out.columns
    assert "OldProcessName" in out.columns
    assert list(out["NewProcessName"]) == ["myapp.exe", "System"]


# --------------------------------------------------------------------------
# Issue #11 — dotnet/native stacks must NOT collapse to a single "unknown"
# row when symbolization is deferred. Module-level attribution from the
# in-memory image rundown (raw_csv Image/* frames) keeps the butterfly table
# usable even without a symbolizer / PDBs.
# --------------------------------------------------------------------------


def _make_module_only_stack_trace(tmp_path: Path) -> trace_mgmt.TraceData:
    etl = tmp_path / "t.etl"
    etl.write_bytes(b"x")
    export_dir = tmp_path / ".export"
    export_dir.mkdir(parents=True, exist_ok=True)
    trace = trace_mgmt.TraceData(
        trace_id="trace_mo", etl_path=etl, export_dir=export_dir,
        symbol_path=None, mode="dotnet",
    )
    # Image rundown in raw_csv (no symbolizer available) — the only attribution
    # source. Two distinct modules so the butterfly has >1 row.
    other_base = _BASE + 0x20000
    trace.raw_csv["Image/Load"] = pd.DataFrame({
        "ImageBase": [_BASE, other_base],
        "ImageSize": [0x10000, 0x10000],
        "FileName": ["tcpip.sys", "afd.sys"],
    })
    # Per-sample stacks (in-memory dumper_df), addresses inside the two ranges.
    leaf_a = _BASE + 0x0577
    caller_a = _BASE + 0x0A33
    leaf_b = other_base + 0x0123
    trace.dumper_df = pd.DataFrame({
        "Stack": [[leaf_a, caller_a]] * 6 + [[leaf_b, caller_a]] * 4,
        "Weight": [1] * 10,
    })
    # Load defers PDB symbolization on real traces.
    trace._defer_symbolization = True
    trace_mgmt.register_trace(trace)
    return trace


def test_stacks_module_only_attribution_no_symbolizer(tmp_path: Path):
    from etw_analyzer.native.aggregators.stack_butterfly import aggregate_stack_butterfly
    trace = _make_module_only_stack_trace(tmp_path)
    stacks = aggregate_stack_butterfly(trace)
    assert stacks is not None and not stacks.empty
    # The bug collapsed every frame to a single ("unknown", "") row.
    assert len(stacks) > 1
    modules = set(stacks["Module"].astype(str))
    assert "tcpip.sys" in modules
    assert "afd.sys" in modules
    assert "unknown" not in modules


def test_get_hot_stacks_module_only_emits_resolve_hint(tmp_path: Path):
    from etw_analyzer.native.aggregators.stack_butterfly import aggregate_stack_butterfly
    from etw_analyzer.tools.stack_analysis import get_hot_stacks
    trace = _make_module_only_stack_trace(tmp_path)
    # Load-time _run_native_aggregators persists the butterfly into raw_csv;
    # simulate that so get_hot_stacks reads the module-only frame directly.
    trace.raw_csv["stacks"] = aggregate_stack_butterfly(trace)
    out = get_hot_stacks("trace_mo", max_rows=10, min_weight_pct=0.0)
    assert "tcpip.sys" in out
    assert "resolve_symbols" in out

