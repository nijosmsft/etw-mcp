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
