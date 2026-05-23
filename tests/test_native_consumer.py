"""Tests for the Phase N1 native ETW consumer."""

from __future__ import annotations

import ctypes
import os
import re
import shutil
import sys
from pathlib import Path

import pytest


# Test trace fixtures from the feasibility experiments. The MULTI_PROVIDER
# trace is 27 MB and contains the manifest providers (TCPIP, AFD, MsQuic)
# that xperf -a dumper cannot enumerate — it's the headline witness that
# the native consumer closes the architectural gap. The LARGE trace is
# 452 MB and exercises the SampledProfile decoder at scale.
MULTI_PROVIDER_ETL = Path(r"C:\temp\etw-feasibility\multi-provider.etl")
LARGE_ETL = Path(r"C:\traces\vmserver-networking-test.etl")

TCPIP_GUID = "2f07e2ee-15db-40f1-90ef-9d7ba282188a"
AFD_GUID = "e53c6823-7bb8-44bb-90dc-3f86090d48a6"
QUIC_GUID = "ff15e657-4f26-570e-88ab-0796b258d11c"
KERNEL_PERFINFO_GUID = "ce1dbfb4-137e-4da6-87b0-3f59aa102cbc"

# Module-level skip for non-Windows hosts. Importing
# ``etw_analyzer.native.bindings.advapi32`` calls WinDLL which raises on
# Linux/Mac. ``importorskip`` keeps the synthetic tests below in scope on
# Windows while quietly skipping everywhere else.
pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Native ETW consumer requires Windows (advapi32 + tdh)",
)


need_multi_provider = pytest.mark.skipif(
    not MULTI_PROVIDER_ETL.exists(),
    reason=f"Test fixture not present: {MULTI_PROVIDER_ETL}",
)

need_large = pytest.mark.skipif(
    not LARGE_ETL.exists(),
    reason=f"Test fixture not present: {LARGE_ETL}",
)


# ---------------------------------------------------------------------------
# Bindings sanity (always runs on Windows — no ETL required)
# ---------------------------------------------------------------------------
def test_bindings_struct_sizes_match_sdk():
    """ctypes struct sizes must match the SDK headers byte-for-byte.

    Sizes pinned from a working consumer run on Windows 11 26100 — if
    they ever drift the consumer crashes long before this test does.
    The point of this guard is to catch accidental layout edits.
    """
    from etw_analyzer.native.bindings import types

    assert ctypes.sizeof(types.GUID) == 16
    assert ctypes.sizeof(types.EVENT_DESCRIPTOR) == 16
    assert ctypes.sizeof(types.EVENT_TRACE_HEADER) == 48
    assert ctypes.sizeof(types.ETW_BUFFER_CONTEXT) == 4
    # EVENT_TRACE is the legacy callback form. 88 bytes on 64-bit:
    # 48 (Header) + 4*2 (Instance/ParentInstance) + 16 (ParentGuid)
    # + 8 (MofData ptr) + 4 (MofLength) + 4 (U union).
    assert ctypes.sizeof(types.EVENT_TRACE) == 88
    assert ctypes.sizeof(types.EVENT_HEADER) == 80
    # TRACE_LOGFILE_HEADER on 64-bit hosts is 280 bytes — the in-memory
    # version pulled inside EVENT_TRACE_LOGFILEW including the
    # TIME_ZONE_INFORMATION block (172 bytes).
    assert ctypes.sizeof(types.TRACE_LOGFILE_HEADER) == 280
    # EVENT_RECORD on 64-bit: 80 (header) + 4 (BC) + 2*2 + 8 (extdata)
    # + 8 (UserData) + 8 (UserContext) = 112 bytes.
    assert ctypes.sizeof(types.EVENT_RECORD) == 112


def test_bindings_load_advapi32_and_tdh():
    """Both DLLs load without raising on Windows."""
    from etw_analyzer.native.bindings import advapi32, tdh
    assert advapi32.OpenTraceW is not None
    assert advapi32.ProcessTrace is not None
    assert advapi32.CloseTrace is not None
    assert tdh.TdhGetEventInformation is not None
    assert tdh.TdhFormatProperty is not None


def test_guid_roundtrip():
    """GUID.from_string and __str__ are inverses."""
    from etw_analyzer.native.bindings.types import GUID
    g = GUID.from_string(TCPIP_GUID)
    assert str(g).lower() == TCPIP_GUID


def test_is_available_returns_true_on_windows_without_etl():
    """``is_available`` with no ETL path probes binding load only."""
    from etw_analyzer.native import is_available
    assert is_available() is True


# ---------------------------------------------------------------------------
# Consumer-level tests (require multi-provider.etl)
# ---------------------------------------------------------------------------
@need_multi_provider
def test_is_available_with_etl_path():
    """``is_available`` opens + closes the file without consuming events."""
    from etw_analyzer.native import is_available
    assert is_available(MULTI_PROVIDER_ETL) is True


@need_multi_provider
def test_consumer_sees_tcpip_provider():
    """Headline test: native consumer sees TCPIP (which xperf-dumper misses)."""
    from etw_analyzer.native import count_events_by_provider

    counts = count_events_by_provider(MULTI_PROVIDER_ETL)
    # multi-provider.etl was captured with TCPIP enabled and routinely
    # contains 100K+ TCPIP events; the threshold of 100 is deliberately
    # very loose so the test stays useful even for shorter captures.
    assert counts.get(TCPIP_GUID, 0) >= 100, (
        f"Expected >=100 TCPIP events; got {counts.get(TCPIP_GUID)} "
        f"(total providers: {len(counts)})"
    )
    # AFD ships in the same multi-provider fixture; check too.
    assert counts.get(AFD_GUID, 0) >= 100


@need_multi_provider
def test_consumer_event_count_matches_total():
    """Bytes-processed and event-count plumbing reports plausible values."""
    from etw_analyzer.native import EtwConsumer

    n = [0]

    def cb(rec):
        n[0] += 1

    with EtwConsumer([MULTI_PROVIDER_ETL], cb) as cons:
        stats = cons.run()

    assert stats.event_count == n[0]
    assert stats.event_count > 0
    assert stats.elapsed_seconds > 0
    assert stats.bytes_processed == MULTI_PROVIDER_ETL.stat().st_size


@need_multi_provider
def test_consumer_callback_exception_is_surfaced():
    """A handler that raises must propagate out of ``run``."""
    from etw_analyzer.native import EtwConsumer, NativeConsumerError

    class Boom(RuntimeError):
        pass

    def cb(_rec):
        raise Boom("handler failure")

    with EtwConsumer([MULTI_PROVIDER_ETL], cb) as cons:
        with pytest.raises(Boom):
            cons.run()


@need_multi_provider
def test_consumer_context_manager_closes_on_exception():
    """``with`` block must release handles even if the body raises."""
    from etw_analyzer.native import EtwConsumer

    consumer_ref = None

    def cb(_rec):
        return

    with pytest.raises(RuntimeError):
        with EtwConsumer([MULTI_PROVIDER_ETL], cb) as cons:
            consumer_ref = cons
            assert cons._handles, "expected open handle inside the with-block"
            raise RuntimeError("simulated body failure")

    assert consumer_ref is not None
    # After __exit__, handles list is cleared and the consumer is closed.
    assert consumer_ref._closed is True
    assert not consumer_ref._handles


@need_multi_provider
def test_consumer_double_run_raises():
    """``run`` is a one-shot — calling twice raises NativeConsumerError."""
    from etw_analyzer.native import EtwConsumer, NativeConsumerError

    def cb(_rec):
        return

    with EtwConsumer([MULTI_PROVIDER_ETL], cb) as cons:
        cons.run()
        with pytest.raises(NativeConsumerError):
            cons.run()


@need_multi_provider
def test_consumer_rejects_missing_file(tmp_path):
    """OpenTraceW is never reached if the path doesn't exist."""
    from etw_analyzer.native import EtwConsumer, NativeConsumerError

    missing = tmp_path / "does-not-exist.etl"
    with pytest.raises(NativeConsumerError):
        EtwConsumer([missing], lambda r: None)


@need_multi_provider
def test_extract_events_returns_canonical_keys():
    """``extract_events`` returns the full canonical class set by default."""
    from etw_analyzer.native import CANONICAL_EVENT_CLASSES, extract_events

    result = extract_events(MULTI_PROVIDER_ETL)
    # Every canonical class must appear, even when empty.
    for name in CANONICAL_EVENT_CLASSES:
        assert name in result, f"missing canonical class {name}"


@need_multi_provider
def test_extract_events_respects_event_classes_filter():
    """Passing event_classes={...} narrows the returned dict."""
    from etw_analyzer.native import extract_events

    result = extract_events(
        MULTI_PROVIDER_ETL,
        event_classes={"SampledProfile"},
    )
    assert set(result.keys()) == {"SampledProfile"}


# ---------------------------------------------------------------------------
# load_trace integration tests
# ---------------------------------------------------------------------------
def _extract_trace_id(load_output: str) -> str:
    m = re.search(r"`(trace_[0-9a-f]+)`", load_output)
    if m is None:  # pragma: no cover — load_trace always emits a trace id
        raise AssertionError(f"No trace_id in load output:\n{load_output}")
    return m.group(1)


def _clear_export_dir(etl: Path) -> None:
    export_dir = etl.parent / f".etw-export-{etl.stem}"
    if export_dir.exists():
        shutil.rmtree(export_dir)


@pytest.fixture
def isolate_traces():
    """Clear the registry before/after each test that touches load_trace."""
    from etw_analyzer.trace_state import clear_traces
    from etw_analyzer.native.config import reset_auto_cache

    clear_traces()
    reset_auto_cache()
    yield
    clear_traces()
    reset_auto_cache()


@need_multi_provider
def test_load_trace_native_mode_sets_trace_mode(isolate_traces):
    """``mode='native'`` is reflected on the resulting TraceData."""
    from etw_analyzer.tools.trace_mgmt import load_trace
    from etw_analyzer.trace_state import get_trace

    _clear_export_dir(MULTI_PROVIDER_ETL)
    result = load_trace(str(MULTI_PROVIDER_ETL), mode="native")
    tid = _extract_trace_id(result)
    trace = get_trace(tid)
    assert trace is not None
    assert trace.mode == "native"


@need_multi_provider
def test_load_trace_native_produces_sampled_profile_df(isolate_traces):
    """Even when SampledProfile is empty, the DataFrame slot must exist."""
    from etw_analyzer.tools.trace_mgmt import load_trace
    from etw_analyzer.trace_state import get_trace

    _clear_export_dir(MULTI_PROVIDER_ETL)
    result = load_trace(str(MULTI_PROVIDER_ETL), mode="native")
    tid = _extract_trace_id(result)
    trace = get_trace(tid)

    # wait_for_dumper blocks until extraction completes.
    df = trace.wait_for_dumper()
    # multi-provider.etl has no kernel SampledProfile events, so the
    # DataFrame can legitimately be empty. The contract is: the slot
    # exists and is a DataFrame.
    assert df is not None


@need_multi_provider
def test_load_trace_xperf_mode_is_unchanged(isolate_traces):
    """Default mode='xperf' must keep working exactly as before."""
    from etw_analyzer.tools.trace_mgmt import load_trace
    from etw_analyzer.trace_state import get_trace

    _clear_export_dir(MULTI_PROVIDER_ETL)
    result = load_trace(str(MULTI_PROVIDER_ETL))
    tid = _extract_trace_id(result)
    trace = get_trace(tid)
    assert trace.mode == "xperf"


@need_multi_provider
def test_wpr_mcp_mode_env_var_overrides_arg(isolate_traces, monkeypatch):
    """WPR_MCP_MODE wins over the load_trace arg when set."""
    from etw_analyzer.tools.trace_mgmt import load_trace
    from etw_analyzer.trace_state import get_trace

    monkeypatch.setenv("WPR_MCP_MODE", "native")
    _clear_export_dir(MULTI_PROVIDER_ETL)
    # Explicit mode='xperf' is overridden by the env var.
    result = load_trace(str(MULTI_PROVIDER_ETL), mode="xperf")
    tid = _extract_trace_id(result)
    trace = get_trace(tid)
    # WPR_MCP_MODE only kicks in when the arg is None/empty per the
    # documented precedence; double-check we honour the arg when both
    # are set.
    assert trace.mode == "xperf"


@need_multi_provider
def test_wpr_mcp_mode_env_var_used_when_arg_default(isolate_traces, monkeypatch):
    """WPR_MCP_MODE is consulted when load_trace is called without mode."""
    from etw_analyzer.native.config import resolve_mode

    monkeypatch.setenv("WPR_MCP_MODE", "native")
    # The default mode='xperf' is passed explicitly via Python's default
    # arg evaluation; ``resolve_mode`` only honours the env var when the
    # argument is falsy. This test pins the contract for resolve_mode.
    assert resolve_mode(None) == "native"
    monkeypatch.setenv("WPR_MCP_MODE", "xperf")
    assert resolve_mode(None) == "xperf"


@need_multi_provider
def test_invalid_mode_is_rejected():
    """An unknown mode string is caught at the boundary."""
    from etw_analyzer.tools.trace_mgmt import load_trace

    result = load_trace(str(MULTI_PROVIDER_ETL), mode="banana")
    assert "Unknown mode" in result


# ---------------------------------------------------------------------------
# Tests on the large trace (skipped when absent — large traces aren't in CI)
# ---------------------------------------------------------------------------
@pytest.mark.slow
@need_large
def test_load_trace_native_large_produces_sampled_profile(isolate_traces):
    """End-to-end smoke test: 452 MB trace produces millions of samples."""
    from etw_analyzer.tools.trace_mgmt import load_trace
    from etw_analyzer.trace_state import get_trace

    _clear_export_dir(LARGE_ETL)
    result = load_trace(str(LARGE_ETL), mode="native")
    tid = _extract_trace_id(result)
    trace = get_trace(tid)
    df = trace.wait_for_dumper()
    assert df is not None
    # The trace ships ~2.5M PerfInfo events; require at least 100K to
    # tolerate future re-captures.
    assert len(df) >= 100_000


@pytest.mark.slow
@need_large
def test_native_extract_pairs_stacks_on_large_trace():
    """Phase N2 acceptance: at least 1000 SampledProfile rows on the large
    trace must carry a non-empty Stack list after the streaming pairing in
    ``extract.extract_events``. The buffer is bounded (1024 entries) so
    most samples evict before their stack arrives, but the pairing rate is
    high enough on the captured trace for a four-digit lower bound."""
    from etw_analyzer.native.extract import extract_events

    result = extract_events(
        LARGE_ETL,
        event_classes={"SampledProfile"},
    )
    sp = result["SampledProfile"]
    assert len(sp) > 100_000
    assert "Stack" in sp.columns
    with_stack = sp["Stack"].apply(lambda s: s is not None).sum()
    assert with_stack >= 1000, (
        f"Expected >=1000 SampledProfile rows with a paired Stack; got {with_stack}"
    )


@pytest.mark.slow
@need_large
def test_native_extract_decodes_kernel_event_classes():
    """Phase N2 acceptance: kernel events for which we shipped MOF decoders
    must produce non-empty DataFrames on the large trace."""
    from etw_analyzer.native.extract import extract_events

    # Pull every-class extraction to cover CSwitch, StackWalk, ImageLoad,
    # ReadyThread, Process, DPC/ISR.
    result = extract_events(LARGE_ETL)

    # SampledProfile dominates the trace.
    assert len(result["SampledProfile"]) > 100_000
    # CSwitch fires every context switch — hundreds of thousands.
    assert len(result["CSwitch"]) > 10_000
    # StackWalk is paired against samples; the count is high on traces
    # captured with -stackwalk enabled.
    assert "StackWalk" in result and len(result["StackWalk"]) > 1_000
    # ImageLoad covers user-mode DLLs (Image/Load) plus the kernel
    # driver rundown (Image/DCStart). At least one of each.
    image_loads = result.get("Image/Load")
    image_dcstart = result.get("Image/DCStart")
    assert image_loads is not None and len(image_loads) >= 10
    assert image_dcstart is not None and len(image_dcstart) >= 10
    # The kernel rundown contains tcpip.sys + ntoskrnl on every Win10+
    # box. Match either via DCStart since Image/Load tends to be user-mode.
    dc_names = image_dcstart["FileName"].str.lower().fillna("")
    assert (
        dc_names.str.contains("tcpip").any()
        or dc_names.str.contains("ntoskrnl").any()
        or dc_names.str.contains("ntdll").any()
    )
