"""Tests for the networking-lens tool wrappers."""

from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer.networking import (
    NETWORK_KERNEL_MODULES,
    NETWORK_MODULES_ALL,
    NETWORK_USER_MODULES,
    module_regex,
    modules_csv,
    resolve_module_set,
)
from etw_analyzer.tools.network_lenses import (
    get_network_dpcs,
    get_network_hot_functions,
    get_network_hot_stacks,
    get_network_lock_contention,
)
from etw_analyzer.trace_state import TraceData, clear_traces, register_trace


@pytest.fixture(autouse=True)
def clean_trace_registry():
    clear_traces()
    yield
    clear_traces()


# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------


class TestModuleSets:
    def test_kernel_modules_not_empty_and_contain_expected(self):
        assert NETWORK_KERNEL_MODULES
        assert "tcpip.sys" in NETWORK_KERNEL_MODULES
        # Casing matches the xperf DPC output (tests/test_parsers.py uses NDIS.SYS).
        assert "NDIS.SYS" in NETWORK_KERNEL_MODULES
        assert "xdp.sys" in NETWORK_KERNEL_MODULES

    def test_user_modules_not_empty_and_contain_expected(self):
        assert NETWORK_USER_MODULES
        assert "ws2_32.dll" in NETWORK_USER_MODULES
        assert "msquic.dll" in NETWORK_USER_MODULES

    def test_modules_all_is_union(self):
        assert NETWORK_MODULES_ALL == NETWORK_KERNEL_MODULES | NETWORK_USER_MODULES

    def test_resolve_module_set_default(self):
        assert resolve_module_set() == NETWORK_MODULES_ALL

    def test_resolve_module_set_extra_modules_unions(self):
        result = resolve_module_set(extra_modules=["custom.sys"])
        assert "custom.sys" in result
        assert "tcpip.sys" in result
        assert result == NETWORK_MODULES_ALL | {"custom.sys"}

    def test_resolve_module_set_replace_modules_overrides(self):
        result = resolve_module_set(replace_modules=["custom.sys"])
        assert result == frozenset({"custom.sys"})
        assert "tcpip.sys" not in result

    def test_module_regex_escapes_dots(self):
        # Backslash-escaped dot in pandas regex prevents tcpip.sys from
        # matching tcpip-sys or tcpipxsys.
        pattern = module_regex({"tcpip.sys"})
        assert r"tcpip\.sys" in pattern

    def test_module_regex_empty_set(self):
        # Empty set should produce a pattern that matches nothing.
        pattern = module_regex(frozenset())
        s = pd.Series(["anything", "tcpip.sys"])
        assert not s.str.contains(pattern, regex=True, na=False).any()

    def test_modules_csv_sorted(self):
        result = modules_csv({"b.sys", "a.sys"})
        assert result == "a.sys,b.sys"


# ---------------------------------------------------------------------------
# Synthetic-trace helpers
# ---------------------------------------------------------------------------


def _register_full_trace(trace_id: str = "trace_net") -> None:
    """Register a synthetic trace covering every data source the wrappers touch.

    Modules deliberately mix networking (tcpip.sys, ndis.sys, NDIS.SYS, afd.sys,
    ws2_32.dll) with non-networking (kernel32.dll, dwm.exe, custom.sys) so we
    can assert filtering behavior.
    """
    cpu_sampling = pd.DataFrame({
        "Process Name": [
            "server.exe", "server.exe", "server.exe", "server.exe",
            "server.exe", "server.exe",
        ],
        "PID": [100, 100, 100, 100, 100, 100],
        "Weight": [500, 300, 200, 100, 250, 150],
        "% Weight": [25.0, 15.0, 10.0, 5.0, 12.5, 7.5],
        "Module": [
            "tcpip.sys", "ndis.sys", "afd.sys", "kernel32.dll",
            "ws2_32.dll", "custom.sys",
        ],
        "Function": [
            "TcpipDeliver", "NdisIndicateReceive", "AfdReceive",
            "DoNothing", "WSARecv", "CustomFn",
        ],
    })

    dpc_isr = pd.DataFrame({
        "Module": [
            "(all)", "NDIS.SYS", "tcpip.sys", "kernel32.dll", "custom.sys",
        ],
        "Bucket_Low_us": [0, 0, 0, 0, 0],
        "Bucket_High_us": [4, 4, 4, 4, 4],
        "Count": [1000, 500, 300, 100, 250],
        "Pct": [100.0, 50.0, 30.0, 10.0, 25.0],
    })

    # ReadyThread cswitch data: stacks contain module!function for the readying frame.
    readythread = pd.DataFrame({
        "CPU": [0, 1, 2, 3],
        "TimeStamp": [1.0, 2.0, 3.0, 4.0],
        "Ready Thread Stack": [
            "ntoskrnl.exe!KeAcquireInStackQueuedSpinLock / tcpip.sys!IppDeliverListToProtocol",
            "ntoskrnl.exe!KeAcquireInStackQueuedSpinLock / afd.sys!AfdReceiveCompletion",
            "ntoskrnl.exe!KeAcquireInStackQueuedSpinLock / kernel32.dll!RandomThing",
            "ntoskrnl.exe!KeAcquireInStackQueuedSpinLock / custom.sys!CustomLockHolder",
        ],
        "Wait (us)": [10.0, 20.0, 15.0, 25.0],
        "New Process Name": ["server.exe", "server.exe", "dwm.exe", "server.exe"],
        "Readying Process Name": [
            "server.exe", "server.exe", "dwm.exe", "server.exe",
        ],
    })

    # Butterfly stacks: each row is a frame with inclusive/exclusive weight.
    stacks = pd.DataFrame({
        "Module": [
            "tcpip.sys", "ndis.sys", "afd.sys", "kernel32.dll",
            "ws2_32.dll", "custom.sys",
        ],
        "Function": [
            "TcpipDeliver", "NdisIndicateReceive", "AfdReceive",
            "DoNothing", "WSARecv", "CustomFn",
        ],
        "Inclusive": [5000, 3000, 2000, 1500, 2500, 2200],
        "Exclusive": [200, 150, 100, 80, 120, 140],
        "Total %": [10.0, 6.0, 4.0, 3.0, 5.0, 4.4],
    })

    cpu_timeline = pd.DataFrame({
        "StartTime": [0],
        "EndTime": [1_000_000],
        "Cpu 0": [80.0],
        "Cpu 1": [70.0],
        "Cpu 2": [60.0],
        "Cpu 3": [40.0],
    })

    register_trace(TraceData(
        trace_id=trace_id,
        etl_path=Path(f"C:\\traces\\{trace_id}.etl"),
        export_dir=Path(f"C:\\traces\\.etw-export-{trace_id}"),
        raw_csv={
            "cpu_sampling": cpu_sampling,
            "dpc_isr": dpc_isr,
            "readythread": readythread,
            "stacks": stacks,
            "cpu_timeline": cpu_timeline,
        },
        duration_seconds=1.0,
        cpu_count=4,
    ))


def _register_empty_trace(trace_id: str = "trace_empty") -> None:
    """Register a trace whose data sources are present but empty."""
    register_trace(TraceData(
        trace_id=trace_id,
        etl_path=Path(f"C:\\traces\\{trace_id}.etl"),
        export_dir=Path(f"C:\\traces\\.etw-export-{trace_id}"),
        raw_csv={
            # Empty cpu_sampling DataFrame with the expected columns.
            "cpu_sampling": pd.DataFrame(columns=[
                "Process Name", "PID", "Weight", "% Weight", "Module", "Function",
            ]),
            "dpc_isr": pd.DataFrame(columns=[
                "Module", "Bucket_Low_us", "Bucket_High_us", "Count", "Pct",
            ]),
            "readythread": pd.DataFrame(columns=[
                "CPU", "TimeStamp", "Ready Thread Stack", "Wait (us)",
                "New Process Name", "Readying Process Name",
            ]),
            "stacks": pd.DataFrame(columns=[
                "Module", "Function", "Inclusive", "Exclusive", "Total %",
            ]),
        },
        duration_seconds=1.0,
        cpu_count=4,
    ))


# ---------------------------------------------------------------------------
# get_network_hot_functions
# ---------------------------------------------------------------------------


class TestHotFunctions:
    def test_default_filters_to_network_only(self):
        _register_full_trace()
        output = get_network_hot_functions("trace_net")

        assert "Networking scope" in output
        # Networking modules should appear.
        assert "tcpip.sys" in output
        assert "ndis.sys" in output
        assert "ws2_32.dll" in output
        # Non-networking modules should be filtered out.
        assert "kernel32.dll" not in output
        assert "custom.sys" not in output

    def test_extra_modules_adds_to_filter(self):
        _register_full_trace()
        output = get_network_hot_functions(
            "trace_net", extra_modules=["custom.sys"],
        )

        assert "custom.sys" in output
        assert "tcpip.sys" in output
        assert "kernel32.dll" not in output

    def test_replace_modules_overrides_filter(self):
        _register_full_trace()
        output = get_network_hot_functions(
            "trace_net", replace_modules=["custom.sys"],
        )

        assert "custom.sys" in output
        # tcpip.sys should be excluded when only custom.sys is in the set —
        # but the header annotation also lists the modules, so check the
        # actual hot-functions output rows. The header lists exactly one
        # module, so tcpip.sys can only appear if it slipped into a row.
        # Easiest assertion: the annotation says "1 module(s)".
        assert "1 module(s)" in output
        # And no data row for tcpip.sys.
        # (The functions table lists Module!Function pairs; checking the
        # specific TcpipDeliver function name is the cleanest test.)
        assert "TcpipDeliver" not in output

    def test_empty_trace_returns_sensible_message(self):
        _register_empty_trace()
        output = get_network_hot_functions("trace_empty")

        # Should not crash, should still annotate the networking scope.
        assert "Networking scope" in output
        # The underlying tool emits a "*No ...*" markdown italic when empty.
        assert "No samples" in output or "No samples match" in output


# ---------------------------------------------------------------------------
# get_network_dpcs
# ---------------------------------------------------------------------------


class TestDpcs:
    def test_default_filters_to_network_only(self):
        _register_full_trace()
        output = get_network_dpcs("trace_net")

        assert "Networking scope" in output
        # Both casing variants of NDIS should make it through the
        # case-insensitive regex.
        assert "NDIS.SYS" in output
        assert "tcpip.sys" in output
        # Non-network modules should be excluded.
        assert "kernel32.dll" not in output
        assert "custom.sys" not in output

    def test_extra_modules_adds_to_filter(self):
        _register_full_trace()
        output = get_network_dpcs("trace_net", extra_modules=["custom.sys"])

        assert "custom.sys" in output
        assert "NDIS.SYS" in output

    def test_replace_modules_overrides_filter(self):
        _register_full_trace()
        output = get_network_dpcs("trace_net", replace_modules=["custom.sys"])

        assert "custom.sys" in output
        # The annotation also includes the module list, but if the replace
        # set is just custom.sys, then tcpip.sys / NDIS.SYS should not appear
        # in the DPC rows. Verify via the annotation length.
        assert "1 module(s)" in output
        # The DPC summary lists "tcpip.sys" as a row header text — if it
        # appears at all, something leaked. Use the bucket header that only
        # appears when tcpip.sys data is included.
        assert "**tcpip.sys**" not in output
        assert "**NDIS.SYS**" not in output

    def test_empty_trace_returns_sensible_message(self):
        _register_empty_trace()
        output = get_network_dpcs("trace_empty")

        assert "Networking scope" in output
        # Underlying tool says "*No DPC/ISR events ...*" when empty.
        assert "No DPC/ISR events" in output


# ---------------------------------------------------------------------------
# get_network_lock_contention
# ---------------------------------------------------------------------------


class TestLockContention:
    def test_default_filters_to_network_only(self):
        _register_full_trace()
        output = get_network_lock_contention("trace_net")

        assert "Networking scope" in output
        # Network-rooted readying stacks should appear in contention sites.
        assert "tcpip.sys" in output or "IppDeliverListToProtocol" in output
        assert "afd.sys" in output or "AfdReceiveCompletion" in output
        # Non-networking readying stacks should be filtered out.
        assert "RandomThing" not in output
        assert "CustomLockHolder" not in output

    def test_extra_modules_adds_to_filter(self):
        _register_full_trace()
        output = get_network_lock_contention(
            "trace_net", extra_modules=["custom.sys"],
        )

        # custom.sys-rooted stack should now appear.
        assert "CustomLockHolder" in output
        # Network stacks still present.
        assert "IppDeliverListToProtocol" in output or "tcpip.sys" in output

    def test_replace_modules_overrides_filter(self):
        _register_full_trace()
        output = get_network_lock_contention(
            "trace_net", replace_modules=["custom.sys"],
        )

        # Only custom.sys-rooted readying stack should match.
        assert "CustomLockHolder" in output
        # tcpip.sys / afd.sys readying stacks should be excluded from the
        # contention-site rows (note: the annotation only lists modules,
        # not stack frames, so checking the function names is the clean test).
        assert "IppDeliverListToProtocol" not in output
        assert "AfdReceiveCompletion" not in output

    def test_empty_trace_returns_sensible_message(self):
        _register_empty_trace()
        output = get_network_lock_contention("trace_empty")

        assert "Networking scope" in output
        # Underlying tool emits "*No context switch events ...*" or the
        # "Context Switch Summary" fallback when empty.
        assert (
            "No context switch events" in output
            or "Context Switch Summary" in output
            or "Total context switches: 0" in output
        )


# ---------------------------------------------------------------------------
# get_network_hot_stacks
# ---------------------------------------------------------------------------


class TestHotStacks:
    def test_default_filters_to_network_only(self):
        _register_full_trace()
        output = get_network_hot_stacks("trace_net", min_weight_pct=0)

        assert "Networking scope" in output
        # Networking module frames present.
        assert "tcpip.sys" in output
        assert "ws2_32.dll" in output
        # Non-network frames excluded.
        assert "kernel32.dll" not in output
        assert "DoNothing" not in output
        assert "CustomFn" not in output

    def test_extra_modules_adds_to_filter(self):
        _register_full_trace()
        output = get_network_hot_stacks(
            "trace_net", min_weight_pct=0, extra_modules=["custom.sys"],
        )

        assert "custom.sys" in output
        assert "CustomFn" in output
        assert "tcpip.sys" in output
        # kernel32.dll still excluded.
        assert "DoNothing" not in output

    def test_replace_modules_overrides_filter(self):
        _register_full_trace()
        output = get_network_hot_stacks(
            "trace_net", min_weight_pct=0, replace_modules=["custom.sys"],
        )

        # The header annotation lists exactly one module.
        assert "1 module(s)" in output
        # custom.sys frame present, networking frames excluded.
        assert "CustomFn" in output
        assert "TcpipDeliver" not in output
        assert "NdisIndicateReceive" not in output

    def test_empty_trace_returns_sensible_message(self):
        _register_empty_trace()
        output = get_network_hot_stacks("trace_empty")

        assert "Networking scope" in output
        # Underlying tool's empty path: either "No matching functions" or
        # "No matching samples" depending on which branch it took.
        assert "No matching" in output
