"""Tests for stack butterfly analysis tools."""

from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer.trace_state import TraceData, clear_traces, register_trace
from etw_analyzer.tools.stack_analysis import (
    butterfly_chain,
    count_stacks,
    get_function_callers,
    get_hot_stacks,
    walk_stack,
)


@pytest.fixture(autouse=True)
def clean_trace_registry():
    clear_traces()
    yield
    clear_traces()


def _register_stack_trace() -> None:
    stacks = pd.DataFrame({
        "Module": ["ntoskrnl.exe", "tcpip.sys", "afd.sys", "ntoskrnl.exe"],
        "Function": [
            "KeAcquireInStackQueuedSpinLock",
            "IppResolveNeighbor",
            "AfdFastDatagramReceive",
            "KiDpcInterrupt",
        ],
        "Inclusive": [1000, 700, 300, 630],
        "Exclusive": [10, 50, 30, 5],
        "Total %": [10.0, 7.0, 3.0, 6.3],
    })
    callers = pd.DataFrame({
        "Target_Module": [
            "ntoskrnl.exe",
            "ntoskrnl.exe",
            "ntoskrnl.exe",
            "tcpip.sys",
            "tcpip.sys",
        ],
        "Target_Function": [
            "KeAcquireInStackQueuedSpinLock",
            "KeAcquireInStackQueuedSpinLock",
            "KeAcquireInStackQueuedSpinLock",
            "IppResolveNeighbor",
            "IppResolveNeighbor",
        ],
        "Direction": ["self", "caller", "caller", "caller", "caller"],
        "Caller_Module": [
            "ntoskrnl.exe",
            "tcpip.sys",
            "afd.sys",
            "ntoskrnl.exe",
            "tcpip.sys",
        ],
        "Caller_Function": [
            "KeAcquireInStackQueuedSpinLock",
            "IppResolveNeighbor",
            "AfdFastDatagramReceive",
            "KiDpcInterrupt",
            "UdpSendMessages",
        ],
        "Weight": [1000, 700, 300, 630, 70],
        "Total %": [10.0, 7.0, 3.0, 6.3, 0.7],
        "Parent %": [100.0, 70.0, 30.0, 90.0, 10.0],
        "Exclusive": [10, 50, 30, 5, 1],
    })
    cpu_sampling = pd.DataFrame({
        "Process Name": ["server.exe", "server.exe"],
        "Weight": [700, 300],
        "Module": ["tcpip.sys", "afd.sys"],
        "Function": ["IppResolveNeighbor", "AfdFastDatagramReceive"],
    })
    cpu_timeline = pd.DataFrame({
        "StartTime": [0],
        "EndTime": [1_000_000],
        "Cpu 0": [95.0],
        "Cpu 1": [90.0],
        "Cpu 2": [0.5],
        "Cpu 3": [0.2],
    })
    register_trace(TraceData(
        trace_id="trace_stack",
        etl_path=Path("C:\\traces\\stack.etl"),
        export_dir=Path("C:\\traces\\.etw-export-stack"),
        raw_csv={
            "stacks": stacks,
            "stacks_callers": callers,
            "cpu_sampling": cpu_sampling,
            "cpu_timeline": cpu_timeline,
        },
        duration_seconds=1.0,
        cpu_count=4,
    ))


def test_hot_stacks_uses_true_inclusive_exclusive_and_active_denominator():
    _register_stack_trace()

    output = get_hot_stacks(
        "trace_stack",
        function_filter="IppResolveNeighbor",
        denominator="active_cpus",
        min_weight_pct=0,
    )

    assert "Inclusive" in output
    assert "Exclusive" in output
    assert "700" in output
    assert "50" in output
    assert "% active_cpus" in output


def test_get_function_callers_reports_parent_and_trace_percentages():
    _register_stack_trace()

    output = get_function_callers("trace_stack", "KeAcquireInStackQueuedSpinLock")

    assert "IppResolveNeighbor" in output
    assert "AfdFastDatagramReceive" in output
    assert "% of Parent" in output
    assert "% trace" in output


def test_walk_stack_dominant_branch_recurses():
    _register_stack_trace()

    output = walk_stack("trace_stack", "KeAcquireInStackQueuedSpinLock")

    assert "KeAcquireInStackQueuedSpinLock" in output
    assert "IppResolveNeighbor" in output
    assert "KiDpcInterrupt" in output
    assert "AfdFastDatagramReceive" not in output


def test_walk_stack_threshold_branch_keeps_siblings():
    _register_stack_trace()

    output = walk_stack(
        "trace_stack",
        "KeAcquireInStackQueuedSpinLock",
        branch_policy="threshold",
        branch_threshold_pct=20.0,
    )

    assert "IppResolveNeighbor" in output
    assert "AfdFastDatagramReceive" in output


def test_count_stacks_estimates_ordered_chain():
    _register_stack_trace()

    output = count_stacks(
        "trace_stack",
        contains=[
            ("ntoskrnl.exe", "KeAcquireInStackQueuedSpinLock"),
            ("tcpip.sys", "IppResolveNeighbor"),
        ],
    )

    assert "Matching Samples" in output
    assert "700" in output
    assert "aggregate-butterfly-estimate" in output


def test_butterfly_chain_table_and_csv():
    _register_stack_trace()

    table_output = butterfly_chain(
        "trace_stack",
        "KeAcquireInStackQueuedSpinLock",
        denominator="active_cpus",
    )
    csv_output = butterfly_chain(
        "trace_stack",
        "KeAcquireInStackQueuedSpinLock",
        output_format="csv",
    )

    assert "Denominator (active_cpus)" in table_output
    assert "IppResolveNeighbor" in table_output
    assert csv_output.startswith("Depth,Frame,Frame Hits")
