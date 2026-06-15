"""Tests for stack butterfly analysis tools."""

from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer.native.event_store import EventStoreTimebase, NativeEventStoreWriter
from etw_analyzer.trace_state import TraceData, clear_traces, register_trace
from etw_analyzer.tools.stack_analysis import (
    butterfly_chain,
    count_stacks,
    get_function_callers,
    get_hot_stacks,
    walk_stack,
)


class _FakeSymbolizer:
    def __init__(self, mapping):
        self._mapping = mapping

    def bulk_resolve(self, addrs):
        return {int(addr): self._mapping.get(int(addr), "") for addr in addrs}


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


def test_count_stacks_accepts_string_frames():
    """Regression: MCP clients can't send Python tuples — JSON arrays decode
    as lists, and bare module names like "afd.sys" come through as strings.
    The signature must accept both shapes so the LLM-friendly form works."""
    _register_stack_trace()

    # Bare-string form: "module" only (matches every function in that module).
    string_output = count_stacks(
        "trace_stack",
        contains=["KeAcquireInStackQueuedSpinLock"],
    )
    assert "Matching Samples" in string_output

    # "module!function" string form.
    bang_output = count_stacks(
        "trace_stack",
        contains=["ntoskrnl.exe!KeAcquireInStackQueuedSpinLock"],
    )
    assert "Matching Samples" in bang_output

    # JSON-list form: [module, function] (what an LLM sends instead of a tuple).
    list_output = count_stacks(
        "trace_stack",
        contains=[
            ["ntoskrnl.exe", "KeAcquireInStackQueuedSpinLock"],
            ["tcpip.sys", "IppResolveNeighbor"],
        ],
    )
    assert "Matching Samples" in list_output
    assert "700" in list_output

    # Mixed string + list (excludes also tolerant).
    mixed_output = count_stacks(
        "trace_stack",
        contains=["ntoskrnl.exe!KeAcquireInStackQueuedSpinLock"],
        excludes=[["tcpip.sys", "IppResolveNeighbor"]],
    )
    assert "Matching Samples" in mixed_output


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


def test_get_function_callers_uses_literal_function_filter():
    callers = pd.DataFrame({
        "Target_Module": ["driver.sys"],
        "Target_Function": ["*SpecialRoutine"],
        "Direction": ["caller"],
        "Caller_Module": ["caller.sys"],
        "Caller_Function": ["CallerRoutine"],
        "Weight": [42],
        "Total %": [4.2],
        "Parent %": [100.0],
        "Exclusive": [1],
    })
    register_trace(TraceData(
        trace_id="trace_literal",
        etl_path=Path("C:\\traces\\literal.etl"),
        export_dir=Path("C:\\traces\\.etw-export-literal"),
        raw_csv={"stacks_callers": callers},
        duration_seconds=1.0,
        cpu_count=1,
    ))

    output = get_function_callers("trace_literal", "*SpecialRoutine")

    assert "CallerRoutine" in output
    assert "driver.sys!*SpecialRoutine" in output


def _register_event_store_stack_trace(tmp_path: Path, *, with_stacks: bool = True) -> str:
    export_dir = tmp_path / ".etw-export-event-store-stack"
    writer = NativeEventStoreWriter(
        export_dir,
        run_id="stack-tools",
        timebase=EventStoreTimebase(qpc_origin=1_000, perf_freq=1_000_000),
        staging=False,
    )
    writer.append(
        "image",
        {
            "EventSequence": 1,
            "TimeStampQpc": 1_000,
            "CPU": 0,
            "ProcessId": 4,
            "ImageBase": 0x1000,
            "ImageSize": 0x1000,
            "FileName": r"C:\Windows\System32\drivers\driver.sys",
            "Type": "DCStart",
        },
    )
    writer.append(
        "image",
        {
            "EventSequence": 2,
            "TimeStampQpc": 1_000,
            "CPU": 0,
            "ProcessId": 4,
            "ImageBase": 0x3000,
            "ImageSize": 0x1000,
            "FileName": r"C:\Windows\System32\ntoskrnl.exe",
            "Type": "DCStart",
        },
    )
    stacks = [
        [0x1010, 0x1020, 0x3010],
        [0x1010, 0x1020],
        [0x1010, 0x1020],
    ]
    for index, stack in enumerate(stacks, start=3):
        writer.append(
            "sampled_profile",
            {
                "EventSequence": index,
                "TimeStampQpc": 1_000 + index,
                "CPU": index % 2,
                "ProcessId": 1234,
                "ThreadId": 5678,
                "PayloadThreadId": 5678,
                "InstructionPointer": 0x1010,
                "Weight": 1,
                "ProfileWeight": 1,
                "Stack": stack if with_stacks else None,
            },
        )
    store = writer.commit()
    trace_id = "trace_event_store_stack"
    trace = TraceData(
        trace_id=trace_id,
        etl_path=tmp_path / "stack.etl",
        export_dir=export_dir,
        mode="native",
        raw_csv={
            "cpu_sampling": pd.DataFrame({
                "Process Name": ["server.exe"],
                "PID": [1234],
                "Weight": [3],
                "% Weight": [100.0],
                "Module": ["driver.sys"],
                "Function": ["Leaf"],
            }),
            "cpu_timeline": pd.DataFrame({
                "StartTime": [0],
                "EndTime": [1_000_000],
                "Cpu 0": [10.0],
                "Cpu 1": [10.0],
            }),
        },
        duration_seconds=1.0,
        cpu_count=2,
        event_store=store,
    )
    trace.symbolizer = _FakeSymbolizer({
        0x1010: "driver.sys!Leaf+0x0",
        0x1020: "driver.sys!Caller+0x0",
        0x3010: "ntoskrnl.exe!Root+0x0",
    })
    register_trace(trace)
    return trace_id


def test_stack_tools_smoke_on_event_store_only_trace(tmp_path: Path):
    trace_id = _register_event_store_stack_trace(tmp_path)

    hot = get_hot_stacks(trace_id, function_filter="Leaf", min_weight_pct=0)
    callers = get_function_callers(trace_id, "Leaf")
    walk = walk_stack(trace_id, "Leaf", max_depth=3)
    chain = butterfly_chain(trace_id, "Leaf", denominator="trace")
    count = count_stacks(
        trace_id,
        contains=[("driver.sys", "Leaf"), ("driver.sys", "Caller")],
    )

    assert "Inclusive" in hot
    assert "Leaf" in hot
    assert "Caller" in callers
    assert "Root" in walk
    assert "Caller" in chain
    assert "Matching Samples" in count
    assert "3" in count


def test_summary_profile_without_stacks_reports_no_stack_data(tmp_path: Path):
    trace_id = _register_event_store_stack_trace(tmp_path, with_stacks=False)

    hot = get_hot_stacks(trace_id, min_weight_pct=0)
    callers = get_function_callers(trace_id, "Leaf")

    assert "exclusive weight only" in hot
    assert "No SampledProfile stack lists" in hot
    assert "No caller/callee data available" in callers
    assert "No SampledProfile stack lists" in callers
