"""Tests for explicit trace_id routing."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer.trace_state import (
    TraceData,
    clear_traces,
    list_loaded_traces,
    register_trace,
    require_trace,
    unregister_trace,
)
from etw_analyzer.tools.cpu_sampling import get_cpu_samples
from etw_analyzer.tools.stack_analysis import get_function_callers
from etw_analyzer.tools.trace_mgmt import list_loaded_traces as list_loaded_traces_tool


@pytest.fixture(autouse=True)
def clean_trace_registry():
    clear_traces()
    yield
    clear_traces()


def _register_trace(trace_id: str, caller_name: str, weight: int) -> None:
    stacks_callers = pd.DataFrame({
        "Target_Module": ["ntoskrnl.exe"],
        "Target_Function": ["KeAcquireInStackQueuedSpinLock"],
        "Direction": ["caller"],
        "Caller_Module": ["tcpip.sys"],
        "Caller_Function": [caller_name],
        "Weight": [weight],
    })
    cpu_sampling = pd.DataFrame({
        "Process Name": ["test.exe"],
        "PID": [100],
        "Weight": [weight],
        "% Weight": [100.0],
        "Module": ["tcpip.sys"],
        "Function": [caller_name],
    })
    trace = TraceData(
        trace_id=trace_id,
        etl_path=Path(f"C:\\traces\\{trace_id}.etl"),
        export_dir=Path(f"C:\\traces\\.etw-export-{trace_id}"),
        raw_csv={
            "stacks_callers": stacks_callers,
            "cpu_sampling": cpu_sampling,
        },
    )
    register_trace(trace)


def test_require_trace_uses_explicit_id():
    _register_trace("trace_a", "NotifyHybridOnly", 11)
    _register_trace("trace_b", "IppResolveNeighbor", 71)

    assert require_trace("trace_a").raw_csv["cpu_sampling"].iloc[0]["Function"] == "NotifyHybridOnly"
    assert require_trace("trace_b").raw_csv["cpu_sampling"].iloc[0]["Function"] == "IppResolveNeighbor"


def test_unknown_trace_id_reports_loaded_ids():
    _register_trace("trace_a", "NotifyHybridOnly", 11)

    with pytest.raises(ValueError, match="trace_a"):
        require_trace("missing_trace")


def test_function_callers_do_not_cross_contaminate():
    _register_trace("trace_a", "NotifyHybridOnly", 11)
    _register_trace("trace_b", "IppResolveNeighbor", 71)

    a_result = get_function_callers("trace_a", "KeAcquireInStackQueuedSpinLock")
    b_result = get_function_callers("trace_b", "KeAcquireInStackQueuedSpinLock")

    assert "NotifyHybridOnly" in a_result
    assert "IppResolveNeighbor" not in a_result
    assert "IppResolveNeighbor" in b_result
    assert "NotifyHybridOnly" not in b_result


def test_cpu_samples_use_explicit_trace_id():
    _register_trace("trace_a", "NotifyHybridOnly", 11)
    _register_trace("trace_b", "IppResolveNeighbor", 71)

    a_result = get_cpu_samples("trace_a", group_by="function")
    b_result = get_cpu_samples("trace_b", group_by="function")

    assert "NotifyHybridOnly" in a_result
    assert "IppResolveNeighbor" not in a_result
    assert "IppResolveNeighbor" in b_result
    assert "NotifyHybridOnly" not in b_result


def test_parallel_function_callers_remain_isolated():
    _register_trace("trace_a", "NotifyHybridOnly", 11)
    _register_trace("trace_b", "IppResolveNeighbor", 71)

    def call(trace_id: str) -> str:
        return get_function_callers(trace_id, "KeAcquireInStackQueuedSpinLock")

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(call, ["trace_a", "trace_b"] * 20))

    for index, result in enumerate(results):
        if index % 2 == 0:
            assert "NotifyHybridOnly" in result
            assert "IppResolveNeighbor" not in result
        else:
            assert "IppResolveNeighbor" in result
            assert "NotifyHybridOnly" not in result


def test_list_and_unload_traces():
    _register_trace("trace_a", "NotifyHybridOnly", 11)
    _register_trace("trace_b", "IppResolveNeighbor", 71)

    assert {trace.trace_id for trace in list_loaded_traces()} == {"trace_a", "trace_b"}

    rendered = list_loaded_traces_tool()
    assert "trace_a" in rendered
    assert "trace_b" in rendered

    assert unregister_trace("trace_a")
    assert {trace.trace_id for trace in list_loaded_traces()} == {"trace_b"}
