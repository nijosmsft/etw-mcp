"""End-to-end integration tests against real ETL captures (#20 / TESTGAP-5).

These exercise the full ``load_trace -> extract -> aggregate -> query``
pipeline against the production traces used by the parity oracle, rather
than synthetic DataFrames. They are the regression guard for the DPC /
diskio parity fix set (issues #4, #13, #14) and are marked ``slow`` so they
stay out of the default fast test run (``addopts = "-m 'not slow'"``).

Run explicitly with::

    uv run pytest tests/test_integration_real_etl.py -m slow -v

The traces are skipped automatically when absent, so the file is safe to
collect on machines without ``C:\\traces``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest


# Production captures (see .squad/.scratch/etw-parity-findings.md):
#   mmsg-fm.etl     — dotnet producer, ~8.6 s, 11M+ DPC rows, 769 diskio rows
#   mmsg-stacks.etl — native producer, ~11.7 s, 8.98M perfinfo_dpc rows
FM_ETL = Path(r"C:\traces\mmsg-fm.etl")
STACKS_ETL = Path(r"C:\traces\mmsg-stacks.etl")


pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        sys.platform != "win32",
        reason="Native ETW pipeline requires Windows (advapi32 + tdh)",
    ),
]

need_fm = pytest.mark.skipif(
    not FM_ETL.exists(), reason=f"Test trace not present: {FM_ETL}"
)
need_stacks = pytest.mark.skipif(
    not STACKS_ETL.exists(), reason=f"Test trace not present: {STACKS_ETL}"
)


def _extract_trace_id(load_output: str) -> str:
    m = re.search(r"`(trace_[0-9a-f]+)`", load_output)
    if m is None:
        raise AssertionError(f"No trace_id in load output:\n{load_output}")
    return m.group(1)


def _table_row_count(markdown: str) -> int:
    """Count data rows in a markdown table (lines starting with ``|`` that
    are not the header or the ``---`` separator)."""
    count = 0
    for line in markdown.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        if set(stripped) <= {"|", "-", " ", ":"}:
            continue  # separator row
        if "DPC Count" in stripped or "% Weight" in stripped or "Module |" in stripped:
            continue  # header row (best-effort)
        count += 1
    return count


def _max_percentage(text: str) -> float:
    """Largest ``NN.N%`` value appearing in tool output."""
    values = [float(v) for v in re.findall(r"(\d+(?:\.\d+)?)\s*%", text)]
    return max(values) if values else 0.0


@pytest.fixture(scope="module")
def fm_trace_id():
    """Load mmsg-fm.etl once for the module and return its trace id."""
    from etw_analyzer.tools.trace_mgmt import load_trace
    from etw_analyzer.trace_state import get_trace, clear_traces

    if not FM_ETL.exists():
        pytest.skip(f"Test trace not present: {FM_ETL}")

    result = load_trace(str(FM_ETL), async_load=False)
    tid = _extract_trace_id(result)
    trace = get_trace(tid)
    trace.wait_for_dumper()
    yield tid
    clear_traces()


@need_fm
def test_real_etl_cpu_samples_have_data(fm_trace_id):
    """#20.1: get_cpu_samples returns substantial sampling data (>1000 rows
    in the underlying cpu_sampling frame)."""
    from etw_analyzer.tools.cpu_sampling import get_cpu_samples
    from etw_analyzer.trace_state import get_trace

    trace = get_trace(fm_trace_id)
    cpu_sampling = trace.raw_csv.get("cpu_sampling")
    assert cpu_sampling is not None and len(cpu_sampling) > 1000

    out = get_cpu_samples(fm_trace_id, group_by="module", max_rows=50)
    assert "No " not in out.splitlines()[0]
    assert "|" in out


@need_fm
def test_real_etl_hot_functions_have_data(fm_trace_id):
    """#20.2: get_hot_functions returns more than 10 functions."""
    from etw_analyzer.tools.cpu_sampling import get_hot_functions

    out = get_hot_functions(fm_trace_id, max_rows=50)
    assert _table_row_count(out) > 10


@need_fm
def test_real_etl_dpc_summary_is_not_empty(fm_trace_id):
    """#20.3 / #13: get_dpc_summary must NOT return "No DPC/ISR data" — the
    11M+ DPC rows are present and must surface a per-module histogram."""
    from etw_analyzer.tools.dpc_isr import get_dpc_summary

    out = get_dpc_summary(fm_trace_id)
    assert "No DPC/ISR data" not in out
    assert "DPC/ISR Duration Summary" in out
    assert _table_row_count(out) >= 1


@need_fm
def test_real_etl_dpc_per_cpu_percentages_are_sane(fm_trace_id):
    """#4: per-CPU DPC percentages must stay bounded by ~100% once the real
    trace duration is used as the denominator (no 1-second-default inflation)."""
    from etw_analyzer.tools.dpc_isr import get_dpc_per_cpu

    out = get_dpc_per_cpu(fm_trace_id)
    assert "DPC Approximation from CPU Sampling" not in out, (
        "DPC per-CPU fell back to CPU sampling — structured DPC data was not "
        "surfaced (regression of #13)."
    )
    # Allow a small rounding margin above 100%.
    assert _max_percentage(out) <= 105.0, out[:500]


@need_fm
def test_real_etl_diskio_summary_is_not_empty(fm_trace_id):
    """#14: get_diskio_summary must surface the 769 diskio rows instead of
    falsely reporting "No disk I/O data"."""
    from etw_analyzer.tools.system_info import get_diskio_summary

    out = get_diskio_summary(fm_trace_id)
    assert "No disk I/O data" not in out
    assert "Disk I/O Summary" in out


@need_fm
@pytest.mark.xfail(
    reason="BUG-1/#11: dotnet sidecar stacks degenerate — owned by the "
    "symbols/sidecar stream, not the DPC stream. Guard flips to xpass once "
    "the stacks rebuild lands.",
    strict=False,
)
def test_real_etl_butterfly_chain_has_call_chain(fm_trace_id):
    """#20.4: butterfly_chain for a known hot network function must return a
    call chain rather than "No stack node found"."""
    from etw_analyzer.tools.stack_analysis import butterfly_chain

    out = butterfly_chain(fm_trace_id, "IppDispatchSendPacketHelper")
    assert "No stack node found" not in out
    assert "->" in out or "→" in out or "|" in out
