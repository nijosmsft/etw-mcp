from __future__ import annotations

import hashlib
import math
from pathlib import Path
from typing import Any

import pandas as pd
import pytest

from etw_analyzer.tools.cpu_sampling import get_cpu_samples
from etw_analyzer.tools.packet_capture import get_packet_capture_summary
from etw_analyzer.tools.per_cpu import get_per_cpu_summary
from etw_analyzer.tools.trace_mgmt import trace_info
from etw_analyzer.trace_state import clear_traces, get_trace


pytestmark = [pytest.mark.fixture, pytest.mark.golden]


@pytest.fixture(autouse=True)
def _isolate_trace_registry():
    clear_traces()
    yield
    clear_traces()


def _assert_between(value: float, expected: dict, *, key: str) -> None:
    minimum = expected.get(f"min_{key}")
    maximum = expected.get(f"max_{key}")
    if minimum is not None:
        assert value >= float(minimum)
    if maximum is not None:
        assert value <= float(maximum)


def _assert_expected_number(value: float, expected: dict, *, key: str) -> None:
    if key in expected:
        assert value == float(expected[key]), (
            f"{key} mismatch: actual {value}, expected {expected[key]}"
        )
        return
    _assert_between(value, expected, key=key)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _expected_or_manifest(
    fixture_name: str,
    fixture_expected_data,
    fixture_manifest_data,
) -> dict[str, Any]:
    expected = fixture_expected_data(fixture_name)
    if expected:
        return expected
    return fixture_manifest_data(fixture_name)


def _assert_expected_identity(etl_path: Path, expected: dict[str, Any]) -> None:
    etl = expected.get("etl")
    if not isinstance(etl, dict):
        return
    if "size" in etl:
        assert etl_path.stat().st_size == int(etl["size"])
    if "sha256" in etl:
        assert _sha256(etl_path) == etl["sha256"]


def _total_weight(df: pd.DataFrame) -> float:
    weight_col = next(
        (col for col in ("Weight", "Count", "Sample Count", "Samples") if col in df.columns),
        None,
    )
    assert weight_col is not None, f"CPU sample weight column missing: {list(df.columns)}"
    total = pd.to_numeric(df[weight_col], errors="coerce").fillna(0).sum()
    return float(total)


def test_empty_trace_loads_with_stable_invariants(
    load_fixture_trace,
    fixture_etl_path,
    fixture_expected_data,
    fixture_manifest_data,
):
    _result, trace_id = load_fixture_trace("empty-trace", mode="native")
    trace = get_trace(trace_id)
    assert trace is not None
    assert trace.trace_id == trace_id
    assert trace.etl_path.name == "empty-trace.etl"
    assert trace.cpu_count is None or trace.cpu_count >= 0
    assert trace.duration_seconds is None or trace.duration_seconds >= 0

    info = trace_info(trace_id)
    assert "**Trace loaded" in info
    assert trace_id in info

    expected_data = _expected_or_manifest(
        "empty-trace",
        fixture_expected_data,
        fixture_manifest_data,
    )
    _assert_expected_identity(fixture_etl_path("empty-trace"), expected_data)
    datasets = expected_data.get("datasets", {})
    if "max_count" in datasets:
        assert len(trace.raw_csv) <= int(datasets["max_count"])

    cpu_result = get_cpu_samples(trace_id)
    assert isinstance(cpu_result, str)
    assert cpu_result


def test_cpu_only_trace_has_cpu_samples_within_expected_ranges(
    load_fixture_trace,
    fixture_etl_path,
    fixture_expected_data,
    fixture_manifest_data,
):
    _result, trace_id = load_fixture_trace("cpu-only-trace", mode="native")
    trace = get_trace(trace_id)
    assert trace is not None

    cpu_df = trace.raw_csv.get("cpu_sampling")
    assert isinstance(cpu_df, pd.DataFrame)
    assert not cpu_df.empty

    expected_data = _expected_or_manifest(
        "cpu-only-trace",
        fixture_expected_data,
        fixture_manifest_data,
    )
    _assert_expected_identity(fixture_etl_path("cpu-only-trace"), expected_data)
    expected = expected_data.get("cpu_sampling", {})
    _assert_expected_number(len(cpu_df), expected, key="rows")
    total_weight = _total_weight(cpu_df)
    _assert_expected_number(total_weight, expected, key="total_weight")
    assert total_weight > 0

    samples = get_cpu_samples(trace_id, group_by="module")
    assert "**CPU Samples**" in samples
    assert "Total weight:" in samples

    per_cpu = get_per_cpu_summary(trace_id)
    assert "CPU" in per_cpu
    assert "Traceback" not in per_cpu


def test_pktmon_capture_trace_reports_packet_capture_invariants(
    load_fixture_trace,
    fixture_etl_path,
    fixture_expected_data,
    fixture_manifest_data,
):
    _result, trace_id = load_fixture_trace("pktmon-capture-trace", mode="native")

    summary = get_packet_capture_summary(trace_id, top_n=10)
    assert "**Packet Capture Summary**" in summary
    assert "Total packets:" in summary
    assert "Traceback" not in summary

    trace = get_trace(trace_id)
    assert trace is not None
    expected_data = _expected_or_manifest(
        "pktmon-capture-trace",
        fixture_expected_data,
        fixture_manifest_data,
    )
    _assert_expected_identity(fixture_etl_path("pktmon-capture-trace"), expected_data)
    expected = expected_data.get("packet_capture", {})
    if not expected and isinstance(expected_data.get("packet_capture"), dict):
        expected = expected_data["packet_capture"]
    if isinstance(trace.packet_capture_df, pd.DataFrame) and not trace.packet_capture_df.empty:
        _assert_expected_number(len(trace.packet_capture_df), expected, key="packets")
        if "total_packets" in expected:
            assert len(trace.packet_capture_df) == int(expected["total_packets"])
    elif expected.get("min_packets") is not None:
        # Pktmon fallback may not materialize NDIS rows, but the MCP summary
        # above still exercises the packet-capture path.
        assert "Pktmon fallback was unavailable" not in summary
    elif "total_packets" in expected:
        assert f"Total packets: {int(expected['total_packets']):,}" in summary


@pytest.mark.xperf
def test_native_xperf_cpu_only_parity_when_enabled(
    load_fixture_trace,
    fixture_expected_data,
    fixture_manifest_data,
    xperf_path,
):
    _native_result, native_trace_id = load_fixture_trace(
        "cpu-only-trace",
        mode="native",
    )
    native_trace = get_trace(native_trace_id)
    assert native_trace is not None
    native_df = native_trace.raw_csv.get("cpu_sampling")
    assert isinstance(native_df, pd.DataFrame)
    native_weight = _total_weight(native_df)

    _xperf_result, xperf_trace_id = load_fixture_trace(
        "cpu-only-trace",
        mode="xperf",
        force=True,
    )
    xperf_trace = get_trace(xperf_trace_id)
    assert xperf_trace is not None
    xperf_df = xperf_trace.raw_csv.get("cpu_sampling")
    assert isinstance(xperf_df, pd.DataFrame)
    xperf_weight = _total_weight(xperf_df)

    assert native_weight > 0
    assert xperf_weight > 0
    assert native_trace_id == xperf_trace_id

    expected_data = _expected_or_manifest(
        "cpu-only-trace",
        fixture_expected_data,
        fixture_manifest_data,
    )
    expected = expected_data.get("parity", {})
    if "cpu_weight_rel_tol" not in expected:
        pytest.skip("cpu-only-trace has no enabled native/xperf CPU parity baseline")
    rel_tol = float(expected.get("cpu_weight_rel_tol", 0.25))
    assert math.isclose(native_weight, xperf_weight, rel_tol=rel_tol)
