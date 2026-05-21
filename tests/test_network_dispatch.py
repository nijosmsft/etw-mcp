"""Tests for the Phase 2 network-dispatch tools."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer.tools.network_dispatch import (
    _per_cpu_dpc_rows,
    get_per_nic_queue_arrivals,
    get_rss_dispatch_quality,
    get_udp_dispatch_quality,
)
from etw_analyzer.trace_state import TraceData, clear_traces, register_trace


@pytest.fixture(autouse=True)
def clean_trace_registry():
    clear_traces()
    yield
    clear_traces()


# ---------------------------------------------------------------------------
# Fixture builders — synthetic dpc_isr_raw and dumper DataFrames
# ---------------------------------------------------------------------------


def _build_dpcisr_raw_text(per_module_cpu_usec: dict[str, dict[int, int]],
                           total_cpus: int = 16) -> str:
    """Build a fake ``dpcisr.txt`` body with per-CPU usec/% pair rows.

    ``per_module_cpu_usec[module][cpu] = usec`` controls which CPUs got
    non-zero DPC time for each module. CPUs not present in the inner dict
    are emitted as ``0 0`` pairs (so the parser sees the full per-CPU
    width). Module name should already include its ``.sys`` extension.

    The output also includes a minimal histogram block per module so the
    file roughly resembles the real shape, but the histogram is not what
    we exercise — only the per-CPU pair line is consumed by
    ``_per_cpu_dpc_rows``.
    """
    lines: list[str] = []
    for module, cpu_map in per_module_cpu_usec.items():
        total = sum(cpu_map.values())
        lines.append(f"Total = {total} for module {module}")
        # Minimal histogram so the block looks complete.
        lines.append(
            f"Elapsed Time, >  0 usecs AND <=  1 usecs, {total}, or 100.00%"
        )
        lines.append(f"Total, {total}")
        # Per-CPU pair line ending with module name. Use a 2-space gap
        # between usec and pct, single comma between CPUs — matches the
        # regex in dpc_isr._parse_per_cpu_dpc.
        pairs = []
        for cpu in range(total_cpus):
            usec = cpu_map.get(cpu, 0)
            pct = (usec / max(total, 1)) * 100.0
            pairs.append(f"{usec}  {pct:.2f}")
        lines.append(", ".join(pairs) + f"  {module}")
        lines.append("")
    return "\n".join(lines)


def _register_trace(
    trace_id: str,
    raw_csv: dict[str, pd.DataFrame],
    dumper_df: pd.DataFrame | None = None,
    cpu_count: int | None = None,
) -> None:
    trace = TraceData(
        trace_id=trace_id,
        etl_path=Path(f"C:\\traces\\{trace_id}.etl"),
        export_dir=Path(f"C:\\traces\\.etw-export-{trace_id}"),
        raw_csv=raw_csv,
        cpu_count=cpu_count,
    )
    if dumper_df is not None:
        trace.dumper_df = dumper_df
        # Signal the wait-for-dumper event so tools don't block.
        trace._dumper_ready.set()
    else:
        # Mark ready even when None so wait_for_dumper() returns immediately.
        trace._dumper_ready.set()
    register_trace(trace)


# ---------------------------------------------------------------------------
# _per_cpu_dpc_rows parsing
# ---------------------------------------------------------------------------


class TestPerCpuDpcRowsParser:
    def test_basic_module_and_cpu_rows(self):
        raw = _build_dpcisr_raw_text(
            {"mlx5.sys": {0: 1000, 3: 2000, 5: 500}},
            total_cpus=8,
        )
        rows = _per_cpu_dpc_rows(raw)
        # Only non-zero CPUs should appear.
        modules_cpus = {(r["Module"], r["CPU"]) for r in rows}
        assert modules_cpus == {
            ("mlx5.sys", 0),
            ("mlx5.sys", 3),
            ("mlx5.sys", 5),
        }
        # DPC_us round-trips.
        usec_by_cpu = {r["CPU"]: r["DPC_us"] for r in rows}
        assert usec_by_cpu == {0: 1000, 3: 2000, 5: 500}

    def test_empty_text(self):
        assert _per_cpu_dpc_rows("") == []

    def test_skips_lines_without_module_suffix(self):
        # Lines that don't end with a recognized module name are ignored.
        raw = "Total = 1234\n0  0,  1  100  not_a_module\n"
        assert _per_cpu_dpc_rows(raw) == []


# ---------------------------------------------------------------------------
# get_per_nic_queue_arrivals
# ---------------------------------------------------------------------------


class TestPerNicQueueArrivals:
    def test_only_subset_of_cpus_handle_nic_dpcs(self):
        # 16 logical CPUs total, but only the first 8 see mlx5.sys DPCs.
        cpu_map = {cpu: 1000 * (cpu + 1) for cpu in range(8)}
        raw = _build_dpcisr_raw_text({"mlx5.sys": cpu_map}, total_cpus=16)
        _register_trace(
            "trace_q",
            raw_csv={
                "dpc_isr_raw": pd.DataFrame({"raw_text": [raw]}),
            },
            cpu_count=16,
        )

        out = get_per_nic_queue_arrivals("trace_q")

        # Summary names the "X of Y" split.
        assert "8 of 16" in out
        # All 8 active CPUs should appear as rows.
        for cpu in range(8):
            assert f"| {cpu} |" in out
        # Idle CPUs (8-15) should NOT appear.
        for cpu in range(8, 16):
            assert f"| {cpu} |" not in out

    def test_module_substring_match_is_case_insensitive(self):
        raw = _build_dpcisr_raw_text(
            {"MLX5.sys": {0: 1000, 1: 2000}},
            total_cpus=4,
        )
        _register_trace(
            "trace_q",
            raw_csv={"dpc_isr_raw": pd.DataFrame({"raw_text": [raw]})},
            cpu_count=4,
        )

        out = get_per_nic_queue_arrivals("trace_q", nic_module="mlx5")
        # Active CPUs reported.
        assert "2 of 4" in out

    def test_unknown_nic_module_lists_alternatives(self):
        raw = _build_dpcisr_raw_text(
            {"tcpip.sys": {0: 500}},
            total_cpus=4,
        )
        _register_trace(
            "trace_q",
            raw_csv={"dpc_isr_raw": pd.DataFrame({"raw_text": [raw]})},
            cpu_count=4,
        )

        out = get_per_nic_queue_arrivals("trace_q", nic_module="mlx5.sys")
        assert "No DPC samples" in out
        # Should hint at what modules ARE present.
        assert "tcpip.sys" in out

    def test_empty_trace_returns_sensible_message(self):
        _register_trace(
            "trace_empty",
            raw_csv={"dpc_isr_raw": pd.DataFrame({"raw_text": [""]})},
            cpu_count=4,
        )
        out = get_per_nic_queue_arrivals("trace_empty")
        # Either "Per-CPU DPC data is empty" or "no per-CPU dpc data"
        # depending on which gate fires first — both are acceptable.
        assert "empty" in out.lower() or "no per-cpu" in out.lower()

    def test_missing_dpc_isr_raw(self):
        _register_trace("trace_empty", raw_csv={}, cpu_count=4)
        out = get_per_nic_queue_arrivals("trace_empty")
        assert "No DPC/ISR raw text" in out


# ---------------------------------------------------------------------------
# get_rss_dispatch_quality
# ---------------------------------------------------------------------------


def _build_dumper_df(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows, columns=[
        "TimeStamp", "Process Name", "PID", "CPU", "Module", "Function", "Weight",
    ])


class TestRssDispatchQuality:
    def test_same_cpu_vs_cross_cpu_processes(self):
        # NIC DPCs on CPUs 0-3 only.
        raw = _build_dpcisr_raw_text(
            {"mlx5.sys": {0: 1000, 1: 1000, 2: 1000, 3: 1000}},
            total_cpus=16,
        )
        # Build a dumper_df where:
        #   - good.exe has 200 networking samples, ALL on CPU 0 (in NIC set).
        #   - bad.exe  has 200 networking samples, ALL on CPU 10 (NOT in NIC set).
        rows = []
        for i in range(200):
            rows.append({
                "TimeStamp": i, "Process Name": "good.exe", "PID": 1,
                "CPU": 0, "Module": "tcpip.sys", "Function": "UdpRecv",
                "Weight": 1,
            })
        for i in range(200):
            rows.append({
                "TimeStamp": 1000 + i, "Process Name": "bad.exe", "PID": 2,
                "CPU": 10, "Module": "tcpip.sys", "Function": "UdpRecv",
                "Weight": 1,
            })
        dumper = _build_dumper_df(rows)

        _register_trace(
            "trace_disp",
            raw_csv={"dpc_isr_raw": pd.DataFrame({"raw_text": [raw]})},
            dumper_df=dumper,
            cpu_count=16,
        )

        out = get_rss_dispatch_quality("trace_disp", min_samples=100)

        # Both processes should appear.
        assert "good.exe" in out
        assert "bad.exe" in out

        # Extract data lines and verify percentages.
        # The table row order is by descending total weight; both have
        # weight 200 so either order is fine. Verify by row content.
        good_lines = [l for l in out.splitlines() if "good.exe" in l]
        bad_lines = [l for l in out.splitlines() if "bad.exe" in l]
        assert good_lines, "good.exe row missing"
        assert bad_lines, "bad.exe row missing"

        # good.exe lives entirely on CPU 0 (in NIC-DPC set) → same=100, cross=0.
        # bad.exe lives entirely on CPU 10 (not in set) → same=0, cross=100.
        good_row = good_lines[0]
        bad_row = bad_lines[0]
        assert "100.0%" in good_row
        # bad.exe row should NOT show "100.0%" for same_cpu_pct, but
        # should show 100.0% for cross_cpu_pct.
        assert "100.0%" in bad_row

        # Stronger: the same_cpu column is the second-to-last numeric, and
        # cross_cpu is the last. The cleanest check is order: good.exe's
        # same_cpu_pct is 100 and cross is 0.
        # 0.0000% / 0.0% rendering — format_pct shows 0.0000% for small values.
        assert "0.0000%" in good_row or "0.00%" in good_row
        # And bad.exe has 100% cross. Tail cell is cross_cpu_pct.
        assert bad_row.rstrip().endswith("100.0% |")

    def test_excludes_non_network_active_process(self):
        raw = _build_dpcisr_raw_text(
            {"mlx5.sys": {0: 1000}},
            total_cpus=4,
        )
        # quiet.exe has 200 samples but ALL in non-networking modules.
        rows = [
            {
                "TimeStamp": i, "Process Name": "quiet.exe", "PID": 3,
                "CPU": 0, "Module": "kernel32.dll", "Function": "DoNothing",
                "Weight": 1,
            }
            for i in range(200)
        ]
        # noisy.exe has 150 networking samples — above 100 threshold.
        rows += [
            {
                "TimeStamp": 1000 + i, "Process Name": "noisy.exe", "PID": 4,
                "CPU": 0, "Module": "tcpip.sys", "Function": "UdpRecv",
                "Weight": 1,
            }
            for i in range(150)
        ]
        dumper = _build_dumper_df(rows)

        _register_trace(
            "trace_disp",
            raw_csv={"dpc_isr_raw": pd.DataFrame({"raw_text": [raw]})},
            dumper_df=dumper,
            cpu_count=4,
        )

        out = get_rss_dispatch_quality("trace_disp", min_samples=100)
        assert "noisy.exe" in out
        assert "quiet.exe" not in out

    def test_empty_dumper_returns_sensible_message(self):
        raw = _build_dpcisr_raw_text(
            {"mlx5.sys": {0: 1000}},
            total_cpus=4,
        )
        # No dumper_df at all (the wait_for_dumper path returns None).
        _register_trace(
            "trace_empty",
            raw_csv={"dpc_isr_raw": pd.DataFrame({"raw_text": [raw]})},
            cpu_count=4,
        )
        out = get_rss_dispatch_quality("trace_empty")
        assert "No SampledProfile" in out

    def test_no_nic_dpcs_returns_sensible_message(self):
        # dpc_isr_raw has no kernel-networking modules.
        raw = _build_dpcisr_raw_text(
            {"someother.sys": {0: 1000}},
            total_cpus=4,
        )
        dumper = _build_dumper_df([
            {
                "TimeStamp": i, "Process Name": "noisy.exe", "PID": 4,
                "CPU": 0, "Module": "tcpip.sys", "Function": "UdpRecv",
                "Weight": 1,
            }
            for i in range(200)
        ])
        _register_trace(
            "trace_nodpc",
            raw_csv={"dpc_isr_raw": pd.DataFrame({"raw_text": [raw]})},
            dumper_df=dumper,
            cpu_count=4,
        )
        out = get_rss_dispatch_quality("trace_nodpc")
        assert "No networking-module DPCs" in out


# ---------------------------------------------------------------------------
# get_udp_dispatch_quality
# ---------------------------------------------------------------------------


class TestUdpDispatchQuality:
    def test_filters_to_udp_path_processes_only(self):
        raw = _build_dpcisr_raw_text(
            {"mlx5.sys": {0: 1000, 1: 1000}},
            total_cpus=8,
        )
        # udp.exe — top frames are UDP-path (tcpip.sys!UdpDeliver).
        udp_rows = [
            {
                "TimeStamp": i, "Process Name": "udp.exe", "PID": 10,
                "CPU": 4, "Module": "tcpip.sys", "Function": "UdpDeliver",
                "Weight": 1,
            }
            for i in range(50)
        ]
        # tcp.exe — tcpip.sys but TCP-path function name → excluded.
        tcp_rows = [
            {
                "TimeStamp": 1000 + i, "Process Name": "tcp.exe", "PID": 11,
                "CPU": 4, "Module": "tcpip.sys", "Function": "TcpRecv",
                "Weight": 1,
            }
            for i in range(50)
        ]
        # other.exe — kernel32.dll, definitely not in the UDP module set.
        other_rows = [
            {
                "TimeStamp": 2000 + i, "Process Name": "other.exe", "PID": 12,
                "CPU": 5, "Module": "kernel32.dll", "Function": "UdpHelper",
                "Weight": 1,
            }
            for i in range(50)
        ]
        dumper = _build_dumper_df(udp_rows + tcp_rows + other_rows)

        _register_trace(
            "trace_udp",
            raw_csv={"dpc_isr_raw": pd.DataFrame({"raw_text": [raw]})},
            dumper_df=dumper,
            cpu_count=8,
        )

        out = get_udp_dispatch_quality("trace_udp", min_samples=25)
        assert "udp.exe" in out
        assert "tcp.exe" not in out
        # other.exe matches the function hint but not the module set → out.
        assert "other.exe" not in out

    def test_cross_cpu_percent_against_nic_set(self):
        raw = _build_dpcisr_raw_text(
            {"mlx5.sys": {0: 1000, 1: 1000, 2: 1000, 3: 1000}},
            total_cpus=16,
        )
        # All samples on CPU 10 → cross-CPU 100%.
        dumper = _build_dumper_df([
            {
                "TimeStamp": i, "Process Name": "udp.exe", "PID": 10,
                "CPU": 10, "Module": "afd.sys", "Function": "AfdReceiveDatagram",
                "Weight": 1,
            }
            for i in range(60)
        ])
        _register_trace(
            "trace_udp",
            raw_csv={"dpc_isr_raw": pd.DataFrame({"raw_text": [raw]})},
            dumper_df=dumper,
            cpu_count=16,
        )

        out = get_udp_dispatch_quality("trace_udp", min_samples=25)
        udp_row = [l for l in out.splitlines() if "udp.exe" in l][0]
        assert udp_row.rstrip().endswith("100.0% |")

    def test_port_arg_is_noop_documented(self):
        raw = _build_dpcisr_raw_text(
            {"mlx5.sys": {0: 1000}},
            total_cpus=4,
        )
        dumper = _build_dumper_df([
            {
                "TimeStamp": i, "Process Name": "udp.exe", "PID": 10,
                "CPU": 0, "Module": "tcpip.sys", "Function": "UdpDeliver",
                "Weight": 1,
            }
            for i in range(30)
        ])
        _register_trace(
            "trace_udp",
            raw_csv={"dpc_isr_raw": pd.DataFrame({"raw_text": [raw]})},
            dumper_df=dumper,
            cpu_count=4,
        )

        out = get_udp_dispatch_quality("trace_udp", port=5000, min_samples=25)
        assert "port=5000" in out
        assert "Phase 3" in out

    def test_empty_dumper_returns_sensible_message(self):
        raw = _build_dpcisr_raw_text(
            {"mlx5.sys": {0: 1000}},
            total_cpus=4,
        )
        _register_trace(
            "trace_empty",
            raw_csv={"dpc_isr_raw": pd.DataFrame({"raw_text": [raw]})},
            cpu_count=4,
        )
        out = get_udp_dispatch_quality("trace_empty")
        assert "No SampledProfile" in out

    def test_no_udp_samples_returns_sensible_message(self):
        raw = _build_dpcisr_raw_text(
            {"mlx5.sys": {0: 1000}},
            total_cpus=4,
        )
        # Only kernel32-style samples — no UDP-path matches at all.
        dumper = _build_dumper_df([
            {
                "TimeStamp": i, "Process Name": "other.exe", "PID": 10,
                "CPU": 0, "Module": "kernel32.dll", "Function": "DoNothing",
                "Weight": 1,
            }
            for i in range(100)
        ])
        _register_trace(
            "trace_noudp",
            raw_csv={"dpc_isr_raw": pd.DataFrame({"raw_text": [raw]})},
            dumper_df=dumper,
            cpu_count=4,
        )
        out = get_udp_dispatch_quality("trace_noudp")
        assert "No UDP-recv-path samples" in out
