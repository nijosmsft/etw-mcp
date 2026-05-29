"""Tests for the raw-text aggregators (sysconfig / process_info / diskio / tracestats)."""

from __future__ import annotations

import types

import pandas as pd

from etw_analyzer.native.aggregators.diskio import build_diskio_text
from etw_analyzer.native.aggregators.process_info import (
    build_process_info_text,
    build_process_table,
)
from etw_analyzer.native.aggregators.sysconfig import build_sysconfig_text
from etw_analyzer.native.aggregators.tracestats import build_tracestats_text


def _trace_with(raw_csv=None, event_counts=None, extract_stats=None):
    trace = types.SimpleNamespace(
        raw_csv=raw_csv or {},
        event_counts=event_counts or {},
    )
    if extract_stats is not None:
        trace._native_extract_stats = extract_stats
    return trace


class TestSysconfig:
    def test_empty(self):
        assert build_sysconfig_text(_trace_with()) is None

    def test_basic(self):
        df = pd.DataFrame([
            {"OpcodeName": "CPU", "PayloadBytes": 32},
            {"OpcodeName": "CPU", "PayloadBytes": 32},
            {"OpcodeName": "NIC", "PayloadBytes": 256},
        ])
        text = build_sysconfig_text(_trace_with({"SystemConfig": df}))
        assert text is not None
        assert "CPU: 2 record" in text
        assert "NIC: 1 record" in text

    def test_metadata_only(self):
        metadata = pd.DataFrame([{
            "NumberOfProcessors": 80,
            "DurationSeconds": 16.4502142,
            "CpuSpeedInMHz": 2295,
            "TimerResolution": 156250,
            "PointerSize": 8,
        }])
        text = build_sysconfig_text(_trace_with({"trace_metadata": metadata}))
        assert text is not None
        assert "ProcessorNum: 80" in text
        assert "ProcessorSpeed: 2295" in text
        assert "DurationSeconds: 16.4502142" in text


class TestProcessInfo:
    def test_empty(self):
        assert build_process_info_text(_trace_with()) is None

    def test_basic(self):
        df = pd.DataFrame([
            {"TimeStamp": 100, "ProcessId": 1234, "ParentId": 4,
             "SessionId": 0, "ImageFileName": "echo_server.exe", "CommandLine": ""},
        ])
        text = build_process_info_text(_trace_with({"Process/Start": df}))
        assert text is not None
        assert "echo_server.exe" in text
        assert "PID=1234" in text

    def test_build_process_table(self):
        df = pd.DataFrame([
            {"TimeStamp": 100, "ProcessId": 1234, "ParentId": 4,
             "SessionId": 0, "ImageFileName": "a.exe", "CommandLine": ""},
            {"TimeStamp": 200, "ProcessId": 1234, "ParentId": 4,
             "SessionId": 0, "ImageFileName": "a.exe", "CommandLine": ""},
        ])
        result = build_process_table(_trace_with({"Process/DCStart": df}))
        assert result is not None
        # Duplicate PIDs deduplicated.
        assert len(result) == 1


class TestDiskio:
    def test_empty(self):
        assert build_diskio_text(_trace_with()) is None

    def test_basic_summary(self):
        reads = pd.DataFrame([
            {"DiskNumber": 0, "TransferSize": 4096, "CPU": 0, "TimeStamp": 1},
            {"DiskNumber": 0, "TransferSize": 8192, "CPU": 0, "TimeStamp": 2},
        ])
        writes = pd.DataFrame([
            {"DiskNumber": 0, "TransferSize": 2048, "CPU": 1, "TimeStamp": 3},
        ])
        text = build_diskio_text(_trace_with({
            "DiskIo/Read": reads,
            "DiskIo/Write": writes,
        }))
        assert text is not None
        assert "Disk 0" in text
        assert "reads=2" in text
        assert "writes=1" in text


class TestTracestats:
    def test_empty(self):
        assert build_tracestats_text(_trace_with()) is None

    def test_with_event_counts_only(self):
        trace = _trace_with(event_counts={"cpu_sampling": 1000, "dpc_isr": 500})
        text = build_tracestats_text(trace)
        assert text is not None
        assert "cpu_sampling: 1000" in text

    def test_with_metadata_only(self):
        metadata = pd.DataFrame([{
            "NumberOfProcessors": 80,
            "DurationSeconds": 16.4502142,
            "EventsLost": 0,
            "BuffersLost": 0,
            "BuffersWritten": 42,
        }])
        trace = _trace_with(raw_csv={"trace_metadata": metadata})
        text = build_tracestats_text(trace)
        assert text is not None
        assert "Number of Processors : 80" in text
        assert "Trace duration (s)   : 16.4502142" in text
        assert "Total # Lost Events  : 0" in text
        assert "Buffers Written      : 42" in text

    def test_with_extract_stats(self):
        from etw_analyzer.native.consumer import TraceLogfileMetadata
        from etw_analyzer.native.extract import ExtractStats
        stats = ExtractStats(
            event_count=12345,
            elapsed_seconds=4.2,
            bytes_processed=99999,
            provider_counts={"abc-guid": 1000},
            decoded_counts={"SampledProfile": 800},
            events_lost=0,
            stacks_paired=600,
            stacks_orphan=200,
            logfile_metadata=[TraceLogfileMetadata(
                number_of_processors=80,
                start_time_utc_100ns=1_000_000_000,
                end_time_utc_100ns=1_164_502_142,
                perf_freq=10_000_000,
                timer_resolution_100ns=156_250,
                cpu_speed_mhz=2295,
                events_lost=0,
                buffers_lost=0,
                buffers_written=1,
                pointer_size=8,
            )],
        )
        trace = _trace_with(extract_stats=stats)
        text = build_tracestats_text(trace)
        assert text is not None
        assert "Number of Processors : 80" in text
        assert "Trace duration (s)   : 16.4502142" in text
        assert "Total events:    12345" in text
        assert "EventCount:      12345" in text
        assert "abc-guid EventCount=1000" in text
        assert "SampledProfile: 800" in text
