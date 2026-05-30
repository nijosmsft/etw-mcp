"""Phase B csharp parity tests.

Extends the Phase A parity coverage (``test_csharp_parity.py``) with
the per-opcode kernel-meta event classes the sidecar started emitting
in Phase B:

* ``perfinfo_{dpc,threaded_dpc,timer_dpc,isr}`` → ``dpc_isr`` /
  ``dpc_isr_raw`` aggregators
* ``process_{start,end,dcstart,dcend,defunct}`` → ``process_info``
* ``thread_{start,end,dcstart,dcend}`` → cswitch enrichment
* ``diskio_{read,write,flushbuffers}`` → ``diskio`` aggregator
  (handles absent parquets gracefully — the test fixture has 0 disk
  events on the real lab hardware)
* ``image_{load,dcstart}`` → symbolizer for ``stacks`` /
  ``stacks_callers``
* ``eventtrace_header`` → authoritative ``trace_metadata`` (replaces
  the QPC-range heuristic)

Each adapter has a unit test (schema in / schema out); each aggregator
has an integration test that runs ``run_aggregation_worker`` against a
synthetic Phase B staging dir and asserts the corresponding raw_csv
key + parquet land on disk.

See ``manager-log/phase-b-sidecar-status.md`` "Column-name contracts"
for the exact Phase B schemas these tests pin.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import pandas as pd
import pytest

from etw_analyzer.native import aggregation_worker
from etw_analyzer.native import aggregation_worker_adapters as adapters
from etw_analyzer.native import cache as native_cache


# ---- shared helpers -----------------------------------------------------


def _make_etl(tmp_path: Path) -> Path:
    etl = tmp_path / "phase_b.etl"
    etl.write_bytes(b"synthetic phase b etl")
    return etl


def _make_sampled_profile(rows: int = 50, cpu_count: int = 4) -> pd.DataFrame:
    qpc_start = 1_000_000
    qpc_per_sample = max(1, 10_000_000 // max(rows, 1))
    return pd.DataFrame({
        "EventSequence": list(range(rows)),
        "TimeStampQpc": [qpc_start + i * qpc_per_sample for i in range(rows)],
        "CPU": [i % cpu_count for i in range(rows)],
        "ProcessId": [1234] * rows,
        "ThreadId": [11 + (i % 4) for i in range(rows)],
        "PayloadThreadId": [11 + (i % 4) for i in range(rows)],
        "InstructionPointer": [0xFF00_0000 + i * 16 for i in range(rows)],
        "Weight": [1] * rows,
        "ProfileWeight": [1] * rows,
        "Stack": [
            [0xFF00_0000 + i * 16, 0xFF00_0000 + (i + 1) * 16]
            for i in range(rows)
        ],
    })


def _make_perfinfo_dpc(rows: int = 100, cpu_count: int = 4, routine: int = 0xFFFFF800_AABB0000) -> pd.DataFrame:
    """Phase B perfinfo_dpc schema: EventSequence, TimeStampQpc, CPU, Routine, ElapsedMicros."""
    qpc_start = 2_000_000
    qpc_per = 1000
    return pd.DataFrame({
        "EventSequence": list(range(rows)),
        "TimeStampQpc": [qpc_start + i * qpc_per for i in range(rows)],
        "CPU": [i % cpu_count for i in range(rows)],
        "Routine": [routine] * rows,
        "ElapsedMicros": [(i % 8) + 1 for i in range(rows)],
    })


def _make_process_dcstart(rows: int = 5) -> pd.DataFrame:
    """Phase B process_dcstart schema: PID/ParentPID (NOT ProcessId/ParentId)."""
    return pd.DataFrame({
        "EventSequence": list(range(rows)),
        "TimeStampQpc": [1_000_000 + i * 1000 for i in range(rows)],
        "CPU": [0] * rows,
        "PID": [1000 + i for i in range(rows)],
        "ParentPID": [4] * rows,
        "ImageFileName": [f"proc_{i}.exe" for i in range(rows)],
        "CommandLine": [f"proc_{i}.exe --foo" for i in range(rows)],
    })


def _make_image_dcstart(rows: int = 3, base: int = 0xFFFFF800_AABB0000) -> pd.DataFrame:
    """Phase B image_dcstart: EventSequence, TimeStampQpc, CPU, PID, ImageBase, ImageSize, TimeDateStamp, FileName."""
    return pd.DataFrame({
        "EventSequence": list(range(rows)),
        "TimeStampQpc": [1_000_000 + i * 1000 for i in range(rows)],
        "CPU": [0] * rows,
        "PID": [4] * rows,
        "ImageBase": [base + i * 0x100_000 for i in range(rows)],
        "ImageSize": [0x80_000] * rows,
        "TimeDateStamp": [0] * rows,
        "FileName": [f"\\SystemRoot\\drivers\\mod_{i}.sys" for i in range(rows)],
    })


def _make_eventtrace_header(
    perf_freq: int = 10_000_000,
    cpu_count: int = 80,
    start_100ns: int = 132_000_000_000_000_000,
    end_100ns: int = 132_000_000_100_000_000,
) -> pd.DataFrame:
    """Phase B eventtrace_header: single-row header parquet."""
    return pd.DataFrame([{
        "EventSequence": 0,
        "TimeStampQpc": 0,
        "CPU": 0,
        "PerfFreq": perf_freq,
        "NumberOfProcessors": cpu_count,
        "TimerResolution": 156250,
        "StartTime100Ns": start_100ns,
        "EndTime100Ns": end_100ns,
        "BootTime100Ns": 0,
        "CpuSpeedMHz": 2300,
        "PointerSize": 8,
        "LogFileMode": 0,
        "BuffersWritten": 100,
        "EventsLost": 0,
        "SessionName": "spike",
        "LogFileName": "spike.etl",
    }])


def _seed_phase_b_staging(
    staging_dir: Path,
    etl: Path,
    *,
    sampled_rows: int = 50,
    cpu_count: int = 4,
    include_perfinfo: bool = False,
    include_process: bool = False,
    include_image: bool = False,
    include_eventtrace_header: bool = False,
    include_diskio: bool = False,
    perfinfo_rows: int = 100,
    process_rows: int = 5,
    image_rows: int = 3,
) -> None:
    """Seed a staging dir with sidecar-shape parquets + v3 manifest.

    Each include_* flag adds the corresponding Phase B per-opcode
    parquets. Always emits sampled_profile + cswitch_events + sysconfig
    + readythread so the trace_metadata + cpu_timeline aggregators
    have inputs.
    """
    staging_dir.mkdir(parents=True, exist_ok=True)

    sampled = _make_sampled_profile(sampled_rows, cpu_count)
    sampled.to_parquet(staging_dir / "sampled_profile.parquet", index=False)

    cswitch = pd.DataFrame({
        "EventSequence": list(range(20)),
        "TimeStampQpc": [1_000_000 + i * 500 for i in range(20)],
        "CPU": [i % cpu_count for i in range(20)],
        "NewTID": [100 + (i % 4) for i in range(20)],
        "OldTID": [200 + (i % 4) for i in range(20)],
        "NewPID": [1234] * 20,
        "OldPID": [4321] * 20,
        "WaitReason": ["Executive"] * 20,
        "Stack": [[] for _ in range(20)],
    })
    cswitch.to_parquet(staging_dir / "cswitch_events.parquet", index=False)

    ready = pd.DataFrame({
        "EventSequence": pd.Series([], dtype="uint64"),
        "TimeStampQpc": pd.Series([], dtype="int64"),
        "CPU": pd.Series([], dtype="int32"),
        "ProcessId": pd.Series([], dtype="int64"),
        "ThreadId": pd.Series([], dtype="int64"),
        "AdjustReason": pd.Series([], dtype="int32"),
        "AdjustIncrement": pd.Series([], dtype="int32"),
        "Flag": pd.Series([], dtype="int32"),
        "Stack": pd.Series([], dtype=object),
    })
    ready.to_parquet(staging_dir / "readythread.parquet", index=False)

    (staging_dir / "sysconfig.txt").write_text(
        "CPU: cores=4 sockets=1\nOS: build=26100\n",
        encoding="utf-8",
    )

    datasets = [
        native_cache.CacheDataset(
            name="sampled_profile", kind="parquet",
            path="sampled_profile.parquet", row_count=sampled_rows,
            materialize_on_load=True,
        ),
        native_cache.CacheDataset(
            name="cswitch_events", kind="parquet",
            path="cswitch_events.parquet", row_count=20,
            materialize_on_load=True,
        ),
        native_cache.CacheDataset(
            name="readythread", kind="parquet",
            path="readythread.parquet", row_count=0,
            materialize_on_load=True,
        ),
        native_cache.CacheDataset(
            name="sysconfig", kind="text", path="sysconfig.txt",
            row_count=1, materialize_on_load=True,
        ),
    ]

    if include_perfinfo:
        for stem in ("perfinfo_dpc", "perfinfo_threaded_dpc", "perfinfo_timer_dpc", "perfinfo_isr"):
            df = _make_perfinfo_dpc(rows=perfinfo_rows, cpu_count=cpu_count)
            df.to_parquet(staging_dir / f"{stem}.parquet", index=False)
            datasets.append(native_cache.CacheDataset(
                name=stem, kind="parquet", path=f"{stem}.parquet",
                row_count=perfinfo_rows, materialize_on_load=True,
            ))

    if include_process:
        df = _make_process_dcstart(rows=process_rows)
        df.to_parquet(staging_dir / "process_dcstart.parquet", index=False)
        datasets.append(native_cache.CacheDataset(
            name="process_dcstart", kind="parquet",
            path="process_dcstart.parquet", row_count=process_rows,
            materialize_on_load=True,
        ))

    if include_image:
        df = _make_image_dcstart(rows=image_rows)
        df.to_parquet(staging_dir / "image_dcstart.parquet", index=False)
        datasets.append(native_cache.CacheDataset(
            name="image_dcstart", kind="parquet",
            path="image_dcstart.parquet", row_count=image_rows,
            materialize_on_load=True,
        ))

    if include_eventtrace_header:
        df = _make_eventtrace_header(cpu_count=cpu_count)
        df.to_parquet(staging_dir / "eventtrace_header.parquet", index=False)
        datasets.append(native_cache.CacheDataset(
            name="eventtrace_header", kind="parquet",
            path="eventtrace_header.parquet", row_count=1,
            materialize_on_load=True,
        ))

    if include_diskio:
        diskio = pd.DataFrame({
            "EventSequence": [0, 1, 2],
            "TimeStampQpc": [1000, 2000, 3000],
            "CPU": [0, 0, 0],
            "DiskNumber": [0, 0, 0],
            "TransferSize": [4096, 8192, 0],
            "ByteOffset": [0, 4096, 0],
            "FileName": ["a.dat", "b.dat", ""],
        })
        # We only emit read here for the integration test; the adapter
        # must cope with write / flushbuffers being absent.
        diskio.to_parquet(staging_dir / "diskio_read.parquet", index=False)
        datasets.append(native_cache.CacheDataset(
            name="diskio_read", kind="parquet", path="diskio_read.parquet",
            row_count=3, materialize_on_load=True,
        ))

    manifest = native_cache.CacheManifest.materialized_small(
        etl, datasets, producer="csharp",
    )
    native_cache.write_manifest(staging_dir, manifest)


# ---- Adapter unit tests: DPC ---------------------------------------------


class TestAdaptCsharpDpcDataframe:
    def test_renames_timestampqpc_to_timestamp(self):
        df = _make_perfinfo_dpc(rows=3)
        result = adapters.adapt_csharp_dpc_dataframe(df)
        assert "TimeStamp" in result.columns
        assert "TimeStampQpc" not in result.columns

    def test_synthesises_initial_time_from_elapsed_micros(self):
        df = _make_perfinfo_dpc(rows=5)
        # Elapsed at 10 MHz QPC is ElapsedMicros * 10 ticks; InitialTime
        # must therefore equal TimeStamp - ElapsedMicros * 10.
        result = adapters.adapt_csharp_dpc_dataframe(df, perf_freq_hz=10_000_000.0)
        assert "InitialTime" in result.columns
        for i in range(5):
            ts = int(result["TimeStamp"].iloc[i])
            elapsed_us = int(df["ElapsedMicros"].iloc[i])
            assert int(result["InitialTime"].iloc[i]) == ts - elapsed_us * 10

    def test_handles_none(self):
        assert adapters.adapt_csharp_dpc_dataframe(None) is None

    def test_handles_empty(self):
        df = pd.DataFrame()
        out = adapters.adapt_csharp_dpc_dataframe(df)
        assert out is df

    def test_preserves_routine_column(self):
        df = _make_perfinfo_dpc(rows=3, routine=0xFFFFF800_DEADBEEF)
        out = adapters.adapt_csharp_dpc_dataframe(df)
        assert "Routine" in out.columns
        assert int(out["Routine"].iloc[0]) == 0xFFFFF800_DEADBEEF

    def test_skips_initial_time_synthesis_when_elapsed_missing(self):
        df = pd.DataFrame({
            "TimeStampQpc": [1, 2],
            "CPU": [0, 1],
            "Routine": [100, 200],
        })
        out = adapters.adapt_csharp_dpc_dataframe(df)
        assert "TimeStamp" in out.columns
        assert "InitialTime" not in out.columns


# ---- Integration: DPC ----------------------------------------------------


class TestPhaseBDpcIsr:
    def test_dpc_isr_aggregator_runs_against_per_opcode_parquets(
        self, tmp_path: Path,
    ):
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_phase_b_staging(
            staging, etl,
            include_perfinfo=True, include_eventtrace_header=True,
        )
        result = aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_dpc",
        )
        assert result.ok is True, f"{result.message} / {result.warnings}"

        # dpc_isr.parquet must land on disk and have non-zero rows.
        parquet = staging / "dpc_isr.parquet"
        assert parquet.exists(), (
            f"dpc_isr.parquet missing. datasets_written={result.datasets_written}"
        )
        df = pd.read_parquet(parquet)
        assert {"Module", "Bucket_Low_us", "Bucket_High_us", "Count", "Pct"}.issubset(
            df.columns
        )
        assert len(df) > 0, "dpc_isr aggregator produced no rows"

    def test_dpc_isr_raw_text_produced(self, tmp_path: Path):
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_phase_b_staging(
            staging, etl,
            include_perfinfo=True, include_eventtrace_header=True,
        )

        # build_dpc_isr_raw_text only includes modules whose name ends
        # in .sys/.exe/.dll — without a symbolizer everything resolves
        # to "unknown" and gets filtered out. Inject a stub so the text
        # path runs end-to-end. (Real csharp mode builds a symbolizer
        # from image_load/image_dcstart parquets, exercised separately
        # in TestPhaseBStacks.)
        from etw_analyzer.native import aggregation_worker as aw
        real_build = aw._build_trace_from_staging

        def with_stub(*args, **kwargs):
            trace = real_build(*args, **kwargs)
            trace.symbolizer = _DpcStubSymbolizer()
            return trace

        aw._build_trace_from_staging = with_stub
        try:
            aw.run_aggregation_worker(
                staging, etl, trace_id="trace_dpc_raw",
            )
        finally:
            aw._build_trace_from_staging = real_build

        text_path = staging / "dpcisr.txt"
        assert text_path.exists(), "dpcisr.txt was not written"
        text = text_path.read_text(encoding="utf-8")
        assert text.strip(), "dpcisr.txt is empty"
        # The stub resolves to ndis.sys; the per-CPU pair line must
        # therefore mention it.
        assert "ndis.sys" in text or "ndis.SYS".lower() in text.lower()

    def test_dpc_isr_canonical_keys_populated_in_raw_csv(self, tmp_path: Path):
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_phase_b_staging(
            staging, etl,
            include_perfinfo=True, include_eventtrace_header=True,
        )

        # Tap into the trace before persist to inspect raw_csv keys.
        from etw_analyzer.native import aggregation_worker as aw
        captured: dict[str, set[str]] = {}
        real_persist = aw._persist_aggregator_outputs

        def capture(staging_dir, trace, warnings):
            captured["keys"] = set(trace.raw_csv.keys())
            return real_persist(staging_dir, trace, warnings)

        aw._persist_aggregator_outputs = capture
        try:
            aw.run_aggregation_worker(staging, etl, trace_id="trace_dpc_keys")
        finally:
            aw._persist_aggregator_outputs = real_persist

        keys = captured["keys"]
        # Every Phase B canonical class with non-zero rows must be in
        # raw_csv (the adapters land them there).
        for cls in (
            "PerfInfo/DPC",
            "PerfInfo/ThreadedDPC",
            "PerfInfo/TimerDPC",
            "PerfInfo/ISR",
        ):
            assert cls in keys, f"{cls!r} missing from raw_csv. Got: {sorted(keys)}"

    def test_dpc_isr_registered_in_manifest(self, tmp_path: Path):
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_phase_b_staging(
            staging, etl,
            include_perfinfo=True, include_eventtrace_header=True,
        )
        from etw_analyzer.native import aggregation_worker as aw
        real_build = aw._build_trace_from_staging

        def with_stub(*args, **kwargs):
            trace = real_build(*args, **kwargs)
            trace.symbolizer = _DpcStubSymbolizer()
            return trace

        aw._build_trace_from_staging = with_stub
        try:
            aw.run_aggregation_worker(
                staging, etl, trace_id="trace_dpc_m",
            )
        finally:
            aw._build_trace_from_staging = real_build

        loaded = native_cache.read_manifest(staging)
        names = {d.name for d in loaded.datasets}
        assert "dpc_isr" in names
        assert "dpc_isr_raw" in names


# ---- stubs used by Phase B integration tests ----------------------------


@dataclass
class _DpcStubSymbolizer:
    """Resolve every routine address to ``ndis.sys!routine_<low12>``.

    Real symbolizer lookups happen in TestPhaseBStacks via the
    image-built symbolizer; for DPC-only tests this is enough to make
    ``build_dpc_isr_raw_text``'s ``.sys/.exe/.dll`` filter pass.
    """

    cache: dict[int, str] = field(default_factory=dict)

    def resolve(self, addr: int) -> str:
        if addr in self.cache:
            return self.cache[addr]
        sym = f"ndis.sys!routine_{addr & 0xFFF:03x}"
        self.cache[addr] = sym
        return sym

    def bulk_resolve(self, addrs: Iterable[int]) -> dict[int, str]:
        return {int(addr): self.resolve(int(addr)) for addr in addrs}

    def close(self) -> None:
        self.cache.clear()


# ---- Adapter unit tests: process ---------------------------------------


class TestAdaptCsharpProcessDataframe:
    def test_renames_pid_to_processid(self):
        df = _make_process_dcstart(rows=3)
        out = adapters.adapt_csharp_process_dataframe(df)
        assert "ProcessId" in out.columns
        assert "PID" not in out.columns

    def test_renames_parentpid_to_parentid(self):
        df = _make_process_dcstart(rows=3)
        out = adapters.adapt_csharp_process_dataframe(df)
        assert "ParentId" in out.columns
        assert "ParentPID" not in out.columns

    def test_synthesises_sessionid_zero(self):
        df = _make_process_dcstart(rows=3)
        out = adapters.adapt_csharp_process_dataframe(df)
        assert "SessionId" in out.columns
        assert (out["SessionId"] == 0).all()

    def test_renames_timestampqpc_to_timestamp(self):
        df = _make_process_dcstart(rows=3)
        out = adapters.adapt_csharp_process_dataframe(df)
        assert "TimeStamp" in out.columns
        assert "TimeStampQpc" not in out.columns

    def test_preserves_image_and_command(self):
        df = _make_process_dcstart(rows=3)
        out = adapters.adapt_csharp_process_dataframe(df)
        assert out["ImageFileName"].iloc[0] == "proc_0.exe"
        assert out["CommandLine"].iloc[1] == "proc_1.exe --foo"

    def test_handles_none_and_empty(self):
        assert adapters.adapt_csharp_process_dataframe(None) is None
        empty = pd.DataFrame()
        out = adapters.adapt_csharp_process_dataframe(empty)
        assert out is empty

    def test_idempotent_when_already_native_shape(self):
        df = pd.DataFrame({
            "TimeStamp": [1],
            "ProcessId": [42],
            "ParentId": [4],
            "SessionId": [1],
            "ImageFileName": ["x.exe"],
            "CommandLine": ["x"],
        })
        out = adapters.adapt_csharp_process_dataframe(df)
        # Already-native shape: SessionId preserved (not overwritten).
        assert out["SessionId"].iloc[0] == 1


# ---- Adapter unit tests: thread (TID->ProcessId/ThreadId rename) -------


def _make_thread_dcstart(rows: int = 5) -> pd.DataFrame:
    """Phase B thread_dcstart schema: PID/TID (NOT ProcessId/ThreadId)."""
    return pd.DataFrame({
        "EventSequence": list(range(rows)),
        "TimeStampQpc": [1_000_000 + i * 1000 for i in range(rows)],
        "CPU": [0] * rows,
        "PID": [1000 + i for i in range(rows)],
        "TID": [4000 + i for i in range(rows)],
        "ImageFileName": [f"proc_{i}.exe" for i in range(rows)],
    })


class TestAdaptCsharpThreadDataframe:
    def test_renames_pid_to_processid(self):
        df = _make_thread_dcstart(rows=3)
        out = adapters.adapt_csharp_thread_dataframe(df)
        assert "ProcessId" in out.columns
        assert "PID" not in out.columns

    def test_renames_tid_to_threadid(self):
        df = _make_thread_dcstart(rows=3)
        out = adapters.adapt_csharp_thread_dataframe(df)
        assert "ThreadId" in out.columns
        assert "TID" not in out.columns

    def test_renames_timestampqpc_to_timestamp(self):
        df = _make_thread_dcstart(rows=3)
        out = adapters.adapt_csharp_thread_dataframe(df)
        assert "TimeStamp" in out.columns
        assert "TimeStampQpc" not in out.columns

    def test_preserves_thread_metadata(self):
        df = _make_thread_dcstart(rows=3)
        out = adapters.adapt_csharp_thread_dataframe(df)
        assert out["ProcessId"].tolist() == [1000, 1001, 1002]
        assert out["ThreadId"].tolist() == [4000, 4001, 4002]
        assert out["ImageFileName"].iloc[0] == "proc_0.exe"

    def test_handles_none_and_empty(self):
        assert adapters.adapt_csharp_thread_dataframe(None) is None
        empty = pd.DataFrame()
        out = adapters.adapt_csharp_thread_dataframe(empty)
        assert out is empty

    def test_idempotent_when_already_native_shape(self):
        df = pd.DataFrame({
            "TimeStamp": [1],
            "ProcessId": [42],
            "ThreadId": [200],
        })
        out = adapters.adapt_csharp_thread_dataframe(df)
        assert "ProcessId" in out.columns
        assert "ThreadId" in out.columns
        assert "TimeStamp" in out.columns
        assert out["ProcessId"].iloc[0] == 42
        assert out["ThreadId"].iloc[0] == 200

    def test_phase_b_thread_stems_cover_start_end_dcstart_dcend(self):
        assert set(adapters.PHASE_B_THREAD_STEMS.keys()) == {
            "thread_start", "thread_end", "thread_dcstart", "thread_dcend",
        }
        # Canonical event-class names must match what the in-tree
        # aggregator helpers look up (Thread/Start, etc.).
        assert adapters.PHASE_B_THREAD_STEMS["thread_start"] == "Thread/Start"
        assert adapters.PHASE_B_THREAD_STEMS["thread_dcstart"] == "Thread/DCStart"


# ---- Adapter unit tests: sampled_profile (ProcessId->PID rename) -------


class TestAdaptCsharpSampledProfileDataframe:
    def test_renames_processid_to_pid(self):
        df = _make_sampled_profile(rows=4)
        out = adapters.adapt_csharp_sampled_profile_dataframe(df)
        assert "PID" in out.columns
        assert "ProcessId" not in out.columns

    def test_renames_timestampqpc_to_timestamp(self):
        df = _make_sampled_profile(rows=4)
        out = adapters.adapt_csharp_sampled_profile_dataframe(df)
        assert "TimeStamp" in out.columns
        assert "TimeStampQpc" not in out.columns

    def test_preserves_payload_thread_id_and_other_columns(self):
        df = _make_sampled_profile(rows=4)
        out = adapters.adapt_csharp_sampled_profile_dataframe(df)
        # ThreadId / PayloadThreadId must NOT be renamed — the
        # SampledProfile MOF shape uses these exact names natively.
        assert "PayloadThreadId" in out.columns
        assert "ThreadId" in out.columns
        # Identifying fields preserved.
        assert "InstructionPointer" in out.columns
        assert "Stack" in out.columns
        assert "Weight" in out.columns
        assert "ProfileWeight" in out.columns

    def test_handles_none_and_empty(self):
        assert adapters.adapt_csharp_sampled_profile_dataframe(None) is None
        empty = pd.DataFrame()
        out = adapters.adapt_csharp_sampled_profile_dataframe(empty)
        assert out is empty

    def test_idempotent_when_already_native_shape(self):
        df = pd.DataFrame({
            "TimeStamp": [1, 2, 3],
            "PID": [1234, 1234, 1234],
            "ThreadId": [11, 11, 11],
            "PayloadThreadId": [11, 11, 11],
            "InstructionPointer": [0xFF000000, 0xFF000010, 0xFF000020],
            "Weight": [1, 1, 1],
            "ProfileWeight": [1, 1, 1],
            "Stack": [[], [], []],
        })
        out = adapters.adapt_csharp_sampled_profile_dataframe(df)
        # Already-native shape: PID preserved (no double-rename).
        assert "PID" in out.columns
        assert out["PID"].iloc[0] == 1234


# ---- Integration: thread loader wires PID/TID->ProcessId/ThreadId ------


class TestPhaseBThreadLoader:
    """Regression test for ``manager-log/sampledprofile-attribution-finding.md``.

    Asserts that ``_load_phase_b_thread`` lands ``Thread/Start`` /
    ``Thread/DCStart`` in ``raw_csv`` with the renamed columns the
    cpu_sampling aggregator needs.
    """

    def test_thread_dcstart_lands_with_renamed_columns(self, tmp_path: Path):
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_phase_b_staging(staging, etl, include_process=True)
        # Seed Phase B thread_dcstart with sidecar-shape PID/TID columns.
        thread_df = _make_thread_dcstart(rows=5)
        thread_df.to_parquet(staging / "thread_dcstart.parquet", index=False)
        # The aggregation worker's loader will discover the parquet by
        # filename even if the manifest doesn't list it.
        from etw_analyzer.native import aggregation_worker as aw

        captured: dict[str, set[str] | pd.DataFrame] = {}
        real_persist = aw._persist_aggregator_outputs

        def cap(staging_dir, trace, warnings):
            captured["keys"] = set(trace.raw_csv.keys())
            tdf = trace.raw_csv.get("Thread/DCStart")
            if tdf is not None:
                captured["thread_dcstart"] = tdf.copy()
            return real_persist(staging_dir, trace, warnings)

        aw._persist_aggregator_outputs = cap
        try:
            aw.run_aggregation_worker(staging, etl, trace_id="trace_thread")
        finally:
            aw._persist_aggregator_outputs = real_persist

        assert "Thread/DCStart" in captured["keys"]
        thread = captured["thread_dcstart"]
        assert "ProcessId" in thread.columns
        assert "ThreadId" in thread.columns
        # The sidecar-shape names must be gone (no double-write).
        assert "PID" not in thread.columns
        assert "TID" not in thread.columns
        assert len(thread) == 5


# ---- Integration: sampled_profile rename feeds cpu_sampling ------------


class TestPhaseBSampledProfileAttribution:
    """Regression test for the column rename that drives Process Name lookup.

    Without ``adapt_csharp_sampled_profile_dataframe`` running on the
    SampledProfile DataFrame, every cpu_sampling row collapses into
    ``Process Name='unknown', PID=0`` on multi-process traces. See
    ``manager-log/sampledprofile-attribution-finding.md``.
    """

    def test_sampled_profile_dumper_df_uses_pid_column_after_load(
        self, tmp_path: Path,
    ):
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        # The synthetic SampledProfile fixture in
        # _seed_phase_b_staging uses sidecar-shape ProcessId.
        _seed_phase_b_staging(staging, etl)
        from etw_analyzer.native import aggregation_worker as aw

        captured: dict[str, pd.DataFrame] = {}
        real_persist = aw._persist_aggregator_outputs

        def cap(staging_dir, trace, warnings):
            if trace.dumper_df is not None:
                captured["dumper"] = trace.dumper_df.copy()
            sp = trace.raw_csv.get("SampledProfile")
            if sp is not None:
                captured["raw_csv"] = sp.copy()
            return real_persist(staging_dir, trace, warnings)

        aw._persist_aggregator_outputs = cap
        try:
            aw.run_aggregation_worker(staging, etl, trace_id="trace_sp")
        finally:
            aw._persist_aggregator_outputs = real_persist

        # Both slots must carry PID (not ProcessId) so the cpu_sampling
        # aggregator's Process Name lookup fires.
        assert "dumper" in captured and "raw_csv" in captured
        for label, df in captured.items():
            assert "PID" in df.columns, f"{label}: PID missing after adapter"
            assert "ProcessId" not in df.columns, (
                f"{label}: ProcessId still present (double-rename risk)"
            )


# ---- Integration: process_info -----------------------------------------


class TestPhaseBProcessInfo:
    def test_process_info_text_produced(self, tmp_path: Path):
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_phase_b_staging(staging, etl, include_process=True)
        result = aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_proc",
        )
        assert result.ok is True, f"{result.message} / {result.warnings}"
        text_path = staging / "process_info.txt"
        assert text_path.exists(), "process_info.txt not written"
        text = text_path.read_text(encoding="utf-8")
        assert "proc_0.exe" in text
        # Each row has TimeStamp / PID / Parent / Session / Image / CmdLine.
        assert "PID=1000" in text
        assert "Parent=4" in text

    def test_process_canonical_key_populated(self, tmp_path: Path):
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_phase_b_staging(staging, etl, include_process=True)
        from etw_analyzer.native import aggregation_worker as aw
        captured: dict[str, set[str]] = {}
        real_persist = aw._persist_aggregator_outputs

        def cap(staging_dir, trace, warnings):
            captured["keys"] = set(trace.raw_csv.keys())
            return real_persist(staging_dir, trace, warnings)

        aw._persist_aggregator_outputs = cap
        try:
            aw.run_aggregation_worker(staging, etl, trace_id="trace_proc_keys")
        finally:
            aw._persist_aggregator_outputs = real_persist
        assert "Process/DCStart" in captured["keys"]

    def test_process_info_registered_in_manifest(self, tmp_path: Path):
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_phase_b_staging(staging, etl, include_process=True)
        aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_proc_m",
        )
        loaded = native_cache.read_manifest(staging)
        kinds_by_name = {d.name: d.kind for d in loaded.datasets}
        assert kinds_by_name.get("process_info") == "text"

    def test_process_table_drives_cpu_sampling_process_name(self, tmp_path: Path):
        """The cpu_sampling aggregator looks up Process Name via build_process_table.

        After Phase B per-opcode adaptation, ProcessId is correctly
        populated, so cpu_sampling rows can be linked back to image
        names. We don't try to assert the full join here (cpu_sampling
        has its own quirks); this just smoke-tests that
        _native_process_events gets populated.
        """
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_phase_b_staging(staging, etl, include_process=True)
        from etw_analyzer.native import aggregation_worker as aw
        captured: dict[str, pd.DataFrame] = {}
        real_persist = aw._persist_aggregator_outputs

        def cap(staging_dir, trace, warnings):
            ptable = trace.raw_csv.get("_native_process_events")
            if ptable is not None:
                captured["ptable"] = ptable.copy()
            return real_persist(staging_dir, trace, warnings)

        aw._persist_aggregator_outputs = cap
        try:
            aw.run_aggregation_worker(staging, etl, trace_id="trace_ptable")
        finally:
            aw._persist_aggregator_outputs = real_persist
        assert "ptable" in captured
        ptable = captured["ptable"]
        assert "ProcessId" in ptable.columns
        assert len(ptable) > 0


# ---- Adapter unit tests: diskio ----------------------------------------


class TestAdaptCsharpDiskioDataframe:
    def test_renames_timestampqpc_to_timestamp(self):
        df = pd.DataFrame({
            "TimeStampQpc": [1, 2],
            "CPU": [0, 0],
            "DiskNumber": [0, 0],
            "TransferSize": [4096, 8192],
        })
        out = adapters.adapt_csharp_diskio_dataframe(df)
        assert "TimeStamp" in out.columns
        assert "TimeStampQpc" not in out.columns

    def test_handles_none(self):
        assert adapters.adapt_csharp_diskio_dataframe(None) is None

    def test_handles_empty(self):
        empty = pd.DataFrame()
        assert adapters.adapt_csharp_diskio_dataframe(empty) is empty

    def test_preserves_disknumber_and_transfersize(self):
        df = pd.DataFrame({
            "TimeStampQpc": [1, 2, 3],
            "DiskNumber": [0, 1, 0],
            "TransferSize": [4096, 8192, 0],
        })
        out = adapters.adapt_csharp_diskio_dataframe(df)
        assert list(out["DiskNumber"]) == [0, 1, 0]
        assert list(out["TransferSize"]) == [4096, 8192, 0]


# ---- Integration: diskio -----------------------------------------------


class TestPhaseBDiskio:
    def test_missing_diskio_parquets_does_not_fail(self, tmp_path: Path):
        """Real fixture has zero disk events; the loader must no-op."""
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_phase_b_staging(staging, etl, include_diskio=False)
        result = aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_diskio_missing",
        )
        assert result.ok is True, f"{result.message} / {result.warnings}"
        # No diskio.txt is the documented "zero events" outcome.
        assert not (staging / "diskio.txt").exists()
        # Aggregator warnings list must not contain a diskio failure —
        # the loader stayed quiet.
        assert not any("diskio" in w.lower() for w in result.warnings), (
            f"warnings mention diskio: {result.warnings}"
        )

    def test_diskio_read_only_produces_text(self, tmp_path: Path):
        """When only diskio_read.parquet exists, the aggregator still runs.

        (The integration test fixture in this file omits write/flushbuffers
        — the adapter must cope.)
        """
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_phase_b_staging(staging, etl, include_diskio=True)
        result = aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_diskio_read_only",
        )
        assert result.ok is True
        # build_diskio_text needs DiskNumber and renders one line per disk.
        text_path = staging / "diskio.txt"
        assert text_path.exists()
        text = text_path.read_text(encoding="utf-8")
        assert "Disk 0" in text
        assert "reads=" in text

    def test_diskio_canonical_key_populated_when_present(self, tmp_path: Path):
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_phase_b_staging(staging, etl, include_diskio=True)
        from etw_analyzer.native import aggregation_worker as aw
        captured: dict[str, set[str]] = {}
        real_persist = aw._persist_aggregator_outputs

        def cap(staging_dir, trace, warnings):
            captured["keys"] = set(trace.raw_csv.keys())
            return real_persist(staging_dir, trace, warnings)

        aw._persist_aggregator_outputs = cap
        try:
            aw.run_aggregation_worker(staging, etl, trace_id="trace_diskio_keys")
        finally:
            aw._persist_aggregator_outputs = real_persist
        assert "DiskIo/Read" in captured["keys"]


# ---- Adapter unit tests: image -----------------------------------------


class TestAdaptCsharpImageDataframe:
    def test_renames_timestampqpc_to_timestamp(self):
        df = _make_image_dcstart(rows=2)
        out = adapters.adapt_csharp_image_dataframe(df)
        assert "TimeStamp" in out.columns
        assert "TimeStampQpc" not in out.columns

    def test_preserves_imagebase_imagesize_filename(self):
        df = _make_image_dcstart(rows=2)
        out = adapters.adapt_csharp_image_dataframe(df)
        assert out["ImageBase"].iloc[0] == 0xFFFFF800_AABB0000
        assert int(out["ImageSize"].iloc[0]) == 0x80_000
        assert "mod_0.sys" in out["FileName"].iloc[0]

    def test_handles_none_and_empty(self):
        assert adapters.adapt_csharp_image_dataframe(None) is None
        empty = pd.DataFrame()
        assert adapters.adapt_csharp_image_dataframe(empty) is empty


# ---- Adapter: symbolizer construction ----------------------------------


class _FakeSymbolizer:
    """In-memory symbolizer used to assert add_module is invoked.

    Replaces the real dbghelp-backed Symbolizer for unit tests so we
    can verify the adapter registers every distinct image base without
    needing native Windows bindings.
    """

    def __init__(self, symbol_path=None):
        self.symbol_path = symbol_path
        self.modules: list[tuple[int, int, str]] = []

    def add_module(self, base: int, size: int, file_name: str) -> None:
        self.modules.append((int(base), int(size), str(file_name)))

    def bulk_resolve(self, addrs):
        out = {}
        for addr in addrs:
            module = "unknown"
            for base, size, name in self.modules:
                if base <= int(addr) < base + size:
                    module = Path(name).name.lower()
                    break
            out[int(addr)] = f"{module}!func_{int(addr) & 0xFFF:03x}"
        return out

    def resolve(self, addr: int) -> str:
        return self.bulk_resolve([addr])[int(addr)]

    def close(self) -> None:
        pass


class TestBuildSymbolizerFromCsharpImages:
    def test_registers_modules_from_image_dcstart(self, tmp_path: Path, monkeypatch):
        from etw_analyzer.trace_state import TraceData
        from etw_analyzer.native import aggregation_worker_adapters as ad

        # Stub the native Symbolizer import.
        import etw_analyzer.native as native_pkg
        monkeypatch.setattr(native_pkg, "Symbolizer", _FakeSymbolizer, raising=False)

        trace = TraceData(
            trace_id="t", etl_path=tmp_path / "x.etl",
            export_dir=tmp_path, raw_csv={},
        )
        trace.raw_csv["Image/DCStart"] = _make_image_dcstart(rows=3)
        ok = ad.build_symbolizer_from_csharp_images(trace)
        assert ok is True
        assert trace.symbolizer is not None
        assert len(trace.symbolizer.modules) == 3
        # First module: base, size, name (sys ending).
        base, size, name = trace.symbolizer.modules[0]
        assert base == 0xFFFFF800_AABB0000
        assert size == 0x80_000
        assert name.endswith("mod_0.sys")

    def test_deduplicates_by_imagebase(self, tmp_path: Path, monkeypatch):
        from etw_analyzer.trace_state import TraceData
        from etw_analyzer.native import aggregation_worker_adapters as ad

        import etw_analyzer.native as native_pkg
        monkeypatch.setattr(native_pkg, "Symbolizer", _FakeSymbolizer, raising=False)

        # Both DCStart and Load reference the same base → registered once.
        same = _make_image_dcstart(rows=2)
        trace = TraceData(
            trace_id="t", etl_path=tmp_path / "x.etl",
            export_dir=tmp_path, raw_csv={},
        )
        trace.raw_csv["Image/DCStart"] = same
        trace.raw_csv["Image/Load"] = same.copy()
        ad.build_symbolizer_from_csharp_images(trace)
        assert len(trace.symbolizer.modules) == 2  # 2 unique, not 4

    def test_returns_false_when_no_image_rows(self, tmp_path: Path, monkeypatch):
        from etw_analyzer.trace_state import TraceData
        from etw_analyzer.native import aggregation_worker_adapters as ad

        import etw_analyzer.native as native_pkg
        monkeypatch.setattr(native_pkg, "Symbolizer", _FakeSymbolizer, raising=False)

        trace = TraceData(
            trace_id="t", etl_path=tmp_path / "x.etl",
            export_dir=tmp_path, raw_csv={},
        )
        ok = ad.build_symbolizer_from_csharp_images(trace)
        assert ok is False
        assert trace.symbolizer is None

    def test_known_address_resolves_to_known_module(self, tmp_path: Path, monkeypatch):
        """Symbolizer-test for stacks: bulk_resolve maps an address inside
        a registered module range to that module's name."""
        from etw_analyzer.trace_state import TraceData
        from etw_analyzer.native import aggregation_worker_adapters as ad

        import etw_analyzer.native as native_pkg
        monkeypatch.setattr(native_pkg, "Symbolizer", _FakeSymbolizer, raising=False)

        trace = TraceData(
            trace_id="t", etl_path=tmp_path / "x.etl",
            export_dir=tmp_path, raw_csv={},
        )
        # One module at base 0xFFFFF800_AABB0000, size 0x80_000 covers
        # addresses 0xFFFFF800_AABB0000 .. 0xFFFFF800_AAB30000.
        trace.raw_csv["Image/DCStart"] = pd.DataFrame([{
            "TimeStampQpc": 0, "CPU": 0, "PID": 4,
            "ImageBase": 0xFFFFF800_AABB0000,
            "ImageSize": 0x80_000,
            "TimeDateStamp": 0,
            "FileName": "\\SystemRoot\\drivers\\hotmod.sys",
        }])
        ad.build_symbolizer_from_csharp_images(trace)
        # Address inside the module's range.
        addr = 0xFFFFF800_AABB1234
        labels = trace.symbolizer.bulk_resolve([addr])
        assert "hotmod.sys" in labels[addr]


# ---- Integration: stacks + stacks_callers ------------------------------


class TestPhaseBStacks:
    def test_stacks_produced_with_csharp_image_symbolizer(
        self, tmp_path: Path, monkeypatch,
    ):
        """Real path: image_dcstart present → symbolizer built → stacks produced."""
        # Make the native import resolve to our fake.
        import etw_analyzer.native as native_pkg
        monkeypatch.setattr(native_pkg, "Symbolizer", _FakeSymbolizer, raising=False)

        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        # SampledProfile stacks reference 0xFF00_0000+; image base in
        # _make_image_dcstart is 0xFFFFF800_AABB0000 (different range).
        # Add an image that DOES cover the stack addresses so the
        # symbolizer resolves them to something other than "unknown".
        _seed_phase_b_staging(
            staging, etl,
            sampled_rows=30, cpu_count=4,
            include_image=True,
        )
        # Patch in an image covering the stack address range.
        cover = pd.DataFrame([{
            "EventSequence": 0,
            "TimeStampQpc": 0,
            "CPU": 0,
            "PID": 4,
            "ImageBase": 0xFF00_0000,
            "ImageSize": 0x100_0000,
            "TimeDateStamp": 0,
            "FileName": "\\SystemRoot\\drivers\\stacks_mod.sys",
        }])
        cover.to_parquet(staging / "image_load.parquet", index=False)

        # Also need to update the manifest to include image_load.
        manifest = native_cache.read_manifest(staging)
        datasets = list(manifest.datasets)
        datasets.append(native_cache.CacheDataset(
            name="image_load", kind="parquet", path="image_load.parquet",
            row_count=1, materialize_on_load=True,
        ))
        new_manifest = native_cache.CacheManifest.materialized_small(
            etl, datasets, producer="csharp",
        )
        native_cache.write_manifest(staging, new_manifest)

        result = aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_stacks_phaseb",
        )
        assert result.ok is True, f"{result.message} / {result.warnings}"
        parquet = staging / "stacks.parquet"
        assert parquet.exists()
        df = pd.read_parquet(parquet)
        assert {"Module", "Function", "Inclusive", "Exclusive"}.issubset(df.columns)
        assert len(df) > 0
        # At least one module entry must be our injected stacks_mod.sys.
        modules = set(df["Module"].astype(str).str.lower())
        assert "stacks_mod.sys" in modules

    def test_stacks_callers_produced_with_csharp_image_symbolizer(
        self, tmp_path: Path, monkeypatch,
    ):
        import etw_analyzer.native as native_pkg
        monkeypatch.setattr(native_pkg, "Symbolizer", _FakeSymbolizer, raising=False)

        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_phase_b_staging(
            staging, etl, sampled_rows=30, cpu_count=4, include_image=True,
        )
        cover = pd.DataFrame([{
            "EventSequence": 0, "TimeStampQpc": 0, "CPU": 0, "PID": 4,
            "ImageBase": 0xFF00_0000, "ImageSize": 0x100_0000,
            "TimeDateStamp": 0,
            "FileName": "\\SystemRoot\\drivers\\stacks_mod.sys",
        }])
        cover.to_parquet(staging / "image_load.parquet", index=False)
        manifest = native_cache.read_manifest(staging)
        datasets = list(manifest.datasets)
        datasets.append(native_cache.CacheDataset(
            name="image_load", kind="parquet", path="image_load.parquet",
            row_count=1, materialize_on_load=True,
        ))
        native_cache.write_manifest(
            staging,
            native_cache.CacheManifest.materialized_small(
                etl, datasets, producer="csharp",
            ),
        )
        aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_callers_phaseb",
        )
        parquet = staging / "stacks_callers.parquet"
        assert parquet.exists()
        df = pd.read_parquet(parquet)
        assert "Direction" in df.columns
        assert "self" in set(df["Direction"])


# ---- Adapter unit tests: EventTrace/Header -----------------------------


class TestEventtraceHeaderToMetadata:
    def test_extracts_perf_freq_and_cpu_count(self):
        df = _make_eventtrace_header(perf_freq=10_000_000, cpu_count=80)
        meta = adapters.eventtrace_header_to_metadata(df)
        assert meta is not None
        assert meta.cpu_count == 80
        assert meta.timestamp_frequency == 10_000_000.0

    def test_computes_duration_from_filetime(self):
        # 1 second = 1e7 FILETIME ticks.
        df = _make_eventtrace_header(
            start_100ns=132_000_000_000_000_000,
            end_100ns=132_000_000_010_000_000,  # +1 second
        )
        meta = adapters.eventtrace_header_to_metadata(df)
        assert meta.duration_seconds == pytest.approx(1.0)

    def test_returns_none_for_empty(self):
        assert adapters.eventtrace_header_to_metadata(None) is None
        assert adapters.eventtrace_header_to_metadata(pd.DataFrame()) is None

    def test_returns_none_when_all_fields_zero(self):
        df = pd.DataFrame([{
            "PerfFreq": 0,
            "NumberOfProcessors": 0,
            "StartTime100Ns": 0,
            "EndTime100Ns": 0,
        }])
        assert adapters.eventtrace_header_to_metadata(df) is None

    def test_handles_invalid_perf_freq(self):
        df = pd.DataFrame([{
            "PerfFreq": "not-a-number",
            "NumberOfProcessors": 8,
            "StartTime100Ns": 0,
            "EndTime100Ns": 0,
        }])
        meta = adapters.eventtrace_header_to_metadata(df)
        assert meta is not None
        assert meta.cpu_count == 8
        assert meta.timestamp_frequency is None


class TestBuildTraceMetadataDataframeWithHeader:
    def test_header_extras_propagate(self):
        meta = adapters.CsharpMetadata(
            cpu_count=80, duration_seconds=1.0, timestamp_frequency=10_000_000.0,
        )
        manifest = native_cache.CacheManifest(
            schema_version=3, mode="native", strategy="materialized-small",
            complete=True,
            etl=native_cache.EtlIdentity(path="x", name="x", size=1, mtime_ns=0),
            datasets=[], producer="csharp",
        )
        header = _make_eventtrace_header(
            perf_freq=10_000_000, cpu_count=80,
            start_100ns=132_000_000_000_000_000,
            end_100ns=132_000_000_010_000_000,
        )
        df = adapters.build_trace_metadata_dataframe(
            meta, manifest, eventtrace_header_df=header,
        )
        # Authoritative values land in the trace_metadata row.
        assert int(df.iloc[0]["StartTime"]) == 132_000_000_000_000_000
        assert int(df.iloc[0]["EndTime"]) == 132_000_000_010_000_000
        assert int(df.iloc[0]["TimerResolution"]) == 156250
        assert int(df.iloc[0]["CpuSpeedInMHz"]) == 2300
        assert int(df.iloc[0]["BuffersWritten"]) == 100

    def test_zero_defaults_when_no_header(self):
        meta = adapters.CsharpMetadata(
            cpu_count=4, duration_seconds=0.5, timestamp_frequency=10_000_000.0,
        )
        manifest = native_cache.CacheManifest(
            schema_version=3, mode="native", strategy="materialized-small",
            complete=True,
            etl=native_cache.EtlIdentity(path="x", name="x", size=1, mtime_ns=0),
            datasets=[], producer="csharp",
        )
        df = adapters.build_trace_metadata_dataframe(meta, manifest)
        assert int(df.iloc[0]["StartTime"]) == 0
        assert int(df.iloc[0]["EndTime"]) == 0


# ---- Integration: trace_metadata upgrade -------------------------------


class TestPhaseBTraceMetadataUpgrade:
    def test_authoritative_perf_freq_from_header(self, tmp_path: Path):
        """trace_metadata PerfFreq comes from eventtrace_header parquet,
        not the heuristic 10 MHz default."""
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        # Use a non-default PerfFreq to prove the header wins.
        _seed_phase_b_staging(staging, etl, include_eventtrace_header=False)
        df = _make_eventtrace_header(perf_freq=3_579_545, cpu_count=80)
        df.to_parquet(staging / "eventtrace_header.parquet", index=False)
        manifest = native_cache.read_manifest(staging)
        datasets = list(manifest.datasets)
        datasets.append(native_cache.CacheDataset(
            name="eventtrace_header", kind="parquet",
            path="eventtrace_header.parquet", row_count=1,
            materialize_on_load=True,
        ))
        native_cache.write_manifest(
            staging,
            native_cache.CacheManifest.materialized_small(
                etl, datasets, producer="csharp",
            ),
        )
        result = aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_header_perffreq",
        )
        assert result.ok is True
        meta_parquet = staging / "trace_metadata.parquet"
        assert meta_parquet.exists()
        meta_df = pd.read_parquet(meta_parquet)
        assert int(meta_df.iloc[0]["PerfFreq"]) == 3_579_545
        assert int(meta_df.iloc[0]["NumberOfProcessors"]) == 80

    def test_start_and_end_time_from_header(self, tmp_path: Path):
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_phase_b_staging(
            staging, etl, include_eventtrace_header=True,
        )
        result = aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_header_st_et",
        )
        assert result.ok is True
        meta_df = pd.read_parquet(staging / "trace_metadata.parquet")
        # Defaults from _make_eventtrace_header.
        assert int(meta_df.iloc[0]["StartTime"]) == 132_000_000_000_000_000
        assert int(meta_df.iloc[0]["EndTime"]) == 132_000_000_100_000_000
        # 100M ticks @ 10 MHz FILETIME = 10 seconds duration.
        assert float(meta_df.iloc[0]["DurationSeconds"]) == pytest.approx(10.0)

    def test_falls_back_to_heuristic_when_no_header(self, tmp_path: Path):
        """No eventtrace_header → heuristic max(CPU)+1 + QPC-range derivation."""
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_phase_b_staging(
            staging, etl, sampled_rows=200, cpu_count=4,
            include_eventtrace_header=False,
        )
        result = aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_header_fallback",
        )
        assert result.ok is True
        meta_df = pd.read_parquet(staging / "trace_metadata.parquet")
        # cpu_count from max(CPU)+1=4; StartTime / EndTime stay 0 because
        # no header was present.
        assert int(meta_df.iloc[0]["NumberOfProcessors"]) == 4
        assert int(meta_df.iloc[0]["StartTime"]) == 0
        assert int(meta_df.iloc[0]["EndTime"]) == 0
        assert int(meta_df.iloc[0]["PerfFreq"]) == 10_000_000

    def test_dpc_initial_time_uses_header_perf_freq(self, tmp_path: Path):
        """The Phase B perf_freq from the header drives DPC InitialTime synthesis."""
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_phase_b_staging(
            staging, etl, include_perfinfo=True, include_eventtrace_header=False,
        )
        # Use a non-default perf_freq.
        hdr = _make_eventtrace_header(perf_freq=2_000_000)  # 2 MHz
        hdr.to_parquet(staging / "eventtrace_header.parquet", index=False)
        manifest = native_cache.read_manifest(staging)
        datasets = list(manifest.datasets)
        datasets.append(native_cache.CacheDataset(
            name="eventtrace_header", kind="parquet",
            path="eventtrace_header.parquet", row_count=1,
            materialize_on_load=True,
        ))
        native_cache.write_manifest(
            staging,
            native_cache.CacheManifest.materialized_small(
                etl, datasets, producer="csharp",
            ),
        )

        # Capture the DataFrame the loader leaves under PerfInfo/DPC.
        from etw_analyzer.native import aggregation_worker as aw
        captured: dict[str, pd.DataFrame] = {}
        real_persist = aw._persist_aggregator_outputs

        def cap(staging_dir, trace, warnings):
            df = trace.raw_csv.get("PerfInfo/DPC")
            if df is not None:
                captured["dpc"] = df.copy()
            return real_persist(staging_dir, trace, warnings)

        aw._persist_aggregator_outputs = cap
        try:
            aw.run_aggregation_worker(staging, etl, trace_id="trace_dpc_freq")
        finally:
            aw._persist_aggregator_outputs = real_persist

        dpc = captured["dpc"]
        assert "InitialTime" in dpc.columns
        # ticks_per_us = 2 (2 MHz / 1 MHz). InitialTime = TimeStamp -
        # ElapsedMicros * 2.
        row = dpc.iloc[0]
        ts = int(row["TimeStamp"])
        elapsed_us = int(row["ElapsedMicros"])
        assert int(row["InitialTime"]) == ts - elapsed_us * 2


# ---- Cross-mode raw_csv parity + rehydrate -----------------------------


class TestPhaseBRawCsvParity:
    def test_at_least_13_raw_csv_keys_with_full_phase_b_inputs(
        self, tmp_path: Path, monkeypatch,
    ):
        """The Phase B target: >= 13 raw_csv keys end-to-end.

        Seeds every Phase B per-opcode parquet (perfinfo, process,
        diskio, image, eventtrace_header) and verifies the aggregation
        worker produces at least 13 keys in raw_csv, covering the
        Phase B aggregator deliverables: dpc_isr, dpc_isr_raw,
        process_info, diskio (or its canonical), stacks, stacks_callers,
        trace_metadata, plus Phase A baseline (cpu_sampling,
        cpu_timeline, tracestats, sysconfig) and the canonical event
        class keys the loaders populate.
        """
        import etw_analyzer.native as native_pkg
        monkeypatch.setattr(native_pkg, "Symbolizer", _FakeSymbolizer, raising=False)

        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_phase_b_staging(
            staging, etl,
            sampled_rows=50, cpu_count=4,
            include_perfinfo=True,
            include_process=True,
            include_image=True,
            include_eventtrace_header=True,
            include_diskio=True,
        )
        # Ensure image_load covers SampledProfile stack range so stacks
        # produces non-empty Module/Function output.
        cover = pd.DataFrame([{
            "EventSequence": 0, "TimeStampQpc": 0, "CPU": 0, "PID": 4,
            "ImageBase": 0xFF00_0000, "ImageSize": 0x100_0000,
            "TimeDateStamp": 0,
            "FileName": "\\SystemRoot\\drivers\\hot.sys",
        }])
        cover.to_parquet(staging / "image_load.parquet", index=False)
        manifest = native_cache.read_manifest(staging)
        datasets = list(manifest.datasets)
        datasets.append(native_cache.CacheDataset(
            name="image_load", kind="parquet", path="image_load.parquet",
            row_count=1, materialize_on_load=True,
        ))
        native_cache.write_manifest(
            staging,
            native_cache.CacheManifest.materialized_small(
                etl, datasets, producer="csharp",
            ),
        )

        from etw_analyzer.native import aggregation_worker as aw
        captured: dict[str, set[str]] = {}
        real_persist = aw._persist_aggregator_outputs

        def cap(staging_dir, trace, warnings):
            captured["keys"] = set(trace.raw_csv.keys())
            return real_persist(staging_dir, trace, warnings)

        aw._persist_aggregator_outputs = cap
        try:
            result = aw.run_aggregation_worker(
                staging, etl, trace_id="trace_phase_b_full",
            )
        finally:
            aw._persist_aggregator_outputs = real_persist

        assert result.ok is True, f"{result.message} / {result.warnings}"
        keys = captured["keys"]

        # Phase A keys still present.
        phase_a = {"cpu_sampling", "cpu_timeline", "trace_metadata",
                   "tracestats", "sysconfig"}
        # Phase B aggregator deliverables.
        phase_b = {"dpc_isr", "dpc_isr_raw", "process_info", "diskio",
                   "stacks", "stacks_callers"}
        missing = (phase_a | phase_b) - keys
        assert not missing, (
            f"Phase A+B target keys missing: {missing}. Got: {sorted(keys)}"
        )
        # Sanity floor — the literal Phase B deliverable.
        assert len(keys) >= 13, (
            f"raw_csv key count {len(keys)} < 13. Keys: {sorted(keys)}"
        )


class TestPhaseBCacheRehydrate:
    def test_manifest_lists_phase_b_dumper_kinds(self, tmp_path: Path):
        """Phase B per-opcode parquets in the rewritten manifest get
        kind='dumper-parquet'. This is the contract that lets the
        trace_mgmt._load_from_cache path rehydrate them into the
        per-class trace attrs on a subsequent load."""
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_phase_b_staging(
            staging, etl,
            include_perfinfo=True,
            include_process=True,
            include_image=True,
            include_eventtrace_header=True,
        )
        aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_rehydrate",
        )
        loaded = native_cache.read_manifest(staging)
        kinds_by_name = {d.name: d.kind for d in loaded.datasets}
        # Every Phase B per-opcode stem that the sidecar emitted (or
        # that _rewrite_manifest synthesised as zero-row) must be
        # dumper-parquet so the cache loader picks it up.
        for stem in (
            "perfinfo_dpc", "perfinfo_threaded_dpc", "perfinfo_timer_dpc",
            "perfinfo_isr",
            "process_dcstart", "process_start", "process_end",
            "process_dcend", "process_defunct",
            "image_load", "image_dcstart",
            "eventtrace_header",
        ):
            assert kinds_by_name.get(stem) == "dumper-parquet", (
                f"{stem!r} not registered as dumper-parquet "
                f"(got {kinds_by_name.get(stem)!r})"
            )

    def test_rehydrate_after_aggregation_finds_phase_b_parquets(
        self, tmp_path: Path,
    ):
        """A cache that was just written by aggregation_worker must be
        re-readable by trace_mgmt._load_from_cache without
        re-extraction. We verify the v3 manifest lists each Phase B
        stem with kind='dumper-parquet' so the cache loader's
        dumper-rehydrate path picks them up on next load."""
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_phase_b_staging(
            staging, etl,
            include_perfinfo=True,
            include_process=True,
            include_image=True,
            include_eventtrace_header=True,
        )
        aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_rehydrate2",
        )

        # All Phase B per-opcode parquets exist on disk; the
        # required_dumper_datasets check in trace_mgmt._load_from_cache
        # therefore passes.
        for stem in (
            "perfinfo_dpc", "perfinfo_threaded_dpc",
            "perfinfo_timer_dpc", "perfinfo_isr",
            "process_dcstart", "process_start", "process_end",
            "process_dcend", "process_defunct",
            "thread_start", "thread_end", "thread_dcstart", "thread_dcend",
            "diskio_read", "diskio_write", "diskio_flushbuffers",
            "image_load", "image_dcstart",
            "eventtrace_header",
        ):
            parquet = staging / f"{stem}.parquet"
            assert parquet.exists(), f"{stem}.parquet missing on disk"
