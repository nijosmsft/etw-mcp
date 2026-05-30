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
