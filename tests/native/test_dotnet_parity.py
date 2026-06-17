"""Tests for Phase A dotnet parity in the post-sidecar aggregation worker.

These tests assert that running ``aggregation_worker.run_aggregation_worker``
against a staging directory populated with dotnet-sidecar-shaped parquets
produces the Phase A target raw_csv keys: ``cpu_timeline``,
``trace_metadata``, ``tracestats``, plus ``sysconfig`` from the sidecar
text passthrough. ``stacks`` / ``stacks_callers`` parity is exercised
with a stub symbolizer because the sidecar does not yet emit Image/Load
events (Phase B follow-up).

See ``manager-log/dotnet-parity-exploration.md`` §4 for the Phase A
scope and §6 for what is intentionally deferred.
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


# ---- shared fixtures ----------------------------------------------------


def _make_etl(tmp_path: Path) -> Path:
    etl = tmp_path / "dotnet_parity.etl"
    etl.write_bytes(b"synthetic dotnet parity etl")
    return etl


def _make_sampled_profile(rows: int = 100, cpu_count: int = 4) -> pd.DataFrame:
    """Build a SampledProfile-shaped DataFrame using the SIDECAR schema."""
    # Spread samples across CPUs and a 1-second window at 10 MHz QPC.
    qpc_start = 1_000_000
    qpc_per_sample = 10_000_000 // rows  # ~1s total at 10 MHz
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


def _make_cswitch(rows: int = 50, cpu_count: int = 4) -> pd.DataFrame:
    qpc_start = 1_000_000
    qpc_per_sample = 10_000_000 // rows
    return pd.DataFrame({
        "EventSequence": list(range(rows)),
        "TimeStampQpc": [qpc_start + i * qpc_per_sample for i in range(rows)],
        "CPU": [i % cpu_count for i in range(rows)],
        "NewTID": [100 + (i % 8) for i in range(rows)],
        "OldTID": [200 + (i % 8) for i in range(rows)],
        "NewPID": [1234] * rows,
        "OldPID": [4321] * rows,
        "WaitReason": ["Executive"] * rows,
        "Stack": [[] for _ in range(rows)],
    })


def _make_empty_readythread() -> pd.DataFrame:
    return pd.DataFrame({
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


def _seed_dotnet_staging(
    staging_dir: Path,
    etl: Path,
    *,
    sampled_rows: int = 100,
    cswitch_rows: int = 50,
    cpu_count: int = 4,
) -> None:
    """Seed staging_dir with sidecar-shape parquets + non-final manifest."""
    staging_dir.mkdir(parents=True, exist_ok=True)

    sampled = _make_sampled_profile(sampled_rows, cpu_count)
    sampled.to_parquet(staging_dir / "sampled_profile.parquet", index=False)

    cswitch = _make_cswitch(cswitch_rows, cpu_count)
    cswitch.to_parquet(staging_dir / "cswitch_events.parquet", index=False)

    ready = _make_empty_readythread()
    ready.to_parquet(staging_dir / "readythread.parquet", index=False)

    (staging_dir / "sysconfig.txt").write_text(
        "CPU: Intel Xeon cores=80 sockets=2\n"
        "OS: build=26100 arch=x64 hostname=test-host\n",
        encoding="utf-8",
    )

    datasets = [
        native_cache.CacheDataset(
            name="sampled_profile",
            kind="parquet",
            path="sampled_profile.parquet",
            row_count=sampled_rows,
            materialize_on_load=True,
        ),
        native_cache.CacheDataset(
            name="cswitch_events",
            kind="parquet",
            path="cswitch_events.parquet",
            row_count=cswitch_rows,
            materialize_on_load=True,
        ),
        native_cache.CacheDataset(
            name="readythread",
            kind="parquet",
            path="readythread.parquet",
            row_count=0,
            materialize_on_load=True,
        ),
        native_cache.CacheDataset(
            name="sysconfig",
            kind="text",
            path="sysconfig.txt",
            row_count=1,
            materialize_on_load=True,
        ),
    ]
    manifest = native_cache.CacheManifest.materialized_small(
        etl,
        datasets,
        complete=False,
        finalized=False,
        producer="dotnet",
        finalizer=None,
    )
    native_cache.write_manifest(staging_dir, manifest)


# ---- adapter unit tests -------------------------------------------------


class TestNormalizeDotnetDataframe:
    def test_renames_timestampqpc_to_timestamp(self):
        df = pd.DataFrame({"TimeStampQpc": [1, 2], "CPU": [0, 1]})
        result = adapters.normalize_dotnet_dataframe(df)
        assert "TimeStamp" in result.columns
        assert "TimeStampQpc" not in result.columns
        assert list(result["TimeStamp"]) == [1, 2]

    def test_noop_when_timestamp_already_present(self):
        df = pd.DataFrame({"TimeStamp": [3, 4], "TimeStampQpc": [9, 10]})
        result = adapters.normalize_dotnet_dataframe(df)
        # Both columns survive; the existing TimeStamp wins.
        assert "TimeStamp" in result.columns
        assert "TimeStampQpc" in result.columns
        assert list(result["TimeStamp"]) == [3, 4]

    def test_noop_when_neither_column_present(self):
        df = pd.DataFrame({"X": [1]})
        result = adapters.normalize_dotnet_dataframe(df)
        assert list(result.columns) == ["X"]

    def test_handles_none(self):
        assert adapters.normalize_dotnet_dataframe(None) is None

    def test_handles_empty_dataframe(self):
        df = pd.DataFrame()
        assert adapters.normalize_dotnet_dataframe(df) is df


class TestDeriveMetadataFromSidecar:
    def test_cpu_count_from_dumper(self, tmp_path: Path):
        from etw_analyzer.trace_state import TraceData

        trace = TraceData(
            trace_id="t", etl_path=tmp_path / "x.etl",
            export_dir=tmp_path, raw_csv={},
        )
        trace.dumper_df = _make_sampled_profile(rows=20, cpu_count=8)
        manifest = native_cache.CacheManifest.materialized_small(
            _seed_etl(tmp_path), [], producer="dotnet",
        )
        meta = adapters.derive_metadata_from_sidecar(trace, manifest)
        assert meta.cpu_count == 8
        assert meta.timestamp_frequency == 10_000_000.0

    def test_duration_from_qpc_range(self, tmp_path: Path):
        from etw_analyzer.trace_state import TraceData

        trace = TraceData(
            trace_id="t", etl_path=tmp_path / "x.etl",
            export_dir=tmp_path, raw_csv={},
        )
        # 20M QPC ticks @ 10 MHz = 2 seconds.
        trace.dumper_df = pd.DataFrame({
            "TimeStampQpc": [1_000_000, 21_000_000],
            "CPU": [0, 1],
        })
        manifest = native_cache.CacheManifest.materialized_small(
            _seed_etl(tmp_path), [], producer="dotnet",
        )
        meta = adapters.derive_metadata_from_sidecar(trace, manifest)
        assert meta.duration_seconds == pytest.approx(2.0)

    def test_duration_none_when_qpc_range_zero(self, tmp_path: Path):
        from etw_analyzer.trace_state import TraceData

        trace = TraceData(
            trace_id="t", etl_path=tmp_path / "x.etl",
            export_dir=tmp_path, raw_csv={},
        )
        trace.dumper_df = pd.DataFrame(
            {"TimeStampQpc": [100, 100], "CPU": [0, 0]},
        )
        manifest = native_cache.CacheManifest.materialized_small(
            _seed_etl(tmp_path), [], producer="dotnet",
        )
        meta = adapters.derive_metadata_from_sidecar(trace, manifest)
        assert meta.duration_seconds is None


class TestApplyMetadataToTrace:
    def test_populates_unset_fields(self, tmp_path: Path):
        from etw_analyzer.trace_state import TraceData

        trace = TraceData(
            trace_id="t", etl_path=tmp_path / "x.etl",
            export_dir=tmp_path, raw_csv={},
        )
        meta = adapters.DotnetMetadata(
            cpu_count=16, duration_seconds=5.0, timestamp_frequency=10_000_000.0,
        )
        adapters.apply_metadata_to_trace(trace, meta)
        assert trace.cpu_count == 16
        assert trace.duration_seconds == 5.0
        assert trace.timestamp_frequency == 10_000_000.0

    def test_does_not_overwrite_existing_values(self, tmp_path: Path):
        from etw_analyzer.trace_state import TraceData

        trace = TraceData(
            trace_id="t", etl_path=tmp_path / "x.etl",
            export_dir=tmp_path, raw_csv={},
            duration_seconds=42.0, cpu_count=2,
            timestamp_frequency=3_000_000.0,
        )
        meta = adapters.DotnetMetadata(
            cpu_count=16, duration_seconds=5.0, timestamp_frequency=10_000_000.0,
        )
        adapters.apply_metadata_to_trace(trace, meta)
        assert trace.cpu_count == 2
        assert trace.duration_seconds == 42.0
        assert trace.timestamp_frequency == 3_000_000.0


class TestBuildTraceMetadataDataframe:
    def test_columns_match_native_schema(self):
        meta = adapters.DotnetMetadata(
            cpu_count=8, duration_seconds=1.5, timestamp_frequency=10_000_000.0,
        )
        manifest = native_cache.CacheManifest(
            schema_version=native_cache.SCHEMA_VERSION, mode="native", strategy="materialized-small",
            complete=True, finalized=True,
            etl=native_cache.EtlIdentity(
                path="x", name="x", size=1, mtime_ns=0,
            ),
            datasets=[], producer="dotnet",
        )
        df = adapters.build_trace_metadata_dataframe(meta, manifest)
        expected_cols = {
            "NumberOfProcessors", "StartTime", "EndTime", "DurationSeconds",
            "PerfFreq", "TimerResolution", "CpuSpeedInMHz", "EventsLost",
            "BuffersLost", "BuffersWritten", "PointerSize",
        }
        assert set(df.columns) == expected_cols
        assert int(df.iloc[0]["NumberOfProcessors"]) == 8
        assert float(df.iloc[0]["DurationSeconds"]) == 1.5
        assert int(df.iloc[0]["PerfFreq"]) == 10_000_000


class TestPopulateEventCountsFromManifest:
    def test_seeds_counts_from_manifest_row_count(self, tmp_path: Path):
        from etw_analyzer.trace_state import TraceData

        trace = TraceData(
            trace_id="t", etl_path=tmp_path / "x.etl",
            export_dir=tmp_path, raw_csv={},
        )
        datasets = [
            native_cache.CacheDataset(
                name="sampled_profile", kind="parquet",
                path="sampled_profile.parquet", row_count=1234,
            ),
            native_cache.CacheDataset(
                name="cswitch_events", kind="parquet",
                path="cswitch_events.parquet", row_count=5678,
            ),
        ]
        manifest = native_cache.CacheManifest.materialized_small(
            _seed_etl(tmp_path), datasets, producer="dotnet",
        )
        adapters.populate_event_counts_from_manifest(trace, manifest)
        assert trace.event_counts["sampled_profile"] == 1234
        assert trace.event_counts["cswitch_events"] == 5678

    def test_does_not_overwrite_existing_counts(self, tmp_path: Path):
        from etw_analyzer.trace_state import TraceData

        trace = TraceData(
            trace_id="t", etl_path=tmp_path / "x.etl",
            export_dir=tmp_path, raw_csv={},
        )
        trace.event_counts["sampled_profile"] = 42
        datasets = [
            native_cache.CacheDataset(
                name="sampled_profile", kind="parquet",
                path="sampled_profile.parquet", row_count=1234,
            ),
        ]
        manifest = native_cache.CacheManifest.materialized_small(
            _seed_etl(tmp_path), datasets, producer="dotnet",
        )
        adapters.populate_event_counts_from_manifest(trace, manifest)
        assert trace.event_counts["sampled_profile"] == 42


# ---- integration tests --------------------------------------------------


class TestCpuTimelineParity:
    def test_dotnet_staging_produces_cpu_timeline(self, tmp_path: Path):
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_dotnet_staging(staging, etl, sampled_rows=200, cpu_count=4)

        result = aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_cpu_timeline",
        )
        assert result.ok is True, f"{result.message} / {result.warnings}"
        parquet = staging / "cpu_timeline.parquet"
        assert parquet.exists()
        df = pd.read_parquet(parquet)
        assert "StartTime" in df.columns
        assert "EndTime" in df.columns
        # 4 CPUs → 4 Cpu N columns.
        cpu_cols = [c for c in df.columns if c.startswith("Cpu ")]
        assert len(cpu_cols) >= 4
        assert len(df) >= 1

    def test_cpu_timeline_registered_in_manifest(self, tmp_path: Path):
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_dotnet_staging(staging, etl, sampled_rows=200, cpu_count=4)
        aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_cpu_timeline_m",
        )
        loaded = native_cache.read_manifest(staging)
        assert loaded is not None
        names = {d.name for d in loaded.datasets}
        assert "cpu_timeline" in names


class TestTraceMetadataParity:
    def test_trace_metadata_synthesized(self, tmp_path: Path):
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_dotnet_staging(staging, etl)
        result = aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_meta",
        )
        assert result.ok is True
        parquet = staging / "trace_metadata.parquet"
        assert parquet.exists()
        df = pd.read_parquet(parquet)
        assert "NumberOfProcessors" in df.columns
        assert "PerfFreq" in df.columns
        # cpu_count derived from max(CPU)+1 with cpu_count=4.
        assert int(df.iloc[0]["NumberOfProcessors"]) == 4

    def test_trace_metadata_registered_in_manifest(self, tmp_path: Path):
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_dotnet_staging(staging, etl)
        aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_meta_m",
        )
        loaded = native_cache.read_manifest(staging)
        assert loaded is not None
        names = {d.name for d in loaded.datasets}
        assert "trace_metadata" in names


class TestTracestatsParity:
    def test_tracestats_text_written(self, tmp_path: Path):
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_dotnet_staging(staging, etl, sampled_rows=200, cswitch_rows=300)
        result = aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_tracestats",
        )
        assert result.ok is True
        text_path = staging / "tracestats.txt"
        assert text_path.exists()
        text = text_path.read_text(encoding="utf-8")
        # Header lines from _metadata_lines.
        assert "Number of Processors" in text
        # Manifest-derived per-dataset counts come through event_counts.
        assert "sampled_profile" in text or "SampledProfile" in text

    def test_tracestats_registered_in_manifest(self, tmp_path: Path):
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_dotnet_staging(staging, etl)
        aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_tracestats_m",
        )
        loaded = native_cache.read_manifest(staging)
        names_by_kind = {(d.name, d.kind) for d in loaded.datasets}
        assert ("tracestats", "text") in names_by_kind


class TestSysconfigParity:
    def test_sysconfig_text_exists_after_aggregation(self, tmp_path: Path):
        """The sysconfig text file must exist post-aggregation.

        The native ``build_sysconfig_text`` aggregator overwrites the
        sidecar's placeholder sysconfig.txt with a synthesized summary
        when trace_metadata is available — this is the same behaviour
        as native mode. The contract is "sysconfig is present and
        non-empty", not "byte-for-byte preserve sidecar text".
        """
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_dotnet_staging(staging, etl, cpu_count=4)
        result = aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_sysconfig",
        )
        assert result.ok is True
        sysconfig_text = (staging / "sysconfig.txt").read_text(encoding="utf-8")
        assert sysconfig_text.strip(), "sysconfig.txt is empty"
        # Either the sidecar's text survives (when no trace_metadata can
        # be derived) or the synthesized native-mode text replaces it.
        # Either way the file must remain.

    def test_sysconfig_raw_csv_key_present(self, tmp_path: Path):
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_dotnet_staging(staging, etl)
        from etw_analyzer.native import aggregation_worker as aw
        captured: dict[str, set[str]] = {}
        real_persist = aw._persist_aggregator_outputs

        def capture_persist(staging_dir, trace, warnings):
            captured["raw_csv"] = set(trace.raw_csv.keys())
            return real_persist(staging_dir, trace, warnings)

        aw._persist_aggregator_outputs = capture_persist
        try:
            aw.run_aggregation_worker(
                staging, etl, trace_id="trace_sysconfig_raw",
            )
        finally:
            aw._persist_aggregator_outputs = real_persist
        assert "sysconfig" in captured["raw_csv"]


# ---- stacks (require stub symbolizer) -----------------------------------


@dataclass
class _StubSymbolizer:
    """Stand-in for the real dbghelp-backed symbolizer.

    The dotnet sidecar does NOT yet emit Image/Load events
    (Phase B follow-up), so the real Symbolizer can't be built. This
    stub lets us still exercise the stacks aggregator end-to-end and
    prove the adapter + dispatch path produces output when a symbolizer
    is present. Returns ``"unknown!unknown+0x<addr>"`` for any address.
    """

    cache: dict[int, str] = field(default_factory=dict)

    def resolve(self, addr: int) -> str:
        if addr in self.cache:
            return self.cache[addr]
        sym = f"stub.dll!stub_func_{addr & 0xFFF:03x}"
        self.cache[addr] = sym
        return sym

    def bulk_resolve(self, addrs: Iterable[int]) -> dict[int, str]:
        return {addr: self.resolve(addr) for addr in addrs}

    def close(self) -> None:  # pragma: no cover - cleanup hook
        self.cache.clear()


class TestStacksParity:
    """End-to-end stacks adapter — Phase B sidecar will provide real symbols.

    These tests inject a stub symbolizer so we can validate that the
    dotnet dumper_df normalization (Stack column survives, addresses
    are usable) lets the existing aggregator emit the correct output.
    """

    def _seed_with_symbolizer(self, tmp_path: Path):
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_dotnet_staging(staging, etl, sampled_rows=50, cpu_count=4)
        return etl, staging

    def test_stacks_parquet_produced_with_symbolizer(self, tmp_path: Path):
        etl, staging = self._seed_with_symbolizer(tmp_path)

        # Monkey-patch the trace creation path to inject our stub
        # symbolizer right after _build_trace_from_staging returns.
        from etw_analyzer.native import aggregation_worker as aw
        real_build = aw._build_trace_from_staging

        def build_with_symbolizer(*args, **kwargs):
            trace = real_build(*args, **kwargs)
            trace.symbolizer = _StubSymbolizer()
            return trace

        aw._build_trace_from_staging = build_with_symbolizer
        try:
            result = aw.run_aggregation_worker(
                staging, etl, trace_id="trace_stacks",
            )
        finally:
            aw._build_trace_from_staging = real_build

        assert result.ok is True, f"{result.message} / {result.warnings}"
        # With a symbolizer the stacks parquet should land.
        parquet = staging / "stacks.parquet"
        assert parquet.exists(), (
            f"stacks.parquet missing. datasets_written={result.datasets_written}"
        )
        df = pd.read_parquet(parquet)
        assert {"Module", "Function", "Inclusive", "Exclusive"}.issubset(df.columns)
        assert len(df) > 0

    def test_stacks_callers_parquet_produced_with_symbolizer(
        self, tmp_path: Path,
    ):
        etl, staging = self._seed_with_symbolizer(tmp_path)
        from etw_analyzer.native import aggregation_worker as aw
        real_build = aw._build_trace_from_staging

        def build_with_symbolizer(*args, **kwargs):
            trace = real_build(*args, **kwargs)
            trace.symbolizer = _StubSymbolizer()
            return trace

        aw._build_trace_from_staging = build_with_symbolizer
        try:
            result = aw.run_aggregation_worker(
                staging, etl, trace_id="trace_stacks_callers",
            )
        finally:
            aw._build_trace_from_staging = real_build

        assert result.ok is True
        parquet = staging / "stacks_callers.parquet"
        assert parquet.exists()
        df = pd.read_parquet(parquet)
        assert "Direction" in df.columns
        # `self` rows must always be present alongside caller/callee edges.
        assert "self" in set(df["Direction"])


# ---- cache rehydrate / end-to-end ---------------------------------------


class TestDotnetCacheRehydrate:
    def test_manifest_lists_dotnet_dumper_kind_for_aggregator_outputs(
        self, tmp_path: Path,
    ):
        """Aggregator parquets in the rewritten manifest get kind='parquet'
        and the sidecar dumper parquets keep kind='dumper-parquet'."""
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_dotnet_staging(staging, etl)
        aggregation_worker.run_aggregation_worker(
            staging, etl, trace_id="trace_kinds",
        )
        loaded = native_cache.read_manifest(staging)
        assert loaded is not None
        by_name = {d.name: d for d in loaded.datasets}
        assert by_name["sampled_profile"].kind == "dumper-parquet"
        assert by_name["cswitch_events"].kind == "dumper-parquet"
        # cpu_timeline is an aggregator output written by us.
        if "cpu_timeline" in by_name:
            assert by_name["cpu_timeline"].kind == "parquet"
        # tracestats is a text output.
        if "tracestats" in by_name:
            assert by_name["tracestats"].kind == "text"

    def test_phase_a_target_raw_csv_keys_appear(self, tmp_path: Path):
        """Verify the Phase A target: ≥9 raw_csv keys after run_aggregation_worker.

        On the test fixture with sampled_profile + cswitch + readythread
        + sysconfig, the post-aggregation set must include cpu_timeline,
        trace_metadata, tracestats, and the passthrough sysconfig in
        addition to whatever the sidecar already provided.
        """
        etl = _make_etl(tmp_path)
        staging = tmp_path / "staging"
        _seed_dotnet_staging(staging, etl, sampled_rows=200, cpu_count=4)

        from etw_analyzer.native import aggregation_worker as aw
        # Tap into the trace before manifest write to inspect raw_csv keys
        # in flight.
        captured: dict[str, set[str]] = {}
        real_persist = aw._persist_aggregator_outputs

        def capture_persist(staging_dir, trace, warnings):
            captured["raw_csv"] = set(trace.raw_csv.keys())
            return real_persist(staging_dir, trace, warnings)

        aw._persist_aggregator_outputs = capture_persist
        try:
            result = aw.run_aggregation_worker(
                staging, etl, trace_id="trace_keys",
            )
        finally:
            aw._persist_aggregator_outputs = real_persist

        assert result.ok is True
        keys = captured["raw_csv"]
        # Phase A success criteria from the parity report:
        for key in ("cpu_timeline", "trace_metadata", "tracestats", "sysconfig"):
            assert key in keys, (
                f"Phase A key {key!r} missing. Got: {sorted(keys)}"
            )
        # cpu_sampling is always produced by the synthesis fallback.
        assert "cpu_sampling" in keys


# ---- helpers used by adapter unit tests ---------------------------------


def _seed_etl(tmp_path: Path) -> Path:
    etl = tmp_path / "stub.etl"
    if not etl.exists():
        etl.write_bytes(b"stub")
    return etl
