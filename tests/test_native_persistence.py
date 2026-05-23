"""Regression tests for native-mode dumper parquet persistence.

These cover the Phase N5 follow-up fixes (see
``udp-perf/docs/wpr-mcp-native-etw-verification.md`` §"Residual Issues"):

* Issue 2: ``cswitch_events.parquet`` failed to write because the
  ``Stack`` column held tuples of uint64 kernel addresses that pyarrow
  silently fell over on (``OverflowError: int too big to convert``).
  The write exception was swallowed in ``_extract``, stranding the
  in-memory DataFrame and producing "No CSwitch events available" on
  any cache-rehydrated load.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer.tools.trace_mgmt import _persist_dumper_parquet


def test_persist_dumper_parquet_handles_uint64_stack_addresses(tmp_path: Path):
    """Stack column tuples may contain kernel-mode addresses that exceed
    signed ``int64`` (e.g. ``0xfffff806b0597655``). The helper must
    coerce them to a uint64-safe representation before writing parquet
    so the round-trip succeeds and the data survives a cache reload.
    """
    df = pd.DataFrame({
        "TimeStamp": [4250801900077, 4250801900928, 4250801910466],
        "NewTID": [3388, 0, 3388],
        "NewPID": [4, 0, 4],
        "WaitReason": ["Executive", "Executive", "Executive"],
        "Stack": [
            (0xFFFFF806B0597655, 0xFFFFF806B05A2CFF, 0xFFFFF806B0AC0BCD),
            None,
            (0xFFFFF806B0597655,),
        ],
    })

    out_path = tmp_path / "cswitch_events.parquet"
    _persist_dumper_parquet(df, out_path)

    assert out_path.exists(), "parquet file must be written"
    assert out_path.stat().st_size > 0

    # Round-trip: read back and confirm the high-bit addresses survive.
    round_trip = pd.read_parquet(out_path)
    assert len(round_trip) == 3
    assert round_trip["NewTID"].tolist() == [3388, 0, 3388]
    assert round_trip["WaitReason"].tolist() == ["Executive"] * 3

    # The non-None stacks must round-trip with their high addresses intact.
    first_stack = round_trip.iloc[0]["Stack"]
    assert first_stack is not None
    assert int(first_stack[0]) == 0xFFFFF806B0597655
    assert int(first_stack[1]) == 0xFFFFF806B05A2CFF

    second_stack = round_trip.iloc[1]["Stack"]
    # ``None`` round-trips as either None or an empty list — both are
    # acceptable as long as the read path doesn't crash.
    if second_stack is not None:
        assert len(second_stack) == 0


def test_persist_dumper_parquet_no_stack_column_is_passthrough(tmp_path: Path):
    """When the DataFrame doesn't have a Stack column the helper is just
    a thin wrapper around ``to_parquet``. Critical to make sure the
    helper isn't accidentally column-specific."""
    df = pd.DataFrame({
        "TimeStamp": [1, 2, 3],
        "Value": [10, 20, 30],
    })
    out_path = tmp_path / "no_stack.parquet"
    _persist_dumper_parquet(df, out_path)
    round_trip = pd.read_parquet(out_path)
    assert round_trip.equals(df)
