"""Real-ETL integration test for the dotnet sidecar ReadyThread + CSwitch path.

Issue #7: the dotnet sidecar extracted 0 ReadyThread events even though the
ETL contains them, because ``_wantReady`` was never enabled (ReadyThread is
absent from ``_DUMPER_EVENT_CLASSES``). The fix activates ReadyThread whenever
CSwitch is requested (same kernel scheduler group).

This exercises the built ``etw-extract.exe`` end to end against a real trace
and asserts:
  * readythread.parquet has > 0 rows (issue #7), and
  * every CSwitch event carries a paired Stack (issues #6/#5 — the QPC
    timestamp-only fallback in PendingStackBuffer).

It is gated behind ``@pytest.mark.slow`` (multi-100MB trace, ~60s run) and is
skipped automatically when the built sidecar binary or the lab ETL is absent,
so it never breaks a default ``pytest`` run on a dev box without the fixtures.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pyarrow.parquet as pq
import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REAL_ETL = Path(r"C:\traces\mmsg-stacks.etl")
_EVENT_CLASSES = [
    "SampledProfile", "CSwitch", "ReadyThread",
    "TcpIp/Recv", "TcpIp/Send", "UdpIp/Recv", "UdpIp/Send",
    "SystemConfig",
]


def _find_sidecar_exe() -> Path | None:
    candidates = list(
        (_REPO_ROOT / "dotnet").glob("**/win-x64/etw-extract.exe")
    ) + list((_REPO_ROOT / "dotnet").glob("**/etw-extract.exe"))
    for exe in candidates:
        if exe.is_file():
            return exe
    return None


@pytest.mark.slow
def test_sidecar_extracts_readythread_and_paired_cswitch_stacks(tmp_path: Path):
    exe = _find_sidecar_exe()
    if exe is None:
        pytest.skip("etw-extract.exe not built; run `dotnet build -c Release` in dotnet/")
    if not _REAL_ETL.exists():
        pytest.skip(f"real ETL fixture not present: {_REAL_ETL}")

    staging = tmp_path / "staging"
    staging.mkdir()
    request = tmp_path / "request.json"
    request.write_text(json.dumps({
        "version": 1,
        "trace_id": "it-readythread",
        "etl_path": str(_REAL_ETL),
        "staging_dir": str(staging),
        "strategy": "materialized-small",
        "requested_event_classes": _EVENT_CLASSES,
        "symbol_path": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols",
        "max_etl_mb": 2048,
        "heartbeat_interval_ms": 5000,
        "log_level": "info",
        "include_tracelogging": False,
    }), encoding="utf-8")

    env = {"ETW_MCP_NATIVE_ALLOW_LARGE": "1"}
    proc = subprocess.run(
        [str(exe), "--request", str(request)],
        cwd=str(_REPO_ROOT / "dotnet"),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=300,
        env={**__import__("os").environ, **env},
    )
    result = None
    for line in proc.stdout.splitlines():
        if line.startswith('{"type":"result"'):
            result = json.loads(line)
    assert result is not None, f"sidecar produced no result line (exit={proc.returncode})"
    assert result.get("ok") is True, f"sidecar failed: {result}"

    # Issue #7 — ReadyThread events must now be extracted (was 0 pre-fix).
    rt_path = staging / "readythread.parquet"
    assert rt_path.exists(), "readythread.parquet missing"
    rt_rows = pq.ParquetFile(rt_path).metadata.num_rows
    assert rt_rows > 0, "ReadyThread extracted 0 rows (issue #7 regression)"

    # Issues #6/#5 — every CSwitch event should carry a paired Stack via the
    # QPC timestamp-only fallback (CSwitch registers NewTid but its trailing
    # StackWalk carries a different TID, so exact-key pairing always missed).
    cs_path = staging / "cswitch_events.parquet"
    assert cs_path.exists(), "cswitch_events.parquet missing"
    cs = pq.read_table(cs_path)
    assert cs.num_rows > 0
    stacks = cs.column("Stack").to_pylist()
    paired = sum(1 for s in stacks if s is not None and len(s) > 0)
    pair_rate = paired / len(stacks)
    assert pair_rate > 0.5, f"CSwitch stack pairing only {pair_rate:.1%} (issue #5 regression)"

    # Issue #6 — pending-buffer eviction loss must stay well under the 24%
    # baseline that motivated the capacity + fallback fix.
    perf = result.get("performance", {})
    rate = perf.get("stack_pairing_rate")
    if rate is not None:
        assert rate > 0.76, f"overall stack pairing {rate:.1%} below 76% (issue #6 regression)"
