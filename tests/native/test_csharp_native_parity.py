"""Cross-producer parity test: csharp sidecar vs native in-process consumer.

This test is opt-in via ``--run-parity``. It runs the same real ETL through
both the C# sidecar and the native ``OpenTraceW`` consumer and asserts that
the resulting datasets agree on row counts within published tolerances.
Aggregator-by-aggregator drift is what the test pins down — small drift is
acceptable for the streaming-heavy aggregators (DPCs, timelines) where
chunking decisions can move counts by a row or two, but the core data
(cpu_sampling, process_info) must match exactly.

Invocation::

    uv run --group dev pytest tests/native/test_csharp_native_parity.py \\
        --run-parity -v

The test silently skips unless **all** of:

* ``--run-parity`` was passed on the command line, AND
* the platform is Windows (``os.name == "nt"``), AND
* ``find_csharp_sidecar()`` returns a binary (env var or PATH), AND
* a real fixture ETL is reachable at ``WPR_MCP_CSHARP_E2E_FIXTURE`` or the
  default ``C:\\git\\wpr-mcp-poc-staging\\real-fixture\\spike-fixture.etl``.

Tolerances (P2 D2):

* ``process_info``: **exact** row-count match.
* ``cpu_sampling``: **±30%** relative — currently observes ~23% drift on
  the real fixture; the harness keeps it as a smoke check at a wider
  bound while the upstream attribution difference is investigated
  separately.
* ``dpc_isr``, ``cpu_timeline``: **±5%** relative.
* ``stacks``, ``stacks_callers``: **±10%** relative.
* Everything else (``raw_csv`` dumper stems): warned, not failed — drift
  is logged but does not fail the test.

The test stages two independent copies of the ETL (one per mode) under
``tmp_path`` so the side-by-side caches don't collide. The csharp pipeline
emits ``producer="csharp"`` parquets; the native pipeline emits
``producer="native"``. Both share the v3 manifest schema.
"""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path
from typing import Iterable

import pytest

from etw_analyzer import trace_state
from etw_analyzer.tools import trace_mgmt


_REAL_FIXTURE_ENV = "WPR_MCP_CSHARP_E2E_FIXTURE"
_REAL_FIXTURE_DEFAULT = (
    r"C:\git\wpr-mcp-poc-staging\real-fixture\spike-fixture.etl"
)

_EXACT_DATASETS: tuple[str, ...] = (
    "process_info",
)
_TOLERANT_DATASETS: dict[str, float] = {
    # cpu_sampling: same Python aggregator runs in both pipelines; tolerance
    # absorbs at-most a handful of rows that vary between "Unknown" /
    # resolved-module attribution on the kernel-space sample fraction.
    # See manager-log/sampledprofile-attribution-finding.md for the bug
    # that caused this to drift to -23% before being fixed by the
    # sampled_profile + thread column adapters.
    "cpu_sampling": 0.05,
    "dpc_isr": 0.05,
    "cpu_timeline": 0.05,
    "stacks": 0.10,
    "stacks_callers": 0.10,
}

# Streaming-mode peak-RSS ceiling. The sidecar's event-store-streaming
# strategy must stay under this when processing the spike fixture; the
# smoke test enforces the same number on the csharp side and the parity
# gate doubles as a perf regression guardrail on the python+csharp pair.
_STREAMING_RSS_CEILING_MB = 2_500.0


def _resolve_real_fixture() -> Path | None:
    candidate = os.environ.get(_REAL_FIXTURE_ENV, _REAL_FIXTURE_DEFAULT)
    if not candidate:
        return None
    path = Path(candidate)
    return path if path.exists() else None


def _stage_etl_copy(src: Path, dst_dir: Path) -> Path:
    """Stage a copy of ``src`` under ``dst_dir`` so each mode gets its own
    cache directory.

    Tries hard-link first (instant, no extra disk), falls back to copy if
    the link fails (cross-volume, ReFS dedup, etc.). The destination ETL
    keeps the same stem so ``.etw-export-<stem>`` is identical between
    modes; the parent directory differs, so the two caches are isolated.
    """

    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / src.name
    if dst.exists():
        return dst
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)
    return dst


def _row_counts(raw_csv: dict) -> dict[str, int]:
    """Map dataset name → row count for every populated dataset."""
    return {name: int(len(df)) for name, df in raw_csv.items()}


def _format_drift_table(
    csharp_counts: dict[str, int],
    native_counts: dict[str, int],
) -> str:
    keys = sorted(set(csharp_counts) | set(native_counts))
    lines = ["| dataset | csharp | native | delta | drift% |", "|---|---:|---:|---:|---:|"]
    for k in keys:
        c = csharp_counts.get(k, 0)
        n = native_counts.get(k, 0)
        delta = c - n
        if n > 0:
            drift = (c - n) / n * 100.0
            drift_s = f"{drift:+.2f}"
        elif c > 0:
            drift_s = "+inf"
        else:
            drift_s = "0.00"
        lines.append(f"| {k} | {c:,} | {n:,} | {delta:+,} | {drift_s} |")
    return "\n".join(lines)


def _assert_exact(
    name: str,
    csharp_counts: dict[str, int],
    native_counts: dict[str, int],
    errors: list[str],
) -> None:
    c = csharp_counts.get(name)
    n = native_counts.get(name)
    if c is None and n is None:
        return  # neither pipeline produced it; not a parity failure
    if c is None or n is None:
        errors.append(
            f"{name}: only one mode produced this dataset (csharp={c}, native={n})"
        )
        return
    if c != n:
        errors.append(
            f"{name}: exact match required; csharp={c:,} native={n:,} delta={c - n:+,}"
        )


def _assert_within(
    name: str,
    tolerance: float,
    csharp_counts: dict[str, int],
    native_counts: dict[str, int],
    errors: list[str],
) -> None:
    c = csharp_counts.get(name)
    n = native_counts.get(name)
    if c is None and n is None:
        return
    if c is None or n is None:
        # Tolerant datasets are allowed to be missing on either side.
        return
    if n == 0:
        if c != 0:
            errors.append(
                f"{name}: native produced 0 rows but csharp produced {c:,}"
            )
        return
    drift = abs(c - n) / float(n)
    if drift > tolerance:
        errors.append(
            f"{name}: drift {drift * 100:.2f}% exceeds tolerance {tolerance * 100:.0f}%; "
            f"csharp={c:,} native={n:,}"
        )


def _load_via(
    mode: str,
    etl_path: Path,
) -> tuple[str, dict[str, int], list[str], float, float]:
    """Run ``load_trace`` for the given mode and return (trace_id,
    row_counts, export_errors, wall_seconds, peak_rss_mb).

    ``peak_rss_mb`` is best-effort — only the csharp pipeline reports it
    (the sidecar fills ``performance.peak_rss_mb`` in its terminal
    ``result`` JSONL line). For native mode this returns 0.0.
    """

    import psutil

    proc = psutil.Process(os.getpid())
    rss_before_mb = proc.memory_info().rss / (1024 * 1024)
    rss_peak_mb = rss_before_mb

    t0 = time.monotonic()
    summary = trace_mgmt.load_trace(str(etl_path), mode=mode, force=True)
    wall_s = time.monotonic() - t0

    # Best-effort post-hoc peak: sample after load, take the max with the
    # pre-load value. The sidecar runs out-of-process so its peak isn't in
    # python RSS; the streaming smoke test inside the sidecar already
    # enforces the ceiling there. For native mode this catches in-process
    # blowups.
    rss_after_mb = proc.memory_info().rss / (1024 * 1024)
    rss_peak_mb = max(rss_peak_mb, rss_after_mb)

    if "Trace ID:" not in summary:
        pytest.fail(f"load_trace({mode!r}) failed:\n{summary}")
    # Parse trace_id out of the markdown summary.
    import re
    m = re.search(r"Trace ID:\*\* `([^`]+)`", summary)
    assert m is not None, f"could not parse trace_id from summary:\n{summary}"
    trace_id = m.group(1)

    trace = trace_state.require_trace(trace_id)
    counts = _row_counts(trace.raw_csv)
    errors = list(trace.export_errors)

    # Wait for the background dumper on native mode so the comparison is
    # against a complete dataset, not the streaming subset.
    if mode == "native":
        trace.wait_for_dumper()
        counts = _row_counts(trace.raw_csv)
        errors = list(trace.export_errors)

    return trace_id, counts, errors, wall_s, rss_peak_mb


@pytest.mark.parity
def test_csharp_vs_native_row_count_parity_real_fixture(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run the real fixture through csharp and native and pin the
    aggregator-by-aggregator row-count drift within published tolerances.
    """

    if os.name != "nt":
        pytest.skip("csharp sidecar is Windows-only")

    from etw_analyzer.native.config import find_csharp_sidecar

    if find_csharp_sidecar() is None:
        pytest.skip(
            "C# sidecar binary not locatable (set WPR_MCP_CSHARP_SIDECAR or "
            "place wpr-mcp-extract.exe on PATH)"
        )

    fixture = _resolve_real_fixture()
    if fixture is None:
        pytest.skip(
            f"set {_REAL_FIXTURE_ENV} to a real ETL or place one at "
            f"{_REAL_FIXTURE_DEFAULT}"
        )

    # Confirm psutil is available — we need it for the RSS sanity check.
    try:
        import psutil  # noqa: F401
    except ImportError:  # pragma: no cover — psutil is a dev-group dep
        pytest.skip("psutil is required for the parity test's RSS check")

    # The real fixture is ~1 GB; the native pipeline's default safety
    # limit is 512 MB. The parity test deliberately runs the same large
    # fixture through both producers, so opt out of the guardrail for
    # this run only (monkeypatch restores it at teardown).
    monkeypatch.setenv("WPR_MCP_NATIVE_ALLOW_LARGE", "1")

    csharp_dir = tmp_path / "csharp"
    native_dir = tmp_path / "native"
    csharp_etl = _stage_etl_copy(fixture, csharp_dir)
    native_etl = _stage_etl_copy(fixture, native_dir)

    # Snapshot trace registry so the parity load doesn't leak into other
    # tests in the same pytest session.
    trace_state.clear_traces()

    csharp_trace_id, csharp_counts, csharp_errors, csharp_wall, csharp_rss = _load_via(
        "csharp", csharp_etl
    )
    native_trace_id, native_counts, native_errors, native_wall, native_rss = _load_via(
        "native", native_etl
    )

    drift_table = _format_drift_table(csharp_counts, native_counts)
    print("\n=== csharp vs native row-count drift ===")
    print(f"csharp wall: {csharp_wall:.1f}s   native wall: {native_wall:.1f}s")
    print(drift_table)
    if csharp_errors:
        print("\ncsharp export_errors:")
        for e in csharp_errors:
            print(f"  - {e}")
    if native_errors:
        print("\nnative export_errors:")
        for e in native_errors:
            print(f"  - {e}")

    failures: list[str] = []
    for name in _EXACT_DATASETS:
        _assert_exact(name, csharp_counts, native_counts, failures)
    for name, tol in _TOLERANT_DATASETS.items():
        _assert_within(name, tol, csharp_counts, native_counts, failures)

    # D5: streaming-mode peak RSS sanity. csharp sidecar is the one whose
    # streaming path we're guarding; we measure the python process's peak
    # as a proxy for "nothing got hauled into Python memory wholesale".
    # The sidecar's own RSS is enforced by its smoke test.
    if csharp_rss > _STREAMING_RSS_CEILING_MB:
        failures.append(
            f"python RSS during csharp load reached {csharp_rss:.0f} MB, "
            f"exceeds streaming ceiling {_STREAMING_RSS_CEILING_MB:.0f} MB"
        )

    if failures:
        msg = (
            "csharp/native parity failed:\n"
            + "\n".join(f"  * {f}" for f in failures)
            + "\n\nrow-count drift table:\n"
            + drift_table
        )
        pytest.fail(msg)

    # Cleanup — drop both traces so we don't leak parquets between tests.
    trace_state.unregister_trace(csharp_trace_id)
    trace_state.unregister_trace(native_trace_id)
