"""Pin the load-telemetry contract.

The ``etw_analyzer.native.telemetry`` logger emits one INFO-level record
per phase of the trace-load pipeline. These tests use ``caplog`` to capture
the records and assert on the event names + key fields. The format is
deliberately ``event=<name> key=value ...`` text (not JSON) so operators
can grep it directly; the tests grep the same way the operators do.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from etw_analyzer.native import telemetry


def _records(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        rec.getMessage()
        for rec in caplog.records
        if rec.name == telemetry.LOGGER_NAME
    ]


def _events(caplog: pytest.LogCaptureFixture) -> list[str]:
    out = []
    for msg in _records(caplog):
        tokens = msg.split(" ", 1)
        if not tokens:
            continue
        head = tokens[0]
        if head.startswith("event="):
            out.append(head.removeprefix("event="))
    return out


def test_format_value_renders_common_types_safely():
    assert telemetry.format_value(None) == "-"
    assert telemetry.format_value(True) == "true"
    assert telemetry.format_value(False) == "false"
    assert telemetry.format_value(42) == "42"
    assert telemetry.format_value(3.14159) == "3.142"
    assert telemetry.format_value(Path(r"C:\tmp\fixture.etl")) == r"C:\tmp\fixture.etl"
    assert telemetry.format_value("simple") == "simple"
    # Whitespace + equals get quoted so the line keeps tokenising.
    assert telemetry.format_value("with space") == '"with space"'
    assert telemetry.format_value("k=v") == '"k=v"'
    # Embedded newlines/control chars are collapsed to single spaces.
    assert telemetry.format_value("line\nwith\rnewline") == '"line with newline"'


def test_emit_includes_event_and_named_fields(caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.INFO, logger=telemetry.LOGGER_NAME)
    telemetry.emit(
        telemetry.EVENT_LOAD_START,
        mode="csharp",
        trace_id="trace_abc",
        etl_size_mb=1024.5,
    )
    records = _records(caplog)
    assert len(records) == 1
    msg = records[0]
    assert msg.startswith("event=load.start ")
    assert "mode=csharp" in msg
    assert "trace_id=trace_abc" in msg
    assert "etl_size_mb=1024.500" in msg


def test_emit_with_orders_mode_and_trace_id_first(caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.INFO, logger=telemetry.LOGGER_NAME)
    telemetry.emit_with(
        telemetry.EVENT_CSHARP_RESULT,
        mode="csharp",
        trace_id="trace_xyz",
        peak_rss_mb=2300.4,
        events_per_second=1_250_000,
    )
    msg = _records(caplog)[0]
    # The output uses dict ordering for the remaining fields, but
    # ``mode`` and ``trace_id`` must come first.
    tokens = msg.split(" ")
    assert tokens[0] == "event=csharp.result"
    assert tokens[1] == "mode=csharp"
    assert tokens[2] == "trace_id=trace_xyz"


def test_emit_with_omits_optional_anchors(caplog: pytest.LogCaptureFixture):
    """When ``mode``/``trace_id`` aren't passed, they don't appear at all."""

    caplog.set_level(logging.INFO, logger=telemetry.LOGGER_NAME)
    telemetry.emit_with(telemetry.EVENT_LOAD_COMPLETE, wall_seconds=42.0)
    msg = _records(caplog)[0]
    assert "mode=" not in msg
    assert "trace_id=" not in msg


def test_emit_silenced_when_logger_below_info(caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.WARNING, logger=telemetry.LOGGER_NAME)
    telemetry.emit(telemetry.EVENT_LOAD_START, mode="csharp")
    assert _records(caplog) == []


def test_known_events_covers_every_constant():
    """Every ``EVENT_*`` constant in the module must be in ``KNOWN_EVENTS``."""

    constants = {
        getattr(telemetry, name)
        for name in dir(telemetry)
        if name.startswith("EVENT_")
    }
    assert constants == set(telemetry.KNOWN_EVENTS)


def test_load_trace_emits_start_and_complete_for_xperf_missing_path(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
):
    """``load_trace`` short-circuits on a missing ETL — before any phase log
    fires — so the only record should be... nothing. That's a smoke test
    that the early-return paths don't accidentally emit. The positive case
    (real ETL → full event stream) is exercised by the parity test under
    ``--run-parity``."""

    from etw_analyzer.tools import trace_mgmt

    caplog.set_level(logging.INFO, logger=telemetry.LOGGER_NAME)
    result = trace_mgmt.load_trace(str(tmp_path / "does-not-exist.etl"))
    assert "File not found" in result
    assert _records(caplog) == []


def test_load_trace_emits_start_for_existing_etl_then_error(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """When the file exists and the suffix check passes, ``load.start``
    fires before mode resolution. We don't drive the full load (that
    requires xperf or the sidecar); we just verify the start event lands
    with the right shape.

    A 4 KB stub ETL is enough for the existence + suffix gate and the
    ``stat().st_size`` formatting; we then expect the load to fail at a
    later stage because the file isn't a real ETL — that's fine for this
    test, we only care about the ``load.start`` record."""

    from etw_analyzer.tools import trace_mgmt

    stub = tmp_path / "stub.etl"
    stub.write_bytes(b"\0" * 4096)

    # Force xperf mode + no xperf on PATH → fails fast with a clean error
    # message, without doing any actual extraction. We just want to see
    # the load.start event before the error.
    monkeypatch.setattr(
        "etw_analyzer.parsing.wpa_exporter.find_xperf",
        lambda: None,
    )
    monkeypatch.setattr(
        "etw_analyzer.tools.trace_mgmt.find_xperf",
        lambda: None,
    )
    caplog.set_level(logging.INFO, logger=telemetry.LOGGER_NAME)

    result = trace_mgmt.load_trace(str(stub), mode="xperf")
    # Result should be the xperf-not-found bail-out OR a successful load —
    # depending on whether xperf is monkeypatched effectively. Either way,
    # load.start must have fired.
    events = _events(caplog)
    assert telemetry.EVENT_LOAD_START in events, (
        f"load.start not in {events!r}, result={result!r}"
    )

    # The load.start record must include mode + etl_path + etl_size_mb.
    start_record = next(
        rec for rec in _records(caplog) if rec.startswith("event=load.start ")
    )
    assert "mode=xperf" in start_record
    assert "etl_size_mb=0.004" in start_record
    assert "stub.etl" in start_record


def test_csharp_phase_telemetry_via_mocked_supervisor(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """End-to-end-ish telemetry coverage for the csharp pipeline using the
    mocked-sidecar pattern from ``test_csharp_worker_supervisor.py``.

    Runs ``run_csharp_worker_extraction`` with a fake process_runner +
    aggregation_runner, then asserts the full event sequence:

        csharp.spawn → csharp.child_exit → csharp.result → csharp.cache_validate
        → csharp.aggregation_start → csharp.aggregation_done → csharp.cache_promote
    """

    import importlib

    # Import the worker supervisor module and its NativeWorkerResult.
    supervisor = importlib.import_module(
        "etw_analyzer.native.worker_supervisor"
    )
    aggregation_worker = importlib.import_module(
        "etw_analyzer.native.aggregation_worker"
    )
    cache_mod = importlib.import_module("etw_analyzer.native.cache")
    test_supervisor = importlib.import_module(
        "tests.native.test_csharp_worker_supervisor"
    )

    etl = tmp_path / "fixture.etl"
    etl.write_bytes(b"\0" * 8192)
    export_dir = tmp_path / "export"
    staging_setup = test_supervisor._seed_sidecar_outputs

    # Force the in-tree sidecar lookup to return a stub path (its absence
    # would raise ValueError before any telemetry fires).
    sidecar_stub = tmp_path / "wpr-mcp-extract.exe"
    sidecar_stub.write_bytes(b"stub")
    monkeypatch.setattr(supervisor, "find_csharp_sidecar", lambda: sidecar_stub)

    def fake_runner(sidecar_path, request_path, **kwargs):
        # Locate the staging dir from the request file and seed it with the
        # minimal sidecar outputs the validator + aggregator expect.
        request_data = test_supervisor.json.loads(
            request_path.read_text(encoding="utf-8")
        )
        staging_dir = Path(request_data["staging_dir"])
        staging_setup(staging_dir, etl)
        return supervisor.NativeWorkerResult(
            ok=True,
            message="ok",
            returncode=0,
            request_path=request_path,
            stdout_tail="",
            stderr_tail="",
            invalid_stdout_tail="",
            progress=[],
            result={
                "type": "result",
                "ok": True,
                "performance": {
                    "wall_seconds": 12.34,
                    "events_per_second": 250_000,
                    "peak_rss_mb": 1234.5,
                },
                "event_counts": {
                    "SampledProfile": 100,
                    "CSwitch": 50,
                },
            },
        )

    def fake_aggregation_runner(staging_dir, etl_path, trace_id):
        return aggregation_worker.AggregationResult(
            ok=True,
            message="aggregation completed",
            staging_dir=staging_dir,
            datasets_written=["cpu_sampling", "cpu_timeline"],
            warnings=[],
        )

    caplog.set_level(logging.INFO, logger=telemetry.LOGGER_NAME)
    result = supervisor.run_csharp_worker_extraction(
        etl_path=etl,
        export_dir=export_dir,
        trace_id="trace_telemetry",
        symbol_path=None,
        requested_event_classes=["SampledProfile", "CSwitch"],
        process_runner=fake_runner,
        aggregation_runner=fake_aggregation_runner,
    )
    assert result.ok, result.message

    events = _events(caplog)
    expected = [
        telemetry.EVENT_CSHARP_SPAWN,
        telemetry.EVENT_CSHARP_CHILD_EXIT,
        telemetry.EVENT_CSHARP_RESULT,
        telemetry.EVENT_CSHARP_CACHE_VALIDATE,
        telemetry.EVENT_CSHARP_AGGREGATION_START,
        telemetry.EVENT_CSHARP_AGGREGATION_DONE,
        telemetry.EVENT_CSHARP_CACHE_PROMOTE,
    ]
    for ev in expected:
        assert ev in events, f"missing {ev} in {events!r}"

    # The order must match the pipeline phase order.
    indices = [events.index(ev) for ev in expected]
    assert indices == sorted(indices), (
        f"telemetry events out of order: {events!r}"
    )

    # Spot-check field content.
    records = _records(caplog)
    spawn = next(r for r in records if r.startswith("event=csharp.spawn "))
    assert "mode=csharp" in spawn
    assert "trace_id=trace_telemetry" in spawn

    result_line = next(r for r in records if r.startswith("event=csharp.result "))
    assert "events_per_second=250000" in result_line
    assert "peak_rss_mb=1234.500" in result_line
    assert "sidecar_wall_seconds=12.340" in result_line

    validate_line = next(
        r for r in records if r.startswith("event=csharp.cache_validate ")
    )
    assert "ok=true" in validate_line
    assert "producer=csharp" in validate_line

    promote = next(
        r for r in records if r.startswith("event=csharp.cache_promote ")
    )
    assert "ok=true" in promote
