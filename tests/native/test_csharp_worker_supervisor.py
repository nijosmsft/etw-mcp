"""Tests for the C# sidecar invocation path in worker_supervisor.

The supervisor reuses the same JSONL/heartbeat/tail infrastructure as the
legacy native worker; these tests pin the csharp-specific behaviour:
request shape, sidecar discovery, aggregation hand-off, and atomic
promotion.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer.native import aggregation_worker
from etw_analyzer.native import cache as native_cache
from etw_analyzer.native import worker_supervisor
from etw_analyzer.native import config


def _make_etl(tmp_path: Path) -> Path:
    etl = tmp_path / "sample.etl"
    etl.write_bytes(b"synthetic etl")
    return etl


def _fake_sidecar(tmp_path: Path) -> Path:
    path = tmp_path / "wpr-mcp-extract.exe"
    path.write_bytes(b"MZ fake sidecar")
    return path


def _seed_sidecar_outputs(staging_dir: Path, etl: Path) -> None:
    """Mimic what the real sidecar would write into staging."""

    staging_dir.mkdir(parents=True, exist_ok=True)
    sampled = pd.DataFrame({
        "Process Name": ["echo_server.exe"],
        "PID": [1234],
        "TID": [11],
        "CPU": [0],
        "Module": ["echo_server.exe"],
        "Function": ["main"],
        "Weight": [10],
        "TimeStamp": [100],
        "Stack": [None],
    })
    sampled.to_parquet(staging_dir / "sampled_profile.parquet", index=False)
    (staging_dir / "sysconfig.txt").write_text("CPU Count: 8\n", encoding="utf-8")

    manifest = native_cache.CacheManifest.materialized_small(
        etl,
        [
            native_cache.CacheDataset(
                name="sampled_profile",
                kind="parquet",
                path="sampled_profile.parquet",
                row_count=len(sampled),
                materialize_on_load=True,
            ),
            native_cache.CacheDataset(
                name="sysconfig",
                kind="text",
                path="sysconfig.txt",
                row_count=1,
                materialize_on_load=True,
            ),
        ],
        producer="csharp",
    )
    native_cache.write_manifest(staging_dir, manifest)


# ---------------------------------------------------------------------------
# Request shape
# ---------------------------------------------------------------------------

def test_build_csharp_request_matches_contract(tmp_path: Path):
    etl = _make_etl(tmp_path)
    staging = tmp_path / "staging"
    req = worker_supervisor.build_csharp_request(
        trace_id="trace_abc",
        etl_path=etl,
        staging_dir=staging,
        requested_event_classes=["SampledProfile", "CSwitch"],
        symbol_path=r"srv*C:\symbols*https://msdl",
    )
    assert req["version"] == 1
    assert req["trace_id"] == "trace_abc"
    assert req["etl_path"] == str(etl.resolve())
    assert req["staging_dir"] == str(staging.resolve())
    assert req["strategy"] == native_cache.MATERIALIZED_SMALL_STRATEGY
    assert req["requested_event_classes"] == ["SampledProfile", "CSwitch"]
    assert req["symbol_path"] == r"srv*C:\symbols*https://msdl"
    assert req["log_level"] == "info"
    assert req["include_tracelogging"] is True
    assert 250 <= req["heartbeat_interval_ms"] <= 30000
    assert req["max_etl_mb"] >= 512


def test_build_csharp_request_dedupes_event_classes(tmp_path: Path):
    req = worker_supervisor.build_csharp_request(
        trace_id="t",
        etl_path=_make_etl(tmp_path),
        staging_dir=tmp_path / "s",
        requested_event_classes=["SampledProfile", "CSwitch", "SampledProfile"],
    )
    assert req["requested_event_classes"] == ["SampledProfile", "CSwitch"]


def test_build_csharp_command_uses_only_request_flag(tmp_path: Path):
    sidecar = _fake_sidecar(tmp_path)
    req = tmp_path / "request.json"
    cmd = worker_supervisor.build_csharp_command(sidecar, req)
    assert cmd == [str(sidecar), "--request", str(req)]


# ---------------------------------------------------------------------------
# End-to-end successful path with a fake process runner.
# ---------------------------------------------------------------------------

def test_run_csharp_worker_success_promotes_to_export_dir(
    tmp_path: Path, monkeypatch
):
    etl = _make_etl(tmp_path)
    sidecar = _fake_sidecar(tmp_path)
    export_dir = tmp_path / ".etw-export-sample"
    trace_id = "trace_csharp_ok"

    seen: dict = {}

    def fake_runner(resolved_sidecar, request_path, **_):
        assert resolved_sidecar == sidecar
        request = json.loads(Path(request_path).read_text("utf-8"))
        staging = Path(request["staging_dir"])
        seen["staging"] = staging
        _seed_sidecar_outputs(staging, etl)
        return worker_supervisor.NativeWorkerResult(
            ok=True,
            message="sidecar fake ok",
            result={"type": "result", "ok": True, "trace_id": trace_id,
                    "producer": "csharp"},
        )

    result = worker_supervisor.run_csharp_worker_extraction(
        etl_path=etl,
        export_dir=export_dir,
        trace_id=trace_id,
        symbol_path=None,
        requested_event_classes=["SampledProfile"],
        sidecar_path=sidecar,
        process_runner=fake_runner,
    )

    assert result.ok is True, f"{result.message}; {result.stdout_tail}"
    assert export_dir.exists()
    # Sidecar staging dir got promoted (so it no longer exists at the
    # original path).
    assert seen["staging"] and not seen["staging"].exists()
    # Manifest must round-trip with producer='csharp'.
    loaded = native_cache.read_manifest(export_dir)
    assert loaded is not None
    assert loaded.producer == "csharp"


def test_run_csharp_worker_sidecar_failure_leaves_staging_for_debug(
    tmp_path: Path,
):
    etl = _make_etl(tmp_path)
    sidecar = _fake_sidecar(tmp_path)
    export_dir = tmp_path / ".etw-export-sample"
    seen: dict = {}

    def fake_runner(_sidecar, request_path, **_):
        request = json.loads(Path(request_path).read_text("utf-8"))
        seen["staging"] = Path(request["staging_dir"])
        (seen["staging"] / "partial.parquet").write_text("x")
        return worker_supervisor.NativeWorkerResult(
            ok=False,
            message="sidecar crashed",
            failure_kind="csharp_exception",
        )

    result = worker_supervisor.run_csharp_worker_extraction(
        etl_path=etl,
        export_dir=export_dir,
        trace_id="trace_csharp_fail",
        symbol_path=None,
        requested_event_classes=["SampledProfile"],
        sidecar_path=sidecar,
        process_runner=fake_runner,
    )
    assert result.ok is False
    assert result.failure_kind == "csharp_exception"
    # Per spike-contract §11 phase 0: staging is NOT deleted on failure.
    assert seen["staging"].exists()
    assert not export_dir.exists()


def test_run_csharp_worker_missing_binary_raises(tmp_path: Path, monkeypatch):
    # Pin env var to a path that doesn't exist. Because env_override is
    # exclusive, the in-tree publish path won't be consulted, so
    # find_csharp_sidecar returns None and the supervisor raises.
    monkeypatch.setenv(
        config.CSHARP_SIDECAR_ENV,
        str(tmp_path / "does-not-exist.exe"),
    )
    config.reset_csharp_cache()

    with pytest.raises(ValueError, match=config.CSHARP_SIDECAR_ENV):
        worker_supervisor.run_csharp_worker_extraction(
            etl_path=_make_etl(tmp_path),
            export_dir=tmp_path / ".etw-export-x",
            trace_id="t",
            symbol_path=None,
            requested_event_classes=["SampledProfile"],
            # No sidecar_path → forces auto-discovery which returns None.
        )


def test_run_csharp_worker_invalid_manifest_returns_invalid_cache(tmp_path: Path):
    etl = _make_etl(tmp_path)
    sidecar = _fake_sidecar(tmp_path)
    export_dir = tmp_path / ".etw-export-sample"

    def fake_runner(_sidecar, request_path, **_):
        request = json.loads(Path(request_path).read_text("utf-8"))
        staging = Path(request["staging_dir"])
        # Sidecar reports success but writes no manifest at all.
        (staging / "sampled_profile.parquet").write_bytes(b"junk")
        return worker_supervisor.NativeWorkerResult(
            ok=True,
            message="ok",
            result={"type": "result", "ok": True, "trace_id": "t"},
        )

    result = worker_supervisor.run_csharp_worker_extraction(
        etl_path=etl,
        export_dir=export_dir,
        trace_id="t",
        symbol_path=None,
        requested_event_classes=["SampledProfile"],
        sidecar_path=sidecar,
        process_runner=fake_runner,
    )
    assert result.ok is False
    assert result.failure_kind == "invalid-cache"


def test_run_csharp_worker_aggregation_failure_returns_aggregation_kind(
    tmp_path: Path,
):
    etl = _make_etl(tmp_path)
    sidecar = _fake_sidecar(tmp_path)
    export_dir = tmp_path / ".etw-export-sample"

    def fake_runner(_sidecar, request_path, **_):
        request = json.loads(Path(request_path).read_text("utf-8"))
        _seed_sidecar_outputs(Path(request["staging_dir"]), etl)
        return worker_supervisor.NativeWorkerResult(
            ok=True,
            message="ok",
            result={"type": "result", "ok": True, "trace_id": "t"},
        )

    def fail_aggregation(*_args, **_kwargs):
        return aggregation_worker.AggregationResult(
            ok=False,
            message="aggregator blew up",
            staging_dir=Path("/dev/null"),
        )

    result = worker_supervisor.run_csharp_worker_extraction(
        etl_path=etl,
        export_dir=export_dir,
        trace_id="t",
        symbol_path=None,
        requested_event_classes=["SampledProfile"],
        sidecar_path=sidecar,
        process_runner=fake_runner,
        aggregation_runner=fail_aggregation,
    )
    assert result.ok is False
    assert result.failure_kind == "aggregation"


# ---------------------------------------------------------------------------
# JSONL protocol — heartbeat/progress forwarding via the same _handle_stdout
# infrastructure used for native.
# ---------------------------------------------------------------------------

class _FakeStream:
    def __init__(self, lines):
        self._lines = list(lines)

    def __iter__(self):
        return iter(self._lines)


class _FakeProcess:
    def __init__(self, stdout_lines=None, stderr_lines=None, returncode=0):
        self.stdout = _FakeStream(stdout_lines or [])
        self.stderr = _FakeStream(stderr_lines or [])
        self.returncode = returncode

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9


def test_run_csharp_process_parses_heartbeat_progress_result(tmp_path: Path):
    sidecar = _fake_sidecar(tmp_path)
    request_path = tmp_path / "request.json"
    request_path.write_text("{}", encoding="utf-8")

    def fake_popen(command, **_):
        return _FakeProcess(
            stdout_lines=[
                '{"type":"heartbeat","time":1.0,"phase":"opening-trace"}\n',
                '{"type":"progress","time":2.0,"phase":"decoding",'
                '"events_decoded":42,"stacks_paired":10,"bytes_processed":99}\n',
                '{"type":"result","time":3.0,"ok":true,"producer":"csharp",'
                '"trace_id":"t","staging_dir":"' + str(tmp_path).replace("\\", "\\\\")
                + '","strategy":"materialized-small","manifest":"x.json",'
                '"datasets":["sampled_profile"]}\n',
            ],
        )

    result = worker_supervisor.run_csharp_process(
        sidecar,
        request_path,
        popen_factory=fake_popen,
    )
    assert result.ok is True
    assert any(p.get("type") == "heartbeat" for p in result.progress)
    assert any(p.get("type") == "progress" for p in result.progress)
    assert result.result is not None
    assert result.result["producer"] == "csharp"


def test_run_csharp_process_structured_failure_surfaces_kind(tmp_path: Path):
    sidecar = _fake_sidecar(tmp_path)
    request_path = tmp_path / "request.json"
    request_path.write_text("{}", encoding="utf-8")

    def fake_popen(command, **_):
        return _FakeProcess(
            stdout_lines=[
                '{"type":"result","time":1.0,"ok":false,"producer":"csharp",'
                '"failure_kind":"etl-too-large","error":"etl too big",'
                '"phase_at_failure":"reading-request"}\n',
            ],
            returncode=1,
        )

    result = worker_supervisor.run_csharp_process(
        sidecar,
        request_path,
        popen_factory=fake_popen,
    )
    assert result.ok is False
    assert result.failure_kind == "etl-too-large"
    assert "etl too big" in result.message


def test_run_csharp_process_no_result_treated_as_crash(tmp_path: Path):
    sidecar = _fake_sidecar(tmp_path)
    request_path = tmp_path / "request.json"
    request_path.write_text("{}", encoding="utf-8")

    def fake_popen(command, **_):
        return _FakeProcess(stdout_lines=[], returncode=2)

    result = worker_supervisor.run_csharp_process(
        sidecar,
        request_path,
        popen_factory=fake_popen,
    )
    assert result.ok is False
    assert result.failure_kind == "no-result"


# ---------------------------------------------------------------------------
# Regression — the native worker path must still work.
# ---------------------------------------------------------------------------

def test_native_worker_path_unchanged(tmp_path: Path):
    """Spot-check that build_worker_request still works for native mode."""

    etl = _make_etl(tmp_path)
    request = worker_supervisor.build_worker_request(
        etl_path=etl,
        export_dir=tmp_path / "export",
        staging_dir=tmp_path / "staging",
        trace_id="trace_native",
        requested_event_classes=["SampledProfile"],
    )
    assert request["mode"] == "native"
    assert request["schema_version"] == native_cache.SCHEMA_VERSION
