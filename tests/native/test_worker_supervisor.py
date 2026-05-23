from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from etw_analyzer.native import cache as native_cache
from etw_analyzer.native import worker_supervisor
import etw_analyzer.tools.trace_mgmt as trace_mgmt


def _make_etl(tmp_path: Path) -> Path:
    etl = tmp_path / "sample.etl"
    etl.write_bytes(b"synthetic etl")
    return etl


def _write_native_cache(cache: Path, etl: Path, weight: int = 1) -> None:
    cache.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame({
        "Process Name": ["proc.exe"],
        "PID": [1234],
        "Weight": [weight],
        "% Weight": [100.0],
        "Module": ["mod.dll"],
        "Function": ["func"],
    })
    df.to_parquet(cache / "cpu_sampling.parquet", index=False)
    for _, stem in trace_mgmt._DUMPER_EVENT_CLASSES.values():
        pd.DataFrame().to_parquet(cache / f"{stem}.parquet", index=False)
    trace_mgmt._write_cache_manifest(cache, etl, "native", {"cpu_sampling": df})


def test_worker_success_promotes_valid_staging_cache(tmp_path: Path):
    etl = _make_etl(tmp_path)
    export_dir = tmp_path / ".etw-export-sample"
    trace_id = "trace_fake"
    seen_staging: list[Path] = []

    def fake_runner(request_path: Path, **kwargs):
        request = json.loads(request_path.read_text(encoding="utf-8"))
        assert request["trace_id"] == trace_id
        staging = Path(request["staging_dir"])
        seen_staging.append(staging)
        _write_native_cache(staging, etl, weight=42)
        return worker_supervisor.NativeWorkerResult(
            ok=True,
            message="ok",
            result={"ok": True, "trace_id": trace_id},
        )

    result = worker_supervisor.run_native_worker_extraction(
        etl_path=etl,
        export_dir=export_dir,
        trace_id=trace_id,
        symbol_path=None,
        requested_event_classes=trace_mgmt._DUMPER_EVENT_CLASSES.keys(),
        process_runner=fake_runner,
    )

    assert result.ok is True
    assert export_dir.exists()
    assert seen_staging and not seen_staging[0].exists()
    manifest = native_cache.read_manifest(export_dir)
    assert manifest is not None
    cached = trace_mgmt._load_from_cache(export_dir, etl, mode="native")
    assert cached is not None
    assert cached["cpu_sampling"]["Weight"].tolist() == [42]


def test_worker_request_uses_streaming_strategy_only_when_enabled(
    monkeypatch,
    tmp_path: Path,
):
    etl = _make_etl(tmp_path)
    export_dir = tmp_path / ".etw-export-sample"
    staging_dir = tmp_path / "staging"

    monkeypatch.delenv(worker_supervisor.NATIVE_STREAMING_ENV, raising=False)
    request = worker_supervisor.build_worker_request(
        etl_path=etl,
        export_dir=export_dir,
        staging_dir=staging_dir,
        trace_id="trace_fake",
        requested_event_classes=["SampledProfile"],
    )
    assert request["strategy"] == native_cache.MATERIALIZED_SMALL_STRATEGY

    monkeypatch.setenv(worker_supervisor.NATIVE_STREAMING_ENV, "1")
    request = worker_supervisor.build_worker_request(
        etl_path=etl,
        export_dir=export_dir,
        staging_dir=staging_dir,
        trace_id="trace_fake",
        requested_event_classes=[
            "SampledProfile",
            "HttpService/Recv",
            "Quic/AckReceived",
        ],
    )
    assert request["strategy"] == native_cache.STREAMING_EVENT_STORE_STRATEGY
    assert request["streaming_profile"] == worker_supervisor.STREAMING_PROFILE_SUMMARY
    assert request["requested_event_classes"] == sorted(
        worker_supervisor.STREAMING_SUMMARY_EVENT_CLASSES
    )
    assert "HttpService/Recv" not in request["requested_event_classes"]
    assert "Quic/AckReceived" not in request["requested_event_classes"]

    monkeypatch.setenv(
        worker_supervisor.NATIVE_STREAMING_PROFILE_ENV,
        worker_supervisor.STREAMING_PROFILE_ALL,
    )
    request = worker_supervisor.build_worker_request(
        etl_path=etl,
        export_dir=export_dir,
        staging_dir=staging_dir,
        trace_id="trace_fake",
        requested_event_classes=[
            "SampledProfile",
            "CSwitch",
            "HttpService/Recv",
            "Quic/AckReceived",
        ],
    )
    assert request["streaming_profile"] == worker_supervisor.STREAMING_PROFILE_ALL
    assert request["requested_event_classes"] == [
        "SampledProfile",
        "CSwitch",
        "HttpService/Recv",
        "Quic/AckReceived",
        "ReadyThread",
    ]

    network_classes = [
        "TcpIp/Recv", "TcpIp/Send", "TcpIp/Retransmit",
        "TcpIp/Connect", "TcpIp/Accept",
        "UdpIp/Recv", "UdpIp/Send",
        "AFD/Recv", "AFD/Send", "AFD/Connect", "AFD/Accept", "AFD/Close",
        "NdisDrop", "NdisPacketCapture",
    ]
    request = worker_supervisor.build_worker_request(
        etl_path=etl,
        export_dir=export_dir,
        staging_dir=staging_dir,
        trace_id="trace_fake",
        requested_event_classes=network_classes,
    )
    assert request["streaming_profile"] == worker_supervisor.STREAMING_PROFILE_ALL
    for event_class in network_classes:
        assert event_class in request["requested_event_classes"]


def test_worker_failure_removes_staging_cache(tmp_path: Path):
    etl = _make_etl(tmp_path)
    export_dir = tmp_path / ".etw-export-sample"
    seen_staging: list[Path] = []

    def fake_runner(request_path: Path, **kwargs):
        request = json.loads(request_path.read_text(encoding="utf-8"))
        staging = Path(request["staging_dir"])
        seen_staging.append(staging)
        (staging / "partial.txt").write_text("partial", encoding="utf-8")
        return worker_supervisor.NativeWorkerResult(
            ok=False,
            message="boom",
            failure_kind="worker-error",
        )

    result = worker_supervisor.run_native_worker_extraction(
        etl_path=etl,
        export_dir=export_dir,
        trace_id="trace_fake",
        symbol_path=None,
        requested_event_classes=trace_mgmt._DUMPER_EVENT_CLASSES.keys(),
        process_runner=fake_runner,
    )

    assert result.ok is False
    assert result.failure_kind == "worker-error"
    assert seen_staging and not seen_staging[0].exists()
    assert not export_dir.exists()


def test_worker_success_with_partial_staging_is_not_promoted(tmp_path: Path):
    etl = _make_etl(tmp_path)
    export_dir = tmp_path / ".etw-export-sample"
    seen_staging: list[Path] = []

    def fake_runner(request_path: Path, **kwargs):
        request = json.loads(request_path.read_text(encoding="utf-8"))
        staging = Path(request["staging_dir"])
        seen_staging.append(staging)
        pd.DataFrame({"x": [1]}).to_parquet(staging / "cpu_sampling.parquet")
        return worker_supervisor.NativeWorkerResult(
            ok=True,
            message="ok",
            result={"ok": True, "trace_id": "trace_fake"},
        )

    result = worker_supervisor.run_native_worker_extraction(
        etl_path=etl,
        export_dir=export_dir,
        trace_id="trace_fake",
        symbol_path=None,
        requested_event_classes=trace_mgmt._DUMPER_EVENT_CLASSES.keys(),
        process_runner=fake_runner,
    )

    assert result.ok is False
    assert result.failure_kind == "invalid-cache"
    assert seen_staging and not seen_staging[0].exists()
    assert not export_dir.exists()
    assert trace_mgmt._load_from_cache(export_dir, etl, mode="native") is None


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
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9


class _HangingProcess(_FakeProcess):
    def __init__(self):
        super().__init__(stdout_lines=[], stderr_lines=[], returncode=None)


def test_worker_command_omits_symbol_path_and_passes_it_via_env(tmp_path: Path):
    request_path = tmp_path / "request.json"
    request_path.write_text("{}", encoding="utf-8")
    secret_symbol_path = r"srv*C:\private-symbols*https://example.invalid/symbols"
    captured = {}

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["env"] = kwargs["env"]
        captured["shell"] = kwargs["shell"]
        return _FakeProcess(
            stdout_lines=['{"type":"result","ok":true,"message":"ok"}\n'],
        )

    result = worker_supervisor.run_worker_process(
        request_path,
        symbol_path=secret_symbol_path,
        popen_factory=fake_popen,
        enforce_job=False,
    )

    assert result.ok is True
    assert captured["shell"] is False
    assert secret_symbol_path not in " ".join(captured["command"])
    assert captured["env"][worker_supervisor.NATIVE_WORKER_SYMBOL_ENV] == secret_symbol_path
    assert captured["env"]["PYTHONUNBUFFERED"] == "1"


def test_worker_supervisor_bounds_invalid_stdout_and_stderr(tmp_path: Path):
    request_path = tmp_path / "request.json"
    request_path.write_text("{}", encoding="utf-8")
    invalid = "not-json " + ("x" * 50_000) + "\n"
    stderr = "stderr " + ("y" * 50_000) + "\n"

    def fake_popen(command, **kwargs):
        return _FakeProcess(
            stdout_lines=[
                invalid,
                '{"type":"result","ok":true,"message":"ok"}\n',
            ],
            stderr_lines=[stderr],
        )

    result = worker_supervisor.run_worker_process(
        request_path,
        symbol_path=None,
        popen_factory=fake_popen,
        enforce_job=False,
    )

    assert result.ok is True
    assert len(result.invalid_stdout_tail.encode("utf-8")) <= (
        worker_supervisor.INVALID_STDOUT_TAIL_BYTES
    )
    assert len(result.stderr_tail.encode("utf-8")) <= worker_supervisor.STDERR_TAIL_BYTES


def test_worker_supervisor_enforces_timeout(tmp_path: Path):
    request_path = tmp_path / "request.json"
    request_path.write_text("{}", encoding="utf-8")
    proc = _HangingProcess()

    def fake_popen(command, **kwargs):
        return proc

    result = worker_supervisor.run_worker_process(
        request_path,
        symbol_path=None,
        timeout_seconds=0.001,
        stale_heartbeat_seconds=100,
        popen_factory=fake_popen,
        enforce_job=False,
    )

    assert result.ok is False
    assert result.failure_kind == "timeout"
    assert proc.terminated is True


def test_worker_supervisor_enforces_stale_heartbeat(tmp_path: Path):
    request_path = tmp_path / "request.json"
    request_path.write_text("{}", encoding="utf-8")
    proc = _HangingProcess()

    def fake_popen(command, **kwargs):
        return proc

    result = worker_supervisor.run_worker_process(
        request_path,
        symbol_path=None,
        timeout_seconds=100,
        stale_heartbeat_seconds=0.001,
        popen_factory=fake_popen,
        enforce_job=False,
    )

    assert result.ok is False
    assert result.failure_kind == "stale-heartbeat"
    assert proc.terminated is True
