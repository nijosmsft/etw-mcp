from __future__ import annotations

import json
import re
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest


FIXTURE_ROOT = Path(__file__).parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[1]
_FIXTURE_BACKENDS = {
    "empty-trace": "xperf",
    "cpu-only-trace": "xperf",
    "pktmon-capture-trace": "pktmon",
}
_GENERATED_FIXTURES: set[tuple[Path, str]] = set()


_RUN_OPTIONS = {
    "fixture": ("--run-fixture", "run ETL fixture tests"),
    "golden": ("--run-golden", "run golden-output fixture tests"),
    "xperf": ("--run-xperf", "run tests that require xperf.exe"),
    "admin": ("--run-admin", "run tests that require administrator privileges"),
    "network": ("--run-network", "run tests that require network access"),
    "benchmark": ("--run-benchmark", "run benchmark/performance tests"),
    "live": ("--run-live", "run tests against live systems or processes"),
    "parity": ("--run-parity", "run csharp vs native cross-producer parity tests against the real fixture"),
}


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("wpr-mcp-server integration gates")
    for _marker, (option, help_text) in _RUN_OPTIONS.items():
        group.addoption(option, action="store_true", default=False, help=help_text)
    group.addoption(
        "--update-fixture-expected",
        action="store_true",
        default=False,
        help="allow tests to update fixture expected.json files when explicitly implemented",
    )
    group.addoption(
        "--generate-fixture-etls",
        action="store_true",
        default=False,
        help="generate missing fixture ETLs and expected JSONs into a cache/output root",
    )
    group.addoption(
        "--fixture-output-root",
        default=None,
        help="directory for generated fixture ETLs/expected JSONs (default: pytest cache)",
    )
    group.addoption(
        "--fixture-duration-seconds",
        type=int,
        default=3,
        help="duration for generated fixture captures",
    )
    group.addoption(
        "--force-generate-fixtures",
        action="store_true",
        default=False,
        help="regenerate fixture ETLs/expected JSONs even when present",
    )


def pytest_configure(config: pytest.Config) -> None:
    for marker, (option, help_text) in _RUN_OPTIONS.items():
        config.addinivalue_line(
            "markers",
            f"{marker}: {help_text}; skipped unless {option} is provided",
        )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        for marker, (option, _help_text) in _RUN_OPTIONS.items():
            if item.get_closest_marker(marker) and not config.getoption(option):
                item.add_marker(pytest.mark.skip(reason=f"requires {option}"))


def _fixture_root(config: pytest.Config) -> Path:
    configured = config.getoption("--fixture-output-root")
    if configured:
        return Path(configured)
    if config.getoption("--generate-fixture-etls"):
        return Path(str(config.cache.makedir("wpr-fixtures")))
    return FIXTURE_ROOT


def _run_fixture_command(cmd: list[str], *, action: str, name: str) -> None:
    result = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = "\n".join(part for part in (result.stdout, result.stderr) if part.strip())
        pytest.fail(f"Could not {action} for fixture {name}:\n{detail}")


def _ensure_generated_fixture(name: str, config: pytest.Config) -> None:
    if not config.getoption("--generate-fixture-etls"):
        return
    if name not in _FIXTURE_BACKENDS:
        pytest.fail(f"No generation backend is registered for fixture {name!r}")

    root = _fixture_root(config).resolve()
    key = (root, name)
    etl = root / name / f"{name}.etl"
    expected = root / name / "expected.json"
    force = bool(config.getoption("--force-generate-fixtures"))
    if key in _GENERATED_FIXTURES and etl.exists() and expected.exists():
        return

    root.mkdir(parents=True, exist_ok=True)
    if force or not etl.exists():
        command = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(REPO_ROOT / "scripts" / "collect_fixture_etl.ps1"),
            "-Fixture",
            name,
            "-DurationSeconds",
            str(max(1, int(config.getoption("--fixture-duration-seconds")))),
            "-OutputRoot",
            str(root),
            "-Force",
        ]
        _run_fixture_command(command, action="generate ETL", name=name)

    if force or not expected.exists():
        command = [
            sys.executable,
            str(REPO_ROOT / "scripts" / "fixture_oracle.py"),
            "generate",
            "--fixture",
            name,
            "--backend",
            _FIXTURE_BACKENDS[name],
            "--fixture-root",
            str(root),
            "--force",
        ]
        _run_fixture_command(command, action="generate expected JSON", name=name)

    _GENERATED_FIXTURES.add(key)


def fixture_etl(name: str, config: pytest.Config | None = None) -> Path:
    """Return tests/fixtures/<name>/<name>.etl, or skip if it is absent."""
    root = _fixture_root(config) if config is not None else FIXTURE_ROOT
    if config is not None:
        _ensure_generated_fixture(name, config)
    path = root / name / f"{name}.etl"
    if not path.exists():
        pytest.skip(
            f"Fixture ETL not present: {path}. "
            f"Place it at tests\\fixtures\\{name}\\{name}.etl or pass --generate-fixture-etls."
        )
    return path


def fixture_manifest(name: str, config: pytest.Config | None = None) -> dict[str, Any]:
    """Return optional tests/fixtures/<name>/manifest.json metadata."""
    root = _fixture_root(config) if config is not None else FIXTURE_ROOT
    if config is not None:
        _ensure_generated_fixture(name, config)
    path = root / name / "manifest.json"
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        pytest.fail(f"Fixture manifest must be a JSON object: {path}")
    return data


def fixture_expected(name: str, config: pytest.Config | None = None) -> dict[str, Any]:
    """Return optional tests/fixtures/<name>/expected.json oracle data."""
    root = _fixture_root(config) if config is not None else FIXTURE_ROOT
    if config is not None:
        _ensure_generated_fixture(name, config)
    path = root / name / "expected.json"
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        pytest.fail(f"Fixture expected data must be a JSON object: {path}")
    return data


def _extract_trace_id(load_result: str) -> str | None:
    match = re.search(r"Trace ID:\*\* `([^`]+)`", load_result)
    return match.group(1) if match else None


def _require_xperf(config: pytest.Config) -> Path:
    if not config.getoption("--run-xperf"):
        pytest.skip("requires --run-xperf")

    from etw_analyzer.parsing.wpa_exporter import find_xperf

    xperf = find_xperf()
    if xperf is None:
        pytest.skip("requires xperf.exe on PATH or in Windows Performance Toolkit")
    return xperf


@pytest.fixture
def fixture_etl_path(request: pytest.FixtureRequest):
    return lambda name: fixture_etl(name, request.config)


@pytest.fixture
def fixture_manifest_data(request: pytest.FixtureRequest):
    return lambda name: fixture_manifest(name, request.config)


@pytest.fixture
def fixture_expected_data(request: pytest.FixtureRequest):
    return lambda name: fixture_expected(name, request.config)


@pytest.fixture
def update_fixture_expected(request: pytest.FixtureRequest) -> bool:
    return bool(request.config.getoption("--update-fixture-expected"))


@pytest.fixture
def xperf_path(request: pytest.FixtureRequest) -> Path:
    return _require_xperf(request.config)


@pytest.fixture
def load_fixture_trace(request: pytest.FixtureRequest):
    def _load(
        name: str,
        *,
        mode: str = "native",
        symbol_path: str | None = None,
        timeout_seconds: int = 300,
        force: bool = False,
    ) -> tuple[str, str]:
        if mode == "xperf":
            _require_xperf(request.config)

        from etw_analyzer.tools import trace_mgmt

        etl = fixture_etl(name, request.config)
        result = trace_mgmt.load_trace(
            str(etl),
            symbol_path=symbol_path,
            timeout_seconds=timeout_seconds,
            force=force,
            mode=mode,
        )
        trace_id = _extract_trace_id(result)
        if trace_id is None and mode == "native":
            lower = result.lower()
            if "native" in lower or "advapi32" in lower or "tdh" in lower:
                pytest.skip(f"native ETW load unavailable for {name}: {result}")
        if trace_id is None and "xperf.exe not found" in result:
            pytest.skip(result)
        assert trace_id is not None, result
        return result, trace_id

    return _load
