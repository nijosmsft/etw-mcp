from __future__ import annotations

import json
import importlib.util
from pathlib import Path

_CONFTEST_SPEC = importlib.util.spec_from_file_location(
    "fixture_conftest_under_test",
    Path(__file__).with_name("conftest.py"),
)
assert _CONFTEST_SPEC is not None
conftest = importlib.util.module_from_spec(_CONFTEST_SPEC)
assert _CONFTEST_SPEC.loader is not None
_CONFTEST_SPEC.loader.exec_module(conftest)


class _FakeConfig:
    def __init__(self, root: Path, *, force: bool) -> None:
        self.root = root
        self.force = force

    def getoption(self, option: str):
        values = {
            "--generate-fixture-etls": True,
            "--fixture-output-root": str(self.root),
            "--force-generate-fixtures": self.force,
            "--fixture-duration-seconds": 1,
        }
        return values.get(option, False)


def test_force_generation_runs_once_per_fixture_per_session(tmp_path: Path, monkeypatch) -> None:
    conftest._GENERATED_FIXTURES.clear()
    calls: list[str] = []

    def fake_run_fixture_command(cmd: list[str], *, action: str, name: str) -> None:
        calls.append(action)
        fixture_dir = tmp_path / name
        fixture_dir.mkdir(parents=True, exist_ok=True)
        if action == "generate ETL":
            (fixture_dir / f"{name}.etl").write_bytes(b"etl")
        elif action == "generate expected JSON":
            (fixture_dir / "expected.json").write_text(
                json.dumps({"fixture": name}),
                encoding="utf-8",
            )

    monkeypatch.setattr(conftest, "_run_fixture_command", fake_run_fixture_command)
    config = _FakeConfig(tmp_path, force=True)

    conftest._ensure_generated_fixture("empty-trace", config)  # type: ignore[arg-type]
    conftest._ensure_generated_fixture("empty-trace", config)  # type: ignore[arg-type]

    assert calls == ["generate ETL", "generate expected JSON"]
