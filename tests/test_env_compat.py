"""Tests for the WPR_MCP_* → ETW_MCP_* env-var back-compat shim.

The shim was added in v0.4.0 when the repo was renamed from
``wpr-mcp-server`` to ``etw-mcp``. Every legacy env var must continue to
resolve (with a one-shot DeprecationWarning) so existing MCP configs
keep working until v1.0.
"""

from __future__ import annotations

import warnings

import pytest

from etw_analyzer.native import env_compat


@pytest.fixture(autouse=True)
def _reset_warn_state():
    """Each test starts with a clean warn-once set."""

    env_compat.reset_warning_state()
    yield
    env_compat.reset_warning_state()


def test_new_name_takes_precedence_over_legacy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ETW_MCP_DOTNET_SIDECAR", "C:\\new\\etw-extract.exe")
    monkeypatch.setenv("WPR_MCP_DOTNET_SIDECAR", "C:\\old\\wpr-mcp-extract.exe")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        value = env_compat.getenv("ETW_MCP_DOTNET_SIDECAR")

    assert value == "C:\\new\\etw-extract.exe"
    # No deprecation warning when the new name resolves — legacy is never
    # consulted.
    assert not [w for w in caught if issubclass(w.category, DeprecationWarning)]


def test_legacy_only_resolves_and_warns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ETW_MCP_DOTNET_SIDECAR", raising=False)
    monkeypatch.setenv("WPR_MCP_DOTNET_SIDECAR", "C:\\old\\wpr-mcp-extract.exe")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        value = env_compat.getenv("ETW_MCP_DOTNET_SIDECAR")

    assert value == "C:\\old\\wpr-mcp-extract.exe"
    dep = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert len(dep) == 1
    msg = str(dep[0].message)
    assert "WPR_MCP_DOTNET_SIDECAR" in msg
    assert "ETW_MCP_DOTNET_SIDECAR" in msg
    assert "v1.0" in msg


def test_warn_fires_once_per_legacy_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ETW_MCP_MODE", raising=False)
    monkeypatch.setenv("WPR_MCP_MODE", "xperf")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        for _ in range(5):
            assert env_compat.getenv("ETW_MCP_MODE") == "xperf"

    dep = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert len(dep) == 1, f"expected exactly one warning, got {len(dep)}"


def test_warn_fires_per_distinct_legacy_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ETW_MCP_MODE", raising=False)
    monkeypatch.delenv("ETW_MCP_DOTNET_SIDECAR", raising=False)
    monkeypatch.setenv("WPR_MCP_MODE", "xperf")
    monkeypatch.setenv("WPR_MCP_DOTNET_SIDECAR", "C:\\old\\wpr-mcp-extract.exe")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        env_compat.getenv("ETW_MCP_MODE")
        env_compat.getenv("ETW_MCP_DOTNET_SIDECAR")
        env_compat.getenv("ETW_MCP_MODE")
        env_compat.getenv("ETW_MCP_DOTNET_SIDECAR")

    dep = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert len(dep) == 2
    messages = " | ".join(str(w.message) for w in dep)
    assert "WPR_MCP_MODE" in messages
    assert "WPR_MCP_DOTNET_SIDECAR" in messages


def test_unknown_name_passes_through_to_os_getenv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOME_UNRELATED_VAR", "hello")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        value = env_compat.getenv("SOME_UNRELATED_VAR")

    assert value == "hello"
    assert not [w for w in caught if issubclass(w.category, DeprecationWarning)]


def test_default_returned_when_both_names_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ETW_MCP_MODE", raising=False)
    monkeypatch.delenv("WPR_MCP_MODE", raising=False)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        value = env_compat.getenv("ETW_MCP_MODE", default="auto")

    assert value == "auto"
    # No deprecation when neither variant is set — the default path is
    # taken without consulting the legacy name's existence beyond a probe.
    assert not [w for w in caught if issubclass(w.category, DeprecationWarning)]


def test_default_returned_for_unknown_name_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEFINITELY_NOT_SET_XYZ", raising=False)
    assert env_compat.getenv("DEFINITELY_NOT_SET_XYZ", default="fallback") == "fallback"
    assert env_compat.getenv("DEFINITELY_NOT_SET_XYZ") is None


def test_all_15_legacy_names_resolve(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sanity check: every alias in the table actually reads from its
    legacy counterpart."""

    expected_aliases = {
        "ETW_MCP_CSHARP_SIDECAR": "WPR_MCP_CSHARP_SIDECAR",
        "ETW_MCP_DOTNET_SIDECAR": "WPR_MCP_DOTNET_SIDECAR",
        "ETW_MCP_EVIDENCE_PATH": "WPR_MCP_EVIDENCE_PATH",
        "ETW_MCP_MODE": "WPR_MCP_MODE",
        "ETW_MCP_NATIVE_ALLOW_LARGE": "WPR_MCP_NATIVE_ALLOW_LARGE",
        "ETW_MCP_NATIVE_MAX_ETL_MB": "WPR_MCP_NATIVE_MAX_ETL_MB",
        "ETW_MCP_NATIVE_STREAMING": "WPR_MCP_NATIVE_STREAMING",
        "ETW_MCP_NATIVE_STREAMING_PROFILE": "WPR_MCP_NATIVE_STREAMING_PROFILE",
        "ETW_MCP_NATIVE_WORKER": "WPR_MCP_NATIVE_WORKER",
        "ETW_MCP_NATIVE_WORKER_DISABLE_JOB": "WPR_MCP_NATIVE_WORKER_DISABLE_JOB",
        "ETW_MCP_NATIVE_WORKER_MEMORY_MB": "WPR_MCP_NATIVE_WORKER_MEMORY_MB",
        "ETW_MCP_NATIVE_WORKER_STALE_SECONDS": "WPR_MCP_NATIVE_WORKER_STALE_SECONDS",
        "ETW_MCP_NATIVE_WORKER_SYMBOL_PATH": "WPR_MCP_NATIVE_WORKER_SYMBOL_PATH",
        "ETW_MCP_NATIVE_WORKER_TIMEOUT_SECONDS": "WPR_MCP_NATIVE_WORKER_TIMEOUT_SECONDS",
    }
    assert env_compat._ENV_VAR_ALIASES == expected_aliases

    for new, legacy in expected_aliases.items():
        monkeypatch.delenv(new, raising=False)
        monkeypatch.setenv(legacy, f"sentinel-{legacy}")
        env_compat.reset_warning_state()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            assert env_compat.getenv(new) == f"sentinel-{legacy}"
        monkeypatch.delenv(legacy, raising=False)
