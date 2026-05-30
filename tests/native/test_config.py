"""Tests for ``etw_analyzer.native.config`` mode resolution including the
new ``mode="dotnet"`` path landed for Track B of the hybrid migration."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from etw_analyzer.native import config


def _make_fake_sidecar(tmp_path: Path) -> Path:
    """Write a fake ``wpr-mcp-extract.exe`` file in ``tmp_path`` and return it."""

    target = tmp_path / config.DOTNET_SIDECAR_EXE
    target.write_bytes(b"MZ fake sidecar")
    return target


@pytest.fixture(autouse=True)
def _clear_caches(monkeypatch):
    """Reset both auto-detect caches so test interaction is impossible."""

    monkeypatch.delenv("WPR_MCP_MODE", raising=False)
    monkeypatch.delenv(config.DOTNET_SIDECAR_ENV, raising=False)
    config.reset_auto_cache()
    yield
    config.reset_auto_cache()


def test_csharp_in_valid_modes():
    assert "dotnet" in config.VALID_MODES
    # The other modes must still be accepted.
    assert {"native", "xperf", "auto"}.issubset(config.VALID_MODES)


def test_normalize_mode_accepts_csharp():
    assert config.normalize_mode("dotnet") == "dotnet"
    assert config.normalize_mode("dotnet") == "dotnet"


def test_normalize_mode_rejects_unknown_mode():
    with pytest.raises(ValueError, match="Unknown mode"):
        config.normalize_mode("rust")


def test_find_csharp_sidecar_honors_env_var(tmp_path, monkeypatch):
    sidecar = _make_fake_sidecar(tmp_path)
    monkeypatch.setenv(config.DOTNET_SIDECAR_ENV, str(sidecar))
    config.reset_dotnet_cache()
    found = config.find_dotnet_sidecar()
    assert found == sidecar.resolve()


def test_find_csharp_sidecar_env_missing_file_returns_none(tmp_path, monkeypatch):
    monkeypatch.setenv(
        config.DOTNET_SIDECAR_ENV,
        str(tmp_path / "does-not-exist.exe"),
    )
    config.reset_dotnet_cache()
    # No env file, no in-tree publish in this fake tree → expect None unless
    # the host happens to have wpr-mcp-extract.exe on PATH. Tolerate that case.
    found = config.find_dotnet_sidecar()
    if found is not None:
        # Must be a real file that exists.
        assert found.is_file()
    else:
        assert found is None


def test_find_csharp_sidecar_cached(tmp_path, monkeypatch):
    sidecar = _make_fake_sidecar(tmp_path)
    monkeypatch.setenv(config.DOTNET_SIDECAR_ENV, str(sidecar))
    config.reset_dotnet_cache()
    first = config.find_dotnet_sidecar()
    # Change env, do NOT reset cache: should keep the cached answer.
    monkeypatch.setenv(config.DOTNET_SIDECAR_ENV, str(tmp_path / "other.exe"))
    second = config.find_dotnet_sidecar()
    assert first == second


def test_resolve_mode_csharp_explicit_with_binary(tmp_path, monkeypatch):
    sidecar = _make_fake_sidecar(tmp_path)
    monkeypatch.setenv(config.DOTNET_SIDECAR_ENV, str(sidecar))
    config.reset_dotnet_cache()
    assert config.resolve_mode("dotnet") == "dotnet"


def test_resolve_mode_csharp_explicit_missing_binary_raises(monkeypatch, tmp_path):
    # Ensure no binary is findable: clear env, point at non-existent path.
    monkeypatch.setenv(config.DOTNET_SIDECAR_ENV, str(tmp_path / "nope.exe"))
    config.reset_dotnet_cache()
    # On a host where wpr-mcp-extract.exe is on PATH this would mis-pass;
    # skip in that case so the test stays portable across dev machines.
    import shutil

    if shutil.which(config.DOTNET_SIDECAR_EXE):
        pytest.skip("wpr-mcp-extract.exe is on PATH; cannot test missing binary case")

    with pytest.raises(ValueError, match=config.DOTNET_SIDECAR_ENV):
        config.resolve_mode("dotnet")


def test_resolve_mode_auto_prefers_csharp_when_available(tmp_path, monkeypatch):
    sidecar = _make_fake_sidecar(tmp_path)
    monkeypatch.setenv(config.DOTNET_SIDECAR_ENV, str(sidecar))
    config.reset_auto_cache()
    # No etl_path needed for the csharp branch — sidecar location is the
    # gating signal.
    assert config.resolve_mode("auto") == "dotnet"


def test_resolve_mode_auto_falls_back_to_native_when_csharp_missing(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(config.DOTNET_SIDECAR_ENV, str(tmp_path / "missing.exe"))
    config.reset_auto_cache()

    import shutil

    if shutil.which(config.DOTNET_SIDECAR_EXE):
        pytest.skip("wpr-mcp-extract.exe is on PATH; cannot test fallback")

    # The native vs xperf branch depends on host capability; we only assert
    # that csharp was NOT chosen (the fallback chain advanced past it).
    resolved = config.resolve_mode("auto")
    assert resolved != "dotnet"
    assert resolved in {"native", "xperf"}


def test_wpr_mcp_mode_env_csharp_honored(tmp_path, monkeypatch):
    sidecar = _make_fake_sidecar(tmp_path)
    monkeypatch.setenv(config.DOTNET_SIDECAR_ENV, str(sidecar))
    monkeypatch.setenv("WPR_MCP_MODE", "dotnet")
    config.reset_auto_cache()
    assert config.resolve_mode(None) == "dotnet"


def test_wpr_mcp_mode_env_native_honored(monkeypatch):
    """Existing contract: env var sets mode when no explicit arg is given."""

    monkeypatch.setenv("WPR_MCP_MODE", "xperf")
    config.reset_auto_cache()
    # xperf never fails to resolve, so this is the safe one to pin.
    assert config.resolve_mode(None) == "xperf"


def test_wpr_mcp_mode_env_auto_honored(monkeypatch):
    monkeypatch.setenv("WPR_MCP_MODE", "auto")
    config.reset_auto_cache()
    resolved = config.resolve_mode(None)
    assert resolved in {"dotnet", "native", "xperf"}


def test_wpr_mcp_mode_env_xperf_honored(monkeypatch):
    monkeypatch.setenv("WPR_MCP_MODE", "xperf")
    config.reset_auto_cache()
    assert config.resolve_mode(None) == "xperf"


def test_explicit_arg_overrides_env_var(tmp_path, monkeypatch):
    """When the caller passes a non-auto mode, the env var is ignored."""

    sidecar = _make_fake_sidecar(tmp_path)
    monkeypatch.setenv(config.DOTNET_SIDECAR_ENV, str(sidecar))
    monkeypatch.setenv("WPR_MCP_MODE", "dotnet")
    config.reset_auto_cache()
    # Explicit xperf wins over env var csharp.
    assert config.resolve_mode("xperf") == "xperf"


def test_explicit_auto_arg_lets_env_var_win(monkeypatch):
    """auto from caller is identical to "no arg" — env var still wins."""

    monkeypatch.setenv("WPR_MCP_MODE", "xperf")
    config.reset_auto_cache()
    assert config.resolve_mode("auto") == "xperf"


def test_auto_detect_ignores_in_tree_csharp_binary(monkeypatch):
    """Auto mode must not silently flip to csharp just because an in-tree
    publish build is sitting in ``csharp/publish/win-x64/``. That binary is
    a dev convenience; flipping the default pipeline on its presence would
    be a surprise to every dev with a published checkout.

    The behaviour is opt-in via the ``WPR_MCP_DOTNET_SIDECAR`` env var or
    by putting the binary on PATH.
    """

    monkeypatch.delenv(config.DOTNET_SIDECAR_ENV, raising=False)
    config.reset_dotnet_cache()

    import shutil

    if shutil.which(config.DOTNET_SIDECAR_EXE):
        pytest.skip(
            "wpr-mcp-extract.exe is on PATH; cannot test the in-tree-only case"
        )

    # The conservative lookup must NOT find the in-tree binary.
    assert config.find_dotnet_sidecar(auto_detect=True) is None
    # The explicit lookup MAY find the in-tree binary — that's its job.
    # We don't assert on it because the in-tree publish may not be present.


def test_explicit_csharp_lookup_includes_in_tree(monkeypatch):
    """The non-auto variant of find_dotnet_sidecar checks the in-tree path."""

    monkeypatch.delenv(config.DOTNET_SIDECAR_ENV, raising=False)
    config.reset_dotnet_cache()
    # On this dev tree we expect the in-tree binary to be present
    # (it ships with the worktree). On hosts without the build, this
    # test is a no-op and just verifies the lookup doesn't crash.
    result = config.find_dotnet_sidecar(auto_detect=False)
    if result is not None:
        assert result.is_file()
        assert result.name.lower() == config.DOTNET_SIDECAR_EXE.lower()
