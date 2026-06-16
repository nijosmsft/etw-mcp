"""Tests for dbghelp MSFZ capability metadata and override discovery."""

from __future__ import annotations

import os
import sys

import pytest


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="dbghelp binding requires Windows",
)


def test_dbghelp_version_supports_msfz_threshold():
    from etw_analyzer.native.bindings.dbghelp import dbghelp_version_supports_msfz

    assert dbghelp_version_supports_msfz("10.0.26100.8328") is False
    assert dbghelp_version_supports_msfz("10.0.29507.1001") is True
    assert dbghelp_version_supports_msfz("not-a-version") is None
    assert dbghelp_version_supports_msfz(None) is None


def test_load_dbghelp_honors_env_override(monkeypatch: pytest.MonkeyPatch):
    from etw_analyzer.native.bindings import dbghelp

    override = dbghelp.LOADED_DBGHELP_PATH
    if not override or not os.path.exists(override):
        pytest.skip("No resolved dbghelp path available for override test")

    monkeypatch.setenv("ETW_MCP_DBGHELP", override)
    monkeypatch.delenv("ETW_MCP_SYMSRV", raising=False)

    dll = dbghelp._load_dbghelp()

    assert dll is not None
    assert dbghelp.LOADED_DBGHELP_PATH is not None
    assert os.path.normcase(os.path.abspath(dbghelp.LOADED_DBGHELP_PATH)) == (
        os.path.normcase(os.path.abspath(override))
    )
