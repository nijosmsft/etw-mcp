"""Startup / MCP-handshake regression tests (fleet parity — see #37).

These guard the fastmcp migration that fixed the startup crash:

  * FastMCP must be sourced from the standalone ``fastmcp`` package, never the
    removed ``mcp.server.fastmcp`` shim (the crash in #37).
  * The ``_EtwFastMCP.tool()`` shim must leave ``@mcp.tool()``-decorated
    functions directly callable (1.x behaviour every tool module + the test
    suite relies on), rather than replacing them with a non-callable
    ``FunctionTool`` object.
  * The server must complete a real MCP ``initialize`` handshake and expose the
    full tool set over both an in-memory client and a real stdio subprocess.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]

# The full tool set is ~65 tools; use a floor so adding tools never breaks this.
_MIN_TOOL_COUNT = 60
_REQUIRED_TOOLS = {"load_trace", "get_thread_cpu_precise"}


# --------------------------------------------------------------------------- #
# Regression guard: FastMCP comes from the standalone `fastmcp` package.
# --------------------------------------------------------------------------- #
def test_fastmcp_sourced_from_standalone_package() -> None:
    """`_EtwFastMCP` must subclass the standalone `fastmcp` FastMCP, not the
    removed `mcp.server.fastmcp` one that caused the #37 startup crash."""
    from etw_analyzer import app

    # The `FastMCP` name bound in app.py must resolve to the standalone package.
    assert app.FastMCP.__module__.startswith("fastmcp"), app.FastMCP.__module__
    assert not app.FastMCP.__module__.startswith("mcp.server.fastmcp")

    # The shim's base class must likewise be the standalone FastMCP.
    base = app._EtwFastMCP.__bases__[0]
    assert base.__name__ == "FastMCP"
    assert base.__module__.startswith("fastmcp"), base.__module__
    assert not base.__module__.startswith("mcp.server.fastmcp")


def test_app_source_imports_standalone_fastmcp() -> None:
    """Source-level guard: app.py imports from `fastmcp`, never
    `mcp.server.fastmcp` (belt-and-suspenders against a silent regression)."""
    source = (REPO_ROOT / "src" / "etw_analyzer" / "app.py").read_text(encoding="utf-8")
    assert "from fastmcp import FastMCP" in source
    # Guard the import, not the prose: app.py's docstring legitimately names the
    # removed `mcp.server.fastmcp` shim when explaining the migration, so only
    # reject an actual import of it.
    assert "import mcp.server.fastmcp" not in source
    assert "from mcp.server.fastmcp" not in source


# --------------------------------------------------------------------------- #
# Regression guard: the tool() shim leaves decorated functions callable.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "module_path, attr",
    [
        ("etw_analyzer.tools.trace_mgmt", "load_trace"),
        ("etw_analyzer.tools.thread_cpu_precise", "get_thread_cpu_precise"),
    ],
)
def test_tool_shim_leaves_functions_callable(module_path: str, attr: str) -> None:
    """`@mcp.tool()` must hand back the underlying function (type `function`,
    callable), not a non-callable FunctionTool object."""
    import etw_analyzer.server  # noqa: F401 — ensures all tools are registered

    module = __import__(module_path, fromlist=[attr])
    fn = getattr(module, attr)
    assert isinstance(fn, types.FunctionType), f"{attr} is {type(fn)!r}, not a function"
    assert callable(fn)
    # A genuine function has a real signature; a FunctionTool object would not.
    assert inspect.signature(fn) is not None


# --------------------------------------------------------------------------- #
# Real MCP initialize handshake — in-memory FastMCP client.
# --------------------------------------------------------------------------- #
def test_in_memory_initialize_and_tools_list() -> None:
    """A real MCP initialize handshake over an in-memory client returns a valid
    result with serverInfo `etw-trace-analyzer` and the full tool set."""
    import etw_analyzer.server as server
    from fastmcp import Client

    async def _run() -> tuple[str, list[str]]:
        async with Client(server.mcp) as client:
            init = client.initialize_result
            tools = await client.list_tools()
            return init.serverInfo.name, [t.name for t in tools]

    name, tool_names = asyncio.run(_run())

    assert name == "etw-trace-analyzer"
    assert len(tool_names) >= _MIN_TOOL_COUNT, f"only {len(tool_names)} tools"
    assert _REQUIRED_TOOLS <= set(tool_names), _REQUIRED_TOOLS - set(tool_names)


# --------------------------------------------------------------------------- #
# Real MCP initialize handshake — actual stdio subprocess (startup smoke).
# --------------------------------------------------------------------------- #
def test_stdio_subprocess_initialize_and_tools_list() -> None:
    """`python -m etw_analyzer.server` must start and complete a JSON-RPC
    initialize + tools/list exchange over real stdio (proves the process boots
    without the #37 import crash)."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(REPO_ROOT / "src"), env.get("PYTHONPATH", "")]
    )

    proc = subprocess.Popen(
        [sys.executable, "-m", "etw_analyzer.server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
        env=env,
        cwd=str(REPO_ROOT),
    )

    def send(obj: dict) -> None:
        assert proc.stdin is not None
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()

    def read_result() -> dict:
        assert proc.stdout is not None
        while True:
            line = proc.stdout.readline()
            assert line, "server closed stdout before responding"
            line = line.strip()
            if not line:
                continue
            msg = json.loads(line)
            if "id" in msg and msg.get("id") is not None:
                return msg

    try:
        send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "handshake-test", "version": "0"},
                },
            }
        )
        init = read_result()
        assert "error" not in init, init
        assert init["result"]["serverInfo"]["name"] == "etw-trace-analyzer"

        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        listing = read_result()
        assert "error" not in listing, listing
        tool_names = [t["name"] for t in listing["result"]["tools"]]
        assert len(tool_names) >= _MIN_TOOL_COUNT, f"only {len(tool_names)} tools"
        assert _REQUIRED_TOOLS <= set(tool_names), _REQUIRED_TOOLS - set(tool_names)
    finally:
        if proc.stdin is not None:
            proc.stdin.close()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.wait(timeout=10)
