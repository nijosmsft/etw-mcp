"""Networking-scoped wrappers around existing analysis tools.

Each tool here is a thin wrapper that defaults ``module_filter`` (or the
equivalent argument on the underlying tool) to the curated networking module
set in :mod:`etw_analyzer.networking`. The point is to let users ask "what's
my network stack doing?" without having to know the exact module names.

Delegation rules:
- These tools do NOT reimplement any aggregation logic.
- They build a regex (or comma-separated string) from the resolved module set
  and call straight through to the underlying ``@mcp.tool()`` function.
- The returned markdown is identical in shape to the underlying tool's output,
  with a small networking-scoped annotation prepended to the header.
"""

from __future__ import annotations

from etw_analyzer.app import mcp
from etw_analyzer.networking import (
    NETWORK_MODULES_ALL,
    module_regex,
    modules_csv,
    resolve_module_set,
)
from etw_analyzer.tools.context_switch import get_lock_contention
from etw_analyzer.tools.cpu_sampling import get_hot_functions
from etw_analyzer.tools.dpc_isr import get_dpc_summary
from etw_analyzer.tools.stack_analysis import get_hot_stacks


_NETWORK_HEADER = "**Networking scope**"


def _annotate(output: str, modules: frozenset[str]) -> str:
    """Prepend a networking-scope annotation to the underlying tool's output."""
    count = len(modules)
    if count <= 6:
        preview = ", ".join(sorted(modules))
    else:
        preview = ", ".join(sorted(modules)[:6]) + f", ... ({count} total)"
    note = f"{_NETWORK_HEADER}: filtered to {count} module(s) — {preview}\n\n"
    return note + output


@mcp.tool()
def get_network_hot_functions(
    trace_id: str,
    cpu_filter: str | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
    max_rows: int = 30,
    denominator: str = "trace",
    denominator_lps: int | None = None,
    denominator_seconds: float | None = None,
    extra_modules: list[str] | None = None,
    replace_modules: list[str] | None = None,
) -> str:
    """Hot functions, scoped to the Windows networking stack by default.

    Wraps :func:`get_hot_functions` with the ``modules`` argument defaulted to
    the curated networking module set (kernel: tcpip.sys, NDIS.SYS, afd.sys,
    http.sys, xdp.sys, NIC drivers, ... user: ws2_32.dll, msquic.dll,
    schannel.dll, ...). Use this when you suspect a network bottleneck and
    don't want to enumerate module names by hand.

    Args:
        trace_id: ID returned by load_trace.
        cpu_filter: CPU range filter, e.g. '0' or '18-39'.
        start_time: Start of analysis window (seconds from trace start).
        end_time: End of analysis window (seconds from trace start).
        max_rows: Maximum rows to return. Default: 30.
        denominator: Percentage denominator: 'trace', 'active_cpus', 'active_busy', or 'custom'.
        denominator_lps: Logical processor count for denominator='custom'.
        denominator_seconds: Duration for denominator='custom'.
        extra_modules: Additional module names to union with the default network set.
        replace_modules: Override the default network set entirely with this list.
    """
    modules = resolve_module_set(extra_modules, replace_modules)
    output = get_hot_functions(
        trace_id=trace_id,
        modules=modules_csv(modules),
        cpu_filter=cpu_filter,
        start_time=start_time,
        end_time=end_time,
        max_rows=max_rows,
        denominator=denominator,
        denominator_lps=denominator_lps,
        denominator_seconds=denominator_seconds,
    )
    return _annotate(output, modules)


@mcp.tool()
def get_network_dpcs(
    trace_id: str,
    max_rows: int = 30,
    extra_modules: list[str] | None = None,
    replace_modules: list[str] | None = None,
) -> str:
    """DPC/ISR summary, scoped to networking modules by default.

    Wraps :func:`get_dpc_summary` with ``module_filter`` defaulted to the
    networking module set. Useful for spotting NIC driver DPCs that exceed
    the DPC watchdog threshold without having to know which driver name
    (mlx5.sys, ixgbe.sys, i40ea.sys, ...) is in use.

    Args:
        trace_id: ID returned by load_trace.
        max_rows: Maximum rows to return. Default: 30.
        extra_modules: Additional module names to union with the default network set.
        replace_modules: Override the default network set entirely with this list.
    """
    modules = resolve_module_set(extra_modules, replace_modules)
    output = get_dpc_summary(
        trace_id=trace_id,
        module_filter=module_regex(modules),
        max_rows=max_rows,
    )
    return _annotate(output, modules)


@mcp.tool()
def get_network_lock_contention(
    trace_id: str,
    function_filter: str | None = None,
    cpu_filter: str | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
    max_rows: int = 30,
    extra_modules: list[str] | None = None,
    replace_modules: list[str] | None = None,
) -> str:
    """Lock contention, scoped to ReadyThread stacks rooted in networking modules.

    Wraps :func:`get_lock_contention` with ``module_filter`` defaulted to the
    networking module set. The underlying tool matches the readying-thread
    stack column against the module pattern, so this surfaces things like UDP
    endpoint locks, NL locks, and AFD endpoint locks without manual hunting.

    Args:
        trace_id: ID returned by load_trace.
        function_filter: Filter by function in the readying stack.
        cpu_filter: CPU range filter, e.g. '18-39'.
        start_time: Start of analysis window (seconds from trace start).
        end_time: End of analysis window (seconds from trace start).
        max_rows: Maximum rows to return. Default: 30.
        extra_modules: Additional module names to union with the default network set.
        replace_modules: Override the default network set entirely with this list.
    """
    modules = resolve_module_set(extra_modules, replace_modules)
    output = get_lock_contention(
        trace_id=trace_id,
        module_filter=module_regex(modules),
        function_filter=function_filter,
        cpu_filter=cpu_filter,
        start_time=start_time,
        end_time=end_time,
        max_rows=max_rows,
    )
    return _annotate(output, modules)


@mcp.tool()
def get_network_hot_stacks(
    trace_id: str,
    function_filter: str | None = None,
    cpu_filter: str | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
    max_depth: int = 10,
    min_weight_pct: float = 1.0,
    dpc_only: bool = False,
    max_rows: int = 50,
    denominator: str = "trace",
    denominator_lps: int | None = None,
    denominator_seconds: float | None = None,
    extra_modules: list[str] | None = None,
    replace_modules: list[str] | None = None,
) -> str:
    """Hot stacks, restricted to frames in networking modules by default.

    Wraps :func:`get_hot_stacks` with ``module_filter`` defaulted to the
    networking module set. Each row is a frame whose module matches the set;
    pair with ``function_filter`` to drill into a specific call site.

    Args:
        trace_id: ID returned by load_trace.
        function_filter: Focus on specific function (substring).
        cpu_filter: CPU range filter, e.g. '18-39'.
        start_time: Start of analysis window (seconds from trace start).
        end_time: End of analysis window (seconds from trace start).
        max_depth: Reserved (kept for API compat).
        min_weight_pct: Prune frames below this % of total. Default: 1.0.
        dpc_only: Reserved (kept for API compat).
        max_rows: Max rows to return. Default: 50.
        denominator: Percentage denominator: 'trace', 'active_cpus', 'active_busy', or 'custom'.
        denominator_lps: Logical processor count for denominator='custom'.
        denominator_seconds: Duration for denominator='custom'.
        extra_modules: Additional module names to union with the default network set.
        replace_modules: Override the default network set entirely with this list.
    """
    modules = resolve_module_set(extra_modules, replace_modules)
    output = get_hot_stacks(
        trace_id=trace_id,
        module_filter=module_regex(modules),
        function_filter=function_filter,
        cpu_filter=cpu_filter,
        start_time=start_time,
        end_time=end_time,
        max_depth=max_depth,
        min_weight_pct=min_weight_pct,
        dpc_only=dpc_only,
        max_rows=max_rows,
        denominator=denominator,
        denominator_lps=denominator_lps,
        denominator_seconds=denominator_seconds,
    )
    return _annotate(output, modules)


__all__ = [
    "get_network_hot_functions",
    "get_network_dpcs",
    "get_network_lock_contention",
    "get_network_hot_stacks",
    "NETWORK_MODULES_ALL",
]
