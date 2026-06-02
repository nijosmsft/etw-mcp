"""Env-var compatibility shim for the v0.3 → v0.4 ``WPR_MCP_*`` →
``ETW_MCP_*`` rename.

All public env vars exposed by the server used to be prefixed
``WPR_MCP_``. The package was renamed from ``wpr-mcp-server`` to
``etw-mcp`` in v0.4.0 (the WPR_MCP_* name was a misnomer — WPR is one
capture tool among many; this MCP analyzes ETW from xperf, native
OpenTraceW, the .NET sidecar, and pktmon). To avoid breaking existing
user MCP configurations, every legacy ``WPR_MCP_*`` env var is still
read with a one-shot ``DeprecationWarning`` when its new
``ETW_MCP_*`` counterpart is unset.

Usage::

    from etw_analyzer.native.env_compat import getenv

    sidecar = getenv("ETW_MCP_DOTNET_SIDECAR")

Reads via :func:`getenv` automatically pick up the legacy name when
the new name is unset. The legacy fallback path will be removed in
v1.0.
"""

from __future__ import annotations

import os
import warnings
from typing import Optional


# (new_name → legacy_name) for every public env var that flipped prefix in
# v0.4.0. Add new pairs here when introducing more env vars that need a
# back-compat alias.
_ENV_VAR_ALIASES: dict[str, str] = {
    "ETW_MCP_CSHARP_SIDECAR": "WPR_MCP_CSHARP_SIDECAR",
    "ETW_MCP_DOTNET_SIDECAR": "WPR_MCP_DOTNET_SIDECAR",
    "ETW_MCP_EVIDENCE_PATH": "WPR_MCP_EVIDENCE_PATH",
    "ETW_MCP_MODE": "WPR_MCP_MODE",
    "ETW_MCP_NATIVE_ALLOW_LARGE": "WPR_MCP_NATIVE_ALLOW_LARGE",
    "ETW_MCP_NATIVE_MAX_ETL_MB": "WPR_MCP_NATIVE_MAX_ETL_MB",
    # v0.5: auto-bootstrap opt-out. Symmetric WPR_MCP_* alias retained
    # so the table stays uniform; this var is brand-new in v0.5 so no
    # real operator is using the legacy name today, but the symmetry
    # keeps the shim's contract obvious for future deprecations.
    "ETW_MCP_NO_AUTO_DOWNLOAD": "WPR_MCP_NO_AUTO_DOWNLOAD",
    "ETW_MCP_NATIVE_STREAMING": "WPR_MCP_NATIVE_STREAMING",
    "ETW_MCP_NATIVE_STREAMING_PROFILE": "WPR_MCP_NATIVE_STREAMING_PROFILE",
    "ETW_MCP_NATIVE_WORKER": "WPR_MCP_NATIVE_WORKER",
    "ETW_MCP_NATIVE_WORKER_DISABLE_JOB": "WPR_MCP_NATIVE_WORKER_DISABLE_JOB",
    "ETW_MCP_NATIVE_WORKER_MEMORY_MB": "WPR_MCP_NATIVE_WORKER_MEMORY_MB",
    "ETW_MCP_NATIVE_WORKER_STALE_SECONDS": "WPR_MCP_NATIVE_WORKER_STALE_SECONDS",
    "ETW_MCP_NATIVE_WORKER_SYMBOL_PATH": "WPR_MCP_NATIVE_WORKER_SYMBOL_PATH",
    "ETW_MCP_NATIVE_WORKER_TIMEOUT_SECONDS": "WPR_MCP_NATIVE_WORKER_TIMEOUT_SECONDS",
}


# Track which legacy names have already emitted a deprecation warning in
# this process so callers don't get spammed when an env var is read on
# every load_trace.
_warned: set[str] = set()


def getenv(name: str, default: Optional[str] = None) -> Optional[str]:
    """Read an env var, preferring the new ``ETW_MCP_*`` name and falling
    back to the legacy ``WPR_MCP_*`` alias with a one-shot warning.

    Parameters
    ----------
    name:
        The new env-var name. When ``name`` is not in the alias table this
        helper is exactly equivalent to :func:`os.getenv`, including for
        the no-prefix case.
    default:
        Returned only when neither the new name nor the legacy alias is
        set.

    Returns
    -------
    str | None
        The resolved env var value, or ``default`` when both names are
        unset.
    """

    if name not in _ENV_VAR_ALIASES:
        return os.getenv(name, default)

    new_val = os.getenv(name)
    if new_val is not None:
        return new_val

    legacy = _ENV_VAR_ALIASES[name]
    legacy_val = os.getenv(legacy)
    if legacy_val is not None:
        _warn_once(legacy, name)
        return legacy_val

    return default


def reset_warning_state() -> None:
    """Forget which legacy names have already warned. Test-only."""

    _warned.clear()


def _warn_once(legacy: str, new: str) -> None:
    if legacy in _warned:
        return
    _warned.add(legacy)
    warnings.warn(
        f"Env var {legacy} is deprecated; rename to {new}. "
        "The legacy name will stop being read in v1.0.",
        DeprecationWarning,
        stacklevel=3,
    )


__all__ = ["getenv", "reset_warning_state"]
