"""Mode resolution for ``load_trace``.

The resolution order is documented in the design doc §8.1:

    1. The explicit ``mode=...`` argument on ``load_trace``.
    2. The ``WPR_MCP_MODE`` environment variable.
    3. The hard-coded default ``"xperf"`` (Phase N5 will flip to
       ``"auto"``).

When ``"auto"`` is requested, the resolved mode is computed by probing
the native consumer; on failure the result is ``"xperf"`` and the
auto-detect failure is cached for the lifetime of the process so we
don't re-probe on every load.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


VALID_MODES = frozenset({"xperf", "native", "auto"})


# Cache the auto-detect result so we don't pay the ``OpenTraceW`` probe
# more than once per process. Set to ``None`` while undetermined, then
# either ``"native"`` (auto chose native) or ``"xperf"`` (probe failed
# and we fell back).
_AUTO_CACHED: Optional[str] = None


def normalize_mode(mode: Optional[str]) -> str:
    """Validate ``mode`` and return it normalised to lowercase.

    Raises
    ------
    ValueError
        If ``mode`` is set to anything outside :data:`VALID_MODES`.
    """

    if mode is None:
        return "xperf"
    m = mode.lower()
    if m not in VALID_MODES:
        raise ValueError(
            f"Unknown mode {mode!r}. Expected one of: {sorted(VALID_MODES)}"
        )
    return m


def resolve_mode(
    arg_mode: Optional[str],
    etl_path: Optional[Path | str] = None,
) -> str:
    """Resolve the effective mode using the documented precedence.

    Returns one of ``"xperf"`` or ``"native"`` — ``"auto"`` is always
    collapsed to a concrete choice.
    """

    global _AUTO_CACHED

    env_mode = os.environ.get("WPR_MCP_MODE")

    # Arg wins. Empty string is treated as "not provided" so users can
    # pass through environment-driven config without quoting tricks.
    candidate: Optional[str] = None
    if arg_mode:
        candidate = normalize_mode(arg_mode)
    elif env_mode:
        candidate = normalize_mode(env_mode)
    else:
        candidate = "xperf"

    if candidate == "auto":
        if _AUTO_CACHED is not None:
            return _AUTO_CACHED
        try:
            from .consumer import is_available
        except Exception:
            _AUTO_CACHED = "xperf"
            return "xperf"
        if is_available(etl_path):
            _AUTO_CACHED = "native"
        else:
            _AUTO_CACHED = "xperf"
        return _AUTO_CACHED

    return candidate


def reset_auto_cache() -> None:
    """Clear the cached auto-detect result. Primarily for tests."""

    global _AUTO_CACHED
    _AUTO_CACHED = None


__all__ = [
    "VALID_MODES",
    "normalize_mode",
    "resolve_mode",
    "reset_auto_cache",
]
