"""Mode resolution for ``load_trace``.

The resolution order is documented in the design doc §8.1:

    1. The explicit ``mode=...`` argument on ``load_trace``.
    2. The ``WPR_MCP_MODE`` environment variable.
    3. The hard-coded default ``"auto"`` (Phase N5 flipped this from
       ``"xperf"`` once the native pipeline reached parity).

When ``"auto"`` is requested, the resolved mode is computed by probing
the native consumer; on failure the result is ``"xperf"`` and the
auto-detect failure is cached for the lifetime of the process so we
don't re-probe on every load.

When ``"native"`` is requested explicitly but the consumer is not
available (e.g. running on a non-Windows host, or ``tdh.dll`` failed
to load), :func:`resolve_mode` raises ``RuntimeError``. Auto silently
falls back to xperf in the same situation — the contract is "explicit
wins over graceful degradation".
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


VALID_MODES = frozenset({"xperf", "native", "auto"})
DEFAULT_NATIVE_MAX_ETL_MB = 512.0
NATIVE_MAX_ETL_MB_ENV = "WPR_MCP_NATIVE_MAX_ETL_MB"
NATIVE_ALLOW_LARGE_ENV = "WPR_MCP_NATIVE_ALLOW_LARGE"


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
        return "auto"
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

    Raises
    ------
    RuntimeError
        When ``mode="native"`` is requested explicitly (via arg or env
        var) but the native consumer is not available on this host.
        ``mode="auto"`` silently degrades to ``"xperf"`` instead.
    """

    global _AUTO_CACHED

    env_mode = os.environ.get("WPR_MCP_MODE")

    # Arg wins, except that ``"auto"`` is treated as "let policy
    # decide" — i.e. it's indistinguishable from "no arg passed"
    # because Python can't tell a caller-supplied ``"auto"`` from
    # the default. That lets the env var override the new default
    # without needing the caller to pass ``mode=None``. Empty string
    # is also treated as "not provided" so callers can pipe through
    # environment-driven config without quoting tricks.
    candidate: Optional[str] = None
    if arg_mode:
        normalized_arg = normalize_mode(arg_mode)
        if normalized_arg == "auto" and env_mode:
            candidate = normalize_mode(env_mode)
        else:
            candidate = normalized_arg
    elif env_mode:
        candidate = normalize_mode(env_mode)
    else:
        candidate = "auto"

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

    if candidate == "native":
        # Explicit native request — fail loudly when the consumer is
        # unavailable so the caller knows to switch to xperf rather
        # than silently getting a different pipeline.
        try:
            from .consumer import is_available
        except Exception as exc:
            raise RuntimeError(
                "mode='native' was requested but the native ETW consumer "
                "could not be imported on this host. Use mode='xperf' "
                "(or set WPR_MCP_MODE=xperf) to fall back to the "
                "text-based xperf extraction pipeline. "
                f"Underlying error: {exc}"
            ) from exc
        if not is_available(etl_path):
            raise RuntimeError(
                "mode='native' was requested but the native ETW consumer "
                "is not available on this host (advapi32/tdh failed to "
                "load, or the trace file could not be probed). Use "
                "mode='xperf' (or set WPR_MCP_MODE=xperf) to fall back "
                "to the text-based xperf extraction pipeline."
            )

    return candidate


def _etl_size_mb(etl_path: Path | str) -> float:
    return Path(etl_path).stat().st_size / (1024 * 1024)


def _native_max_etl_mb() -> float:
    raw = os.environ.get(NATIVE_MAX_ETL_MB_ENV)
    if raw is None or raw.strip() == "":
        return DEFAULT_NATIVE_MAX_ETL_MB
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(
            f"{NATIVE_MAX_ETL_MB_ENV} must be a positive number of MB, got {raw!r}."
        ) from exc
    if value <= 0:
        raise ValueError(
            f"{NATIVE_MAX_ETL_MB_ENV} must be a positive number of MB, got {raw!r}."
        )
    return value


def _allow_large_native() -> bool:
    return os.environ.get(NATIVE_ALLOW_LARGE_ENV) == "1"


def _native_was_forced(arg_mode: Optional[str]) -> bool:
    if arg_mode:
        normalized_arg = normalize_mode(arg_mode)
        if normalized_arg == "native":
            return True
        if normalized_arg != "auto":
            return False

    env_mode = os.environ.get("WPR_MCP_MODE")
    if env_mode:
        return normalize_mode(env_mode) == "native"
    return False


def apply_native_size_guardrail(
    arg_mode: Optional[str],
    resolved_mode: str,
    etl_path: Path | str,
) -> tuple[str, str | None]:
    """Apply the native ETW size guardrail.

    Native extraction buffers decoded events today. To avoid OOM on large
    traces, auto mode falls back to xperf above ``WPR_MCP_NATIVE_MAX_ETL_MB``.
    Explicit native requests fail fast unless ``WPR_MCP_NATIVE_ALLOW_LARGE=1``
    is set.
    """

    if resolved_mode != "native" or _allow_large_native():
        return resolved_mode, None

    max_mb = _native_max_etl_mb()
    size_mb = _etl_size_mb(etl_path)
    if size_mb <= max_mb:
        return resolved_mode, None

    base = (
        f"ETL is {size_mb:.1f} MB, above the native safety limit of "
        f"{max_mb:.1f} MB ({NATIVE_MAX_ETL_MB_ENV}). The native ETW "
        "pipeline currently buffers decoded events and may run out of memory "
        "on large traces."
    )
    if _native_was_forced(arg_mode):
        raise RuntimeError(
            base
            + " Use mode='xperf' for this trace, raise "
            f"{NATIVE_MAX_ETL_MB_ENV}, or set {NATIVE_ALLOW_LARGE_ENV}=1 to "
            "bypass the guardrail."
        )

    return "xperf", base + " Falling back to mode='xperf'."


def reset_auto_cache() -> None:
    """Clear the cached auto-detect result. Primarily for tests."""

    global _AUTO_CACHED
    _AUTO_CACHED = None


__all__ = [
    "VALID_MODES",
    "DEFAULT_NATIVE_MAX_ETL_MB",
    "NATIVE_ALLOW_LARGE_ENV",
    "NATIVE_MAX_ETL_MB_ENV",
    "apply_native_size_guardrail",
    "normalize_mode",
    "resolve_mode",
    "reset_auto_cache",
]
