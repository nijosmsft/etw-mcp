"""Mode resolution for ``load_trace``.

The resolution order is documented in the design doc §8.1:

    1. The explicit ``mode=...`` argument on ``load_trace``.
    2. The ``ETW_MCP_MODE`` environment variable
       (legacy ``WPR_MCP_MODE`` still read with a DeprecationWarning).
    3. The hard-coded default ``"auto"`` (Phase N5 flipped this from
       ``"xperf"`` once the native pipeline became a fast-path coverage
       subset for common analysis).

When ``"auto"`` is requested, the resolved mode is computed by probing
each backend in preference order: ``"dotnet"`` wins when the .NET sidecar
binary is locatable (see :func:`find_dotnet_sidecar`), then ``"native"``
when the in-process ETW consumer loads, and finally ``"xperf"`` as the
universally-available fallback. The auto-detect result is cached for the
lifetime of the process so we don't re-probe on every load. None of the
non-xperf modes are full xperf parity — they decode curated subsets of
providers and aggregations.

When ``"native"`` is requested explicitly but the consumer is not
available (e.g. running on a non-Windows host, or ``tdh.dll`` failed
to load), :func:`resolve_mode` raises ``RuntimeError``. When
``"dotnet"`` is requested explicitly but the sidecar binary is not
locatable, :func:`resolve_mode` raises ``ValueError`` naming the
``ETW_MCP_DOTNET_SIDECAR`` override. Auto silently falls back along the
chain in the same situation — the contract is "explicit wins over
graceful degradation".
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from .env_compat import getenv as _compat_getenv


VALID_MODES = frozenset({"xperf", "native", "dotnet", "auto"})
DEFAULT_NATIVE_MAX_ETL_MB = 512.0
NATIVE_MAX_ETL_MB_ENV = "ETW_MCP_NATIVE_MAX_ETL_MB"
NATIVE_ALLOW_LARGE_ENV = "ETW_MCP_NATIVE_ALLOW_LARGE"
DOTNET_SIDECAR_ENV = "ETW_MCP_DOTNET_SIDECAR"
DOTNET_SIDECAR_EXE = "etw-extract.exe"


# Cache the auto-detect result so we don't pay the ``OpenTraceW`` probe
# or the .NET sidecar path lookup more than once per process. Set to
# ``None`` while undetermined, then ``"dotnet"``, ``"native"`` or
# ``"xperf"`` once resolved.
_AUTO_CACHED: Optional[str] = None
_DOTNET_SIDECAR_CACHED: Optional[Path] = None
_DOTNET_SIDECAR_PROBED: bool = False


def find_dotnet_sidecar(*, auto_detect: bool = False) -> Path | None:
    """Locate the C# sidecar binary ``etw-extract.exe``.

    Search order:

    1. ``ETW_MCP_DOTNET_SIDECAR`` environment variable (legacy
       ``WPR_MCP_DOTNET_SIDECAR`` still read with a DeprecationWarning) —
       when set, the value MUST point at an existing file or ``None`` is
       returned. This lets a deployment pin the exact build that gets
       exercised.
    2. Relative to the installed package — ``../../dotnet/publish/win-x64/``
       resolved from this module's directory. Convenient for in-tree
       development where ``dotnet publish`` lands the binary next to the
       Python source. **Skipped when ``auto_detect=True``** — auto-mode
       should not silently flip a developer's existing native pipeline
       to dotnet just because they happen to have a publish output
       lying around.
    3. ``PATH`` lookup — last resort for system-wide installations.

    The result is cached for the lifetime of the process; tests can clear
    the cache via :func:`reset_dotnet_cache`. Note that the cache key
    is **independent** of ``auto_detect`` — the first call wins for the
    process; pass ``auto_detect=True`` only for the auto-fallback chain.

    Parameters
    ----------
    auto_detect:
        When ``True``, used by :func:`resolve_mode` for the auto chain.
        Skips the in-tree publish probe so a stale dev build doesn't
        change the default pipeline. When ``False`` (the default,
        e.g. an explicit ``mode="dotnet"`` request) all three paths
        are checked.
    """

    global _DOTNET_SIDECAR_CACHED, _DOTNET_SIDECAR_PROBED

    # When auto-detecting, never consult the cache — the cache may have
    # been populated by an explicit lookup that included the in-tree
    # path. Recompute every time with the narrow rules. This is cheap
    # (an env var read and a ``shutil.which`` call).
    if not auto_detect and _DOTNET_SIDECAR_PROBED:
        return _DOTNET_SIDECAR_CACHED

    candidates: list[Path] = []
    env_only = False

    env_override = _compat_getenv(DOTNET_SIDECAR_ENV)
    if env_override:
        # When the env var is set, the caller has pinned an exact path.
        # Don't fall through to in-tree / PATH lookup — that masks
        # misconfigurations (typo'd path silently picks up the in-tree
        # build of a different version).
        candidates.append(Path(env_override))
        env_only = True
    elif not auto_detect:
        # ``config.py`` lives at ``src/etw_analyzer/native/config.py``. The
        # in-tree publish output is at ``dotnet/publish/win-x64/`` from the
        # repo root, i.e. three directories up.
        here = Path(__file__).resolve()
        repo_root_guess = here.parent.parent.parent.parent
        candidates.append(
            repo_root_guess / "dotnet" / "publish" / "win-x64" / DOTNET_SIDECAR_EXE
        )

    found: Path | None = None
    for candidate in candidates:
        if candidate.is_file():
            found = candidate.resolve()
            break

    if found is None and not env_only:
        # PATH lookup. ``shutil.which`` returns ``None`` when missing.
        import shutil

        which = shutil.which(DOTNET_SIDECAR_EXE)
        if which:
            found = Path(which).resolve()

    if not auto_detect:
        _DOTNET_SIDECAR_CACHED = found
        _DOTNET_SIDECAR_PROBED = True
    return found


def reset_dotnet_cache() -> None:
    """Clear the cached C# sidecar lookup. Primarily for tests."""

    global _DOTNET_SIDECAR_CACHED, _DOTNET_SIDECAR_PROBED
    _DOTNET_SIDECAR_CACHED = None
    _DOTNET_SIDECAR_PROBED = False


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

    env_mode = _compat_getenv("ETW_MCP_MODE")

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
        # Preferred order: dotnet → native → xperf. Auto-detect uses the
        # conservative .NET sidecar lookup (env var + PATH only), so a
        # stray in-tree publish build does not flip the default pipeline.
        if find_dotnet_sidecar(auto_detect=True) is not None:
            _AUTO_CACHED = "dotnet"
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

    if candidate == "dotnet":
        # Explicit dotnet request — fail loudly when the binary cannot
        # be located so the caller knows to install/publish the sidecar
        # rather than silently falling through to a different pipeline.
        if find_dotnet_sidecar() is None:
            raise ValueError(
                "mode='dotnet' was requested but the .NET sidecar binary "
                f"({DOTNET_SIDECAR_EXE}) could not be located. Set the "
                f"{DOTNET_SIDECAR_ENV} environment variable to the absolute "
                "path of the built binary, publish it under "
                "dotnet/publish/win-x64/ in the repo, or add it to PATH. "
                "Use mode='native' or mode='xperf' to bypass the sidecar."
            )
        return candidate

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
                "(or set ETW_MCP_MODE=xperf) to fall back to the "
                "text-based xperf extraction pipeline. "
                f"Underlying error: {exc}"
            ) from exc
        if not is_available(etl_path):
            raise RuntimeError(
                "mode='native' was requested but the native ETW consumer "
                "is not available on this host (advapi32/tdh failed to "
                "load, or the trace file could not be probed). Use "
                "mode='xperf' (or set ETW_MCP_MODE=xperf) to fall back "
                "to the text-based xperf extraction pipeline."
            )

    return candidate


def _etl_size_mb(etl_path: Path | str) -> float:
    return Path(etl_path).stat().st_size / (1024 * 1024)


def _native_max_etl_mb() -> float:
    raw = _compat_getenv(NATIVE_MAX_ETL_MB_ENV)
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
    return _compat_getenv(NATIVE_ALLOW_LARGE_ENV) == "1"


def _native_was_forced(arg_mode: Optional[str]) -> bool:
    if arg_mode:
        normalized_arg = normalize_mode(arg_mode)
        if normalized_arg == "native":
            return True
        if normalized_arg != "auto":
            return False

    env_mode = _compat_getenv("ETW_MCP_MODE")
    if env_mode:
        return normalize_mode(env_mode) == "native"
    return False


def _dotnet_was_forced(arg_mode: Optional[str]) -> bool:
    if arg_mode:
        normalized_arg = normalize_mode(arg_mode)
        if normalized_arg == "dotnet":
            return True
        if normalized_arg != "auto":
            return False

    env_mode = _compat_getenv("ETW_MCP_MODE")
    if env_mode:
        return normalize_mode(env_mode) == "dotnet"
    return False


def apply_native_size_guardrail(
    arg_mode: Optional[str],
    resolved_mode: str,
    etl_path: Path | str,
) -> tuple[str, str | None]:
    """Apply the native ETW size guardrail.

    Native extraction buffers decoded events today. To avoid OOM on large
    traces, auto mode falls back to xperf above ``ETW_MCP_NATIVE_MAX_ETL_MB``.
    Explicit native requests fail fast unless ``ETW_MCP_NATIVE_ALLOW_LARGE=1``
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
    reset_dotnet_cache()


__all__ = [
    "DOTNET_SIDECAR_ENV",
    "DOTNET_SIDECAR_EXE",
    "VALID_MODES",
    "DEFAULT_NATIVE_MAX_ETL_MB",
    "NATIVE_ALLOW_LARGE_ENV",
    "NATIVE_MAX_ETL_MB_ENV",
    "apply_native_size_guardrail",
    "find_dotnet_sidecar",
    "normalize_mode",
    "resolve_mode",
    "reset_auto_cache",
    "reset_dotnet_cache",
]
