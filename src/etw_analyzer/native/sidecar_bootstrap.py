"""Locate the .NET sidecar binary, fetching it from upstream when necessary.

Resolution order (first hit wins):

    1. ``ETW_MCP_DOTNET_SIDECAR`` env var     -> explicit override
    2. ``ETW_MCP_NO_AUTO_DOWNLOAD=1``         -> fail fast (air-gapped)
    3. cached binary at ``%LOCALAPPDATA%``    -> reuse
    4. fetch from GitHub release              -> cache + reuse

The fetched binary is verified against the release's SHA256 checksum
file (``etw-extract.exe.sha256``) when one is published. When no
checksum file is found, a warning is logged to stderr and the binary
is used unverified — the v0.4.0 release workflow does NOT publish a
SHA256 file, so the warning is the expected outcome today. The fetch
is atomic: ``urlretrieve`` writes to a sibling ``.tmp`` path and the
final filename appears only on ``os.replace`` success.

The wheel runs over MCP stdio, so all progress / warning output is
sent to ``stderr`` where MCP clients surface it as operator-visible
log lines.

Public surface
--------------
- :func:`resolve_sidecar_path` — the only function the rest of the
  package should call. Returns a usable :class:`pathlib.Path` to
  ``etw-extract.exe`` or raises :class:`RuntimeError` with an
  LLM-actionable message.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from .env_compat import getenv as _compat_getenv


SIDECAR_ENV = "ETW_MCP_DOTNET_SIDECAR"
NO_AUTO_DOWNLOAD_ENV = "ETW_MCP_NO_AUTO_DOWNLOAD"
SIDECAR_EXE = "etw-extract.exe"
SIDECAR_SHA256_SUFFIX = ".sha256"
RELEASE_URL_TEMPLATE = (
    "https://github.com/nijosmsft/etw-mcp/releases/download/v{version}/{filename}"
)
PACKAGE_DIST_NAME = "etw-mcp"


def resolve_sidecar_path() -> Path:
    """Return a path to a usable ``etw-extract.exe`` binary.

    Walks the four-step resolution chain documented at the module
    docstring. On any unrecoverable failure raises
    :class:`RuntimeError` with a message naming the relevant env vars
    and (when applicable) the cache path and the upstream URL, so an
    LLM operator can act on the error without re-reading source.
    """

    override = _explicit_override()
    if override is not None:
        return override

    version = _wheel_version()
    cache_path = _cached_binary_path(version)
    if cache_path.exists():
        return cache_path

    if _autobootstrap_blocked():
        raise RuntimeError(
            f"{SIDECAR_ENV} is unset and {NO_AUTO_DOWNLOAD_ENV} blocks "
            f"fetching. Set {SIDECAR_ENV} to the sidecar binary path, "
            f"or unset {NO_AUTO_DOWNLOAD_ENV}."
        )

    _fetch_sidecar(version, cache_path)
    return cache_path


def _explicit_override() -> Optional[Path]:
    """Step 1: honor an explicit ``ETW_MCP_DOTNET_SIDECAR`` setting.

    Returns ``None`` when the env var is unset (so the caller can fall
    through to the cache / fetch paths). Raises :class:`RuntimeError`
    when the env var is set but points at a non-existent file — that
    is an operator misconfiguration and must surface loudly rather
    than be papered over by the auto-fetch path.
    """

    raw = _compat_getenv(SIDECAR_ENV)
    if not raw:
        return None
    path = Path(raw)
    if not path.exists():
        raise RuntimeError(
            f"{SIDECAR_ENV} is set to {raw} but no file exists at that "
            "path. Either update the env var to point at a valid "
            f"sidecar binary, or unset {SIDECAR_ENV} to let the wheel "
            "auto-fetch the matching release."
        )
    return path


def _autobootstrap_blocked() -> bool:
    """Step 2: return ``True`` when ``ETW_MCP_NO_AUTO_DOWNLOAD=1``.

    Accepts only the literal ``"1"`` so an unrelated truthy value
    (e.g. a path) doesn't accidentally disable auto-bootstrap.
    """

    raw = _compat_getenv(NO_AUTO_DOWNLOAD_ENV)
    return raw == "1"


def _cached_binary_path(version: str) -> Path:
    """Return the per-version cache path under ``%LOCALAPPDATA%``.

    On non-Windows hosts (e.g. dev sandboxes, CI) ``LOCALAPPDATA`` may
    not be set; we fall back to ``~/.cache/etw-mcp/sidecar`` so the
    resolver still produces a deterministic path the caller can
    interrogate. The wheel itself is Windows-only at runtime so the
    fallback is purely a developer-ergonomics concession.
    """

    local_app = os.environ.get("LOCALAPPDATA")
    if local_app:
        base = Path(local_app) / "etw-mcp" / "sidecar"
    else:
        base = Path.home() / ".cache" / "etw-mcp" / "sidecar"
    return base / f"v{version}" / SIDECAR_EXE


def _wheel_version() -> str:
    """Return the installed wheel version.

    Primary: :func:`importlib.metadata.version` against the
    distribution name. Falls back to ``etw_analyzer.__version__`` for
    the editable-install case where the dist-info metadata is missing
    or stale (e.g. ``pip install -e .`` without a fresh build, or
    running directly from a source checkout).
    """

    try:
        return importlib.metadata.version(PACKAGE_DIST_NAME)
    except importlib.metadata.PackageNotFoundError:
        from etw_analyzer import __version__

        return __version__


def _fetch_sidecar(version: str, dest: Path) -> None:
    """Step 4: download the sidecar and write it atomically to ``dest``.

    The file is downloaded to ``dest.with_suffix(dest.suffix + ".tmp")``
    first, optionally verified, then renamed via :func:`os.replace`.
    A mid-fetch crash leaves only the ``.tmp`` artefact behind — the
    final filename never contains a partially-written file.
    """

    url = RELEASE_URL_TEMPLATE.format(version=version, filename=SIDECAR_EXE)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")

    print(
        f"etw-mcp: fetching sidecar v{version} from {url}",
        file=sys.stderr,
        flush=True,
    )

    try:
        urllib.request.urlretrieve(url, tmp)
    except (urllib.error.URLError, OSError) as exc:
        # urlretrieve may have left a partial .tmp behind; clean it up
        # so retries see a fresh slate.
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise RuntimeError(
            f"Failed to fetch sidecar from {url}: {exc}. Set "
            f"{SIDECAR_ENV} to a manually-downloaded "
            f"{SIDECAR_EXE} to bypass, or set "
            f"{NO_AUTO_DOWNLOAD_ENV}=1 to disable auto-fetch."
        ) from exc

    try:
        _try_verify_sha256(url, tmp)
    except Exception:
        # Verification failure: drop the tmp so a retry does not reuse
        # a tampered/corrupt artefact.
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise

    os.replace(tmp, dest)
    print(
        f"etw-mcp: cached sidecar at {dest}",
        file=sys.stderr,
        flush=True,
    )


def _try_verify_sha256(url: str, binary_path: Path) -> bool:
    """Verify ``binary_path`` against ``<url>.sha256`` when one exists.

    Returns ``True`` when verification succeeded or the checksum file
    is absent (the v0.4.0 release workflow does NOT publish one yet —
    that is a documented gap, not a failure). Returns ``False`` only
    when an unexpected non-404 transport error occurred while fetching
    the checksum (also non-fatal — we warn and proceed). Raises
    :class:`RuntimeError` only on a real checksum mismatch.
    """

    checksum_url = url + SIDECAR_SHA256_SUFFIX

    try:
        with urllib.request.urlopen(checksum_url) as resp:
            checksum_body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            print(
                "etw-mcp: sidecar fetched without checksum verification "
                "— release workflow does not publish SHA256 today "
                f"({checksum_url} returned 404).",
                file=sys.stderr,
                flush=True,
            )
            return True
        print(
            f"etw-mcp: could not fetch checksum from {checksum_url} "
            f"(HTTP {exc.code}); proceeding without verification.",
            file=sys.stderr,
            flush=True,
        )
        return False
    except (urllib.error.URLError, OSError) as exc:
        print(
            f"etw-mcp: could not fetch checksum from {checksum_url} "
            f"({exc}); proceeding without verification.",
            file=sys.stderr,
            flush=True,
        )
        return False

    expected = _parse_sha256_body(checksum_body)
    if expected is None:
        print(
            f"etw-mcp: checksum file at {checksum_url} did not contain "
            "a recognizable SHA256 digest; proceeding without "
            "verification.",
            file=sys.stderr,
            flush=True,
        )
        return False

    actual = _sha256_of_file(binary_path)
    if actual.lower() != expected.lower():
        raise RuntimeError(
            f"Sidecar checksum mismatch for {url}: expected "
            f"{expected.lower()}, got {actual.lower()}. The download "
            "may be corrupt or tampered. Refusing to install."
        )
    return True


def _parse_sha256_body(body: str) -> Optional[str]:
    """Extract a 64-hex SHA256 from a checksum-file body.

    Accepts either ``"<hex>  filename"`` (shasum-style) or a bare hex
    string on its own line. Returns ``None`` when the body has no
    plausible digest.
    """

    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0]
        if len(token) == 64 and all(c in "0123456789abcdefABCDEF" for c in token):
            return token
    return None


def _sha256_of_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "NO_AUTO_DOWNLOAD_ENV",
    "RELEASE_URL_TEMPLATE",
    "SIDECAR_ENV",
    "SIDECAR_EXE",
    "resolve_sidecar_path",
]
