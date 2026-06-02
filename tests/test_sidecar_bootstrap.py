"""Tests for :mod:`etw_analyzer.native.sidecar_bootstrap`.

Covers the four-step resolution chain documented at the module
docstring: explicit override, NO_AUTO_DOWNLOAD opt-out, cache hit,
and the auto-fetch path. All tests use ``tmp_path`` for filesystem
isolation and mock ``urllib.request`` so no real network is touched.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import urllib.error
from pathlib import Path
from typing import Callable

import pytest

from etw_analyzer.native import sidecar_bootstrap as sb


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Each test starts with a clean env + a private LOCALAPPDATA.

    The bootstrap module reads ``LOCALAPPDATA``, ``ETW_MCP_DOTNET_SIDECAR``,
    and ``ETW_MCP_NO_AUTO_DOWNLOAD``. Wiping them per-test keeps cases
    deterministic and prevents the host env from leaking into the
    suite.
    """

    monkeypatch.delenv("ETW_MCP_DOTNET_SIDECAR", raising=False)
    monkeypatch.delenv("WPR_MCP_DOTNET_SIDECAR", raising=False)
    monkeypatch.delenv("ETW_MCP_NO_AUTO_DOWNLOAD", raising=False)
    monkeypatch.delenv("WPR_MCP_NO_AUTO_DOWNLOAD", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "AppData" / "Local"))


@pytest.fixture
def fake_version(monkeypatch: pytest.MonkeyPatch) -> str:
    """Force ``_wheel_version`` to return a known value."""

    version = "9.9.9"
    monkeypatch.setattr(
        importlib.metadata, "version", lambda dist: version
    )
    return version


def _make_binary(path: Path, payload: bytes = b"FAKE-SIDECAR") -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return payload


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _install_urlretrieve(
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[str, Path], None],
) -> list[tuple[str, Path]]:
    """Install a fake ``urlretrieve`` that records calls + delegates."""

    calls: list[tuple[str, Path]] = []

    def fake_urlretrieve(url: str, filename, *_args, **_kwargs):
        path = Path(filename)
        calls.append((url, path))
        handler(url, path)
        return (str(path), None)

    monkeypatch.setattr(sb.urllib.request, "urlretrieve", fake_urlretrieve)
    return calls


def _install_urlopen_404(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the SHA256 fetch to 404 (the v0.4.0 release-workflow gap)."""

    def fake_urlopen(url, *_args, **_kwargs):
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

    monkeypatch.setattr(sb.urllib.request, "urlopen", fake_urlopen)


# ---------------------------------------------------------------------------
# 1. Explicit override wins
# ---------------------------------------------------------------------------


def test_explicit_override_wins_when_file_exists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = tmp_path / "etw-extract.exe"
    _make_binary(binary)
    monkeypatch.setenv("ETW_MCP_DOTNET_SIDECAR", str(binary))

    # Belt-and-braces: even if urlretrieve were called, it would fail the
    # test by raising. The override path must short-circuit before it.
    def boom(*_a, **_kw):
        raise AssertionError("urlretrieve must not be called when override is set")

    monkeypatch.setattr(sb.urllib.request, "urlretrieve", boom)

    result = sb.resolve_sidecar_path()
    assert result == binary


# ---------------------------------------------------------------------------
# 2. Explicit override but file missing
# ---------------------------------------------------------------------------


def test_explicit_override_missing_file_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    missing = tmp_path / "does-not-exist.exe"
    monkeypatch.setenv("ETW_MCP_DOTNET_SIDECAR", str(missing))

    with pytest.raises(RuntimeError) as ei:
        sb.resolve_sidecar_path()

    msg = str(ei.value)
    assert "ETW_MCP_DOTNET_SIDECAR" in msg
    assert str(missing) in msg


# ---------------------------------------------------------------------------
# 3. No env var, NO_AUTO_DOWNLOAD=1
# ---------------------------------------------------------------------------


def test_no_env_var_and_no_auto_download_raises(
    monkeypatch: pytest.MonkeyPatch, fake_version: str
) -> None:
    monkeypatch.setenv("ETW_MCP_NO_AUTO_DOWNLOAD", "1")

    def boom(*_a, **_kw):
        raise AssertionError("urlretrieve must not be called when blocked")

    monkeypatch.setattr(sb.urllib.request, "urlretrieve", boom)

    with pytest.raises(RuntimeError) as ei:
        sb.resolve_sidecar_path()

    msg = str(ei.value)
    assert "ETW_MCP_DOTNET_SIDECAR" in msg
    assert "ETW_MCP_NO_AUTO_DOWNLOAD" in msg


# ---------------------------------------------------------------------------
# 4. No env var, cache hit
# ---------------------------------------------------------------------------


def test_cache_hit_returns_cached_binary(
    monkeypatch: pytest.MonkeyPatch, fake_version: str
) -> None:
    cache_path = sb._cached_binary_path(fake_version)
    _make_binary(cache_path)

    def boom(*_a, **_kw):
        raise AssertionError("urlretrieve must not be called on cache hit")

    monkeypatch.setattr(sb.urllib.request, "urlretrieve", boom)

    result = sb.resolve_sidecar_path()
    assert result == cache_path
    assert result.read_bytes() == b"FAKE-SIDECAR"


# ---------------------------------------------------------------------------
# 5. No env var, cache miss, fetch succeeds
# ---------------------------------------------------------------------------


def test_cache_miss_fetches_and_caches(
    monkeypatch: pytest.MonkeyPatch,
    fake_version: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cache_path = sb._cached_binary_path(fake_version)
    assert not cache_path.exists()

    payload = b"DOWNLOADED-BYTES"

    def handler(url: str, tmp: Path) -> None:
        # Sanity-check that we got the .tmp sibling, never the real path.
        assert tmp.name.endswith(".tmp")
        assert tmp != cache_path
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(payload)

    calls = _install_urlretrieve(monkeypatch, handler)
    _install_urlopen_404(monkeypatch)

    result = sb.resolve_sidecar_path()

    assert result == cache_path
    assert cache_path.read_bytes() == payload
    # No stray .tmp left behind.
    assert not cache_path.with_suffix(cache_path.suffix + ".tmp").exists()

    assert len(calls) == 1
    fetched_url, _ = calls[0]
    expected_url = sb.RELEASE_URL_TEMPLATE.format(
        version=fake_version, filename=sb.SIDECAR_EXE
    )
    assert fetched_url == expected_url

    err = capsys.readouterr().err
    assert expected_url in err
    assert "fetching" in err.lower()


# ---------------------------------------------------------------------------
# 6. Fetch fails (404, network error)
# ---------------------------------------------------------------------------


def test_fetch_failure_raises_actionable_error(
    monkeypatch: pytest.MonkeyPatch, fake_version: str
) -> None:
    cache_path = sb._cached_binary_path(fake_version)

    def handler(url: str, tmp: Path) -> None:
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

    _install_urlretrieve(monkeypatch, handler)

    with pytest.raises(RuntimeError) as ei:
        sb.resolve_sidecar_path()

    msg = str(ei.value)
    assert "ETW_MCP_DOTNET_SIDECAR" in msg
    assert "ETW_MCP_NO_AUTO_DOWNLOAD" in msg
    assert not cache_path.exists()
    assert not cache_path.with_suffix(cache_path.suffix + ".tmp").exists()


# ---------------------------------------------------------------------------
# 7. Atomic rename: mid-fetch crash leaves only .tmp, never partial real file
# ---------------------------------------------------------------------------


def test_atomic_rename_partial_crash_never_creates_real_file(
    monkeypatch: pytest.MonkeyPatch, fake_version: str
) -> None:
    cache_path = sb._cached_binary_path(fake_version)

    def handler(url: str, tmp: Path) -> None:
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(b"PARTIAL")

    _install_urlretrieve(monkeypatch, handler)
    _install_urlopen_404(monkeypatch)

    # Inject a failure between urlretrieve and os.replace.
    def crashing_replace(_src, _dst):
        raise RuntimeError("simulated post-download crash")

    monkeypatch.setattr(sb.os, "replace", crashing_replace)

    with pytest.raises(RuntimeError, match="simulated post-download crash"):
        sb.resolve_sidecar_path()

    # The real file must never have appeared.
    assert not cache_path.exists()
    # The .tmp may or may not remain depending on which step failed; in
    # this scenario os.replace raised after the bytes landed, so the
    # .tmp is still there. That is the contract: at no point did the
    # final filename hold partial bytes.
    tmp_path = cache_path.with_suffix(cache_path.suffix + ".tmp")
    assert tmp_path.exists()
    assert tmp_path.read_bytes() == b"PARTIAL"


# ---------------------------------------------------------------------------
# 8. Wheel version probe
# ---------------------------------------------------------------------------


def test_wheel_version_probe_uses_importlib_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        importlib.metadata, "version", lambda dist: "1.2.3" if dist == "etw-mcp" else "X"
    )
    assert sb._wheel_version() == "1.2.3"


# ---------------------------------------------------------------------------
# 9. Editable-install fallback
# ---------------------------------------------------------------------------


def test_wheel_version_falls_back_to_package_constant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_not_found(_dist: str) -> str:
        raise importlib.metadata.PackageNotFoundError("etw-mcp")

    monkeypatch.setattr(importlib.metadata, "version", raise_not_found)

    import etw_analyzer

    # Round-trip through the module: whatever the package advertises is
    # what _wheel_version must return on the fallback path.
    assert sb._wheel_version() == etw_analyzer.__version__


# ---------------------------------------------------------------------------
# 10. Checksum verification absent path (warn + proceed)
# ---------------------------------------------------------------------------


def test_checksum_absent_warns_but_proceeds(
    monkeypatch: pytest.MonkeyPatch,
    fake_version: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cache_path = sb._cached_binary_path(fake_version)
    payload = b"WITHOUT-CHECKSUM"

    def handler(_url: str, tmp: Path) -> None:
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(payload)

    _install_urlretrieve(monkeypatch, handler)
    _install_urlopen_404(monkeypatch)

    result = sb.resolve_sidecar_path()
    assert result == cache_path
    assert result.read_bytes() == payload

    err = capsys.readouterr().err
    assert "without checksum verification" in err.lower()
    assert sb.SIDECAR_SHA256_SUFFIX in err


# ---------------------------------------------------------------------------
# 11. Checksum verification present path
# ---------------------------------------------------------------------------


def test_checksum_match_silent_success(
    monkeypatch: pytest.MonkeyPatch,
    fake_version: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cache_path = sb._cached_binary_path(fake_version)
    payload = b"VERIFIED-PAYLOAD"
    expected_hex = _sha256_hex(payload)

    def handler(_url: str, tmp: Path) -> None:
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(payload)

    _install_urlretrieve(monkeypatch, handler)

    class FakeResp:
        def __init__(self, body: bytes) -> None:
            self._body = body

        def read(self) -> bytes:
            return self._body

        def __enter__(self) -> "FakeResp":
            return self

        def __exit__(self, *_args) -> None:
            return None

    body = f"{expected_hex}  {sb.SIDECAR_EXE}\n".encode("utf-8")

    def fake_urlopen(url, *_a, **_kw):
        assert url.endswith(sb.SIDECAR_SHA256_SUFFIX)
        return FakeResp(body)

    monkeypatch.setattr(sb.urllib.request, "urlopen", fake_urlopen)

    result = sb.resolve_sidecar_path()
    assert result == cache_path
    assert result.read_bytes() == payload

    err = capsys.readouterr().err
    # No mismatch / no "without verification" message — silent success
    # except for the fetch + cached lines.
    assert "mismatch" not in err.lower()
    assert "without checksum verification" not in err.lower()


def test_checksum_mismatch_raises_and_cleans_tmp(
    monkeypatch: pytest.MonkeyPatch, fake_version: str
) -> None:
    cache_path = sb._cached_binary_path(fake_version)
    payload = b"REAL-BYTES"
    wrong_hex = "0" * 64

    def handler(_url: str, tmp: Path) -> None:
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(payload)

    _install_urlretrieve(monkeypatch, handler)

    class FakeResp:
        def read(self) -> bytes:
            return f"{wrong_hex}  {sb.SIDECAR_EXE}\n".encode("utf-8")

        def __enter__(self) -> "FakeResp":
            return self

        def __exit__(self, *_args) -> None:
            return None

    monkeypatch.setattr(sb.urllib.request, "urlopen", lambda *a, **kw: FakeResp())

    with pytest.raises(RuntimeError) as ei:
        sb.resolve_sidecar_path()

    msg = str(ei.value)
    assert "checksum mismatch" in msg.lower()
    assert wrong_hex in msg
    actual_hex = _sha256_hex(payload)
    assert actual_hex in msg

    # The bad bytes must be gone (no .tmp, no cache_path).
    assert not cache_path.exists()
    assert not cache_path.with_suffix(cache_path.suffix + ".tmp").exists()
