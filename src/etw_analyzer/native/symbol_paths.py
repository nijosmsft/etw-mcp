"""Shared local symbol-path parsing and PDB candidate enumeration."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable


def parse_symbol_path(sym_path: str) -> list[tuple[str, Path]]:
    """Return searchable filesystem directories from a symbol path."""

    out: list[tuple[str, Path]] = []
    if not sym_path:
        return out
    for raw in sym_path.split(";"):
        entry = raw.strip()
        if not entry:
            continue
        lower = entry.lower()
        if lower.startswith("srv*") or lower.startswith("symsrv*"):
            parts = entry.split("*")
            if len(parts) >= 2 and parts[1]:
                out.append(("server", Path(parts[1])))
            for upstream in parts[2:]:
                if not upstream:
                    continue
                up_lower = upstream.lower()
                if up_lower.startswith(("http://", "https://")):
                    continue
                if up_lower == "symweb" or up_lower.startswith("symweb/"):
                    continue
                out.append(("store", Path(upstream)))
            continue
        if lower.startswith("cache*"):
            parts = entry.split("*", 1)
            if len(parts) == 2 and parts[1]:
                out.append(("symcache", Path(parts[1])))
            continue
        out.append(("local", Path(entry)))
    return out


def resolve_file_ptr(ptr_file: Path) -> Path | None:
    """Resolve a symstore file.ptr target, returning None on any miss."""

    try:
        content = ptr_file.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    if not content:
        return None
    if content.upper().startswith("PATH:"):
        target = Path(content[5:].strip())
    else:
        target = Path(content)
    if not target.is_absolute():
        target = (ptr_file.parent / target).resolve()
    try:
        return target if target.is_file() else None
    except OSError:
        return None


def iter_pdb_candidates(
    sym_path: str,
    module_name: str,
    pdb_name: str,
) -> Iterable[tuple[Path, str | None]]:
    """Yield direct and file.ptr-resolved PDB candidates in path order."""

    del module_name  # Reserved for future module-specific lookup rules.
    for _kind, dir_path in parse_symbol_path(sym_path):
        try:
            if not dir_path.exists():
                continue
            flat = dir_path / pdb_name
            if flat.is_file():
                yield (flat, None)
            sym_root = dir_path / pdb_name
            if sym_root.is_dir():
                for sub in sorted(sym_root.iterdir()):
                    if not sub.is_dir():
                        continue
                    candidate = sub / pdb_name
                    if candidate.is_file():
                        yield (candidate, None)
                    ptr = sub / "file.ptr"
                    if ptr.is_file():
                        target = resolve_file_ptr(ptr)
                        if target is not None:
                            yield (
                                target,
                                f"via file.ptr redirect: {ptr} -> {target}",
                            )
        except OSError:
            continue


_SYMSTORE_FOLDER_RE = re.compile(r"^[0-9A-Fa-f]{33,}$")


def symstore_folder_identity(candidate: Path) -> tuple[str, int] | None:
    """Return GUID and age encoded by a symstore GUID+Age directory."""

    try:
        name = candidate.parent.name
    except (OSError, ValueError):
        return None
    if not _SYMSTORE_FOLDER_RE.match(name):
        return None
    try:
        return (name[:32].upper(), int(name[32:], 16))
    except ValueError:
        return None


def candidate_pdb_paths(
    sym_path: str,
    module_name: str,
    pdb_name: str,
) -> list[Path]:
    """Return every locally enumerable PDB candidate in symbol-path order."""

    return [
        path
        for path, _redirect in iter_pdb_candidates(
            sym_path,
            module_name,
            pdb_name,
        )
    ]
