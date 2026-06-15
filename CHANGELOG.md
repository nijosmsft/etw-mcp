# Changelog

All notable changes to etw-mcp are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions match the wheel tags published on GitHub.

## [Unreleased]

## [0.6.2] - 2026-06-15

### Fixed
- `count_stacks` MCP tool rejected the natural JSON-array invocation shape with `Input should be a valid tuple [type=tuple_type, ...]`. The `contains` and `excludes` parameters were typed as `list[tuple[str, str]]`, but JSON arrays decode to Python lists, not tuples — Pydantic v2 refused to coerce a string or 2-element array into a tuple at the MCP boundary. Widen both parameters to `list[str | list[str]]` and document the three accepted per-frame forms in the docstring: `"module"`, `"module!function"`, and `["module", "function"]`. The internal `_split_stack_ref` helper already handled all three; only the MCP-facing type annotation needed widening.

## [0.6.1] - 2026-06-15

### Fixed
- Dotnet-mode cache-hit loads now rebuild the per-trace `Symbolizer` from the on-disk image parquets. Previously, every cache hit left `trace.symbolizer = None` because the in-process dbghelp state could not be persisted across loads, and the rebuild path was unreachable. The user-visible symptom was every kernel-mode (and many user-mode) stack frame resolving to `unknown+0x...` even when ntoskrnl.exe, tcpip.sys, mlx5.sys, NDIS.SYS, etc. were present in the trace.
- `build_symbolizer_from_dotnet_images` now also reads the combined `raw_csv["image"]` key (the cache-hit hydration shape) in addition to the canonical `Image/Load` and `Image/DCStart` keys.

### Added
- Load-time diagnostic: when `trace.symbolizer is None` despite image rows being present in `raw_csv`, the load summary appends a one-line note pointing operators at `load_trace(force=True)` to regenerate. Future regressions of this bug class are now immediately LLM-visible instead of silently producing `unknown+0x...` frames.
- 7 regression tests covering the rebuild path: combined `"image"` source, canonical `Image/Load + Image/DCStart` source, dedup by ImageBase, kernel-PID rows registered, etc.

### Operator note
Any cached export dir under `.etw-export-<stem>/` from v0.6.0 already has the image parquets on disk; the next `load_trace` call after upgrading to v0.6.1 will rebuild the symbolizer from them automatically. Pre-computed aggregates like `cpu_sampling.parquet` still hold pre-fix labels — re-run with `load_trace(force=True)` once if those tables need refresh; tools that resolve live (`get_hot_stacks`, `get_dpc_summary`, anything calling `symbolizer.bulk_resolve`) pick up kernel modules from the next call without re-extracting.

## [0.6.0] - 2025

### Changed
- Symbol resolution now honestly reports PE-export-table fallback (`SYMFLAG_EXPORT`) instead of silently claiming "resolved". `check_symbols` returns a three-category classification (OK / EXPORT_ONLY / MISSING).
- `check_symbols`, `resolve_symbols`, and `load_trace` accept an `extra_symbol_paths` argument that appends to `_NT_SYMBOL_PATH` for the current call without losing the existing entries.

### Added
- `diagnose_symbol_load` tool — reconciles the EXE's RSDS record with every candidate PDB on disk and what dbghelp actually loaded, so EXPORT_ONLY modules can be debugged end-to-end.
- `clean_stale_symbol_files` tool — removes stale `C:\SymCache\<pdb>\<GUID+Age>\` subfolders that no longer match the current EXE's RSDS record (dry-run by default).

## [0.5.0] - 2025

### Added
- Auto-bootstrap for the .NET sidecar (`etw-extract.exe`). A clean wheel install followed by the first `load_trace` call now self-downloads the matching binary into `%LOCALAPPDATA%\etw-mcp\sidecar\v<wheel-version>\`; no manual `Invoke-WebRequest` step.
- `ETW_MCP_NO_AUTO_DOWNLOAD=1` to opt out of the auto-fetch (the server then falls back to the in-process native consumer).
- `ETW_MCP_DOTNET_SIDECAR` to pin a manually-built or downloaded sidecar binary.

## Naming history

- Earlier versions of this server called the sidecar mode `"csharp"` (matching the language of the binary). It was renamed to `"dotnet"` across the API (env vars, `mode=` args, manifest `producer` field, telemetry events, Python symbols) to align with the user-facing `.NET sidecar` label, which more accurately describes the bundled runtime. Stale on-disk caches with `producer="csharp"` no longer validate; pass `force=True` (or delete the `.etw-export-*` directory) once to re-extract under the new producer name. The old `ETW_MCP_CSHARP_SIDECAR` env var is no longer recognized — set `ETW_MCP_DOTNET_SIDECAR` instead.
