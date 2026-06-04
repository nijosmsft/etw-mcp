# Changelog

All notable changes to etw-mcp are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions match the wheel tags published on GitHub.

## [Unreleased]

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
