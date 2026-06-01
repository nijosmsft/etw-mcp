# Rename `wpr-mcp-server` → `etw-mcp` — assumptions

Judgment calls made while executing the rename without further user input.

## Env vars

- The task lists 15 env vars but enumerates only 14 distinct names (one duplicate). A full repo scan found a **15th** variable, `WPR_MCP_CSHARP_SIDECAR`, referenced in `docs/decisions/rust-vs-csharp-spike-review.md` (historical decision doc). Included in the alias dict for completeness; it is not currently read by any code path, so the shim is a forward-compat measure only.
- `WPR_MCP_NATIVE_WORKER` (single name) and the `WPR_MCP_NATIVE_WORKER_*` family are treated as separate vars — each gets its own alias entry.
- The deprecation warning fires exactly once per legacy var name, per process — implemented with a module-level `_warned: set[str]`. Matches the "once per process" wording in the spec.

## Cache and on-disk compatibility

- **Cache manifest filename** `wpr-mcp-cache-manifest.json` is **kept**. Renaming the filename would invalidate every existing extracted-parquet cache directory on every user's disk. The cache directory is keyed by ETL identity and the next `load_trace` would silently re-extract (30-180 s wall) — a much louder user-visible regression than retaining the historical filename. An inline comment in `cache.py` notes the back-compat rationale.
- **Parquet metadata keys** `wpr_mcp_event_class` and `wpr_mcp_schema_version` (in `schemas.py`) are **kept** for the same reason — they live inside cached parquet files and are matched by old caches. An inline comment notes this.

## Documentation that stays as-is

- Historical decision docs under `docs/decisions/` are left untouched. They describe past decisions in past tense and reference the old name as a name of record at that time. Updating them would rewrite history.
- The wider udp-perf prose references (`wpr-mcp-native-etw-design.md`, `wpr-mcp-networking-plan.md`, etc.) are external doc names not owned by this repo and not part of the rename scope.
- The `wpr-mcp-server-dotnet-sidecar` worktree path that appears in some inline examples is updated where it was a fresh-user instruction. Historical examples in deferred POC docs (DOTNET_PARITY_SMOKE.md) are kept since they describe a specific historical run.

## Version bump

- `0.3.0` → `0.4.0`. The rename is non-breaking thanks to the env-var shim and the GitHub auto-redirect, but the package name change is significant enough to warrant a minor bump (not a patch).

## C# sidecar

- Assembly `wpr-mcp-extract` → `etw-extract` (binary becomes `etw-extract.exe`). Namespace `WprMcpExtract` → `EtwExtract`. The `dotnet/` directory name itself is kept (it is already framework-neutral).
- The `.csproj` file is renamed from `wpr-mcp-extract.csproj` to `etw-extract.csproj`. The release workflow already references the file by name and is updated.
- `DOTNET_SIDECAR_EXE` constant flips to `"etw-extract.exe"`. The env var `ETW_MCP_DOTNET_SIDECAR` is what users should set going forward; if they have `WPR_MCP_DOTNET_SIDECAR` pointing at the old `wpr-mcp-extract.exe` binary, the shim still resolves the env var and the path still works (the binary they downloaded from v0.2.0 / v0.3.0 still has the old name).

## Tests

- The 30+ existing tests that hardcode `WPR_MCP_*` are updated to the new names. Where coverage is naturally about the env name (e.g. assertion that a help message mentions the env var), the assertion is updated AND a small parametrized case is added in `test_env_compat.py` that the legacy name still works at runtime.
- The dedicated `tests/test_env_compat.py` covers: new wins over legacy, legacy alone resolves, unknown name passes through, warn-once semantics, default value handling.
