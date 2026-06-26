# Changelog

All notable changes to etw-mcp are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions match the wheel tags published on GitHub.

## [Unreleased]

## [0.8.6] - 2026-06-26

### Fixed

- **get_dpc_per_cpu >100% bug (#4):** DPC per-CPU percentages now use the trace
  duration as the denominator (from `trace.duration_seconds` /
  `trace_metadata.DurationSeconds`), eliminating the >100% values that arose
  when the old 1-second default was used. NDIS.SYS CPU40 dropped from 278.7%
  → 22.27%; all per-CPU values are now ≤100%.
- **DPC silent exception swallow (#13):** `_get_dpc_df` now counts raw DPC rows
  before aggregation. If aggregation fails with rows present, it logs the
  exception with `exc_info=True` and raises a `ValueError` pointing to
  `resolve_symbols(trace_id)` for remediation, rather than silently returning a
  misleading "No DPC/ISR data" message.
- **get_diskio_summary no-data bug (#14):** `_gather_diskio()` now handles
  xperf slash-key format (`DiskIo/Read`), native/dotnet underscore-key format
  (`diskio_read`), and combined `diskio` parquet with `Kind`/`Type`/`Operation`
  columns, while avoiding double-counting when per-operation rows exist.
  Verified exact match: reads=12, writes=755, flushes=2 against xperf oracle.

### Added

- **Tests #16, #18, #20:** `test_dpc_isr_tools.py` covers DPC exception/message
  paths and metadata-duration handling (12/12 pass); `test_system_info_summary.py`
  covers diskio Kind/Type/underscore key normalization; `test_integration_real_etl.py`
  provides end-to-end real ETL validation (5 pass, 1 expected xfail for BUG-1/#11).

## [0.8.5] - 2026-06-26

### Fixed

- DPC/ISR tools now work on dotnet/native traces. The sidecar emits a combined
  `dpc_isr` frame carrying `Routine` + `ElapsedMicros` + `Kind` per event, but
  `aggregate_dpc_isr` only understood the PerfInfo start/end-pairing schema and
  ignored it, so `get_dpc_summary` / `get_dpc_per_cpu` / `get_network_dpcs`
  reported "No DPC/ISR data" despite millions of rows. The aggregator now
  consumes the combined frame directly (duration = `ElapsedMicros`).
- Stack tools (`get_hot_stacks`, `butterfly_chain`, `walk_stack`) now resolve on
  dotnet/native traces. A deferred load left the cached `stacks` dataset as a
  1-row "unknown" placeholder; the tools now rebuild the butterfly on demand
  from `sampled_profile.parquet`. The Stack column is read via pyarrow because
  `pandas.read_parquet` coerces the nullable `list<uint64>` to float64 and
  corrupts the low bits of every frame address (making symbolization fail).
- `get_lock_contention` / `get_network_lock_contention` now surface native
  `cswitch_events` (a 0-row `readythread` placeholder no longer short-circuits
  the lookup) and show a switch-out WaitReason breakdown when the capture has no
  ReadyThread readying stacks, instead of reporting no context-switch events.
- The dotnet result telemetry now records `stacks_paired`, `stack_eligible_events`,
  and `pending_evictions` for stack-pairing observability.

### Known limitations

- Full readying-stack lock attribution still requires a capture that records
  ReadyThread events with stacks. CSwitch-attached stacks from the sidecar are
  not yet surfaced (a sidecar stack-pairing/serialization follow-up).

## [0.8.4] - 2026-06-26

### Fixed

- Bundled capture profiles can now be started in memory (ring-buffer) mode.
  Every `.wprp` previously declared only a `LoggingMode="File"` profile, so
  `wpr -start <profile>` without `-filemode` (WPR defaults to memory mode)
  failed with `0xc5584017` and silently produced no file. Each of the 9
  profiles now also ships a `LoggingMode="Memory"` twin sharing the same
  profile Name, so both file mode (`-filemode`, recommended) and memory mode
  work. The generated capture commands document both modes.

## [0.8.3] - 2026-06-26

### Fixed

- `check_symbols` no longer misreports 0% PDB resolution on a deferred load. It
  now resolves function names on demand from the raw samples (the same path
  `get_hot_functions` uses) before classifying, so its per-module PDB/Export/
  Unknown breakdown matches reality and is annotated as resolved-on-demand.
  Previously it classified the deferred `cpu_sampling` placeholder whose
  `SymbolSource` is all "unknown", reporting 100% unresolved even while function
  names resolved fine elsewhere — this was a real inconsistency, not report lag.
- Module filtering now applies when resolving from native-decoder raw samples.
  `_resolve_deferred_instruction_pointers` derives the `Module` column from the
  symbolizer label even when the raw frame has no `Module` column (the native
  event-store schema omits it), so `get_hot_functions(modules=...)` correctly
  narrows results instead of silently returning all modules.

## [0.8.2] - 2026-06-26

### Fixed

- Function-level symbol names now resolve in `get_hot_functions` and
  `get_cpu_samples` (group_by=function) after a normal load. A large trace
  defers per-PDB function symbolization at load time (keeping only module
  attribution), and two plumbing gaps left the `Function` column empty forever:
  (1) on a cache hit no symbolizer was rebuilt, because the per-opcode image
  parquets are excluded from `raw_csv`; (2) the query tools read the aggregated
  `cpu_sampling` frame, whose groupby had dropped `InstructionPointer`, so the
  on-demand resolver had nothing to resolve. The cache loader now rehydrates the
  `image_load`/`image_dcstart`/`image_dcend` parquets and rebuilds the
  symbolizer, and the query tools resolve function names on demand from the raw
  `sampled_profile` samples (memoized per trace). Symbol resolution itself was
  never broken (it produces real PDB names, e.g. `tcpip.sys!UdpSend`); only the
  pipeline that surfaced them was. xperf mode and small (non-deferred) traces
  are unchanged.

## [0.8.1] - 2026-06-25

### Fixed

- Kernel sample addresses no longer collapse into the `unknown` module. Both
  the native in-process extractor and the .NET sidecar now capture the
  `Image/DCEnd` kernel stop-rundown, which on most captures is the only place
  the already-loaded kernel modules (`ntoskrnl.exe`, `tcpip.sys`, `ndis.sys`,
  NIC drivers, ...) are enumerated. Previously only `Image/Load` +
  `Image/DCStart` were consumed, so traces that relied on stop-rundown showed
  ~99% of CPU samples as `unknown` while `xperf` mode resolved them correctly.
  `EVENT_SCHEMA_VERSION` is bumped 3 -> 4; existing `.etw-export-*` caches are
  invalidated and re-extracted on next `load_trace`.

## [0.8.0] - 2026-06-17

### Added

- `load_trace` now supports non-blocking async extraction with an inline wait
  budget (`wait_seconds`, defaulting from `ETW_MCP_LOAD_WAIT` or 20s). Small
  traces and cache hits keep the historical ready summary shape; slow traces
  return JSON status with `status: "extracting"`, progress percent, current
  phase/dataset, and an ETA.
- New `get_load_status` tool reports `extracting`, `ready`, `failed`, or
  `not_found` for an ETL path, trace ID, or job ID. `list_loaded_traces` now
  includes in-progress/failed load jobs alongside loaded traces.
- Async loads write `extracting.json` status markers with pid/host heartbeat,
  percent, current dataset/phase, ETA, and trace identity. Fresh markers are
  reused by repeat/concurrent `load_trace` calls; stale markers are reclaimed.
  Failures leave `failed.json` with the error for later status queries.
- ETA is based on ETL size and an extraction-throughput constant (22 MB/s by
  default, override with `ETW_MCP_EXTRACT_MBPS`) and is refined as progress
  events arrive from the sidecar/worker.

### Fixed

- Symbol resolution is now lazy/deferred per module: trace load no longer
  blocks downloading every module's PDB from remote symbol servers (a
  many-module server trace previously hung at the "aggregating" phase).
  Kernel symbols still resolve by exact GUID on first query.
- `load_trace` cache readiness now depends on an atomic finalized manifest:
  Python writes `wpr-mcp-cache-manifest.json` last via temp-file +
  `os.replace`, incomplete or partial caches are never rehydrated, and the
  native event schema is bumped to invalidate older manifests.

## [0.7.2] - 2026-06-16

### Fixed

- **Bug F: MSFZ-compressed kernel PDBs now produce actionable dbghelp
  diagnostics instead of misleading unreadable/export-only guesses.** The
  native symbolizer honors `ETW_MCP_DBGHELP` / `ETW_MCP_SYMSRV`, records the
  loaded dbghelp path and FileVersion, broadens WinDbg / Windows SDK discovery,
  and reports when an MSFZ PDB is present but the loaded dbghelp predates MSFZ
  support. No MSFZ decompression is attempted; operators should install a
  current Debugging Tools for Windows / WinDbg dbghelp.

## [0.7.1] - 2026-06-16

### Fixed

- **Bundled capture profiles: kernel ImageLoad rundown now survives on Windows
  Server 2025 build 29614** (Bug E).
  Traces captured with any etw-mcp .wprp profile on Server 2025 29614 were
  missing the kernel Image/DCStart rundown burst so kernel modules could not be
  attributed or symbolized -- even though each profile's SystemProvider has the
  Loader keyword set.

  Two root causes addressed (see commits for full analysis):

  1. **cpu.wprp SystemCollector undersized** (VERIFIED): the original
     128 x 1024 KB = 128 MB allocation yields ~1.6 buffers per CPU on an
     80-CPU server -- below the ETW minimum-buffers recommendation of
     >= 2 x NumberOfProcessors (160 for 80 CPUs).  At session start the
     kernel Image/DCStart + ProcessThread rundown burst can exhaust the initial
     pool before file-mode draining begins, silently dropping the events.
     Fix: bumped to 320 x 4096 KB = 1.28 GB, matching all other profiles.

  2. **All profiles missing TraceMergeProperties** (PROPOSED / well-grounded):
     the built-in WPR "CPU" profile injects ImageID/DbgID_RSDS records at
     wpr -stop via its hardcoded merge properties (confirmed: 13 104 events in
     the reference wpa5 trace, GUID b3e675d7...).  Custom .wprp files on Server
     2025 build 29614 do NOT receive this injection by default; without an
     explicit <TraceMergeProperties> section the final ETL lacks the RSDS
     identity the etw-mcp consumer needs for kernel PDB lookup.
     Fix: added <TraceMergeProperties><TraceMergeProperty><CustomEvents>
     <CustomEvent Value="ImageId"/></CustomEvents></TraceMergeProperty>
     </TraceMergeProperties> to all nine bundled .wprp files, matching the
     merge-time injection that built-in WPR profiles perform.

  **Static validation only.** End-to-end confirmation (capturing on Server 2025
  build 29614 and verifying the DCStart rundown lands in the ETL) requires lab
  hardware and has NOT been performed here.

## [0.7.0] - 2026-06-15

### Fixed

- **Kernel-mode stack frames now resolve from PDBs** via captured DbgID_RSDS identity.
  Previously all kernel-mode frames (ntoskrnl.exe, tcpip.sys, afd.sys, mlx5.sys, etc.)
  were resolved using PE export-table fallback only -- ntoskrnl showed bogus symbols such
  as MmCopyMemory, strncpy, and FsRtlAreNamesEqual; driver frames were blank.
  Root cause: the symbolizer called `SymLoadModuleEx` with the analyst box's local kernel
  image path, causing dbghelp to derive the wrong PDB GUID from the local image instead
  of from the trace.
  Fix (M1-M5): the .NET sidecar and native in-process consumer now capture each image's
  DbgID_RSDS record (PdbGuid, PdbAge, PdbName) at trace-dump time. The symbolizer calls
  `SymFindFileInPathW(SSRVOPT_GUIDPTR)` with the exact RSDS identity to locate and load
  the correct PDB from the symbol server, completely bypassing the local image.

- **CPU sampling aggregator now preserves kernel-space InstructionPointer values** when
  building `cpu_sampling.parquet`. Kernel addresses (bit-63 set, e.g. 0xFFFFF8...) stored
  as uint64 in the sampled_profile parquet were previously cast to int64, making them
  negative Python ints; the ip_to_label dict lookup then failed to find them (signed
  -N != unsigned 2^64-N as a dict key). Result: ntoskrnl and all other kernel modules
  appeared as Module="unknown" in get_hot_functions even when the symbolizer correctly
  resolved those addresses. Fix: use `int(x)` (Python's arbitrary-precision int) instead
  of `.astype("int64")` -- `int()` preserves the full unsigned value for all dtype inputs.

- **Native in-process mode now decodes ImageID/DbgID_RSDS events** (event-class GUID
  `b3e675d7-...`) to populate PdbGuid/PdbAge/PdbName per image. Previously these events
  were silently dropped by the in-process consumer; the Symbolizer could only use the
  PE-export fallback path when running in native mode. (M5/M5b)

- `diagnose_symbol_load` / `check_symbols`: follow `file.ptr` redirects in downstream
  symbol stores before reporting a module as MISSING. (#20)

- `export_analysis`: honor the `filter_query` argument instead of returning the
  unfiltered full-trace template. (#21)

### Changed (breaking)

- **Cache schema `EVENT_SCHEMA_VERSION` bumped 1 -> 2.** The native image parquet schema
  now carries `PdbGuid`, `PdbAge`, `PdbName`, and `TimeDateStamp` columns per image row.
  All existing `.etw-export-*` cache directories from v0.6.x are invalidated; the next
  `load_trace` call re-extracts from the ETL automatically. No back-compat by design.

### Requirements (operational)

- **MSFZ-format PDB stores require a recent `dbghelp.dll`** (v10.0.29507 or later).
  Internal Microsoft and lab symbol servers distribute kernel/driver PDBs in MSFZ
  (compressed) format; the system dbghelp.dll (v10.0.26100, shipped with Windows) cannot
  load them and falls back to PE-export-table symbols. etw-mcp now prefers the WinDbg
  "Debugging Tools for Windows" dbghelp at `C:\Debuggers\dbghelp.dll` over the system one
  when it is present. Users with only the system dbghelp will see EXPORT_ONLY for
  MSFZ-stored symbols; public Microsoft symbol server (msdl.microsoft.com) PDBs use
  standard MSF7 format and are unaffected.

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
