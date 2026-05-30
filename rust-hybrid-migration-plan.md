# Native Sidecar Migration Plan — `wpr-mcp-server` (v3)

**Status:** v3 — rewritten 2026-05-29 to address the third review
(`rust-vs-csharp-spike-review.md` — pending). v3 is **language-neutral**
through phase 0 and forks into a Rust path or a C# path based on the
spike outcome.

**Companion docs:**
- `native-vs-xperf-parity-review.md` — parity gaps this rewrite
  incidentally fixes.
- `rust-hybrid-migration-plan-review.md` — first independent review (gpt-5.5)
- `rust-hybrid-migration-plan-review-2.md` — second independent review (gpt-5.4)
- `rust-vs-csharp-spike-review.md` — third review with C# vs Rust recommendation
- §17 below — full change log v1 → v3

**Renamed from:** `rust-hybrid-migration-plan.md` — name preserved for
backward-compatibility but the plan is no longer Rust-committed. The
language is decided in phase 0.

---

## 1. Strategic positioning

This plan describes a **tactical native-code acceleration for the ETW
analyzer**. It is **not** the strategic architecture for the long-term
"general Windows debugging MCP" north star — that belongs to the
evidence-model + federation effort tracked separately.

The two efforts are **orthogonal**: a native sidecar writes parquet, the
evidence model reads parquet. They can proceed in parallel given
bandwidth.

## 2. Pre-commit decision gate — the spike

The language for the sidecar is **not yet decided.** Run two parallel
1-week spikes targeting the **same output contract** on the **same
fixture ETL**:

- **Rust spike** — `windows-rs` + arrow-rs/parquet, hand-rolled
  MOF/TDH decoders
- **C# spike** — `Microsoft.Diagnostics.Tracing.TraceEvent` (Microsoft's
  15-year-old maintained ETW library) + Apache.Arrow/Parquet.Net

**Recommended prior** (per third-review analysis):
**C# is the favored option (85% confidence)** because most of the
~3500 lines of Python being replaced is Windows ETW semantic decoding —
exactly what TraceEvent already implements. Rust would faithfully port
the fragile decoder layer; C# can delete it.

### Spike pass/fail criteria

**Pick C# if:**
- It decodes `SampledProfile`, `StackWalk`, `CSwitch`, `ReadyThread`,
  `TcpIp/Recv`, `AFD/Recv`, `NdisDrop`, `SystemConfig` with **<25%
  hand-rolled binary parsing code**.
- Stack pairing matches Python native row counts within **0.5%**.
- `get_cpu_samples` top-10 modules/functions match Python native.
- It produces **richer SystemConfig** than current native: CPU model,
  NIC friendly names + drivers, disk model/size — closes parity gap #3
  for free.
- End-to-end `load_trace` wall time within **30% of Rust** OR **2× faster
  than current Python native**.
- Self-contained single-file signed build works from `uv sync` without
  requiring a separate .NET install.

**Pick Rust if:**
- C# cannot preserve raw QPC timestamps for stack pairing.
- C# requires substantial manual TDH/MOF parsing anyway (erases
  TraceEvent's advantage).
- C# is **>2× slower** than Rust on a realistic multi-million-event
  trace including parquet output.
- TraceEvent packaging is broken (no single-file deploy, no signing
  path, runtime requirements the team can't tolerate).

### Required spike outputs (both languages must report)

- **LOC by category:** ETW consume, MOF/TDH decode, mapping/projection,
  symbolization, parquet/cache, protocol. (Field-coverage parity, not
  raw LOC, is the headline metric.)
- **Event classes decoded** and **fields per class** with parity scoring
  against Python native.
- **Row-count parity** vs Python native and xperf for each event class.
- **Stack pairing rate** (paired / total stack-eligible events).
- **Peak RSS and wall time** for the fixture.
- **Package size and deployment steps** (what the user installs).
- **Failure behavior** for: callback panic/exception, truncated ETL,
  missing PDB, ETL larger than 512 MB guardrail.

A **spike harness** (§12) automates these measurements so both spikes
report comparable numbers. See "What's needed for the spike" in the
companion section below.

## 3. Goals and non-goals

### Goals
- Replace `src/etw_analyzer/native/{consumer,extract,decoder,manifest,
  mof/,bindings/,symbolizer,sinks}.py` (~3500 lines of byte-bashing)
  with a native sidecar binary (Rust or C#) invoked by the existing
  Python `worker_supervisor`.
- Preserve the existing **two** cache strategies
  (`materialized-small` and `event-store-streaming`, per
  `native/cache.py:14-18`) exactly.
- Preserve the existing `worker_supervisor` operational model: staging
  dir per run, heartbeat/progress JSONL, atomic promotion, validation,
  stderr/stdout tail capture, Windows Job Object memory limit.
- **Preserve where Layer-3 aggregators run.** Today `worker.py:153-263`
  runs them before promotion. In v3 a thin Python aggregation pass
  takes over that responsibility (§7).
- Ship as a single bundled binary alongside the Python package via a
  platform-tagged wheel.

### Non-goals
- Rewriting the MCP server, FastMCP integration, or any of the **60**
  `@mcp.tool()` functions.
- Rewriting Python aggregators (`native/aggregators/*.py`). They stay.
- Rewriting `cache.py`, `event_store.py` Python *interfaces*. The
  sidecar *produces* the file formats; the readers stay Python.
- Replacing `xperf` for the gaps the parity review identified (memory
  pools, full sysconfig text, full diskio detail). Those tools
  continue to invoke `xperf` directly until a separate effort fills
  them.

## 4. Architecture (language-neutral)

### 4.1 Boundary

The sidecar binary slots into the position currently held by
`python -m etw_analyzer.native.worker`, driven by
`worker_supervisor.py`. Replaces extraction; **does not replace
aggregation**.

```
Python tool                  worker_supervisor                native sidecar
load_trace(etl_path)
    │
    ├─ resolve_mode() → "rust" or "csharp" (whichever wins phase 0)
    │
    └─ run_native_worker_extraction(...)
          │
          ├─ stage_dir = export_dir.parent / ".staging-<uuid>"
          │
          ├─ subprocess.Popen([
          │       wpr-mcp-extract.exe,    ◄─── reads request JSON
          │       "--request", request.json,
          │   ])                            runs ProcessTrace / TraceEvent
          │     ◄─── JSONL heartbeats      writes Layer 1/2 to stage_dir
          │     ◄─── result.json
          │
          ├─ run_python_aggregation_pass(stage_dir)
          │     ├─ load Layer 1/2 parquets from staging
          │     ├─ symbolize residual addresses if sidecar deferred
          │     ├─ _run_native_aggregators → writes Layer 3 to staging
          │     └─ write wpr-mcp-cache-manifest.json with all 3 layers
          │
          ├─ validate stage_dir per native/cache.py rules
          ├─ atomic rename(stage_dir → export_dir)
          │
          └─ Python reloads cache via existing _load_from_cache path
```

### 4.2 Why this boundary

- `worker_supervisor.py` already solved staging, heartbeats, timeouts,
  promotion, Job Object limits, partial-extraction protection.
  Reusing it is a 50-line change vs reimplementing it.
- The Python aggregation pass keeps Layer 3 (cpu_sampling, dpc_isr,
  stacks, sysconfig text) in Python, where all 60 tools already
  consume from `raw_csv`. Sidecar language doesn't need to know about
  aggregators.
- PyO3 and Arrow-IPC-over-stdout remain rejected for v1.

### 4.3 Fallback chain

```
mode="auto":
    1. try sidecar binary       (if wpr-mcp-extract.exe exists)
    2. fall back to Python native (current native path)
    3. fall back to xperf         (current xperf path)

mode="sidecar":  force the sidecar (language is whichever was built)
mode="native":   force Python native (legacy; deprecated in phase 4)
mode="xperf":    force xperf subprocess (today's behavior)
```

**Note on mode naming:** `mode` in the cache manifest stays
`"native"` (because the file format is unchanged from today's
"native"). The sidecar's language is tracked in a new `producer` field
(`"rust"` | `"csharp"` | `"python"`). This fixes the conflict reviewer
caught between v2's proposed `mode="rust"` and `cache.py:256-265`'s
`mode == "native"` validation.

## 5. The three schema contracts

### 5.1 Layer 1 — Event-store physical schemas

**Source of truth:** `src/etw_analyzer/native/schemas.py` (Arrow
schemas, `EVENT_SCHEMA_VERSION = 1`). **Stays Python-authoritative for
v1.** A language-neutral schema spec (JSON/YAML) is future work;
short-term, the sidecar mirrors `schemas.py` and a build-time test
asserts schema equivalence.

**What the sidecar must emit:** Parquet files inside
`native-store/generations/<run_id>/<event-class>/part-NNNN.parquet`
matching `schemas.py` byte-for-byte.

Example (`sampled_profile`, per `schemas.py:133-147`):
```
EventSequence: UInt64, non-null
TimeStampQpc: Int64, non-null
CPU: Int32, non-null
ProcessId: Int64, nullable
ThreadId: Int64, nullable
PayloadThreadId: Int64, nullable
InstructionPointer: UInt64, non-null
Weight: Int64, non-null
ProfileWeight: Int64, non-null
Stack: List<UInt64>, nullable
```

### 5.2 Layer 2 — Materialized dumper parquets

**Source of truth:** `tools/trace_mgmt._DUMPER_EVENT_CLASSES`
(`trace_mgmt.py:555-585`), `_persist_dumper_parquet`
(`trace_mgmt.py:588-625`).

**What it is:** Flat per-event-class parquets (`tcpip_recv.parquet`,
`udp_send.parquet`, etc.) loaded into a `TraceData.*_df` attribute
(e.g. `trace.tcpip_recv_df`), used by tools that don't go through the
event-store accessor path.

**Schema:** `Process Name` / `PID` / `ThreadID` / `CPU` projection of
each event class. **Not** the same as Layer 1.

**What the sidecar must emit:** In `materialized-small` strategy,
write these files alongside (or instead of) Layer 1.

### 5.3 Layer 3 — Aggregate outputs (Python-owned)

**Source of truth:** `_run_native_aggregators`
(`trace_mgmt.py:896-1143`).

**Owner:** **The Python aggregation pass** (new, takes over from
`worker.py`). Sidecar does **not** produce Layer 3. Sidecar produces
Layers 1 and 2; the aggregation pass digests them into Layer 3.

This resolves v2's contradiction: aggregators stay Python, and there's
now an explicit place for them to run (the aggregation pass, between
sidecar exit and cache validation).

### 5.4 Cache manifest

**Source of truth:** `native/cache.py`. Filename
`wpr-mcp-cache-manifest.json`. Schema:
- `schema_version` (int, currently 2; bump to 3 for the `producer`
  addition)
- `mode` (string: stays `"native"` for the sidecar path — same file
  format)
- `producer` (string: `"rust"` | `"csharp"` | `"python"`) — **new in v3**
- `strategy` (string: `"materialized-small"` | `"event-store-streaming"`)
- `complete` (bool)
- `etl` (object with path/size/mtime)
- `datasets` (list of `{name, kind, path, schema_version, row_count,
  materialize_on_load}`)
  - `kind ∈ {"parquet", "text", "dumper-parquet", "native-event-store"}`
- `native_store` (object, present when `strategy = event-store-streaming`)

`cache.py` validation gains: accept `mode="native"` regardless of
`producer`; surface `producer` in `load_trace` summary output for
diagnostics.

**Event-store sub-manifest:** `native-event-store-manifest.json` per
`event_store.py:34-41, 509-599`. Sidecar must write both manifests for
the streaming strategy.

## 6. CLI contract — `wpr-mcp-extract.exe`

Language-neutral; identical interface whether Rust or C# binary.

### 6.1 Invocation

```
wpr-mcp-extract.exe --request <request.json>
```

### 6.2 Request JSON schema

(Mirrors current `native/worker.py:23-86`):

```json
{
  "version": 1,
  "trace_id": "trace_abc123def456",
  "etl_path": "C:\\traces\\foo.etl",
  "staging_dir": "C:\\traces\\.staging-uuid",
  "symbol_path": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols",
  "requested_event_classes": ["SampledProfile", "CSwitch", ...],
  "strategy": "materialized-small",
  "max_etl_mb": 512,
  "heartbeat_interval_ms": 1000,
  "log_level": "info"
}
```

### 6.3 Stdout protocol — JSONL

One JSON object per line (matches `worker.py:89-109, 441-443`):

```
{"type":"progress","timestamp":...,"events_decoded":12345,"stacks_paired":2000,"bytes_processed":...}
{"type":"result","ok":true,"summary":{...},"datasets":[...],"producer":"csharp"}
```

On failure:
```
{"type":"result","ok":false,"error":"...","failure_kind":"..."}
```

### 6.4 Outputs in staging dir

Per strategy:

**materialized-small:**
- Layer 1 + Layer 2 parquets in flat layout
- (Python aggregation pass adds Layer 3 + writes cache manifest)

**event-store-streaming:**
- Layer 1 chunks under `native-store/generations/<run_id>/...`
- `native-event-store-manifest.json`
- (Python aggregation pass adds materialized aggregates and writes
  cache manifest)

### 6.5 Exit codes

Exit 0 = success and a `result` JSONL line was written. Python relies
on the JSONL `result`, not the exit code, for status. Matches existing
`worker_supervisor` protocol.

## 7. Native module ownership matrix (v3)

| File | v3 fate | Notes |
|---|---|---|
| `consumer.py` | **Replaced by sidecar** | OpenTraceW/ProcessTrace (Rust) or TraceEvent (C#) |
| `extract.py` | **Replaced by sidecar** | Event dispatch + stack pairing |
| `decoder.py` (TdhDecoder) | **Replaced by sidecar** | TDH wrapper + schema cache (or TraceEvent equivalent) |
| `manifest.py` | **Replaced by sidecar** | Manifest event mappers (NdisDrop included) |
| `mof/*.py` | **Replaced by sidecar** | Kernel MOF struct decoders (Rust) or TraceEvent intrinsic (C#) |
| `bindings/*.py` (ctypes) | **Deleted** | Replaced by `windows-rs` or .NET P/Invoke as needed |
| `symbolizer.py` | **Replaced by sidecar** | dbghelp wrapper |
| `sinks.py` | **Replaced by sidecar** | Parquet writers |
| `worker.py` | **Transformed into aggregation_worker.py** | No longer runs extraction; now runs only the Python aggregation pass between sidecar exit and cache promotion (§4.1). Most of `worker.py:153-263` becomes `aggregation_worker.run_aggregators(stage_dir, etl_path, producer)`. |
| `worker_supervisor.py` | **Retained, extended** | Now invokes sidecar then aggregation_worker before staging→promotion |
| `event_store.py` | **Retained as Python reader** | Sidecar writes the format; Python reads. Schema must match. |
| `cache.py` | **Retained, extended** | Add `producer` field handling; bump SCHEMA_VERSION to 3 |
| `accessors.py` | **Retained** | Tool-side reader of event-store batches |
| `aggregators/*.py` | **Retained** | All aggregators stay in Python; called by `aggregation_worker` |
| `schemas.py` | **Retained as Python source-of-truth (v1)** | Sidecar must match these schemas; tested via parity tests. Future: extract to language-neutral spec. |
| `config.py` | **Retained, extended** | Add `mode="sidecar"`; extend size guardrail |
| `networking.py` | **Retained** | Not consumer code |

**Net Python LOC removed:** ~4800. **Python LOC retained for native
cache + aggregation integration:** ~3500.

## 8. Sidecar implementation layout — Rust path

If Rust wins the spike:

```
rust/
├── Cargo.toml                       # workspace
├── crates/
│   ├── wpr-etw-core/                # consumer + MOF + TDH + manifest + symbolizer
│   │   └── src/                     # lifetime-safe ETW callback, mof/, tdh.rs, manifest/, symbolizer.rs, stack_pairing.rs
│   ├── wpr-cache-contract/          # parquet/cache layouts
│   │   └── src/                     # cache_manifest.rs, event_store.rs, schemas.rs, strategies.rs
│   ├── wpr-mcp-protocol/            # request/result/heartbeat JSON
│   └── wpr-mcp-extract/             # the binary
└── README.md
```

Dependencies: `windows-rs` (Microsoft), `arrow`, `parquet`, `serde`,
`serde_json`, `clap`, `tracing`, `uuid`. **Not** `polars`.

## 9. Sidecar implementation layout — C# path

If C# wins the spike:

```
csharp/
├── WprMcp.sln
├── src/
│   ├── WprMcp.EtwCore/              # TraceEvent wrappers + provider mappings
│   │   ├── EventExtractor.cs        # uses Microsoft.Diagnostics.Tracing.TraceEvent
│   │   ├── Symbolizer.cs            # uses Microsoft.Diagnostics.Symbols (ClrMD)
│   │   ├── ManifestMappers/         # canonical-class projection (NdisDrop included)
│   │   └── StackPairing.cs
│   ├── WprMcp.CacheContract/        # parquet/cache layouts
│   │   ├── CacheManifest.cs
│   │   ├── EventStoreManifest.cs
│   │   ├── Schemas.cs               # Apache.Arrow Schema constructors
│   │   └── Strategies.cs
│   ├── WprMcp.Protocol/             # request/result/heartbeat JSON
│   └── WprMcp.Extract/              # the binary (entry point)
│       └── Program.cs
└── README.md
```

Dependencies (NuGet): `Microsoft.Diagnostics.Tracing.TraceEvent`,
`Microsoft.Diagnostics.Symbols`, `Apache.Arrow`, `Parquet.Net`,
`System.CommandLine`, `Microsoft.Extensions.Logging`. .NET 8 LTS.

## 10. FFI / runtime safety

### Rust path
- Every callback function body wrapped in `std::panic::catch_unwind`.
  No exceptions. Unwinding across Win32 FFI is UB.
- On panic: store error in thread-local, return cleanly, surface via
  worker result JSON.
- Clippy lint flags any `panic!`, `unwrap`, `expect`, `unreachable!`
  inside `wpr-etw-core/src/callback/`.

### C# path
- Every TraceEvent callback wrapped in try/catch with structured
  exception handling for SEH (`AccessViolationException`, etc.) via
  `[HandleProcessCorruptedStateExceptions]` where applicable.
- On exception: emit `{"type":"result","ok":false,
  "failure_kind":"csharp_exception",...}` and exit cleanly.
- Self-contained single-file deployment (`<PublishSingleFile>true</PublishSingleFile>`,
  `<SelfContained>true</SelfContained>`) — NativeAOT only after
  TraceEvent trim-compatibility is verified.

Both paths: **negative test** — deliberately trigger a panic/exception
in the callback, verify clean failure (`failure_kind` set), no UB or
hang.

## 11. Phased migration

### Phase 0 — Decision spike (2 weeks parallel, ~1 week each)
Two engineers, one per language; or one engineer over 2 weeks
sequentially.

**Mandatory spike scope** (both paths):
- `SampledProfile` + `StackWalk` pairing
- `CSwitch` + `ReadyThread`
- `TcpIp/Recv` (TDH path)
- `AFD/Recv` (TDH path)
- `NdisDrop` (parity gap #1 — guards regression)
- `SystemConfig` (CPU model + NIC name decode — closes gap #3 if C#
  wins for free)
- One dbghelp symbol resolution pass
- Event-store output (chunked parquet) for SampledProfile
- Cache manifest write (Layer 4)
- Worker request/result protocol over stdin/stdout
- Panic safety negative test

**Exit:** §2 pass/fail criteria. End of phase 0 = language decision.
Rest of plan continues unchanged regardless of language choice.

### Phase 1 — Full decoder coverage (3 weeks if C#, 4 weeks if Rust)

C# path (3 weeks):
- 1a — Wire remaining TraceEvent providers (HttpService, MsQuic,
  NDIS-PacketCapture)
- 1b — Verify SystemConfig completeness (closes parity gap #3)
- 1c — Wire DPC/ISR + DiskIo + FileIo + Process/Thread/Image events

Rust path (4 weeks):
- 1a — Kernel MOF (perfinfo, thread, stackwalk, process, imageload,
  diskio, fileio, eventtrace, sysconfig)
- 1b — TDH decoder (positive cache, provider-wide negative cache,
  `PROPERTY_PARAM_LENGTH`, 32-bit headers, partial-row recovery)
- 1c — Manifest mappers (TCPIP, AFD, MsQuic, HttpService,
  NDIS-PacketCapture, NdisDrop)
- 1d — Symbolizer (dbghelp wrapper, bulk_resolve, deferred-load retry)

### Phase 2 — Event-store streaming (1 week)
Chunked output + manifest writers + cache manifest with
`strategy="event-store-streaming"`. Same for both languages.

### Phase 3 — Python aggregation_worker + worker_supervisor integration (1 week)
- Transform `worker.py` into `aggregation_worker.py` (extraction
  removed; aggregator pass retained).
- Extend `worker_supervisor.py` to invoke sidecar then
  aggregation_worker before promotion.
- JSONL heartbeat/progress/result protocol adapter.

### Phase 4 — Cutover (1 week)
- `resolve_mode()` auto picks sidecar over native when binary present.
- `mode="native"` deprecation warning; remains functional through 1
  release.
- Documentation update.

### Phase 5 — Deprecate Python native (1 release later)
Delete files marked "Replaced by sidecar" in §7.

## 12. Spike harness (build first, before phase 0)

A reusable measurement tool, ~200 lines of Python. **Built in week 0,
before either spike starts.** Lives at `tests/tools/spike_harness.py`.

```python
# Usage:
#   python -m tests.tools.spike_harness \
#       --etl C:\traces\multi-provider-small.etl \
#       --sidecar-binary path\to\wpr-mcp-extract.exe \
#       --oracle-mode native \
#       --output spike_report.json
```

Produces a structured report comparing sidecar output to a "Python
native" oracle:

```json
{
  "fixture": "multi-provider-small.etl",
  "sidecar": {
    "path": "path\\to\\wpr-mcp-extract.exe",
    "size_mb": 8.2,
    "language": "csharp",
    "version": "0.1.0-spike"
  },
  "metrics": {
    "wall_time_seconds": {"sidecar": 4.1, "oracle": 12.7},
    "peak_rss_mb": {"sidecar": 180, "oracle": 1100},
    "events_per_second": {"sidecar": 312000, "oracle": 98000}
  },
  "per_class_parity": [
    {
      "class": "SampledProfile",
      "sidecar_rows": 49823, "oracle_rows": 49891,
      "row_diff_pct": 0.14,
      "field_coverage": ["EventSequence", "TimeStampQpc", "CPU", ...],
      "missing_fields": [],
      "stack_pairing_rate": {"sidecar": 0.962, "oracle": 0.961}
    },
    {"class": "NdisDrop", "sidecar_rows": 234, "oracle_rows": 0,
     "note": "Oracle has known gap; sidecar fixes parity gap #1"},
    ...
  ],
  "deploy_check": {
    "self_contained": true,
    "requires_runtime_install": false,
    "signed": false,
    "package_steps": 1
  },
  "panic_test": {"clean_failure": true, "failure_kind": "csharp_exception"}
}
```

Both spike implementations submit a report from this harness; the team
makes the decision based on side-by-side comparison.

## 13. Packaging

### Wheel strategy (both languages)
- Build platform-tagged wheels:
  - `wpr_mcp_server-<ver>-py3-none-win_amd64.whl`
  - `wpr_mcp_server-<ver>-py3-none-win_arm64.whl` (when needed)
- Each wheel includes `src/etw_analyzer/bin/wpr-mcp-extract.exe` for its
  architecture.
- `sdist` excludes binary; falls back to Python native / xperf.
- `pyproject.toml` custom hatchling build hook copies the pre-built
  binary based on `--plat-name`.

### Per-language packaging
- **Rust:** statically linked `.exe`, ~5–10 MB.
- **C#:** self-contained single-file `.exe` (`<PublishSingleFile>true</PublishSingleFile>`),
  ~60–90 MB. NativeAOT only after trim-compat is proven for
  TraceEvent.

### Signing (required for v1 release per reviewer escalation)
- EV cert or Microsoft-managed signing service. Document in release
  runbook. Unsigned dev builds OK for local testing only.

## 14. Testing

### 14.1 Existing tests
3-way parameterization where applicable:
```python
@pytest.mark.parametrize("mode", ["xperf", "native", "sidecar"])
def test_get_cpu_samples_happy(load_with_mode, fixture_etl, mode):
    ...
```

### 14.2 Per-language unit tests
- **Rust:** `cargo test` mirrors `tests/native/test_mof_*.py` cases via
  shared `.bin` synthetic fixtures.
- **C#:** `dotnet test` mirrors the same cases via the same `.bin`
  fixtures.

### 14.3 Parity tests (cross-language)
Test target runs sidecar and compares emitted parquets to
checked-in Python native baseline. Fails on column/value mismatch
outside tolerance.

### 14.4 New test categories (per reviewers)
- Fuzz / malformed ETL
- Truncated parquet (mid-write)
- Panic/exception recovery
- Memory leak / load-repeat (100×)
- Concurrent extraction (staging promotion serializes)
- Performance breakdown (callback decode vs parquet write vs
  symbolization vs pandas aggregation)

## 15. Effort estimate

| Phase | C# weeks | Rust weeks | Net dev-days (winner) |
|---|---|---|---|
| -1 — Spike harness | 0.5 | 0.5 | 3 |
| 0 — Spike (both langs) | 1 | 1 | 8 (4 ea, parallel) |
| 1 — Full decoder coverage | 3 | 4 | 15–20 |
| 2 — Event-store streaming | 1 | 1 | 5 |
| 3 — Aggregation worker + supervisor | 1 | 1 | 5 |
| 4 — Cutover + docs + signing | 1 | 1 | 4 |
| 5 — Cleanup (1 release later) | 0.5 | 0.5 | 2 |
| Buffer | 2 | 2.5 | 8–10 |
| **Total (C# wins)** | **~10 weeks** | — | **~50 dev-days** |
| **Total (Rust wins)** | — | **~12 weeks** | **~60 dev-days** |

## 16. Risks

| Risk | Rating | Mitigation |
|---|---|---|
| TraceEvent missing required fields (kills C# path) | Medium / High | Spike's mandatory-class list (§11 phase 0) exercises field coverage explicitly |
| `windows-rs` ETW API gaps (kills Rust path) | Medium / High | Phase 0 exercises ProcessTrace + raw timestamps + TDH |
| Schema drift between sidecar and Python | High / High | Schema parity test on every build; bump `schema_version` on incompatible change |
| Binary signing / AV blocks enterprise users | High / Medium-High | Signing required for v1 release; documented in release runbook |
| Large trace handling regression | High / High | Event-store streaming is phase 2, not phase 5 |
| Rust panic / C# exception crossing FFI | High / High (unmitigated) → Low / High (with §10) | §10 mandates catch_unwind / structured-exception trap |
| Wrong language committed before spike | Medium / High | §2 spike + pass/fail criteria; recommended prior is C# |
| Python aggregation pass becomes bottleneck | Medium / Medium | Performance breakdown test (§14.4) catches it; can move stack_butterfly to native if needed |
| Dual-codepath maintenance through phase 4 | Medium / Medium | Phase 5 (1 release later) deletes Python native; not indefinite |

## 17. Change log — v2 → v3

Driven by `rust-vs-csharp-spike-review.md` (gpt-5.5).

### Added
- **§2 explicit spike pass/fail criteria** — C# vs Rust decision is now
  measurable, not just "do a spike."
- **§4.1 Python aggregation pass** between sidecar and promotion — fixes
  v2's missing step where Layer 3 was supposed to come from.
- **§9 C# implementation layout** — parallel to Rust layout. v2 lacked
  this entirely.
- **§12 spike harness** — measurement tool built before either spike,
  so both spikes produce comparable reports.
- **`producer` field in cache manifest** — fixes v2's `mode="rust"` vs
  `cache.py` `mode == "native"` conflict.

### Changed
- **Title and framing:** "Rust hybrid migration plan" →
  "Native sidecar migration plan." Plan is now language-neutral
  through phase 0.
- **§5 schema source of truth:** stays Python (`native/schemas.py`) for
  v1. v2 proposed Rust-as-source; backwards if C# wins. Language-neutral
  spec is future work.
- **§7 ownership matrix:** `worker.py` is **transformed** into
  `aggregation_worker.py`, not deleted. Runs the Python aggregation
  pass between sidecar exit and promotion.
- **§10 FFI safety:** now language-specific (Rust catch_unwind; C#
  structured exception trap).
- **§11 phasing:** C# path is 3 weeks for phase 1 vs Rust's 4 (TraceEvent
  eliminates ~25% of the porting work).
- **§15 effort:** C# total ~10 weeks; Rust total ~12 weeks.

### Removed
- v2's assertion that Rust is the source of truth for schemas
  (premature commitment).
- v2's `mode="rust"` in cache manifest (conflicts with existing
  validation).
- v2's deletion of `worker.py` without replacement for aggregator
  orchestration.

### Carried forward unchanged from v2
- Strategic positioning: tactical, not the north-star.
- Subprocess + parquet boundary (rejection of PyO3 and Arrow IPC
  streaming).
- Event-store streaming required in phase 2.
- `worker_supervisor` reused, not replaced.
- Wheel packaging plan.
- Signing required for v1.
- Test categories added per reviewers.

## 18. Open questions

1. **Phase 0 outcome.** Resolves in week 1 of phase 0.
2. **`ferrisetw` vs raw `windows-rs`** (only if Rust wins). Decide in
   phase 0 spike.
3. **Code-signing infrastructure access.** Required for v1 release.
4. **ARM64 Windows.** Day 1 or deferred?
5. **TraceEvent NativeAOT compatibility** (only if C# wins). Single-file
   self-contained is the safe default; NativeAOT is a later optimization.
6. **`get_memory_pools` strategy.** Stays xperf-only. Future: maybe
   proxy through the sidecar so users only see one binary.

## 19. Exit criteria

- `wpr-mcp-extract.exe` exists, signed, built in CI for `win_amd64`.
- All 60 tools pass tests with `mode="sidecar"` on committed fixtures.
- All 5 parity gaps from `native-vs-xperf-parity-review.md` either
  fixed or explicitly documented as out-of-scope:
  - **#1 NdisDrop:** fixed by sidecar (mapper in
    `wpr-etw-core/manifest/ndis.rs` or `WprMcp.EtwCore/ManifestMappers/NdisDropMapper.cs`).
  - **#2 cpu_sampling Idle row:** Python aggregator change; can be
    fixed in parallel.
  - **#3 sysconfig content:** **closed if C# wins** (TraceEvent decodes
    SystemConfig fully); stays open if Rust wins.
  - **#4 diskio detail:** still xperf-only; document.
  - **#5 tracestats format:** still differs; document.
- Cache reload from Python-native-era caches works under sidecar mode
  (cache.py treats `producer="python"` caches as valid prior
  generations).
- Documentation updated:
  - README marks sidecar as default for ETW analysis specifically.
  - CLAUDE.md describes the sidecar/aggregation_worker/Python-tools
    split.
- Fresh-machine user can `uv sync` and run ETW analysis without
  installing cargo/rustc (Rust path) or .NET SDK (C# path) — the
  wheel ships the binary.

## 20. Cross-references

- Reviews: `rust-hybrid-migration-plan-review.md` (gpt-5.5 tactical),
  `rust-hybrid-migration-plan-review-2.md` (gpt-5.4 tactical),
  `rust-vs-csharp-spike-review.md` (gpt-5.5 strategic + language
  recommendation).
- Parity gaps: `native-vs-xperf-parity-review.md`.
- Current Python source: `src/etw_analyzer/native/`.
- Test infrastructure: `tests/fixtures/README.md`,
  `tests/native/test_worker_supervisor.py`,
  `tests/native/test_event_store.py`.
- Schema source of truth (current): `src/etw_analyzer/native/schemas.py`.
- Cache contract: `src/etw_analyzer/native/cache.py`,
  `src/etw_analyzer/native/event_store.py`.
- Worker protocol: `src/etw_analyzer/native/worker.py`,
  `src/etw_analyzer/native/worker_supervisor.py`.
- Networking WPR profile: `C:\git\udp-perf\scripts\networking.wprp`.
