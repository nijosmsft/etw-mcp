# Review #2 of `rust-hybrid-migration-plan.md` (v1)

**Reviewer:** GPT-5.4 sub-agent, dispatched 2026-05-29.
**Plan reviewed:** `rust-hybrid-migration-plan.md` (initial draft, 2026-05-29).
**Companion context provided to reviewer:** parity review, all
`src/etw_analyzer/native/` source, `tests/fixtures/README.md`, project
conventions.
**Independence note:** dispatched in parallel with `rust-plan-review` and
explicitly forbidden from reading review #1, to produce a truly
independent second opinion.

This document captures the second review verbatim. The plan has been
updated in-place to address both reviews; see the change log at the end
of `rust-hybrid-migration-plan.md` for what was edited.

---

## 1. TL;DR

Proceed **with major modifications**, not as-is. The core direction —
move ETW decode/TDH/MOF/dbghelp into a Rust subprocess while keeping
tools and most analytics in Python — is reasonable. But the plan's
central claim that "parquet schema is the contract" is currently
underspecified and, in places, wrong relative to the real Python contract
in `src\etw_analyzer\native\cache.py`, `event_store.py`,
`trace_mgmt.py`, and the event-store-aware tools. If you start
implementation from this document unchanged, you will almost certainly
ship a Rust extractor that Python cannot reload correctly.

## 2. Strengths

- **Right blast-radius choice:** keeping FastMCP + tool modules in Python
  avoids rewriting 50+ tool surfaces.
- **Subprocess boundary is directionally correct:** better than PyO3 for
  this repo's current packaging and debugging model.
- **The plan targets the real unsafe surface:** `consumer.py`,
  `decoder.py`, `mof\*`, `manifest.py`, `symbolizer.py` are the byte/FFI-
  heavy parts.
- **It explicitly calls out real parity bugs** (`NdisDrop`, uint64
  overflow, 32-bit header issues) from
  `native-vs-xperf-parity-review.md`.
- **Schema parity tests are the right instinct**, just aimed at the wrong
  schema layer.

## 3. Critical issues

### 3.1 The cache/manifest contract in the plan does not match the real one
**What's wrong:** The plan says Python↔Rust communicate via parquet +
`cache_manifest.json` (`rust-hybrid-migration-plan.md:42-43, 62-64,
213-215`). The actual filename is `wpr-mcp-cache-manifest.json`
(`src\etw_analyzer\native\cache.py:11`,
`tools\trace_mgmt.py:1263`). The actual manifest shape is
`schema_version/mode/strategy/complete/etl/datasets/native_store`, with
dataset-level `kind`, `path`, `schema_version`, `row_count`,
`materialize_on_load` (`native\cache.py:97-145`, `247-291`). There is
**no** `extract_stats` blob in the manifest.

**Why it matters:** Python cache reload is contract-sensitive:
`trace_mgmt._load_native_v2_from_cache()` expects dataset kinds and
`materialize_on_load` semantics (`tools\trace_mgmt.py:1596-1673`).

**Suggested resolution:** Replace the plan's hand-wavy manifest
description with the exact v2 JSON schema, including dataset kinds:
`parquet`, `text`, `dumper-parquet`, `native-event-store`.

### 3.2 The plan conflates two different schema layers
**What's wrong:** Line `239` says `wpr-schemas` mirrors
`native/schemas.py`, and the sample schema at `251-263` uses `PID` /
`Process Name`. But `src\etw_analyzer\native\schemas.py` is the
**event-store physical schema**, where `sampled_profile` has
`ProcessId`, `ThreadId`, `PayloadThreadId`, `InstructionPointer`,
`Stack` (`native\schemas.py:133-147`). `cpu_sampling`, `dpc_isr`,
`stacks`, `sysconfig`, etc. are **aggregated/materialized outputs**
produced elsewhere (`tools\trace_mgmt.py:1100-1142`).

**Why it matters:** A Rust implementation built from the plan will
likely generate the wrong parquet schemas and break both reload and
event-store-aware tools.

**Suggested resolution:** Split the contract section into:
1. event-store physical schemas (`native/schemas.py`),
2. materialized aggregate outputs (`cpu_sampling.parquet`,
   `dpc_isr.parquet`, text files),
3. manifest metadata.

### 3.3 The CLI output contract contradicts the plan's own phasing
**What's wrong:** Section 4 says the Rust binary writes
`cpu_sampling.parquet`, `dpc_isr.parquet`, `cpu_timeline.parquet`,
`stacks.parquet`, `stacks_callers.parquet`, plus event parquets
(`rust-hybrid-migration-plan.md:206-216`). But Phase 2 says aggregators
stay in Python and Rust emits raw event parquets only (`316-324`).

**Why it matters:** This is not editorial; it changes ownership of
`trace_mgmt._run_native_aggregators()` and the cache finalization path.

**Suggested resolution:** Pick one:
- **Rust emits only raw/event-store data**, Python still runs
  aggregators and writes aggregate/text outputs; or
- **Rust owns full cache finalization**, in which case the "aggregators
  stay in Python" claim is false.

### 3.4 The plan ignores the current event-store/streaming contract
**What's wrong:** The repo no longer has one native cache shape.
`native/cache.py` defines both `materialized-small` and
`event-store-streaming` (`native\cache.py:14-18, 146-181`).
`event_store.py` defines `native-store\generations\<run_id>` plus its
own `native-event-store-manifest.json` (`native\event_store.py:34-41,
509-599`). Tools already consume event-store-backed traces via
`accessors.py` (`native\accessors.py:63-193`) and multiple tool modules
(`tools\context_switch.py`, `app_layer.py`, `packet_capture.py`,
`network_wait_chain.py` per repo grep).

**Why it matters:** "Preserve the existing parquet cache format
exactly" (`plan:20-23`) is false unless Rust preserves **both**
strategies.

**Suggested resolution:** Add a first-class section for streaming/event-
store compatibility. If Rust v1 only supports flat materialized caches,
say so explicitly and scope out event-store parity.

### 3.5 Operationally, the proposed subprocess is weaker than the current worker model
**What's wrong:** The plan's subprocess example writes directly to
`--out` and reports only exit codes + `extract.log` (`51-64`,
`218-227`). The current system uses unique staging dirs, validation,
heartbeat/progress JSONL, stderr/stdout tail capture, and atomic
promotion (`native\worker.py:112-143`,
`native\worker_supervisor.py:200-306, 745-759`). Tests explicitly
assert that partial staging is not promoted
(`tests\native\test_worker_supervisor.py:185-214`) and that cache
reload must not materialize events in streaming mode
(`tests\native\test_event_store.py:301-365`).

**Why it matters:** This is already solved operational complexity. The
plan would regress crash reporting and race safety.

**Suggested resolution:** Keep the existing Python supervisor pattern
and swap only the child executable. Rust should write to staging;
Python should validate + promote.

### 3.6 Fresh-machine / no-xperf claim is not currently defensible
**What's wrong:** Exit criteria say a fresh machine should work
"without … xperf" (`560-561`). But `get_memory_pools` is still
xperf-only and shells to `_run_xperf(..., "pool", ...)`
(`tools\memory.py:12-43`).

**Why it matters:** The plan overpromises distribution simplicity.

**Suggested resolution:** Either narrow the claim to the hot-path tools,
or explicitly add a gap strategy (e.g. Rust sidecar can invoke xperf
for pool/sysconfig gaps so users still don't manage xperf themselves).

### 3.7 Rust callback panic safety is missing from the plan
**What's wrong:** Python's consumer explicitly traps callback exceptions
instead of unwinding through ETW (`native\consumer.py:140-145,
175-179, 230-239, 305-309`). The Rust plan never says how
`EVENT_RECORD_CALLBACK` is made unwind-safe.

**Why it matters:** In Rust, unwinding across Win32 FFI is UB.

**Suggested resolution:** Add a hard requirement: callback body must be
wrapped in `catch_unwind` and communicate failure through a side
channel / atomic flag, never by unwinding.

## 4. Design concerns

- **Subprocess + disk is still the right default boundary**, but only
  because this repo already treats on-disk cache as the system boundary
  (`tools\trace_mgmt.py:1676-1803`). PyO3 is indeed unattractive.
  Arrow IPC is only interesting if Rust also owns aggregation.
- **Cargo workspace is over-focused on decoder domains and under-focused
  on contract domains.** A `wpr-cache-contract` / `wpr-event-store`
  crate boundary would map better to the real Python integration surface
  than separate `wpr-manifest` vs `wpr-tdh-decoder`.
- **`polars` is a scope leak.** The plan says aggregators stay in
  pandas (`27-33`, `316-324`) but adds `polars` anyway (`169-172`).
  That increases compile time and binary complexity for no v1 benefit.
- **Phase 0 is too weak.** `SampledProfile` validates neither TDH, nor
  stack pairing, nor event-store, nor symbolizer, nor cache promotion.
  It is not a meaningful architectural spike for this design.
- **The 10-week / 40-day estimate is low.** TDH alone is non-trivial:
  positive cache, provider-wide negative cache, `PROPERTY_PARAM_LENGTH`,
  32-bit header handling, partial-row behavior
  (`native\decoder.py:15-30, 203-410`). DbgHelp also has real quirks
  (`native\symbolizer.py:167-185, 345-383`).

## 5. Missing items

- Exact **v2 cache manifest schema** and example JSON.
- Exact **event-store generation layout** (`native-store\generations\...`)
  and its manifest.
- Explicit **staging/promote protocol** for concurrent loads of the same
  ETL/export dir.
- A **performance breakdown plan**: callback decode vs parquet write vs
  symbolization vs pandas aggregation.
- **Fuzz / malformed ETL / truncated parquet / panic recovery / memory
  leak** test categories.
- A real **wheel strategy** for `win_amd64` and `win_arm64`. Current
  `pyproject.toml` is pure-Python hatchling config only
  (`pyproject.toml:41-46`).

## 6. Overstated/understated risks

- **Understated:** unsigned binary / AV risk. The plan rates it medium
  (`520`). In enterprise Windows environments, unsigned sidecars are a
  predictable support problem.
- **Understated:** `windows-rs` + ETW/TDH bus factor. This is niche API
  territory; the risk is not "Low" just because bindings exist (`513`).
- **Understated:** dual-codepath maintenance. Through phase 4 you are
  really carrying Rust extractor + Python native + xperf + worker/event-
  store compatibility, not just "insurance."
- **Overstated:** disk I/O overhead from parquet (`76-77`). The real
  unresolved cost is more likely symbolization and pandas stack
  aggregation, not a few parquet writes.

## 7. Recommended changes to the plan document

1. Replace all `cache_manifest.json` references with the real filenames
   and schemas:
   - `wpr-mcp-cache-manifest.json`
   - `native-event-store-manifest.json`
2. Split "Schema contract" into:
   - event-store physical schemas,
   - materialized aggregate outputs,
   - manifest dataset kinds.
3. Rewrite Section 4 so the CLI contract matches one chosen ownership
   model:
   - raw-only extractor, or
   - full cache builder.
4. Add a section "Compatibility with current streaming/event-store
   mode" referencing:
   - `src\etw_analyzer\native\event_store.py`
   - `src\etw_analyzer\native\accessors.py`
   - event-store-aware tools.
5. Add a non-negotiable "FFI safety" subsection: `catch_unwind`, no
   unwinding across ETW callbacks.
6. Replace the packaging section with a concrete hatchling/wheel plan
   for `win_amd64` and `win_arm64`; do not imply a bundled `.exe` can
   live in a generic pure wheel.
7. Change phase 0 exit criteria to include at least:
   - one TDH/manifest event,
   - one stack-paired kernel event,
   - one cache reload through Python,
   - one worker crash-path validation.

## 8. Bottom-line recommendation

**Proceed with modifications.** The Rust sidecar idea is good, and
better than PyO3 here. But the document currently misstates the Python
contract at exactly the points that matter most: manifest shape, schema
ownership, event-store compatibility, packaging, and subprocess
supervision. Fix the contract section first; otherwise the
implementation will optimize the wrong boundary.
