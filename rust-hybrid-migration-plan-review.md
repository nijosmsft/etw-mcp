# Review of `rust-hybrid-migration-plan.md` (v1)

**Reviewer:** GPT-5.5 sub-agent, dispatched 2026-05-29.
**Plan reviewed:** `rust-hybrid-migration-plan.md` (initial draft, 2026-05-29).
**Companion context provided to reviewer:** `native-vs-xperf-parity-review.md`,
the full `src/etw_analyzer/native/` source, the existing
`tests/fixtures/README.md`.

This document captures the review verbatim. The plan has been updated
in-place to address the critical issues; see the change log at the end of
`rust-hybrid-migration-plan.md` for what was edited.

---

## 1. TL;DR

Proceed **only with substantial modifications**. The sidecar direction is
plausible, but the plan is not implementation-ready: it relies on a missing
`native-test-plan.md`, misstates the current cache/manifest/schema
contracts, treats the existing streaming `event_store` path as future work,
and underestimates stack pairing, TDH, dbghelp, packaging, and
crash-recovery complexity. The biggest risk is not Rust itself; it is
replacing a messy but working Python-native pipeline without faithfully
modeling the real contracts that Python tools and aggregators depend on.

## 2. Strengths

- Correctly keeps MCP server/tool layer in Python; rewriting FastMCP tools
  would be scope creep.
- Subprocess isolation is a good default for ETW/dbghelp crashes and Rust
  panics.
- Recognizes `StackWalk` pairing, TDH negative cache, `NdisDrop`, and
  dbghelp as hard parts.
- Preserving parquet/cache as the boundary is directionally good for tool
  compatibility.
- Keeping aggregators in Python initially is reasonable if the goal is
  decode/runtime robustness, not analytics rewrite.

## 3. Critical issues

### 1. The test foundation the plan depends on does not exist

**What's wrong:** The plan repeatedly references `native-test-plan.md`
(`rust-hybrid-migration-plan.md:11`, `290`, `309`, `390`, `549`, `567`),
but `C:\git\wpr-mcp-server\native-test-plan.md` is not present. Repo
fixtures also do not match the plan: `tests\fixtures\README.md:5-10` lists
only `empty-trace`, `cpu-only-trace`, and `pktmon-capture-trace`, not 9
fixtures F1–F9. Current tool count appears to be 60 `@mcp.tool()`
registrations, not 55.

**Why it matters:** The migration's gates are built on nonexistent
artifacts. "All 55 tools pass" and "F1 fixture" cannot be executed as
written.

**Suggested resolution:** Add a preliminary phase: reconcile the test
inventory with the actual repo. Either commit `native-test-plan.md` or
replace all references with the current fixture/oracle system. Recount
tools from `src\etw_analyzer\tools\*.py` and make the Rust exit criteria
match the real count.

### 2. The plan confuses three different schema contracts

**What's wrong:** The plan says `wpr-schemas` becomes the source of truth
(`rust-hybrid-migration-plan.md:237-272`), but current Python has at least
two distinct contracts:

- Event-store physical schemas in `native\schemas.py`, with
  `TimeStampQpc`, `EventSequence`, etc. (`schemas.py:133-147`).
- Materialized dumper/cache parquets loaded into trace attributes via
  `_DUMPER_EVENT_CLASSES` (`trace_mgmt.py:555-585`) and excluded from
  `raw_csv` (`trace_mgmt.py:1226-1258`).
- Aggregate/text outputs like `cpu_sampling`, `dpc_isr`, `stacks`,
  `sysconfig`.

The plan's sample `sampled_profile_schema`
(`rust-hybrid-migration-plan.md:251-263`) mixes event-store fields
(`TimeStampQpc`) with dumper-ish fields (`PID`, `Process Name`). That is
not the current `native\schemas.py` sampled_profile schema
(`schemas.py:133-147`).

**Why it matters:** If Rust writes "matching parquet" to the wrong
contract, Python may load it but aggregators will silently compute wrong
results or skip data.

**Suggested resolution:** Split the contract section into:
1. **event-store raw schemas** — mirror `native\schemas.py`;
2. **dumper per-event parquets** — stems and trace attributes from
   `_DUMPER_EVENT_CLASSES`;
3. **aggregate outputs** — `raw_csv` keys and text files from
   `_run_native_aggregators`.

Do not make Rust schemas the source of truth until Python can
generate/validate both event-store and materialized schemas from a single
neutral schema descriptor.

### 3. Streaming/event-store is not phase-5 optional work

**What's wrong:** The plan treats streaming/Arrow IPC as future
(`rust-hybrid-migration-plan.md:32-33`, `340-345`, `538-540`), but the
repo already has a chunked native event store:

- `extract_events_to_store` streams directly into chunks
  (`extract.py:545-563`).
- `NativeEventStoreWriter` writes staged generations and manifests
  (`event_store.py:509-598`).
- `accessors.py` prefers materialized frames but can scan/iterate
  event-store batches (`accessors.py:86-120`).
- Worker streaming mode exists (`worker.py:286-438`).
- Large native traces are guarded at 512 MB (`config.py:33-36`).

**Why it matters:** A Rust sidecar that only writes flat parquets
regresses the existing large-trace path. The plan's "same user-facing
behavior" claim is false unless Rust can produce
`native-store\generations\<run_id>\native-event-store-manifest.json` and a
v2 cache manifest referencing it.

**Suggested resolution:** Make event-store output part of phase 1 or
phase 2, not phase 5. Rust must implement both `materialized-small` and
`event-store-streaming` strategies from `native\cache.py:14-16`.

### 4. The subprocess contract ignores the existing worker/supervisor design

**What's wrong:** The plan proposes direct `subprocess.run([... --out
export_dir ...])` (`rust-hybrid-migration-plan.md:51-65`) plus five exit
codes (`218-227`). The current native worker already solved several
operational problems:

- staging dir per run (`worker_supervisor.py:213-218`);
- JSON request/result contract (`worker.py:23-86`, `112-143`);
- heartbeats/progress (`worker.py:89-109`, `441-443`);
- timeout/stale heartbeat supervision (`worker_supervisor.py:431-444`);
- Windows Job Object memory limit (`worker_supervisor.py:31-35`,
  `375-383`);
- cache validation before promotion (`worker_supervisor.py:250-286`).

**Why it matters:** Writing directly into `export_dir` risks corrupting a
valid cache on crash. Five exit codes cannot express timeout, stale
heartbeat, invalid cache, promotion failure, partial dataset failure,
panic, or killed process.

**Suggested resolution:** Reuse the existing supervisor model. Replace
`python -m etw_analyzer.native.worker` with `wpr-mcp-extract.exe --request
request.json`, preserve JSONL progress, result JSON, staging promotion,
and cache validation.

### 5. The "what to port" list is incomplete and internally inconsistent

**What's wrong:** Goals list only
`consumer,extract,decoder,manifest,mof,bindings,symbolizer`
(`rust-hybrid-migration-plan.md:17-19`). Phase 4 says keep `cache.py`,
`event_store.py`, `schemas.py`, `accessors.py` (`335-337`) but says delete
byte-bashing files. It omits `worker.py`, `worker_supervisor.py`, and
`sinks.py`, all of which are now part of extraction/cache generation.

Also, line `59` says Rust will "Aggregate (Polars/Arrow)", while
non-goals say aggregators stay Python (`29-32`) and phase 2 says Python
aggregators digest Rust output (`312-324`).

**Why it matters:** Implementation will hit ownership ambiguity: who
writes aggregate parquets, who writes raw event parquets, who writes
event-store chunks, who writes manifests, and who runs symbolization?

**Suggested resolution:** Add an explicit ownership matrix for every
native module:
- replaced by Rust;
- retained as Python reader/adapter;
- deleted;
- temporarily dual-run.

Include `worker.py`, `worker_supervisor.py`, `sinks.py`, `accessors.py`,
`cache.py`, and `event_store.py`.

### 6. Phase 0 spike is too weak

**What's wrong:** Phase 0 validates only `SampledProfile`
(`rust-hybrid-migration-plan.md:278-290`). That avoids the hardest
cross-cutting issues: StackWalk pairing, TDH schema/negative cache,
dbghelp lifetime, parquet list<uint64>, event-store chunks, and panic
safety in ETW callbacks.

**Why it matters:** A SampledProfile-only spike can pass while the
architecture still fails on the real risks.

**Suggested resolution:** Phase 0 should include:
- `SampledProfile + StackWalk` pairing;
- one TDH manifest provider, e.g. TCPIP or AFD;
- one dbghelp symbol resolution pass;
- one event-store chunked output;
- panic/callback error containment test;
- manifest/cache reload through Python.

## 4. Design concerns

### A. Subprocess + parquet is reasonable, but the alternatives are under-analyzed

**What:** The plan rejects PyO3 and Arrow IPC quickly
(`rust-hybrid-migration-plan.md:72-79`).

**Why:** Subprocess is good for crash isolation, but a long-lived daemon
deserves consideration. TDH schema caches, dbghelp module state, symbol
server access, and process startup are per-trace costs today. A daemon
could amortize them and offer progress/cancellation.

**Alternative:** Keep v1 as one-shot subprocess, but design the
request/result protocol so it can later target either
`wpr-mcp-extract.exe extract-once` or `wpr-mcp-extractd` without changing
Python tools.

### B. Cargo workspace is over-split for a first port

**What:** Seven crates are proposed
(`rust-hybrid-migration-plan.md:102-143`).

**Why:** Separate crates for MOF, TDH, manifest, symbolizer, schemas may
create API churn before the design stabilizes.

**Alternative:** Start with:
- `wpr-etw-core` library: consumer, decoders, schemas, symbolizer;
- `wpr-mcp-extract` binary;
- optional `wpr-etw-testutil`.
Split later when APIs harden.

### C. Performance assumptions are not proven

**What:** The plan assumes Rust callback/parquet is faster enough to
justify porting.

**Why:** Existing code says symbolization is expensive:
`profile_detail.py:26-28` says 10M samples collapse to <50K unique IPs and
`bulk_resolve` is the costly step. `stack_butterfly.py:16-18` also
centers cost on symbolization. Parquet write/read and pandas aggregators
may dominate after moving the callback to Rust.

**Alternative:** Add a benchmark gate before phase 1:
- ProcessTrace decode-only events/sec;
- decode + parquet write;
- decode + symbolization;
- full `load_trace` wall clock including Python aggregators.
Report where time moves.

### D. Keeping all aggregators in Python is mostly right, but stack butterfly is a likely exception

**What:** The plan keeps `native\aggregators\*.py` in Python
(`rust-hybrid-migration-plan.md:312-319`).

**Why:** Good for correctness, but `stack_butterfly.py` has
high-cardinality counters and symbolization caps
(`stack_butterfly.py:41-44`, `293-333`, `342-359`). It is already
written to support streaming batches (`610-646`), making it a natural
candidate for Rust or Arrow-native aggregation.

**Alternative:** Keep all aggregators Python for cutover except define a
profiling-triggered fast path for stack aggregation.

### E. `ferrisetw` decision is too vague

**What:** The plan defers `ferrisetw` vs raw `windows-rs` to phase 0
(`rust-hybrid-migration-plan.md:181-183`, `526-527`).

**Why:** This choice affects callback lifetime, raw timestamp mode,
multiple ETL handles, TDH access, and panic boundaries.

**Alternative:** Add two architecture sketches:
- raw `windows-rs`: exact `EVENT_RECORD` control, more unsafe code;
- `ferrisetw`: less boilerplate but must prove raw timestamp, offline
  ETL, and stack pairing support.

## 5. Missing items

- The referenced `native-test-plan.md` file is missing.
- Plan does not mention that current repo has only three scaffolded
  fixture names, not F1–F9.
- Current tool count appears stale.
- No cache filename accuracy: current manifest is
  `wpr-mcp-cache-manifest.json` (`cache.py:11`), not `cache_manifest.json`
  (`rust-hybrid-migration-plan.md:213`).
- No event-store manifest details:
  `native-event-store-manifest.json`, `native-store`, generations, staging
  (`event_store.py:34-40`).
- No `materialize_on_load`/dataset-kind handling from `cache.py:97-132`.
- No atomic promotion strategy.
- No concurrent invocation design for same ETL/export dir.
- No panic policy: Rust must not unwind through ETW callback.
- No fuzz/property tests for binary MOF decoders.
- No memory leak/load-repeat tests for dbghelp/TDH/ProcessTrace.
- No ARM64 Windows packaging plan.
- No platform wheel tagging plan.
- No MSVC runtime/static-linking plan.
- No code-signing plan beyond "if complaints surface".
- No clear partial-success model.
- No log surfacing in `load_trace` output.
- No privilege model discussion.
- No xperf-only tool strategy, especially `get_memory_pools`, which still
  shells to xperf (`memory.py:15-35`).
- No plan for current `worker_supervisor` Job Object memory limit.
- No clear migration story for `mode="native"` caches vs `mode="rust"`
  caches.

## 6. Overstated/understated risks

### `windows-rs` ETW API surface incomplete
- **Plan rating:** Low likelihood / High impact
  (`rust-hybrid-migration-plan.md:513`)
- **My rating:** Medium / High
- **Justification:** Availability of bindings is not the only risk. ETW
  correctness depends on callback ABI, raw timestamp flags, EVENT_RECORD
  lifetimes, TDH interop, and offline trace metadata. Raw FFI fallback is
  plausible, but it should be budgeted.

### Parquet schema drift
- **Plan rating:** Medium / High
  (`rust-hybrid-migration-plan.md:515`)
- **My rating:** High / High
- **Justification:** The plan already shows drift by mixing event-store
  and dumper schemas. This is the most likely implementation failure.

### Binary signing / AV
- **Plan rating:** Medium / Medium
  (`rust-hybrid-migration-plan.md:520`)
- **My rating:** High / Medium-High
- **Justification:** A bundled unsigned Windows `.exe` inside a Python
  package is exactly the pattern that triggers enterprise AV and
  WDAC/AppLocker policies. "Sign if users complain" is not good enough
  for a Microsoft-adjacent perf tool.

### Subprocess overhead
- **Plan rating:** Low / Low
  (`rust-hybrid-migration-plan.md:516`)
- **My rating:** Low / Low for large traces, Medium / Low for fixture/test
  loops
- **Justification:** Not a blocker, but CI and small fixture tests will
  feel it. Existing worker already has heartbeat/JSON overhead; benchmark
  it.

### Loss of Python-developer hackability
- **Plan rating:** High / Low-Medium
  (`rust-hybrid-migration-plan.md:518`)
- **My rating:** High / Medium
- **Justification:** The "byte-bashing" code is exactly where provider
  quirks are discovered. Moving it to Rust improves safety but raises the
  barrier for quick ETW mapper fixes.

### Large trace handling
- **Plan rating:** Not treated as a core risk
- **My rating:** High / High
- **Justification:** Existing native has a 512 MB guardrail and a
  streaming worker path. A flat-parquet Rust sidecar regresses this.

### Aggregator bottleneck
- **Plan rating:** Future optimization
  (`rust-hybrid-migration-plan.md:340-342`)
- **My rating:** Medium / Medium
- **Justification:** If Python stack/pandas/dbghelp remains dominant,
  Rust decode may not improve end-to-end `load_trace`.

## 7. Recommended changes to the plan document itself

1. Replace all `native-test-plan.md` references with a real committed
   test document or the current `tests\fixtures\README.md` fixture/oracle
   model.
2. Add a "Current contracts" section covering:
   - `_DUMPER_EVENT_CLASSES` stems/attributes
     (`trace_mgmt.py:555-585`);
   - `_PARQUET_EXCLUDED` (`trace_mgmt.py:1226-1258`);
   - native cache v2 (`cache.py:11-16`, `136-181`);
   - event-store manifests (`event_store.py:34-40`, `188-233`).
3. Correct manifest filename from `cache_manifest.json` to
   `wpr-mcp-cache-manifest.json`.
4. Make event-store streaming a required cutover feature, not phase 5.
5. Replace direct `subprocess.run` design with a request/result/staging
   protocol compatible with `worker_supervisor.py`.
6. Add a module ownership matrix for all files in
   `src\etw_analyzer\native\`, including `worker.py`,
   `worker_supervisor.py`, `sinks.py`, `accessors.py`, and `cache.py`.
7. Expand phase 0 to include StackWalk, TDH, dbghelp, event-store, and
   panic containment.
8. Add performance gates with baseline measurements against current
   Python native and xperf.
9. Remove `polars` from dependencies unless Rust aggregators are in
   scope; use `arrow`/`parquet` directly for sidecar output.
10. Add ARM64 and wheel platform tagging plan.
11. Require code signing for release builds or explicitly document
    enterprise-blocked deployment risk.
12. Add xperf integration strategy for unsupported analyses like memory
    pools.
13. Clarify `mode="auto"` and `mode="native"`/`mode="rust"` naming.
    "native alias to rust" (`rust-hybrid-migration-plan.md:338`) will be
    confusing because native currently means Python OpenTrace.
14. Add concurrent extraction locking or per-run export directories with
    atomic promotion.
15. Add crash/partial-success semantics beyond exit codes.

## 8. Bottom-line recommendation

**Proceed with modifications.** The Rust sidecar is a defensible direction
for crash isolation, safer binary parsing, and eventually better decode
speed. But the current plan should not start implementation as-is. First
fix the test-plan mismatch, formalize the real cache/schema/event-store
contracts, reuse the existing worker-supervisor pattern, and make
StackWalk/TDH/dbghelp/event-store part of the initial spike. Otherwise
this will become a second native pipeline that is faster in demos but
less compatible and harder to operate.
