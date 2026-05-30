# Architecture

Single source of truth for how the WPR trace analyzer fits together with the
C# sidecar, the optional evidence federation, and its peer MCPs. Replaces the
ad-hoc status notes in `manager-log/`. Pair with
[`GETTING-STARTED.md`](GETTING-STARTED.md) for a clone-to-first-query walkthrough
and [`CLAUDE.md`](CLAUDE.md) for AI-assistant operating notes.

## 1. Purpose

`wpr-mcp-server-csharp-sidecar` is the production tree for an MCP server that
loads Windows ETW/WPR `.etl` traces, decodes them into a structured parquet
cache, and exposes pandas-backed analysis tools (CPU sampling, DPC/ISR, hot
stacks, network flows, HTTP/QUIC events) over the [Model Context
Protocol](https://modelcontextprotocol.io/). It is one of three MCPs that
together form a federated debugging story for Windows performance + reliability
work: this server is the **ETW writer**, `crash-dump-mcp-server` is the
in-scope-but-not-currently-wired **crash writer**, and `wpr-mcp-evidence-query`
is the **reader** that correlates whatever the writers have left in the shared
evidence store.

## 2. Repo map

Five repos cooperate. Boundaries are intentional — three of them ship binaries
or libraries, two are MCP servers.

| Repo | Role | Key entry points |
|---|---|---|
| `wpr-mcp-server` (master / production) | Stable production tree of this server (no C# sidecar, no evidence wiring). | `src/etw_analyzer/server.py`, `README.md` |
| `wpr-mcp-server-csharp-sidecar` (this worktree, `feature/csharp-sidecar`) | Production tree extended with the C# sidecar (csharp mode) and evidence-wiring extras. | `src/etw_analyzer/server.py`, `csharp/`, this `ARCHITECTURE.md` |
| `wpr-mcp-evidence-store` (library) | Per-machine DuckDB schema + identity helpers (`module_id`, `nic_id`, `machine_id`). No MCP surface; producers and the query MCP both depend on it. | `docs/IDENTITY-SPEC.md`, `docs/PRODUCER-CONTRACT.md` |
| `wpr-mcp-evidence-query` (MCP, reader) | MCP server that federates across per-machine DuckDB files written by the producers. Headline tool: `correlate_trace_and_dump`. | `src/evidence_query/server.py`, `README.md` |
| `crash-dump-mcp-server` (MCP, producer-in-design) | Loads `.dmp` files, runs `!analyze`-style workflows. Designed to write the same `module_id`/`nic_id` keys but the wiring branch was rolled back; see `manager-log/VERDICT-csharp-wiring.md` "Removed scope". | `crash_dump_mcp/server.py`, `README.md` |

```
            ┌──────────────────────────────┐
   .etl ─►  │ wpr-mcp-server-csharp-sidecar│  ──parquet cache──► (instant reload)
            │  (ETW writer MCP)            │
            └─────────────┬────────────────┘
                          │ (optional, WPR_MCP_EVIDENCE_PATH)
                          ▼
                ┌─────────────────────┐
                │ wpr-mcp-evidence-   │
                │     store (lib)     │◄─── crash-dump-mcp-server
                │  per-machine        │     (in-scope, currently unwired)
                │  DuckDB files       │
                └─────────┬───────────┘
                          │
                          ▼
                ┌─────────────────────┐
                │ wpr-mcp-evidence-   │
                │  query (reader MCP) │
                └─────────────────────┘
```

## 3. End-to-end dataflow

A single `load_trace` call walks one of three extraction backends, lands the
result in a shared parquet cache, then registers a `TraceData` in process. The
optional evidence hook fires once at the end and is a no-op when not configured.

```
            ┌─ csharp → wpr-mcp-extract.exe (self-contained .NET) ─┐
.etl ──►    ├─ native → OpenTraceW + tdh.dll (in-process)         ─┼─► per-event parquets
            └─ xperf  → xperf.exe -a dumper (subprocess pool)     ─┘
                                  │
                                  ▼
                       Layer-3 aggregators (Python, pandas)
                        cpu_sampling, dpc_isr, cpu_timeline,
                        stacks, stacks_callers, sysconfig, ...
                                  │
                                  ▼
                       parquet cache (.etw-export-<stem>/)
                       + wpr-mcp-cache-manifest.json (schema v3)
                                  │
              ┌───────────────────┼──────────────────────────┐
              ▼                   ▼                          ▼
       MCP tools                trace registry          (optional)
       (analyze, get_*)         (TraceData in           evidence-store
                                 trace_state.py)        register_entities_from_trace
                                                              │
                                                              ▼
                                                  per-machine DuckDB at
                                                  $WPR_MCP_EVIDENCE_PATH/<machine_id>/
                                                              │
                                                              ▼
                                                  wpr-mcp-evidence-query
                                                  (separate MCP process)
```

The pipelines are interchangeable on disk — the manifest schema is identical
across `producer ∈ {csharp, native, xperf}`, so a trace decoded under one mode
rehydrates from cache under any other.

## 4. Producer-consumer model

The evidence federation is strictly **multi-producer, single-reader**. The
producers (this server's csharp/native/xperf load paths, and eventually
`crash-dump-mcp-server`) only write rows into a per-machine DuckDB; the reader
(`wpr-mcp-evidence-query`) only reads them.

| Role | MCP | DB access |
|---|---|---|
| Producer (ETW) | this server (`evidence_integration.register_entities_from_trace`) | append-only writes to `<root>/<machine_id>/evidence.duckdb` |
| Producer (crash) | `crash-dump-mcp-server` (rolled back; pattern documented) | append-only writes to the same path |
| Reader | `wpr-mcp-evidence-query` | read-only DuckDB connections; SQL escape hatch has `read_only=True` guard |

The four isolation guarantees that make this safe to ship behind an optional
extra are in `evidence-mcp-poc-plan.md` §1.1:

| Guarantee | Mechanism | Verified by |
|---|---|---|
| G1 — separate repos for new code | `wpr-mcp-evidence-store` and `wpr-mcp-evidence-query` are new standalone repos. | repo creation, not a code path |
| G2 — feature branches, never master | worktrees + feature branches; main never touched. | `git log master -1` on this server's parent |
| G3 — optional dep + double import guard | `evidence-store` lives only in `[project.optional-dependencies] evidence`; integration module does `try: import / except ImportError` AND short-circuits when `WPR_MCP_EVIDENCE_PATH` is unset. | tests in `tests/test_evidence_integration*.py` |
| G4 — no merge to master during POC | branches stay on `feature/*`; production merge requires a separate human-reviewed PR. | branch state |

The cross-tool identity contract is byte-deterministic so a second producer in
any language can be added without changing the reader. See
`wpr-mcp-evidence-store/docs/IDENTITY-SPEC.md` for the UUIDv5 derivation
(`module_id = name_lower + TimeDateStamp + SizeOfImage`, `nic_id = LUID`,
`machine_id = stable host token`).

## 5. Cache / manifest lifecycle

The on-disk shape is shared across all three extraction backends. The cache
directory sits beside the source ETL:

```
<etl-parent>/.etw-export-<etl-stem>/
├── wpr-mcp-cache-manifest.json   ← schema v3
├── sampled_profile.parquet
├── cswitch_events.parquet
├── tcpip_recv.parquet            …one parquet per event class (see _DUMPER_EVENT_CLASSES)
├── cpu_sampling.parquet          ← Layer-3 aggregator output
├── cpu_timeline.parquet
├── dpc_isr.parquet
├── stacks.parquet
├── stacks_callers.parquet
├── sysconfig.txt                 ← raw text for sysconfig
└── process.parquet
```

Manifest schema v3 (the current shape):

```json
{
  "schema_version": 3,
  "producer": "csharp",                    // {csharp, native, xperf}
  "mode": "native",                        // on-disk pipeline name (csharp = "native"-shaped + producer)
  "etl_identity": {
    "path": "C:\\traces\\spike-fixture.etl",
    "size": 1149620224,
    "mtime_ns": 1730000000000000000        // see "C# mtime_ns" in §8
  },
  "datasets": { "sampled_profile": "sampled_profile.parquet", ... },
  "created_at": "2026-05-30T17:42:00Z"
}
```

**Producer field semantics.** `producer` records *who decoded the events into
parquet*; `mode` records the on-disk shape. csharp writes
`mode="native" producer="csharp"` so the in-process consumer's loader can
rehydrate the cache without changes.

**Cross-producer compatibility.** v2 manifests still load and back-fill to
`producer="native"`. A csharp-produced cache rehydrates under `mode="native"`
or `mode="xperf"` on the next load — verified by
`tests/test_trace_mgmt_cache.py`.

**Invalidation.** The loader compares ETL `(size, mtime_ns)` to the manifest
and re-decodes from scratch on mismatch. The csharp sidecar has a known
`mtime_ns` quirk (.NET Ticks vs Unix epoch) — the Python `EtlIdentity` falls
back to "loose" matching (`size` + `name` only) when `producer="csharp"` until
the C# fix lands. Both behaviors are pinned by tests in
`tests/test_trace_mgmt_cache.py`.

## 6. Tool registration and trace lifecycle

The CLAUDE.md trace lifecycle section is the canonical narrative; the short
version:

* `server.py` imports each `tools.*` module; each module attaches functions to
  the shared FastMCP instance via `@mcp.tool()` at import time. A new tool file
  is invisible until a matching `import` line is added to `server.py`.
* Every analysis tool's signature starts with `trace_id: str` and calls
  `require_trace(trace_id)` immediately. There is no "current trace" state —
  IDs are explicit so multiple traces analyze concurrently in one process.
* `trace_id` is `trace_<sha256[:12]>` of `(lowercase path | size | mtime_ns)`,
  stable per ETL version. All three pipelines produce the same `trace_id`.
* `load_trace` blocks until the background dumper *and* its aggregators finish,
  so the summary it returns reflects every dataset. After that, analysis tools
  read from `TraceData.raw_csv` synchronously.

Full narrative + per-mode flow diagrams live in [`CLAUDE.md`](CLAUDE.md) under
"Trace lifecycle". Sidecar plumbing detail lives in
[`src/etw_analyzer/native/SIDECAR.md`](src/etw_analyzer/native/SIDECAR.md).

## 7. Evidence model

The evidence store is intentionally *small* — it is a per-machine DuckDB
holding entities the producers agree on, not a generic event log. Three core
entity kinds, each keyed by a UUIDv5 derived from a stable identity tuple:

| Entity | Identity tuple | Why it's stable |
|---|---|---|
| `module` | `(image_name_lower, TimeDateStamp, SizeOfImage)` | binary identity; matches across producers regardless of file path |
| `nic` | `LUID` | network adapter LUID is stable across reboots and rename; friendly name is not |
| `machine` | `(stable host token)` — see `IDENTITY-SPEC` for the supported derivations | per-machine DB lives at `$WPR_MCP_EVIDENCE_PATH/<machine_id>/evidence.duckdb` |

A producer writes `EvidenceRef` rows pointing at these entities (e.g. "trace
`trace_0dd889e969b0` saw 1.4M CPU samples in `tcpip.sys` `v10.0.26100.1234`"),
and the reader joins those refs on the entity tables.

The contract documents both producers must satisfy:

* `wpr-mcp-evidence-store/docs/IDENTITY-SPEC.md` — byte-exact UUIDv5 derivation
  with golden vectors.
* `wpr-mcp-evidence-store/docs/PRODUCER-CONTRACT.md` — per-machine DB layout,
  lock/mismatch behavior, EvidenceRef shape.

This server's integration module is `src/etw_analyzer/evidence_integration.py`
(behind the optional `evidence` extra). It runs after
`_run_native_aggregators` and is a no-op when the import fails or
`WPR_MCP_EVIDENCE_PATH` is unset.

## 8. Common failure modes

Concrete error text → actionable fix. The error rewrites in `tools/trace_mgmt.py`
follow this same "what next" pattern.

### 8.1 C# sidecar binary not found

```
load_trace(..., mode="csharp")
→ ValueError: mode='csharp' requested but wpr-mcp-extract.exe was not found.
  Set WPR_MCP_CSHARP_SIDECAR to the published binary path
  (e.g. C:\\install\\wpr-mcp-extract.exe), or build it once with
  `cd csharp; dotnet publish -c Release -r win-x64 --self-contained`,
  or use mode='native'/'xperf' instead.
```

Fix: build the sidecar (`cd csharp; dotnet publish -c Release -r win-x64
--self-contained -o publish\win-x64`) and set
`WPR_MCP_CSHARP_SIDECAR=...\wpr-mcp-extract.exe`. The auto-detect *intentionally*
skips the in-tree `csharp/publish/win-x64/` path so a stray dev build doesn't
silently change the default pipeline. Explicit `mode="csharp"` does check that
path.

### 8.2 Cache schema mismatch

```
load_trace(..., force=False)
→ Native ETW worker extraction failed: invalid-cache: cache manifest
  schema_version=2 does not match expected 3. No trace was loaded.
  Re-run with force=True to rebuild from the ETL.
```

Fix: pass `force=True` on the next `load_trace` call (or delete
`.etw-export-<stem>/`). The manifest writer adds a `producer` field at v3 —
v2 manifests load with `producer="native"` back-filled, but mismatches between
the parquet schema and the manifest version trigger a forced re-decode.

### 8.3 Lock contention on the cache directory

```
load_trace(...)
→ TimeoutError: another process is writing to .etw-export-<stem>/ (held lock
  for >60s). If no other load_trace is in flight, delete .etw-export-<stem>/
  and retry.
```

Fix: the worker supervisor holds an exclusive file lock during the
sidecar/native worker run and the atomic staging promotion. If a previous run
was killed mid-flight, the lock file may be stale — remove the cache directory
and retry. Concurrent `load_trace` calls against the same ETL serialize
through this lock by design.

### 8.4 Missing symbols (functions resolved as `<unknown>` / `module+offset`)

```
get_hot_functions(trace_id)
→ ...rows like  ntoskrnl.exe!FunctionA+0x1234  ...
```

Fix: set `_NT_SYMBOL_PATH` in the MCP env (typically
`srv*C:\\symbols*https://msdl.microsoft.com/download/symbols`) and call
`resolve_symbols(trace_id)` to force a re-download + reload. `check_symbols`
reports which modules failed to resolve and why. The csharp sidecar does
**not** symbolize — symbolization is Python-side in
`etw_analyzer.native.symbolizer` regardless of producer.

### 8.5 xperf.exe not found, no native bindings, no sidecar configured

```
load_trace(...)
→ xperf.exe not found. Install Windows Performance Toolkit (part of Windows
  SDK/ADK) or add it to PATH. Expected at: C:\\Program Files (x86)\\Windows
  Kits\\10\\Windows Performance Toolkit\\xperf.exe — OR set WPR_MCP_MODE=native
  / mode=native if the in-process consumer is available, OR build the C#
  sidecar and set WPR_MCP_CSHARP_SIDECAR.
```

Fix: install the Windows SDK (`winget install Microsoft.WindowsSDK`), or
install the C# sidecar, or run on a Windows build that has the native
consumer. `mode="auto"` will pick whichever is available without further
intervention.

### 8.6 Sidecar JSONL parse failure

```
load_trace(..., mode="csharp")
→ Native ETW worker extraction failed: invalid-stdout: sidecar emitted
  malformed JSONL. The sidecar may be a stale build — rebuild with
  `cd csharp; dotnet publish -c Release -r win-x64 --self-contained` and
  retry, or fall back to mode='native'/'xperf'.
```

Fix: the JSONL protocol changed between the spike and the production build; a
sidecar binary from before the contract was frozen will emit incompatible
shapes. Rebuild the sidecar against the current source tree.

## 9. Quick links

### In this repo

* [`README.md`](README.md) — user-facing install + tool catalog
* [`GETTING-STARTED.md`](GETTING-STARTED.md) — 30-minute onboarding
* [`CLAUDE.md`](CLAUDE.md) — AI-assistant operating notes (canonical trace
  lifecycle narrative)
* [`csharp/README.md`](csharp/README.md) — sidecar build/run/smoke-test
* [`src/etw_analyzer/native/SIDECAR.md`](src/etw_analyzer/native/SIDECAR.md) —
  supervisor + debugging notes for the sidecar

### In sibling repos (relative paths from this worktree)

* [`../wpr-mcp-server`](../wpr-mcp-server) — production master tree
* [`../wpr-mcp-evidence-store/README.md`](../wpr-mcp-evidence-store/README.md)
  and `docs/IDENTITY-SPEC.md`, `docs/PRODUCER-CONTRACT.md`
* [`../wpr-mcp-evidence-query/README.md`](../wpr-mcp-evidence-query/README.md)
* [`../crash-dump-mcp-server/README.md`](../crash-dump-mcp-server/README.md)

### Plans and decision history (kept in this tree)

* [`evidence-mcp-poc-plan.md`](evidence-mcp-poc-plan.md) — §1.1 documents the
  G1-G4 isolation guarantees called out above.
* [`rust-hybrid-migration-plan.md`](rust-hybrid-migration-plan.md) — the
  language-choice plan the C# sidecar implements.
* [`docs/decisions/`](docs/decisions/) — promoted review docs that shape the
  architecture (`rust-vs-csharp-spike-review.md`,
  `native-vs-xperf-parity-review.md`, `evidence-language-review.md`). See
  [`docs/decisions/README.md`](docs/decisions/README.md) for what each one
  decides.

### Staging (transient — promoted as decisions stabilize)

* `manager-log/improve-docs-dx-exploration.md` and
  `improve-llm-mcp-exploration.md` — the audits that drove this doc.
* `manager-log/VERDICT-csharp-wiring.md` — canonical state of the POC.
