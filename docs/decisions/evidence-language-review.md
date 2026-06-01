# Evidence language-choice review

**Scope:** `wpr-mcp-evidence-store` library and `wpr-mcp-evidence-query` MCP server.  
**Decision lens:** strategic language choice, not code review.  
**Weights:** HIGH=3, MEDIUM=2, LOW=1. Maximum weighted score = 100.

## §1. Workload characterization

### Write path: `evidence_store.register_*`

The write-side library is small and synchronous. `EvidenceStore.open()` takes a sidecar file lock, opens a writable DuckDB connection, applies schema DDL, records/checks `schema_version`, then holds the writer lock until `close()` (`store.py:85-117`, `locking.py:33-82`). The public write API is one `INSERT ... ON CONFLICT DO NOTHING` per entity registration (`store.py:190-357`). `register_module(..., source=...)` can additionally write one `ModuleSeen` observation (`store.py:255-292`), but the current ETW producer does **not** pass `source`, so it is not on today’s hot path.

Current ETW producer integration calls the library by **Python import**, not subprocess/IPC: guarded import of `EvidenceStore` (`evidence_integration.py:40-48`), `EvidenceStore.open(path)` (`:255-257`), then:

- 1 `register_machine` call per trace (`:258-260`)
- 1 `register_module` call per distinct `(module name, tds+size)` from `Image/Load` and `Image/DCStart` (`:135-176`, `:262-269`)
- 1 `register_process` call per distinct `(pid, start_time)` from `process` or `_native_process_events` (`:179-215`, `:274-282`)
- 0 observations today from ETW registration; `source_path` is explicitly unused/reserved (`:287-292`)

Therefore, per `load_trace`, today’s evidence writes are:

`1 + distinct_modules(Image/Load ∪ Image/DCStart) + distinct_processes(process/_native_process_events)` DuckDB `INSERT` statements, plus open-time schema setup (`13` `CREATE TABLE/INDEX IF NOT EXISTS` statements in `schema.ALL_DDL`, `schema.py:158-172`) and a schema-version read/insert/check (`store.py:157-177`). The exact `N` is trace-dependent and is not measured in code; synthetic tests prove duplicate Image/Load rows collapse to two module rows (`test_evidence_integration.py:150-176`).

Latency budget: evidence registration is hooked at the **end** of `_run_native_aggregators`, after CPU sampling, timeline, DPC/ISR, stacks, sysconfig/process/disk/tracestats have already been persisted (`trace_mgmt.py:1080-1143`) and immediately before the dumper marks itself ready (`trace_mgmt.py:1145-1155`, `:820-822`). `load_trace` is already a user-visible, expensive operation; project guidance calls re-export “30-180s” (`wpr-mcp-server/CLAUDE.md:124-127`). Evidence registration should therefore be low single-digit seconds on realistic traces, and ideally sub-second for hundreds/thousands of modules/processes. The code does not currently time this hook; add measurement before using performance as a migration reason.

Concurrency: DuckDB’s single-writer limitation is accepted by design (`evidence-mcp-poc-plan.md:184-190`). The library adds a `portalocker` sidecar `.lock` file so a second writer waits instead of failing (`README.md:21-23`, `locking.py:1-18`). Realistic contention is expected to be rare because writes happen once per producer operation (`load_trace` / dump analysis), not continuously. If ETW and dump producers analyze the same machine simultaneously, contention lasts for the entity-registration window, not for the entire trace analysis.

### Read path: `evidence_query` tools

`evidence-query` is read-side only by default. Each tool call opens a fresh DuckDB connection with `read_only=True` (`state.py:79-98`), so many LLM/tool calls can read concurrently without the writer lock. It does **not** import `evidence-store`; the pyproject explicitly says the peer library is intentionally absent and the MCP opens DuckDB directly (`pyproject.toml:31-40`, `README.md:106-115`).

Query shapes:

- `list_machines()` is enumeration plus metadata counts: list directories, then `COUNT(*)` over entity tables and a `Machine LIMIT 1` lookup per DB (`list_machines.py:36-87`). Result size is one row per machine DB.
- `list_entities()` is table enumeration with optional `machine_id` filter and `LOWER(name_col) LIKE LOWER(?)`, capped by `max_rows + 1` (`list_entities.py:61-123`). Default max is 200 rows.
- `correlate_trace_and_dump()` is the only cross-source join/aggregation: `Module` left-joined to aggregated `CpuSample` weights, distinct `ModuleLoad`, and distinct `CrashFrame`, filtered to modules with at least one signal and ordered by ETW weight/faulting-stack/name (`correlate.py:48-73`). Test fixture returns the four-row demo table exactly (`test_correlate_demo.py:13-39`).
- `sql()` is an escape hatch: one statement only, read-only denylist, wraps the query in `SELECT * FROM (...) LIMIT 1001`, then formats at most 1000 rows (`sql.py:36-118`).

Important schema observation: `evidence-query` currently targets the demo schema in its tests (`ModuleLoad` table; `observations.module_id`, `weight`, etc., `tests/conftest.py:28-104`). `evidence-store` v1 instead has `observation_entities` and `payload_json`, and no `ModuleLoad` table (`schema.py:115-143`). That is an interop/schema-contract gap, not a language problem. Fixing the schema contract is higher priority than moving languages.

### Schema surface

`evidence-store` schema is simple: 7 entity tables (`Machine`, `Process`, `Thread`, `Module`, `Driver`, `Service`, `NIC`), 3 evidence/observation tables (`evidence`, `observations`, `observation_entities`), 2 indexes, and 1 `schema_version` table (`schema.py:28-172`). Joins are ordinary primary-key/foreign-key joins and observation-to-entity many-to-many joins (`store.py:455-517`). There are **no migrations** today; schema-version mismatch raises `SchemaError` (`store.py:171-176`, `README.md:113-115`). Tests enforce schema creation/idempotence/mismatch behavior (`test_schema.py:24-65`).

### Interop boundary

- Producer side: direct Python import of `evidence_store` (`evidence_integration.py:40-48`, `:255-257`).
- Query side: direct DuckDB opens, no `evidence_store` dependency (`state.py:23-24`, `pyproject.toml:31-40`).
- Cross-tool identity: UUIDv5 over stable identity tuple serialization with per-kind namespaces (`identifiers.py:7-24`, `:36-50`, `:57-100`). Current ETW identity uses module `version = "tds=<TimeDateStamp>;size=<ImageSize>"` (`evidence_integration.py:135-176`), and tests lock this down against the crash-dump side (`test_cross_tool_identity.py:1-15`, `:36-46`, `:73-98`).

### Cross-language ambition

The POC plan explicitly chose Python as a non-goal for introducing a new language (`evidence-mcp-poc-plan.md:27-37`) and the two current producer MCPs are Python/FastMCP (`wpr-mcp-server/CLAUDE.md:5-8`; crash dump app imports `FastMCP`, `crash_analyzer/app.py:1-20`). However, the strategic federation vision is polyglot: future producers may include a Rust XDP collector, Go telemetry agent, or C++ DPC profiler. If that future is real, the durable contract cannot be “import this Python package”; it must be the DuckDB schema, identity-hash spec, and conformance tests. That does not require migrating the POC library today.

Validation run: `evidence-store` passed 33 tests with 91.70% coverage; `evidence-query` passed 38 tests.

## §2. Per-language scoring matrix

| Language | Criterion | Weight | Score | Weighted | Justification |
|---|---|---:|---:|---:|---|
| Python | Cross-language reach | 3 | 2 | 6 | Excellent for current producers, but non-Python producers cannot import it directly; the DuckDB file is the real cross-language seam. |
| Python | Producer-side integration cost | 3 | 5 | 15 | Current ETW and crash MCPs are Python/FastMCP; integration is a guarded import plus direct calls. |
| Python | MCP-server ergonomics | 3 | 5 | 15 | FastMCP is already used by both producer MCPs and `evidence-query`. |
| Python | DuckDB driver maturity | 2 | 5 | 10 | Python DuckDB/Arrow/Pandas path is first-class and already implemented. |
| Python | Identity-hash determinism | 2 | 4 | 8 | UUIDv5 is deterministic, but cross-language compatibility needs a spec/test vector. |
| Python | Pydantic vs equivalents | 2 | 5 | 10 | Pydantic handles source-reference validation with minimal code. |
| Python | Deployment | 2 | 5 | 10 | Existing MCP deployment already requires Python/uv; no extra runtime. |
| Python | File-lock behavior | 1 | 4 | 4 | `portalocker` covers Windows/POSIX; sufficient for POC. |
| Python | Tests + tooling | 1 | 5 | 5 | Pytest/coverage/pyright are already green and productive. |
| Python | Hireability/community | 1 | 5 | 5 | Widest contributor pool. |
| **Python total** |  |  |  | **88** |  |
| Rust | Cross-language reach | 3 | 4 | 12 | Strong for native SDK/CLI/C ABI possibilities, but every non-Rust language still needs bindings or IPC. |
| Rust | Producer-side integration cost | 3 | 2 | 6 | Current Python producers would need PyO3, ctypes, or subprocess/IPC. |
| Rust | MCP-server ergonomics | 3 | 3 | 9 | `rmcp` exists, but Python FastMCP is more mature here. |
| Rust | DuckDB driver maturity | 2 | 4 | 8 | Good bindings exist, less frictionless than Python/C++. |
| Rust | Identity-hash determinism | 2 | 5 | 10 | Easy to make byte-exact with UUID/SHA crates and golden vectors. |
| Rust | Pydantic vs equivalents | 2 | 5 | 10 | Serde/types are excellent for schema validation. |
| Rust | Deployment | 2 | 4 | 8 | Single binary is attractive; Python bindings/wheels add complexity. |
| Rust | File-lock behavior | 1 | 5 | 5 | Straightforward crates/Win32 APIs. |
| Rust | Tests + tooling | 1 | 4 | 4 | Strong, but slower iteration than pytest for this POC. |
| Rust | Hireability/community | 1 | 3 | 3 | Smaller pool for this Windows-debugging team than Python/C#. |
| **Rust total** |  |  |  | **75** |  |
| Go | Cross-language reach | 3 | 4 | 12 | Excellent standalone agents/CLI; as a shared embedded library it still needs C ABI or IPC. |
| Go | Producer-side integration cost | 3 | 2 | 6 | Python producers would call a binary/service, not import naturally. |
| Go | MCP-server ergonomics | 3 | 3 | 9 | Feasible MCP server, but not as ergonomic/mature as FastMCP here. |
| Go | DuckDB driver maturity | 2 | 4 | 8 | Usable drivers, not as first-class as Python/C++. |
| Go | Identity-hash determinism | 2 | 5 | 10 | Trivial with standard crypto/uuid packages. |
| Go | Pydantic vs equivalents | 2 | 3 | 6 | Struct validation exists but is less expressive than Pydantic/Serde. |
| Go | Deployment | 2 | 5 | 10 | Static-ish single binary is excellent. |
| Go | File-lock behavior | 1 | 5 | 5 | Straightforward. |
| Go | Tests + tooling | 1 | 4 | 4 | Good standard tooling. |
| Go | Hireability/community | 1 | 4 | 4 | Broad, especially for agents/telemetry. |
| **Go total** |  |  |  | **74** |  |
| C# | Cross-language reach | 3 | 3 | 9 | Strong in .NET/Windows; Python/Go/C++ still need IPC/COM/pythonnet/C ABI. |
| C# | Producer-side integration cost | 3 | 2 | 6 | Current Python producers do not naturally embed .NET. |
| C# | MCP-server ergonomics | 3 | 3 | 9 | .NET MCP exists, but the project is already FastMCP-centric. |
| C# | DuckDB driver maturity | 2 | 4 | 8 | Good enough; Python/C++ are more direct. |
| C# | Identity-hash determinism | 2 | 5 | 10 | Straightforward. |
| C# | Pydantic vs equivalents | 2 | 4 | 8 | Records/DataAnnotations/source generators are solid. |
| C# | Deployment | 2 | 3 | 6 | Self-contained .NET works but adds runtime/package size. |
| C# | File-lock behavior | 1 | 5 | 5 | Windows file locking is first-class. |
| C# | Tests + tooling | 1 | 4 | 4 | Strong xUnit/NUnit/MSTest ecosystem. |
| C# | Hireability/community | 1 | 4 | 4 | Strong Windows/debugging community. |
| **C# total** |  |  |  | **69** |  |
| C++ | Cross-language reach | 3 | 5 | 15 | Best raw ABI reach and DuckDB-native alignment. |
| C++ | Producer-side integration cost | 3 | 1 | 3 | Highest cost for current Python MCPs; binding surface must be hand-designed. |
| C++ | MCP-server ergonomics | 3 | 2 | 6 | Possible but least attractive for MCP server implementation. |
| C++ | DuckDB driver maturity | 2 | 5 | 10 | DuckDB itself is C++; native API is first-class. |
| C++ | Identity-hash determinism | 2 | 5 | 10 | Trivial. |
| C++ | Pydantic vs equivalents | 2 | 2 | 4 | Validation/error ergonomics are much worse for this schema-heavy API. |
| C++ | Deployment | 2 | 3 | 6 | Native DLL/EXE is deployable but ABI/runtime/signing complexity rises. |
| C++ | File-lock behavior | 1 | 5 | 5 | Straightforward Win32/POSIX APIs. |
| C++ | Tests + tooling | 1 | 3 | 3 | Good but slower/heavier than pytest. |
| C++ | Hireability/community | 1 | 2 | 2 | Good systems pool, weaker for rapid MCP/LLM-facing iteration. |
| **C++ total** |  |  |  | **64** |  |

## §3. Per-language strengths and weaknesses

### Python

Python’s main strength is integration gravity. The existing ETW and crash-dump producer MCPs are Python/FastMCP, the current producer hook imports `EvidenceStore` directly, and the query MCP is already implemented in the same style. For the actual workload — tens to thousands of metadata inserts after a 30-180s trace load, plus small read-side markdown queries — Python is not the bottleneck. The tests are already strong for a POC: 33 store tests at 91.70% coverage and 38 query tests.

Python’s weakness is cross-language reach. A Rust XDP collector or Go telemetry agent should not have to embed Python just to write a `Machine` or `Module` row. If the project treats `evidence-store` the package as the canonical API, Python becomes strategic friction. The mitigation is not necessarily “rewrite in Rust”; it is to make the DuckDB schema, identity derivation, and conformance suite canonical, with Python as the first SDK.

### Rust

Rust is the strongest alternative for a future native evidence-store core. It gives excellent deterministic serialization, schema validation through Serde, safe concurrency primitives, low deployment overhead as a CLI/static binary, and a credible path to Python bindings via PyO3. If the future includes high-volume non-Python producers, a Rust writer library plus a small C ABI/CLI could become a shared implementation instead of reimplementing identity logic in every language.

Rust is a bad near-term fit for `evidence-query` and a costly near-term fit for the existing Python producers. The value of the current library is mostly thin DuckDB DDL/INSERTs plus identity derivation; Rust would add FFI/wheel/ABI complexity before the schema contract is even stable. It also would not automatically solve the query MCP’s current schema mismatch with the library.

### Go

Go is attractive for standalone telemetry producers: simple deployment, good concurrency, broad contributor base, and straightforward DuckDB/file-lock/hash implementation. If the future producer is a Go agent, a Go-native evidence writer would be easy to maintain and distribute. A Go CLI writer could also serve other languages through subprocess invocation.

Go is less compelling as the central shared library. Python producers would still cross an IPC/FFI boundary, Go validation ergonomics are weaker than Pydantic/Serde, and MCP server ergonomics do not beat FastMCP for this repo. Go is a good producer language, not the best language for this POC’s shared library or query server.

## §4. The cross-language reach question

This is the load-bearing axis. My position: **the long-term federation should assume polyglot producers**, but the **canonical contract should be language-neutral**, not “the library must be native now.” The evidence store is a single DuckDB file with deterministic IDs; that is inherently language-neutral if specified precisely. The current Python package should be treated as the reference implementation and current Python SDK, not as the only blessed way to write evidence.

If the project commits that all producers for the next 12 months will be Python MCPs, Python wins by default: lowest integration cost, best MCP ergonomics, no extra runtime. If the project expects non-Python producers to ship in the next 12 months, Python loses points as a universal library — but the right first move is conformance: golden identity vectors, schema DDL tests, and a documented SQL write contract. Migrate only when the first non-Python producer has a concrete integration requirement.

## §5. The hybrid option

A Rust core with Python bindings could buy a single implementation for identity derivation, schema management, and writes, while preserving Python import ergonomics for the existing MCPs. The best shape would be `evidence-store-core` in Rust, exposed as: (1) a Python wheel via PyO3, (2) a small CLI for any language, and eventually (3) optional C ABI if embedding is required. This could reduce drift once non-Python producers arrive.

The cost is substantial: Windows wheels, PyO3 build/release pipeline, DuckDB native dependency packaging, Python/Rust error mapping, binding tests, and a second runtime/toolchain in two producer MCPs. It also only helps if the schema is stable. Today, `evidence-query` and `evidence-store` disagree on the demo schema, so a hybrid core would freeze the wrong thing unless the schema contract is fixed first. C++ with Python bindings offers wider ABI reach but far worse safety/ergonomics. C# with pythonnet/COM is Windows-friendly but less polyglot than Rust+CLI and adds .NET deployment.

## §6. Recommendation

### `evidence-store` library

**Decision: keep Python for the POC and near-term productionization; do not migrate yet. Confidence: 80%.**

Rationale: current producers are Python, current workload is light metadata writes after expensive trace/dump operations, DuckDB/PyArrow/Pydantic are mature, and tests are healthy. A rewrite would not solve the biggest current risk: schema-contract drift between writer and query. However, change the strategic framing: Python is the reference SDK, while the durable contract is the DuckDB schema + identity spec + conformance tests.

Dissent/confidence caveat: if a non-Python producer is committed for delivery in the next 1-2 quarters and must write evidence in-process, lower confidence to ~55% and spike a Rust core/CLI immediately.

### `evidence-query` MCP server

**Decision: keep Python. Confidence: 92%.**

Rationale: this is an MCP server with four markdown-returning tools, small result sets, read-only DuckDB opens, and direct alignment with FastMCP. Rust/Go/C#/C++ provide no meaningful benefit for the current query shapes. Even if the library later gets a Rust core, the MCP server should remain Python unless the whole MCP ecosystem moves.

### Should the two repos differ?

Not now. Keep both Python. In a later polyglot phase, they may differ: `evidence-store` could become a Rust core with Python bindings/CLI while `evidence-query` remains Python/FastMCP.

## §7. If we were to migrate — minimum viable spike

Do **not** execute this now. Run it only if a committed non-Python producer appears or if Python registration time becomes measurable user pain.

### Spike: Rust evidence-store core with Python binding and CLI

**Time budget:** 3-5 engineering days.

**Decision harness:**

1. Define a language-neutral conformance fixture:
   - Golden identity vectors for every entity kind, including edge cases for case-folding and `None`/empty rejection.
   - Golden DuckDB produced by the current Python library for Machine, Module, Process, Thread, Driver, Service, NIC, evidence, observations, and observation_entities.
   - A fixed ETW-like input with duplicate Image/Load rows and process rows.
2. Implement minimum Rust core:
   - `derive_entity_id` exactly compatible with Python UUIDv5 serialization.
   - `open`, `register_machine`, `register_module`, `register_process`, `add_observation`.
   - Sidecar writer lock compatible with the Python `.lock` file convention.
   - Python binding or CLI wrapper sufficient for the ETW integration hook.
3. Oracle:
   - Existing 33 `evidence-store` tests pass through Python binding, or an equivalent conformance suite proves byte-identical DB contents.
   - Existing 38 `evidence-query` tests pass against DBs written by both Python and Rust writers after the schema mismatch is resolved.
   - Two concurrent writer processes serialize exactly as today.
   - Registration latency measured on a realistic trace is no worse than Python by >30%, or absolute overhead remains <1s for 10k entity rows.
4. Report:
   - LOC by category: identity, schema, DuckDB, lock, Python binding/CLI, tests.
   - Package size and install steps on a fresh Windows machine.
   - Failure behavior: lock timeout, schema mismatch, malformed identity input, DuckDB open failure.

**Pick Rust/hybrid if:** it preserves Python import ergonomics, proves byte-identical identity/schema behavior, and materially improves non-Python producer integration without increasing deployment fragility.  
**Reject migration if:** binding/packaging dominates the implementation, schema drift remains unresolved, or the only benefit is theoretical cross-language reach.

## §8. Counter-arguments and dissent

A thoughtful reviewer against “keep Python” would say: the entire point of federation is cross-tool/cross-language evidence. If the team waits until non-Python producers exist, every producer may implement its own subtly different identity hashing and schema writes. The safe strategic move is to centralize identity and writes in a native, language-neutral core now, before multiple Python-specific APIs become entrenched. Rust would force a clean contract, reduce future drift, and avoid Python runtime dependencies in agents that might run on constrained systems.

That critique is valid. My response is sequencing: the current schema is not yet stable, and the query MCP already exposes drift from the writer schema. Migrating now risks hardening an immature contract. The stronger near-term move is to write the conformance spec and golden vectors immediately. If those are in place, future Rust/Go/C++ producers can either call a shared CLI or implement against tests without needing a premature rewrite.

A reviewer against “keep evidence-query Python” would argue that if the store core becomes Rust/Go/C#, the query server should follow to avoid a polyglot stack. I disagree: MCP ergonomics and LLM-facing markdown/tool descriptions are the dominant concerns for `evidence-query`, not raw execution speed. A Python query MCP over a language-neutral DuckDB file is an acceptable and clean split.

## §9. Decision criteria for the human reviewer

- Prefer **Python for both** if the next 12 months are mostly Python MCP producers, POC iteration speed matters, and evidence writes remain post-processing metadata registration.
- Prefer **Python query + Rust/hybrid store** if a non-Python producer is committed soon and must write evidence without spawning Python.
- Prefer **Go writer SDK/CLI** if the first major non-Python producer is a Go telemetry agent and subprocess/CLI integration is acceptable.
- Prefer **C#** only if the evidence layer becomes tightly coupled to Windows diagnostics APIs/TraceEvent/ClrMD rather than plain DuckDB writes.
- Prefer **C++** only if a stable C ABI is mandatory and the team accepts higher memory-safety/API-maintenance cost.
- Before any migration, require: schema alignment between store/query, golden identity vectors, cross-language conformance tests, and measured evidence-registration latency from real traces.
