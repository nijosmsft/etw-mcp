# Evidence MCP POC Plan

**Goal:** validate the **federation + shared evidence store** pattern
(Pattern E from the strategic review) on real data before committing to
it as the long-term architecture for a general Windows debugging MCP.

**Companion docs:**
- Strategic review (referenced in `rust-hybrid-migration-plan.md` v3 §1)
  established Pattern E as the most important missing layer.
- The earlier "what to actually do" recommendation outlined a 4-week
  wedge; this document is the executable version.

---

## 1. Goals and non-goals

### Goals
- Prove (or disprove) that the federation + evidence model answers
  cross-tool debugging questions the LLM cannot answer today.
- Produce a runnable 2-minute demo at the end of week 4 (`correlate_trace_and_dump`).
- Define the v1 entity model in a way that survives contact with real
  ETW + crash-dump data.
- Keep the per-MCP integration cost low (target: ~50 lines of changes
  per MCP).
- Sit *next to* existing parquet caches — do not replace anything.

### Non-goals
- Building the "real" orchestrator MCP. (The demo's
  `correlate_trace_and_dump` is intentionally a toy.)
- Federating more than 2 MCPs in this POC. (Just `etw-trace-analyzer`
  and `crash-dump-analyzer`.)
- Real-time / streaming correlation. (Offline-only for v1.)
- Multi-machine / global evidence store. (Per-machine scope.)
- Schema evolution machinery. (Greenfield schema; revisit after the
  pattern is validated.)
- A new programming language. (Python, alongside existing MCPs.)
- **Shipping anything to production users during the POC.** All work
  stays on feature branches; nothing merges to `main` of any MCP repo
  until the decision gate (§5) explicitly says "scale" AND a human
  approves a production rollout PR.

---

## 1.1 Production isolation guarantees

The production `etw-trace-analyzer` and `crash-dump-analyzer` MCPs are
**unaffected** by this POC. Four enforced guarantees:

### G1 — Separate repos for new code
- `wpr-mcp-evidence-store` — new repo, the library
- `wpr-mcp-evidence-query` — new repo, the demo MCP

Neither repo exists today; creating them cannot affect production.

### G2 — Worktrees + feature branches for MCP modifications
- `etw-trace-analyzer` wiring: worktree
  `..\wpr-mcp-server-evidence-wiring` on branch `feature/evidence-wiring`.
  The main checkout (`C:\git\wpr-mcp-server`) is never touched.
- `crash-dump-analyzer` wiring: separate clone or worktree on branch
  `feature/evidence-wiring`. Main branch never touched.

### G3 — Optional dependency with import guard
The `evidence-store` library is an **optional** dependency, never a
hard import. The integration module uses the pattern:

```python
# src/etw_analyzer/evidence_integration.py
try:
    from evidence_store import EvidenceStore
    _EVIDENCE_AVAILABLE = True
except ImportError:
    EvidenceStore = None
    _EVIDENCE_AVAILABLE = False


def register_entities_from_trace(trace: "TraceData") -> str | None:
    """Register entities; returns machine_id, or None if disabled."""
    if not _EVIDENCE_AVAILABLE:
        return None
    if not os.environ.get("WPR_MCP_EVIDENCE_PATH"):
        return None
    # ... actual registration logic
```

`_run_native_aggregators` calls this and ignores `None`. The library
is opt-in via `WPR_MCP_EVIDENCE_PATH` env var — without it, the
integration is a no-op even if the library is installed.

`pyproject.toml` adds `evidence-store` to a new **optional** extras
group, not the default deps:

```toml
[project.optional-dependencies]
evidence = ["evidence-store>=0.1,<0.2"]
```

Production users running `uv sync` get **no new behavior** unless they
explicitly run `uv sync --extra evidence` AND set
`WPR_MCP_EVIDENCE_PATH`.

### G4 — No merge to main during the POC
- `feature/evidence-wiring` branches stay unmerged for the duration of
  the POC.
- At end of week 4, decision is recorded; branches are tagged
  `evidence-poc-archive` regardless of outcome.
- **Production merge requires a separate, human-reviewed PR**, gated
  on the "scale" outcome from §5 and an explicit go-decision from the
  project owner.

These four guarantees together mean: **a production user running
`uv sync` from `main` during or after the POC sees zero behavior
change.** The POC can fail, succeed, or be abandoned without rollback
risk.

---

## 2. Strategic positioning

This POC is **the north-star wedge**. The Rust/C# sidecar work
(`rust-hybrid-migration-plan.md`) is tactical ETW acceleration; this
POC is what determines whether the broader debugging-MCP vision is
achievable.

**The two efforts are orthogonal and proceed in parallel.** Different
people can run them simultaneously without contention.

Decision authority at the end of week 4:
- **Demo works, integration cost was reasonable** → scale (federate
  `lablink`, then perfcounters, then registry/WMI; build the real
  evidence-query MCP).
- **Demo works but integration was rough** → simplify (one shared DB
  instead of per-MCP DBs, or thinner entity model); iterate one more
  month.
- **Demo doesn't feel useful** → kill (the strategic recommendation was
  wrong; double down on ETW analyzer and Rust/C# sidecar).

---

## 3. Architecture

### 3.1 Components

```
┌─────────────────────────┐         ┌─────────────────────────┐
│ etw-trace-analyzer MCP   │         │ crash-dump-analyzer MCP │
│ (existing)               │         │ (existing)              │
│                          │         │                         │
│  + evidence_writer       │         │  + evidence_writer      │
│    registers entities    │         │    registers entities   │
│    after load_trace      │         │    after analyze        │
└────────────┬─────────────┘         └────────────┬────────────┘
             │ writes                              │ writes
             ▼                                     ▼
    ┌─────────────────────────────────────────────────────────┐
    │  C:\evidence\<machine_id>\evidence.duckdb               │
    │  ─────────────────────────────────────────────          │
    │  entities:       Machine, Process, Thread,              │
    │                  Module, Driver, Service, NIC           │
    │  observations:   CrashFrame, CpuSample, DPC,            │
    │                  PacketDrop, ServiceFailure             │
    │  evidence:       (observation_id, source_kind,          │
    │                   source_path, source_locator)          │
    │  + DuckDB views over existing .etw-export-*\*.parquet   │
    └────────────────────────┬────────────────────────────────┘
                             │ reads (SQL)
                             ▼
    ┌─────────────────────────────────────────────────────────┐
    │ evidence-query MCP  (NEW, ~300 lines)                   │
    │   tools:                                                │
    │     - list_machines()                                    │
    │     - list_entities(machine_id, entity_type)             │
    │     - correlate_trace_and_dump(machine_id, trace_id,     │
    │                                 dump_id)  [DEMO]         │
    │     - sql(query)              [escape hatch]             │
    └─────────────────────────────────────────────────────────┘
                             ▲
                             │ calls
                             │
                       LLM (Claude / GPT)
```

### 3.2 Storage decisions

| Decision | Choice | Rationale |
|---|---|---|
| Storage engine | **DuckDB** | Can query existing parquets in place (no copy); has Python bindings; columnar; single-file embedded; MIT license |
| Database scope | **Per-machine** | A single DB holds ETW + dump + future WMI/perfcounter data for one host. Cross-machine correlation deferred. |
| DB file location | `C:\evidence\<machine_id>\evidence.duckdb` | Predictable path; one dir per investigated host |
| Concurrent writes | **One writer at a time** (DuckDB limitation) | Acceptable for POC; MCPs serialize via a file lock helper |
| Schema migrations | **Schema-version field per table** | Future-proofing; not exercised in v1 |
| Versioning | `evidence-store` library has a semver; DB has `schema_version` table | Standard pattern |

### 3.3 Producer model

Each MCP gains a small `evidence_writer.py` module:

```python
# In etw-trace-analyzer:
def _register_entities_after_load(trace: TraceData) -> None:
    machine_id = _derive_machine_id(trace)
    store = EvidenceStore.open(_evidence_path(machine_id))
    
    store.register_machine(
        machine_id=machine_id,
        hostname=trace.metadata.get("hostname"),
        os_build=trace.metadata.get("os_build"),
    )
    
    for row in trace.raw_csv.get("Image/Load", pd.DataFrame()).itertuples():
        store.register_module(
            machine_id=machine_id,
            name=row.FileName,
            version=row.Version,
            base_addr=row.ImageBase,
            source_kind="etl_row",
            source_path=str(trace.etl_path),
            source_locator=f"Image/Load@{row.TimeStamp}",
        )
    # ... similar for Process, Thread, NIC
```

Push model means each MCP owns its semantic model and writes opportunistically.

### 3.4 Identity strategy (the load-bearing decision)

For cross-tool correlation to work, entities from different sources must collapse into one identity. v1 rules:

| Entity | Identity tuple | Notes |
|---|---|---|
| `Machine` | `(hostname_lower)` | For v1; later add boot_id or BIOS UUID |
| `Process` | `(machine_id, pid, start_time)` | start_time disambiguates pid reuse |
| `Thread` | `(machine_id, pid, tid, start_time)` | same reasoning |
| `Module` | `(machine_id, name_lower, version)` | NOT keyed on base_addr (ASLR varies per load) |
| `ModuleLoad` | `(module_id, process_id, base_addr, load_time)` | Separate entity for per-process load instances |
| `Driver` | `(machine_id, service_name_lower)` | one per registered driver |
| `Service` | `(machine_id, name_lower)` | one per registered service |
| `NIC` | `(machine_id, friendly_name)` | could use MAC; document the choice |

Identity collisions are an open risk: document each collision as it surfaces during the POC and adjust the tuples in week 4 if needed.

### 3.5 Observation/evidence model

Every observation row carries:
- `observation_id` (uuid)
- `kind` (e.g. `"CpuSample"`, `"CrashFrame"`)
- `entity_id` (or list of related entity_ids)
- `timestamp_utc` (where applicable)
- `payload` (JSON column with kind-specific fields)
- Foreign key to `evidence` table with `(source_kind, source_path, source_locator)`

Source kinds in v1: `"etl_row"`, `"etl_aggregate"`, `"dump_module_list"`, `"dump_thread_stack"`.

---

## 4. Phases

### Phase 0 — Setup (~1 day, human or one agent)

Create the new repo or directory:

```powershell
# Option A: new repo (recommended for cleaner ownership)
gh repo create wpr-mcp-evidence-store --private
cd C:\git
git clone https://github.com/<user>/wpr-mcp-evidence-store
cd wpr-mcp-evidence-store
git checkout -b main
uv init --package
# Add deps: duckdb, pyarrow, pydantic

# Option B: sibling directory in wpr-mcp-server
cd C:\git\wpr-mcp-server
git checkout -b feature/evidence-store-poc
mkdir src/evidence_store
```

Recommend Option A — keeps the library independently versionable and
usable by multiple MCPs without coupling them through the wpr-mcp-server
repo.

### Phase 1 — Design doc + entity model (3 days, 1 person)

**Deliverable:** `docs/evidence-model.md` in the evidence-store repo.

Contents:
- The 7 v1 entity schemas (Machine, Process, Thread, Module, Driver,
  Service, NIC)
- Identity tuple rules (§3.4 above, with rationale)
- 4 observation schemas (CpuSample, CrashFrame, DPC, ServiceFailure)
  — these are what the demo needs; defer others
- Evidence record schema
- Two example questions the model must answer:
  1. "Show modules that appear in both this ETW trace and this crash
     dump."
  2. "For modules in #1, show CPU sample weight and faulting-stack
     presence side-by-side."
- Three example SQL queries that should be expressible
- Schema-evolution rule (additive only; column adds get a new version)

Get the doc reviewed via `review-broker` before any code. The entity
model is the load-bearing decision; iterate the doc until it's clean.

### Phase 2 — Library implementation (4 days, 1 person)

**Deliverable:** Installable Python package `evidence-store`.

Structure:
```
evidence-store/
├── pyproject.toml
├── src/evidence_store/
│   ├── __init__.py
│   ├── schema.py            # DuckDB DDL (CREATE TABLE for entities, observations, evidence)
│   ├── store.py             # EvidenceStore class (open, register_*, query, close)
│   ├── entities.py          # Typed pydantic dataclasses for each entity
│   ├── identifiers.py       # Identity-tuple → entity_id deterministic logic
│   ├── locking.py           # File-lock helper for concurrent-writer protection
│   └── views.py             # CREATE VIEW over parquet caches in the same dir
├── tests/
│   ├── test_entity_dedup.py # Same module from 2 tools → same entity_id
│   ├── test_concurrent_writers.py
│   ├── test_view_over_parquet.py
│   └── test_schema_round_trip.py
└── README.md
```

API surface (deliberately small):

```python
class EvidenceStore:
    @classmethod
    def open(cls, path: Path) -> "EvidenceStore": ...
    
    def register_machine(self, *, hostname: str, **kwargs) -> str: ...
    def register_process(self, *, machine_id: str, pid: int, start_time: int, **kwargs) -> str: ...
    def register_module(self, *, machine_id: str, name: str, version: str, **kwargs) -> str: ...
    # ... etc per entity
    
    def add_observation(self, *, kind: str, entity_ids: list[str], 
                        timestamp_utc: int, payload: dict, 
                        evidence: EvidenceRef) -> str: ...
    
    def query(self, sql: str) -> pyarrow.Table: ...
    def close(self) -> None: ...
```

Unit tests are mandatory (no MCP integration yet; just prove the library
behaves).

### Phase 3 — Wire two MCPs in PARALLEL (3 days each, 2 agents)

Both branches start from the same point: the published `evidence-store`
library from phase 2.

#### Phase 3A — Wire `etw-trace-analyzer`

**Worktree:** `C:\git\wpr-mcp-server-evidence-wiring`
**Branch:** `feature/evidence-wiring`

Diff scope (~100 lines):

1. Add `evidence-store` to **`[project.optional-dependencies]` extras
   group `evidence`** in `pyproject.toml` — NOT default deps. (Per G3.)
2. New file `src/etw_analyzer/evidence_integration.py`:
   - Import-guarded `try/except ImportError` block (per G3).
   - `register_entities_from_trace(trace: TraceData) -> str | None` —
     returns machine_id, or `None` when library is unavailable OR
     `WPR_MCP_EVIDENCE_PATH` is unset.
   - Reads from `trace.raw_csv["Image/Load"]`, `Process/DCStart`,
     `Process/Start`, `NIC` info from sysconfig.
3. Hook into `tools/trace_mgmt._run_native_aggregators` (or a
   dedicated post-aggregation step) to call
   `register_entities_from_trace` — call site treats `None` as
   no-op.
4. New MCP tool `get_entities(trace_id, entity_type, filter=None)` —
   returns rows from `evidence.duckdb`, or a friendly "evidence store
   not enabled" message when the library is unavailable.
5. Tests in `tests/test_evidence_integration.py` covering both code
   paths:
   - With `evidence-store` installed + `WPR_MCP_EVIDENCE_PATH` set:
     entities registered, `get_entities` works.
   - Without library OR without env var: load_trace still works, no
     errors, `get_entities` returns friendly message.

**Definition of done:**
- All new tests pass (both with-library and without-library code paths).
- Existing tests in `tests/` pass UNCHANGED — no regressions in the
  default install path.
- A `uv sync` (without `--extra evidence`) followed by
  `pytest tests/` succeeds and no test imports `evidence_store`.
- Manual smoke test documented in `tests/manual_evidence_smoke.md`.
- Commit is signed off.
- **Branch is NOT merged to main; see G4.**

#### Phase 3B — Wire `crash-dump-analyzer`

**Worktree:** `C:\git\<crash-dump-analyzer-repo>-evidence-wiring`
(separate repo per the existing MCP layout in `C:\git\CLAUDE.md`)
**Branch:** `feature/evidence-wiring`

Diff scope (~100 lines):

1. Add `evidence-store` to an **optional `evidence` extras group**,
   NOT default deps. (Per G3.)
2. New module that runs after `analyze` / `auto_configure_symbols`:
   - Import-guarded `try/except ImportError` block (per G3).
   - Reads the dump's module list (via the existing `get_modules`
     internal API).
   - Extracts crash frames from the bugcheck/exception path.
   - Registers `Machine` (hostname from dump header), `Module`,
     `ModuleLoad`, and `CrashFrame` observations.
   - No-op when library is unavailable OR `WPR_MCP_EVIDENCE_PATH` is
     unset.
3. Tests: synthetic dump or recorded fixture, covering both with- and
   without-library paths.

**Definition of done:**
- All new tests pass (both code paths).
- Existing tests pass UNCHANGED — no regressions in default install.
- A `uv sync` (without `--extra evidence`) followed by `pytest tests/`
  succeeds and no test imports `evidence_store`.
- Module identity for a known module (e.g. `ntoskrnl.exe`) matches
  what `etw-trace-analyzer` produces for the same module on the same
  machine (cross-MCP identity collapse — the key correctness test).
- Manual smoke test documented.
- Commit is signed off.
- **Branch is NOT merged to main; see G4.**

#### Why parallel

Both wiring jobs are independent — different MCPs, different repos,
same library API. Two agents (or one agent serially) can do them.
Sequential time: 6 days. Parallel time: 3 days. Choose based on
bandwidth.

### Phase 4 — Demo + evidence-query MCP (4 days, 1 person)

**Deliverable:** A new repo `wpr-mcp-evidence-query` with one
substantive tool.

Layout:
```
wpr-mcp-evidence-query/
├── src/evidence_query/
│   ├── __init__.py
│   ├── server.py            # FastMCP entry
│   ├── tools/
│   │   ├── list_machines.py
│   │   ├── list_entities.py
│   │   ├── correlate.py     # the demo
│   │   └── sql.py           # raw SQL escape hatch
├── tests/
└── README.md
```

The headline tool:

```python
@mcp.tool()
def correlate_trace_and_dump(
    machine_id: str,
) -> str:
    """For a given machine, join modules across ETW trace + crash dump.
    
    Returns a markdown table showing which modules were both CPU-hot
    in the trace and present in the crash, with faulting-stack annotation.
    """
    store = EvidenceStore.open(_evidence_path(machine_id))
    result = store.query("""
        SELECT
            m.name,
            m.version,
            COALESCE(cs.weight_sum, 0) AS etw_samples,
            (ml.module_id IS NOT NULL) AS in_dump,
            (cf.module_id IS NOT NULL) AS in_faulting_stack
        FROM Module m
        LEFT JOIN (
            SELECT module_id, SUM(weight) AS weight_sum
            FROM observations
            WHERE kind = 'CpuSample'
            GROUP BY module_id
        ) cs ON cs.module_id = m.entity_id
        LEFT JOIN ModuleLoad ml ON ml.module_id = m.entity_id
        LEFT JOIN (
            SELECT DISTINCT module_id FROM observations WHERE kind = 'CrashFrame'
        ) cf ON cf.module_id = m.entity_id
        WHERE m.machine_id = ?
        ORDER BY etw_samples DESC, in_faulting_stack DESC
    """, params=[machine_id])
    return _format_markdown_table(result)
```

### Phase 4 demo session (the success metric)

Run this verbatim. If the output is impressive, the POC succeeded:

```
# Step 1: load a trace from a real machine
> load_trace("C:\\traces\\flaky-vm-2026-05-28.etl", mode="auto")
trace_abc123def456 loaded.

# Step 2: load a crash dump from the same machine
> load_dump("C:\\dumps\\flaky-vm-MEMORY.DMP")
dump_def456abc789 loaded.

# Step 3: call the new evidence tool
> correlate_trace_and_dump(machine_id="flaky-vm")

| Module       | Version    | ETW samples | In dump | In faulting stack |
|--------------|------------|-------------|---------|-------------------|
| mlx5.sys     | 23.10.1234 | 1,200,000   | Yes     | Yes               |
| ntoskrnl.exe | 10.0.22621 | 800,000     | Yes     | Yes               |
| tcpip.sys    | 10.0.22621 | 400,000     | Yes     | No                |
| xdp.sys      | 1.3.0      | 200,000     | No      | No                |

# Step 4: LLM concludes
"mlx5.sys is the hottest module in the trace AND appears in the
crash's faulting stack — that's your suspect."
```

That table cannot be produced today without manual cross-referencing.
Producing it automatically is the north star in miniature.

---

## 5. Decision gate

End of week 4, ask:

1. **Does the demo's answer feel like the kind of cross-tool insight the
   north star demands?** (Cited, multi-source, actionable.)
2. **Was the per-MCP wiring cost (~80 lines, 3 days) sustainable to
   repeat for 5 more MCPs?**
3. **Did anything in the entity model (especially Module identity) break
   down under real data?**

Based on answers:

| Outcome | Next move |
|---|---|
| All three "yes" | **Scale.** Open a separate, human-reviewed PR per G4 to merge `feature/evidence-wiring` to `main` of each MCP repo. Federate `lablink` (system inventory: services, drivers, registry). Add perfcounter collector. Build the *real* evidence-query MCP with a planning layer. Month 2 plan documented at end of week 4. |
| Mostly yes, wiring rough | **Simplify.** Do NOT merge. Branches stay on `feature/evidence-wiring`. One shared evidence DB instead of per-machine; thinner entity model; iterate one more month before re-evaluating. |
| Demo answer felt thin | **Kill.** Do NOT merge. Tag branches as `evidence-poc-archive` and delete worktrees. Pattern E was wrong. Strategic recommendation reconsidered. Pivot to: deepen the ETW analyzer (finish Rust/C# sidecar), defer multi-tool work to a different design. |

The decision is recorded in `evidence-poc-decision.md` with the demo
output as evidence. **Regardless of outcome, production users see no
change until a separate "scale" PR lands** (per G4).

---

## 6. Coordination with the sidecar spike

If the team is also running the Rust vs C# spike
(`parallel-spike-execution-plan.md`) concurrently, the two efforts are
**orthogonal**:

| Resource | Sidecar spike | Evidence POC |
|---|---|---|
| Repo | `wpr-mcp-server` | New: `wpr-mcp-evidence-store`, `wpr-mcp-evidence-query` |
| Worktrees | `spike-rust`, `spike-csharp` | New worktree(s) for wiring branches |
| Dev time | 1-2 weeks | 4 weeks |
| Decision gate | End of spike week 2 | End of POC week 4 |
| Shared resource conflict | None (separate repos, separate branches) | None |

Both can run in parallel without contention. If only one dev is
available, do the evidence POC first — the strategic value is higher
(per the strategic review).

---

## 7. Risks

| Risk | Mitigation |
|---|---|
| Module identity collisions (same name, diff vendor) | Entity model includes version; if collisions still occur, add `(file_size_bytes, file_hash)` to the tuple |
| DuckDB single-writer blocks concurrent MCPs | File-lock helper serializes; long-term solution is one writer process or move to SQLite WAL |
| `Machine` identity unstable across reboots | v1 uses hostname; v2 adds BIOS UUID via WMI when `lablink` is federated |
| Entity model survives 2 MCPs but breaks at 5 | That's why the decision gate at week 4 exists — surface before scaling |
| Demo runs but feels underwhelming | Counter-test with more workloads (e.g. wait-chain across multiple processes); if the broader question set is also weak, kill the pattern |
| Crash-dump-analyzer doesn't expose module list / crash frame info via a stable API | Phase 0.2 prerequisite: read `crash-dump-analyzer` source first; if APIs are missing, add them on a feature branch before phase 3B |
| evidence-store dep version drift between consuming MCPs | Pin to exact version; bump deliberately |

---

## 8. Total wall-clock plan

| Day | Activity | Owner |
|---|---|---|
| 0 | Phase 0: repo setup, branches, worktrees | Human, ~2 hours |
| 1-3 | Phase 1: design doc + review-broker review | 1 person |
| 4-7 | Phase 2: evidence-store library + tests | 1 person |
| 8-10 | Phase 3A + 3B: wire two MCPs (parallel) | 2 agents (or 1 sequentially in 6 days) |
| 11-14 | Phase 4: evidence-query MCP + demo | 1 person |
| 15 | Decision meeting + record outcome | Human, ~1 day |

**Total calendar: 3-4 weeks.** Active human time: ~2.5 weeks. With one
parallel agent: ~3 weeks.

---

## 9. What's needed up front

### People
- 1 dev for phase 1, 2, 4 (the design + library + demo MCP).
- 2 agents (or 1 dev) for phase 3 wiring.

### Fixtures
- One real ETW trace from a lab VM (5–50 MB) — reuse what's available
  in the lab.
- One real crash dump from the same VM (kernel minidump or full dump).
- Critical: trace and dump must be from the **same machine** during the
  same incident window. If no such pair exists, capture one
  intentionally: run a stress workload + force a bugcheck (`!crash` in
  WinDbg or `notmyfault` for a controlled crash).

### Tooling
- DuckDB CLI for ad-hoc debugging
- `uv` (existing)
- Access to the `crash-dump-analyzer` MCP source (to add the
  `evidence_writer` wiring in phase 3B)
- `review-broker` MCP for design-doc review

### Pre-reads (for the implementing person/agent)
1. `rust-hybrid-migration-plan.md` v3 §1 (the strategic positioning
   passage that motivates this POC)
2. The earlier conversation about Pattern E (what the evidence model is
   and isn't)
3. `crash-dump-analyzer` MCP tool list (what it already exposes)
4. `wpr-mcp-server`'s `tools/trace_mgmt.py` (`_run_native_aggregators`
   is where the ETW hook lands)

---

## 10. Verbatim agent prompts for phase 3 (parallel wiring)

### Phase 3A prompt — Wire `etw-trace-analyzer`

```
You are wiring the wpr-mcp-server ETW trace analyzer into the new
evidence-store library so it registers entities (Machine, Process,
Module, NIC) after a trace is loaded.

WORKTREE: C:\git\wpr-mcp-server-evidence-wiring
BRANCH: feature/evidence-wiring
DO NOT TOUCH: any file outside src/etw_analyzer/, tests/, pyproject.toml

READ FIRST:
1. C:\git\wpr-mcp-evidence-store\docs\evidence-model.md  (entity model spec)
2. C:\git\wpr-mcp-evidence-store\src\evidence_store\store.py  (API to call)
3. C:\git\wpr-mcp-server\src\etw_analyzer\tools\trace_mgmt.py:_run_native_aggregators
   (the hook point)
4. C:\git\wpr-mcp-server\src\etw_analyzer\trace_state.py  (TraceData schema)

DELIVERABLE:
1. Add `evidence-store` to pyproject.toml.
2. New file src/etw_analyzer/evidence_integration.py with:
   - `register_entities_from_trace(trace: TraceData) -> str` returning machine_id
3. Hook into _run_native_aggregators (or post-aggregator step).
4. New MCP tool `get_entities(trace_id, entity_type, filter=None)` in a
   new tools/evidence.py file.
5. Tests in tests/test_evidence_integration.py covering:
   - Loaded trace produces expected Machine, Module entities
   - Re-loading same trace is idempotent (same entity_ids)
   - get_entities returns expected rows

DEFINITION OF DONE:
- All new tests pass
- Existing tests in tests/ still pass
- Manual smoke test documented in tests/manual_evidence_smoke.md
- Commit is signed off

WHEN BLOCKED:
- If trace.raw_csv doesn't have the expected field for an entity,
  document the gap and register a partial entity; do not block.
- If evidence-store API needs a missing helper, document the missing
  helper in a comment and skip that entity (the library agent will pick
  it up in a follow-up).

TIME BUDGET: 3 days.
```

### Phase 3B prompt — Wire `crash-dump-analyzer`

```
You are wiring the crash-dump-analyzer MCP into the new evidence-store
library so it registers entities (Machine, Module, ModuleLoad) and
observations (CrashFrame) after a dump is loaded.

REPO: C:\git\crash-dump-analyzer  (or wherever it lives)
BRANCH: feature/evidence-wiring
DO NOT TOUCH: any file outside src/, tests/, pyproject.toml

READ FIRST:
1. C:\git\wpr-mcp-evidence-store\docs\evidence-model.md  (entity model spec)
2. C:\git\wpr-mcp-evidence-store\src\evidence_store\store.py  (API to call)
3. The existing crash-dump-analyzer load_dump and analyze tools (find
   the hook point where module list + crash frame info is available)

DELIVERABLE:
1. Add `evidence-store` to deps.
2. New module: evidence_integration.py with:
   - register_entities_from_dump(dump_session) -> str returning machine_id
3. Hook into the load_dump/analyze flow.
4. Tests covering:
   - A known fixture dump produces expected Module + CrashFrame entries
   - Re-analyzing same dump is idempotent
   - Module identity matches what etw-trace-analyzer produces for the
     same module (test this via a shared fixture)

DEFINITION OF DONE:
- All new tests pass
- Existing tests still pass
- A manual smoke test documented
- Commit is signed off

WHEN BLOCKED:
- If the dump session API doesn't expose module list cleanly, use the
  cdb `lm` command output or whatever internal API exists.
- If you need a new tool added to crash-dump-analyzer to expose the
  data, add it; document the change in the PR description.

TIME BUDGET: 3 days.
```

Dispatch both via `task` tool with `mode="background"`, both with
`general-purpose` agent type, both using `claude-opus` or `gpt-5.5`.

---

## 11. Cross-references

- Strategic review (Pattern E): referenced in `rust-hybrid-migration-plan.md` v3 §1
- Parallel spike plan (orthogonal effort): `parallel-spike-execution-plan.md`
- Existing MCPs referenced: `crash-dump-analyzer`, `lablink`,
  `etw-trace-analyzer`
- Parent project conventions: `C:\git\CLAUDE.md`
- ETW project conventions: `C:\git\wpr-mcp-server\CLAUDE.md`
