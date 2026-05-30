# Parallel Rust + C# Spike Execution Plan

**Goal:** run the Rust and C# ETW sidecar spikes (per
`rust-hybrid-migration-plan.md` v3 §2) in parallel using two coding
agents in isolated git worktrees, then decide between languages from
their harness reports.

**Companion docs:**
- `rust-hybrid-migration-plan.md` — v3, the umbrella plan
- `rust-vs-csharp-spike-review.md` — the decision criteria (§7) and
  spike scope (§2 of v3 plan)

---

## 1. Topology

```
wpr-mcp-server/                     ← main repo (existing checkout)
  ├── main                          (branch, untouched)
  └── feature/spike-shared          (branch, NEW)
      ├── tests/fixtures/spike-multi-provider/spike-multi-provider.etl
      ├── tests/fixtures/spike-multi-provider/oracle/                    ← Python native baseline
      ├── tests/tools/spike_harness.py                                    ← shared harness
      ├── docs/spike-contract.md                                          ← exact JSON/parquet contract
      └── (existing files unchanged)

../wpr-mcp-server-spike-rust/        ← worktree, branch: feature/spike-rust
  └── (everything from spike-shared, plus...)
      └── rust/                                                            ← Rust sidecar workspace
          ├── Cargo.toml
          ├── crates/wpr-mcp-extract/
          └── target/release/wpr-mcp-extract.exe
      └── spike-results/rust-report.json

../wpr-mcp-server-spike-csharp/      ← worktree, branch: feature/spike-csharp
  └── (everything from spike-shared, plus...)
      └── csharp/                                                          ← C# sidecar solution
          ├── WprMcp.sln
          ├── src/WprMcp.Extract/
          └── publish/win-x64/wpr-mcp-extract.exe
      └── spike-results/csharp-report.json
```

**Why worktrees:** both agents see the same fixture ETL (deduped via
`.git/objects` shared store), the same oracle output, and the same
harness. They cannot collide on Rust vs C# subdirectories or branches.

---

## 2. Phase 0 — Shared setup (human, ~3 days)

Done by a human (or one setup agent) before either spike agent runs.
Commits land on `feature/spike-shared`.

### 2.1 Branches and worktrees

```powershell
# From the existing checkout root (C:\git\wpr-mcp-server)
cd C:\git\wpr-mcp-server
git checkout -b feature/spike-shared main
git push -u origin feature/spike-shared

# Create the two child branches (no work yet)
git branch feature/spike-rust feature/spike-shared
git branch feature/spike-csharp feature/spike-shared

# Create worktrees in sibling directories
git worktree add ..\wpr-mcp-server-spike-rust   feature/spike-rust
git worktree add ..\wpr-mcp-server-spike-csharp feature/spike-csharp
```

### 2.2 Capture the fixture ETL

On a lab VM with NIC, run a 60-second mixed workload while WPR captures
using `udp-perf/scripts/networking.wprp`. Workload includes:

- 1 HTTP echo server + 5 clients (covers HttpService)
- 1 QUIC echo server + 5 clients (covers MsQuic)
- 1 UDP echo server + 5 clients (covers UdpIp/Recv/Send)
- 1 firewall rule blocking a UDP port + clients sending to it
  (covers `NdisDrop` — **required** for parity gap #1 regression test)
- CPU pegged on a worker (covers SampledProfile + StackWalk)
- A few file writes (covers DiskIo)

Target ETL size: 5–20 MB. Save to
`tests/fixtures/spike-multi-provider/spike-multi-provider.etl`.

Commit via Git LFS (or download URL + SHA256 if LFS unavailable).
Document the capture command, OS build, and date in
`tests/fixtures/spike-multi-provider/NOTES.md`.

### 2.3 Generate the oracle

```powershell
$env:WPR_MCP_MODE = "native"
uv run python -m etw_analyzer.tools.dump_fixture_oracle `
    --etl tests/fixtures/spike-multi-provider/spike-multi-provider.etl `
    --out tests/fixtures/spike-multi-provider/oracle/
```

Writes per-event-class parquet, `_native_extract_stats.json`, and
symbol resolution results to `oracle/`. ~30-line helper script — write
it as part of phase 0 if it doesn't exist (`dump_fixture_oracle` is new).

### 2.4 Build the spike harness

`tests/tools/spike_harness.py` per `rust-hybrid-migration-plan.md` v3
§12. ~200 lines. Takes a sidecar binary + ETL + oracle directory,
returns a JSON report comparing them.

### 2.5 Write the spike contract document

`docs/spike-contract.md` — the canonical input/output spec both agents
target. Contents:

- Exact `request.json` schema (mirrors `native/worker.py:23-86`)
- Exact JSONL stdout protocol (heartbeat/result types)
- Exact parquet output paths and schemas per `native/schemas.py`
- Exact `wpr-mcp-cache-manifest.json` shape with `producer` field
- Exact `native-event-store-manifest.json` shape
- The 8 required event classes (SampledProfile, StackWalk, CSwitch,
  ReadyThread, TcpIp/Recv, AFD/Recv, NdisDrop, SystemConfig)
- The panic/exception negative-test requirement
- Definition of done

This is what each spike agent reads as its source-of-truth.

### 2.6 Commit and propagate

```powershell
git checkout feature/spike-shared
git add tests/fixtures/spike-multi-provider/ tests/tools/spike_harness.py docs/spike-contract.md
git commit -s -m "spike: shared infrastructure (fixture, oracle, harness, contract)"
git push

# Propagate shared setup to both spike branches
git checkout feature/spike-rust
git merge --ff-only feature/spike-shared
git push -u origin feature/spike-rust

git checkout feature/spike-csharp
git merge --ff-only feature/spike-shared
git push -u origin feature/spike-csharp
```

Now both worktrees have the fixture, oracle, harness, and contract.

---

## 3. Phase 1 — Parallel spike execution (~1 week)

Two agents work simultaneously, each in their own worktree, each on
their own branch.

### 3.1 Agent A — Rust spike

**Worktree:** `C:\git\wpr-mcp-server-spike-rust`
**Branch:** `feature/spike-rust`
**Runtime:** `general-purpose` agent, Opus or GPT-5.5,
**`mode="background"`**.
**Expected duration:** 4–5 calendar days.
**Definition of done:** `spike-results/rust-report.json` committed and
pushed.

#### Verbatim prompt for Agent A

```
You are implementing the Rust half of a parallel spike to choose between
Rust and C# as the native ETW sidecar language for the wpr-mcp-server
project.

YOUR WORKTREE: C:\git\wpr-mcp-server-spike-rust
YOUR BRANCH: feature/spike-rust
DO NOT TOUCH: any file outside the `rust/` subdirectory, except
`spike-results/rust-report.json` which is your only output.

READ FIRST (in order):
1. C:\git\wpr-mcp-server-spike-rust\rust-hybrid-migration-plan.md
   (especially §2, §5, §6, §9, §11 phase 0)
2. C:\git\wpr-mcp-server-spike-rust\docs\spike-contract.md
   (the contract you must implement)
3. C:\git\wpr-mcp-server-spike-rust\src\etw_analyzer\native\schemas.py
   (the parquet schemas you must emit)
4. C:\git\wpr-mcp-server-spike-rust\src\etw_analyzer\native\cache.py
   (the cache manifest you must write)
5. C:\git\wpr-mcp-server-spike-rust\tests\tools\spike_harness.py
   (the measurement tool you will be scored against)

DELIVERABLE: a Rust binary at
`rust/target/release/wpr-mcp-extract.exe` that:
- Reads `--request request.json` per the contract
- Opens the fixture ETL via `windows-rs` OpenTraceW/ProcessTrace
- Decodes 8 event classes: SampledProfile, StackWalk, CSwitch,
  ReadyThread, TcpIp/Recv, AFD/Recv, NdisDrop, SystemConfig
- Pairs StackWalk events with their target events via QPC timestamp
- Loads symbols via dbghelp (wrap with windows-rs FFI)
- Writes Layer 1 parquets per native/schemas.py byte-for-byte
- Writes wpr-mcp-cache-manifest.json with producer="rust"
- Writes native-event-store-manifest.json
- Emits JSONL heartbeat + result on stdout
- Wraps every callback in std::panic::catch_unwind (NON-NEGOTIABLE per
  v3 plan §10)
- Handles a deliberate panic in the callback cleanly (emit
  failure_kind="rust_panic", exit cleanly)

SCOPE LIMITS:
- 8 event classes only; do NOT try to cover all 25+ canonical classes
- Use raw `windows-rs` OR `ferrisetw` — decide based on which gives
  cleaner code; document the choice in `rust/README.md`
- Cargo workspace layout per v3 plan §8 (4 crates max)
- Use `arrow` and `parquet` crates; do NOT add `polars`

TESTING:
- Unit tests in cargo for each decoder; mirror existing
  `tests/native/test_mof_*.py` cases via shared `.bin` fixtures
- Integration test: run the binary against the fixture, validate output
  parses with pyarrow

MEASUREMENT (THE OUTPUT YOU COMMIT):
After the binary is built and the integration test passes, run:

    uv run python -m tests.tools.spike_harness \
        --etl tests/fixtures/spike-multi-provider/spike-multi-provider.etl \
        --sidecar-binary rust/target/release/wpr-mcp-extract.exe \
        --oracle-dir tests/fixtures/spike-multi-provider/oracle/ \
        --output spike-results/rust-report.json

Commit and push `spike-results/rust-report.json`.

DO NOT:
- Modify any file outside `rust/` or `spike-results/`
- Add new Python dependencies
- Modify `tests/tools/spike_harness.py`
- Modify the fixture ETL or oracle directory
- Rebase your branch onto anything other than `feature/spike-shared`
- Push to any branch other than `feature/spike-rust`

DEFINITION OF DONE:
- `spike-results/rust-report.json` exists, parses, and contains
  per-class parity numbers
- `cargo test --workspace` passes
- The integration test passes
- Git log on `feature/spike-rust` is clean and signed off
- A `rust/README.md` documents how to reproduce the build

WHEN BLOCKED:
- If `windows-rs` API gaps prevent decoding a required event class,
  document the gap in `rust/README.md` and skip that class in the
  report (with `"missing_due_to_api_gap": true`).
- If a panic test cannot be implemented cleanly, document the workaround
  used.
- DO NOT block on cross-language coordination — the C# agent is working
  independently in another worktree.

TIME BUDGET: 4-5 days. If you cannot complete the 8 classes in that
time, prioritize SampledProfile + StackWalk + CSwitch + NdisDrop +
SystemConfig (the parity-gap-relevant ones) and document what was
skipped.
```

### 3.2 Agent B — C# spike

**Worktree:** `C:\git\wpr-mcp-server-spike-csharp`
**Branch:** `feature/spike-csharp`
**Runtime:** `general-purpose` agent, Opus or GPT-5.5,
**`mode="background"`**.
**Expected duration:** 3–4 calendar days (TraceEvent makes most of this
easier).
**Definition of done:** `spike-results/csharp-report.json` committed
and pushed.

#### Verbatim prompt for Agent B

```
You are implementing the C# half of a parallel spike to choose between
Rust and C# as the native ETW sidecar language for the wpr-mcp-server
project.

YOUR WORKTREE: C:\git\wpr-mcp-server-spike-csharp
YOUR BRANCH: feature/spike-csharp
DO NOT TOUCH: any file outside the `csharp/` subdirectory, except
`spike-results/csharp-report.json` which is your only output.

READ FIRST (in order):
1. C:\git\wpr-mcp-server-spike-csharp\rust-hybrid-migration-plan.md
   (especially §2, §5, §6, §9, §11 phase 0)
2. C:\git\wpr-mcp-server-spike-csharp\docs\spike-contract.md
   (the contract you must implement)
3. C:\git\wpr-mcp-server-spike-csharp\src\etw_analyzer\native\schemas.py
   (the parquet schemas you must emit)
4. C:\git\wpr-mcp-server-spike-csharp\src\etw_analyzer\native\cache.py
   (the cache manifest you must write)
5. C:\git\wpr-mcp-server-spike-csharp\tests\tools\spike_harness.py
   (the measurement tool you will be scored against)

DELIVERABLE: a self-contained single-file C# binary at
`csharp/publish/win-x64/wpr-mcp-extract.exe` that:
- Reads `--request request.json` per the contract
- Opens the fixture ETL via Microsoft.Diagnostics.Tracing.TraceEvent
  (ETWTraceEventSource for offline ETLs)
- Subscribes to events for 8 classes: SampledProfile, StackWalk,
  CSwitch, ReadyThread, TcpIp/Recv, AFD/Recv, NdisDrop, SystemConfig
- Uses TraceEvent's built-in stack pairing (Process.Stack.Stack)
- Loads symbols via TraceEventStackSource or
  Microsoft.Diagnostics.Symbols
- Writes Layer 1 parquets per native/schemas.py byte-for-byte using
  Apache.Arrow + Parquet.Net
- Writes wpr-mcp-cache-manifest.json with producer="csharp"
- Writes native-event-store-manifest.json
- Emits JSONL heartbeat + result on stdout
- Wraps every event callback in try/catch with structured exception
  handling (per v3 plan §10)
- Handles a deliberate exception in the callback cleanly (emit
  failure_kind="csharp_exception", exit cleanly)

SCOPE LIMITS:
- 8 event classes only; do NOT try to cover all 25+ canonical classes
- .NET 8 LTS only; do not use .NET 9 preview features
- Use self-contained single-file deployment
  (`<PublishSingleFile>true</PublishSingleFile>`,
  `<SelfContained>true</SelfContained>`,
  `<IncludeNativeLibrariesForSelfExtract>true</IncludeNativeLibrariesForSelfExtract>`)
- Do NOT use NativeAOT (TraceEvent trim-compat unverified)
- Solution layout per v3 plan §9 (4 projects max)

TESTING:
- xUnit tests for each event-class mapper; mirror existing
  `tests/native/test_mof_*.py` cases via shared `.bin` fixtures
- Integration test: run the binary against the fixture, validate output
  parses with pyarrow

MEASUREMENT (THE OUTPUT YOU COMMIT):
After the binary is published and the integration test passes, run:

    uv run python -m tests.tools.spike_harness \
        --etl tests/fixtures/spike-multi-provider/spike-multi-provider.etl \
        --sidecar-binary csharp/publish/win-x64/wpr-mcp-extract.exe \
        --oracle-dir tests/fixtures/spike-multi-provider/oracle/ \
        --output spike-results/csharp-report.json

Commit and push `spike-results/csharp-report.json`.

DO NOT:
- Modify any file outside `csharp/` or `spike-results/`
- Add new Python dependencies
- Modify `tests/tools/spike_harness.py`
- Modify the fixture ETL or oracle directory
- Rebase your branch onto anything other than `feature/spike-shared`
- Push to any branch other than `feature/spike-csharp`

DEFINITION OF DONE:
- `spike-results/csharp-report.json` exists, parses, and contains
  per-class parity numbers
- `dotnet test` passes
- The integration test passes
- Git log on `feature/spike-csharp` is clean and signed off
- A `csharp/README.md` documents how to reproduce the build

WHEN BLOCKED:
- If TraceEvent does not expose a required field, document the gap in
  `csharp/README.md`, attempt P/Invoke to TDH directly as a workaround,
  and report accurately in the spike report.
- If single-file publishing breaks under TraceEvent's dependencies,
  fall back to framework-dependent publish and document the runtime
  install requirement.
- DO NOT block on cross-language coordination — the Rust agent is
  working independently in another worktree.

TIME BUDGET: 3-4 days. If you cannot complete the 8 classes in that
time, prioritize SampledProfile + StackWalk + CSwitch + NdisDrop +
SystemConfig (the parity-gap-relevant ones) and document what was
skipped.
```

### 3.3 Dispatching the agents

Both agents are dispatched as background tasks (so the human can do
other work while they run). The dispatcher (human or orchestrator
agent) issues two `task` tool calls:

```
task(name="spike-rust", agent_type="general-purpose",
     model="claude-opus-4.7-1m-internal" or "gpt-5.5",
     mode="background", prompt=<Agent A prompt above>)

task(name="spike-csharp", agent_type="general-purpose",
     model="claude-opus-4.7-1m-internal" or "gpt-5.5",
     mode="background", prompt=<Agent B prompt above>)
```

Wait for both completion notifications before phase 2.

---

## 4. Phase 2 — Decision (~1 day)

### 4.1 Verify outputs

```powershell
# Pull both branches into the main worktree
cd C:\git\wpr-mcp-server
git fetch origin feature/spike-rust feature/spike-csharp

# Look at the two reports side by side
git show origin/feature/spike-rust:spike-results/rust-report.json | jq '.'
git show origin/feature/spike-csharp:spike-results/csharp-report.json | jq '.'
```

### 4.2 Score against pass/fail criteria

Apply `rust-hybrid-migration-plan.md` v3 §2 criteria to both reports.
For each axis, mark Rust / C# / tie:

| Axis | Rust report | C# report | Winner |
|---|---|---|---|
| <25% hand binary parsing | | | |
| Stack pairing within 0.5% | | | |
| Top-10 cpu_samples match | | | |
| SystemConfig richness | | | |
| End-to-end time ratio | | | |
| Self-contained single file | | | |
| Failure kinds clean | | | |
| Package size | | | |

### 4.3 Record the decision

Create `rust-vs-csharp-spike-decision.md` capturing:
- Which language won and why
- The two reports as evidence (or links to commits)
- Any open issues that the winning spike couldn't address
- Next steps (which language gets phase 1 of the migration)

Commit on `main` (or a `feature/spike-decision` branch reviewed via PR).

### 4.4 Cleanup

```powershell
# Archive the losing spike (don't delete — useful reference)
git tag spike-rust-archive feature/spike-rust
git tag spike-csharp-archive feature/spike-csharp
git push origin --tags

# Remove the losing worktree
git worktree remove ..\wpr-mcp-server-spike-<loser>

# Keep the winner's worktree active for phase 1 of the migration,
# OR merge it back to main and remove the worktree:
cd C:\git\wpr-mcp-server
git checkout main
git merge --no-ff feature/spike-<winner> -m "Adopt <winner> sidecar from spike"
git worktree remove ..\wpr-mcp-server-spike-<winner>
git branch -d feature/spike-<loser>
```

---

## 5. Coordination protocol

### 5.1 Shared resources (read-only for both agents)
- `tests/fixtures/spike-multi-provider/` — fixture + oracle
- `tests/tools/spike_harness.py` — measurement tool
- `docs/spike-contract.md` — input/output spec
- `src/etw_analyzer/native/schemas.py` — parquet schemas
- `src/etw_analyzer/native/cache.py` — cache manifest format

If either agent thinks they need to modify a shared resource: **STOP,
ask the human.** Mutation of shared resources is a coordination event
that requires both agents to re-sync.

### 5.2 Branch hygiene
- Neither agent rebases.
- Neither agent merges.
- Neither agent force-pushes.
- Both agents only push to their own branch.

### 5.3 If the shared infrastructure needs a fix mid-spike
1. Human commits the fix on `feature/spike-shared` and pushes.
2. Human merges `feature/spike-shared` into both spike branches.
3. Both agents are notified to `git pull` before continuing.

This is rare; the spike contract should be stable by the time agents
start.

---

## 6. Risk mitigation

| Risk | Mitigation |
|---|---|
| Agent gets stuck on Windows API quirk | Time budget (4-5d) forces them to document and skip; partial reports are still useful |
| Both agents fail to produce a runnable binary | Decision deferred; revisit spike scope. (Unlikely — phase 0 scope is intentionally small.) |
| Agents converge on incompatible interpretations of the contract | Phase 0 produces `docs/spike-contract.md` *before* either agent starts; if interpretation diverges, the contract doc is wrong (fix it on `spike-shared`, propagate to both branches). |
| Harness gives different scores on repeated runs | Harness must be deterministic; symbol resolution gated behind a fixed `_NT_SYMBOL_PATH`; cache cleared between runs. |
| Hardware availability for fixture capture | Phase 0 is on the critical path; capture the fixture first, before scheduling agents. |
| Agent submits report but doesn't actually pass the integration test | Report includes a `harness_self_check` field that asserts the binary ran successfully; harness fails the report if not. |

---

## 7. Total wall-clock plan

| Day | Activity |
|---|---|
| 0 | Phase 0.1: branch and worktree setup (30 min) |
| 0 | Phase 0.2: capture fixture ETL on lab VM (2 hours) |
| 0 | Phase 0.3: generate oracle (15 min) |
| 1 | Phase 0.4: build spike harness (4 hours) |
| 1 | Phase 0.5: write spike contract doc (4 hours) |
| 1 | Phase 0.6: commit and propagate (15 min) |
| 2-6 | Phase 1: agents work in parallel (background) |
| 7 | Phase 2: review reports, decide, record, clean up (1 day) |

**Total calendar: ~1 week of wall time. Total active human time: ~2.5
days. Total agent time: 7-9 days of compute (run in background, so no
human-blocking cost).**

---

## 8. What success looks like at the end of week 1

- Two committed reports (`spike-results/rust-report.json`,
  `spike-results/csharp-report.json`) with comparable per-class
  parity, timing, and packaging metrics.
- A signed-off decision document
  (`rust-vs-csharp-spike-decision.md`) naming the winner and
  citing the evidence.
- One archived branch + tag for the loser (kept for reference).
- The winner's branch ready to be developed into phase 1 of the
  migration (per v3 plan §11).
- The human spent ~2.5 days of active time and gained an evidence-
  backed answer to a 10-12-week strategic question.

---

## 9. After-the-fact: what carries forward

Regardless of which language wins:
- The fixture ETL — keep, useful for every future test.
- The oracle — keep, useful baseline for any future sidecar work.
- The spike harness — evolves into the per-tool parity test from the
  test plan.
- The spike contract — becomes the v1 sidecar contract in the migration
  plan.
- The decision record — referenced by the migration plan v4 (which
  drops the language-undecided framing).
