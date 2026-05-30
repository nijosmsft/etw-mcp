# Native vs xperf Path Parity Review — `wpr-mcp-server`

Review of `src\etw_analyzer\native\*` against `src\etw_analyzer\parsing\wpa_exporter.py`
and the wiring in `tools\trace_mgmt.py`. The native path is **substantially in parity**
for the core event flow but has **5 real gaps** and ~6 subtle differences worth knowing.

## Architecture: solid parity

Both paths feed the same `TraceData.raw_csv` dict, the same parquet cache (same
`trace_id`, same filenames, same schema), and the same per-event DataFrames on
`trace.*_df` attributes. `trace_mgmt._DUMPER_EVENT_CLASSES` is the single source
of truth, and `extract.CANONICAL_EVENT_CLASSES` mirrors `wpa_exporter.EVENT_HANDLERS`.
A trace loaded once in either mode reloads from cache in the other.

## Real parity gaps

### 1. `NdisDrop` mapper missing on native — silent data loss

`CANONICAL_EVENT_CLASSES` advertises `NdisDrop` (`extract.py:74`) and the
schema/cache slot exists (`schemas.py:255`, `network.py:62`). But
`manifest._REGISTRY` has **no entry** that maps an NDIS drop event to
`_map_ndis_drop`. xperf catches it via `_EVENT_PREFIX_ALIASES["NdisDrop"]` in
dumper text.

**User-visible impact:** `get_packet_drops` returns "no dropped packets" on
native even when the trace has them.

### 2. `cpu_sampling` — Idle row missing in the materialized native path

- xperf's `profile -detail` denominator naturally includes idle time → an
  "Idle (0)" row dominates the output.
- `aggregate_cpu_sampling` (`profile_detail.py:160`) computes
  `% Weight = Weight / sum(Weight)` — so percentages sum to 100% over only
  the observed samples.
- The Idle synthesis (`streaming.py:296-304`) only kicks in for the
  **streaming/event-store** path, and only when
  `current_total > expected_capacity * 1.5`. Materialized native traces with
  low utilization get no Idle row.

**User-visible impact:** `get_cpu_samples` / `get_hot_functions` % values are
inflated vs xperf and `Idle` doesn't show up in the top list.

### 3. `sysconfig` — drastic content gap

- xperf `-a sysconfig -cpu -nic -disk -memory` emits a multi-page block with
  CPU model name, NIC friendly names + drivers + MAC, disk model/size,
  service list.
- `build_sysconfig_text` (`sysconfig.py`) only emits per-opcode counts
  (`CPU: 2 record(s), 32 byte(s) of payload`) + 6 header values. The
  SystemConfig MOF decoder is a passthrough (`mof/__init__.py:23-26`); the
  design said TDH should decode SystemConfig payloads, but that wiring isn't
  there.

**User-visible impact:** `get_sysconfig` returns much less info on native
(no CPU model name, no NIC names, no disk model).

### 4. `diskio` — summary-only on native

- xperf `-a diskio -summary` produces per-file IO, latency, queue depth.
- `build_diskio_text` (`diskio.py`) emits one line per disk number:
  `Disk N: reads=X (YB), writes=Z (WB), flushes=K`. No file paths, no
  latencies.

### 5. `tracestats` — different text format

- xperf's tracestats lists each provider with EventCount/BufferCount/etc. in
  a fixed format.
- `build_tracestats_text` emits different headers (`Total events:`,
  `Bytes processed:`, `Provider events:`). Both convey similar info but
  text diff tools won't recognize them as equivalent.

## Subtle differences (work-as-designed but worth knowing)

| Area | xperf | Native | Risk |
|---|---|---|---|
| **TCP send/recv 5-tuple** | Comes from kernel TcpIp_TypeGroup1 events with the 5-tuple inline | Comes from manifest TCPIP (events 1332/1074), which carries only `Tcb`; 5-tuple is back-joined from `TcpConnectionRundown` (1300) via `enrich_network_events` | Connections without a connect/rundown event get blank addresses |
| **CSwitch process names** | xperf dumper text contains process names inline | Native MOF gets only TIDs; PIDs and names are backfilled in `_run_native_aggregators` (`trace_mgmt.py:967-1055`) | The backfill works but adds a Python loop over every CSwitch row; the original CSwitch DataFrame is mutated in place and re-persisted |
| **stacks_callers** | xperf's `TblSN` HTML table = a real butterfly with multi-level inclusive | Native walks adjacent stack pairs (target ↔ immediate caller only). Transitive callers are not emitted | `get_function_callers` may show shallower callers on native |
| **dpc_isr "(all)"** | Emitted only when xperf actually outputs a `Total = N` line without a module | Native always synthesizes "(all)" rows from per-module buckets (`dpcisr.py:389-403`) | Row counts differ but both totals are correct |
| **StackWalk frame size** | xperf handles 32-bit and 64-bit | `mof/stackwalk.py:56-59` hardcodes 8-byte u64 frames. `perfinfo.py:44` hardcodes 8-byte IP; `perfinfo.py:52` hardcodes 8-byte Routine | 32-bit kernel traces would mis-decode (irrelevant for the project's x64 lab) |
| **ReadyThread stack** | Lives in the parsed xperf text as `ReadyThread Stack` column | Lives in the event-store as a `Stack` list column. `get_lock_contention` routes through `_get_lock_contention_from_event_store` when present | Parity only works if the event-store path is taken; pure `raw_csv['readythread']` lookup won't see the stack |

## Test coverage of parity

- `tests/native/aggregators/*` unit-test each native aggregator independently with
  synthetic inputs but **don't compare against xperf output**.
- `tests/test_parsers.py` covers xperf text parsers in isolation.
- There is **no test that loads the same `.etl` in both modes and diffs the
  resulting DataFrames** — the CLAUDE.md note ("Tests don't cover the xperf
  path. End-to-end with a real ETL is manual") is honest about this.

## Recommendations (in priority order)

1. **Add `NdisDrop` to `manifest._REGISTRY`** — find the NDIS drop provider
   GUID + event id, write a `_map_ndis_drop` modeled on `_handle_ndis_drop`.
   This is the only "silent data loss" gap.
2. **Add an Idle synthesis to the materialized `aggregate_cpu_sampling`**
   (not just streaming) — compute `expected_capacity_us = duration * cpu_count`
   and insert an `Idle / <Low Power>` row for the residual. Keeps
   `get_cpu_samples` percentages compatible with xperf.
3. **Wire TDH decoding for SystemConfig opcodes** (CPU=10, NIC=11, PhyDisk=12,
   Power=24, …) into `build_sysconfig_text` — the design doc already calls for
   this.
4. **Add an end-to-end parity test fixture** — load a small canned `.etl` (e.g.
   one of the `multi-provider.etl` traces already referenced) in both modes and
   assert that core aggregates (`cpu_sampling`, `dpc_isr`, `tcpip_send_df` row
   counts, connection 5-tuples) match within tolerance.
5. **Document 32-bit limitation** if 32-bit traces are out-of-scope (likely
   yes), or add `EVENT_HEADER_FLAG_32_BIT_HEADER` handling to the three hot
   decoders.

The native path is doing the hard work correctly — the gaps are localized in a
few aggregators and one missing mapper, not in the consumer plumbing.

---

## Addendum — Is "parity" the right goal?

The framing above (and the codebase's own framing — see
`config.py:8`'s "Phase N5 flipped this from `xperf` once the native pipeline
reached parity") oversells what's achievable. Full parity with xperf is **not**
a realistic target, and the default-mode decision should rest on a different
argument.

### The `-tle` question is actually inverted

[PR #1](https://github.com/nijosmsft/wpr-mcp-server/pull/1) adds `-tle`
(tolerate lost events) to the xperf invocation so traces with buffer overruns
can still be analyzed. `-tle` and its sibling `-tti` exist because xperf's
*analysis layer* (the `-a <action>` passes) halts when it detects lost events
or timer inversions.

The native pipeline has no such gate — `ProcessTrace` keeps invoking the
callback regardless. So native is **accidentally** "always -tle, always -tti"
— not by design, by absence of the strict check. That's lucky on this
particular dimension but it makes the broader point: native doesn't *match*
xperf's behavior, it just has different behavior that happens to be
acceptable here.

### What xperf really is

xperf is a 20-year-old, internally-validated analysis suite with dozens of
`-a` actions. Looking at what `wpr-mcp-server` actually uses:

| xperf action | Native replacement? |
|---|---|
| `profile -detail`, `profile -util` | Yes (with Idle-row + percentage caveats from §gaps) |
| `dpcisr` | Yes |
| `stack -butterfly` | Approximated (adjacent-pair walking, not real butterfly) |
| `cswitch`, `readythread -stacks` | Partial (event-store path only, not text-DataFrame path) |
| `tracestats`, `sysconfig`, `process`, `diskio` | Yes but with content gaps (see §gaps) |
| **`pool -pooltags -images`** | **No — `tools/memory.py:28` always shells to xperf** |
| `dumper` (per-event) | Yes |
| `dispatch`, `hardfault`, `virtfaults`, `vamap`, `tcb`, `mmcss`, `gtbttbl`, `bidi`, `usb`, `wifi`, … | None of these — never attempted |

`get_memory_pools` is the smoking gun: even with `mode="native"` set, the
implementation silently calls `_run_xperf(... "pool" ...)`. The native path
doesn't replace xperf; it replaces *a slice* of xperf.

### Where native will keep losing

1. **Provider-specific quirks** xperf accumulated across Windows builds —
   the CSwitch column-drift bug history in `wpa_exporter.py:803-852` shows
   how easily binary MOF decoders diverge from reality.
2. **Pool / memory / VA-space analysis** — requires decoders for kernel
   structures (PFN entries, VAD trees) that don't exist in `mof/`.
3. **HTML butterfly view** — `stack -butterfly` does multi-level inclusive
   counting with reach-set semantics. Native walks adjacent pairs. Same
   column names, materially different numbers on deep stacks.
4. **Large traces** — native has a 512 MB guardrail
   (`WPR_MCP_NATIVE_MAX_ETL_MB`); above that it auto-falls-back to xperf in
   auto mode or errors in explicit native mode. xperf streams.
5. **Future providers** — any new kernel provider needs a hand-written MOF
   decoder. xperf gets it via Windows updates.

### Implications for the default mode

This actually *strengthens* the case for keeping native as default, but for a
different reason than "parity":

- **Native isn't trying to be xperf — it's trying to handle the 80% case
  fast and without installs.** When users hit the 20%, the code
  transparently falls back to xperf (auto mode + the `xperf is None`
  checks) or surfaces a clear error.
- **The honest framing isn't "parity" — it's "coverage of the project's
  hot path."** UDP/QUIC perf analysis (the project's reason for existing)
  lives entirely inside the native subset.
- **Forcing xperf default punishes the 80% to fix the 20%.** Multi-GB SDK
  install, slower extraction, brittle text parsing, all to recover features
  most users never call.

### Recommended doc/code edits to stop overselling parity

1. **README** — change "native ETW consumer (default)" → "in-process ETW
   consumer covering CPU/DPC/network/stack analysis; xperf required for
   memory pools and large (>512 MB) traces."
2. **`config.py:8`** — drop the "once the native pipeline reached parity"
   phrasing; it overstates the scope.
3. **Per-tool docstrings** — `get_memory_pools`, `get_lock_contention`,
   `get_sysconfig`, `get_diskio_summary` should note where xperf gives
   richer output.
4. **`load_trace` summary output** — when `resolved_mode == "native"`,
   include a one-liner like: "Native mode: pool/sysconfig detail limited —
   use `mode='xperf'` for full output."

**Net recommendation:** keep native as default, but stop calling it parity.
Call it "the in-process fast path that covers what wpr-mcp-server is
actually used for." The 5 fixable gaps in §gaps are worth closing; the
unfixable ones (pool, HTML butterfly semantics, large-trace streaming)
should be documented as "use `mode='xperf'`" instead of pretended away.
