# Rust vs C# Spike Review — `wpr-mcp-server`

**Reviewer:** GPT-5.5 sub-agent, dispatched 2026-05-29.
**Reviewed:** `rust-hybrid-migration-plan.md` v2, in light of the two
prior tactical reviews.
**Independence note:** dispatched after v2 was written; reviewer had
access to v2 plan, both prior reviews, full `native/` source.

This document captures the third review verbatim. The plan has been
updated to v3 to address its findings; see v3 §17 for the change log.

---

## 1. v2 plan verdict

**Approve with changes.** v2 does address the prior tactical review
items: correct manifest filename, schema-layer split, event-store scope,
worker/supervisor reuse, ownership matrix, stronger phase 0,
`catch_unwind`, wheel/signing, no Polars, revised estimate/tool
count/fresh-machine claim, and reduced Cargo split. But v2 now exposes
a more important strategic issue: once C# `TraceEvent` is admitted as a
serious option, the remaining plan is still Rust-shaped and
under-specifies what changes if C# wins.

## 2. New issues v2 introduces

1. **Aggregator orchestration is broken/underspecified.** v2 says Rust
   emits only raw Layer 1/2 data and Python aggregators own Layer 3
   (`plan:215-223`), but also deletes `worker.py` (`plan:332`). Today
   `worker.py` runs extraction, symbolization,
   `_run_native_aggregators`, CPU synthesis, metadata, and manifest
   writing before promotion (`worker.py:153-263`).
   `worker_supervisor.py` only stages/validates/promotes; it does not
   run aggregators. v2 needs a "post-sidecar Python aggregation step"
   before cache validation/promotion, or Rust/C# must produce aggregate
   outputs too.

2. **Manifest mode contract conflicts with current cache code.** v2
   proposes cache manifest `mode ∈ {"rust","native","xperf"}`
   (`plan:230-232`), but current `cache.py` rejects anything except
   `mode == "native"` in shape validation (`cache.py:256-265`) and
   validates exact `mode` on reload (`cache.py:294-305`,
   `trace_mgmt.py:1596-1615`). This also conflicts with
   "Python-native-era caches reload under mode=rust" (`plan:702-704`).
   Prefer keeping cache `mode="native"` for the ETW-native cache format
   and adding `producer="rust|csharp|python"`.

3. **C# path is not actually planned.** §2 says "same architecture,
   different language" (`plan:57-60`, `467-471`), but later sections
   assume Cargo crates, Rust schema-codegen as source of truth,
   `catch_unwind`, `windows-rs`, and Rust packaging (`plan:347-413`,
   `415-440`, `677-680`). If C# wins, the plan lacks the equivalent
   project layout, build, schema contract, TraceEvent event mapping
   strategy, and .NET packaging choice.

4. **Event-store/materialized strategy remains ambiguous.**
   `plan:211-213` says materialized-small writes Layer 2 "alongside
   the event-store output (or instead of, per strategy)," and
   `plan:295-303` mistakenly labels `_DUMPER_EVENT_CLASSES` parquets
   as "Layer 1." The plan must define exactly which datasets exist in
   each strategy and which are materialized on load.

5. **The C# spike metrics underweight correctness.** §2 measures
   LOC/time/throughput/size, but the decisive issue is provider
   coverage and field correctness. The gate should require C# vs Rust
   comparison on decoded field coverage for kernel MOF, TDH manifest
   events, SystemConfig, NDIS drops, stack pairing, and parity against
   Python/xperf.

6. **Schema-codegen source of truth is risky.** v2 proposes Rust
   `wpr-cache-contract` as source and Python `schemas.py` generated
   (`plan:338`, `677-680`). That is backwards if C# may win and if
   Python remains the host. Use language-neutral schema specs, or keep
   Python schemas authoritative until the language decision is final.

## 3. Rust vs C# — decision recommendation

**I recommend C# with TraceEvent as the sidecar language, with 85%
confidence.** For this specific project, the hard problem is not
"write safe native code"; it is "correctly decode Windows ETW across
kernel MOF, TDH manifest providers, stack walks, symbols, and
SystemConfig quirks." TraceEvent directly attacks that problem. Rust
gives better packaging and lower-level safety, but it mostly
reimplements already-maintained Microsoft ETW logic.

## 4. Comparison table

| Axis | Rust score | C# score | Winner | Why |
|---|---:|---:|---|---|
| A. ETW decode correctness | 6/10 | 9.5/10 | **C#** | Rust must port `decoder.py`, `manifest.py`, `mof/*`; TraceEvent covers kernel MOF + manifest providers. |
| B. Symbolizer/dbghelp | 7/10 | 8/10 | **C# slight** | Both can misuse dbghelp; C# has TraceEvent/Microsoft symbol ecosystem. Rust raw FFI repeats Python risks. |
| C. Arrow/parquet | 9/10 | 7/10 | **Rust** | `arrow-rs`/`parquet` are stronger. But sidecar only writes contract files; this is not decisive. |
| D. MCP/native host future | 6/10 | 9/10 | **C#** | Python stays now; if host later moves native, C# has better Windows/debugging/MCP alignment. |
| E. Binary parsing safety | 9/10 | 8/10 | **Rust slight** | Rust prevents lifetime bugs better, but TraceEvent removes much binary parsing entirely. |
| F. Packaging/deployment | 9/10 | 7/10 | **Rust** | Rust single exe is cleaner. C# should use self-contained single-file .NET, not NativeAOT initially. |
| G. Maintainer burden | 6/10 | 9/10 | **C#** | Windows perf/debugging ecosystem and team ramp strongly favor C#. |
| H. Phase-0 speed/risk | 6/10 | 9/10 | **C#** | TraceEvent should reach SampledProfile+StackWalk+TCPIP+symbols faster. |
| I. Existing code replacement | 6/10 | 9/10 | **C#** | C# eliminates most TDH/MOF decode; Rust ports it. |
| J. Strategic north star | 5/10 | 9/10 | **C#** | Crash dumps, WMI, PDH, services, event logs, ClrMD/dbgeng all align better with C#. |

## 5. The argument for the recommendation

The Python code shows that most complexity is **Windows ETW semantic
decoding**, not generic performance. `decoder.py` is a hand TDH
implementation with positive caches, provider-wide negative caches,
`PROPERTY_PARAM_LENGTH`, pointer-size handling, and partial-row
recovery (`decoder.py:1-36`, `218-310`). TraceEvent already owns that
class of logic. A Rust port would faithfully rewrite the same fragile
layer; a C# port can delete most of it.

The MOF tree is even more compelling. The project manually unpacks
`SampledProfile` and DPC/ISR structs (`mof/perfinfo.py:39-52`),
StackWalk QPC join payloads (`mof/stackwalk.py:1-17`, `55-60`),
Thread/ReadyThread fixed and variable layouts (`mof/thread.py:42-82`),
and Process SID/string drift (`mof/process.py:21-37`, `98-111`).
TraceEvent's core value proposition is decoding these kernel events.
That likely eliminates **80-90% of the current decode plumbing**, while
Rust keeps it as project-owned code.

TraceEvent also directly targets current parity gaps. Native sysconfig
is only a passthrough despite comments saying TDH can decode it
(`mof/sysconfig.py:5-11`, `95-108`), which is why the parity review
reports missing CPU model, NIC names, and disk model
(`native-vs-xperf-parity-review.md:43-55`). TraceEvent has mature
SystemConfig support, so C# is much more likely to close that gap for
free. The NDIS drop gap is currently a missing registry mapping
(`manifest.py:593-676` lacks `_map_ndis_drop`); TraceEvent makes
provider discovery and event identity less hand-maintained.

Dbghelp does not flip the decision to Rust. The current bugs are not
Python-specific type bugs; they are dbghelp lifecycle/global-state
issues: synthetic handles to isolate traces (`symbolizer.py:53-67`),
serialized `SymLoadModuleExW`/`SymFromAddrW` (`symbolizer.py:143-144`),
deferred-load retry (`symbolizer.py:346-371`), and cleanup
(`symbolizer.py:401-416`). Rust raw FFI does not inherently prevent
those. C# can still P/Invoke incorrectly, but TraceEvent's surrounding
symbol tooling and Microsoft.Diagnostics ecosystem reduce bespoke
surface area.

Rust's best argument is packaging and low-level safety, but this
sidecar is not a long-running kernel-adjacent datapath. It is an
offline ETL translator producing parquet/cache artifacts. The
highest-value safety move is to **avoid writing decoders at all**, not
to rewrite them in a safer language. A self-contained .NET sidecar is
bigger, but for a Windows-only MCP trace analyzer that already
processes large ETL/parquet files, 60-90 MB is an acceptable trade for
correctness and maintainability.

Finally, C# aligns better with the strategic north star. The broader
debugging MCP wants crash dumps, ClrMD, dbgeng, WMI, PDH, services,
and event logs. Those are first-class or at least conventional in C#.
If the team chooses Rust now, the project likely becomes Python + Rust
ETW sidecar + future C# crash/debug sidecars. Choosing C# now reduces
future polyglot sprawl.

## 6. The counter-argument

The strongest case for Rust is operational simplicity and deterministic
deployment. A signed Rust `.exe` is small, fast, and runtime-free.
`arrow-rs`/`parquet` are excellent, and Rust's ownership model is ideal
for callback lifetime hazards like `EVENT_RECORD` reuse
(`consumer.py:139-145`, `230-238`). If the sidecar becomes a
high-throughput streaming transform over huge traces, Rust may win on
CPU, memory, and distribution.

Rust may also be strategically valuable if the team wants to build deep
Windows-native infrastructure in Rust over time. Microsoft is
increasingly investing in Rust for systems components, and a Rust
sidecar would force clean contracts around schemas, manifests, and
binary parsing. If TraceEvent's abstraction hides needed raw ETW
details — especially raw timestamp mode for stack pairing, offline ETL
multi-handle behavior, or exact xperf-compatible fields — C# could hit
a ceiling that Rust avoids.

Where I might be wrong: TraceEvent may not expose every exact field
needed in the same shape as xperf/Python, especially for niche
networking providers, packet capture bytes, or lost-event/timestamp
behavior. Also, .NET trimming/AOT/single-file behavior with TraceEvent
may be awkward. The spike must test these explicitly.

## 7. What to look for in the phase-0 spike

Use the same ETL and require both spikes to emit the same cache/event-
store contract.

Pick **C#** if:
- It decodes `SampledProfile`, `StackWalk`, `CSwitch`, `ReadyThread`,
  `TcpIp/Recv`, `AFD/Recv`, `NdisDrop`, and `SystemConfig` with **less
  than 25% hand binary parsing code**.
- Stack pairing matches Python native row counts within **0.5%** and
  top-10 `get_cpu_samples` modules/functions match.
- It produces richer SystemConfig fields than current native: CPU
  model, NIC names/drivers, disk model/size.
- End-to-end time is within **30% of Rust** or at least **2x faster
  than current Python native**.
- Self-contained single-file signed build works from `uv sync` without
  requiring a .NET install. Prefer self-contained .NET first; only use
  NativeAOT if TraceEvent trimming is proven safe.

Pick **Rust** if:
- C# cannot preserve raw QPC timestamp stack pairing or loses
  essential fields.
- C# requires substantial manual TDH/MOF parsing anyway, erasing
  TraceEvent's advantage.
- C# sidecar is more than **2x slower** than Rust on a realistic
  multi-million-event trace after parquet output is included.
- TraceEvent packaging is unacceptable: broken single-file deployment,
  impossible signing story, or runtime requirements the team cannot
  tolerate.
- Rust spike demonstrates full TDH/MOF/stack/symbol/event-store
  correctness with contained unsafe code and no major `windows-rs`
  gaps.

Both spikes must report:
- LOC by category: ETW consume, MOF/TDH decode, mapping/projection,
  symbolization, parquet/cache, protocol.
- Event classes decoded and fields per class.
- Row-count parity vs Python native/xperf.
- Stack pairing rate.
- Peak RSS and wall time.
- Package size and deployment steps.
- Failure behavior for callback panic/exception and truncated ETL.

## 8. Net recommendation summary

This week: run both spikes, but set the prior to **C# wins unless
TraceEvent fails raw timestamp/field coverage or is materially slower**.
Next week: if C# passes the correctness gate, rewrite the plan as a C#
TraceEvent sidecar plan and drop the Rust-specific crate/codegen
assumptions. Month 2: implement sidecar + Python post-extraction
aggregation + cache compatibility, keeping xperf for pool and remaining
out-of-scope analyses.
