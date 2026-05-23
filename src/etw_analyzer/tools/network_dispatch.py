"""Phase 2 dispatch-quality tools — answer RSS/SWRSS/CPUMAP correctness questions.

These tools aggregate over data the trace already has (``dpc_isr`` structured
data, optional ``dpc_isr_raw`` per-CPU text, and the dumper-populated
SampledProfile DataFrame), so they cost nothing beyond what ``load_trace``
already extracted.

Each tool answers one concrete dispatch question:

- :func:`get_rss_dispatch_quality` — for each network-active process, what
  fraction of its CPU samples land on a CPU that handled a networking DPC?
  High cross-CPU % is the symptom CPUMAP is trying to fix.

- :func:`get_per_nic_queue_arrivals` — how many distinct CPUs are seeing the
  NIC driver's DPCs? "8 of 80" tells the user RSS is bottlenecked on the
  default queue count.

- :func:`get_udp_dispatch_quality` — UDP-stack samples per process / CPU,
  with overlap against NIC-DPC CPUs. Same shape as the RSS tool but scoped
  to UDP. ``port=`` is accepted for forward-compat but is a no-op until
  Phase 3 AFD events land.
"""

from __future__ import annotations

import re

import pandas as pd

from etw_analyzer.app import mcp
from etw_analyzer.formatting.markdown import format_pct, format_table
from etw_analyzer.networking import (
    NETWORK_KERNEL_MODULES,
    NETWORK_MODULES_ALL,
    NETWORK_USER_MODULES,
)
from etw_analyzer.native.aggregators.dpcisr import build_dpc_per_cpu_dataframe
from etw_analyzer.trace_state import TraceData, require_trace


# Modules whose top frame indicates a UDP receive/processing path. The samples
# we get from the dumper are single-frame (Image!Function on the running PC),
# so the heuristic is "top frame's module is on this list AND the function name
# carries a UDP-shaped hint". Phase 3 AFD events will let us refine this with
# per-socket port attribution.
_UDP_PATH_MODULES = frozenset({
    "tcpip.sys",
    "afd.sys",
    "ws2_32.dll",
    "mswsock.dll",
})

# Function-name substring hints that signal UDP-side processing on a top frame.
# Case-insensitive. Deliberately broad — the goal is recall, not precision,
# and per-process aggregation washes out incidental matches.
_UDP_FUNCTION_HINTS = ("udp", "datagram", "dgram")

# Minimum sample count required to consider a process "network-active" for the
# RSS dispatch tool. Tuned low so synthetic test data with handfuls of rows
# still surfaces — the production traces have orders of magnitude more samples
# and this threshold is dominated by the NIC-DPC overlap signal anyway.
_NETWORK_ACTIVE_MIN_SAMPLES = 100


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _module_in_set(module: object, module_set: frozenset[str]) -> bool:
    """Case-insensitive membership against a curated module set."""
    if not isinstance(module, str):
        return False
    return module.lower() in {m.lower() for m in module_set}


def _per_cpu_dpc_rows(raw_text: str) -> list[dict]:
    """Parse ``dpcisr.txt`` into one row per (module, CPU).

    The raw text encodes per-CPU DPC time after each module's histogram as a
    single line of comma-separated ``usec  pct`` pairs ending with the module
    name (see :func:`etw_analyzer.tools.dpc_isr._parse_per_cpu_dpc` for the
    shape we're matching).

    Returns:
        List of dicts with keys ``Module``, ``CPU``, ``DPC_us``, ``Pct``.
        Empty list if no per-CPU rows could be parsed (older xperf variants
        or trace types that didn't capture DPC events).
    """
    rows: list[dict] = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        # Same regex shape as dpc_isr._parse_per_cpu_dpc: trailing ".sys"/.exe/.dll
        # token is the module, everything before it is the CSV pair list.
        m = re.match(r"^(.+?)\s+([\w.]+\.(sys|exe|dll))$", stripped, re.IGNORECASE)
        if not m:
            continue
        data_part = m.group(1)
        module = m.group(2)
        for cpu_idx, pair in enumerate(data_part.split(",")):
            pair = pair.strip()
            parts = pair.split()
            if len(parts) < 2:
                continue
            try:
                usec = int(parts[0])
                pct = float(parts[1])
            except (ValueError, IndexError):
                continue
            if usec <= 0:
                continue
            rows.append({
                "Module": module,
                "CPU": cpu_idx,
                "DPC_us": usec,
                "Pct": pct,
            })
    return rows


def _structured_per_cpu_dpc_rows(trace: TraceData) -> list[dict]:
    """Return per-CPU DPC rows from native structured event data."""
    per_cpu = build_dpc_per_cpu_dataframe(trace)
    if per_cpu is None or per_cpu.empty:
        return []

    df = per_cpu.copy()
    required = {"Module", "CPU", "DPC_us"}
    if not required.issubset(df.columns):
        return []
    df["CPU"] = pd.to_numeric(df["CPU"], errors="coerce").fillna(-1).astype("int64")
    df["DPC_us"] = pd.to_numeric(df["DPC_us"], errors="coerce").fillna(0).astype("int64")
    if "Pct" in df.columns:
        df["Pct"] = pd.to_numeric(df["Pct"], errors="coerce").fillna(0.0)
    else:
        df["Pct"] = 0.0
    df = df[(df["CPU"] >= 0) & (df["DPC_us"] > 0)]
    if df.empty:
        return []

    return [
        {
            "Module": str(row["Module"]),
            "CPU": int(row["CPU"]),
            "DPC_us": int(row["DPC_us"]),
            "Pct": float(row["Pct"]),
        }
        for _, row in df.iterrows()
    ]


def _per_cpu_dpc_dataframe(trace: TraceData) -> pd.DataFrame:
    """Return per-CPU DPC rows from raw text or native structured data."""
    raw_df = trace.raw_csv.get("dpc_isr_raw")
    if raw_df is not None and "raw_text" in raw_df.columns and not raw_df.empty:
        rows = _per_cpu_dpc_rows(str(raw_df.iloc[0]["raw_text"]))
        if rows:
            return pd.DataFrame(rows)

    rows = _structured_per_cpu_dpc_rows(trace)
    if rows:
        return pd.DataFrame(rows)
    return pd.DataFrame()


def _nic_dpc_cpu_set(
    trace: TraceData,
    modules: frozenset[str] = NETWORK_KERNEL_MODULES,
) -> tuple[set[int], pd.DataFrame]:
    """Return (CPU set, per-CPU rows) where networking DPCs fired.

    "Heavy networking DPC" is defined inclusively: any CPU that handled a DPC
    from a kernel networking module counts. Tunable via the ``modules`` arg.

    Returns:
        ``(cpus, df)`` where ``cpus`` is the set of CPU IDs and ``df`` is the
        per-CPU DPC DataFrame (handy for downstream tools). Both are empty
        when no per-CPU DPC data is available.
    """
    df = _per_cpu_dpc_dataframe(trace)
    if df.empty:
        return set(), pd.DataFrame()
    net_mask = df["Module"].apply(lambda m: _module_in_set(m, modules))
    cpus = set(int(c) for c in df.loc[net_mask, "CPU"].unique().tolist())
    return cpus, df


def _empty_or_missing(df: pd.DataFrame | None) -> bool:
    return df is None or df.empty


# ---------------------------------------------------------------------------
# get_rss_dispatch_quality
# ---------------------------------------------------------------------------


@mcp.tool()
def get_rss_dispatch_quality(
    trace_id: str,
    min_samples: int = _NETWORK_ACTIVE_MIN_SAMPLES,
    max_rows: int = 30,
) -> str:
    """Per-process cross-CPU dispatch rate between NIC DPCs and recv-side samples.

    For each network-active process this reports:

    - ``nic_dpc_cpus``: count of CPUs that handled any networking-module DPC.
    - ``recv_cpus``: distinct CPUs the process's CPU samples ran on.
    - ``same_cpu_pct``: % of the process's sample weight on a CPU that also
      handled networking DPCs (the "NIC RSS landed on the receiving CPU"
      case — what RSS alone gets you).
    - ``cross_cpu_pct``: complement. High values mean packets are arriving on
      the NIC DPC CPUs but the receiver is parked elsewhere — the gap CPUMAP
      / SWRSS is designed to close.

    Source data: per-CPU DPC data + the background-extracted ``dumper_df``
    (SampledProfile events). The dumper extraction is started
    by ``load_trace``; this tool blocks on ``wait_for_dumper()`` if it's still
    running.

    Args:
        trace_id: ID returned by load_trace.
        min_samples: Minimum sample count for a process to count as
            "network-active". Default: 100.
        max_rows: Maximum process rows to return. Default: 30.
    """
    trace = require_trace(trace_id)

    nic_cpus, _ = _nic_dpc_cpu_set(trace)
    dumper_df = trace.wait_for_dumper()

    if _empty_or_missing(dumper_df):
        return "*No SampledProfile (dumper) data available — RSS dispatch quality needs per-CPU samples.*"

    if not nic_cpus:
        return (
            "*No networking-module DPCs found in DPC/ISR data.* "
            "Trace may have been collected without DPC/ISR kernel flags."
        )

    df = dumper_df
    required = {"Process Name", "CPU", "Module", "Weight"}
    missing = required - set(df.columns)
    if missing:
        return f"*dumper_df missing required columns: {sorted(missing)}.*"

    # Network-active process gate: at least one sample whose top frame is in
    # the unified networking module set.
    net_module_lower = {m.lower() for m in NETWORK_MODULES_ALL}
    df = df.copy()
    df["_is_net_frame"] = df["Module"].astype(str).str.lower().isin(net_module_lower)

    # Build per-process aggregates.
    rows = []
    for proc, group in df.groupby("Process Name", dropna=False):
        total_samples = int(len(group))
        # Match plan: "at least N samples where any sample's Module is in the
        # combined networking module set". Use sample count, not weight, to
        # match the threshold's intent.
        net_samples = int(group["_is_net_frame"].sum())
        if net_samples < min_samples:
            continue

        # Per-CPU weight (sum across all samples for this process, not just
        # the network-frame ones — once it's a network-active process we
        # care about where the whole process runs).
        cpu_weights = group.groupby("CPU")["Weight"].sum()
        total_weight = float(cpu_weights.sum())
        if total_weight <= 0:
            continue

        recv_cpus = sorted(int(c) for c in cpu_weights.index.tolist())
        same_weight = float(
            cpu_weights[cpu_weights.index.isin(nic_cpus)].sum()
        )
        same_pct = same_weight / total_weight * 100.0
        cross_pct = 100.0 - same_pct

        # Compact CPU lists — show at most 8 to keep rows readable. The
        # ``len()`` is in the adjacent column so users still see the spread.
        def _fmt_cpu_list(cpus: list[int]) -> str:
            if len(cpus) <= 8:
                return ",".join(str(c) for c in cpus)
            return ",".join(str(c) for c in cpus[:8]) + f",... (+{len(cpus) - 8})"

        rows.append({
            "Process Name": str(proc),
            "Samples": total_samples,
            "NIC-DPC CPUs": len(nic_cpus),
            "Recv CPUs": len(recv_cpus),
            "Recv CPU list": _fmt_cpu_list(recv_cpus),
            "same_cpu_pct": format_pct(same_pct),
            "cross_cpu_pct": format_pct(cross_pct),
            "_sort": total_weight,
        })

    if not rows:
        return (
            "*No network-active processes found "
            f"(threshold: {min_samples} networking-module samples per process).*"
        )

    result = pd.DataFrame(rows).sort_values("_sort", ascending=False).drop(columns=["_sort"])
    result = result.head(max_rows).reset_index(drop=True)

    nic_cpu_preview = ",".join(str(c) for c in sorted(nic_cpus)[:16])
    if len(nic_cpus) > 16:
        nic_cpu_preview += f",... (+{len(nic_cpus) - 16})"

    header = "**RSS Dispatch Quality** (per-process NIC-DPC vs. recv CPU overlap)"
    footer = (
        f"\n**NIC-DPC CPUs** ({len(nic_cpus)} total): {nic_cpu_preview}\n"
        f"**Min samples threshold:** {min_samples}"
    )
    return f"{header}\n\n{format_table(result, max_rows=max_rows)}{footer}"


# ---------------------------------------------------------------------------
# get_per_nic_queue_arrivals
# ---------------------------------------------------------------------------


@mcp.tool()
def get_per_nic_queue_arrivals(
    trace_id: str,
    nic_module: str = "mlx5.sys",
    max_rows: int = 80,
) -> str:
    """Per-CPU distribution of NIC-driver DPCs — exposes RSS queue spread.

    Counts how many distinct CPUs handled DPCs from the named NIC driver.
    Compares against the system's total CPU count to highlight the classic
    "only 8 of 80 CPUs are getting traffic" RSS bottleneck.

    Source data: per-(module, CPU) DPC rows from either raw dpcisr text or
    native structured DPC events. The unit is per-CPU DPC time in
    microseconds, not absolute DPC counts.

    Args:
        trace_id: ID returned by load_trace.
        nic_module: NIC driver module name (case-insensitive substring).
            Default: ``mlx5.sys`` to match the project's test hardware.
        max_rows: Maximum CPU rows. Default: 80.
    """
    trace = require_trace(trace_id)

    df = _per_cpu_dpc_dataframe(trace)
    if df.empty:
        return (
            "*No per-CPU DPC data in trace.* "
            "Re-collect with `wpr -start GeneralProfile` or a profile that "
            "includes the DPC/ISR kernel flag."
        )

    nic_mask = df["Module"].astype(str).str.contains(nic_module, case=False, na=False, regex=False)
    nic_df = df[nic_mask]
    if nic_df.empty:
        modules_seen = sorted(df["Module"].unique().tolist())
        return (
            f"*No DPC samples for module matching `{nic_module}`.*\n\n"
            f"Modules with per-CPU DPC data: {', '.join(modules_seen)}"
        )

    # Aggregate over (possibly multiple) module rows that match the substring.
    per_cpu = nic_df.groupby("CPU", as_index=False)["DPC_us"].sum()
    total_us = float(per_cpu["DPC_us"].sum())
    if total_us <= 0:
        return f"*Matched `{nic_module}` rows but DPC time totals are zero.*"

    per_cpu["% of total"] = per_cpu["DPC_us"] / total_us * 100.0
    per_cpu = per_cpu.sort_values("DPC_us", ascending=False).reset_index(drop=True)

    # Format for display — keep the underlying numeric column out of the
    # rendered table.
    display = pd.DataFrame({
        "CPU": per_cpu["CPU"].astype(int),
        "DPC Time (us)": per_cpu["DPC_us"].astype(int).map(lambda v: f"{v:,}"),
        "% of total": per_cpu["% of total"].apply(format_pct),
    }).head(max_rows)

    active_cpus = int((per_cpu["DPC_us"] > 0).sum())
    # Total CPUs in the system — prefer trace.cpu_count, else fall back to
    # "every CPU the dumper saw".
    total_cpus = trace.cpu_count
    if not total_cpus:
        dumper_df = trace.dumper_df
        if dumper_df is not None and not dumper_df.empty and "CPU" in dumper_df.columns:
            try:
                total_cpus = int(dumper_df["CPU"].max()) + 1
            except (TypeError, ValueError):
                total_cpus = None

    expected_per_cpu = (total_us / active_cpus) if active_cpus else 0
    expected_uniform = (total_us / total_cpus) if total_cpus else 0

    summary_lines = [
        f"**NIC module matched:** `{nic_module}` (case-insensitive substring)",
        f"**Active CPUs:** {active_cpus}"
        + (f" of {total_cpus} total" if total_cpus else "")
        + f" (total DPC time: {total_us:,.0f} us)",
    ]
    if active_cpus and expected_per_cpu:
        summary_lines.append(
            f"**Mean DPC time per active CPU:** {expected_per_cpu:,.0f} us"
        )
    if total_cpus:
        summary_lines.append(
            f"**Expected per-CPU DPC time if uniformly distributed across {total_cpus} CPUs:** "
            f"{expected_uniform:,.0f} us"
        )
        if active_cpus and active_cpus < total_cpus:
            summary_lines.append(
                f"**RSS spread:** {active_cpus} of {total_cpus} CPUs handled `{nic_module}` DPCs "
                f"({active_cpus / total_cpus * 100:.0f}% of the system) — "
                "indicates RSS queue count is limiting parallelism."
            )

    header = f"**Per-NIC-Queue Arrivals** — `{nic_module}` DPC distribution"
    return (
        f"{header}\n\n"
        + format_table(display, max_rows=max_rows)
        + "\n\n"
        + "\n".join(summary_lines)
    )


# ---------------------------------------------------------------------------
# get_udp_dispatch_quality
# ---------------------------------------------------------------------------


@mcp.tool()
def get_udp_dispatch_quality(
    trace_id: str,
    port: int | None = None,
    min_samples: int = 25,
    max_rows: int = 30,
) -> str:
    """UDP recv-path sample distribution per process / CPU.

    For each process whose CPU samples touch UDP-recv-path code, this lists
    the CPUs the samples landed on and overlaps that set with the
    networking-DPC CPUs. Big cross-CPU % is the inefficiency CPUMAP fixes.

    "UDP recv path" is matched heuristically on the top-frame module
    (tcpip.sys, afd.sys, ws2_32.dll, mswsock.dll) plus a function-name hint
    (``Udp``, ``Datagram``, ``Dgram``). Phase 3 AFD events will replace this
    heuristic with per-socket attribution.

    The ``port`` argument is accepted but currently a no-op — per-port
    attribution needs AFD recv events (Phase 3) and is not derivable from
    the SampledProfile stream.

    Args:
        trace_id: ID returned by load_trace.
        port: Reserved — accepted for forward-compat, ignored today.
        min_samples: Minimum UDP-path sample count for a process to appear.
            Default: 25 (lower than the RSS tool because UDP-path filtering
            already narrows the population).
        max_rows: Maximum process rows. Default: 30.
    """
    trace = require_trace(trace_id)

    nic_cpus, _ = _nic_dpc_cpu_set(trace)
    dumper_df = trace.wait_for_dumper()

    if _empty_or_missing(dumper_df):
        return "*No SampledProfile (dumper) data available — UDP dispatch quality needs per-CPU samples.*"

    df = dumper_df
    required = {"Process Name", "CPU", "Module", "Function", "Weight"}
    missing = required - set(df.columns)
    if missing:
        return f"*dumper_df missing required columns: {sorted(missing)}.*"

    # Heuristic UDP recv-path filter on the top frame.
    udp_module_lower = {m.lower() for m in _UDP_PATH_MODULES}
    module_lc = df["Module"].astype(str).str.lower()
    func_lc = df["Function"].astype(str).str.lower()
    udp_mask = module_lc.isin(udp_module_lower) & func_lc.apply(
        lambda f: any(hint in f for hint in _UDP_FUNCTION_HINTS)
    )
    udp_df = df[udp_mask]

    if udp_df.empty:
        return (
            "*No UDP-recv-path samples found.* "
            "Heuristic matches top frames in tcpip.sys/afd.sys/ws2_32.dll/mswsock.dll "
            "whose function name contains 'udp', 'datagram', or 'dgram'."
        )

    rows = []
    for proc, group in udp_df.groupby("Process Name", dropna=False):
        sample_count = int(len(group))
        if sample_count < min_samples:
            continue
        cpu_weights = group.groupby("CPU")["Weight"].sum()
        total_weight = float(cpu_weights.sum())
        if total_weight <= 0:
            continue
        recv_cpus = sorted(int(c) for c in cpu_weights.index.tolist())
        if nic_cpus:
            cross_weight = float(
                cpu_weights[~cpu_weights.index.isin(nic_cpus)].sum()
            )
            cross_pct = cross_weight / total_weight * 100.0
            cross_pct_str = format_pct(cross_pct)
        else:
            cross_pct_str = "n/a"

        def _fmt_cpu_list(cpus: list[int]) -> str:
            if len(cpus) <= 8:
                return ",".join(str(c) for c in cpus)
            return ",".join(str(c) for c in cpus[:8]) + f",... (+{len(cpus) - 8})"

        rows.append({
            "Process Name": str(proc),
            "UDP samples": sample_count,
            "Recv CPUs": len(recv_cpus),
            "Recv CPU list": _fmt_cpu_list(recv_cpus),
            "NIC-DPC CPUs": len(nic_cpus),
            "Cross-CPU %": cross_pct_str,
            "_sort": total_weight,
        })

    if not rows:
        return (
            "*No process met the UDP-path sample threshold "
            f"({min_samples}).*"
        )

    result = pd.DataFrame(rows).sort_values("_sort", ascending=False).drop(columns=["_sort"])
    result = result.head(max_rows).reset_index(drop=True)

    notes = []
    if port is not None:
        notes.append(
            f"*Note:* `port={port}` is accepted but ignored — per-port attribution "
            "requires AFD recv events (Phase 3 dependency)."
        )
    if not nic_cpus:
        notes.append(
            "*Note:* no networking-DPC CPUs detected, so the Cross-CPU % column is `n/a`. "
            "Re-collect the trace with the DPC/ISR kernel flag."
        )

    header = "**UDP Dispatch Quality** (per-process recv CPU spread vs. NIC-DPC CPUs)"
    body = format_table(result, max_rows=max_rows)
    if notes:
        return f"{header}\n\n{body}\n\n" + "\n".join(notes)
    return f"{header}\n\n{body}"


__all__ = [
    "get_rss_dispatch_quality",
    "get_per_nic_queue_arrivals",
    "get_udp_dispatch_quality",
]
