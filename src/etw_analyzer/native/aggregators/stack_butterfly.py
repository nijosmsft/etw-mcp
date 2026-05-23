"""Aggregator: ``stacks`` — replacement for ``xperf -a stack -butterfly``.

Output DataFrame schema mirrors :func:`parsing.wpa_exporter._parse_stack_butterfly_html`::

    Module, Function, Inclusive, Exclusive, Weight, Total %

Algorithm
---------
For every SampledProfile row with a paired ``Stack`` (set by the Phase
N2 stack-pairing buffer):

* The leaf frame (index 0) is the *executing* function — contributes
  to its Exclusive count.
* Every frame in the stack contributes to its own Inclusive count.

We symbolize every unique address across every stack via
``trace.symbolizer.bulk_resolve``, group by (module, function), and
compute Total % against the sum of Exclusive counts (matches xperf's
denominator).

v1 caveat
~~~~~~~~~
This module ships the simpler "Functions by UniInclusive Hits"
table only. The caller/callee table (``stacks_callers``) is wired in
:func:`aggregate_stack_callers` — its v1 produces a minimal set of
caller edges sufficient for ``walk_stack`` / ``butterfly_chain`` and
flagged as a known gap in the commit message.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import TYPE_CHECKING, Optional

import pandas as pd

if TYPE_CHECKING:
    from etw_analyzer.trace_state import TraceData


_SYM_RE = re.compile(r"^([^!]+)!([^+]+)(?:\+0x[0-9a-fA-F]+)?$")
_SYM_FALLBACK_RE = re.compile(r"^([^+]+)\+0x[0-9a-fA-F]+$")


def _split_label(label: str) -> tuple[str, str]:
    if not label:
        return "unknown", ""
    m = _SYM_RE.match(label)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    m = _SYM_FALLBACK_RE.match(label)
    if m:
        return m.group(1).strip(), ""
    return label, ""


def _collect_unique_addresses(stacks: list[tuple[int, ...]]) -> list[int]:
    seen: set[int] = set()
    for stk in stacks:
        for addr in stk:
            if addr:
                seen.add(int(addr))
    return list(seen)


def aggregate_stack_butterfly(
    trace: "TraceData",
    *,
    max_stacks: int = 200_000,
) -> Optional[pd.DataFrame]:
    """Build the ``stacks`` DataFrame from native SampledProfile + StackWalk.

    Parameters
    ----------
    trace:
        Trace with ``dumper_df`` populated; rows whose ``Stack`` column
        is a non-empty tuple contribute frames.
    max_stacks:
        Hard cap on the number of stacks symbolized. The default keeps
        big traces' load times bounded — production samples can reach
        millions of stack events, and the dbghelp cost is the dominant
        factor.

    Returns ``None`` when no stacks have been paired or the trace lacks
    a symbolizer (in which case nothing can be attributed by symbol).
    """
    dumper = trace.dumper_df
    if dumper is None or dumper.empty:
        return None
    if "Stack" not in dumper.columns:
        return None

    weight_col = "Weight" if "Weight" in dumper.columns else None

    # Only rows with a real Stack contribute. Numpy isnull doesn't work
    # on object-typed tuples; pick by truthiness.
    stacks_with_weight: list[tuple[tuple[int, ...], int]] = []
    for stack, w in zip(
        dumper["Stack"].tolist(),
        (dumper[weight_col].tolist() if weight_col else [1] * len(dumper)),
    ):
        if isinstance(stack, tuple) and stack:
            stacks_with_weight.append((stack, int(w) if w else 1))
            if len(stacks_with_weight) >= max_stacks:
                break

    if not stacks_with_weight:
        return None

    symbolizer = getattr(trace, "symbolizer", None)
    if symbolizer is None:
        return None

    unique_addrs = _collect_unique_addresses([s for s, _w in stacks_with_weight])
    if not unique_addrs:
        return None

    try:
        addr_to_label = symbolizer.bulk_resolve(unique_addrs)
    except Exception:
        return None

    # Pre-split labels once.
    label_to_pair: dict[str, tuple[str, str]] = {}

    def _pair_for(addr: int) -> tuple[str, str]:
        label = addr_to_label.get(addr, "")
        pair = label_to_pair.get(label)
        if pair is None:
            pair = _split_label(label)
            label_to_pair[label] = pair
        return pair

    inclusive: dict[tuple[str, str], int] = defaultdict(int)
    exclusive: dict[tuple[str, str], int] = defaultdict(int)

    for stk, weight in stacks_with_weight:
        # Leaf is the executing function — contributes to Exclusive.
        leaf_addr = int(stk[0])
        leaf_pair = _pair_for(leaf_addr)
        exclusive[leaf_pair] += weight

        seen_in_stack: set[tuple[str, str]] = set()
        for addr in stk:
            pair = _pair_for(int(addr))
            if pair in seen_in_stack:
                continue
            seen_in_stack.add(pair)
            inclusive[pair] += weight

    total_exclusive = sum(exclusive.values()) or 1

    rows: list[dict] = []
    keys = set(inclusive.keys()) | set(exclusive.keys())
    for module, function in keys:
        incl = inclusive.get((module, function), 0)
        excl = exclusive.get((module, function), 0)
        rows.append({
            "Module": module,
            "Function": function,
            "Inclusive": incl,
            "Exclusive": excl,
            "Weight": incl,
            "Total %": round(excl / total_exclusive * 100.0, 2),
        })

    df = pd.DataFrame(rows)
    if df.empty:
        return None
    df = df.sort_values("Inclusive", ascending=False).reset_index(drop=True)
    return df


def aggregate_stack_callers(
    trace: "TraceData",
    *,
    max_stacks: int = 200_000,
) -> Optional[pd.DataFrame]:
    """Build a minimal ``stacks_callers`` DataFrame.

    Columns match :func:`parsing.wpa_exporter.parse_stack_butterfly_callers`::

        Target_Module, Target_Function, Direction, Caller_Module,
        Caller_Function, Weight, Total %, Parent %, Exclusive

    v1 produces only the ``Direction='caller'`` rows — one entry per
    distinct (target → caller) edge across paired stacks. The
    ``Direction='callee'`` and ``Direction='self'`` rows xperf emits
    in its HTML output are out of scope for this phase; downstream
    ``walk_stack`` / ``butterfly_chain`` tools already gracefully
    handle a smaller frame set.
    """
    dumper = trace.dumper_df
    if dumper is None or dumper.empty:
        return None
    if "Stack" not in dumper.columns:
        return None

    weight_col = "Weight" if "Weight" in dumper.columns else None
    stacks_with_weight: list[tuple[tuple[int, ...], int]] = []
    for stack, w in zip(
        dumper["Stack"].tolist(),
        (dumper[weight_col].tolist() if weight_col else [1] * len(dumper)),
    ):
        if isinstance(stack, tuple) and len(stack) >= 2:
            stacks_with_weight.append((stack, int(w) if w else 1))
            if len(stacks_with_weight) >= max_stacks:
                break

    if not stacks_with_weight:
        return None

    symbolizer = getattr(trace, "symbolizer", None)
    if symbolizer is None:
        return None

    unique_addrs = _collect_unique_addresses([s for s, _w in stacks_with_weight])
    if not unique_addrs:
        return None
    try:
        addr_to_label = symbolizer.bulk_resolve(unique_addrs)
    except Exception:
        return None

    edges: dict[tuple[str, str, str, str], int] = defaultdict(int)
    target_totals: dict[tuple[str, str], int] = defaultdict(int)
    target_exclusive: dict[tuple[str, str], int] = defaultdict(int)
    for stk, weight in stacks_with_weight:
        # Leaf first; (callee=stk[i], caller=stk[i+1]) for each adjacent pair.
        for i in range(len(stk) - 1):
            callee_lbl = addr_to_label.get(int(stk[i]), "")
            caller_lbl = addr_to_label.get(int(stk[i + 1]), "")
            tm, tf = _split_label(callee_lbl)
            cm, cf = _split_label(caller_lbl)
            edges[(tm, tf, cm, cf)] += weight
            target_totals[(tm, tf)] += weight
        leaf_lbl = addr_to_label.get(int(stk[0]), "")
        tm0, tf0 = _split_label(leaf_lbl)
        target_exclusive[(tm0, tf0)] += weight

    rows: list[dict] = []
    grand_total = sum(target_totals.values()) or 1
    for (tm, tf, cm, cf), weight in edges.items():
        target_total = target_totals.get((tm, tf), 1)
        rows.append({
            "Target_Module": tm,
            "Target_Function": tf,
            "Direction": "caller",
            "Caller_Module": cm,
            "Caller_Function": cf,
            "Weight": weight,
            "Total %": round(weight / grand_total * 100.0, 2),
            "Parent %": round(weight / target_total * 100.0, 2),
            "Exclusive": target_exclusive.get((tm, tf), 0),
        })

    if not rows:
        return None
    df = pd.DataFrame(rows)
    df = df.sort_values("Weight", ascending=False).reset_index(drop=True)
    return df


__all__ = ["aggregate_stack_butterfly", "aggregate_stack_callers"]
