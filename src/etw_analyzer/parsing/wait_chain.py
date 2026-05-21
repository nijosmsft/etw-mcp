"""Wait-chain walker over parsed CSwitch events.

For a target thread, finds the context-switch events that "woke it up" — the
events where ``NewTID == target_tid`` — and classifies them by ``WaitReason``.
This is a poor-man's Critical Path Analysis (CPA): we surface what kinds of
waits the thread is satisfying (thread-pool work, dispatch interrupts, lock
acquisitions, …) without doing the full ReadyThread correlation that real CPA
needs.

Limitations vs. full CPA:

- We do not correlate each wake with the readying thread's preceding switch-out.
  True causal-chain attribution requires the ``ReadyThread`` events
  (``Microsoft-Windows-Kernel-Process``) joined by timestamp to the CSwitch
  stream. v1 here only does the WaitReason histogram + a sample list.
- We do not walk recursively (``max_depth`` is reserved for v2 when ReadyThread
  joins land). The argument is accepted today so callers don't have to change
  later.
"""

from __future__ import annotations

import pandas as pd


# WaitReasons we surface as "interesting" causes of a thread waking up. These
# are the canonical kernel wait reasons that show up on networking-recv worker
# threads: dispatcher/preempted, thread-pool queue, alertable I/O wait, lock
# waits, and yield/quantum expiration. The set is informational only — the
# walker still returns every wake event regardless of reason.
INTERESTING_WAIT_REASONS = frozenset({
    "WrQueue",            # Worker waiting for thread-pool work
    "WrDispatchInt",      # Wait for dispatch interrupt
    "WrPreempted",        # Preempted by higher-priority thread
    "WrYieldExecution",   # Voluntary yield
    "WrAlertByThreadId",  # Alerted by another thread (typical for ALPC/IOCP)
    "WrResource",         # Waiting on a kernel resource
    "WrEventPair",        # Event-pair wait (used by some sync primitives)
    "WrUserRequest",      # Generic user-mode wait (e.g. WaitForSingleObject)
    "WrLpcReceive",       # ALPC receive
    "WrLpcReply",         # ALPC reply
})


def walk_wait_chain(
    cswitch_df: pd.DataFrame,
    target_tid: int,
    max_depth: int = 10,
    max_window_us: float = 1_000_000,
) -> list[dict]:
    """Walk context-switch wake events for ``target_tid``.

    Args:
        cswitch_df: DataFrame produced by ``parse_dumper_events`` for the
            ``CSwitch`` class. Must have ``NewTID`` and ``WaitReason``
            columns; other columns are passed through.
        target_tid: Thread ID to walk.
        max_depth: Reserved for v2 (ReadyThread correlation). Accepted
            today for API stability.
        max_window_us: Reserved for v2 (will bound the readying-chain walk).
            Accepted today for API stability.

    Returns:
        A list of dicts, one per CSwitch event where ``NewTID == target_tid``.
        Each dict carries the row's full column set so callers can build
        tables, histograms, or readying-chain queries.

        Empty list if the TID is not present in the trace or the DataFrame
        is empty.
    """
    # max_depth / max_window_us reserved for the v2 ReadyThread join. We
    # accept them today to keep the call sites stable across versions.
    del max_depth, max_window_us

    if cswitch_df is None or cswitch_df.empty:
        return []
    if "NewTID" not in cswitch_df.columns:
        return []

    target_rows = cswitch_df[cswitch_df["NewTID"] == target_tid]
    if target_rows.empty:
        return []

    # Preserve the DataFrame ordering — caller decides how to sort.
    return target_rows.to_dict(orient="records")


def summarize_wait_reasons(events: list[dict]) -> dict[str, int]:
    """Count occurrences per ``WaitReason``.

    Args:
        events: Output of :func:`walk_wait_chain`.

    Returns:
        ``{wait_reason: count}``. An event without a ``WaitReason`` field is
        counted under the empty string.
    """
    counts: dict[str, int] = {}
    for ev in events:
        reason = ev.get("WaitReason", "") or ""
        counts[reason] = counts.get(reason, 0) + 1
    return counts


def find_tids_for_process(
    cswitch_df: pd.DataFrame,
    process_substring: str,
) -> list[tuple[int, str, int]]:
    """Find TIDs whose owning process name contains ``process_substring``.

    Case-insensitive substring match against ``NewProcessName``. Returns
    a sorted list of ``(tid, process_name, sample_count)`` tuples sorted by
    sample count descending so the caller can surface the busiest worker
    threads first.

    Args:
        cswitch_df: Parsed CSwitch DataFrame.
        process_substring: Substring to look for in ``NewProcessName``.

    Returns:
        List of (tid, process_name, count) tuples. Empty list if no match.
    """
    if cswitch_df is None or cswitch_df.empty:
        return []
    if "NewProcessName" not in cswitch_df.columns or "NewTID" not in cswitch_df.columns:
        return []

    needle = process_substring.lower()
    mask = cswitch_df["NewProcessName"].astype(str).str.lower().str.contains(
        needle, regex=False, na=False
    )
    matched = cswitch_df[mask]
    if matched.empty:
        return []

    # Group by (TID, NewProcessName) — the same TID always belongs to the
    # same process, but include the name so the caller can render rich rows.
    grouped = (
        matched.groupby(["NewTID", "NewProcessName"], dropna=False)
        .size()
        .reset_index(name="Count")
        .sort_values("Count", ascending=False)
    )
    return [
        (int(row["NewTID"]), str(row["NewProcessName"]), int(row["Count"]))
        for _, row in grouped.iterrows()
    ]
