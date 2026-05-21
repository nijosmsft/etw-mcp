"""ETL trace export — uses xperf.exe to extract data from ETL traces."""

from __future__ import annotations

import csv
import io
import os
import re
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path

import pandas as pd

# Standard install locations for xperf (Windows Performance Toolkit)
_WPT_SEARCH_PATHS = [
    Path(r"C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit"),
    Path(r"C:\Program Files\Windows Kits\10\Windows Performance Toolkit"),
]


def find_xperf() -> Path | None:
    """Find xperf.exe on the system."""
    for wpt_dir in _WPT_SEARCH_PATHS:
        xperf = wpt_dir / "xperf.exe"
        if xperf.exists():
            return xperf

    import shutil
    found = shutil.which("xperf")
    if found:
        return Path(found)

    return None


def find_wpaexporter() -> Path | None:
    """Find wpaexporter.exe (kept for potential future use)."""
    for wpt_dir in _WPT_SEARCH_PATHS:
        wpa = wpt_dir / "wpaexporter.exe"
        if wpa.exists():
            return wpa

    import shutil
    found = shutil.which("wpaexporter")
    return Path(found) if found else None


def _run_xperf(
    etl_path: Path,
    action: str,
    action_args: list[str] | None = None,
    symbol_path: str | None = None,
    symbols: bool = True,
    timeout_seconds: int = 300,
) -> str:
    """Run xperf with the given action and return stdout."""
    xperf = find_xperf()
    if xperf is None:
        raise FileNotFoundError(
            "xperf.exe not found. Install Windows Performance Toolkit "
            "(part of Windows SDK/ADK)."
        )

    cmd = [str(xperf), "-i", str(etl_path)]
    if symbols:
        cmd.append("-symbols")
    cmd.extend(["-a", action])
    if action_args:
        cmd.extend(action_args)

    env = os.environ.copy()
    if symbol_path:
        env["_NT_SYMBOL_PATH"] = symbol_path

    # CREATE_NO_WINDOW prevents xperf from writing progress bars
    # directly to the console handle (bypassing stdout/stderr capture)
    import sys
    creation_flags = 0
    if sys.platform == "win32":
        creation_flags = subprocess.CREATE_NO_WINDOW

    try:
        result = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            env=env,
            creationflags=creation_flags,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"xperf timed out after {timeout_seconds}s. "
            "Try a shorter trace or increase timeout."
        )

    # xperf sometimes returns non-zero but still produces output
    output = result.stdout
    if not output and result.returncode != 0:
        raise RuntimeError(
            f"xperf -a {action} failed (exit {result.returncode}):\n"
            f"stderr: {result.stderr[:1000]}"
        )

    return output


def _run_xperf_lines(
    etl_path: Path,
    action: str,
    action_args: list[str] | None = None,
    symbol_path: str | None = None,
    symbols: bool = True,
    timeout_seconds: int = 300,
) -> Iterator[str]:
    """Run xperf and yield stdout one line at a time.

    Same arg semantics as ``_run_xperf``. This variant uses ``subprocess.Popen``
    and streams ``proc.stdout`` line-by-line so callers can process gigabyte-scale
    output (e.g. ``xperf -a dumper``) without buffering the whole thing in memory.

    Notes:
      * Timeout: ``Popen`` has no built-in timeout. A ``threading.Timer`` arms
        ``proc.kill()`` after ``timeout_seconds``; the iterator then raises
        ``RuntimeError``. The timer is cancelled in the ``finally`` block.
      * Stderr: redirected to ``DEVNULL``. The blocking variant captures stderr
        only to format error messages; in streaming mode we can't safely block
        on ``communicate()`` to retrieve it without risking a pipe-deadlock with
        the (potentially huge) stdout we're already consuming, so we discard it.
      * Non-zero exit: tolerated if any output was produced — matches the
        behavior of ``_run_xperf`` (xperf is noisy about returning non-zero on
        traces it still successfully dumped).
      * Cleanup: if the caller stops iterating early (``break``, exception),
        the generator's ``finally`` calls ``proc.terminate()`` + ``wait()`` so
        the child process doesn't outlive us.
    """
    xperf = find_xperf()
    if xperf is None:
        raise FileNotFoundError(
            "xperf.exe not found. Install Windows Performance Toolkit "
            "(part of Windows SDK/ADK)."
        )

    cmd = [str(xperf), "-i", str(etl_path)]
    if symbols:
        cmd.append("-symbols")
    cmd.extend(["-a", action])
    if action_args:
        cmd.extend(action_args)

    env = os.environ.copy()
    if symbol_path:
        env["_NT_SYMBOL_PATH"] = symbol_path

    import sys
    creation_flags = 0
    if sys.platform == "win32":
        creation_flags = subprocess.CREATE_NO_WINDOW

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,  # line-buffered
        env=env,
        creationflags=creation_flags,
    )

    timed_out = {"flag": False}

    def _on_timeout() -> None:
        timed_out["flag"] = True
        try:
            proc.kill()
        except OSError:
            pass

    timer = threading.Timer(timeout_seconds, _on_timeout)
    timer.daemon = True
    timer.start()

    produced_any = False
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            produced_any = True
            yield line.rstrip("\r\n")

        if timed_out["flag"]:
            raise RuntimeError(
                f"xperf timed out after {timeout_seconds}s. "
                "Try a shorter trace or increase timeout."
            )

        # Drain & reap. Tolerate non-zero exit only if we got output.
        proc.wait()
        if proc.returncode != 0 and not produced_any:
            raise RuntimeError(
                f"xperf -a {action} failed (exit {proc.returncode}); "
                "no stdout produced."
            )
    finally:
        timer.cancel()
        if proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except OSError:
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        if proc.stdout is not None:
            try:
                proc.stdout.close()
            except OSError:
                pass


def _parse_profile_detail(text: str) -> pd.DataFrame:
    """Parse xperf -a profile -detail output into a DataFrame.

    Format:
       Process Name ( PID),     Weight,    Usage %,          Module Name!Function Name
    """
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Process Name"):
            continue

        # Parse: "   Process Name ( PID),     Weight,    Usage %,          Module!Function"
        parts = line.split(",")
        if len(parts) < 4:
            continue

        try:
            proc_raw = parts[0].strip()
            weight = int(parts[1].strip())
            usage_pct = float(parts[2].strip())
            mod_func = ",".join(parts[3:]).strip()  # rejoin in case function has commas
        except (ValueError, IndexError):
            continue

        # Parse process name and PID
        m = re.match(r"(.+?)\(\s*(\d+)\s*\)", proc_raw)
        if m:
            process_name = m.group(1).strip()
            pid = int(m.group(2))
        else:
            process_name = proc_raw
            pid = 0

        # Parse module!function
        if "!" in mod_func:
            module, function = mod_func.split("!", 1)
            module = module.strip().strip('"')
            function = function.strip().strip('"')
        else:
            module = mod_func.strip().strip('"')
            function = ""

        rows.append({
            "Process Name": process_name,
            "PID": pid,
            "Weight": weight,
            "% Weight": usage_pct,
            "Module": module,
            "Function": function,
        })

    return pd.DataFrame(rows)


def _parse_dpcisr(text: str) -> pd.DataFrame:
    """Parse xperf -a dpcisr output into a DataFrame.

    Extracts per-module duration histograms. The format is:
        Total = 2068066 for module NDIS.SYS
        Elapsed Time, >  0 usecs AND <=  1 usecs, 6318, or 0.31%
        ...

    Returns DataFrame with columns: Module, Bucket_Low_us, Bucket_High_us, Count, Pct
    """
    rows = []
    current_module = None

    for line in text.splitlines():
        stripped = line.strip()

        # Detect module header: "Total = 2068066 for module NDIS.SYS"
        m = re.match(r"Total\s*=\s*(\d+)\s+for\s+module\s+(\S+)", stripped)
        if m:
            current_module = m.group(2)
            continue

        # Global total (no module): "Total = 2752216"
        if re.match(r"^Total\s*=\s*\d+$", stripped):
            current_module = "(all)"
            continue

        # Histogram line: "Elapsed Time, > 0 usecs AND <= 1 usecs, 6318, or 0.31%"
        m = re.match(
            r"Elapsed Time,\s*>\s*(\d+)\s*usecs\s+AND\s*<=\s*(\d+)\s*usecs,\s*(\d+),\s*or\s*([\d.]+)%",
            stripped,
        )
        if m and current_module:
            rows.append({
                "Module": current_module,
                "Bucket_Low_us": int(m.group(1)),
                "Bucket_High_us": int(m.group(2)),
                "Count": int(m.group(3)),
                "Pct": float(m.group(4)),
            })
            continue

        # "Total," line at end of histogram — reset module
        if stripped.startswith("Total,") and current_module:
            current_module = None

    return pd.DataFrame(rows)


def parse_readythread_stacks(text: str) -> pd.DataFrame:
    """Parse ``xperf -a readythread -stacks`` output into a DataFrame.

    The format alternates between ReadyThread event lines and Stack frame lines::

        ReadyThread, TimeStamp, Process Name (PID), ThreadID, Rdy Process Name (PID), Rdy TID, AdjustReason, AdjustIncrement, InDPC
            Stack, TimeStamp, ThreadID, No., Address, Image!Function

    Returns DataFrame with one row per event, columns:
        TimeStamp, ProcessName, PID, ThreadID, ReadyingProcessName, ReadyPID,
        ReadyTID, AdjustReason, InDPC, ReadyThreadStack
    where ReadyThreadStack is frames joined with " / ".
    """
    rows: list[dict] = []
    current_event: dict | None = None
    current_stack: list[str] = []

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("ReadyThread,"):
            # Skip header line: "ReadyThread, TimeStamp, Process Name ..."
            if "TimeStamp" in stripped and "Process Name" in stripped:
                continue

            # Flush previous event
            if current_event is not None:
                current_event["ReadyThread Stack"] = " / ".join(current_stack)
                rows.append(current_event)

            # Parse: ReadyThread, TimeStamp, "ProcessName" (PID), ThreadID,
            #         ReadyProcessName (PID), ReadyTID, AdjustReason, AdjustIncrement, InDPC
            parts = stripped.split(",")
            if len(parts) < 8:
                current_event = None
                current_stack = []
                continue

            # Extract process name and PID from quoted format: "ProcessName" ( PID)
            # or unquoted: ProcessName ( PID)
            proc_field = parts[2].strip()
            ready_field = parts[4].strip()

            def _parse_proc(field: str) -> tuple[str, int]:
                m = re.match(r'"?([^"]*)"?\s*\(\s*(-?\d+)\)', field)
                if m:
                    return m.group(1).strip(), int(m.group(2))
                return field, -1

            proc_name, pid = _parse_proc(proc_field)
            ready_name, ready_pid = _parse_proc(ready_field)

            current_event = {
                "TimeStamp": int(parts[1].strip()),
                "New Process Name": proc_name,
                "PID": pid,
                "ThreadID": int(parts[3].strip()),
                "Readying Process Name": ready_name,
                "ReadyPID": ready_pid,
                "ReadyTID": int(parts[5].strip()),
                "AdjustReason": parts[6].strip(),
                "InDPC": parts[-1].strip() if len(parts) > 8 else "",
            }
            current_stack = []

        elif stripped.startswith("Stack,") and current_event is not None:
            # Stack, TimeStamp, ThreadID, No., Address, Image!Function
            parts = stripped.split(",", 5)
            if len(parts) >= 6:
                func = parts[5].strip()
                current_stack.append(func)

    # Flush last event
    if current_event is not None:
        current_event["ReadyThread Stack"] = " / ".join(current_stack)
        rows.append(current_event)

    return pd.DataFrame(rows)


def run_readythread(
    etl_path: Path,
    symbol_path: str | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
    timeout_seconds: int = 300,
) -> pd.DataFrame:
    """Run ``xperf -a readythread -stacks`` and return parsed DataFrame.

    Args:
        etl_path: Path to the .etl file.
        symbol_path: Symbol path for resolution.
        start_time: Start of time range in seconds (converted to microseconds for xperf).
        end_time: End of time range in seconds.
        timeout_seconds: Max seconds for xperf.

    Returns:
        DataFrame with ReadyThread events and flattened stacks.
    """
    action_args = ["-stacks"]
    if start_time is not None or end_time is not None:
        t1 = int((start_time or 0) * 1_000_000)
        t2 = int((end_time or 999999) * 1_000_000)
        action_args.extend(["-range", str(t1), str(t2)])

    text = _run_xperf(
        etl_path, "readythread", action_args,
        symbol_path=symbol_path,
        symbols=True,
        timeout_seconds=timeout_seconds,
    )
    return parse_readythread_stacks(text)


def _parse_profile_utilization(text: str) -> pd.DataFrame:
    """Parse xperf -a profile (no -detail) — per-CPU utilization timeline.

    Format: CSV with StartTime, EndTime, Cpu 0, Cpu 1, ...
    """
    lines = text.splitlines()
    if not lines:
        return pd.DataFrame()

    # Find header line
    header_idx = None
    for i, line in enumerate(lines):
        if "StartTime" in line and "Cpu" in line:
            header_idx = i
            break

    if header_idx is None:
        return pd.DataFrame()

    csv_text = "\n".join(lines[header_idx:])
    return pd.read_csv(io.StringIO(csv_text), skipinitialspace=True)


def _strip_html_cell(cell: str) -> str:
    """Strip tags/entities from a small HTML table cell."""
    import html as html_mod

    return html_mod.unescape(re.sub(r"<[^>]+>", "", cell)).strip().lstrip("\xa0").strip()


def _parse_int_cell(value: str) -> int:
    """Parse an integer-like HTML table cell."""
    cleaned = value.replace(",", "").replace("%", "").strip()
    if not cleaned:
        return 0
    try:
        return int(float(cleaned))
    except ValueError:
        return 0


def _parse_pct_cell(value: str) -> float:
    """Parse a percent-like HTML table cell."""
    cleaned = value.replace(",", "").replace("%", "").strip()
    if not cleaned:
        return 0.0
    try:
        return float(cleaned)
    except ValueError:
        return 0.0


def _html_section_by_heading(html_text: str, heading: str) -> str:
    """Return the HTML section that starts at a specific h2 heading."""
    start = html_text.find(f"<h2>{heading}</h2>")
    if start == -1:
        return ""
    end = html_text.find("<h2>", start + 1)
    return html_text[start:end if end != -1 else len(html_text)]


def _html_table_rows(section: str) -> list[list[str]]:
    """Return stripped table cells for every row in an HTML section."""
    rows: list[list[str]] = []
    for tr_match in re.finditer(r"<tr[^>]*>(.*?)</tr>", section, re.DOTALL):
        cells = re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", tr_match.group(1), re.DOTALL)
        rows.append([_strip_html_cell(cell) for cell in cells])
    return rows


def _split_module_function(value: str) -> tuple[str, str] | None:
    """Split a module!function cell."""
    if "!" not in value:
        return None
    module, function = value.split("!", 1)
    module = module.strip()
    function = re.sub(r"\s*\(trimmed\)\s*$", "", function.strip())
    if not module or not function:
        return None
    return module, function


def _parse_stack_butterfly_html(html_text: str) -> pd.DataFrame:
    """Parse xperf -a stack -butterfly HTML output into a DataFrame.

    The HTML contains multiple tables. We extract rows from all tables
    that have module!function entries with hit counts.

    HTML row format:
      <tr class='ff'><td><a href='...'>module</a>!<a href='...'>function</a></td>
      <td>12345</td><td>67890</td><td>12.34%</td></tr>

    Or without links:
      <tr class='pf'><td>&nbsp;module!function</td><td></td><td>123</td><td>0.05%</td></tr>
    """
    records: dict[tuple[str, str], dict] = {}

    def ensure_record(module: str, function: str) -> dict:
        key = (module, function)
        if key not in records:
            records[key] = {
                "Module": module,
                "Function": function,
                "Inclusive": 0,
                "Exclusive": 0,
                "Weight": 0,
                "Total %": 0.0,
            }
        return records[key]

    # xperf's "Functions by UniInclusive Hits" table has the accurate
    # function-level inclusive/exclusive pair:
    # function, inclusive hits, total percent, exclusive hits, ...
    si_section = _html_section_by_heading(html_text, "Functions by UniInclusive Hits")
    if si_section:
        for cells in _html_table_rows(si_section):
            if len(cells) < 4 or cells[0].lower().startswith("function name"):
                continue
            split = _split_module_function(cells[0])
            if split is None:
                continue
            module, function = split
            rec = ensure_record(module, function)
            rec["Inclusive"] = max(rec["Inclusive"], _parse_int_cell(cells[1]))
            rec["Total %"] = max(rec["Total %"], _parse_pct_cell(cells[2]))
            rec["Exclusive"] = max(rec["Exclusive"], _parse_int_cell(cells[3]))

    # The exclusive table repeats the same pair in a different sort order and
    # is useful for older/corrupt SI sections:
    # function, exclusive hits, total percent, inclusive hits, ...
    se_section = _html_section_by_heading(html_text, "Functions by Exclusive Hits")
    if se_section:
        for cells in _html_table_rows(se_section):
            if len(cells) < 4 or cells[0].lower().startswith("function name"):
                continue
            split = _split_module_function(cells[0])
            if split is None:
                continue
            module, function = split
            rec = ensure_record(module, function)
            rec["Exclusive"] = max(rec["Exclusive"], _parse_int_cell(cells[1]))
            rec["Total %"] = max(rec["Total %"], _parse_pct_cell(cells[2]))
            rec["Inclusive"] = max(rec["Inclusive"], _parse_int_cell(cells[3]))

    # Unit-test and older-export fallback: parse any simple module!function row
    # with at least one numeric cell as a flat sample.
    if not records:
        for cells in _html_table_rows(html_text):
            if len(cells) < 2 or cells[0].lower().startswith("function name"):
                continue
            func_cell = cells[0]
            if func_cell.startswith("-->") or func_cell.startswith("<--"):
                continue
            split = _split_module_function(func_cell)
            if split is None:
                continue
            module, function = split
            weight = _parse_int_cell(cells[1])
            if weight <= 0:
                continue
            rec = ensure_record(module, function)
            rec["Inclusive"] = max(rec["Inclusive"], weight)
            rec["Exclusive"] = max(rec["Exclusive"], weight)

    rows = []
    for rec in records.values():
        rec["Weight"] = rec["Inclusive"]
        rows.append(rec)

    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values("Inclusive", ascending=False).reset_index(drop=True)

    return df


def parse_stack_butterfly_callers(html_text: str) -> pd.DataFrame:
    """Parse caller/callee relationships from xperf butterfly HTML.

    Extracts data from the TblSN section ("Functions by Multi-Inclusive Hits
    with Callers and Callees"). Center function rows are plain module!function;
    callee rows are prefixed with --> and caller rows with <--.

    Returns DataFrame with columns:
        Target_Module, Target_Function, Direction, Caller_Module, Caller_Function, Weight
    where Direction is 'caller' (<--) or 'callee' (-->).
    """
    # Focus on the multi-inclusive caller/callee section.
    section = _html_section_by_heading(
        html_text,
        "Functions by Multi-Inclusive Hits with Callers and Callees",
    )
    if not section:
        sn_start = html_text.find("id='TblSN'")
        if sn_start == -1:
            return pd.DataFrame()
        sn_end = html_text.find("id='TblSE'", sn_start)
        if sn_end == -1:
            sn_end = len(html_text)
        section = html_text[sn_start:sn_end]

    rows: list[dict] = []
    center_func: str | None = None
    center_mod: str | None = None

    for cells in _html_table_rows(section):
        if len(cells) < 2:
            continue

        func_cell = cells[0]
        if not func_cell or func_cell.lower().startswith("function name"):
            continue
        if "!" not in func_cell and "***itself***" not in func_cell:
            continue

        hits = _parse_int_cell(cells[1]) if len(cells) > 1 else 0
        total_pct = _parse_pct_cell(cells[2]) if len(cells) > 2 else 0.0
        parent_pct = _parse_pct_cell(cells[3]) if len(cells) > 3 else 0.0
        exclusive = _parse_int_cell(cells[4]) if len(cells) > 4 else 0

        if func_cell.startswith("-->"):
            raw = func_cell[3:].strip()
            split = _split_module_function(raw)
            if split is not None and center_func is not None:
                mod, func = split
                rows.append({
                    "Target_Module": center_mod,
                    "Target_Function": center_func,
                    "Direction": "callee",
                    "Caller_Module": mod,
                    "Caller_Function": func,
                    "Weight": hits,
                    "Total %": total_pct,
                    "Parent %": parent_pct,
                    "Exclusive": exclusive,
                })
        elif func_cell.startswith("<--"):
            raw = func_cell[3:].strip()
            split = _split_module_function(raw)
            if split is not None and center_func is not None:
                mod, func = split
                rows.append({
                    "Target_Module": center_mod,
                    "Target_Function": center_func,
                    "Direction": "caller",
                    "Caller_Module": mod,
                    "Caller_Function": func,
                    "Weight": hits,
                    "Total %": total_pct,
                    "Parent %": parent_pct,
                    "Exclusive": exclusive,
                })
        elif "***itself***" in func_cell:
            pass
        else:
            split = _split_module_function(func_cell)
            if split is None:
                continue
            center_mod, center_func = split
            # Keep center stats as node metadata rows for stack-walk tools.
            rows.append({
                "Target_Module": center_mod,
                "Target_Function": center_func,
                "Direction": "self",
                "Caller_Module": center_mod,
                "Caller_Function": center_func,
                "Weight": hits,
                "Total %": total_pct,
                "Parent %": 100.0,
                "Exclusive": exclusive,
            })

    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values("Weight", ascending=False).reset_index(drop=True)

    return df


def _parse_proc_field(field: str) -> tuple[str, int]:
    """Parse a "Process Name ( PID)" field into (name, pid).

    Returns ("", 0) if unparseable so callers can still emit a row.
    """
    field = field.strip()
    m = re.match(r'"?([^"]*)"?\s*\(\s*(-?\d+)\s*\)', field)
    if m:
        return m.group(1).strip(), int(m.group(2))
    return field, 0


def _handle_sampled_profile(
    parts: list[str],
    *,
    cpu_filter: set[int] | None,
) -> dict | None:
    """Handler for ``SampledProfile`` dumper lines.

    Layout (column positions, 0-indexed; broadly stable across builds):
        0: "SampledProfile"
        1: TimeStamp
        2: "Process Name ( PID)"
        3: ThreadID
        4: PrgrmCtr
        5: CPU
        6: ThreadStartImage!Function
        7: Image!Function
        8: Count
        9+: Type/extras (ignored)
    """
    if len(parts) < 8:
        return None
    try:
        timestamp = int(parts[1].strip())
        cpu = int(parts[5].strip())
    except (ValueError, IndexError):
        return None

    if cpu_filter is not None and cpu not in cpu_filter:
        return None

    process_name, pid = _parse_proc_field(parts[2])

    img_func = parts[7].strip()
    if "!" in img_func:
        module, function = img_func.split("!", 1)
        module = module.strip()
        function = function.strip()
    else:
        module = img_func
        function = "Unknown"

    try:
        count = int(parts[8].strip())
    except (ValueError, IndexError):
        count = 1

    return {
        "TimeStamp": timestamp,
        "Process Name": process_name,
        "PID": pid,
        "CPU": cpu,
        "Module": module,
        "Function": function,
        "Weight": count,
    }


def _handle_cswitch(parts: list[str], **_kwargs) -> dict | None:
    """Handler for ``CSwitch`` dumper lines.

    Stable column layout used here (varies across Windows builds — be
    defensive, skip on parse failure):

        0:  "CSwitch"
        1:  TimeStamp
        2:  "New Process Name ( PID)"
        3:  New TID
        4:  NPri (new priority)
        5:  NQnt (new quantum)
        6:  NWaitTime (irrelevant)
        7:  "Old Process Name ( PID)"
        8:  Old TID
        9:  OPri (old priority)
        10: OQnt
        11: OldState
        12: WaitReason
        13+: Swapable, InSwitchTime, CPU, IdealProc, OldRemQnt, NewPriDecr, PrevCState

    Newer builds add columns after position 12; older may have fewer. We
    only require the columns up through WaitReason and try to find CPU near
    the tail. Anything we can't parse → return None to drop the row.

    Emits columns: TimeStamp, NewProcessName, NewPID, NewTID, OldProcessName,
    OldPID, OldTID, WaitReason, OldState, CPU, NewPriority, OldPriority.
    """
    if len(parts) < 13:
        return None

    try:
        timestamp = int(parts[1].strip())
        new_tid = int(parts[3].strip())
        old_tid = int(parts[8].strip())
    except (ValueError, IndexError):
        return None

    new_name, new_pid = _parse_proc_field(parts[2])
    old_name, old_pid = _parse_proc_field(parts[7])

    # Priorities (best-effort)
    try:
        new_pri = int(parts[4].strip())
    except (ValueError, IndexError):
        new_pri = -1
    try:
        old_pri = int(parts[9].strip())
    except (ValueError, IndexError):
        old_pri = -1

    old_state = parts[11].strip()
    wait_reason = parts[12].strip()

    # CPU is at position 15 in the standard recent-build layout:
    #   13:Swapable, 14:InSwitchTime, 15:CPU, 16:IdealProc, ...
    # If position 15 isn't a valid CPU number, fall back to scanning a wider
    # window for the first small non-negative integer that looks like a CPU
    # number (skip very large values which are timing fields).
    cpu = -1
    if len(parts) > 15:
        try:
            cpu = int(parts[15].strip())
        except (ValueError, IndexError):
            cpu = -1
    if cpu < 0 or cpu >= 4096:
        # Layout drift fallback. Skip Swapable (small boolean) and
        # InSwitchTime (potentially large timestamp) by looking past them.
        cpu = -1
        for idx in range(14, min(len(parts), 19)):
            candidate = parts[idx].strip()
            try:
                value = int(candidate)
            except ValueError:
                continue
            # CPU numbers are 0..4095 in practice. Also exclude obvious
            # InSwitchTime values (typically much larger).
            if 0 <= value < 4096:
                cpu = value
                break

    return {
        "TimeStamp": timestamp,
        "NewProcessName": new_name,
        "NewPID": new_pid,
        "NewTID": new_tid,
        "OldProcessName": old_name,
        "OldPID": old_pid,
        "OldTID": old_tid,
        "WaitReason": wait_reason,
        "OldState": old_state,
        "CPU": cpu,
        "NewPriority": new_pri,
        "OldPriority": old_pri,
    }


# ---------------------------------------------------------------------------
# TCPIP / UDP handlers — Phase 3a
# ---------------------------------------------------------------------------
#
# xperf's dumper format for kernel TcpIp/UdpIp events is not well documented.
# What we know from the MOF schemas (Microsoft-Windows-Kernel-Network /
# Microsoft-Windows-TCPIP) — see TcpIp_TypeGroup1 / UdpIp_TypeGroup1 /
# TcpIp_TypeGroup2 docs:
#
#   TcpIp_TypeGroup1 (Recv, Retransmit, Disconnect):
#     PID, size, daddr, saddr, dport, sport, seqnum, connid
#   TcpIp_TypeGroup2 (Connect, Accept):
#     PID, size, daddr, saddr, dport, sport, mss, sackopt, tsopt, wsopt,
#     rcvwin, rcvwinscale, sndwinscale, seqnum, connid
#   UdpIp_TypeGroup1 (Send, Recv):
#     PID, size, daddr, saddr, dport, sport, seqnum, connid
#
# xperf's dumper prepends its standard event header to every line: event
# name, TimeStamp, Process Name (PID), ThreadID, CPU. After that the
# event-specific fields appear in MOF-defined order.
#
# Our handlers parse by *position* (best-effort) but are defensive:
#   - Return None on any parse failure rather than crashing
#   - Tolerate variable column counts (older builds, IPv6 variants)
#   - Accept addresses as opaque strings (xperf renders dotted-quad/IPv6
#     literals)
#
# The exact column count for each event class will need to be validated
# against a real .wprp-collected trace. Until then, treat this code as
# best-effort and prefer skipping malformed rows over guessing.

# Layout assumption shared by every TCPIP/UDP handler. The first 5 columns
# come from xperf's standard event header (event name, TimeStamp,
# Process Name ( PID), ThreadID, CPU); the remainder are event-specific.
_TCPIP_HEADER_COLS = 5  # event_name, TimeStamp, Process(PID), ThreadID, CPU


def _parse_int_or_none(value: str) -> int | None:
    """Parse an integer, returning None on failure."""
    value = value.strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _parse_tcpip_header(parts: list[str]) -> dict | None:
    """Parse the leading 5-column header common to every TCPIP/UDP dumper line.

    Layout (best-effort; will need validation against a real trace):
        0: event name (e.g. "TcpIp/Recv" or "TcpIp_Recv")
        1: TimeStamp (uint)
        2: "Process Name ( PID)"
        3: ThreadID (uint, may be -1 if not attributable)
        4: CPU (uint)

    Returns dict with TimeStamp/Process Name/PID/ThreadID/CPU, or None on
    parse failure.
    """
    if len(parts) < _TCPIP_HEADER_COLS:
        return None
    timestamp = _parse_int_or_none(parts[1])
    if timestamp is None:
        return None
    process_name, pid = _parse_proc_field(parts[2])
    tid = _parse_int_or_none(parts[3])
    cpu = _parse_int_or_none(parts[4])
    return {
        "TimeStamp": timestamp,
        "Process Name": process_name,
        "PID": pid,
        "ThreadID": tid if tid is not None else -1,
        "CPU": cpu if cpu is not None else -1,
    }


def _handle_tcpip_recv_or_send(parts: list[str], **_kwargs) -> dict | None:
    """Handler for TcpIp/Recv and TcpIp/Send dumper lines.

    Best-effort layout (MOF TcpIp_TypeGroup1, prefixed with xperf header):

        0: event name (TcpIp/Recv | TcpIp_Recv | TcpIp/Send | TcpIp_Send)
        1: TimeStamp
        2: Process Name ( PID)
        3: ThreadID
        4: CPU
        5: size           (uint32)
        6: daddr          (IPv4/IPv6 string)
        7: saddr          (IPv4/IPv6 string)
        8: dport          (uint16)
        9: sport          (uint16)
        10: seqnum        (uint32)
        11: connid        (uint32, optional)

    The Phase 3 plan column schema asks for: TimeStamp, Process Name, PID,
    ThreadID, CPU, LocalAddr, LocalPort, RemoteAddr, RemotePort, Size, SeqNo.
    For Recv: source = remote, dest = local. For Send: source = local,
    dest = remote.

    Returns None if the header doesn't parse. Missing event-specific fields
    are filled with sensible defaults so downstream code can rely on the
    schema.
    """
    header = _parse_tcpip_header(parts)
    if header is None:
        return None

    event_name = parts[0].strip()
    is_recv = "recv" in event_name.lower() or "receive" in event_name.lower()

    size = _parse_int_or_none(parts[5]) if len(parts) > 5 else None
    daddr = parts[6].strip() if len(parts) > 6 else ""
    saddr = parts[7].strip() if len(parts) > 7 else ""
    dport = _parse_int_or_none(parts[8]) if len(parts) > 8 else None
    sport = _parse_int_or_none(parts[9]) if len(parts) > 9 else None
    seqnum = _parse_int_or_none(parts[10]) if len(parts) > 10 else None
    connid = _parse_int_or_none(parts[11]) if len(parts) > 11 else None

    # On Recv: daddr/dport = local (our side), saddr/sport = remote.
    # On Send: daddr/dport = remote, saddr/sport = local.
    if is_recv:
        local_addr, local_port = daddr, dport
        remote_addr, remote_port = saddr, sport
    else:
        local_addr, local_port = saddr, sport
        remote_addr, remote_port = daddr, dport

    return {
        **header,
        "LocalAddr": local_addr,
        "LocalPort": local_port if local_port is not None else 0,
        "RemoteAddr": remote_addr,
        "RemotePort": remote_port if remote_port is not None else 0,
        "Size": size if size is not None else 0,
        "SeqNo": seqnum if seqnum is not None else 0,
        "ConnId": connid if connid is not None else 0,
    }


def _handle_tcpip_retransmit(parts: list[str], **_kwargs) -> dict | None:
    """Handler for TcpIp/Retransmit dumper lines.

    Best-effort layout (MOF TcpIp_TypeGroup1):

        Same as recv/send + an optional ``RetransmitCount`` field that some
        xperf builds emit after the connid column. If absent we treat each
        retransmit event as a single retransmission (count = 1) — the
        per-connection aggregator sums these.

    Treated as send-direction (local → remote) for the addr columns.
    """
    base = _handle_tcpip_recv_or_send(parts, **_kwargs)
    if base is None:
        return None

    # Retransmit fields beyond the standard tuple are inconsistent across
    # builds. If a 12th field is present and integer-ish, treat it as the
    # retransmit count.
    rtx_count = 1
    if len(parts) > 12:
        parsed = _parse_int_or_none(parts[12])
        if parsed is not None and parsed > 0:
            rtx_count = parsed

    base["RetransmitCount"] = rtx_count
    return base


def _handle_tcpip_connect_or_accept(parts: list[str], **_kwargs) -> dict | None:
    """Handler for TcpIp/Connect and TcpIp/Accept dumper lines.

    Best-effort layout (MOF TcpIp_TypeGroup2). The schema is wider than
    TypeGroup1 because it includes handshake-establishment options. xperf
    typically emits:

        0-4: event header (name, TimeStamp, Process(PID), ThreadID, CPU)
        5:   size
        6:   daddr
        7:   saddr
        8:   dport
        9:   sport
        10:  mss          (handshake)
        11:  sackopt
        12:  tsopt
        13:  wsopt
        14:  rcvwin
        15:  rcvwinscale
        16:  sndwinscale
        17:  seqnum
        18:  connid

    Accept = inbound (our side is the destination = local).
    Connect = outbound (our side is the source = local).
    """
    header = _parse_tcpip_header(parts)
    if header is None:
        return None

    event_name = parts[0].strip()
    is_accept = "accept" in event_name.lower()

    size = _parse_int_or_none(parts[5]) if len(parts) > 5 else None
    daddr = parts[6].strip() if len(parts) > 6 else ""
    saddr = parts[7].strip() if len(parts) > 7 else ""
    dport = _parse_int_or_none(parts[8]) if len(parts) > 8 else None
    sport = _parse_int_or_none(parts[9]) if len(parts) > 9 else None
    mss = _parse_int_or_none(parts[10]) if len(parts) > 10 else None
    rcvwin = _parse_int_or_none(parts[14]) if len(parts) > 14 else None
    seqnum = _parse_int_or_none(parts[17]) if len(parts) > 17 else None
    connid = _parse_int_or_none(parts[18]) if len(parts) > 18 else None

    if is_accept:
        local_addr, local_port = daddr, dport
        remote_addr, remote_port = saddr, sport
    else:
        local_addr, local_port = saddr, sport
        remote_addr, remote_port = daddr, dport

    return {
        **header,
        "LocalAddr": local_addr,
        "LocalPort": local_port if local_port is not None else 0,
        "RemoteAddr": remote_addr,
        "RemotePort": remote_port if remote_port is not None else 0,
        "Size": size if size is not None else 0,
        "MSS": mss if mss is not None else 0,
        "RcvWin": rcvwin if rcvwin is not None else 0,
        "SeqNo": seqnum if seqnum is not None else 0,
        "ConnId": connid if connid is not None else 0,
    }


# ---------------------------------------------------------------------------
# AFD / NDIS handlers — Phase 3b
# ---------------------------------------------------------------------------
#
# AFD events come from the Microsoft-Windows-Winsock-AFD provider when the
# Phase 0.1 networking.wprp profile is in use. xperf's dumper does not
# publish a stable, documented column layout for AFD events — the layouts
# below are best-effort and derived from the MOF/manifest field order, with
# defensive parsing throughout. Every helper returns ``None`` rather than
# raising when a field is missing or malformed.
#
# Column layout assumed for the AFD I/O events (Recv / Send), prefixed with
# xperf's standard 5-column event header:
#
#     0: event name (e.g. "AFD/Recv" or "AFD_Recv")
#     1: TimeStamp (uint)
#     2: "Process Name ( PID)"
#     3: ThreadID
#     4: CPU
#     5: SocketHandle (hex or decimal)
#     6: Size            (uint, may be 0 for control events)
#     7: CompletionStatus (uint / NTSTATUS, may be -1)
#
# For Connect / Accept:
#     5: SocketHandle
#     6: LocalAddr
#     7: LocalPort
#     8: RemoteAddr
#     9: RemotePort
#
# For Close:
#     5: SocketHandle
#
# NdisDrop events (Microsoft-Windows-NDIS dropped-packet) layout assumed:
#     0: event name
#     1: TimeStamp
#     2: Process Name ( PID)  (may be "<unknown>")
#     3: ThreadID
#     4: CPU
#     5: MiniportName / FriendlyName
#     6: Reason (string, e.g. "MissingBuffer")
#     7: Size (bytes)
#
# All of this needs validation against a real trace. Document the
# assumption rather than guess — handlers degrade to "" / 0 when columns
# are missing.


def _parse_socket_handle(value: str) -> int:
    """Parse a socket handle from a column (decimal, "0x" hex, or bare hex).

    Returns 0 on failure — sockets routinely round-trip through user-mode
    as 64-bit identifiers and we want a single integer key for grouping.
    """
    value = value.strip().strip('"')
    if not value:
        return 0
    try:
        if value.lower().startswith("0x"):
            return int(value, 16)
        return int(value)
    except ValueError:
        # Some xperf builds emit pointer-style handles like "FFFFAB00..."
        try:
            return int(value, 16)
        except ValueError:
            return 0


def _handle_afd_recv_or_send(parts: list[str], **_kwargs) -> dict | None:
    """Handler for AFD/Recv and AFD/Send dumper lines."""
    header = _parse_tcpip_header(parts)
    if header is None:
        return None

    handle = _parse_socket_handle(parts[5]) if len(parts) > 5 else 0
    size = _parse_int_or_none(parts[6]) if len(parts) > 6 else None
    status = _parse_int_or_none(parts[7]) if len(parts) > 7 else None

    return {
        **header,
        "SocketHandle": handle,
        "Size": size if size is not None else 0,
        "CompletionStatus": status if status is not None else 0,
    }


def _handle_afd_connect_or_accept(parts: list[str], **_kwargs) -> dict | None:
    """Handler for AFD/Connect and AFD/Accept dumper lines.

    5-tuple fields are optional — older builds emit only the socket handle.
    """
    header = _parse_tcpip_header(parts)
    if header is None:
        return None

    handle = _parse_socket_handle(parts[5]) if len(parts) > 5 else 0
    local_addr = parts[6].strip() if len(parts) > 6 else ""
    local_port = _parse_int_or_none(parts[7]) if len(parts) > 7 else None
    remote_addr = parts[8].strip() if len(parts) > 8 else ""
    remote_port = _parse_int_or_none(parts[9]) if len(parts) > 9 else None

    return {
        **header,
        "SocketHandle": handle,
        "LocalAddr": local_addr,
        "LocalPort": local_port if local_port is not None else 0,
        "RemoteAddr": remote_addr,
        "RemotePort": remote_port if remote_port is not None else 0,
    }


def _handle_afd_close(parts: list[str], **_kwargs) -> dict | None:
    """Handler for AFD/Close dumper lines (just the socket handle)."""
    header = _parse_tcpip_header(parts)
    if header is None:
        return None

    handle = _parse_socket_handle(parts[5]) if len(parts) > 5 else 0
    return {
        **header,
        "SocketHandle": handle,
    }


def _handle_ndis_drop(parts: list[str], **_kwargs) -> dict | None:
    """Handler for NDIS dropped-packet dumper lines.

    Layout is provider-specific and not stable across builds. We extract:
    TimeStamp, MiniportName, Reason, Size — process attribution is usually
    "<unknown>" because the drop happens before socket dispatch.
    """
    # We reuse _parse_tcpip_header for the leading 5 columns but tolerate the
    # process-name field being "<unknown>" or empty — _parse_proc_field already
    # falls back gracefully.
    header = _parse_tcpip_header(parts)
    if header is None:
        return None

    miniport = parts[5].strip() if len(parts) > 5 else ""
    reason = parts[6].strip() if len(parts) > 6 else ""
    size = _parse_int_or_none(parts[7]) if len(parts) > 7 else None

    return {
        **header,
        "MiniportName": miniport,
        "Reason": reason,
        "Size": size if size is not None else 0,
    }


def _handle_udp_recv_or_send(parts: list[str], **_kwargs) -> dict | None:
    """Handler for UdpIp/Recv and UdpIp/Send dumper lines.

    Best-effort layout (MOF UdpIp_TypeGroup1) — identical to TcpIp_TypeGroup1
    minus the seqnum/connid (UDP has no sequence numbers semantically, but
    the MOF still defines fields for them; we accept any value).

        0-4: header
        5:   size
        6:   daddr
        7:   saddr
        8:   dport
        9:   sport
        10:  seqnum (may be 0 — UDP has no real sequence)
        11:  connid (may be 0)

    Recv: dest = local. Send: source = local.
    """
    header = _parse_tcpip_header(parts)
    if header is None:
        return None

    event_name = parts[0].strip()
    is_recv = "recv" in event_name.lower() or "receive" in event_name.lower()

    size = _parse_int_or_none(parts[5]) if len(parts) > 5 else None
    daddr = parts[6].strip() if len(parts) > 6 else ""
    saddr = parts[7].strip() if len(parts) > 7 else ""
    dport = _parse_int_or_none(parts[8]) if len(parts) > 8 else None
    sport = _parse_int_or_none(parts[9]) if len(parts) > 9 else None

    if is_recv:
        local_addr, local_port = daddr, dport
        remote_addr, remote_port = saddr, sport
    else:
        local_addr, local_port = saddr, sport
        remote_addr, remote_port = daddr, dport

    return {
        **header,
        "LocalAddr": local_addr,
        "LocalPort": local_port if local_port is not None else 0,
        "RemoteAddr": remote_addr,
        "RemotePort": remote_port if remote_port is not None else 0,
        "Size": size if size is not None else 0,
    }


# Dispatch table. Each entry maps a *canonical* event-class name to a
# handler. The canonical name is what callers pass in ``event_classes``,
# what gets used as a DataFrame key, and what the cache parquet stem is
# derived from in :func:`tools.trace_mgmt._start_background_dumper`.
#
# The canonical names use the slash form (e.g. "TcpIp/Recv"). Real xperf
# dumper output may emit either slash or underscore separators (e.g.
# "TcpIp_Recv" or "TcpIpRecv"). The prefix set used at parse time is
# defined separately in :data:`_EVENT_PREFIX_ALIASES` so the dispatch
# tolerates all observed forms.
EVENT_HANDLERS = {
    "SampledProfile": _handle_sampled_profile,
    "CSwitch": _handle_cswitch,
    "TcpIp/Recv": _handle_tcpip_recv_or_send,
    "TcpIp/Send": _handle_tcpip_recv_or_send,
    "TcpIp/Retransmit": _handle_tcpip_retransmit,
    "TcpIp/Connect": _handle_tcpip_connect_or_accept,
    "TcpIp/Accept": _handle_tcpip_connect_or_accept,
    "UdpIp/Recv": _handle_udp_recv_or_send,
    "UdpIp/Send": _handle_udp_recv_or_send,
    # Phase 3b: AFD socket-level events + NDIS drops
    "AFD/Recv": _handle_afd_recv_or_send,
    "AFD/Send": _handle_afd_recv_or_send,
    "AFD/Connect": _handle_afd_connect_or_accept,
    "AFD/Accept": _handle_afd_connect_or_accept,
    "AFD/Close": _handle_afd_close,
    "NdisDrop": _handle_ndis_drop,
}


def _alias_set(*aliases: str) -> frozenset[str]:
    return frozenset(aliases)


# Map canonical class name → set of dumper line prefixes that should
# dispatch to it. Built conservatively from observed xperf behavior:
# slash form, underscore form, and squashed form (e.g. "TcpIpRecv"). Keep
# this in sync with EVENT_HANDLERS — every canonical class needs an entry.
_EVENT_PREFIX_ALIASES: dict[str, frozenset[str]] = {
    "SampledProfile":   _alias_set("SampledProfile"),
    "CSwitch":          _alias_set("CSwitch"),
    "TcpIp/Recv":       _alias_set("TcpIp/Recv", "TcpIp_Recv", "TcpIpRecv"),
    "TcpIp/Send":       _alias_set("TcpIp/Send", "TcpIp_Send", "TcpIpSend"),
    "TcpIp/Retransmit": _alias_set(
        "TcpIp/Retransmit", "TcpIp_Retransmit", "TcpIpRetransmit"
    ),
    "TcpIp/Connect":    _alias_set("TcpIp/Connect", "TcpIp_Connect", "TcpIpConnect"),
    "TcpIp/Accept":     _alias_set("TcpIp/Accept", "TcpIp_Accept", "TcpIpAccept"),
    "UdpIp/Recv":       _alias_set("UdpIp/Recv", "UdpIp_Recv", "UdpIpRecv"),
    "UdpIp/Send":       _alias_set("UdpIp/Send", "UdpIp_Send", "UdpIpSend"),
    # Phase 3b. AFD events are namespaced by the Winsock-AFD provider; xperf
    # may emit any of these forms depending on the build.
    "AFD/Recv":         _alias_set("AFD/Recv", "AFD_Recv", "AFDRecv", "Afd/Recv"),
    "AFD/Send":         _alias_set("AFD/Send", "AFD_Send", "AFDSend", "Afd/Send"),
    "AFD/Connect":      _alias_set("AFD/Connect", "AFD_Connect", "AFDConnect", "Afd/Connect"),
    "AFD/Accept":       _alias_set("AFD/Accept", "AFD_Accept", "AFDAccept", "Afd/Accept"),
    "AFD/Close":        _alias_set("AFD/Close", "AFD_Close", "AFDClose", "Afd/Close"),
    # NDIS dropped-packet event. Different xperf builds label this as
    # "NdisDrop", "NDIS/Drop", "Ndis/Drop", or "PacketDrop".
    "NdisDrop":         _alias_set("NdisDrop", "NDIS/Drop", "Ndis/Drop", "NDIS_Drop", "PacketDrop"),
}


# Event names we explicitly want to ignore (similar prefix to wanted classes).
_EVENT_SKIP_PREFIXES = frozenset({
    "SampledProfileNmi",
})


def parse_dumper_events(
    etl_path: Path,
    symbol_path: str | None = None,
    cpu_filter: set[int] | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
    timeout_seconds: int = 300,
    event_classes: set[str] | None = None,
) -> dict[str, pd.DataFrame]:
    """Single-pass dumper extraction with multi-event dispatch.

    Streams ``xperf -a dumper`` stdout line-by-line and dispatches each line
    by its event-class prefix to a handler in :data:`EVENT_HANDLERS`. Each
    handler produces row dicts, which are collected per class and turned into
    DataFrames at the end.

    Args:
        etl_path: Path to the .etl file.
        symbol_path: Optional ``_NT_SYMBOL_PATH`` override.
        cpu_filter: Restrict ``SampledProfile`` rows to these CPUs.
        start_time: Window start (seconds from trace start).
        end_time: Window end (seconds from trace start).
        timeout_seconds: xperf timeout.
        event_classes: Which classes to extract. Default
            ``{"SampledProfile", "CSwitch"}``. Pass a subset to skip work.

    Returns:
        ``{class_name: DataFrame}`` for every requested class. DataFrames
        are empty if no matching rows were found.

    Notes:
        - Dumper output can reach multiple GB on a CPU-sampling trace.
          Streaming is mandatory; we never buffer the full text.
        - The handler dispatch table is the Phase-3 keystone refactor —
          adding TCPIP/UDP/AFD/NDIS extraction is just one new handler per
          event class, no parser surgery required.
    """
    requested = event_classes if event_classes is not None else {"SampledProfile", "CSwitch"}
    # Only dispatch to handlers we know about AND that were requested.
    active_handlers = {
        name: handler
        for name, handler in EVENT_HANDLERS.items()
        if name in requested
    }
    if not active_handlers:
        return {name: pd.DataFrame() for name in requested}

    # Build range args (times in microseconds)
    action_args: list[str] = []
    if start_time is not None or end_time is not None:
        t1 = int((start_time or 0) * 1_000_000)
        t2 = int((end_time or 999999) * 1_000_000)
        action_args.extend(["-range", str(t1), str(t2)])

    # Cheap line prefilter to avoid splitting every line. For each active
    # handler, expand its canonical name into the set of accepted dumper
    # prefixes (see ``_EVENT_PREFIX_ALIASES``) — xperf may emit any of:
    # "TcpIp/Recv,", "TcpIp_Recv,", "TcpIpRecv,". Build a flat
    # (prefix → canonical name) list so the per-line scan is one pass.
    prefix_to_canonical: list[tuple[str, str]] = []
    for canonical in active_handlers:
        aliases = _EVENT_PREFIX_ALIASES.get(canonical, frozenset({canonical}))
        for alias in aliases:
            prefix_to_canonical.append((f"{alias},", canonical))
    skip_prefixes = tuple(f"{name}," for name in _EVENT_SKIP_PREFIXES)

    line_iter = _run_xperf_lines(
        etl_path, "dumper", action_args,
        symbol_path=symbol_path,
        symbols=True,
        timeout_seconds=timeout_seconds,
    )

    rows_by_class: dict[str, list[dict]] = {name: [] for name in active_handlers}

    for line in line_iter:
        # Strip leading whitespace once — many dumper lines have variable
        # indentation depending on event class.
        stripped = line.lstrip()
        if not stripped:
            continue

        # Skip explicitly-ignored event classes (e.g. SampledProfileNmi).
        if stripped.startswith(skip_prefixes):
            continue

        # Find the matching class prefix. List scan is O(prefixes) but our
        # prefix list is small (single-digit canonical classes × ~3 aliases).
        matched = None
        for prefix, canonical in prefix_to_canonical:
            if stripped.startswith(prefix):
                matched = canonical
                break
        if matched is None:
            continue

        # Skip xperf's header lines for this event class. xperf emits one
        # header per class with column names (e.g. "TimeStamp" in field 1).
        # The real timestamp is always numeric.
        parts = stripped.split(",")
        if len(parts) >= 2 and not parts[1].strip().lstrip("-").isdigit():
            continue

        try:
            row = active_handlers[matched](parts, cpu_filter=cpu_filter)
        except Exception:
            # Defensive: a malformed line should never crash the parser.
            continue
        if row is not None:
            rows_by_class[matched].append(row)

    return {name: pd.DataFrame(rows) for name, rows in rows_by_class.items()}


def parse_sampled_profile_events(
    etl_path: Path,
    symbol_path: str | None = None,
    cpu_filter: set[int] | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
    timeout_seconds: int = 300,
) -> pd.DataFrame:
    """Extract per-CPU SampledProfile events via xperf -a dumper.

    Thin backward-compat wrapper around :func:`parse_dumper_events`. Returns
    only the SampledProfile DataFrame — preserves the original single-class
    signature used by the existing background-dumper code path. New callers
    that need other event classes should use :func:`parse_dumper_events`
    directly.

    Returns DataFrame with columns: TimeStamp, Process Name, PID, CPU,
    Module, Function, Weight.
    """
    results = parse_dumper_events(
        etl_path=etl_path,
        symbol_path=symbol_path,
        cpu_filter=cpu_filter,
        start_time=start_time,
        end_time=end_time,
        timeout_seconds=timeout_seconds,
        event_classes={"SampledProfile"},
    )
    return results.get("SampledProfile", pd.DataFrame())


def _parse_pool(text: str) -> pd.DataFrame:
    """Parse xperf -a pool -pooltags -images output.

    Expected format (per pool type section):
        Image, Tag, Alloc #, Alloc KB, Out Alloc#, Out Alloc KB
        ndis.sys, NDnd, 12345, 678, 100, 50
    """
    rows = []
    current_pool_type = "Unknown"

    for line in text.splitlines():
        stripped = line.strip()

        # Detect pool type sections
        if "non-paged pool" in stripped.lower() or "paged pool" in stripped.lower():
            if "nx non-paged" in stripped.lower():
                current_pool_type = "NX NonPaged"
            elif "ex non-paged" in stripped.lower():
                current_pool_type = "EX NonPaged"
            elif "non-paged" in stripped.lower():
                current_pool_type = "NonPaged"
            elif "paged" in stripped.lower():
                current_pool_type = "Paged"
            continue

        # Skip headers and separators
        if stripped.startswith("Image") or stripped.startswith("---") or not stripped:
            continue

        # Parse data rows: "module.sys, Tag, num, num, num, num"
        parts = [p.strip() for p in stripped.split(",")]
        if len(parts) >= 6:
            try:
                image = parts[0]
                tag = parts[1]
                allocs = int(parts[2])
                alloc_kb = float(parts[3])
                out_allocs = int(parts[4])
                out_kb = float(parts[5])

                rows.append({
                    "PoolType": current_pool_type,
                    "Module": image,
                    "Tag": tag,
                    "Allocs": allocs,
                    "Alloc KB": alloc_kb,
                    "Outstanding": out_allocs,
                    "Outstanding KB": out_kb,
                })
            except (ValueError, IndexError):
                continue

    return pd.DataFrame(rows)


def _save_df(df: pd.DataFrame, output_dir: Path, name: str) -> Path:
    """Save a DataFrame as parquet (fast binary format)."""
    path = output_dir / f"{name}.parquet"
    df.to_parquet(path, index=False)
    return path


def _export_cpu_sampling(
    etl_path: Path, output_dir: Path, symbol_path: str | None, timeout: int,
) -> dict[str, Path]:
    """Export CPU sampling via xperf -a profile -detail."""
    results: dict[str, Path] = {}
    try:
        text = _run_xperf(
            etl_path, "profile", ["-detail"],
            symbol_path=symbol_path, symbols=True, timeout_seconds=timeout,
        )
        df = _parse_profile_detail(text)
        if not df.empty:
            results["cpu_sampling"] = _save_df(df, output_dir, "cpu_sampling")
            (output_dir / "profile-detail.txt").write_text(text, encoding="utf-8")
    except Exception as e:
        (output_dir / "cpu_sampling_error.txt").write_text(str(e))
    return results


def _export_cpu_timeline(
    etl_path: Path, output_dir: Path, symbol_path: str | None, timeout: int,
) -> dict[str, Path]:
    """Export per-CPU utilization via xperf -a profile."""
    results: dict[str, Path] = {}
    try:
        text = _run_xperf(
            etl_path, "profile", [],
            symbol_path=symbol_path, symbols=False, timeout_seconds=timeout,
        )
        df = _parse_profile_utilization(text)
        if not df.empty:
            results["cpu_timeline"] = _save_df(df, output_dir, "cpu_timeline")
    except Exception:
        pass
    return results


def _export_dpcisr(
    etl_path: Path, output_dir: Path, symbol_path: str | None, timeout: int,
) -> dict[str, Path]:
    """Export DPC/ISR histograms via xperf -a dpcisr."""
    results: dict[str, Path] = {}
    try:
        text = _run_xperf(
            etl_path, "dpcisr", [],
            symbol_path=symbol_path, symbols=False, timeout_seconds=timeout,
        )
        df = _parse_dpcisr(text)
        if not df.empty:
            results["dpc_isr"] = _save_df(df, output_dir, "dpc_isr")
        raw_path = output_dir / "dpcisr.txt"
        raw_path.write_text(text, encoding="utf-8")
        results["dpc_isr_raw"] = raw_path
    except Exception as e:
        (output_dir / "dpc_isr_error.txt").write_text(str(e))
    return results


def _export_cswitch(
    etl_path: Path, output_dir: Path, symbol_path: str | None, timeout: int,
) -> dict[str, Path]:
    """Export context switch data via xperf -a cswitch."""
    results: dict[str, Path] = {}
    try:
        text = _run_xperf(
            etl_path, "cswitch", [],
            symbol_path=symbol_path, symbols=False, timeout_seconds=timeout,
        )
        if text.strip():
            raw_path = output_dir / "cswitch.txt"
            raw_path.write_text(text, encoding="utf-8")
            results["cswitch_raw"] = raw_path
    except Exception:
        pass
    return results


def _export_stacks(
    etl_path: Path, output_dir: Path, symbol_path: str | None, timeout: int,
) -> dict[str, Path]:
    """Export call stacks via xperf -a stack -butterfly."""
    results: dict[str, Path] = {}
    try:
        text = _run_xperf(
            etl_path, "stack", ["-butterfly", "5"],
            symbol_path=symbol_path, symbols=True, timeout_seconds=timeout,
        )
        if text.strip():
            (output_dir / "stack-butterfly.html").write_text(text, encoding="utf-8")
            df = _parse_stack_butterfly_html(text)
            if not df.empty:
                results["stacks"] = _save_df(df, output_dir, "stacks")
            callers_df = parse_stack_butterfly_callers(text)
            if not callers_df.empty:
                results["stacks_callers"] = _save_df(callers_df, output_dir, "stacks_callers")
    except Exception as e:
        (output_dir / "stacks_error.txt").write_text(str(e))
    return results


def _export_tracestats(
    etl_path: Path, output_dir: Path, symbol_path: str | None, timeout: int,
) -> dict[str, Path]:
    """Export trace metadata via xperf -a tracestats."""
    results: dict[str, Path] = {}
    try:
        text = _run_xperf(
            etl_path, "tracestats", [],
            symbol_path=symbol_path, symbols=False, timeout_seconds=60,
        )
        if text.strip():
            raw_path = output_dir / "tracestats.txt"
            raw_path.write_text(text, encoding="utf-8")
            results["tracestats"] = raw_path
    except Exception:
        pass
    return results


def _export_sysconfig(
    etl_path: Path, output_dir: Path, symbol_path: str | None, timeout: int,
) -> dict[str, Path]:
    """Export system configuration via xperf -a sysconfig."""
    results: dict[str, Path] = {}
    try:
        text = _run_xperf(
            etl_path, "sysconfig", ["-cpu", "-nic", "-disk", "-memory"],
            symbol_path=symbol_path, symbols=False, timeout_seconds=60,
        )
        if text.strip():
            raw_path = output_dir / "sysconfig.txt"
            raw_path.write_text(text, encoding="utf-8")
            results["sysconfig"] = raw_path
    except Exception:
        pass
    return results


def _export_process_info(
    etl_path: Path, output_dir: Path, symbol_path: str | None, timeout: int,
) -> dict[str, Path]:
    """Export process/thread/image info via xperf -a process."""
    results: dict[str, Path] = {}
    try:
        text = _run_xperf(
            etl_path, "process", ["-withcmdline"],
            symbol_path=symbol_path, symbols=False, timeout_seconds=60,
        )
        if text.strip():
            raw_path = output_dir / "process_info.txt"
            raw_path.write_text(text, encoding="utf-8")
            results["process_info"] = raw_path
    except Exception:
        pass
    return results


def _export_diskio(
    etl_path: Path, output_dir: Path, symbol_path: str | None, timeout: int,
) -> dict[str, Path]:
    """Export disk I/O summary via xperf -a diskio."""
    results: dict[str, Path] = {}
    try:
        text = _run_xperf(
            etl_path, "diskio", ["-summary"],
            symbol_path=symbol_path, symbols=False, timeout_seconds=60,
        )
        if text.strip():
            raw_path = output_dir / "diskio.txt"
            raw_path.write_text(text, encoding="utf-8")
            results["diskio"] = raw_path
    except Exception:
        pass
    return results


def export_all_profiles(
    etl_path: Path,
    output_dir: Path,
    symbol_path: str | None = None,
    timeout_seconds: int = 300,
) -> dict[str, Path]:
    """Export all data from an ETL trace using xperf.

    Runs xperf actions in parallel and saves parsed data as parquet files.
    Raw text outputs (dpcisr, cswitch, tracestats) are saved as .txt.

    Returns:
        Dict of dataset_name → file path (.parquet or .txt).
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    xperf = find_xperf()
    if xperf is None:
        raise FileNotFoundError(
            "xperf.exe not found. Install Windows Performance Toolkit "
            "(part of Windows SDK/ADK).\n"
            "Expected at: C:\\Program Files (x86)\\Windows Kits\\10\\"
            "Windows Performance Toolkit\\xperf.exe"
        )

    output_dir.mkdir(parents=True, exist_ok=True)

    # Run all xperf actions in parallel (they are independent subprocesses)
    export_fns = [
        _export_cpu_sampling,
        _export_cpu_timeline,
        _export_dpcisr,
        _export_cswitch,
        _export_stacks,
        _export_tracestats,
        _export_sysconfig,
        _export_process_info,
        _export_diskio,
    ]

    results: dict[str, Path] = {}
    with ThreadPoolExecutor(max_workers=len(export_fns)) as executor:
        futures = {
            executor.submit(fn, etl_path, output_dir, symbol_path, timeout_seconds): fn.__name__
            for fn in export_fns
        }
        for future in as_completed(futures):
            try:
                partial = future.result()
                results.update(partial)
            except Exception:
                pass  # Individual export errors are handled inside each function

    return results
