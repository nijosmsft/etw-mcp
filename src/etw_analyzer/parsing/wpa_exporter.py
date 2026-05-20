"""ETL trace export — uses xperf.exe to extract data from ETL traces."""

from __future__ import annotations

import csv
import io
import os
import re
import subprocess
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


def parse_sampled_profile_events(
    etl_path: Path,
    symbol_path: str | None = None,
    cpu_filter: set[int] | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
    timeout_seconds: int = 300,
) -> pd.DataFrame:
    """Extract per-CPU SampledProfile events via xperf -a dumper.

    Parses raw dumper output for SampledProfile lines which have the format:
        SampledProfile, TimeStamp, Process Name (PID), ThreadID, PrgrmCtr, CPU,
            ThreadStartImage!Function, Image!Function, Count, Type

    Returns DataFrame with columns: TimeStamp, Process Name, PID, CPU, Module, Function, Count
    """
    # Build range args (times in microseconds)
    action_args: list[str] = []
    if start_time is not None or end_time is not None:
        t1 = int((start_time or 0) * 1_000_000)
        t2 = int((end_time or 999999) * 1_000_000)
        action_args.extend(["-range", str(t1), str(t2)])

    text = _run_xperf(
        etl_path, "dumper", action_args,
        symbol_path=symbol_path,
        symbols=True,
        timeout_seconds=timeout_seconds,
    )

    rows = []
    for line in text.splitlines():
        # Match: "         SampledProfile,  timestamp, ..."
        if "SampledProfile," not in line or "SampledProfileNmi," in line:
            continue

        # Skip header lines
        stripped = line.strip()
        if stripped.startswith("SampledProfile,") and "TimeStamp" in stripped:
            continue

        parts = stripped.split(",")
        if len(parts) < 8:
            continue

        try:
            timestamp = int(parts[1].strip())
            cpu = int(parts[5].strip())
        except (ValueError, IndexError):
            continue

        # Apply CPU filter early to avoid building huge DataFrames
        if cpu_filter is not None and cpu not in cpu_filter:
            continue

        # Parse process name and PID: "Process Name ( PID)"
        proc_raw = parts[2].strip()
        m = re.match(r"(.+?)\(\s*(\d+)\s*\)", proc_raw)
        if m:
            process_name = m.group(1).strip()
            pid = int(m.group(2))
        else:
            process_name = proc_raw
            pid = 0

        # Parse Image!Function (field 7, 0-indexed)
        img_func = parts[7].strip()
        if "!" in img_func:
            module, function = img_func.split("!", 1)
            module = module.strip()
            function = function.strip()
        else:
            module = img_func
            function = "Unknown"

        # Count field (field 8)
        try:
            count = int(parts[8].strip())
        except (ValueError, IndexError):
            count = 1

        rows.append({
            "TimeStamp": timestamp,
            "Process Name": process_name,
            "PID": pid,
            "CPU": cpu,
            "Module": module,
            "Function": function,
            "Weight": count,
        })

    return pd.DataFrame(rows)


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
