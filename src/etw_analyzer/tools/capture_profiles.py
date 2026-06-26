"""MCP tools for capturing WPR/ETW traces (the complement to load_trace).

These tools are intentionally transport-agnostic: they emit paste-ready
PowerShell that can run on the local machine, a LabLink MCP target, an
SSH session, or be handed to a human to run. They do NOT invoke wpr.exe
themselves - the LLM workflow drives the capture on whatever transport
makes sense, then calls ``load_trace`` against the resulting .etl file.

Tool list:

- :func:`list_capture_profiles` - overview table of the 9 WPR scenarios
  plus the ``pktmon`` pseudo-scenario.
- :func:`get_capture_profile` - metadata + full ``.wprp`` XML for one
  scenario, ready to save to a file on the target.
- :func:`get_capture_commands` - 3-step paste-ready PowerShell
  (start / sleep / stop) for one scenario + output path + duration.
- :func:`get_capture_instructions` - long-form runbook including
  prerequisites, transfer-back examples (PowerShell remoting / LabLink
  / scp), and pointers at the analysis tools.

The pktmon scenario uses a different command set (``pktmon start
--capture`` instead of ``wpr -start``). All four tools branch on
``meta.capture_tool`` and handle it.
"""

from __future__ import annotations

import pandas as pd

from etw_analyzer.app import mcp
from etw_analyzer.formatting.markdown import format_table
from etw_analyzer.profiles.metadata import (
    PROFILES,
    ProfileMeta,
    load_wprp_text,
)


_VALID_TARGETS = ("local", "remote")
_VALID_MODES = ("file", "memory")
_MIN_DURATION = 1
_MAX_DURATION = 3600


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _valid_scenarios_csv() -> str:
    return ", ".join(sorted(PROFILES.keys()))


def _scenario_or_error(scenario: str) -> ProfileMeta | str:
    """Return the ProfileMeta for ``scenario``, or a friendly error string."""
    meta = PROFILES.get(scenario)
    if meta is None:
        return (
            f"Unknown scenario `{scenario}`. Valid scenarios: "
            f"{_valid_scenarios_csv()}.\n\n"
            "Call `list_capture_profiles()` for an overview table."
        )
    return meta


def _target_or_error(target: str) -> str | None:
    """Return None when target is valid, else a friendly error string."""
    if target not in _VALID_TARGETS:
        return (
            f"Unknown target `{target}`. Valid: "
            f"{', '.join(_VALID_TARGETS)}. Use `local` for "
            "captures on the same machine you're calling from, "
            "or `remote` to get the transfer-back examples."
        )
    return None


def _mode_or_error(mode: str) -> str | None:
    """Return None when the logging mode is valid, else an error string.

    ``mode`` selects the WPR logging mode (and therefore which bundled
    ``<Profile>`` variant ``wpr -start`` resolves):

    - ``"file"``   -> ``wpr -start <p>.wprp -filemode`` (writes straight
      to disk; the safe default).
    - ``"memory"`` -> ``wpr -start <p>.wprp`` (fixed-size RAM ring,
      merged to the ETL at ``-stop``; preferred for high-rate captures
      where file mode drops events).
    """
    if mode not in _VALID_MODES:
        return (
            f"Unknown mode `{mode}`. Valid: "
            f"{', '.join(_VALID_MODES)}. Use `file` to write straight to "
            "disk (default), or `memory` for a fixed-size RAM ring that "
            "is merged to the ETL at `wpr -stop` (preferred for high-rate "
            "captures where file mode drops events)."
        )
    return None


def _validate_capture_args(
    scenario: str, output_path: str, duration_s: int
) -> ProfileMeta | str:
    """Common validation for ``get_capture_commands`` /
    ``get_capture_instructions``. Returns the ProfileMeta on success
    or a friendly error string on failure."""
    meta_or_err = _scenario_or_error(scenario)
    if isinstance(meta_or_err, str):
        return meta_or_err
    if not output_path or not output_path.strip():
        return (
            "`output_path` must be a non-empty path (e.g. "
            "`C:\\traces\\capture.etl`).\n\n"
            "Call `list_capture_profiles()` to see the workflow."
        )
    if (
        not isinstance(duration_s, int)
        or duration_s < _MIN_DURATION
        or duration_s > _MAX_DURATION
    ):
        return (
            f"`duration_s` must be an integer between {_MIN_DURATION} "
            f"and {_MAX_DURATION} seconds (got {duration_s!r})."
        )
    return meta_or_err


def _metadata_table(meta: ProfileMeta) -> str:
    """Format a small markdown table summarizing ``meta``."""
    rows = [
        ("Title", meta.title),
        ("When to use", meta.when_to_use),
        ("Capture tool", meta.capture_tool),
        ("Privilege", meta.privilege),
        ("VM compatible", "yes" if meta.vm_compatible else "no"),
        (
            "Container compatible",
            "yes" if meta.container_compatible else "no",
        ),
        ("Recommended duration", f"{meta.recommended_duration_s} s"),
        ("Estimated overhead", meta.est_overhead),
        ("Providers", ", ".join(meta.providers) if meta.providers else "-"),
        (
            "Analysis tools",
            ", ".join(meta.analysis_tools) if meta.analysis_tools else "-",
        ),
    ]
    if meta.wprp_filename:
        rows.append(("Bundled .wprp", meta.wprp_filename))
    if meta.notes:
        rows.append(("Notes", meta.notes))
    df = pd.DataFrame(rows, columns=["Field", "Value"])
    return format_table(df, max_rows=len(rows) + 1)


def _build_wpr_commands(
    scenario: str, output_path: str, duration_s: int, mode: str = "file"
) -> str:
    """Render the 3-step PowerShell block for a WPR scenario.

    ``mode`` is ``"file"`` (emit ``-filemode``) or ``"memory"`` (omit
    ``-filemode`` so WPR uses the bundled ``LoggingMode="Memory"``
    variant). The unused mode is shown as a commented-out alternative.
    """
    wprp_filename = f"{scenario}.wprp"
    if mode == "memory":
        start_line = f"wpr -start .\\{wprp_filename}"
        mode_comment = (
            "# Memory (ring-buffer) logging mode: events are held in a "
            "fixed-size RAM ring and\n"
            "# merged to the ETL at -stop. Preferred for high-rate "
            "captures where file mode drops events.\n"
            "# Uses the bundled LoggingMode='Memory' profile variant "
            "(no '-filemode').\n"
        )
        alt_comment = (
            "# File-mode alternative (writes straight to disk) - add "
            "'-filemode':\n"
            f"#   wpr -start .\\{wprp_filename} -filemode\n"
        )
    else:
        start_line = f"wpr -start .\\{wprp_filename} -filemode"
        mode_comment = (
            "# File logging mode ('-filemode'): events are written "
            "straight to disk. Safe default.\n"
        )
        alt_comment = (
            "# Memory (ring-buffer) mode alternative - omit '-filemode' "
            "(preferred for high-rate captures):\n"
            f"#   wpr -start .\\{wprp_filename}\n"
        )
    return (
        "```powershell\n"
        "# Step 1 - Start capture.\n"
        f"# Save the XML from get_capture_profile('{scenario}') to "
        f".\\{wprp_filename} in the current directory first.\n"
        "# These profiles ship BOTH a File and a Memory logging-mode "
        "variant.\n"
        f"{mode_comment}"
        f"{start_line}\n"
        f"{alt_comment}"
        "\n"
        f"# Step 2 - Wait {duration_s} seconds (or do work during this window).\n"
        f"Start-Sleep -Seconds {duration_s}\n"
        "\n"
        "# Step 3 - Stop capture and write the ETL.\n"
        f"wpr -stop '{output_path}'\n"
        "\n"
        "# Step 4 (optional) - Verify the trace file was written.\n"
        f"Get-Item '{output_path}' | Select-Object FullName, Length, LastWriteTime\n"
        "```\n"
    )


def _build_pktmon_commands(output_path: str, duration_s: int) -> str:
    """Render the 3-step PowerShell block for the pktmon scenario."""
    return (
        "```powershell\n"
        "# Step 1 - Start pktmon all-traffic capture.\n"
        "# pktmon writes its own ETL; conversion to pcapng is optional.\n"
        f"pktmon start --capture --pkt-size 0 -f '{output_path}'\n"
        "\n"
        f"# Step 2 - Wait {duration_s} seconds (or do work during this window).\n"
        f"Start-Sleep -Seconds {duration_s}\n"
        "\n"
        "# Step 3 - Stop capture; pktmon flushes the file on exit.\n"
        "pktmon stop\n"
        "\n"
        "# Step 4 (optional) - Verify the trace file was written.\n"
        f"Get-Item '{output_path}' | Select-Object FullName, Length, LastWriteTime\n"
        "\n"
        "# Step 5 (optional) - Convert to pcapng for wireshark / tshark.\n"
        f"# pktmon etl2pcap '{output_path}' -o '{output_path}.pcapng'\n"
        "```\n"
    )


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def list_capture_profiles() -> str:
    """List the bundled WPR capture profiles + the pktmon pseudo-scenario.

    Use this as the entry point for any capture workflow. The output is
    a markdown table summarizing each scenario, followed by a workflow
    overview pointing at the other three capture tools.

    Workflow:

        list_capture_profiles
          -> get_capture_profile(scenario)        # see provider XML
          -> get_capture_commands(scenario, ...)  # paste-ready PowerShell
          -> run on target (any transport)
          -> load_trace(etl_path=...)             # analyze
    """
    rows = []
    for scenario in sorted(PROFILES.keys()):
        meta = PROFILES[scenario]
        rows.append(
            {
                "Scenario": scenario,
                "Title": meta.title,
                "When to use": meta.when_to_use,
                "Providers": ", ".join(meta.providers) if meta.providers else "-",
                "Est. overhead": meta.est_overhead,
            }
        )
    df = pd.DataFrame(rows)
    table = format_table(df, max_rows=len(rows) + 1)

    return (
        "**Capture profiles**\n"
        "\n"
        f"{table}\n"
        "\n"
        "**Workflow**\n"
        "\n"
        "1. Pick a scenario from the table.\n"
        "2. Call `get_capture_profile(scenario)` to view the bundled "
        "`.wprp` XML and metadata.\n"
        "3. Call `get_capture_commands(scenario, output_path, "
        "duration_s)` for paste-ready 3-step PowerShell.\n"
        "4. Run those commands on the target (local PowerShell, "
        "LabLink MCP target, SSH host, or hand them to a human). The "
        "tool is transport-agnostic.\n"
        "5. Transfer the resulting `.etl` back if you captured "
        "remotely, then call `load_trace(etl_path=...)` and use the "
        "analysis tools listed in `get_capture_profile`.\n"
        "\n"
        "**Notes**\n"
        "\n"
        "- Pass the scenario name (e.g. `cpu`), not the file path, "
        "to the subsequent tools.\n"
        "- `pktmon` is a separate mechanism (uses `pktmon start "
        "--capture --pkt-size 0`, not `wpr -start`). The same four "
        "tools handle it - they branch internally on the capture tool.\n"
        "- All WPR profiles require administrator elevation on the "
        "target machine. WPR uses the NT Kernel Logger and so cannot "
        "run inside a Windows container.\n"
    )


@mcp.tool()
def get_capture_profile(scenario: str) -> str:
    """Return metadata + the bundled .wprp XML for one capture scenario.

    Args:
        scenario: One of the IDs from ``list_capture_profiles``
            (e.g. ``"cpu"``, ``"network"``, ``"xdp_cpumap"``,
            ``"pktmon"``).

    Returns:
        A markdown document with a header, a metadata table, and a
        fenced ```xml``` block containing the .wprp text. For the
        ``pktmon`` pseudo-scenario the XML block is replaced by a note
        because pktmon uses a different capture mechanism.
    """
    meta_or_err = _scenario_or_error(scenario)
    if isinstance(meta_or_err, str):
        return meta_or_err
    meta = meta_or_err

    parts = [
        f"**Profile:** `{scenario}`",
        "",
        _metadata_table(meta),
        "",
    ]

    if meta.wprp_filename is None:
        parts.extend(
            [
                f"**Capture mechanism:** `{meta.capture_tool}`",
                "",
                f"`{scenario}` does not use a WPR `.wprp` file. Call "
                f"`get_capture_commands(scenario='{scenario}', "
                "output_path=..., duration_s=...)` for the paste-ready "
                f"`{meta.capture_tool}` command set, or "
                f"`get_capture_instructions(scenario='{scenario}', ...)` "
                "for the full runbook.",
            ]
        )
    else:
        xml = load_wprp_text(scenario)
        parts.extend(
            [
                f"**Bundled .wprp** (`{meta.wprp_filename}`):",
                "",
                "```xml",
                xml.rstrip("\n"),
                "```",
                "",
                "**Next steps**",
                "",
                f"- `get_capture_commands(scenario='{scenario}', "
                "output_path=..., duration_s=...)` for paste-ready "
                "PowerShell.",
                f"- `get_capture_instructions(scenario='{scenario}', "
                "target='local'|'remote', output_path=...)` for the "
                "full step-by-step runbook including remote-transport "
                "examples.",
            ]
        )

    return "\n".join(parts) + "\n"


@mcp.tool()
def get_capture_commands(
    scenario: str,
    output_path: str,
    duration_s: int = 10,
    mode: str = "file",
) -> str:
    """Return paste-ready 3-step PowerShell to capture a trace.

    Args:
        scenario: One of the IDs from ``list_capture_profiles``.
        output_path: Where the ETL should be written on the target,
            e.g. ``"C:\\traces\\capture.etl"``. Must be non-empty.
            For the ``pktmon`` scenario the file should end in ``.etl``.
        duration_s: Capture window in seconds. Must be between 1 and
            3600. Default 10.
        mode: WPR logging mode for the bundled profile - ``"file"``
            (default; emits ``wpr -start <p>.wprp -filemode``, writing
            straight to disk) or ``"memory"`` (emits ``wpr -start
            <p>.wprp`` with no ``-filemode``, using the bundled
            ``LoggingMode="Memory"`` variant - a fixed-size RAM ring
            merged to the ETL at ``-stop``). Memory mode is preferred
            for high-rate captures where file mode drops events. Ignored
            for the ``pktmon`` scenario, which has no WPR logging mode.

    Returns:
        A markdown document with one ```powershell``` fenced block
        containing the start / wait / stop / verify steps. The actual
        commands differ for ``pktmon`` (uses ``pktmon start --capture``
        rather than ``wpr -start``).
    """
    result = _validate_capture_args(scenario, output_path, duration_s)
    if isinstance(result, str):
        return result
    meta = result

    if meta.capture_tool == "pktmon":
        commands = _build_pktmon_commands(output_path, duration_s)
        note = (
            "`pktmon` captures all traffic by default. Add filters via "
            "`pktmon filter add` before Step 1 to scope the capture. "
            "(The `mode` argument is a WPR logging mode and does not "
            "apply to pktmon.)"
        )
    else:
        mode_err = _mode_or_error(mode)
        if mode_err is not None:
            return mode_err
        commands = _build_wpr_commands(
            scenario, output_path, duration_s, mode
        )
        if mode == "memory":
            note = (
                f"Save `get_capture_profile('{scenario}')` XML to "
                f"`.\\{scenario}.wprp` in the working directory before "
                "running Step 1. Memory (ring-buffer) logging mode is "
                "selected: events are held in RAM and merged to the ETL "
                "at `wpr -stop`. Make sure the host has enough free RAM "
                "for the ring."
            )
        else:
            note = (
                f"Save `get_capture_profile('{scenario}')` XML to "
                f"`.\\{scenario}.wprp` in the working directory before "
                "running Step 1. File logging mode is selected; pass "
                "`mode='memory'` for a RAM-ring capture (preferred for "
                "high-rate workloads where file mode drops events)."
            )

    mode_label = "" if meta.capture_tool == "pktmon" else f", mode `{mode}`"
    return (
        f"**Capture commands** - scenario `{scenario}`, output "
        f"`{output_path}`, duration `{duration_s}s`{mode_label}\n"
        "\n"
        f"{commands}\n"
        f"{note}\n"
        "\n"
        "After the capture completes, call "
        f"`load_trace(etl_path='{output_path}')` to analyze it.\n"
    )


@mcp.tool()
def get_capture_instructions(
    scenario: str,
    target: str = "local",
    output_path: str = "C:\\traces\\capture.etl",
    mode: str = "file",
) -> str:
    """Return a full step-by-step capture runbook for a scenario.

    Args:
        scenario: One of the IDs from ``list_capture_profiles``.
        target: ``"local"`` for captures on the same machine you are
            calling from, or ``"remote"`` to additionally get the
            transfer-back transport examples. Default ``"local"``.
        output_path: Where the ETL should be written on the target.
            Default ``"C:\\traces\\capture.etl"``.
        mode: WPR logging mode - ``"file"`` (default; ``wpr -start
            <p>.wprp -filemode``) or ``"memory"`` (``wpr -start
            <p>.wprp``, the bundled ``LoggingMode="Memory"`` variant -
            a RAM ring merged to the ETL at ``-stop``, preferred for
            high-rate captures). Ignored for ``pktmon``.

    Returns:
        A long-form markdown runbook covering prerequisites, profile
        save, start/stop, verification, and (when ``target='remote'``)
        three transport examples for pulling the .etl back. Use this
        when you need narrative documentation rather than just the
        paste-ready commands from ``get_capture_commands``.
    """
    target_err = _target_or_error(target)
    if target_err is not None:
        return target_err
    duration_s = PROFILES.get(scenario).recommended_duration_s if scenario in PROFILES else 10
    result = _validate_capture_args(scenario, output_path, duration_s)
    if isinstance(result, str):
        return result
    meta = result
    if meta.capture_tool != "pktmon":
        mode_err = _mode_or_error(mode)
        if mode_err is not None:
            return mode_err

    sections: list[str] = []

    # 1. Overview
    sections.append(f"# Capture runbook: `{scenario}` ({target} target)")
    sections.append("")
    sections.append("## 1. Overview")
    sections.append("")
    sections.append(
        f"This runbook captures a `{scenario}` trace ({meta.title}) "
        f"to `{output_path}` and prepares it for `load_trace`. "
        f"The capture uses `{meta.capture_tool}` on the target machine. "
        f"Recommended duration is `{meta.recommended_duration_s}s`; "
        f"adjust per workload."
    )
    sections.append("")
    sections.append(meta.when_to_use)
    sections.append("")

    # 2. Prerequisites
    sections.append("## 2. Prerequisites")
    sections.append("")
    sections.append(f"- Privilege: {meta.privilege}.")
    if meta.capture_tool == "wpr":
        sections.append(
            "- `wpr.exe` available on the target. WPR ships in-box on "
            "Windows 10 / Server 2019 and later."
        )
    else:
        sections.append(
            "- `pktmon.exe` available on the target. pktmon ships "
            "in-box on Windows 10 1809 / Server 2019 and later."
        )
    sections.append(
        f"- VM compatible: {'yes' if meta.vm_compatible else 'no'}. "
        f"Container compatible: "
        f"{'yes' if meta.container_compatible else 'no'} "
        "(WPR uses NT Kernel Logger which is per-host, not "
        "per-container)."
    )
    if meta.providers:
        sections.append(
            "- Providers required on the target: "
            + ", ".join(f"`{p}`" for p in meta.providers)
            + "."
        )
    if meta.notes:
        sections.append(f"- Notes: {meta.notes}")
    sections.append("")

    # 3. Save the profile
    sections.append("## 3. Save the profile")
    sections.append("")
    if meta.wprp_filename is not None:
        sections.append(
            f"Save the XML from `get_capture_profile('{scenario}')` to "
            f"`{scenario}.wprp` in the working directory on the target. "
            "The Step 4 `wpr -start` command references the file by "
            "relative path."
        )
    else:
        sections.append(
            f"`{scenario}` does not need a saved profile file - the "
            f"`{meta.capture_tool}` command in Step 4 carries the "
            "configuration inline."
        )
    sections.append("")

    # 4. Start the capture
    sections.append("## 4. Start the capture")
    sections.append("")
    mode_arg = "" if meta.capture_tool == "pktmon" else f", mode='{mode}'"
    sections.append(
        "Run the start / wait / stop / verify commands. Equivalent to "
        f"calling `get_capture_commands('{scenario}', '{output_path}', "
        f"{meta.recommended_duration_s}{mode_arg})`:"
    )
    sections.append("")
    if meta.capture_tool == "pktmon":
        sections.append(
            _build_pktmon_commands(output_path, meta.recommended_duration_s)
        )
    else:
        sections.append(
            _build_wpr_commands(
                scenario, output_path, meta.recommended_duration_s, mode
            )
        )

    # 5. Stop and verify
    sections.append("## 5. Stop and verify")
    sections.append("")
    sections.append(
        f"`Get-Item '{output_path}'` in Step 4 prints the file size. "
        "Sanity check: a 10s capture on a quiet machine is typically "
        "10-50 MB for the cpu profile, 200 MB - 1 GB for the network "
        "profiles, and 1-2 GB for `network_packets` at line rate. "
        "If the file is missing or 0 bytes, re-run with an elevated "
        "shell and check that `wpr -status` (or `pktmon status`) "
        "reports the session was stopped cleanly."
    )
    sections.append("")

    # 6. Transfer the trace back (remote only)
    if target == "remote":
        sections.append("## 6. Transfer the trace back")
        sections.append("")
        sections.append(
            "Pull the `.etl` to the analysis machine. Three example "
            "transports - pick whichever matches your environment. "
            "LabLink is one example MCP transport; the same shape "
            "works with any MCP file-transfer tool."
        )
        sections.append("")
        sections.append("**PowerShell remoting**")
        sections.append("")
        sections.append("```powershell")
        sections.append("$session = New-PSSession -ComputerName <host>")
        sections.append(
            f"Copy-Item -FromSession $session -Path '{output_path}' "
            "-Destination 'C:\\local\\traces\\capture.etl'"
        )
        sections.append("Remove-PSSession $session")
        sections.append("```")
        sections.append("")
        sections.append("**LabLink (or any equivalent MCP transport)**")
        sections.append("")
        sections.append("```text")
        sections.append(
            f"pull_file(node='<name>', remote_path='{output_path}', "
            "local_path='C:\\\\local\\\\traces\\\\capture.etl')"
        )
        sections.append("```")
        sections.append("")
        sections.append("**Manual: scp / copy by hand**")
        sections.append("")
        sections.append("```bash")
        sections.append(
            f"scp <user>@<host>:'{output_path}' "
            "/local/traces/capture.etl"
        )
        sections.append("```")
        sections.append("")
        sections.append(
            "Or just have a human copy the file via RDP / file share / "
            "USB key when the host is not reachable from automation."
        )
        sections.append("")

    # 7. Load and analyze
    next_section = 7 if target == "remote" else 6
    sections.append(f"## {next_section}. Load and analyze")
    sections.append("")
    sections.append(
        f"After the trace is on the analysis machine, call "
        f"`load_trace(etl_path='<local_path>')` (where `<local_path>` "
        f"is `{output_path}` for `target='local'`, or wherever Step 6 "
        "wrote the file for `target='remote'`)."
    )
    sections.append("")
    if meta.analysis_tools:
        sections.append("Suggested analysis tools for this scenario:")
        sections.append("")
        for tool in meta.analysis_tools:
            sections.append(f"- `{tool}`")
        sections.append("")

    # 8. Cleanup
    sections.append(f"## {next_section + 1}. Cleanup")
    sections.append("")
    if meta.wprp_filename is not None:
        sections.append(
            f"Delete the saved profile and the on-target ETL once "
            f"analysis is done:\n"
            "\n"
            "```powershell\n"
            f"Remove-Item '.\\{scenario}.wprp'\n"
            f"Remove-Item '{output_path}'\n"
            "```\n"
        )
    else:
        sections.append(
            f"Delete the on-target ETL once analysis is done:\n"
            "\n"
            "```powershell\n"
            f"Remove-Item '{output_path}'\n"
            "```\n"
        )

    return "\n".join(sections) + "\n"
