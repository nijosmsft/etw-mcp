"""Tests for ``etw_analyzer.tools.capture_profiles`` (the 4 capture tools).

The capture tools are synthetic - they emit paste-ready commands and
markdown documentation, they never invoke wpr.exe or pktmon.exe. So
every test here runs offline with no fixtures and no real captures.

Coverage:

1. ``list_capture_profiles`` lists all 10 scenarios.
2. ``get_capture_profile`` returns metadata + XML for a known scenario.
3. ``get_capture_profile`` returns a friendly error for an unknown
   scenario.
4. ``get_capture_profile('pktmon')`` skips the XML block (pktmon does
   not use .wprp).
5. ``get_capture_commands`` returns the WPR command sequence for a
   normal scenario.
6. ``get_capture_commands('pktmon', ...)`` branches to the pktmon
   command set.
7. ``get_capture_commands`` rejects an empty ``output_path``.
8. ``get_capture_commands`` rejects out-of-range ``duration_s``.
9. ``get_capture_commands`` rejects an unknown scenario.
10. ``get_capture_instructions`` returns the long-form runbook for
    ``target='local'`` (no Transfer section).
11. ``get_capture_instructions(target='remote')`` includes the
    transfer-back section with three transport examples.
12. ``get_capture_instructions`` rejects an unknown ``target``.
13. Resource invariant: every WPR profile is loadable via
    ``load_wprp_text`` and contains the safe keyword
    ``0x7FFFFFFFFFFFFFFF`` somewhere - never the unsafe
    ``0xFFFFFFFFFFFFFFFF`` (downlevel WPR bug).
14. Resource invariant: ``Strict="true"`` only appears in the two
    XDP-aware profiles (``network.wprp`` and ``xdp_cpumap.wprp``).
15. ``PROFILES`` metadata invariants: every wpr scenario points at an
    existing .wprp; the pktmon pseudo-scenario has wprp_filename=None.
"""

from __future__ import annotations

import pytest

from etw_analyzer.profiles.metadata import PROFILES, load_wprp_text
from etw_analyzer.tools.capture_profiles import (
    get_capture_commands,
    get_capture_instructions,
    get_capture_profile,
    list_capture_profiles,
)


_ALL_SCENARIOS = sorted(PROFILES.keys())
_WPR_SCENARIOS = sorted(
    name for name, meta in PROFILES.items() if meta.wprp_filename is not None
)


# ---------------------------------------------------------------------------
# 1. list_capture_profiles
# ---------------------------------------------------------------------------


def test_list_capture_profiles_includes_all_scenarios():
    out = list_capture_profiles()
    assert isinstance(out, str)
    assert "**Capture profiles**" in out
    for scenario in _ALL_SCENARIOS:
        # Every scenario name appears in the table (each row starts with
        # the scenario id surrounded by pipes from format_table).
        assert scenario in out, f"scenario {scenario!r} missing from list"
    # The workflow header steers callers at the next tools.
    assert "get_capture_profile" in out
    assert "get_capture_commands" in out
    # And the workflow ends at load_trace.
    assert "load_trace" in out


# ---------------------------------------------------------------------------
# 2-4. get_capture_profile
# ---------------------------------------------------------------------------


def test_get_capture_profile_returns_metadata_and_xml_for_wpr_scenario():
    out = get_capture_profile("cpu")
    assert "**Profile:** `cpu`" in out
    # Metadata table fields rendered by _metadata_table.
    assert "Title" in out
    assert "Capture tool" in out
    assert "Providers" in out
    # XML block is fenced and references the saved-file name.
    assert "```xml" in out
    assert "<?xml" in out
    assert "<WindowsPerformanceRecorder" in out
    # Next-steps section points at the other tools.
    assert "get_capture_commands" in out
    assert "get_capture_instructions" in out


def test_get_capture_profile_unknown_scenario_returns_friendly_error():
    out = get_capture_profile("does_not_exist")
    assert "Unknown scenario" in out
    assert "does_not_exist" in out
    # Lists the valid scenarios so the caller can recover.
    for scenario in _ALL_SCENARIOS:
        assert scenario in out
    assert "list_capture_profiles" in out


def test_get_capture_profile_pktmon_omits_xml_block():
    out = get_capture_profile("pktmon")
    assert "**Profile:** `pktmon`" in out
    # No fenced XML for the pktmon pseudo-scenario.
    assert "```xml" not in out
    # Explicitly points at the alternate command set.
    assert "pktmon" in out.lower()
    assert "get_capture_commands" in out


# ---------------------------------------------------------------------------
# 5-9. get_capture_commands
# ---------------------------------------------------------------------------


def test_get_capture_commands_wpr_emits_3_step_powershell():
    out = get_capture_commands("cpu", r"C:\traces\cpu.etl", duration_s=15)
    assert "```powershell" in out
    # The WPR command pattern: start .wprp -filemode -> sleep -> stop.
    assert "wpr -start .\\cpu.wprp -filemode" in out
    assert "Start-Sleep -Seconds 15" in out
    assert "wpr -stop 'C:\\traces\\cpu.etl'" in out
    # And tells the caller what to do next.
    assert "load_trace" in out
    assert "C:\\traces\\cpu.etl" in out


def test_get_capture_commands_pktmon_branches_to_pktmon_cli():
    out = get_capture_commands(
        "pktmon", r"C:\traces\pktmon.etl", duration_s=20
    )
    assert "```powershell" in out
    # Branches to pktmon, NOT wpr.
    assert "pktmon start --capture --pkt-size 0" in out
    assert "pktmon stop" in out
    assert "wpr -start" not in out
    # Sleep step retained, with the requested duration.
    assert "Start-Sleep -Seconds 20" in out
    # Output path threaded through.
    assert "C:\\traces\\pktmon.etl" in out


def test_get_capture_commands_rejects_empty_output_path():
    out = get_capture_commands("cpu", "", duration_s=10)
    assert "output_path" in out
    # No actual command emitted on validation failure.
    assert "```powershell" not in out


@pytest.mark.parametrize("bad_duration", [0, -5, 3601, 100000])
def test_get_capture_commands_rejects_out_of_range_duration(bad_duration):
    out = get_capture_commands(
        "cpu", r"C:\traces\cpu.etl", duration_s=bad_duration
    )
    assert "duration_s" in out
    assert "between" in out
    assert "```powershell" not in out


def test_get_capture_commands_rejects_unknown_scenario():
    out = get_capture_commands(
        "nope", r"C:\traces\x.etl", duration_s=10
    )
    assert "Unknown scenario" in out
    assert "nope" in out
    assert "```powershell" not in out


# ---------------------------------------------------------------------------
# 10-12. get_capture_instructions
# ---------------------------------------------------------------------------


def test_get_capture_instructions_local_omits_transfer_section():
    out = get_capture_instructions(
        "cpu", target="local", output_path=r"C:\traces\cpu.etl"
    )
    assert "# Capture runbook: `cpu`" in out
    assert "## 1. Overview" in out
    assert "## 2. Prerequisites" in out
    assert "## 4. Start the capture" in out
    # The local runbook must NOT include the transfer section.
    assert "Transfer the trace back" not in out
    assert "PowerShell remoting" not in out
    assert "scp" not in out
    # Still tells the caller to call load_trace at the end.
    assert "load_trace" in out


def test_get_capture_instructions_remote_includes_three_transport_examples():
    out = get_capture_instructions(
        "network", target="remote", output_path=r"C:\traces\net.etl"
    )
    assert "Transfer the trace back" in out
    # All three transport examples appear, by name and by a code shape.
    assert "PowerShell remoting" in out
    assert "New-PSSession" in out
    assert "Copy-Item -FromSession" in out
    assert "LabLink" in out
    assert "pull_file(node=" in out
    assert "scp" in out
    # And the load_trace pointer survives.
    assert "load_trace" in out


@pytest.mark.parametrize("bad_target", ["", "elsewhere", "Local", "REMOTE"])
def test_get_capture_instructions_rejects_unknown_target(bad_target):
    out = get_capture_instructions(
        "cpu", target=bad_target, output_path=r"C:\traces\cpu.etl"
    )
    assert "Unknown target" in out
    # Friendly error, not the runbook.
    assert "# Capture runbook" not in out


# ---------------------------------------------------------------------------
# 13-15. resource and metadata invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario", _WPR_SCENARIOS)
def test_wprp_files_load_via_importlib_resources(scenario):
    xml = load_wprp_text(scenario)
    assert isinstance(xml, str)
    assert "<?xml" in xml
    assert "<WindowsPerformanceRecorder" in xml
    # Authoring stamp per the prompt - confirms our vendored copy, not
    # an upstream rename.
    assert 'Author="etw-mcp"' in xml
    # Safe keyword present; unsafe all-bits-set keyword must not appear
    # anywhere (downlevel WPR bug).
    assert "0x7FFFFFFFFFFFFFFF" in xml
    assert "0xFFFFFFFFFFFFFFFF" not in xml


@pytest.mark.parametrize("scenario", _WPR_SCENARIOS)
def test_wprp_is_well_formed_xml(scenario):
    """Every bundled .wprp must be well-formed XML so ``wpr -start`` accepts it.

    Regression guard: a comment body containing ``--`` (illegal inside XML
    comments) makes the profile malformed even though string-matching tests
    still pass. wpr.exe parses the file strictly and would reject the capture.
    """
    import xml.etree.ElementTree as ET

    text = load_wprp_text(scenario)
    # Raises ET.ParseError on any malformed XML (incl. ``--`` in a comment).
    root = ET.fromstring(text)
    assert root.tag.endswith("WindowsPerformanceRecorder")
    # Belt-and-suspenders: no ``--`` sequence inside a comment body. Strip the
    # legal ``<!--`` / ``-->`` delimiters first, then assert no bare ``--``.
    for raw_line in text.splitlines():
        stripped = raw_line.replace("<!--", "").replace("-->", "")
        assert "--" not in stripped, (
            f"{scenario}.wprp has '--' inside a comment body "
            f"(illegal XML, breaks wpr -start): {raw_line.strip()!r}"
        )


def test_strict_true_only_on_xdp_aware_profiles():
    import re

    xdp_aware = {"network", "xdp_cpumap"}
    comment_re = re.compile(r"<!--.*?-->", re.DOTALL)
    for scenario in _WPR_SCENARIOS:
        xml = load_wprp_text(scenario)
        # Strict="true" appears descriptively in our top-of-file
        # comments; only the actual EventProvider attribute counts.
        xml_no_comments = comment_re.sub("", xml)
        has_strict = 'Strict="true"' in xml_no_comments
        if scenario in xdp_aware:
            assert has_strict, (
                f"{scenario} is an XDP-aware profile and must keep "
                'Strict="true" on its XDP providers'
            )
        else:
            assert not has_strict, (
                f"{scenario} must not contain Strict=\"true\" - it "
                "would block capture on machines that lack one of the "
                "providers"
            )


def test_profiles_table_invariants():
    # Exactly 10 scenarios: the 9 WPR profiles plus the pktmon pseudo.
    assert len(PROFILES) == 10
    assert "pktmon" in PROFILES
    # pktmon has no .wprp and uses a different capture tool.
    pkt = PROFILES["pktmon"]
    assert pkt.wprp_filename is None
    assert pkt.capture_tool == "pktmon"
    # Loading the pktmon "wprp" via the helper must fail loudly.
    with pytest.raises(KeyError):
        load_wprp_text("pktmon")
    # And every wpr-mode scenario claims an existing .wprp file the
    # importlib.resources loader can read.
    for scenario in _WPR_SCENARIOS:
        meta = PROFILES[scenario]
        assert meta.wprp_filename == f"{scenario}.wprp"
        assert meta.capture_tool == "wpr"
        # Smoke-load to make sure the resource is wheel-visible.
        assert load_wprp_text(scenario)


# ---------------------------------------------------------------------------
# Bug E -- Server 2025 build 29614 rundown-drop fixes
# ---------------------------------------------------------------------------


def test_cpu_wprp_system_collector_buffering():
    """cpu.wprp must use 4096 KB x 320 buffers = 1.28 GB for the SystemCollector.

    The original 128 x 1024 KB (128 MB) allocation was dangerously
    underprovisioned for an 80-CPU Server 2025 box: ~1.6 buffers/CPU at
    session start is below the ETW minimum-buffers recommendation of
    >= 2 x NumberOfProcessors, causing the Image/DCStart rundown burst to
    be dropped silently before the file-mode consumer can drain the ring.
    """
    import re

    xml = load_wprp_text("cpu")
    # Strip comments so we only test the live XML, not comment prose.
    xml_no_comments = re.sub(r"<!--.*?-->", "", xml, flags=re.DOTALL)
    assert '<BufferSize Value="4096"/>' in xml_no_comments, (
        "cpu.wprp SystemCollector must use BufferSize 4096 KB (was 1024 KB) "
        "to provide sufficient initial buffer headroom for the DCStart rundown "
        "on Server 2025 boxes with 80+ CPUs."
    )
    assert '<Buffers Value="320"/>' in xml_no_comments, (
        "cpu.wprp SystemCollector must use 320 buffers (was 128) to meet the "
        "ETW recommendation of >= 2 x NumberOfProcessors on 80-CPU servers."
    )


@pytest.mark.parametrize("scenario", _WPR_SCENARIOS)
def test_wprp_has_tracemergeproperty_imageid(scenario):
    """Every WPR profile must include TraceMergeProperties / CustomEvent ImageId.

    The built-in WPR 'CPU' profile injects ImageID/DbgID_RSDS records at
    wpr -stop via its hardcoded merge properties, which is why traces captured
    with it contain the RSDS identity (13 104 events in the reference trace).
    Custom .wprp files on Windows Server 2025 build 29614 do NOT receive this
    injection by default; without TraceMergeProperties the final merged ETL
    lacks the image-identity records that the etw-mcp consumer relies on for
    kernel symbolization (Bug E).
    """
    import re

    xml = load_wprp_text(scenario)
    # Strip comments to avoid matching comment prose about the rationale.
    xml_no_comments = re.sub(r"<!--.*?-->", "", xml, flags=re.DOTALL)
    assert "<TraceMergeProperties>" in xml_no_comments, (
        f"{scenario}.wprp is missing <TraceMergeProperties>; without it WPR "
        "on Server 2025 does not inject ImageID/DbgID_RSDS at merge time."
    )
    assert '<CustomEvent Value="ImageId"/>' in xml_no_comments, (
        f"{scenario}.wprp TraceMergeProperties must include "
        '<CustomEvent Value="ImageId"/> to ensure RSDS records land in the ETL.'
    )
