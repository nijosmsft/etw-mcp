"""Tests for xperf output parsers."""

import pandas as pd
import pytest

from etw_analyzer.parsing.wpa_exporter import (
    _parse_profile_detail,
    _parse_profile_utilization,
    _parse_dpcisr,
    _parse_stack_butterfly_html,
    parse_stack_butterfly_callers,
    parse_sampled_profile_events,
)


class TestParseProfileDetail:
    """Tests for xperf -a profile -detail parser."""

    SAMPLE_OUTPUT = """\
Process Name ( PID),     Weight,    Usage %,          Module!Function
  echo_server.exe (17448),       389,    40.70,      ntoskrnl.exe!EtwpEventWriteFull
  echo_server.exe (17448),       128,    13.20,          NDIS.SYS!ndisIterativeDPInvokeHandlerOnTracker
  echo_server.exe (17448),        94,     9.62,           afd.sys!AfdFastDatagramSend
             Idle (   0),    120000,    98.10,  <Heuristic Low Power State>!<C3>
"""

    def test_basic_parsing(self):
        df = _parse_profile_detail(self.SAMPLE_OUTPUT)
        assert len(df) == 4
        assert list(df.columns) == ["Process Name", "PID", "Weight", "% Weight", "Module", "Function"]

    def test_process_name_and_pid(self):
        df = _parse_profile_detail(self.SAMPLE_OUTPUT)
        assert df.iloc[0]["Process Name"] == "echo_server.exe"
        assert df.iloc[0]["PID"] == 17448
        assert df.iloc[3]["Process Name"] == "Idle"
        assert df.iloc[3]["PID"] == 0

    def test_weight_and_percent(self):
        df = _parse_profile_detail(self.SAMPLE_OUTPUT)
        assert df.iloc[0]["Weight"] == 389
        assert df.iloc[0]["% Weight"] == 40.70

    def test_module_function_split(self):
        df = _parse_profile_detail(self.SAMPLE_OUTPUT)
        assert df.iloc[0]["Module"] == "ntoskrnl.exe"
        assert df.iloc[0]["Function"] == "EtwpEventWriteFull"
        assert df.iloc[1]["Module"] == "NDIS.SYS"

    def test_empty_input(self):
        df = _parse_profile_detail("")
        assert df.empty

    def test_header_only(self):
        df = _parse_profile_detail("Process Name ( PID),     Weight,    Usage %,          Module!Function\n")
        assert df.empty

    def test_no_function(self):
        """Module without ! separator puts everything in Module."""
        text = "  system (4),  100,  1.0,  ntoskrnl.exe\n"
        df = _parse_profile_detail(text)
        assert len(df) == 1
        assert df.iloc[0]["Module"] == "ntoskrnl.exe"
        assert df.iloc[0]["Function"] == ""


class TestParseProfileUtilization:
    """Tests for xperf -a profile -util parser (per-CPU timeline)."""

    SAMPLE_OUTPUT = """\
 StartTime,   EndTime,  Cpu 0,  Cpu 1,  Cpu 2,  Cpu 3
         0,   1000000,  94.74,   0.70,  40.33,   0.50
   1000000,   2000000, 100.00,   0.80,  42.83,   0.48
"""

    def test_basic_parsing(self):
        df = _parse_profile_utilization(self.SAMPLE_OUTPUT)
        assert len(df) == 2
        assert "StartTime" in df.columns
        assert "Cpu 0" in df.columns
        assert "Cpu 3" in df.columns

    def test_values(self):
        df = _parse_profile_utilization(self.SAMPLE_OUTPUT)
        assert df.iloc[0]["Cpu 0"] == pytest.approx(94.74)
        assert df.iloc[1]["Cpu 0"] == pytest.approx(100.0)
        assert df.iloc[0]["Cpu 1"] == pytest.approx(0.70)

    def test_timestamps(self):
        df = _parse_profile_utilization(self.SAMPLE_OUTPUT)
        assert df.iloc[0]["StartTime"] == 0
        assert df.iloc[1]["EndTime"] == 2000000

    def test_empty_input(self):
        df = _parse_profile_utilization("")
        assert df.empty

    def test_no_header(self):
        df = _parse_profile_utilization("some random text\nno csv here\n")
        assert df.empty


class TestParseDpcIsr:
    """Tests for xperf -a dpcisr histogram parser."""

    SAMPLE_OUTPUT = """\
Total = 2068066 for module NDIS.SYS
Elapsed Time, >  0 usecs AND <=  1 usecs, 6318, or 0.31%
Elapsed Time, >  1 usecs AND <=  2 usecs, 412805, or 19.96%
Elapsed Time, >  2 usecs AND <=  4 usecs, 1289532, or 62.35%
Elapsed Time, > 16 usecs AND <= 32 usecs, 8401, or 0.41%
Total, 2068066

Total = 500000 for module xdp.sys
Elapsed Time, >  0 usecs AND <=  1 usecs, 100, or 0.02%
Elapsed Time, >  1 usecs AND <=  2 usecs, 200000, or 40.00%
Elapsed Time, > 32 usecs AND <= 64 usecs, 50, or 0.01%
Total, 500000
"""

    def test_basic_parsing(self):
        df = _parse_dpcisr(self.SAMPLE_OUTPUT)
        assert not df.empty
        assert "Module" in df.columns
        assert "Count" in df.columns
        assert "Bucket_Low_us" in df.columns
        assert "Bucket_High_us" in df.columns

    def test_module_detection(self):
        df = _parse_dpcisr(self.SAMPLE_OUTPUT)
        modules = df["Module"].unique()
        assert "NDIS.SYS" in modules
        assert "xdp.sys" in modules

    def test_bucket_values(self):
        df = _parse_dpcisr(self.SAMPLE_OUTPUT)
        ndis = df[df["Module"] == "NDIS.SYS"]
        first_row = ndis.iloc[0]
        assert first_row["Bucket_Low_us"] == 0
        assert first_row["Bucket_High_us"] == 1
        assert first_row["Count"] == 6318
        assert first_row["Pct"] == pytest.approx(0.31)

    def test_count_totals(self):
        df = _parse_dpcisr(self.SAMPLE_OUTPUT)
        ndis_total = df[df["Module"] == "NDIS.SYS"]["Count"].sum()
        assert ndis_total == 6318 + 412805 + 1289532 + 8401

    def test_empty_input(self):
        df = _parse_dpcisr("")
        assert df.empty


class TestParseStackButterfly:
    """Tests for xperf -a stack -butterfly HTML parser."""

    SAMPLE_HTML = """\
<html><body>
<table id='TblSE'>
<tr class='ff'><td>ntoskrnl.exe!KeAcquireSpinLock</td><td>12345</td><td>6.5%</td></tr>
<tr class='ff'><td>tcpip.sys!UdpSendMessages</td><td>5678</td><td>3.0%</td></tr>
<tr class='ff'><td>ndis.sys!NdisSendNetBufferLists</td><td>2345</td><td>1.2%</td></tr>
</table>
</body></html>
"""

    def test_basic_parsing(self):
        df = _parse_stack_butterfly_html(self.SAMPLE_HTML)
        assert len(df) >= 3
        assert "Module" in df.columns
        assert "Function" in df.columns

    def test_module_function(self):
        df = _parse_stack_butterfly_html(self.SAMPLE_HTML)
        row = df[df["Function"] == "KeAcquireSpinLock"].iloc[0]
        assert row["Module"] == "ntoskrnl.exe"

    def test_sorted_by_weight(self):
        df = _parse_stack_butterfly_html(self.SAMPLE_HTML)
        # Should be sorted descending
        weights = df["Inclusive"].tolist()
        assert weights == sorted(weights, reverse=True)

    def test_real_butterfly_inclusive_exclusive_columns(self):
        html = """\
<html><body>
<h2>Functions by UniInclusive Hits</h2>
<table id='TblSI'>
<tr class='ff'><td>tcpip.sys!IppResolveNeighbor</td><td>3,631</td><td>2.14%</td><td>279</td><td>0</td><td>0</td><td>0</td></tr>
<tr class='ff'><td>ntoskrnl.exe!KeAcquireInStackQueuedSpinLock</td><td>3,633</td><td>2.14%</td><td>0</td><td>0</td><td>0</td><td>0</td></tr>
</table>
<h2>Functions by Exclusive Hits</h2>
<table id='TblSE'>
<tr class='ff'><td>tcpip.sys!IppResolveNeighbor</td><td>279</td><td>0.16%</td><td>3,631</td><td>0</td><td>0</td><td>0</td></tr>
</table>
</body></html>
"""
        df = _parse_stack_butterfly_html(html)
        row = df[df["Function"] == "IppResolveNeighbor"].iloc[0]
        assert row["Inclusive"] == 3631
        assert row["Exclusive"] == 279
        assert row["Total %"] == pytest.approx(2.14)

    def test_empty_html(self):
        df = _parse_stack_butterfly_html("")
        assert df.empty


class TestParseStackButterflyCallers:
    """Tests for caller/callee extraction from butterfly HTML."""

    SAMPLE_HTML = """\
<html><body>
<table id='TblSN'>
<tr><td>ntoskrnl.exe!KeAcquireSpinLock</td><td>12345</td></tr>
<tr><td><-- tcpip.sys!UdpSendMessages</td><td>5000</td></tr>
<tr><td><-- ndis.sys!NdisSendNetBufferLists</td><td>3000</td></tr>
<tr><td>--> ntoskrnl.exe!KxWaitForLock</td><td>10000</td></tr>
<tr><td>afd.sys!AfdFastDatagramSend</td><td>8000</td></tr>
<tr><td><-- ntoskrnl.exe!IopCompleteRequest</td><td>4000</td></tr>
</table>
<table id='TblSE'></table>
</body></html>
"""

    def test_basic_parsing(self):
        df = parse_stack_butterfly_callers(self.SAMPLE_HTML)
        assert not df.empty
        assert "Target_Module" in df.columns
        assert "Direction" in df.columns

    def test_callers_detected(self):
        df = parse_stack_butterfly_callers(self.SAMPLE_HTML)
        callers = df[df["Direction"] == "caller"]
        assert len(callers) >= 2

    def test_callees_detected(self):
        df = parse_stack_butterfly_callers(self.SAMPLE_HTML)
        callees = df[df["Direction"] == "callee"]
        assert len(callees) >= 1

    def test_center_function_tracking(self):
        df = parse_stack_butterfly_callers(self.SAMPLE_HTML)
        # First center function is KeAcquireSpinLock
        first_callers = df[
            (df["Target_Function"] == "KeAcquireSpinLock") &
            (df["Direction"] == "caller")
        ]
        assert len(first_callers) >= 1

    def test_real_butterfly_parent_percent_and_self_rows(self):
        html = """\
<html><body>
<h2>Functions by Multi-Inclusive Hits with Callers and Callees</h2>
<table id='TblSN'>
<tr class='ff'><td>ntoskrnl.exe!KeAcquireInStackQueuedSpinLock</td><td>3,633</td><td>2.14%</td><td>2.14%</td><td>0</td><td>0</td><td>0</td><td>0</td></tr>
<tr class='ff'><td>***itself***</td><td>3,633</td><td>2.14%</td><td>100.00%</td><td>0</td><td>0</td><td>0</td><td>0</td></tr>
<tr class='ff'><td>&lt;-- tcpip.sys!IppResolveNeighbor</td><td>2,722</td><td>1.60%</td><td>74.93%</td><td>279</td><td>0</td><td>0</td><td>0</td></tr>
</table>
</body></html>
"""
        df = parse_stack_butterfly_callers(html)
        caller = df[df["Direction"] == "caller"].iloc[0]
        assert caller["Weight"] == 2722
        assert caller["Parent %"] == pytest.approx(74.93)
        assert caller["Exclusive"] == 279
        assert not df[df["Direction"] == "self"].empty

    def test_empty_html(self):
        df = parse_stack_butterfly_callers("")
        assert df.empty
