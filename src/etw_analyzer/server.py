"""ETW Trace Analyzer MCP Server.

Provides tools for analyzing ETW traces (.etl files).
Uses xperf.exe to extract data and pandas for aggregation.
"""

from etw_analyzer.app import mcp  # noqa: F401 — re-export for backward compat

# Register all tool modules — each module calls @mcp.tool() on import
import etw_analyzer.tools.trace_mgmt  # noqa: F401, E402
import etw_analyzer.tools.cpu_sampling  # noqa: F401, E402
import etw_analyzer.tools.stack_analysis  # noqa: F401, E402
import etw_analyzer.tools.dpc_isr  # noqa: F401, E402
import etw_analyzer.tools.context_switch  # noqa: F401, E402
import etw_analyzer.tools.thread_cpu_precise  # noqa: F401, E402  — get_thread_cpu_precise (CPU Usage Precise)
import etw_analyzer.tools.per_cpu  # noqa: F401, E402
import etw_analyzer.tools.memory  # noqa: F401, E402
import etw_analyzer.tools.system_info  # noqa: F401, E402
import etw_analyzer.tools.compare  # noqa: F401, E402
import etw_analyzer.tools.summary  # noqa: F401, E402
import etw_analyzer.tools.network_lenses  # noqa: F401, E402
import etw_analyzer.tools.network_dispatch  # noqa: F401, E402
import etw_analyzer.tools.network_wait_chain  # noqa: F401, E402
import etw_analyzer.tools.network_events  # noqa: F401, E402
import etw_analyzer.tools.network_events_extra  # noqa: F401, E402
import etw_analyzer.tools.packet_capture  # noqa: F401, E402
import etw_analyzer.tools.app_layer  # noqa: F401, E402
import etw_analyzer.tools.evidence  # noqa: F401, E402  — optional evidence-store federation hook
import etw_analyzer.tools.capture_profiles  # noqa: F401, E402  — trace-capture authoring (WPR + pktmon)
import etw_analyzer.tools.symbol_diagnostics  # noqa: F401, E402  — diagnose_symbol_load, clean_stale_symbol_files


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
