"""Per-scenario metadata for the vendored WPR capture profiles.

This module is the single source of truth for:

- which scenarios exist (``PROFILES`` dict)
- what providers and analysis tools each scenario maps to
- runtime overhead / privilege expectations
- the loader (``load_wprp_text``) that reads the on-wheel ``.wprp`` file
  via ``importlib.resources`` so we don't depend on filesystem layout

The pseudo-scenario ``"pktmon"`` has ``wprp_filename=None`` because
pktmon traces are captured with ``pktmon start --capture --pkt-size 0``,
not with ``wpr -start``. The capture-profile tools handle it explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources


@dataclass(frozen=True)
class ProfileMeta:
    """Metadata describing one capture scenario.

    Attributes:
        scenario: Short ID used by the MCP tools (e.g. ``"cpu"``).
        title: One-line human title used in tables.
        when_to_use: 1-2 sentence guidance an LLM can use to pick this
            scenario from the ``list_capture_profiles`` output.
        providers: List of provider short names included in the profile.
        analysis_tools: List of analysis MCP tool names that read the
            resulting ETL well (used in ``get_capture_instructions``).
        privilege: Privilege requirement summary (e.g. ``"admin"``).
        container_compatible: True if the underlying mechanism works
            inside a Windows container. WPR / NT Kernel Logger does not.
        vm_compatible: True if the underlying mechanism works in a VM.
        recommended_duration_s: Suggested capture duration default.
        est_overhead: Human-readable overhead estimate (size / minute).
        notes: Free-form notes / caveats. Multi-sentence allowed.
        wprp_filename: Name of the bundled ``.wprp`` resource, or
            ``None`` for the ``pktmon`` pseudo-scenario.
        capture_tool: ``"wpr"`` for ETW profiles, ``"pktmon"`` for the
            pktmon pseudo-scenario. The capture-profile tools branch
            on this field.
    """

    scenario: str
    title: str
    when_to_use: str
    providers: list[str] = field(default_factory=list)
    analysis_tools: list[str] = field(default_factory=list)
    privilege: str = "admin (wpr requires elevation)"
    container_compatible: bool = False
    vm_compatible: bool = True
    recommended_duration_s: int = 10
    est_overhead: str = "moderate"
    notes: str = ""
    wprp_filename: str | None = None
    capture_tool: str = "wpr"


PROFILES: dict[str, ProfileMeta] = {
    "cpu": ProfileMeta(
        scenario="cpu",
        title="CPU profiling (lowest overhead)",
        when_to_use=(
            "Pick this when you want a fast snapshot of where CPU is being "
            "spent across the system. No DPC/ISR, scheduler, or network "
            "providers - just SampledProfile with stacks."
        ),
        providers=["SampledProfile", "Loader", "ProcessThread", "IdleStates"],
        analysis_tools=[
            "get_cpu_samples",
            "get_hot_functions",
            "get_per_cpu_summary",
            "get_cpu_timeline",
        ],
        recommended_duration_s=10,
        est_overhead="low (~50 MB/min on a busy 16-core box)",
        notes=(
            "Smallest trace size in the catalog. Cannot answer DPC, lock "
            "contention, or networking questions - use cpu_dpc_isr or one "
            "of the network profiles for those."
        ),
        wprp_filename="cpu.wprp",
    ),
    "cpu_dpc_isr": ProfileMeta(
        scenario="cpu_dpc_isr",
        title="CPU + DPC + ISR + scheduler with stacks",
        when_to_use=(
            "Pick this when you suspect kernel pressure: high DPC time, "
            "ISR storms, spinlock contention, or context-switch hot spots. "
            "Adds CSwitch / ReadyThread / DPC / Interrupt over cpu.wprp."
        ),
        providers=[
            "SampledProfile",
            "CSwitch",
            "ReadyThread",
            "DPC",
            "Interrupt",
            "IdleStates",
            "Loader",
            "ProcessThread",
        ],
        analysis_tools=[
            "get_cpu_samples",
            "get_hot_functions",
            "get_hot_stacks",
            "get_dpc_summary",
            "get_dpc_per_cpu",
            "get_lock_contention",
            "get_per_cpu_summary",
        ],
        recommended_duration_s=10,
        est_overhead="moderate (~200-400 MB/min on 80-core systems)",
        notes=(
            "Best general kernel-pressure profile. Add a network profile "
            "if you need TCPIP / AFD / NDIS provider visibility."
        ),
        wprp_filename="cpu_dpc_isr.wprp",
    ),
    "network": ProfileMeta(
        scenario="network",
        title="Full networking stack including XDP",
        when_to_use=(
            "Pick this when you want everything: TCPIP + AFD + NDIS + "
            "QUIC + HTTP + XDP, on a machine that HAS the XDP manifest "
            "installed. XDP provider is Strict so wpr -start fails fast "
            "if XDP is missing - use network_minimal otherwise."
        ),
        providers=[
            "Microsoft-Windows-TCPIP",
            "Microsoft-Windows-Winsock-AFD",
            "Microsoft-Windows-NDIS-PacketCapture",
            "Microsoft-Quic",
            "Microsoft-Windows-HttpService",
            "Microsoft-Windows-XDP",
            "Microsoft-Windows-Kernel-Network",
            "Kernel CPU/DPC/CSwitch stacks",
        ],
        analysis_tools=[
            "get_network_hot_functions",
            "get_network_hot_stacks",
            "get_network_dpcs",
            "get_per_process_socket_throughput",
            "get_connection_summary",
            "get_tcp_retransmits",
            "get_udp_flow_summary",
            "get_packet_drops",
            "get_rss_dispatch_quality",
        ],
        recommended_duration_s=10,
        est_overhead="high (~1-3 GB/min on 100 GbE under load)",
        notes=(
            "Strict=true on EP_Net_Xdp. If wpr -start fails 0xc558300c "
            "the XDP manifest is missing - use network_minimal.wprp."
        ),
        wprp_filename="network.wprp",
    ),
    "network_minimal": ProfileMeta(
        scenario="network_minimal",
        title="Networking stack without XDP",
        when_to_use=(
            "Pick this on a machine that does NOT have the XDP manifest "
            "installed. Same coverage as network.wprp minus the XDP "
            "provider - everything else (TCPIP, AFD, NDIS, QUIC, HTTP, "
            "Kernel-Network) is still captured."
        ),
        providers=[
            "Microsoft-Windows-TCPIP",
            "Microsoft-Windows-Winsock-AFD",
            "Microsoft-Windows-NDIS-PacketCapture",
            "Microsoft-Quic",
            "Microsoft-Windows-HttpService",
            "Microsoft-Windows-Kernel-Network",
            "Kernel CPU/DPC/CSwitch stacks",
        ],
        analysis_tools=[
            "get_network_hot_functions",
            "get_network_hot_stacks",
            "get_network_dpcs",
            "get_per_process_socket_throughput",
            "get_connection_summary",
            "get_tcp_retransmits",
            "get_udp_flow_summary",
            "get_packet_drops",
        ],
        recommended_duration_s=10,
        est_overhead="high (~1-3 GB/min on 100 GbE under load)",
        notes=(
            "Documented workaround for the XDP-missing-manifest case. "
            "Identical to network.wprp aside from the dropped XDP provider."
        ),
        wprp_filename="network_minimal.wprp",
    ),
    "network_packets": ProfileMeta(
        scenario="network_packets",
        title="Networking with larger ring for packet-level decode",
        when_to_use=(
            "Pick this when you need per-packet decode at 100 GbE - the "
            "EventCollector ring is doubled (2 GB) so NDIS-PacketCapture "
            "does not drop frames under multi-million-PPS traffic."
        ),
        providers=[
            "Microsoft-Windows-TCPIP",
            "Microsoft-Windows-Winsock-AFD",
            "Microsoft-Windows-NDIS-PacketCapture",
            "Microsoft-Quic",
            "Microsoft-Windows-HttpService",
            "Microsoft-Windows-Kernel-Network",
            "Kernel CPU/DPC/CSwitch stacks",
        ],
        analysis_tools=[
            "get_packet_capture_summary",
            "get_packet_timeline",
            "decode_packet",
            "get_send_recv_latency",
            "get_per_process_socket_throughput",
        ],
        recommended_duration_s=5,
        est_overhead="very high (~3-5 GB/min on 100 GbE; ring sized 2 GB)",
        notes=(
            "Drop XDP because the larger ring is usually enough. Shorten "
            "captures - 5-10s is plenty to fill the 2 GB ring at line rate."
        ),
        wprp_filename="network_packets.wprp",
    ),
    "xdp_cpumap": ProfileMeta(
        scenario="xdp_cpumap",
        title="XDP / CPUMAP fast-path debugging",
        when_to_use=(
            "Pick this when investigating the XDP fast path: CPUMAP ring "
            "behavior, drain DPC timing, NBL flow through the LWF, or "
            "XSK socket activity. Combines kernel CPU/DPC stacks with "
            "the XDP per-frame ETW + XDP WPP providers."
        ),
        providers=[
            "Microsoft-XDP (per-frame)",
            "XDP WPP",
            "Kernel CPU/DPC/CSwitch stacks",
        ],
        analysis_tools=[
            "get_dpc_summary",
            "get_dpc_per_cpu",
            "get_lock_contention",
            "get_hot_functions",
            "get_rss_dispatch_quality",
            "butterfly_chain",
        ],
        recommended_duration_s=10,
        est_overhead="high (XDP per-frame at Level 25 is verbose)",
        notes=(
            "Strict=true on both XDP providers - wpr -start fails fast "
            "if XDP isn't installed."
        ),
        wprp_filename="xdp_cpumap.wprp",
    ),
    "quic": ProfileMeta(
        scenario="quic",
        title="QUIC handshake and connection analysis",
        when_to_use=(
            "Pick this when the workload of interest is msquic. Captures "
            "MsQuic + Schannel (for TLS) + TCPIP (for UDP datapath) + "
            "AFD plus the kernel CPU/DPC/CSwitch stacks needed to "
            "correlate scheduling jitter with QUIC events."
        ),
        providers=[
            "Microsoft-Quic",
            "Microsoft-Windows-TCPIP",
            "Microsoft-Windows-Winsock-AFD",
            "Schannel WPP",
            "Kernel CPU/DPC/CSwitch stacks",
        ],
        analysis_tools=[
            "get_quic_connections",
            "get_quic_cid_distribution",
            "get_quic_ack_delays",
            "get_connect_latency",
            "get_network_hot_functions",
            "get_per_process_socket_throughput",
        ],
        recommended_duration_s=10,
        est_overhead="moderate-high (~500 MB-1 GB/min)",
        notes=(
            "TCPIP at Level 4 (Informational) only - skips per-packet "
            "send/recv to keep volume reasonable. Bump to Level 5 by "
            "editing the .wprp if you need per-UDP-packet visibility."
        ),
        wprp_filename="quic.wprp",
    ),
    "ebpf": ProfileMeta(
        scenario="ebpf",
        title="eBPF for Windows runtime + verifier",
        when_to_use=(
            "Pick this when investigating eBPF program loading, the "
            "verifier, JIT compilation, or program execution. Includes "
            "ebpfcore + netebpfext providers plus kernel CPU/DPC stacks."
        ),
        providers=[
            "eBPF ExecutionContext",
            "NetEbpfExt",
            "Microsoft-Windows-TCPIP",
            "Kernel CPU/DPC/CSwitch stacks",
        ],
        analysis_tools=[
            "get_cpu_samples",
            "get_hot_functions",
            "get_dpc_summary",
            "get_network_hot_functions",
        ],
        recommended_duration_s=10,
        est_overhead="moderate (~300-500 MB/min depending on program rate)",
        notes=(
            "ExecutionContext + NetEbpfExt require ebpf-for-windows "
            "installed. Both providers are non-Strict so the trace will "
            "still start (silently dropping them) if eBPF is missing."
        ),
        wprp_filename="ebpf.wprp",
    ),
    "general": ProfileMeta(
        scenario="general",
        title="General-purpose default (CPU + DPC + TCPIP info)",
        when_to_use=(
            "Pick this when you don't know what you're looking for. "
            "Equivalent to cpu_dpc_isr.wprp plus TCPIP at Level 4 "
            "(Informational) so you get connection-level network "
            "visibility without flooding the ring with per-packet events."
        ),
        providers=[
            "Microsoft-Windows-TCPIP (Informational)",
            "Kernel CPU/DPC/CSwitch stacks",
        ],
        analysis_tools=[
            "analyze",
            "get_cpu_samples",
            "get_hot_functions",
            "get_dpc_summary",
            "get_connection_summary",
            "get_tcp_retransmits",
        ],
        recommended_duration_s=15,
        est_overhead="moderate (~250-450 MB/min)",
        notes=(
            "Good first-pass capture when triaging an unknown problem. "
            "Switch to a more specific scenario after the initial "
            "analyze run identifies where to focus."
        ),
        wprp_filename="general.wprp",
    ),
    "pktmon": ProfileMeta(
        scenario="pktmon",
        title="pktmon packet capture (separate mechanism)",
        when_to_use=(
            "Pick this when you need a pure packet capture and have "
            "pktmon available. NOT a WPR profile - uses pktmon's own "
            "ETL/pcapng output. Call get_capture_instructions(scenario="
            "'pktmon', ...) for the alternate command set."
        ),
        providers=["pktmon (all-traffic capture)"],
        analysis_tools=[
            "get_packet_capture_summary",
            "get_packet_timeline",
            "decode_packet",
            "get_pktmon_layer_latency",
        ],
        privilege="admin (pktmon requires elevation)",
        container_compatible=False,
        vm_compatible=True,
        recommended_duration_s=10,
        est_overhead="varies with --pkt-size and filter",
        notes=(
            "pktmon is captured separately: `pktmon start --capture "
            "--pkt-size 0 -f <out.etl>`, then `pktmon stop`. The MCP "
            "tools document this in get_capture_commands and "
            "get_capture_instructions. Convert to pcapng with "
            "`pktmon etl2pcap <in.etl> -o <out.pcapng>` if a tool "
            "needs the wireshark format."
        ),
        wprp_filename=None,
        capture_tool="pktmon",
    ),
}


def load_wprp_text(scenario: str) -> str:
    """Return the raw ``.wprp`` XML for ``scenario``.

    Reads via ``importlib.resources.files`` so the lookup works whether
    the package is installed from source, a wheel, or a zipapp.

    Raises:
        KeyError: if ``scenario`` is not a known WPR scenario, or is
            the ``"pktmon"`` pseudo-scenario (which has no .wprp file).
        FileNotFoundError: if the bundled resource is missing - this
            indicates a packaging error.
    """
    if scenario not in PROFILES:
        raise KeyError(
            f"Unknown scenario {scenario!r}. Valid: "
            + ", ".join(sorted(PROFILES.keys()))
        )
    meta = PROFILES[scenario]
    if meta.wprp_filename is None:
        raise KeyError(
            f"Scenario {scenario!r} has no .wprp file - it uses the "
            f"{meta.capture_tool!r} capture mechanism. Call "
            "get_capture_commands or get_capture_instructions for it."
        )
    resource = resources.files("etw_analyzer.profiles").joinpath(
        meta.wprp_filename
    )
    return resource.read_text(encoding="utf-8")
