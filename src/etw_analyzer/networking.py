"""Curated lists of Windows networking modules.

Used by the network-lens tools in :mod:`etw_analyzer.tools.network_lenses` to
default ``module_filter``-style args to "anything that looks like the network
stack". Modules are referenced via case-insensitive substring matching by the
underlying tools, so casing variations between xperf outputs (e.g. ``NDIS.SYS``
in DPC tables vs. ``ndis.sys`` in sampling tables) are tolerated.

Callers can extend or override the default set per-call via ``extra_modules``
and ``replace_modules`` arguments on the tool wrappers.
"""

from __future__ import annotations

import re

NETWORK_KERNEL_MODULES: frozenset[str] = frozenset({
    # Core Windows network stack
    "tcpip.sys", "tcpip6.sys", "NDIS.SYS", "afd.sys", "http.sys",
    "fwpkclnt.sys", "netio.sys", "wfplwfs.sys",
    # XDP / eBPF
    "xdp.sys", "xdplwf.sys", "ebpfcore.sys", "netebpfext.sys",
    # NIC drivers / virtual switch — extend as encountered
    "mlx5.sys", "mlx4_bus.sys", "ixgbe.sys", "i40ea.sys", "vmswitch.sys",
})

NETWORK_USER_MODULES: frozenset[str] = frozenset({
    "ws2_32.dll", "wininet.dll", "winhttp.dll", "mswsock.dll",
    "msquic.dll", "schannel.dll", "ncrypt.dll",
})

NETWORK_MODULES_ALL: frozenset[str] = NETWORK_KERNEL_MODULES | NETWORK_USER_MODULES


def resolve_module_set(
    extra_modules: list[str] | None = None,
    replace_modules: list[str] | None = None,
) -> frozenset[str]:
    """Return the effective module set for a network-lens tool call.

    - ``replace_modules`` (if non-empty) wins and overrides the default entirely.
    - ``extra_modules`` (if non-empty) is unioned with the default set.
    - Otherwise returns :data:`NETWORK_MODULES_ALL`.
    """
    if replace_modules:
        return frozenset(m.strip() for m in replace_modules if m and m.strip())
    if extra_modules:
        return NETWORK_MODULES_ALL | frozenset(
            m.strip() for m in extra_modules if m and m.strip()
        )
    return NETWORK_MODULES_ALL


def module_regex(modules: frozenset[str] | set[str] | list[str]) -> str:
    """Build a case-insensitive regex that matches any module name in ``modules``.

    The underlying tools call ``pandas.Series.str.contains(pattern, case=False)``
    which supports regex by default, so a ``|``-joined alternation of escaped
    names is the cheapest way to express "match any of these modules" through
    the existing ``module_filter`` arg.
    """
    if not modules:
        # An impossible-to-match pattern keeps semantics sane for empty sets.
        return r"(?!x)x"
    return "|".join(re.escape(m) for m in sorted(modules))


def modules_csv(modules: frozenset[str] | set[str] | list[str]) -> str:
    """Build a comma-separated module list for tools that accept that format.

    Used by :func:`get_network_hot_functions` to feed the ``modules`` arg of
    :func:`etw_analyzer.tools.cpu_sampling.get_hot_functions`, which expects
    comma-separated names rather than a regex.
    """
    return ",".join(sorted(modules)) if modules else ""
