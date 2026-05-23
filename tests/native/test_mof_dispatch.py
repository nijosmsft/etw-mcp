"""Test the kernel-MOF dispatch registration."""

from __future__ import annotations

from etw_analyzer.native.mof import (
    kernel_provider_guids,
    register_kernel_handlers,
)


def test_register_populates_dispatch_table():
    table: dict = {}
    register_kernel_handlers(table)

    # The table must be non-trivially large — every kernel provider should
    # contribute at least one entry.
    assert len(table) >= 25

    # Keys must be (guid_lower, opcode_int, version_or_None) tuples.
    for key, entry in table.items():
        guid, opcode, version = key
        assert isinstance(guid, str) and guid == guid.lower()
        assert isinstance(opcode, int)
        assert version is None or isinstance(version, int)
        canonical, fn = entry
        assert isinstance(canonical, str)
        assert callable(fn)


def test_register_does_not_clobber_existing_entries():
    """User-registered overrides must take priority."""
    sentinel = ("OVERRIDE", lambda payload, hdr: None)
    table: dict = {
        ("ce1dbfb4-137e-4da6-87b0-3f59aa102cbc", 46, None): sentinel,
    }
    register_kernel_handlers(table)
    assert table[("ce1dbfb4-137e-4da6-87b0-3f59aa102cbc", 46, None)] is sentinel


def test_kernel_provider_guids_includes_all_modules():
    guids = kernel_provider_guids()
    expected = {
        "ce1dbfb4-137e-4da6-87b0-3f59aa102cbc",   # PerfInfo
        "def2fe46-7bd6-4b80-bd94-f57fe20d0ce3",   # StackWalk
        "3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c",   # Thread
        "3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c",   # Process
        "2cb15d1d-5fc1-11d2-abe1-00a0c911f518",   # Image
        "3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c",   # DiskIo
        "90cbdc39-4a3e-11d1-84f4-0000f80464e3",   # FileIo
        "68fdd900-4a3e-11d1-84f4-0000f80464e3",   # EventTrace
        "01853a65-418f-4f36-aefc-dc0f1d2fd235",   # SystemConfig
    }
    assert expected.issubset(guids)


def test_perfinfo_sampledprofile_registered():
    """Most-common kernel event — SampledProfile @ opcode 46."""
    table: dict = {}
    register_kernel_handlers(table)
    entry = table.get(("ce1dbfb4-137e-4da6-87b0-3f59aa102cbc", 46, None))
    assert entry is not None
    canonical, _fn = entry
    assert canonical == "SampledProfile"


def test_cswitch_routes_to_existing_decoder():
    """The Phase N0 decoder (parsing.mof_cswitch.decode_cswitch_v5) must be
    the one wired in — we don't fork its enum tables."""
    from etw_analyzer.parsing.mof_cswitch import decode_cswitch_v5

    table: dict = {}
    register_kernel_handlers(table)
    entry = table.get(("3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c", 36, None))
    assert entry is not None
    canonical, fn = entry
    assert canonical == "CSwitch"
    assert fn is decode_cswitch_v5
