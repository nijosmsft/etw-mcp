"""Tests for :mod:`etw_analyzer.native.mof.imageid` (M5 -- ImageID/DbgID_RSDS decoder).

Reference values from the real ETL (wpa5-1M-260615-143816.etl), first RSDS
record captured at trace-start rundown:
  ImageBase = 0xFFFFF8057E600000
  GUID      = AFB1E3B1-3754-8BA7-3B92-C060D6D5605F
  Age       = 1
  PdbName   = ntkrnlmp.pdb  (basename of the kernel PDB)

These constants drive the unit tests so that any regression in GUID byte-order
handling or null-terminator parsing is immediately visible.

Coverage
--------
1. ``test_decode_ntoskrnl_*``   -- reference values, basic correctness.
2. ``test_format_guid_*``       -- GUID formatting edge cases.
3. ``test_full_build_path``     -- basename extraction from full path.
4. ``test_too_short_*``         -- guard against under-length payloads.
5. ``test_zero_guid``           -- all-zero GUID treated as invalid.
6. ``test_handlers_*``          -- HANDLERS registration + dispatch.
7. ``test_merge_rsds_*``        -- _merge_rsds_into_image_rows helper.
8. ``test_kernel_pid0_present`` -- Bug C regression (kernel PID=0 rows survive).
"""

from __future__ import annotations

import struct

import pytest

from etw_analyzer.native.mof.imageid import (
    HANDLERS,
    PROVIDER_GUID,
    _format_guid,
    decode_dbgid_rsds,
)
from etw_analyzer.native.extract import _merge_rsds_into_image_rows


# ---------------------------------------------------------------------------
# Reference payload for ntoskrnl RSDS record
# ---------------------------------------------------------------------------

_NTOSKRNL_IMAGE_BASE = 0xFFFFF8057E600000
_NTOSKRNL_GUID_STR   = "AFB1E3B1-3754-8BA7-3B92-C060D6D5605F"
_NTOSKRNL_AGE        = 1
_NTOSKRNL_PDB        = "ntkrnlmp.pdb"


def _build_ntoskrnl_payload(pdb_name: bytes = b"ntkrnlmp.pdb\x00") -> bytes:
    """Construct a synthetic DbgID_RSDS payload matching the reference record.

    Layout: ImageBase(8) + Reserved(4) + GUID(16) + Age(4) + PdbFileName.
    The 4-byte Reserved field is zero for kernel images (version 2 on-wire layout
    confirmed by raw-byte probe on wpa5-1M-260615-143816.etl).
    """
    return (
        struct.pack("<Q", _NTOSKRNL_IMAGE_BASE)          # ImageBase  (offset 0)
        + struct.pack("<I", 0)                            # Reserved   (offset 8, always 0)
        + struct.pack("<IHH", 0xAFB1E3B1, 0x3754, 0x8BA7)  # GUID Data1/2/3 LE (offset 12)
        + bytes([0x3B, 0x92, 0xC0, 0x60, 0xD6, 0xD5, 0x60, 0x5F])  # Data4 (offset 20)
        + struct.pack("<I", _NTOSKRNL_AGE)                # Age        (offset 28)
        + pdb_name                                        # PdbFileName (offset 32)
    )


_NTOSKRNL_HDR = {"TimeStamp": 0x12345678, "ProcessorNumber": 0, "ProcessId": 0}


# ---------------------------------------------------------------------------
# 1. Basic decode correctness
# ---------------------------------------------------------------------------

def test_decode_ntoskrnl_guid():
    row = decode_dbgid_rsds(_build_ntoskrnl_payload(), _NTOSKRNL_HDR)
    assert row is not None
    assert row["PdbGuid"] == _NTOSKRNL_GUID_STR


def test_decode_ntoskrnl_age():
    row = decode_dbgid_rsds(_build_ntoskrnl_payload(), _NTOSKRNL_HDR)
    assert row is not None
    assert row["PdbAge"] == _NTOSKRNL_AGE


def test_decode_ntoskrnl_pdb_name():
    row = decode_dbgid_rsds(_build_ntoskrnl_payload(), _NTOSKRNL_HDR)
    assert row is not None
    assert row["PdbName"] == _NTOSKRNL_PDB


def test_decode_ntoskrnl_image_base():
    row = decode_dbgid_rsds(_build_ntoskrnl_payload(), _NTOSKRNL_HDR)
    assert row is not None
    assert row["ImageBase"] == _NTOSKRNL_IMAGE_BASE


def test_decode_ntoskrnl_process_id_from_header():
    """ProcessId must come from the event header (kernel images have PID=0)."""
    row = decode_dbgid_rsds(_build_ntoskrnl_payload(), {**_NTOSKRNL_HDR, "ProcessId": 0})
    assert row is not None
    assert row["ProcessId"] == 0


def test_decode_ntoskrnl_pdb_full_path_raw():
    row = decode_dbgid_rsds(_build_ntoskrnl_payload(), _NTOSKRNL_HDR)
    assert row is not None
    assert row["PdbFullPath"] == "ntkrnlmp.pdb"


# ---------------------------------------------------------------------------
# 2. GUID formatting
# ---------------------------------------------------------------------------

def test_format_guid_ntoskrnl():
    guid_bytes = (
        struct.pack("<IHH", 0xAFB1E3B1, 0x3754, 0x8BA7)
        + bytes([0x3B, 0x92, 0xC0, 0x60, 0xD6, 0xD5, 0x60, 0x5F])
    )
    result = _format_guid(guid_bytes)
    assert result == "AFB1E3B1-3754-8BA7-3B92-C060D6D5605F"


def test_format_guid_is_uppercase():
    guid_bytes = struct.pack("<IHH", 0xAABBCCDD, 0x1122, 0x3344) + b"\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11"
    result = _format_guid(guid_bytes)
    assert result == result.upper()


def test_format_guid_too_short_returns_empty():
    assert _format_guid(b"\x00" * 8) == ""


def test_format_guid_length():
    guid_bytes = struct.pack("<IHH", 1, 2, 3) + bytes(8)
    result = _format_guid(guid_bytes)
    # 8-4-4-4-12 + 3 dashes = 32 hex chars + 4 dashes = 36 chars
    assert len(result) == 36
    parts = result.split("-")
    assert [len(p) for p in parts] == [8, 4, 4, 4, 12]


# ---------------------------------------------------------------------------
# 3. PdbFileName basename extraction
# ---------------------------------------------------------------------------

def test_full_build_path_basename():
    """A full Windows build path must be reduced to the basename only."""
    full_path = rb"C:\__w\1\s\build\bin\amd64fre\kmdll\symcryptk.pdb" + b"\x00"
    payload = _build_ntoskrnl_payload(pdb_name=full_path)
    row = decode_dbgid_rsds(payload, _NTOSKRNL_HDR)
    assert row is not None
    assert row["PdbName"] == "symcryptk.pdb"
    assert row["PdbFullPath"].endswith("symcryptk.pdb")


def test_no_null_terminator_still_decodes():
    """If the string is not null-terminated, consume the rest of payload."""
    payload = _build_ntoskrnl_payload(pdb_name=b"ntkrnlmp.pdb")  # no \x00
    row = decode_dbgid_rsds(payload, _NTOSKRNL_HDR)
    assert row is not None
    assert row["PdbName"] == "ntkrnlmp.pdb"


def test_empty_pdb_name():
    """Payload with only a null terminator for PdbFileName must not crash."""
    payload = _build_ntoskrnl_payload(pdb_name=b"\x00")
    row = decode_dbgid_rsds(payload, _NTOSKRNL_HDR)
    # A null-GUID row is filtered earlier; this has valid GUID so we get a row.
    assert row is not None
    assert row["PdbName"] == ""


# ---------------------------------------------------------------------------
# 4. Guard against bad/short payloads
# ---------------------------------------------------------------------------

def test_too_short_payload_returns_none():
    assert decode_dbgid_rsds(b"\x00" * 10, _NTOSKRNL_HDR) is None


def test_exactly_31_bytes_returns_none():
    """One byte short of the 32-byte fixed prefix must return None."""
    assert decode_dbgid_rsds(b"\x01" * 31, _NTOSKRNL_HDR) is None


def test_exactly_32_bytes_with_empty_pdb_name():
    """32 bytes (no PdbFileName bytes at all) is valid -- empty PdbName."""
    payload = (
        struct.pack("<Q", _NTOSKRNL_IMAGE_BASE)
        + struct.pack("<I", 0)                            # Reserved
        + struct.pack("<IHH", 0xAFB1E3B1, 0x3754, 0x8BA7)
        + bytes([0x3B, 0x92, 0xC0, 0x60, 0xD6, 0xD5, 0x60, 0x5F])
        + struct.pack("<I", _NTOSKRNL_AGE)
        # No PdbFileName bytes
    )
    assert len(payload) == 32
    row = decode_dbgid_rsds(payload, _NTOSKRNL_HDR)
    # The GUID is valid so the row is produced with empty PdbName.
    assert row is not None
    assert row["PdbName"] == ""


# ---------------------------------------------------------------------------
# 5. Invalid GUID handling
# ---------------------------------------------------------------------------

def test_zero_guid_returns_none():
    """All-zero GUID is not a valid PDB identity."""
    payload = (
        struct.pack("<Q", _NTOSKRNL_IMAGE_BASE)
        + struct.pack("<I", 0)    # Reserved
        + bytes(16)               # zero GUID
        + struct.pack("<I", 1)    # Age
        + b"fake.pdb\x00"
    )
    assert decode_dbgid_rsds(payload, _NTOSKRNL_HDR) is None


# ---------------------------------------------------------------------------
# 6. HANDLERS registration
# ---------------------------------------------------------------------------

def test_handlers_key_36():
    """Opcode 36 is the DbgID_RSDS event."""
    assert (36, None) in HANDLERS


def test_handlers_canonical_name():
    canonical, fn = HANDLERS[(36, None)]
    assert canonical == "ImageID/DbgID_RSDS"


def test_handlers_fn_is_callable():
    _, fn = HANDLERS[(36, None)]
    assert callable(fn)


def test_provider_guid_value():
    # M5b fix: the actual EVENT_RECORD ProviderId for ImageID kernel events is
    # b3e675d7-..., NOT b059b83f-... (the manifest provider GUID).
    # Confirmed by raw-byte probe on wpa5-1M-260615-143816.etl: 13104 events
    # under b3e675d7, 0 events under b059b83f.
    assert PROVIDER_GUID == "b3e675d7-2554-4f18-830b-2762732560de"


def test_handler_dispatches_correctly():
    """HANDLERS[(36, None)][1] is exactly decode_dbgid_rsds."""
    _, fn = HANDLERS[(36, None)]
    assert fn is decode_dbgid_rsds


# ---------------------------------------------------------------------------
# 7. _merge_rsds_into_image_rows
# ---------------------------------------------------------------------------

def _rsds_row(
    base: int, pid: int = 0, guid: str = _NTOSKRNL_GUID_STR,
    age: int = 1, name: str = "ntkrnlmp.pdb",
) -> dict:
    return {
        "ProcessId": pid,
        "ImageBase": base,
        "PdbGuid": guid,
        "PdbAge": age,
        "PdbName": name,
        "PdbFullPath": name,
    }


def _image_row(base: int, pid: int = 0, fname: str = "ntoskrnl.exe") -> dict:
    return {
        "ProcessId": pid,
        "ImageBase": base,
        "ImageSize": 0x800000,
        "FileName": fname,
        "PdbGuid": None,
        "PdbAge": None,
        "PdbName": None,
    }


def test_merge_rsds_adds_pdb_guid():
    rows_by_class: dict[str, list[dict]] = {
        "Image/Load": [_image_row(_NTOSKRNL_IMAGE_BASE)],
        "ImageID/DbgID_RSDS": [_rsds_row(_NTOSKRNL_IMAGE_BASE)],
    }
    _merge_rsds_into_image_rows(rows_by_class)
    row = rows_by_class["Image/Load"][0]
    assert row["PdbGuid"] == _NTOSKRNL_GUID_STR
    assert row["PdbAge"] == 1
    assert row["PdbName"] == "ntkrnlmp.pdb"


def test_merge_rsds_dcstart():
    rows_by_class: dict[str, list[dict]] = {
        "Image/DCStart": [_image_row(_NTOSKRNL_IMAGE_BASE)],
        "ImageID/DbgID_RSDS": [_rsds_row(_NTOSKRNL_IMAGE_BASE)],
    }
    _merge_rsds_into_image_rows(rows_by_class)
    row = rows_by_class["Image/DCStart"][0]
    assert row["PdbGuid"] == _NTOSKRNL_GUID_STR


def test_merge_rsds_no_rsds_rows_is_noop():
    rows_by_class: dict[str, list[dict]] = {
        "Image/Load": [_image_row(_NTOSKRNL_IMAGE_BASE)],
    }
    _merge_rsds_into_image_rows(rows_by_class)
    row = rows_by_class["Image/Load"][0]
    # No RSDS data -- PdbGuid stays None.
    assert row["PdbGuid"] is None


def test_merge_rsds_does_not_overwrite_existing_guid():
    """If an image row already has a PdbGuid, it must not be clobbered."""
    existing_guid = "00000000-0000-0000-0000-000000000001"
    img = _image_row(_NTOSKRNL_IMAGE_BASE)
    img["PdbGuid"] = existing_guid
    rows_by_class: dict[str, list[dict]] = {
        "Image/Load": [img],
        "ImageID/DbgID_RSDS": [_rsds_row(_NTOSKRNL_IMAGE_BASE)],
    }
    _merge_rsds_into_image_rows(rows_by_class)
    assert rows_by_class["Image/Load"][0]["PdbGuid"] == existing_guid


def test_merge_rsds_primary_key_pid_base():
    """Primary join key is (ProcessId, ImageBase)."""
    base = 0x7FFF00000000
    img = _image_row(base, pid=1234)
    rsds = _rsds_row(base, pid=1234, name="user.pdb")
    rows_by_class: dict[str, list[dict]] = {
        "Image/Load": [img],
        "ImageID/DbgID_RSDS": [rsds],
    }
    _merge_rsds_into_image_rows(rows_by_class)
    assert rows_by_class["Image/Load"][0]["PdbName"] == "user.pdb"


def test_merge_rsds_fallback_base_only():
    """Fallback key (ImageBase alone) used when ProcessId differs."""
    base = _NTOSKRNL_IMAGE_BASE
    # RSDS has PID=4 (System), image row has PID=0 -- common for kernel rundown.
    img = _image_row(base, pid=0)
    rsds = _rsds_row(base, pid=4)
    rows_by_class: dict[str, list[dict]] = {
        "Image/Load": [img],
        "ImageID/DbgID_RSDS": [rsds],
    }
    _merge_rsds_into_image_rows(rows_by_class)
    # Fallback by ImageBase must still find the RSDS row.
    assert rows_by_class["Image/Load"][0]["PdbGuid"] == _NTOSKRNL_GUID_STR


def test_merge_rsds_multiple_images():
    """Every image row must receive its own RSDS identity."""
    base_a = 0xFFFFF80100000000
    base_b = 0xFFFFF80200000000
    rows_by_class: dict[str, list[dict]] = {
        "Image/Load": [_image_row(base_a, fname="a.sys"), _image_row(base_b, fname="b.sys")],
        "ImageID/DbgID_RSDS": [
            _rsds_row(base_a, name="a.pdb"),
            _rsds_row(base_b, name="b.pdb"),
        ],
    }
    _merge_rsds_into_image_rows(rows_by_class)
    names = {r["PdbName"] for r in rows_by_class["Image/Load"]}
    assert names == {"a.pdb", "b.pdb"}


def test_merge_rsds_empty_rows_by_class():
    """Must not raise on an empty input dict."""
    rows_by_class: dict[str, list[dict]] = {}
    _merge_rsds_into_image_rows(rows_by_class)  # should not raise


# ---------------------------------------------------------------------------
# 8. Bug C regression: kernel PID=0 image rows must survive extraction
# ---------------------------------------------------------------------------

def test_kernel_pid0_image_row_survives_merge():
    """Image rows with ProcessId=0 (kernel images) must not be dropped."""
    base = _NTOSKRNL_IMAGE_BASE
    rows_by_class: dict[str, list[dict]] = {
        "Image/Load": [_image_row(base, pid=0, fname="ntoskrnl.exe")],
        "ImageID/DbgID_RSDS": [_rsds_row(base, pid=0)],
    }
    _merge_rsds_into_image_rows(rows_by_class)
    # Row must still be present, and now have PdbGuid.
    rows = rows_by_class["Image/Load"]
    assert len(rows) == 1
    assert rows[0]["ProcessId"] == 0
    assert rows[0]["PdbGuid"] == _NTOSKRNL_GUID_STR


def test_kernel_images_not_filtered_by_pid_in_merge():
    """_merge_rsds_into_image_rows must not filter out PID=0 or any PID."""
    pids = [0, 4, 1234, 9999]
    image_rows = [_image_row(0xFFFFF80000000000 + i * 0x1000000, pid=p) for i, p in enumerate(pids)]
    rsds_rows = [
        _rsds_row(0xFFFFF80000000000 + i * 0x1000000, pid=p, name=f"mod{i}.pdb")
        for i, p in enumerate(pids)
    ]
    rows_by_class: dict[str, list[dict]] = {
        "Image/Load": image_rows,
        "ImageID/DbgID_RSDS": rsds_rows,
    }
    _merge_rsds_into_image_rows(rows_by_class)
    assert len(rows_by_class["Image/Load"]) == len(pids)
    for i, row in enumerate(rows_by_class["Image/Load"]):
        assert row["PdbGuid"] == _NTOSKRNL_GUID_STR, f"Row {i} lost PdbGuid"


# ---------------------------------------------------------------------------
# 9. Dispatch-path regression (M5b fix)
#    Verify that the corrected PROVIDER_GUID causes the event to route through
#    the MOF dispatch table and produce the correct PDB identity.
# ---------------------------------------------------------------------------

def test_dispatch_guid_is_correct_event_class_guid():
    """PROVIDER_GUID must be the event-class GUID seen in EVENT_RECORD.ProviderId.

    b3e675d7-2554-4f18-830b-2762732560de is the GUID confirmed by raw-byte
    probe (13 104 events).  b059b83f-... is the manifest provider GUID which
    yields 0 events in the callback.
    """
    assert PROVIDER_GUID == "b3e675d7-2554-4f18-830b-2762732560de"
    assert PROVIDER_GUID != "b059b83f-d946-4b13-87ca-4292839dc2f2"


def test_dispatch_table_contains_correct_guid():
    """_DISPATCH must have an entry keyed on (b3e675d7-..., 36, None)."""
    from etw_analyzer.native.extract import _DISPATCH

    key = ("b3e675d7-2554-4f18-830b-2762732560de", 36, None)
    assert key in _DISPATCH, (
        "ImageID/DbgID_RSDS not reachable: b3e675d7-... opcode=36 missing from _DISPATCH"
    )
    canonical, fn = _DISPATCH[key]
    assert canonical == "ImageID/DbgID_RSDS"
    assert fn is decode_dbgid_rsds


def test_dispatch_table_does_not_have_old_guid():
    """_DISPATCH must NOT have the manifest provider GUID b059b83f-... at opcode 36.

    That GUID produced 0 hits in the EVENT_RECORD callback; adding it to the
    dispatch table would be dead code and confuse future readers.
    """
    from etw_analyzer.native.extract import _DISPATCH

    key = ("b059b83f-d946-4b13-87ca-4292839dc2f2", 36, None)
    assert key not in _DISPATCH, (
        "Dead-code dispatch entry for b059b83f-... should have been removed"
    )


def test_dispatch_path_decodes_ntoskrnl_guid():
    """End-to-end: routing through _DISPATCH with correct GUID yields AFB1E3B1 GUID."""
    from etw_analyzer.native.extract import _DISPATCH

    key = ("b3e675d7-2554-4f18-830b-2762732560de", 36, None)
    assert key in _DISPATCH
    canonical, fn = _DISPATCH[key]
    payload = _build_ntoskrnl_payload()
    row = fn(payload, _NTOSKRNL_HDR)
    assert row is not None
    assert row["PdbGuid"] == _NTOSKRNL_GUID_STR
    assert row["PdbAge"] == _NTOSKRNL_AGE
    assert row["PdbName"] == _NTOSKRNL_PDB


def test_kernel_provider_guids_contains_new_guid():
    """b3e675d7-... must be in the kernel-provider set so TDH skips it."""
    from etw_analyzer.native.mof import kernel_provider_guids

    assert "b3e675d7-2554-4f18-830b-2762732560de" in kernel_provider_guids()


def test_kernel_provider_guids_does_not_contain_old_guid():
    """b059b83f-... must NOT be in the kernel-provider TDH-skip set."""
    from etw_analyzer.native.mof import kernel_provider_guids

    assert "b059b83f-d946-4b13-87ca-4292839dc2f2" not in kernel_provider_guids()
