"""Canonical PDB identity parsing.

PE RSDS records and symbol servers identify a PDB by GUID plus the DBI stream
age.  The PDB information stream also contains an age field, but it can
legitimately differ after post-link PDB processing and is not the value used by
SymChk's ``PdbDbiAge`` validation.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path


_PDB_MSF7_MAGIC = b"Microsoft C/C++ MSF 7.00"
_PDB_MSFZ_MAGIC = b"Microsoft MSFZ Container"
_PDB_LEGACY_MAGIC = b"Microsoft C/C++ program database"
_PDB_INFO_STREAM = 1
_PDB_DBI_STREAM = 3


class PdbIdentityError(ValueError):
    """Base error for PDB identity decoding failures."""


class UnsupportedPdbFormatError(PdbIdentityError):
    """The file is a recognized PDB format this parser cannot decode."""


class InvalidPdbError(PdbIdentityError):
    """The file is not a structurally valid PDB 7.0/MSF container."""


@dataclass(frozen=True)
class PdbIdentity:
    """Strict CodeView identity for a PDB.

    ``age`` is the DBI stream age used by PE RSDS/SymChk matching.
    ``info_age`` is retained only for diagnostics.
    """

    guid: str
    age: int
    info_age: int
    format: str = "msf7"
    age_source: str = "dbi"

    @property
    def symstore_key(self) -> str:
        return f"{self.guid}{self.age:X}"


def classify_pdb_format(pdb_path: Path) -> str:
    """Return ``msf7``, ``msfz``, ``legacy``, or ``unknown``."""

    try:
        with pdb_path.open("rb") as file:
            head = file.read(64)
    except OSError:
        return "unknown"
    if head.startswith(_PDB_MSF7_MAGIC):
        return "msf7"
    if head.startswith(_PDB_MSFZ_MAGIC):
        return "msfz"
    if head.startswith(_PDB_LEGACY_MAGIC):
        return "legacy"
    return "unknown"


def _guid_from_bytes(guid_bytes: bytes) -> str:
    if len(guid_bytes) != 16:
        raise InvalidPdbError("PDB information stream contains a truncated GUID")
    data1 = int.from_bytes(guid_bytes[0:4], "little")
    data2 = int.from_bytes(guid_bytes[4:6], "little")
    data3 = int.from_bytes(guid_bytes[6:8], "little")
    data4 = guid_bytes[8:16]
    return (
        f"{data1:08X}{data2:04X}{data3:04X}"
        + "".join(f"{byte:02X}" for byte in data4)
    )


def _read_msf_streams(pdb_path: Path) -> list[bytes | None]:
    try:
        with pdb_path.open("rb") as file:
            header = file.read(56)
            if len(header) < 56 or not header.startswith(_PDB_MSF7_MAGIC):
                raise InvalidPdbError("not a PDB 7.0/MSF file")

            page_size = struct.unpack_from("<I", header, 32)[0]
            page_count = struct.unpack_from("<I", header, 40)[0]
            directory_size = struct.unpack_from("<I", header, 44)[0]
            directory_map_page = struct.unpack_from("<I", header, 52)[0]
            if page_size < 512 or page_size & (page_size - 1):
                raise InvalidPdbError(f"invalid MSF page size {page_size}")
            if page_count <= 0 or directory_size <= 0:
                raise InvalidPdbError("empty MSF page directory")

            directory_page_count = (directory_size + page_size - 1) // page_size
            if directory_page_count * 4 > page_size:
                raise UnsupportedPdbFormatError(
                    "multi-page MSF directory block maps are not supported"
                )
            if directory_map_page >= page_count:
                raise InvalidPdbError("MSF directory map page is out of range")

            file.seek(directory_map_page * page_size)
            directory_map = file.read(page_size)
            if len(directory_map) < directory_page_count * 4:
                raise InvalidPdbError("truncated MSF directory map")
            directory_pages = struct.unpack_from(
                f"<{directory_page_count}I", directory_map, 0
            )

            directory = bytearray()
            for page in directory_pages:
                if page >= page_count:
                    raise InvalidPdbError("MSF directory page is out of range")
                file.seek(page * page_size)
                data = file.read(page_size)
                if len(data) != page_size:
                    raise InvalidPdbError("truncated MSF directory page")
                directory.extend(data)
            directory = directory[:directory_size]
            if len(directory) < 4:
                raise InvalidPdbError("truncated MSF stream directory")

            stream_count = struct.unpack_from("<I", directory, 0)[0]
            sizes_end = 4 + stream_count * 4
            if stream_count <= _PDB_DBI_STREAM or sizes_end > len(directory):
                raise InvalidPdbError("PDB is missing required info/DBI streams")
            stream_sizes = struct.unpack_from(
                f"<{stream_count}I", directory, 4
            )

            page_offset = sizes_end
            streams: list[bytes | None] = []
            wanted_streams = {_PDB_INFO_STREAM, _PDB_DBI_STREAM}
            for stream_index, stream_size in enumerate(stream_sizes):
                if stream_size == 0xFFFFFFFF:
                    streams.append(None)
                    continue
                stream_page_count = (
                    (stream_size + page_size - 1) // page_size
                    if stream_size
                    else 0
                )
                page_list_end = page_offset + stream_page_count * 4
                if page_list_end > len(directory):
                    raise InvalidPdbError("truncated MSF stream page list")
                stream_pages = struct.unpack_from(
                    f"<{stream_page_count}I", directory, page_offset
                )
                page_offset = page_list_end

                if stream_index not in wanted_streams:
                    streams.append(None)
                    continue

                stream = bytearray()
                for page in stream_pages:
                    if page >= page_count:
                        raise InvalidPdbError("MSF stream page is out of range")
                    file.seek(page * page_size)
                    data = file.read(page_size)
                    if len(data) != page_size:
                        raise InvalidPdbError("truncated MSF stream page")
                    stream.extend(data)
                streams.append(bytes(stream[:stream_size]))
            return streams
    except OSError as exc:
        raise InvalidPdbError(f"cannot read PDB: {exc}") from exc
    except struct.error as exc:
        raise InvalidPdbError(f"malformed PDB structure: {exc}") from exc


def read_pdb_identity(pdb_path: Path) -> PdbIdentity:
    """Read the strict GUID + DBI age identity from a PDB 7.0 file.

    MSFZ and legacy PDB containers are rejected explicitly. Callers that can
    validate those via DbgHelp or a symstore folder may do so, but must not
    silently substitute the information-stream age.
    """

    format_name = classify_pdb_format(pdb_path)
    if format_name == "msfz":
        raise UnsupportedPdbFormatError(
            "MSFZ-compressed PDB identity requires an MSFZ-capable dbghelp"
        )
    if format_name == "legacy":
        raise UnsupportedPdbFormatError(
            "legacy pre-PDB7 containers do not provide an RSDS GUID identity"
        )
    if format_name != "msf7":
        raise InvalidPdbError("unrecognized PDB container")

    streams = _read_msf_streams(pdb_path)
    info = streams[_PDB_INFO_STREAM]
    dbi = streams[_PDB_DBI_STREAM]
    if info is None or len(info) < 28:
        raise InvalidPdbError("PDB information stream is missing or truncated")
    if dbi is None or len(dbi) < 12:
        raise InvalidPdbError("PDB DBI stream is missing or truncated")

    _version, _signature, info_age = struct.unpack_from("<III", info, 0)
    dbi_signature, _dbi_version, dbi_age = struct.unpack_from("<iII", dbi, 0)
    if dbi_signature != -1:
        raise InvalidPdbError(
            f"invalid DBI stream signature {dbi_signature}"
        )
    if dbi_age <= 0:
        raise InvalidPdbError(f"invalid DBI age {dbi_age}")

    return PdbIdentity(
        guid=_guid_from_bytes(info[12:28]),
        age=int(dbi_age),
        info_age=int(info_age),
    )
