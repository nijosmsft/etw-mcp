"""Guardrails against the two schema-drift bugs that silently broke the
dotnet sidecar's cpu_sampling extraction.

Background
----------
The C# sidecar embeds an ``event_schema_version`` in its cache manifest that
MUST equal Python's ``schemas.EVENT_SCHEMA_VERSION``. When the two drifted
(C# stayed at 4 while Python moved to 5) the native cache validator rejected
*every* dotnet load, auto-mode fell back to native, and the streaming native
path silently produced no ``cpu_sampling`` — the trace looked empty even
though SampledProfile events were present. See ``native/cache.py::validate_manifest``.

A second, related regression: ``aggregation_worker._rewrite_manifest`` derives
the set of ``dumper-parquet`` stems from ``_SIDECAR_STEM_TO_ATTR``. The native
loader (``trace_mgmt._required_dumper_stems_for_mode``) independently requires
every dumper stem from ``_DUMPER_EVENT_CLASSES``. If a required stem is missing
from ``_SIDECAR_STEM_TO_ATTR`` (as ``readythread`` once was), the promoted cache
is rejected with "<stem> missing" and the whole load fails.

These tests fail loudly the next time either invariant is broken, so the fix
isn't rediscovered the hard way against an 800 MB trace.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from etw_analyzer.native.schemas import EVENT_SCHEMA_VERSION, EVENT_SCHEMAS


_REPO_ROOT = Path(__file__).resolve().parents[1]
_MANIFEST_EMITTER = _REPO_ROOT / "dotnet" / "src" / "ManifestEmitter.cs"
_ROWS_CS = _REPO_ROOT / "dotnet" / "src" / "Rows.cs"


def _read_cs(path: Path) -> str:
    if not path.exists():
        pytest.skip(f"C# sidecar source not present: {path}")
    return path.read_text(encoding="utf-8")


def test_sidecar_event_schema_version_matches_python():
    """The C# sidecar manifest version must equal Python's EVENT_SCHEMA_VERSION.

    A mismatch makes native/cache.py::validate_manifest reject every dotnet
    cache, which is exactly the bug that hid cpu_sampling.
    """
    source = _read_cs(_MANIFEST_EMITTER)
    match = re.search(r"event_schema_version\s*=\s*(\d+)", source)
    assert match, (
        "could not find `event_schema_version = <n>` in ManifestEmitter.cs; "
        "if the assignment was renamed, update this test AND keep it in sync "
        "with schemas.EVENT_SCHEMA_VERSION"
    )
    cs_version = int(match.group(1))
    assert cs_version == EVENT_SCHEMA_VERSION, (
        f"C# sidecar event_schema_version={cs_version} but Python "
        f"EVENT_SCHEMA_VERSION={EVENT_SCHEMA_VERSION}. These MUST match or the "
        "native cache validator rejects every dotnet load (cpu_sampling and "
        "all sidecar datasets silently vanish). Bump ManifestEmitter.cs and "
        "rebuild/redeploy the sidecar."
    )


def test_sidecar_stems_cover_required_native_dumper_stems():
    """Every dumper stem the native loader requires must be reclassifiable.

    ``_rewrite_manifest`` builds its dumper-parquet set from
    ``_SIDECAR_STEM_TO_ATTR``. ``_required_dumper_stems_for_mode('native')``
    independently requires all ``_DUMPER_EVENT_CLASSES`` stems. If the former
    misses a stem the latter requires, the promoted cache is rejected with
    "<stem> missing" (this is exactly what happened to ``readythread``).
    """
    from etw_analyzer.native.aggregation_worker import _SIDECAR_STEM_TO_ATTR
    from etw_analyzer.tools.trace_mgmt import _required_dumper_stems_for_mode

    required = set(_required_dumper_stems_for_mode("native"))
    available = set(_SIDECAR_STEM_TO_ATTR.keys())
    missing = required - available
    assert not missing, (
        "dumper stems required by the native cache loader are absent from "
        f"_SIDECAR_STEM_TO_ATTR: {sorted(missing)}. Add them so "
        "_rewrite_manifest reclassifies them as dumper-parquet "
        "(materialize_on_load=False); otherwise the promoted dotnet cache is "
        "rejected on load."
    )


def test_python_cswitch_schema_has_v5_columns():
    """The v5 cswitch columns must be present in the Python store schema."""
    cswitch = EVENT_SCHEMAS["cswitch"]
    names = set(cswitch.schema.names)
    for col in ("WaitMode", "NewPriority", "OldPriority"):
        assert col in names, (
            f"cswitch v5 column {col!r} missing from EVENT_STORE_SCHEMAS; "
            "the schema and EVENT_SCHEMA_VERSION were bumped together — keep "
            "them in sync."
        )


def test_sidecar_cswitch_row_has_v5_fields():
    """The C# CSwitchRow must carry the v5 wait-state / priority fields.

    Guards against the C# row struct drifting behind the Python schema (the
    sidecar would then emit a v5 manifest without the v5 columns).
    """
    source = _read_cs(_ROWS_CS)
    # Isolate the CSwitchRow definition so we don't match identically-named
    # fields on other row types.
    struct_match = re.search(
        r"(?:record|class|struct)\s+CSwitchRow\b.*?\{(.*?)\n\}",
        source,
        re.DOTALL,
    )
    assert struct_match, "could not locate CSwitchRow definition in Rows.cs"
    body = struct_match.group(1)
    for field in ("WaitMode", "NewPriority", "OldPriority"):
        assert re.search(rf"\b{field}\b", body), (
            f"CSwitchRow is missing the v5 field {field!r}; the C# sidecar "
            "would emit a v5 manifest without the v5 cswitch columns."
        )
