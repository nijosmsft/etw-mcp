"""ctypes bindings for the Windows ETW consumer APIs.

The split mirrors the underlying DLL boundaries:

    * :mod:`.types` — pure struct definitions (no DLL calls).
    * :mod:`.advapi32` — ``OpenTraceW`` / ``ProcessTrace`` / ``CloseTrace``
      and the ``PROCESS_TRACE_MODE_*`` flag constants.
    * :mod:`.tdh` — Trace Data Helper APIs used by manifest-event decoding
      (Phase N2 will start consuming them).

Importing any of these modules outside of Windows raises ``OSError``.
The :func:`native.is_available` helper catches that so callers can
probe before committing to native mode.
"""

from __future__ import annotations

from . import types  # noqa: F401  (re-export module)

__all__ = ["types"]
