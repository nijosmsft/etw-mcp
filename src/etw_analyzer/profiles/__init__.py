"""Vendored WPR profiles and per-profile metadata.

Each ``<scenario>.wprp`` file is shipped inside the wheel. Use
``etw_analyzer.profiles.metadata.load_wprp_text(scenario)`` to read the
XML at runtime via ``importlib.resources`` (works regardless of whether
the package is installed from source, a wheel, or a zipapp).
"""
