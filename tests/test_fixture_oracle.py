from __future__ import annotations

import json
from pathlib import Path

from scripts import fixture_oracle


PKTMON_TEXT = """\
10:00:00.000001 PktGroupId 1, PktNumber 1, Appearance 1, Direction Tx, Type Ethernet, Component 12, Edge 1, OriginalSize 60, LoggedSize 60
\tIPv4, length 46: 192.0.2.1.5000 > 198.51.100.2.443: tcp
10:00:00.000002 PktGroupId 1, PktNumber 1, Appearance 2, Direction Tx, Type Ethernet, Component 4, Edge 1, OriginalSize 60, LoggedSize 60
\tIPv4, length 46: 192.0.2.1.5000 > 198.51.100.2.443: tcp
10:00:00.000003 PktGroupId 2, PktNumber 1, Appearance 1, Direction Rx, Type Ethernet, Component 1, Edge 1, OriginalSize 70, LoggedSize 70
\tIPv4, length 56: 198.51.100.2.443 > 192.0.2.1.5000: tcp
10:00:00.000004 Drop: PktGroupId 3, PktNumber 1, Appearance 1, Direction Rx, Type Ethernet, Component 1, Edge 1, OriginalSize 80, LoggedSize 80
\tIPv4, length 66: 203.0.113.10.53 > 192.0.2.1.53000: udp
10:00:00.000005 PktGroupId 4, PktNumber 1, Appearance 1, Direction Rx, Type IP, Component 1, Edge 1, OriginalSize 90, LoggedSize 90
\tIPv4, length 76: 203.0.113.10.53 > 192.0.2.1.53000: udp
"""


def test_parse_pktmon_boundary_rows_uses_tx12_rx1_boundaries() -> None:
    rows = fixture_oracle.parse_pktmon_boundary_rows(PKTMON_TEXT)

    assert rows == [
        {
            "direction": "send",
            "five_tuple": "192.0.2.1:5000 -> 198.51.100.2:443/tcp",
            "protocol": "tcp",
            "size": 60,
        },
        {
            "direction": "recv",
            "five_tuple": "198.51.100.2:443 -> 192.0.2.1:5000/tcp",
            "protocol": "tcp",
            "size": 70,
        },
    ]


def test_summarize_pktmon_rows_counts_packets_and_flows() -> None:
    rows = fixture_oracle.parse_pktmon_boundary_rows(PKTMON_TEXT)
    summary = fixture_oracle.summarize_pktmon_rows(rows)

    assert summary["total_packets"] == 2
    assert summary["send_packets"] == 1
    assert summary["recv_packets"] == 1
    assert summary["total_bytes"] == 130
    assert summary["protocols"] == {"tcp": 2}
    assert [flow["total_packets"] for flow in summary["five_tuples"]] == [1, 1]


def test_metadata_generate_and_validate_round_trip(tmp_path: Path, monkeypatch) -> None:
    fixture_root = tmp_path / "fixtures"
    fixture_dir = fixture_root / "tiny"
    fixture_dir.mkdir(parents=True)
    etl_path = fixture_dir / "tiny.etl"
    etl_path.write_bytes(b"not a real etl")
    expected_path = fixture_dir / "expected.json"
    monkeypatch.setattr(fixture_oracle, "FIXTURE_ROOT", fixture_root)

    data = fixture_oracle.generate_expected("tiny", "metadata", expected_path)
    fixture_oracle.write_expected(expected_path, data, force=False)

    loaded = json.loads(expected_path.read_text(encoding="utf-8"))
    assert loaded["schema_version"] == fixture_oracle.SCHEMA_VERSION
    assert loaded["fixture"] == "tiny"
    assert loaded["backend"] == "metadata"
    assert loaded["etl"]["size"] == len(b"not a real etl")
    assert fixture_oracle.validate_expected("tiny", expected_path) == []


def test_generate_and_validate_accept_explicit_fixture_root(tmp_path: Path) -> None:
    fixture_root = tmp_path / "custom-root"
    fixture_dir = fixture_root / "tiny"
    fixture_dir.mkdir(parents=True)
    etl_path = fixture_dir / "tiny.etl"
    etl_path.write_bytes(b"custom root etl")
    expected_path = fixture_dir / "expected.json"

    data = fixture_oracle.generate_expected(
        "tiny",
        "metadata",
        expected_path,
        fixture_root,
    )
    fixture_oracle.write_expected(expected_path, data, force=False)

    assert fixture_oracle.validate_expected("tiny", expected_path, fixture_root) == []
    assert json.loads(expected_path.read_text(encoding="utf-8"))["etl"]["path"] == str(etl_path)


def test_validate_expected_reports_identity_mismatch(tmp_path: Path, monkeypatch) -> None:
    fixture_root = tmp_path / "fixtures"
    fixture_dir = fixture_root / "tiny"
    fixture_dir.mkdir(parents=True)
    etl_path = fixture_dir / "tiny.etl"
    etl_path.write_bytes(b"actual")
    expected_path = fixture_dir / "expected.json"
    monkeypatch.setattr(fixture_oracle, "FIXTURE_ROOT", fixture_root)
    expected_path.write_text(
        json.dumps({
            "schema_version": fixture_oracle.SCHEMA_VERSION,
            "fixture": "tiny",
            "backend": "metadata",
            "etl": {"size": 999, "sha256": "bad"},
        }),
        encoding="utf-8",
    )

    errors = fixture_oracle.validate_expected("tiny", expected_path)

    assert any("size mismatch" in error for error in errors)
    assert any("sha256 mismatch" in error for error in errors)


def test_validate_expected_requires_identity_fields(tmp_path: Path, monkeypatch) -> None:
    fixture_root = tmp_path / "fixtures"
    fixture_dir = fixture_root / "tiny"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "tiny.etl").write_bytes(b"actual")
    expected_path = fixture_dir / "expected.json"
    monkeypatch.setattr(fixture_oracle, "FIXTURE_ROOT", fixture_root)
    expected_path.write_text(
        json.dumps({
            "schema_version": fixture_oracle.SCHEMA_VERSION,
            "fixture": "tiny",
            "backend": "metadata",
            "etl": {},
        }),
        encoding="utf-8",
    )

    errors = fixture_oracle.validate_expected("tiny", expected_path)

    assert "etl.size is required" in errors
    assert "etl.sha256 is required" in errors
