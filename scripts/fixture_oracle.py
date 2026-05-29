from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from etw_analyzer.parsing.wpa_exporter import (
    _parse_profile_detail,
    _parse_profile_utilization,
    find_xperf,
)


SCHEMA_VERSION = 1
FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures"
PKTMON_TIMEOUT_SECONDS = 120
XPERF_TIMEOUT_SECONDS = 120

_PKTMON_HEADER_RE = re.compile(
    r"^(?P<ts>\d\d:\d\d:\d\d\.\d+) "
    r"(?P<drop>Drop: )?PktGroupId (?P<group>\d+), "
    r"PktNumber (?P<number>\d+), "
    r"Appearance (?P<appearance>\d+), "
    r"Direction\s+(?P<direction>Tx|Rx)\s*, "
    r"Type\s+(?P<type>\w+)\s*, "
    r"Component\s+(?P<component>\d+)"
    r"(?:,\s*Edge\s+(?P<edge>\d+))?.*?"
    r"OriginalSize\s+(?P<size>\d+),\s*LoggedSize\s+(?P<logged>\d+)",
)
_PKTMON_FLOW_RE = re.compile(
    r"(?P<family>IPv4|IPv6), length (?P<iplen>\d+): "
    r"(?P<src>.+)\.(?P<srcport>\d+) > "
    r"(?P<dst>.+)\.(?P<dstport>\d+): "
    r"(?P<proto>tcp|udp)\b",
    re.IGNORECASE,
)


def default_etl_path(fixture: str, fixture_root: Path | None = None) -> Path:
    root = fixture_root or FIXTURE_ROOT
    return root / fixture / f"{fixture}.etl"


def default_expected_path(fixture: str, fixture_root: Path | None = None) -> Path:
    root = fixture_root or FIXTURE_ROOT
    return root / fixture / "expected.json"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def etl_metadata(etl_path: Path) -> dict[str, Any]:
    stat = etl_path.stat()
    return {
        "path": str(etl_path),
        "sha256": file_sha256(etl_path),
        "size": int(stat.st_size),
        "mtime_ns": int(stat.st_mtime_ns),
    }


def base_expected(fixture: str, backend: str, etl_path: Path) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "fixture": fixture,
        "backend": backend,
        "etl": etl_metadata(etl_path),
        "datasets": {},
    }


def _stable_top_counts(df: pd.DataFrame, column: str, weight_column: str, limit: int = 20) -> list[dict[str, Any]]:
    if df.empty or column not in df.columns or weight_column not in df.columns:
        return []
    grouped = (
        df.assign(_weight=pd.to_numeric(df[weight_column], errors="coerce").fillna(0))
        .groupby(column, dropna=False)["_weight"]
        .sum()
        .reset_index()
        .rename(columns={column: "name", "_weight": "weight"})
    )
    grouped["name"] = grouped["name"].astype(str)
    grouped = grouped.sort_values(["weight", "name"], ascending=[False, True]).head(limit)
    return [
        {"name": str(row["name"]), "weight": int(row["weight"])}
        for row in grouped.to_dict("records")
    ]


def summarize_profile_detail(text: str) -> dict[str, Any]:
    df = _parse_profile_detail(text)
    if df.empty:
        return {"rows": 0, "total_weight": 0, "modules": [], "processes": []}
    weight = pd.to_numeric(df.get("Weight"), errors="coerce").fillna(0)
    return {
        "rows": int(len(df)),
        "total_weight": int(weight.sum()),
        "modules": _stable_top_counts(df, "Module", "Weight"),
        "processes": _stable_top_counts(df, "Process Name", "Weight"),
    }


def summarize_profile_util(text: str) -> dict[str, Any]:
    df = _parse_profile_utilization(text)
    if df.empty:
        return {"rows": 0, "cpu_columns": [], "max_cpu_pct": 0.0}
    cpu_columns = [col for col in df.columns if str(col).strip().lower().startswith("cpu")]
    max_cpu = 0.0
    if cpu_columns:
        numeric = df[cpu_columns].apply(pd.to_numeric, errors="coerce").fillna(0)
        max_cpu = float(numeric.max().max())
    return {
        "rows": int(len(df)),
        "cpu_columns": sorted(str(col) for col in cpu_columns),
        "max_cpu_pct": round(max_cpu, 3),
    }


def summarize_tracestats(text: str) -> dict[str, Any]:
    nonempty = [line.strip() for line in text.splitlines() if line.strip()]
    key_values: dict[str, str] = {}
    for line in nonempty:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = " ".join(key.strip().split())
        value = " ".join(value.strip().split())
        if key and value and len(key_values) < 50:
            key_values[key] = value
    return {
        "line_count": len(text.splitlines()),
        "nonempty_line_count": len(nonempty),
        "key_values": dict(sorted(key_values.items())),
    }


def _run_xperf_direct(etl_path: Path, action: str, action_args: list[str] | None = None) -> str:
    xperf = find_xperf()
    if xperf is None:
        raise RuntimeError(
            "xperf.exe not found. Install Windows Performance Toolkit "
            "(Windows SDK/ADK) or put xperf.exe on PATH."
        )
    cmd = [str(xperf), "-i", str(etl_path), "-tle", "-a", action]
    if action_args:
        cmd.extend(action_args)

    creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    result = subprocess.run(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=XPERF_TIMEOUT_SECONDS,
        creationflags=creation_flags,
        check=False,
    )
    if result.returncode != 0 and not result.stdout:
        detail = (result.stderr or "").strip()
        raise RuntimeError(f"xperf -a {action} failed (exit {result.returncode}): {detail}")
    return result.stdout


def generate_metadata_expected(fixture: str, etl_path: Path) -> dict[str, Any]:
    data = base_expected(fixture, "metadata", etl_path)
    data["datasets"] = {"raw_csv": [], "packet_capture": {"present": False}}
    return data


def generate_xperf_expected(fixture: str, etl_path: Path) -> dict[str, Any]:
    data = base_expected(fixture, "xperf", etl_path)
    tracestats = _run_xperf_direct(etl_path, "tracestats")
    profile_detail = _run_xperf_direct(etl_path, "profile", ["-detail"])
    profile_util = _run_xperf_direct(etl_path, "profile")
    data["xperf"] = {
        "tracestats": summarize_tracestats(tracestats),
        "profile_detail": summarize_profile_detail(profile_detail),
        "profile_util": summarize_profile_util(profile_util),
    }
    data["datasets"] = {
        "cpu_sampling": {"rows": data["xperf"]["profile_detail"]["rows"]},
        "cpu_timeline": {"rows": data["xperf"]["profile_util"]["rows"]},
    }
    return data


def _read_text_any_encoding(path: Path) -> str:
    raw = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-16", "utf-8"):
        try:
            return raw.decode(encoding)
        except UnicodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _is_pktmon_boundary_packet(direction: str, packet_type: str, component: int, edge: int) -> bool:
    return packet_type == "Ethernet" and (
        (direction == "Tx" and component == 12 and edge == 1)
        or (direction == "Rx" and component == 1 and edge == 1)
    )


def parse_pktmon_boundary_rows(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    pending: dict[str, str] | None = None

    for line in text.splitlines():
        header = _PKTMON_HEADER_RE.match(line)
        if header:
            direction = header.group("direction")
            packet_type = header.group("type")
            component = int(header.group("component"))
            edge = int(header.group("edge") or -1)
            pending = (
                header.groupdict()
                if not header.group("drop")
                and _is_pktmon_boundary_packet(direction, packet_type, component, edge)
                else None
            )
            continue

        if pending is None:
            continue
        if not line.startswith("\t"):
            pending = None
            continue

        flow = _PKTMON_FLOW_RE.search(line)
        packet = pending
        pending = None
        if flow is None:
            continue
        direction = "send" if packet["direction"] == "Tx" else "recv"
        proto = flow.group("proto").lower()
        rows.append({
            "direction": direction,
            "five_tuple": (
                f"{flow.group('src')}:{flow.group('srcport')} -> "
                f"{flow.group('dst')}:{flow.group('dstport')}/{proto}"
            ),
            "protocol": proto,
            "size": int(packet["size"]),
        })
    return rows


def summarize_pktmon_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    flows: dict[str, dict[str, Any]] = {}
    protocols: dict[str, int] = {}
    recv_packets = 0
    send_packets = 0
    total_bytes = 0
    for row in rows:
        five_tuple = str(row["five_tuple"])
        direction = str(row["direction"])
        protocol = str(row["protocol"])
        size = int(row["size"])
        protocols[protocol] = protocols.get(protocol, 0) + 1
        total_bytes += size
        if direction == "recv":
            recv_packets += 1
        elif direction == "send":
            send_packets += 1
        flow = flows.setdefault(
            five_tuple,
            {
                "five_tuple": five_tuple,
                "protocol": protocol,
                "recv_packets": 0,
                "send_packets": 0,
                "total_packets": 0,
                "total_bytes": 0,
            },
        )
        if direction == "recv":
            flow["recv_packets"] += 1
        elif direction == "send":
            flow["send_packets"] += 1
        flow["total_packets"] += 1
        flow["total_bytes"] += size

    five_tuples = sorted(
        flows.values(),
        key=lambda item: (-int(item["total_packets"]), str(item["five_tuple"])),
    )
    return {
        "total_packets": len(rows),
        "recv_packets": recv_packets,
        "send_packets": send_packets,
        "total_bytes": total_bytes,
        "protocols": dict(sorted(protocols.items())),
        "five_tuples": five_tuples,
    }


def _run_pktmon_etl2txt(etl_path: Path, text_path: Path) -> str:
    cmd = ["pktmon", "etl2txt", str(etl_path), "--out", str(text_path), "--brief", "--timestamp"]
    result = subprocess.run(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=PKTMON_TIMEOUT_SECONDS,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"pktmon etl2txt failed (exit {result.returncode}): {detail}")
    if not text_path.exists():
        raise RuntimeError("pktmon etl2txt did not produce an output file")
    return _read_text_any_encoding(text_path)


def generate_pktmon_expected(fixture: str, etl_path: Path, output_path: Path) -> dict[str, Any]:
    data = base_expected(fixture, "pktmon", etl_path)
    text_path = output_path.with_suffix(".pktmon.txt")
    try:
        text = _run_pktmon_etl2txt(etl_path, text_path)
    finally:
        try:
            text_path.unlink()
        except FileNotFoundError:
            pass
    rows = parse_pktmon_boundary_rows(text)
    data["packet_capture"] = summarize_pktmon_rows(rows)
    data["datasets"] = {"packet_capture": {"present": bool(rows), "rows": len(rows)}}
    return data


def generate_expected(
    fixture: str,
    backend: str,
    output_path: Path,
    fixture_root: Path | None = None,
) -> dict[str, Any]:
    etl_path = default_etl_path(fixture, fixture_root)
    if not etl_path.exists():
        raise RuntimeError(f"Fixture ETL not found: {etl_path}")
    if backend == "metadata":
        return generate_metadata_expected(fixture, etl_path)
    if backend == "xperf":
        return generate_xperf_expected(fixture, etl_path)
    if backend == "pktmon":
        return generate_pktmon_expected(fixture, etl_path, output_path)
    raise RuntimeError(f"Unknown backend: {backend}")


def write_expected(path: Path, data: dict[str, Any], *, force: bool) -> None:
    if path.exists() and not force:
        raise RuntimeError(f"Refusing to overwrite {path}; pass --force to replace it.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_expected(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise RuntimeError(f"Expected data must be a JSON object: {path}")
    return data


def validate_expected(
    fixture: str,
    expected_path: Path,
    fixture_root: Path | None = None,
) -> list[str]:
    errors: list[str] = []
    if not expected_path.exists():
        return [f"Expected JSON not found: {expected_path}"]
    try:
        data = load_expected(expected_path)
    except (OSError, json.JSONDecodeError, RuntimeError) as exc:
        return [str(exc)]

    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            f"schema_version must be {SCHEMA_VERSION}, got {data.get('schema_version')!r}"
        )
    if data.get("fixture") != fixture:
        errors.append(f"fixture must be {fixture!r}, got {data.get('fixture')!r}")

    etl_path = default_etl_path(fixture, fixture_root)
    if not etl_path.exists():
        errors.append(f"Fixture ETL not found: {etl_path}")
        return errors

    etl = data.get("etl")
    if not isinstance(etl, dict):
        errors.append("etl must be an object")
        return errors

    for required_key in ("size", "sha256"):
        if required_key not in etl:
            errors.append(f"etl.{required_key} is required")

    if "size" in etl and int(etl["size"]) != etl_path.stat().st_size:
        errors.append(f"size mismatch: expected {etl['size']}, actual {etl_path.stat().st_size}")
    if "sha256" in etl:
        actual_hash = file_sha256(etl_path)
        if etl["sha256"] != actual_hash:
            errors.append(f"sha256 mismatch: expected {etl['sha256']}, actual {actual_hash}")
    return errors


def _cmd_generate(args: argparse.Namespace) -> int:
    fixture_root = Path(args.fixture_root) if args.fixture_root else FIXTURE_ROOT
    output_path = Path(args.output) if args.output else default_expected_path(args.fixture, fixture_root)
    try:
        data = generate_expected(args.fixture, args.backend, output_path, fixture_root)
        write_expected(output_path, data, force=args.force)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote {output_path}")
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    fixture_root = Path(args.fixture_root) if args.fixture_root else FIXTURE_ROOT
    expected_path = Path(args.expected) if args.expected else default_expected_path(args.fixture, fixture_root)
    errors = validate_expected(args.fixture, expected_path, fixture_root)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"Validated {expected_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate and validate ETL fixture oracle JSON.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate", help="generate expected.json from an independent backend")
    generate.add_argument("--fixture", required=True, help="fixture name under tests\\fixtures")
    generate.add_argument("--backend", choices=("metadata", "xperf", "pktmon"), required=True)
    generate.add_argument("--fixture-root", help="root directory containing <fixture>\\<fixture>.etl")
    generate.add_argument("--output", help="output expected JSON path")
    generate.add_argument("--force", action="store_true", help="overwrite an existing expected JSON")
    generate.set_defaults(func=_cmd_generate)

    validate = subparsers.add_parser("validate", help="validate expected.json identity fields")
    validate.add_argument("--fixture", required=True, help="fixture name under tests\\fixtures")
    validate.add_argument("--fixture-root", help="root directory containing <fixture>\\<fixture>.etl")
    validate.add_argument("--expected", help="expected JSON path")
    validate.set_defaults(func=_cmd_validate)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
