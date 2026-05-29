# ETL fixture directory

Place optional golden-test ETLs under `tests/fixtures/<name>/<name>.etl`.

Current scaffolded fixture names:

- `empty-trace`
- `cpu-only-trace`
- `pktmon-capture-trace`

Binary ETLs are intentionally not included here. If an ETL is committed later,
store it with Git LFS and include a small `expected.json` or `manifest.json`
with stable expected ranges rather than exact large exports.

## Collecting local fixtures

Use the helper script from the repository root when you need local ETLs:

```powershell
.\scripts\collect_fixture_etl.ps1 -Fixture empty-trace,cpu-only-trace,pktmon-capture-trace
```

The script keeps traces short and writes them to
`tests\fixtures\<name>\<name>.etl`. It requires `xperf.exe` for the empty
fixture, `wpr.exe` for the CPU fixture (`CPU.light`), and `pktmon.exe` for the
packet-capture fixture.

## Generating oracle data

Expected oracle files are generated without calling the MCP server or native
`load_trace` path:

```powershell
uv run python .\scripts\fixture_oracle.py generate --fixture empty-trace --backend xperf --force
uv run python .\scripts\fixture_oracle.py generate --fixture cpu-only-trace --backend xperf --force
uv run python .\scripts\fixture_oracle.py generate --fixture pktmon-capture-trace --backend pktmon --force
uv run python .\scripts\fixture_oracle.py validate --fixture cpu-only-trace
```

The `xperf` backend invokes Windows Performance Toolkit `xperf.exe` directly
with `-tle` and summarizes trace statistics plus CPU profile outputs. The
`pktmon` backend invokes `pktmon etl2txt` directly and summarizes boundary
packets using Tx component/edge `12/1` and Rx component/edge `1/1`.

Run fixture tests explicitly:

```powershell
uv run --group dev pytest tests\test_fixture_golden.py --run-fixture --run-golden -q
```

To let pytest generate missing ETLs and oracle files into its cache instead of
`tests\fixtures`, add `--generate-fixture-etls`:

```powershell
uv run --group dev pytest tests\test_fixture_golden.py --run-fixture --run-golden --generate-fixture-etls -q
```

Use `--fixture-output-root C:\wpr-fixtures-cache` to keep generated ETLs in a
stable external directory, and `--force-generate-fixtures` to replace them.
The generation path still requires the same local tools (`xperf.exe`, `wpr.exe`,
and `pktmon.exe`) and may require elevation.

Native/xperf differential tests are intentionally separate. Enable them only
after a fixture has an explicit parity baseline:

```powershell
uv run --group dev pytest tests\test_fixture_golden.py --run-fixture --run-golden --run-xperf -q
```
