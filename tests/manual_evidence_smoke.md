# Manual smoke test — evidence-store federation hook (etw side)

End-to-end smoke test for the optional `evidence-store` integration in
`etw-trace-analyzer`. Demonstrates both G3 gates: the library install
AND the env var.

## Prereqs
- Real ETL file on disk (any trace works; networking.wprp output is fine).
- Co-located `wpr-mcp-evidence-store` repo at `..\wpr-mcp-evidence-store`.

## Steps

```powershell
# 1. Sync with the evidence extra (this is what production users
#    explicitly opt into; default `uv sync` does NOT install it).
cd C:\git\wpr-mcp-server-evidence-wiring
uv sync --extra evidence --group dev

# 2. Point the federation at a per-machine evidence root.
$env:WPR_MCP_EVIDENCE_PATH = "C:\Temp\evidence-poc"

# 3. Run the MCP server.
uv run python -m etw_analyzer.server
```

Then from your MCP client:

```text
> load_trace("C:\\traces\\sample.etl", mode="auto")
trace_<id> loaded.

> get_evidence_status()
**Evidence federation status**
- Library installed: **True**
- `WPR_MCP_EVIDENCE_PATH` set: **True**
- Evidence root: `C:\Temp\evidence-poc`

> get_entities(trace_id="trace_<id>", entity_type="module")
**Module entities** for machine `machine_<...>` (db: `...`)
| entity_id | name | version | path |
| --- | --- | --- | --- |
| module_... | ntoskrnl.exe | tds=...;size=... | \Windows\System32\ntoskrnl.exe |
| module_... | tcpip.sys    | tds=...;size=... | C:\Windows\System32\drivers\tcpip.sys |

> get_entities(trace_id="trace_<id>", entity_type="machine")
> get_entities(trace_id="trace_<id>", entity_type="process", filter="echo")
```

## Negative — the G3 guarantee

Confirm a plain install (no extra, no env var) does NOT regress the
server or pull `evidence-store`:

```powershell
# In a clean checkout:
uv sync                       # no --extra evidence
uv run python -m etw_analyzer.server
# Tools list still works; get_evidence_status reports library missing.
# load_trace runs to completion with zero evidence-related work.
```
