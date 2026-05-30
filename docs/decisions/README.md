# Decision Records

Reviewed decision documents that materially shape the architecture of the
sidecar + evidence federation tree. Promoted out of `manager-log/` or the
worktree root so they have a stable home next to the running code.

These docs are the **why** behind the implementation. They are not living
runbooks — once a decision lands they freeze, and the rationale is preserved
unedited for future contributors and post-mortems.

| Document | What it decides | Why it lives here |
|---|---|---|
| [`rust-vs-csharp-spike-review.md`](rust-vs-csharp-spike-review.md) | Side-by-side review of the Rust and C# extraction-backend spikes; selects C# as the production sidecar language. | Implementation lives in [`../../csharp/`](../../csharp/); the review explains the tradeoffs (TraceProcessing parity, MSAL ergonomics, self-contained publish footprint) that made C# the better fit. |
| [`native-vs-xperf-parity-review.md`](native-vs-xperf-parity-review.md) | Coverage gaps between the in-process native consumer and the legacy xperf pipeline; selects which gaps block production. | Drives the `mode="xperf"` fallback policy in [`../../src/etw_analyzer/tools/trace_mgmt.py`](../../src/etw_analyzer/tools/trace_mgmt.py) and the per-tool "use mode='xperf' for full coverage" notes in `README.md`. |
| [`evidence-language-review.md`](evidence-language-review.md) | Language and storage choice for the evidence federation layer; selects DuckDB + Python + UUIDv5 identity. | Sets the byte-deterministic contract documented in `wpr-mcp-evidence-store/docs/IDENTITY-SPEC.md` and `PRODUCER-CONTRACT.md`, which both this server's producer hook and the `wpr-mcp-evidence-query` reader rely on. |

## Adding new decisions

* Land the decision doc in `manager-log/` while it is still under review.
* When the architecture lands in code, copy the final version into this
  directory in the same commit (or the immediate follow-up) that ships the
  change. The redirect note at
  [`../../../wpr-mcp-poc-staging/manager-log/promoted-docs.md`](../../../wpr-mcp-poc-staging/manager-log/promoted-docs.md)
  tracks what has been promoted vs. what is still active.
* Update [`../../ARCHITECTURE.md`](../../ARCHITECTURE.md) §9 to link the new
  decision into the architecture overview.
