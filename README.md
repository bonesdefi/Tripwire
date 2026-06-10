# Tripwire

**The semantic verification layer for AI agents. Deterministic where possible, consensus where necessary, auditable always.**

AI agents now take real actions — payments, trades, writes, sends — and the parameters of those actions are taken on faith. Existing MCP security gateways are syntactic (globs, allowlists, regex); none can answer the question that matters: *is this action grounded in the evidence and consistent with the user's intent?*

Tripwire is an MIT-licensed **MCP proxy**. Point any MCP agent at Tripwire instead of its tool servers; Tripwire forwards everything transparently while running a three-tier verification pipeline on calls that policy marks as consequential:

- **Tier 0 — Receipts (deterministic, ~1ms).** Every tool result is signed with HMAC-SHA256 into an unforgeable ledger of what actually happened. Fabricated tool results and tampered values fail against the receipts.
- **Tier 1 — Provenance (deterministic, ~ms).** Every value observed in tool results is indexed with its origin and trust label. A payment address that only ever appeared inside an untrusted document is blocked *by construction* — no model call, no heuristic.
- **Tier 2 — Multi-model consensus (probabilistic, high-stakes only).** Independent models from different providers check intent match, source grounding, and bounds/sanity, with strict-JSON verdicts, quorum aggregation, and fail-closed semantics.

Every decision — including passes — lands in a hash-chained, append-only audit log that `tripwire verify-log` re-validates.

The full design and build plan is in [TRIPWIRE_PLAN.md](TRIPWIRE_PLAN.md).

## Status

Phase 1 of 5 is complete: **transparent proxy + Tier 0 receipts.**

- [x] **Phase 1 — Transparent proxy + receipts.** stdio MCP proxy; tools from multiple upstreams merged and re-exposed as `<upstream>__<tool>` with definitions passed through verbatim; byte-equivalent passthrough proven by integration test; HMAC-SHA256 receipt ledger over canonical JSON (in-memory + JSONL); hash-chained audit log of all traffic; `tripwire verify-log`.
- [ ] Phase 2 — Policy engine + provenance index (Tier 1 structural blocks)
- [ ] Phase 3 — Intent capture + multi-model consensus (Tier 2)
- [ ] Phase 4 — Benchmark (catch rate / false-block rate) + the poisoned-invoice demo
- [ ] Phase 5 — Threat model + launch

## Try it

```sh
npm install
npx tsx src/cli.ts run --config tripwire.example.yaml
```

That starts Tripwire on stdio, proxying three toy upstreams (a trusted vendor DB, an untrusted document reader, a payments rail). Point any MCP client at that command — e.g. for Claude Code:

```json
{
  "mcpServers": {
    "tripwire": {
      "command": "npx",
      "args": ["tsx", "src/cli.ts", "run", "--config", "tripwire.example.yaml"]
    }
  }
}
```

Every session records to `.tripwire/sessions/<session-id>/`:

| File             | Contents                                                              |
| ---------------- | --------------------------------------------------------------------- |
| `receipts.jsonl` | HMAC-signed receipt for every tool execution (created mode 0600)       |
| `audit.jsonl`    | hash-chained audit log — hashes and receipt refs, no raw values        |
| `hmac.key`       | session receipt key (omitted when `TRIPWIRE_HMAC_KEY` is set)          |

Verify a recorded session after the fact:

```sh
npx tsx src/cli.ts verify-log .tripwire/sessions/<session-id>
# audit chain    OK   (14 entries)
# receipts       OK   (7 receipts)
```

Tamper with a single byte of either file and verification fails loudly, naming the line.

## Development

```sh
npm test            # deterministic; spawns real MCP servers over stdio, no API keys needed
npm run typecheck
npm run lint
npm run build
```

## License

MIT
