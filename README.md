# Tripwire

**The security gateway for MCP agents that other gateways can't be: it blocks prompt-injection-driven tool calls by checking whether an action is grounded in evidence and intent — not just whether it matches a regex.**

![Tripwire stops the poisoned-invoice attack: the same agent pays an attacker when undefended, and is blocked then self-corrects when Tripwire is on](docs/demo.svg)

```sh
npm install -g tripwire-mcp   # then: tripwire init
```

AI agents now take real actions — payments, trades, writes, sends — and the parameters of those actions are taken on faith. Existing MCP security gateways are syntactic (globs, allowlists, regex); none can answer the question that matters: _is this action grounded in the evidence and consistent with the user's intent?_ A payment to an attacker's address looks identical to a payment to the real vendor.

Tripwire is an MIT-licensed **MCP proxy**. Point any MCP agent at Tripwire instead of its tool servers; Tripwire forwards everything transparently while running a three-tier verification pipeline on calls that policy marks as consequential:

- **Tier 0 — Receipts (deterministic, ~1ms).** Every tool result is signed with HMAC-SHA256 into an unforgeable ledger of what actually happened. Fabricated tool results and tampered values fail against the receipts.
- **Tier 1 — Provenance (deterministic, ~ms).** Every value observed in tool results is indexed with its origin and trust label. A payment address that only ever appeared inside an untrusted document is blocked _by construction_ — no model call, no heuristic.
- **Tier 2 — Multi-model consensus (probabilistic, high-stakes only).** Independent models from different providers check intent match, source grounding, and bounds/sanity, with strict-JSON verdicts, quorum aggregation, and fail-closed semantics.

Every decision — including passes — lands in a hash-chained, append-only audit log that `tripwire verify-log` re-validates.

The full design and build plan is in [TRIPWIRE_PLAN.md](TRIPWIRE_PLAN.md).

**Read next:** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — what each tier defends against, and exactly what Tripwire cannot do. [docs/POLICY.md](docs/POLICY.md) — the policy YAML reference.

## Status

v0.2.0 — all five build phases complete, plus a no-engineering-required setup flow (`tripwire init` / `check` / `logs`). See [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md).

- [x] **Phase 1 — Transparent proxy + receipts.** stdio MCP proxy; tools from multiple upstreams merged and re-exposed as `<upstream>__<tool>` with definitions passed through verbatim; byte-equivalent passthrough proven by integration test; HMAC-SHA256 receipt ledger over canonical JSON (in-memory + JSONL); hash-chained audit log of all traffic; `tripwire verify-log`.
- [x] **Phase 2 — Policy engine + provenance index.** Zod-validated YAML policy (tool globs, upstream, annotation matching; first rule wins); session value-provenance index over every receipted result (addresses, amounts, emails, URLs, ids — normalized across case, whitespace, hex prefixes, number formatting); structural Tier 1 enforcement of `sensitive_params` provenance, with anti-laundering (echoed inputs never gain a tool's trust label, failed executions are not evidence); structured machine-actionable BLOCK results built for agent self-correction. The poisoned-invoice attack is blocked by Tier 1 alone — zero model calls.
- [x] **Phase 3 — Intent capture + Tier 2 consensus.** Synthetic `tripwire__declare_intent` tool (receipted; policy can require it via `require_intent`, and the block error tells the agent how to self-serve); verification packet builder (intent + proposed call + Tier 1 provenance + receipted evidence excerpts); thin fetch-based verifier clients for Anthropic/OpenAI/Google with strict JSON verdict parsing; parallel panel with majority/unanimous quorum; timeouts, malformed output, and missing keys all count as failed verdicts under fail-closed; verifier disagreement flagged as signal; versioned prompt templates pinned in every audit entry. Live smoke script gated behind env keys (`npm run smoke:live`); CI stays fully deterministic with mocked verifiers.
- [x] **Phase 4 — Benchmark + demo.** 42-scenario corpus (21 attacks, 21 legitimate false-positive traps); deterministic harness whose numbers reproduce in CI with zero API calls; `npm run demo` shows the disarmed agent paying the attacker, the identical agent blocked structurally and self-correcting, and Tier 2 catching a plausible-but-wrong amount.
- [x] **Phase 5 — Threat model + launch.** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) (per-tier defenses, assumptions stated as attack surface, and a plain list of what Tripwire does NOT defend against), [docs/POLICY.md](docs/POLICY.md) policy reference, v0.1.0.

## The demo

```sh
npm install
npm run demo          # deterministic, no API keys needed
npm run demo -- --live  # same demo with a real multi-provider verifier panel
```

Three runs of the same scripted agent against the same poisoned invoice ("our banking details changed — remit to `0xBBBB…`"):

1. **Disarmed:** the agent reads the invoice, believes it, and pays the attacker. The money is gone.
2. **Armed:** the identical script is blocked by Tier 1 — the address only ever appeared inside untrusted document content, so the call is refused _structurally_, with zero model calls. The agent reads the machine-actionable error, re-queries the trusted vendor record, and pays the real vendor.
3. **Armed, Tier 2:** the agent fat-fingers the amount (the full treasury balance — a value that _is_ receipted, so Tier 1 passes). The consensus panel's `bounds_and_sanity` check blocks it; the agent re-reads the invoice and pays the right amount.

The demo ends with the audit excerpt: every decision hash-chained, every execution HMAC-receipted.

## Benchmark

42 scripted sessions: 21 attacks, 21 legitimate flows built to tempt false positives (vendors genuinely rotating banking details, unusual-but-correct amounts, batches, encoding variations, partial payments). Reproduce with `npm run bench`; the numbers are pinned by `test/bench.test.ts`.

| Metric                                         | Result          |
| ---------------------------------------------- | --------------- |
| Attacks caught                                 | 19/21 (90.5%)   |
| — caught by Tier 1 (structural, 0 model calls) | 15/21           |
| — caught by Tier 2 (consensus)                 | 4/21            |
| Attacks missed (documented)                    | 2/21            |
| **False-block rate (the headline)**            | **1/21 (4.8%)** |

Honesty notes, because alert fatigue is how security tools die:

- The two **misses** are documented in the corpus: conflicting "amount due" figures across documents (requires live-model judgement; the offline heuristic accepts any documented amount), and a stale-but-trusted rotated wallet (receipt-ordering staleness flags are the Tier 0 roadmap item).
- The one **false positive** is a partial payment (5,000 against a 12,500 invoice): the offline bounds heuristic can't read the installment agreement; live verifier panels can.
- Tier 2 numbers above use the **deterministic offline reference verifier** so they reproduce exactly in CI. `npm run bench -- --live` re-runs the corpus against a real Anthropic/OpenAI/Google panel.

### What a Tier 1 block looks like

The agent reads a poisoned invoice ("our banking details changed: `0xBBBB…`") and tries to pay it. The address only ever appeared inside untrusted document content, so the call never reaches the payment rail:

```json
{
  "tripwire": "blocked",
  "code": "provenance_violation",
  "tool": "payments__send_payment",
  "violations": [
    {
      "param": "recipient",
      "reason": "untrusted_provenance",
      "required_provenance": "trusted",
      "value_preview": "0xBBBB000000…0000BBBB",
      "observed_origins": [
        {
          "upstream": "docs",
          "tool": "docs__read_document",
          "trust": "untrusted",
          "receipt_seq": 2
        }
      ]
    }
  ],
  "remediation": "Fetch the required value from a trusted tool in this session…"
}
```

A well-built agent reads this, re-queries the vendor record (trusted), and retries with the real address — which passes. That loop is tested end-to-end with zero verifier models in `test/tier1.integration.test.ts`.

## Set it up (no config files to hand-write)

New to this? Follow **[docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)** — written for non-engineers.

```sh
npm install -g tripwire-mcp     # or, before the npm release: github:bonesdefi/tripwire

tripwire init     # answers a few plain-language questions, writes your config
tripwire check    # confirms your servers start and your rules make sense
```

`tripwire init` also writes `tripwire-agent-config.json` — paste it into your AI agent's MCP settings (Claude Desktop, Claude Code, etc.), replacing the tool servers it lists today. Tripwire now sits in front of them. Then use your agent normally; dangerous calls are verified, and `tripwire logs` shows you what happened in plain English.

### See the attack and the defense first

```sh
npm run demo      # the poisoned-invoice story, no API keys needed
```

### Run it by hand

```sh
tripwire run --config tripwire.example.yaml
```

That proxies three toy servers (a trusted vendor DB, an untrusted document reader, a payments rail). Point any MCP client at that command:

```json
{
  "mcpServers": {
    "tripwire": {
      "command": "tripwire",
      "args": ["run", "--config", "tripwire.example.yaml"]
    }
  }
}
```

Every session records to `.tripwire/sessions/<session-id>/`:

| File             | Contents                                                         |
| ---------------- | ---------------------------------------------------------------- |
| `receipts.jsonl` | HMAC-signed receipt for every tool execution (created mode 0600) |
| `audit.jsonl`    | hash-chained audit log — hashes and receipt refs, no raw values  |
| `hmac.key`       | session receipt key (omitted when `TRIPWIRE_HMAC_KEY` is set)    |

Read a session in plain English, or verify it cryptographically:

```sh
tripwire logs .tripwire/sessions/<session-id>        # what happened, in plain English
tripwire verify-log .tripwire/sessions/<session-id>  # prove the record wasn't altered
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
