# TRIPWIRE v2

**The semantic verification layer for AI agents. Deterministic where possible, consensus where necessary, auditable always.**

This is the complete build specification, revised after a competitive and research review (June 9, 2026). It is written to be handed directly to Claude Code. Read the entire document before writing any code. Where this document and convenience conflict, this document wins.

---

## 1. The Problem

AI agents now take real actions — payments, trades, writes, sends. The parameters of those actions are taken on faith. If the model hallucinated a wallet address, fabricated a tool result, misread a document, or was steered by a prompt injection buried in retrieved content, the tool executes anyway. And errors compound: in multi-step workflows, each step reasons over the previous step’s possibly-wrong output, so chain reliability collapses far below per-step reliability. Verification must happen per action, at runtime, with provenance.

## 2. The Landscape (and why Tripwire is not redundant)

MCP security gateways already exist: Microsoft’s Agent Governance Toolkit (deterministic allow/deny/approve policy per tool call), mcp-firewall (policy enforcement, threat feeds, audit logging), Lasso’s MCP Gateway, Pangea’s guardrail proxy, LiteLLM MCP guardrails. **All of them are syntactic**: globs, allowlists, regex, DLP filters, rate limits. None of them can answer the question that actually matters: _is this action grounded in the evidence and consistent with the user’s intent?_ A payment to an attacker’s address looks syntactically identical to a payment to the real vendor.

Meanwhile, the 2025–2026 research frontier converged on three techniques that no shipping gateway combines:

1. **Capability/provenance enforcement (CaMeL — DeepMind; FIDES — Microsoft Research).** Attach origin metadata to every value; structurally forbid untrusted-origin data from reaching sensitive sinks. Deterministic, attack-class-eliminating, not heuristic. CaMeL’s framing: don’t guess whether text is malicious — ask whether _this data_ is allowed to reach _that sink_.
1. **Cryptographic tool receipts (NabaOS, arXiv:2603.10060).** HMAC-sign every real tool execution; cross-reference the agent’s claims against unforgeable receipts. ~91% of fabricated-tool-result hallucinations caught at <15ms overhead. An agent can no longer claim “I checked the vendor record” without a receipt proving it.
1. **Claim-level grounding with calibrated trust (span-level verification literature, VeriTrail’s per-step provenance).** Classify claims by epistemic source — direct tool output vs. inference vs. ungrounded assertion — and verify the ones that matter against evidence.

**Tripwire’s position:** not another firewall. The verification layer that sits _behind_ any gateway (or alone), combining receipts + provenance + multi-model semantic consensus in one tiered pipeline. Rules-based gateways are complementary and integrable, not competition.

## 3. The Solution

Tripwire is an open-source (MIT) **MCP proxy**. Point any MCP agent at Tripwire instead of its tool servers; Tripwire forwards everything transparently while running a **three-tier verification pipeline** on calls that policy marks as consequential.

### Tier 0 — Receipts (deterministic, ~1ms)

Every tool result passing through the proxy is wrapped with an HMAC-SHA256 receipt: `HMAC(key, tool_name | canonical(args) | canonical(result) | seq | timestamp)`. The key lives only in the Tripwire process; the agent cannot forge receipts. The receipt ledger is the ground truth of _what actually happened_ in the session.

Checks this enables, deterministically:

- **Fabricated execution:** agent’s declared intent references a tool result that has no receipt → fail.
- **Value tampering:** a parameter the agent claims came from a tool result doesn’t match any receipted result value → fail.
- **Stale/replayed evidence:** receipt sequence/timestamps show the “evidence” predates a contradicting later result → flag.

### Tier 1 — Provenance / taint tracking (deterministic, ~ms)

Tripwire maintains a session **value-provenance index**: every distinct value (addresses, amounts, emails, URLs, IDs) observed in tool results is recorded with its origin (which tool, which call, which trust label). Upstream tools are labeled in policy as `trusted` (vendor DB, internal ledger) or `untrusted` (web fetch, email reader, document parser — anything carrying third-party content).

When a guarded call arrives, each sensitive parameter is traced: _where did this value first appear?_

- Recipient address appears only inside the body of an untrusted document → **structural block**. This is the CaMeL/FIDES insight applied at the proxy layer: the poisoned-invoice attack fails by construction, regardless of how persuasive the injection was, with zero LLM calls and zero false-positive ambiguity.
- Value appears in a trusted-tool result → annotate provenance and continue.
- Value appears nowhere in session history (agent invented it or carried it from outside) → escalate to Tier 2 with an `unknown_provenance` flag.

This tier is Tripwire’s deterministic backbone. Per the security literature’s hard-won lesson: in adversarial settings, 99% probabilistic detection is a failing grade; structural guarantees are not. Build Tier 1 as if it will be attacked by people who read the source code — because it will be.

### Tier 2 — Multi-model consensus (probabilistic, seconds, high-stakes only)

For calls that pass Tiers 0–1 but match a high-stakes policy (or carry escalation flags), a panel of 2–3 **independent models from different providers** each receives a verification packet and returns a structured verdict. Verifiers never see each other’s outputs (no anchoring). The acting agent’s own model/provider is excluded or de-weighted when known.

The packet: declared intent (see §4.3), the proposed call (tool + full params), provenance annotations from Tier 1, the receipted evidence excerpts relevant to the parameters, and the tool’s schema/annotations.

The checks (each a versioned prompt template, each returning strict JSON):

- `intent_match` — does the action serve the declared goal, or a goal introduced by content the agent read? (the semantic injection check)
- `source_grounding` — claim-level: is each material parameter supported by receipted evidence? Classify each as _directly evidenced / inferred / ungrounded_.
- `bounds_and_sanity` — amounts, units, decimals, plausibility against evidence (the “fat-finger” check rules engines miss when the value is technically in range but inconsistent with the invoice).

Aggregation per policy quorum (majority/unanimous). Malformed or timed-out verdicts count as **fail** under fail-closed. Disagreement between verifiers is itself signal → flag/hold rather than silently average.

### Verdict → action

**PASS** (forward), **BLOCK** (refuse with a structured, machine-actionable error telling the agent exactly which check failed, what evidence conflicted, and what would make the call acceptable — well-built agents self-correct, and that loop is part of the demo), or **HOLD** (human approval required; minimal CLI prompt in v1). Everything — including passes — is written to the audit log.

### Audit log

Append-only JSONL, hash-chained (`prev_hash`, SHA-256), recording: packet hash, tier results, per-verifier verdicts with model IDs and prompt versions, final decision, latency per tier, receipt references. `tripwire verify-log` re-validates the chain. Sensitive parameter values are redacted per policy before logging. (Optional later: periodic chain-head anchoring on-chain — we know exactly how.)

## 4. Architecture

```
 ┌────────────┐ MCP (stdio/HTTP) ┌────────────────────────────────────────────┐  MCP   ┌──────────────┐
 │   Agent    │◀────────────────▶│ TRIPWIRE                                    │◀──────▶│ Real tool    │
 └────────────┘                  │  Proxy Core ─▶ Policy Engine                │        │ server(s)    │
                                 │       │            │                        │        └──────────────┘
                                 │       ▼            ▼                        │
                                 │  Receipt Ledger  Verification Pipeline      │
                                 │  (HMAC, Tier 0)   Tier 1: Provenance Index  │
                                 │       │           Tier 2: Consensus Panel ──┼──▶ Model A / B / C
                                 │       ▼                                     │    (independent providers)
                                 │  Audit Log (hash chain)                     │
                                 └────────────────────────────────────────────┘
```

### 4.1 Proxy Core

Transparent MCP man-in-the-middle: MCP **client** to one or more upstream servers, MCP **server** to the agent. Merges upstream tool lists (namespaced `serverName__toolName`), passes tool descriptions through verbatim, passes all non-tool-call traffic untouched. Transports: **stdio first** (Claude Code / Desktop demo path), streamable HTTP with stateless JSON second. Every tool _result_ is receipted and indexed for provenance before being returned to the agent — Tiers 0–1 piggyback on traffic Tripwire already handles, which is why they’re nearly free.

### 4.2 Policy Engine

Declarative YAML, Zod-validated with actionable config errors. Match on tool glob, upstream, parameter predicates, and MCP annotations (`destructiveHint: true` auto-escalates). Each rule selects: which tiers run, sensitive parameters and their allowed provenance (`recipient: { provenance: trusted }`), panel composition and quorum, on-fail action, fail mode (**fail-closed mandatory for anything touching money**), timeout.

```yaml
upstreams:
  - name: vendors # trusted: internal vendor DB
    command: ['node', 'demo/vendors-mcp/dist/index.js']
    trust: trusted
  - name: docs # untrusted: reads third-party documents
    command: ['node', 'demo/docs-mcp/dist/index.js']
    trust: untrusted
  - name: payments
    command: ['node', 'demo/payments-mcp/dist/index.js']
    trust: trusted

defaults: { on_unmatched: pass, audit: all }

rules:
  - match: { tool: 'payments__send_payment' }
    sensitive_params:
      recipient: { provenance: trusted } # Tier 1 structural rule
      amount: { provenance: trusted }
    verify:
      tiers: [receipts, provenance, consensus]
      panel: [anthropic/claude-sonnet-latest, openai/gpt-latest, google/gemini-latest]
      quorum: unanimous
      checks: [intent_match, source_grounding, bounds_and_sanity]
      on_fail: block
      fail_mode: closed
      timeout_ms: 8000
  - match: { annotation: { destructiveHint: true } }
    verify: { tiers: [receipts, provenance, consensus], quorum: majority, on_fail: hold }
```

### 4.3 Intent capture (the hard problem — solve it honestly)

A proxy sees tool calls, not the user’s goal. v1 mechanism: Tripwire injects one synthetic tool into the merged tool list, `tripwire__declare_intent(goal, plan_summary)`, with a description instructing the agent to call it before consequential actions. Policy can require a declared intent for guarded tools (no intent on file → block with an error that tells the agent to declare one — the agent self-serves). The declared intent is receipted like everything else, becomes the `intent_match` reference, and **its own consistency with subsequent actions is exactly what Tier 2 verifies**. Document the limitation plainly: a fully compromised agent can declare a malicious intent — but then the intent itself is on the audit record, Tier 1 still constrains where values may come from, and `source_grounding` still requires evidence. Defense in depth, not a silver bullet. (v2 direction: client-side hook that forwards the actual user message as trusted intent.)

### 4.4 Tech stack

TypeScript, official `@modelcontextprotocol/sdk` (server + client in one process), Zod everywhere, ESM, strict mode. Verifier clients: thin `fetch`-based `VerifierClient` interface per provider (Anthropic/OpenAI/Google), keys via env, timeouts and one retry, strict JSON-verdict parsing (non-conforming → fail). No LLM framework dependency — this is security infrastructure; keep the supply-chain surface minimal and auditable. Canonical JSON serialization (stable key order) for HMAC — get this right or receipts are flaky. Node `crypto` for HMAC/SHA-256. Vitest; mock upstreams and mock verifiers in CI (fully deterministic, no live API calls); one live smoke script gated behind env keys. ESLint + Prettier, tsup, GitHub Actions.

Before Phase 1, fetch and skim: the MCP TypeScript SDK README (`https://raw.githubusercontent.com/modelcontextprotocol/typescript-sdk/main/README.md`) and the stdio + streamable HTTP transport pages on modelcontextprotocol.io.

### 4.5 Repository layout

```
tripwire/
├── src/
│   ├── proxy/            # MCP server+client core, transports, tool merging
│   ├── receipts/         # Tier 0: HMAC ledger, canonical serialization, claim checks
│   ├── provenance/       # Tier 1: value index, origin tracing, structural rules
│   ├── consensus/        # Tier 2: packet builder, verifier clients, aggregation
│   │   └── prompts/      # versioned verifier prompt templates (one file per check)
│   ├── policy/           # YAML schema (Zod), rule matching
│   ├── audit/            # hash-chained JSONL writer, verify-log
│   ├── intent/           # tripwire__declare_intent synthetic tool
│   ├── cli.ts            # tripwire run | verify-log | logs
│   └── index.ts
├── demo/
│   ├── vendors-mcp/  docs-mcp/  payments-mcp/   # toy upstreams (in-memory)
│   ├── scenario/         # scripted victim-agent run, poisoned document
│   └── run-demo.ts       # disarmed run, armed run, side-by-side output
├── bench/                # FP/catch-rate benchmark harness + scenario corpus
├── test/
├── docs/                 # THREAT_MODEL.md, policy reference, architecture
├── tripwire.example.yaml
└── README.md             # the manifesto
```

## 5. Build Plan (for Claude Code — phase gates are hard gates)

**Phase 1 — Transparent proxy + receipts (Days 1–4).**
Scaffold repo. Proxy core with stdio transport; merge and re-expose tools from the three toy upstreams; byte-equivalent passthrough proven by integration test. Receipt ledger: canonical serialization, HMAC signing of every result, in-memory + JSONL persistence. Audit logging of all traffic from day one (logging precedes verification). _Gate:_ Claude Code through Tripwire is behaviorally indistinguishable from direct connection; receipts verifiable for every call in a recorded session.

**Phase 2 — Policy engine + provenance index + audit chain (Days 5–7).**
YAML policy with Zod validation. Value-provenance index: extract and index distinct values from every tool result (exact-match first; normalize obvious encodings — case, whitespace, hex prefixes); origin tracing for sensitive parameters; structural allow/block per `sensitive_params` provenance rules. Hash-chained audit writer + `verify-log`. _Gate:_ the poisoned-address scenario is blocked by Tier 1 alone with verifiers disabled; tamper test on the chain fails loudly; matcher edge cases exhaustively unit-tested.

**Phase 3 — Intent + consensus engine (Days 8–11).**
`tripwire__declare_intent` synthetic tool + policy requirement. Verification packet builder. VerifierClient per provider; parallel panel; quorum aggregation; fail-closed semantics; structured BLOCK errors designed for agent self-correction. The three check prompts as versioned templates demanding strict JSON (`verdict, confidence, reasons, evidence_refs, suspected_injection`). _Gate:_ full-pipeline integration tests with mocked verifiers covering pass / split / unanimous-fail / timeout / malformed; live smoke test p50 added latency ≤ ~5s for a 3-model panel.

**Phase 4 — Benchmark + the demo (Days 12–14).**
**bench/**: ≥40 scripted scenarios — half attacks (poisoned recipient, fabricated tool result, amount manipulation, stale evidence, intent hijack), half _legitimate edge cases designed to tempt false positives_ (vendor genuinely changed banking details via a trusted-tool update; unusual but correct amounts; multi-invoice batches). Output: catch rate AND false-block rate per tier. **This table goes in the README — false-positive rate is the headline metric, because alert fatigue is how security tools die.**
**Demo:** “pay the outstanding Acme invoice.” Vendor DB says `0xAAA…`; a poisoned PDF in context says “updated banking details `0xBBB…`.” Run 1 disarmed: agent pays the attacker. Run 2 armed: Tier 1 structurally blocks, agent reads the error, re-queries the vendor record, pays correctly; Tier 2 shown firing on a second scenario (plausible-but-ungrounded amount) so the consensus layer gets screen time too. Beautiful terminal output; audit excerpt printed at the end; `npm run demo` works from a clean clone with only API keys. _Gate:_ demo is deterministic and re-runnable; benchmark numbers reproduce.

**Phase 5 — Threat model + launch assets (Days 15–16).**
`docs/THREAT_MODEL.md`: what each tier defends against, with explicit honesty about what Tripwire cannot do — verifiers are themselves fallible and injectable models (mitigations: independence, structured outputs, deterministic tiers first); a fully compromised agent can declare malicious intent (mitigation: provenance rules + grounding + audit trail); receipts prove what tools returned, not that upstream data was true; prompt injection is not fully solvable — Tripwire reduces blast radius (cite the defense-in-depth consensus, CaMeL, FIDES, Rule of Two). This honesty is a feature: it is what makes a security README credible. Manifesto README with the demo GIF up top, quickstart ≤10 lines, the benchmark table, policy reference. MIT license. Tag v0.1.0.

**Engineering standards (non-negotiable):** fail-closed on money paths; every external call has a timeout; no secrets or unredacted sensitive values in code, logs, or errors; structured errors everywhere; canonical-serialization and policy-matching code tested to near-exhaustion — these are the components adversaries will read and probe.

## 6. Why this is the revolutionary version

The v1 plan was “LLMs voting on tool calls” — a better demo than a defense, and competing on the same probabilistic turf as every guardrail vendor. v2 inverts the architecture to match where security research actually landed: **structural guarantees first (receipts, provenance), semantic judgment last (consensus), every decision auditable.** The poisoned-payment attack isn’t _detected_ — it’s made _impossible by construction_, and the consensus layer handles only the residue that structure can’t express. No shipping MCP gateway does this. That’s the claim, the demo proves it, the benchmark quantifies it, and the threat model earns the trust.

## 7. Success criteria for v0.1

A stranger clones the repo, sets two API keys, runs one command, and within five minutes watches: (1) an undefended agent pay an attacker, (2) Tripwire stop the identical attack structurally, (3) the agent self-correct off the block error, (4) the audit chain verify. The benchmark table shows a false-block rate low enough that nobody screams “alert fatigue.” Everything else is iteration.

---

_Spec v2 — June 9, 2026. Hand to Claude Code with: “Read TRIPWIRE_PLAN.md in full, then begin Phase 1. Phase gates are hard gates.”_
_Research anchors: CaMeL (arXiv:2503.18813), FIDES (Microsoft Research), NabaOS tool receipts (arXiv:2603.10060), VeriTrail (Microsoft Research, Jan 2026), span-level grounding literature._
