# Tripwire Threat Model

Tripwire is a verification layer, not a force field. This document states
precisely what each tier defends against, the assumptions those defenses rest
on, and — just as importantly — what Tripwire **cannot** do. Prompt injection
is not a fully solvable problem with today's techniques; the defensible claim
(and the consensus of the research it builds on — CaMeL, FIDES, the
defense-in-depth literature, Meta's "Rule of Two") is _blast-radius
reduction_: structural guarantees first, semantic judgement last, every
decision auditable.

## System model

```
 Agent (untrusted-by-default) ⇄ TRIPWIRE (trusted process) ⇄ Upstream tool servers
```

- **The Tripwire process is the trust anchor.** The HMAC key, the policy, the
  provenance index, and the audit chain live inside it. If the host running
  Tripwire is compromised, all bets are off — that is outside this model.
- **The agent is on the other side of an MCP boundary** and is assumed to be
  steerable: it may hallucinate, be prompt-injected by content it reads, or in
  the worst case be adversarial outright.
- **Upstream tool servers** are labeled in policy: `trusted` (your vendor DB,
  your ledger) or `untrusted` (anything that carries third-party content —
  document parsers, mail readers, web fetchers). A _trusted_ label means "we
  trust this server to report its own data honestly," nothing more.
- **Verifier models** (Tier 2) are independent, fallible, and themselves
  injectable. They are treated as advisors with a strict output contract,
  never as the primary defense.

## What each tier defends against

### Tier 0 — Receipts (HMAC-SHA256 over canonical JSON)

| Threat                                                                        | Defense                                                                                                                                                                    |
| ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Fabricated tool results ("I checked the vendor record" when no call happened) | Every real execution is receipted with a key the agent never sees. No receipt → the claim is unsupported; values with no receipted origin surface as `unknown_provenance`. |
| Post-hoc tampering with the session record                                    | Receipts are HMAC-signed over canonical bytes; `tripwire verify-log` re-derives every MAC and the audit hash chain, and names the exact tampered line.                     |
| Disputes about what happened                                                  | The ledger + chain are the ground truth: every decision (passes included) carries packet hashes, receipt references, verifier IDs, and prompt versions.                    |

Assumptions and limits:

- Receipts prove **what tools returned**, not that upstream data was _true_.
  A compromised "trusted" upstream produces perfectly receipted lies.
- The HMAC key is persisted (mode 0600) or supplied via env so sessions can be
  verified later. Anyone with host-level read access to the key can forge
  receipts — the boundary is the agent/MCP side, not the local filesystem.
- Stale/replayed-evidence detection via receipt ordering (an "evidence
  predates a contradicting later result" flag) is a documented roadmap item,
  not yet enforced — see the benchmark's `atk_stale_rotated_wallet` miss.

### Tier 1 — Provenance (taint tracking, structural)

| Threat                                                                                                        | Defense                                                                                                                                                                        |
| ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Poisoned-document recipient swap (the classic injected "our banking details changed")                         | The injected value's only origin is an untrusted tool result → the call is refused **by construction**, regardless of how persuasive the injection text was. Zero model calls. |
| Re-encoding evasion (case changes, stripped `0x`, whitespace, `12,500` vs `12500`)                            | Values are indexed and traced via tagged normal forms; trivially re-encoded values resolve to the same origin.                                                                 |
| Hallucinated / carried-in values (addresses or amounts from nowhere)                                          | No origin in session history → `unknown_provenance` → blocked under fail-closed policy.                                                                                        |
| Trust laundering via echo (query a trusted tool with the attacker's value so its error/response "blesses" it) | A result never confers its tool's trust label on values present in the call's own arguments, and failed executions are never indexed as evidence.                              |

Assumptions and limits — **read these as attack surface**, because adversaries
who read this source will:

- **Granularity is the tool, not the field.** Trust labels apply per upstream.
  If a "trusted" tool returns a record containing third-party text (e.g. a
  vendor "notes" field an attacker can edit), values inside it inherit trust.
  Label such tools untrusted, or split them.
- **Exact/normalized matching, not dataflow.** Tier 1 traces value _equality_
  across the session, not computation. A value derived from untrusted input
  by arithmetic or string surgery the normalizer doesn't model (e.g. an
  address assembled from two halves) will surface as `unknown_provenance` —
  blocked under fail-closed, but as "unknown", not attributed to the attack.
- **A value seen in both trusted and untrusted sources is allowed** (any
  trusted origin satisfies `provenance: trusted`). An attacker who mirrors the
  _real_ value gains nothing; an attacker who plants their value in a trusted
  source has already won upstream of Tripwire.
- **Coverage follows policy.** Only parameters listed in `sensitive_params`
  are traced. An unlisted parameter (a memo used for exfiltration, a quantity
  field on an unguarded tool) passes untraced. Policy review is part of the
  defense.
- Extraction is deliberately generous (a missed extraction becomes a false
  block, not a missed attack), but values inside images, archives, or exotic
  encodings are not extracted from results — they simply never become
  _trusted_ provenance.

### Tier 2 — Multi-model consensus (probabilistic, last line)

| Threat                                                                                                   | Defense                                                                              |
| -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Plausible-but-wrong values that ARE receipted (paying the whole balance; using another invoice's figure) | `bounds_and_sanity` compares quantitative parameters against the receipted evidence. |
| Goal substitution (declared intent says Acme, action pays someone else)                                  | `intent_match` checks the action against the receipted declared intent.              |
| Ungrounded material parameters that slipped past structural rules                                        | `source_grounding` demands per-parameter evidential support.                         |

Assumptions and limits:

- **Verifiers are fallible, injectable models.** Mitigations, not cures:
  independent providers (no shared weights or provider-level compromise),
  verifiers never see each other's outputs (no anchoring), the packet is
  delivered as fenced data with explicit instructions that evidence text
  carrying instructions is itself an injection signal, the output contract is
  strict JSON (malformed → failed verdict), and the deterministic tiers run
  _first_ so consensus only handles the residue structure can't express.
- **Fail-closed is the money-path default**: timeouts, malformed verdicts,
  missing API keys, and unknown providers all count as FAIL votes.
  `fail_mode: open` exists for low-stakes paths and changes only the
  availability story — returned fail verdicts still block.
- **Disagreement is signal**: split panels are flagged in the audit record
  rather than silently averaged; `quorum: unanimous` makes any dissent block.
- Consensus adds seconds of latency and per-call inference cost; policy keeps
  it scoped to consequential calls.

### Intent capture — honest about the hard problem

A proxy sees tool calls, not the user's goal. The v1 mechanism (the
`tripwire__declare_intent` synthetic tool) means **the intent is
agent-reported**. A fully compromised agent can declare a malicious intent —
and then:

1. the declaration is on the unforgeable audit record (post-incident, you
   know exactly what it claimed it was doing);
2. Tier 1 still constrains where parameter values may come from;
3. `source_grounding` still requires receipted evidence for material
   parameters.

Defense in depth, not a silver bullet. The v2 direction is a client-side hook
that forwards the actual user message as trusted intent, removing the agent
from that loop.

## What Tripwire does NOT defend against

Stated plainly, because a security README that hides its gaps deserves no
trust:

- **A compromised Tripwire host.** Key, policy, and index live in the
  process; host compromise defeats everything.
- **Lies from trusted upstreams.** Receipts attest to what was returned, not
  to its truth. Vetting which servers deserve `trusted` is your job, and the
  most consequential line in the config.
- **Attacks entirely inside allowed semantics.** If policy allows paying any
  trusted-provenance vendor any documented amount, an attacker who controls a
  trusted source or a plausible document operates inside the envelope (see
  the benchmark's two documented misses).
- **Denial of service via verification.** Fail-closed means an attacker who
  can take down your verifier providers can stall guarded calls. That is the
  designed trade on money paths; use `fail_mode: open` only where a wrong
  action is cheaper than a stalled one.
- **Exfiltration through unguarded channels.** Tripwire guards the parameters
  policy tells it to guard. Side channels (unguarded tools, memo fields,
  upstream servers reachable without the proxy) need policy and network
  control, not just this proxy.
- **Prompt injection as a class.** Tripwire makes the highest-impact
  injection outcomes (untrusted values reaching sensitive sinks) structurally
  impossible and shrinks the rest of the blast radius. It does not make the
  agent immune to being steered.

## Engineering posture

- Fail-closed on money paths is mandatory in policy validation, not a
  convention.
- Every external call has a timeout and bounded retry.
- Sensitive values never reach the audit log (hashes + receipt references
  only); block errors carry truncated previews, never full values; receipts
  (which must carry full values to be useful) are written mode 0600.
- The components adversaries will probe first — canonical serialization,
  value extraction/normalization, policy matching, panel aggregation — carry
  the densest test coverage in the repo (147 deterministic tests, no live
  calls in CI).

## Research anchors

CaMeL (arXiv:2503.18813) and FIDES (Microsoft Research) for
capability/provenance enforcement; NabaOS tool receipts (arXiv:2603.10060)
for cryptographic execution receipts; VeriTrail (Microsoft Research, 2026)
and the span-level grounding literature for claim-level verification; the
defense-in-depth consensus and Meta's "Rule of Two" for the overall posture.
