# Policy Reference

Tripwire policy is declarative YAML, validated with Zod at startup — invalid
configs fail loudly with the offending path. See
[`tripwire.example.yaml`](../tripwire.example.yaml) for a working example.

## Top level

```yaml
upstreams: [...] # required — the tool servers Tripwire proxies
defaults: { ... } # optional — behavior for calls no rule matches
rules: [...] # optional — verification rules, first match wins
state_dir: .tripwire # optional — where session artifacts are written
```

## `upstreams`

```yaml
upstreams:
  - name: vendors # alphanumeric + dashes; no underscores
    command: ['node', 'dist/vendors.js'] # spawned over stdio
    trust: trusted # trusted | untrusted (default: untrusted)
    env: { LOG_LEVEL: warn } # optional extra environment
```

- `name` becomes the tool namespace: the upstream's `get_vendor` is exposed
  to the agent as `vendors__get_vendor`. Underscores are forbidden in names
  because `__` delimits the namespace; `tripwire` is reserved.
- `trust` is consumed by Tier 1: values first observed in a `trusted`
  upstream's results satisfy `provenance: trusted`. **Untrusted is the
  default** — trust must be opted into, and means "this server carries no
  third-party content and reports its own data honestly."

## `defaults`

```yaml
defaults:
  on_unmatched: pass # pass | block — what happens to calls no rule matches
  audit: all # all | decisions
```

`on_unmatched: block` turns Tripwire into an allowlist: every guarded tool
needs a rule.

## `rules`

First matching rule wins; later rules are not consulted.

```yaml
rules:
  - match:
      tool: 'payments__*' # glob on the namespaced name (* and ?)
      upstream: payments # exact upstream name
      annotation: { destructiveHint: true } # subset match on MCP tool annotations
    sensitive_params:
      recipient: { provenance: trusted } # value must have a trusted-tool origin
      amount: { provenance: any } # value must be receipted somewhere
    verify:
      tiers: [receipts, provenance, consensus]
      require_intent: true # block until tripwire__declare_intent
      panel: [anthropic/claude-sonnet-4-6, openai/gpt-5.1, google/gemini-2.5-pro]
      quorum: unanimous # majority | unanimous
      checks: [intent_match, source_grounding, bounds_and_sanity]
      on_fail: block # block | hold
      fail_mode: closed # closed | open
      timeout_ms: 8000
```

### `match`

At least one clause is required; provided clauses are ANDed.

| Clause       | Semantics                                                                                                                                                 |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tool`       | Glob against the namespaced tool name. `*` matches any run of characters, `?` exactly one; everything else is literal.                                    |
| `upstream`   | Exact upstream name.                                                                                                                                      |
| `annotation` | Strict per-key equality against the upstream tool's MCP annotations (e.g. `destructiveHint: true` auto-escalates anything an upstream marks destructive). |

### `sensitive_params`

Per-parameter Tier 1 provenance requirements, applied when the parameter is
present in the call. Array parameters are traced element-by-element;
untraceable types (objects, booleans) fail closed.

| Requirement           | Meaning                                                                                           |
| --------------------- | ------------------------------------------------------------------------------------------------- |
| `provenance: trusted` | The value must have appeared in at least one trusted-tool result this session.                    |
| `provenance: any`     | The value must have appeared in _some_ receipted tool result (blocks invented/carried-in values). |

### `verify`

| Field            | Default                  | Notes                                                                                                                                                                           |
| ---------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tiers`          | `[receipts, provenance]` | Listing `consensus` requires a non-empty `panel` (validated at startup, never silently skipped).                                                                                |
| `require_intent` | `false`                  | Guarded calls are blocked (with self-serve remediation) until the agent declares an intent.                                                                                     |
| `panel`          | `[]`                     | `provider/model` entries; providers: `anthropic`, `openai`, `google`. Keys via `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`/`GOOGLE_API_KEY`.                        |
| `quorum`         | `majority`               | `unanimous` makes any dissenting verdict block.                                                                                                                                 |
| `checks`         | all three                | `intent_match`, `source_grounding`, `bounds_and_sanity` — every check must pass.                                                                                                |
| `on_fail`        | `block`                  | `block` returns a structured machine-actionable error; `hold` refuses pending human approval.                                                                                   |
| `fail_mode`      | `closed`                 | `closed`: verifier timeouts/malformed output/missing keys count as FAIL votes. `open`: errored verifiers abstain (returned fail verdicts still block). Keep money paths closed. |
| `timeout_ms`     | `8000`                   | Per-verifier budget, enforced by the panel itself.                                                                                                                              |

## Session artifacts

Each run writes to `<state_dir>/sessions/<session-id>/`:

| File             | Contents                                                                              |
| ---------------- | ------------------------------------------------------------------------------------- |
| `audit.jsonl`    | Hash-chained audit log — decisions, hashes, receipt refs; never raw sensitive values. |
| `receipts.jsonl` | HMAC-signed receipt for every execution (full values; created mode 0600).             |
| `hmac.key`       | Session receipt key (omitted when `TRIPWIRE_HMAC_KEY` is set).                        |

Verify any time with `tripwire verify-log <session-dir>`.
