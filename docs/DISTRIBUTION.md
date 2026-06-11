# Publishing & Distribution

Everything here is prepared and ready; the steps below require credentials a
maintainer holds (npm login, GitHub auth), so they are documented rather than
automated.

## 1. Publish to npm

The package is `tripwire-mcp` (the `tripwire` command). The name is available.

```sh
npm login
npm publish        # runs prepublishOnly: typecheck + lint + build + 155 tests
```

`prepublishOnly` refuses to publish unless the full suite is green, and `files`
ships only `dist/`, the example config, and the docs — no source, no tests. Verify
the exact tarball contents first without publishing:

```sh
npm pack --dry-run
```

After publishing, the install line in the README/getting-started works as written:

```sh
npm install -g tripwire-mcp
```

Bump `version` in both `package.json` and `server.json` together for each release
(they must match what's on npm), then `npm publish` again.

## 2. List in the official MCP Registry

`server.json` (repo root) is a valid manifest against the
`2025-12-11` registry schema. **Ownership validation:** the registry checks
that the npm package's `package.json` contains
`"mcpName": "io.github.bonesdefi/tripwire"` matching `server.json`'s `name` —
so the npm version referenced in `server.json` must have been published with
that field (present since 0.3.1). To publish, authenticate ownership of the
`io.github.bonesdefi/*` namespace with your GitHub account via the official
`mcp-publisher` CLI:

```sh
# install the publisher CLI (see github.com/modelcontextprotocol/registry)
mcp-publisher login github      # proves you own github.com/bonesdefi
mcp-publisher publish           # reads ./server.json
```

The namespace `io.github.bonesdefi/tripwire` is owned automatically by the
GitHub account `bonesdefi` — no separate approval needed. Re-run `publish` on each
version bump.

Note: Tripwire is a **proxy in front of** your real servers, not a turnkey MCP
server, so the registry entry is primarily for discovery. The `packageArguments`
point at `tripwire.yaml`, which `tripwire init` generates.

## 3. Community lists (the highest-traffic discovery path)

MCP users browse curated lists far more than the registry today. Open a PR
adding Tripwire to each, using the blurb below.

- **`punkpeye/awesome-mcp-servers`** — the largest list; add under a Security
  category.
- **`wong2/awesome-mcp-servers`**
- **`modelcontextprotocol/servers`** — "community servers" section of the
  reference repo.
- Any "awesome LLM security" / "AI agent security" lists — Tripwire fits the
  prompt-injection-defense niche specifically.

### Ready-to-paste list entry

```markdown
- [Tripwire](https://github.com/bonesdefi/Tripwire) — Security gateway that
  blocks prompt-injection-driven tool calls (poisoned payments, fabricated
  results) using cryptographic receipts, value-provenance enforcement, and
  multi-model consensus. Sits in front of any MCP server.
```

### One-line pitch (for HN/X/Discord intros)

> Existing MCP firewalls are syntactic — globs, allowlists, regex. None can tell
> whether a tool call is actually grounded in evidence and the user's intent. A
> payment to an attacker's address looks identical to a payment to the real
> vendor. Tripwire is the verification layer that checks that, and makes the
> poisoned-invoice attack impossible by construction rather than detected.

## Release checklist

1. `npm run typecheck && npm run lint && npm test` green
2. `npm run demo:svg` if the demo output changed (regenerates `docs/demo.svg`)
3. Bump `version` in `package.json` **and** `server.json`
4. `npm publish`
5. `mcp-publisher publish`
6. Tag the release on GitHub (`v0.2.0`) and write release notes
