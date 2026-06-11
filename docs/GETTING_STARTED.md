# Getting Started with Tripwire

This guide is for everyone — you do **not** need to be an engineer. If you can
copy a command and answer a few questions, you can set up Tripwire.

## What Tripwire does, in one paragraph

AI agents can take real actions for you: send payments, send email, post
things, delete things. They decide _what_ to do partly from content they read —
documents, web pages, messages — and that content can be poisoned by an
outsider to trick the agent ("our bank details changed, send the money here
instead"). Tripwire sits between your agent and its tools and **checks
dangerous actions before they happen**, blocking the ones that aren't backed by
a trustworthy source. It keeps a tamper-proof record of everything.

## What you need

- A computer with **Node.js 20 or newer** ([nodejs.org](https://nodejs.org) — the
  "LTS" download is fine).
- The MCP tool servers your agent already uses (you'll reuse their existing
  start commands — no need to understand them).
- _Optional:_ an API key from Anthropic, OpenAI, and/or Google if you want the
  AI double-check layer. Tripwire works without them; you just get the
  deterministic protections, which stop the headline attacks.

## Step 1 — Install

In a terminal:

```sh
npm install -g tripwire-mcp
```

(Before the npm release goes live, use `npm install -g github:bonesdefi/tripwire`
instead — same result.) Either way you get a `tripwire` command. Prefer not to
install globally? Clone the repo, run `npm install`, and use `npx tripwire` in
that folder.

## Step 2 — Run the guided setup

```sh
tripwire init
```

It asks plain-language questions and writes the configuration for you:

1. **Your tool servers.** For each one: a short name, the command that starts
   it (the same command already in your agent's settings), and one important
   question — _"Can content from outside your organization reach the agent
   through this server?"_ Say **yes** for anything that carries web pages,
   email, shared documents, or chat; say **no** for your own internal database
   or API. This is the single most important answer: it tells Tripwire which
   sources are allowed to supply sensitive values like account numbers.
2. **The actions worth guarding.** The tools that could do real damage with the
   wrong input — payments, sending messages, deleting data — and which of their
   inputs must come from a trusted source.
3. **Extra protection.** Whether the agent must state its goal first, and
   whether to turn on the AI double-check (offered automatically if it finds
   your API keys).

When it finishes you'll have two files:

- `tripwire.yaml` — your protection rules.
- `tripwire-agent-config.json` — the snippet to give your agent.

## Step 3 — Check that it works

```sh
tripwire check
```

This actually starts each of your tool servers and tells you, in plain English,
whether everything is wired up: green check marks for things that work, warnings
for things to look at (like a missing API key), and clear ✘ marks for anything
that must be fixed. Re-run it until you're happy.

## Step 4 — Point your agent at Tripwire

Open `tripwire-agent-config.json`. It looks like this:

```json
{
  "mcpServers": {
    "tripwire": {
      "command": "tripwire",
      "args": ["run", "--config", "tripwire.yaml"]
    }
  }
}
```

In your AI agent's settings (for example, Claude Desktop's MCP servers section),
**replace the tool servers it currently lists with this one entry.** If the
snippet includes an `env` section with `<your key here>` placeholders, paste
your real API keys there. Save and restart the agent.

That's it. Your agent now reaches its tools _through_ Tripwire. Everyday use
doesn't change — the agent sees the same tools and works the same way — except
that dangerous calls are now verified, and unsafe ones come back with a clear
explanation the agent can act on.

## Step 5 — See what happened

Every session is recorded under `.tripwire/sessions/`. To read the most recent
one in plain English:

```sh
tripwire logs .tripwire/sessions/<the newest folder>
```

You'll see a timeline: what the agent did, what was allowed, and what was
blocked and why. To _prove_ the record hasn't been altered (useful for audits
or disputes):

```sh
tripwire verify-log .tripwire/sessions/<the newest folder>
```

## What's protected, and what isn't (the honest version)

- The **deterministic protections** (receipts + provenance) are always on and
  stop the main attack — a poisoned document can't redirect a payment, because
  the bad address never came from a trusted source. No AI, no guessing.
- The **AI double-check** (optional) catches subtler problems, like a payment
  that's technically allowed but the wrong amount. If your AI providers can't be
  reached, guarded actions are **blocked, not waved through** — safe by default.
- Tripwire protects the actions and inputs your rules cover. Choosing which
  servers are trusted and which actions to guard is the real work — `tripwire
init` walks you through it, and [THREAT_MODEL.md](THREAT_MODEL.md) explains
  the trade-offs and, importantly, what Tripwire **cannot** do.

## Getting unstuck

| Symptom                               | What to do                                                                                                                                                              |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tripwire: command not found`         | Re-run the install in Step 1, or use `npx tripwire …` from a clone.                                                                                                     |
| `tripwire check` shows ✘ for a server | The start command is wrong — copy it exactly from your agent's current settings.                                                                                        |
| Guarded calls always get blocked      | Usually no server is marked **trusted**, so protected values have nowhere safe to come from. Re-run `tripwire init` and mark your internal system of record as trusted. |
| A warning about a missing API key     | Either add the key to the agent's settings, or re-run `tripwire init` and turn the AI double-check off.                                                                 |
| Full settings reference               | [POLICY.md](POLICY.md).                                                                                                                                                 |
