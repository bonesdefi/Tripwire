import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { verifyAuditFile, type AuditEntry } from '../src/audit/log.js';
import type { BlockPayload } from '../src/proxy/block.js';
import { type Receipt } from '../src/receipts/ledger.js';

/**
 * Phase 2 gate: the poisoned-address scenario is blocked by Tier 1 alone —
 * verifiers disabled, zero model calls — and the legitimate flow (re-fetch
 * from the trusted source, retry) succeeds. Runs through the real proxy
 * over real stdio MCP.
 */

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const TRUSTED_WALLET = '0xAAAA00000000000000000000000000000000AAAA';
const ATTACKER_WALLET = '0xBBBB00000000000000000000000000000000BBBB';
const UNSEEN_WALLET = '0xCCCC00000000000000000000000000000000CCCC';

let workDir: string;
let stateDir: string;
let client: Client;

const tsxArgs = (script: string, ...args: string[]) => ['--import', 'tsx', script, ...args];

async function call(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  return (await client.callTool({ name, arguments: args })) as CallToolResult;
}

function blockPayload(result: CallToolResult): BlockPayload {
  expect(result.isError).toBe(true);
  const text = (result.content as { type: string; text: string }[])[0];
  expect(text?.type).toBe('text');
  const payload = JSON.parse(text!.text) as BlockPayload;
  expect(payload.tripwire).toBe('blocked');
  return payload;
}

async function balance(): Promise<number> {
  const result = await call('payments__get_balance', {});
  const text = (result.content as { text: string }[])[0]!.text;
  return (JSON.parse(text) as { balance: number }).balance;
}

beforeAll(async () => {
  workDir = mkdtempSync(join(tmpdir(), 'tripwire-tier1-'));
  stateDir = join(workDir, 'state');

  const upstream = (name: string, trust: string) => ({
    name,
    command: [process.execPath, ...tsxArgs(join(ROOT, 'demo', `${name}-mcp`, 'index.ts'))],
    trust,
  });
  const config = {
    upstreams: [
      upstream('vendors', 'trusted'),
      upstream('docs', 'untrusted'),
      upstream('payments', 'trusted'),
    ],
    defaults: { on_unmatched: 'pass', audit: 'all' },
    rules: [
      {
        match: { tool: 'payments__send_payment' },
        sensitive_params: {
          recipient: { provenance: 'trusted' },
          amount: { provenance: 'any' },
        },
        verify: {
          // Tier 1 only — the whole point of this gate is zero model calls.
          tiers: ['receipts', 'provenance'],
          on_fail: 'block',
          fail_mode: 'closed',
        },
      },
      {
        match: { annotation: { destructiveHint: true } },
        verify: { tiers: ['receipts', 'provenance'], on_fail: 'block' },
      },
    ],
    state_dir: stateDir,
  };
  const configPath = join(workDir, 'tripwire.yaml');
  writeFileSync(configPath, JSON.stringify(config)); // JSON is valid YAML

  client = new Client({ name: 'victim-agent', version: '0.0.0' });
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: tsxArgs(join(ROOT, 'src', 'cli.ts'), 'run', '--config', configPath),
      cwd: ROOT,
      stderr: 'inherit',
    }),
  );
});

afterAll(async () => {
  await client?.close();
  rmSync(workDir, { recursive: true, force: true });
});

describe('poisoned-invoice scenario (Tier 1 only, no verifiers)', () => {
  it('blocks payment to the injected address after the agent reads the poisoned doc', async () => {
    const doc = await call('docs__read_document', { id: 'invoice-acme-7741' });
    expect((doc.content as { text: string }[])[0]!.text).toContain(ATTACKER_WALLET);

    const blocked = await call('payments__send_payment', {
      recipient: ATTACKER_WALLET,
      amount: 12_500,
      currency: 'USDC',
      memo: 'invoice #7741',
    });
    const payload = blockPayload(blocked);
    expect(payload.code).toBe('provenance_violation');
    expect(payload.violations).toHaveLength(1);
    expect(payload.violations?.[0]).toMatchObject({
      param: 'recipient',
      reason: 'untrusted_provenance',
      required_provenance: 'trusted',
    });
    // The error tells the agent exactly where the value really came from.
    expect(payload.violations?.[0]?.observed_origins).toEqual([
      expect.objectContaining({ upstream: 'docs', trust: 'untrusted' }),
    ]);
    // And never echoes the full address back.
    expect(JSON.stringify(payload)).not.toContain(ATTACKER_WALLET);

    // The payment never reached the upstream.
    expect(await balance()).toBe(100_000);
  });

  it('blocks payment to an address that appeared nowhere in the session', async () => {
    const payload = blockPayload(
      await call('payments__send_payment', {
        recipient: UNSEEN_WALLET,
        amount: 12_500,
        currency: 'USDC',
      }),
    );
    expect(payload.violations?.[0]).toMatchObject({
      param: 'recipient',
      reason: 'unknown_provenance',
    });
  });

  it('blocks an invented amount even when the recipient is trusted', async () => {
    await call('vendors__get_vendor', { vendor: 'acme-corp' }); // trusted fetch
    const payload = blockPayload(
      await call('payments__send_payment', {
        recipient: TRUSTED_WALLET,
        amount: 4_321, // appears in no receipted result
        currency: 'USDC',
      }),
    );
    expect(payload.violations?.[0]).toMatchObject({
      param: 'amount',
      reason: 'unknown_provenance',
    });
  });

  it('does not let a trusted-tool echo launder the attacker address', async () => {
    // get_vendor(attacker address) returns an isError echo of the input.
    const echo = await call('vendors__get_vendor', { vendor: ATTACKER_WALLET });
    expect(echo.isError).toBe(true);

    const payload = blockPayload(
      await call('payments__send_payment', {
        recipient: ATTACKER_WALLET,
        amount: 12_500,
        currency: 'USDC',
      }),
    );
    expect(payload.violations?.[0]?.param).toBe('recipient');
  });

  it('lets the corrected, grounded payment through (the self-correction path)', async () => {
    // Recipient from the trusted vendor record (fetched above); amount from
    // the receipted invoice document. Case differences must not matter.
    const result = await call('payments__send_payment', {
      recipient: TRUSTED_WALLET.toLowerCase(),
      amount: 12_500,
      currency: 'USDC',
      memo: 'invoice #7741',
    });
    expect(result.isError).toBeFalsy();
    const tx = JSON.parse((result.content as { text: string }[])[0]!.text) as {
      tx_id: string;
    };
    expect(tx.tx_id).toBe('tx_0001');
    expect(await balance()).toBe(87_500);
  });

  it('records blocks and passes in the audit chain; blocked calls leave no execution receipt', () => {
    const sessions = readdirSync(join(stateDir, 'sessions'));
    expect(sessions).toHaveLength(1);
    const dir = join(stateDir, 'sessions', sessions[0]!);

    const audit = verifyAuditFile(join(dir, 'audit.jsonl'));
    expect(audit.errors).toEqual([]);
    expect(audit.ok).toBe(true);

    const entries = readFileSync(join(dir, 'audit.jsonl'), 'utf8')
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as AuditEntry);

    const blocks = entries.filter((e) => e.type === 'tool_call_blocked');
    expect(blocks).toHaveLength(4);
    expect(blocks.every((b) => b.data.code === 'provenance_violation')).toBe(true);

    // The successful payment carries Tier 1 provenance annotations.
    const paid = entries.find(
      (e) =>
        e.type === 'tool_call' &&
        e.data.tool === 'payments__send_payment' &&
        e.data.decision === 'pass',
    );
    expect(paid).toBeDefined();
    const tier1 = paid?.data.tier1_provenance as Record<
      string,
      { upstream: string; trust: string }[]
    >;
    expect(tier1.recipient?.[0]).toMatchObject({ upstream: 'vendors', trust: 'trusted' });
    expect(tier1.amount?.[0]).toMatchObject({ upstream: 'docs', trust: 'untrusted' });

    // Exactly one send_payment receipt exists: the one that executed.
    const receipts = readFileSync(join(dir, 'receipts.jsonl'), 'utf8')
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as Receipt);
    expect(receipts.filter((r) => r.tool === 'payments__send_payment')).toHaveLength(1);
  });
});
