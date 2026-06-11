import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { verifyAuditFile, type AuditEntry } from '../src/audit/log.js';
import { canonicalize } from '../src/receipts/canonical.js';
import { verifyReceiptFile, type Receipt } from '../src/receipts/ledger.js';

/**
 * Phase 1 gate: an agent connected through Tripwire must be behaviorally
 * indistinguishable from one connected directly to the upstreams, and every
 * forwarded call must leave a verifiable receipt and audit entry.
 *
 * Everything here runs against real child processes over real stdio MCP —
 * no mocks on the transport path.
 */

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const DEMOS = ['vendors', 'docs', 'payments'] as const;
type DemoName = (typeof DEMOS)[number];

const demoEntry = (name: DemoName) => join(ROOT, 'demo', `${name}-mcp`, 'index.ts');
const tsxCommand = (script: string, ...args: string[]) => ({
  command: process.execPath,
  args: ['--import', 'tsx', script, ...args],
});

let workDir: string;
let stateDir: string;
let proxyClient: Client;
const directClients = {} as Record<DemoName, Client>;
let proxiedCallCount = 0;

async function connectClient(params: { command: string; args: string[] }): Promise<Client> {
  const client = new Client({ name: 'test-agent', version: '0.0.0' });
  await client.connect(new StdioClientTransport({ ...params, cwd: ROOT, stderr: 'inherit' }));
  return client;
}

function sessionDir(): string {
  const sessions = readdirSync(join(stateDir, 'sessions'));
  expect(sessions).toHaveLength(1);
  return join(stateDir, 'sessions', sessions[0]!);
}

/** Call the same tool directly and through the proxy; assert byte-equivalence. */
async function expectPassthrough(
  upstream: DemoName,
  tool: string,
  args: Record<string, unknown>,
): Promise<CallToolResult> {
  const direct = await directClients[upstream].callTool({ name: tool, arguments: args });
  const proxied = await proxyClient.callTool({
    name: `${upstream}__${tool}`,
    arguments: args,
  });
  proxiedCallCount += 1;
  expect(canonicalize(proxied)).toBe(canonicalize(direct));
  return proxied as CallToolResult;
}

beforeAll(async () => {
  workDir = mkdtempSync(join(tmpdir(), 'tripwire-itest-'));
  stateDir = join(workDir, 'state');

  const config = {
    upstreams: DEMOS.map((name) => {
      const { command, args } = tsxCommand(demoEntry(name));
      return { name, command: [command, ...args], trust: 'untrusted' };
    }),
    state_dir: stateDir,
  };
  const configPath = join(workDir, 'tripwire.yaml');
  writeFileSync(configPath, JSON.stringify(config)); // JSON is valid YAML

  proxyClient = await connectClient(
    tsxCommand(join(ROOT, 'src', 'cli.ts'), 'run', '--config', configPath),
  );
  for (const name of DEMOS) {
    directClients[name] = await connectClient(tsxCommand(demoEntry(name)));
  }
});

afterAll(async () => {
  await Promise.allSettled([
    proxyClient?.close(),
    ...Object.values(directClients).map((c) => c.close()),
  ]);
  rmSync(workDir, { recursive: true, force: true });
});

describe('transparent passthrough', () => {
  it('merges upstream tools under namespaces with definitions verbatim', async () => {
    const all = (await proxyClient.listTools()).tools;
    // The one synthetic tool Tripwire adds; everything else is verbatim.
    expect(all.some((t) => t.name === 'tripwire__declare_intent')).toBe(true);
    const proxied = all.filter((t) => t.name !== 'tripwire__declare_intent');
    const expected: unknown[] = [];
    for (const name of DEMOS) {
      const direct = (await directClients[name].listTools()).tools;
      expected.push(...direct.map((tool) => ({ ...tool, name: `${name}__${tool.name}` })));
    }
    const byName = (a: { name: string }, b: { name: string }) => a.name.localeCompare(b.name);
    expect(canonicalize([...proxied].sort(byName))).toBe(
      canonicalize((expected as { name: string }[]).sort(byName)),
    );
    // Annotations survive the merge (Phase 2 policy depends on them).
    const send = proxied.find((t) => t.name === 'payments__send_payment');
    expect(send?.annotations?.destructiveHint).toBe(true);
  });

  it('forwards tool results byte-for-byte', async () => {
    await expectPassthrough('vendors', 'get_vendor', { vendor: 'acme-corp' });
    await expectPassthrough('vendors', 'list_vendors', {});
    await expectPassthrough('docs', 'read_document', { id: 'invoice-acme-7741' });
    await expectPassthrough('docs', 'list_documents', {});
    await expectPassthrough('payments', 'get_balance', {});
  });

  it('forwards isError results byte-for-byte', async () => {
    const result = await expectPassthrough('docs', 'read_document', { id: 'no-such-doc' });
    expect(result.isError).toBe(true);
  });

  it('forwards consequential calls (send_payment) identically', async () => {
    const result = await expectPassthrough('payments', 'send_payment', {
      recipient: '0xAAAA00000000000000000000000000000000AAAA',
      amount: 12_500,
      currency: 'USDC',
      memo: 'invoice #7741',
    });
    const text = result.content?.[0];
    expect(text?.type).toBe('text');
    expect(JSON.parse((text as { text: string }).text)).toMatchObject({
      status: 'submitted',
      tx_id: 'tx_0001',
    });
  });

  it('rejects unknown and un-namespaced tool names', async () => {
    await expect(proxyClient.callTool({ name: 'ghost__tool', arguments: {} })).rejects.toThrow(
      /Unknown tool/,
    );
    await expect(proxyClient.callTool({ name: 'not-namespaced', arguments: {} })).rejects.toThrow(
      /Unknown tool/,
    );
  });
});

describe('tier 0 receipts and audit (recorded session)', () => {
  it('writes a verifiable receipt for every forwarded call', () => {
    const dir = sessionDir();
    const key = Buffer.from(readFileSync(join(dir, 'hmac.key'), 'utf8').trim(), 'hex');
    const receiptsPath = join(dir, 'receipts.jsonl');

    const verdict = verifyReceiptFile(key, receiptsPath);
    expect(verdict.failures).toEqual([]);
    expect(verdict.ok).toBe(true);
    expect(verdict.count).toBe(proxiedCallCount);

    // Receipts capture the real traffic.
    const receipts = readFileSync(receiptsPath, 'utf8')
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as Receipt);
    const payment = receipts.find((r) => r.tool === 'payments__send_payment');
    expect(payment?.upstream).toBe('payments');
    expect(payment?.args).toMatchObject({ amount: 12_500 });

    // A tampered ledger fails verification.
    const tampered = receipts.map((r) =>
      r.tool === 'payments__send_payment'
        ? { ...r, args: { ...(r.args as object), amount: 999_999 } }
        : r,
    );
    const tamperedPath = join(workDir, 'tampered-receipts.jsonl');
    writeFileSync(tamperedPath, tampered.map((r) => JSON.stringify(r)).join('\n') + '\n');
    expect(verifyReceiptFile(key, tamperedPath).ok).toBe(false);
  });

  it('maintains a verifiable hash-chained audit log of all traffic', () => {
    const dir = sessionDir();
    const auditPath = join(dir, 'audit.jsonl');

    const verdict = verifyAuditFile(auditPath);
    expect(verdict.errors).toEqual([]);
    expect(verdict.ok).toBe(true);

    const entries = readFileSync(auditPath, 'utf8')
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as AuditEntry);

    const types = entries.map((e) => e.type);
    expect(types.filter((t) => t === 'upstream_connected')).toHaveLength(3);
    expect(types).toContain('proxy_started');
    expect(types.filter((t) => t === 'tool_call')).toHaveLength(proxiedCallCount);
    expect(types.filter((t) => t === 'tool_call_rejected')).toHaveLength(2);

    // Audit entries reference receipts but never carry raw parameter values.
    const call = entries.find(
      (e) => e.type === 'tool_call' && e.data.tool === 'payments__send_payment',
    );
    expect(call?.data.receipt_seq).toBeTypeOf('number');
    expect(call?.data.args_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(call)).not.toContain('0xAAAA');
  });
});
