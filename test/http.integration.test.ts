import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { AuditLog } from '../src/audit/log.js';
import {
  HttpTransportSchema,
  isLoopbackHost,
  resolveHttpAuth,
  type RuleConfig,
} from '../src/policy/config.js';
import type { BlockPayload } from '../src/proxy/block.js';
import { serveHttp, type HttpServerHandle } from '../src/proxy/http-server.js';
import { TripwireProxy } from '../src/proxy/proxy.js';
import { ReceiptLedger, generateReceiptKey } from '../src/receipts/ledger.js';

/**
 * Phase 6 gate: the full verification pipeline over real Streamable HTTP —
 * many agents against one Tripwire process, each in an isolated session —
 * plus the auth and fail-closed exposure rules.
 */

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const TRUSTED_WALLET = '0xAAAA00000000000000000000000000000000AAAA';
const ATTACKER_WALLET = '0xBBBB00000000000000000000000000000000BBBB';
const TOKEN = 'test-token-0123456789abcdef';

let workDir: string;
let handle: HttpServerHandle;
let sessionCounter = 0;

const upstream = (name: string, trust: 'trusted' | 'untrusted') => ({
  name,
  command: [process.execPath, '--import', 'tsx', join(ROOT, 'demo', `${name}-mcp`, 'index.ts')] as [
    string,
    ...string[],
  ],
  trust,
  env: {},
});

const RULES: RuleConfig[] = [
  {
    match: { tool: 'payments__send_payment' },
    sensitive_params: {
      recipient: { provenance: 'trusted' },
      amount: { provenance: 'any' },
    },
    verify: {
      tiers: ['receipts', 'provenance'],
      require_intent: true,
      panel: [],
      quorum: 'majority',
      checks: ['intent_match', 'source_grounding', 'bounds_and_sanity'],
      on_fail: 'block',
      fail_mode: 'closed',
      timeout_ms: 2_000,
    },
  },
];

async function connect(token?: string): Promise<Client> {
  const client = new Client({ name: 'http-agent', version: '0.0.0' });
  const transport = new StreamableHTTPClientTransport(new URL(handle.url), {
    requestInit: token === undefined ? {} : { headers: { authorization: `Bearer ${token}` } },
  });
  // Cast: SDK accessor-based optionals vs exactOptionalPropertyTypes.
  await client.connect(transport as unknown as Parameters<Client['connect']>[0]);
  return client;
}

async function call(
  client: Client,
  name: string,
  args: Record<string, unknown>,
): Promise<CallToolResult> {
  return (await client.callTool({ name, arguments: args })) as CallToolResult;
}

function blockPayload(result: CallToolResult): BlockPayload {
  expect(result.isError).toBe(true);
  return JSON.parse((result.content as { text: string }[])[0]!.text) as BlockPayload;
}

beforeAll(async () => {
  workDir = mkdtempSync(join(tmpdir(), 'tripwire-http-'));
  handle = await serveHttp({
    http: HttpTransportSchema.parse({ port: 0 }), // ephemeral port
    token: TOKEN,
    createSessionProxy: () => {
      sessionCounter += 1;
      const label = `http-test-${sessionCounter}`;
      return {
        label,
        proxy: new TripwireProxy({
          upstreams: [
            upstream('vendors', 'trusted'),
            upstream('docs', 'untrusted'),
            upstream('payments', 'trusted'),
          ],
          ledger: new ReceiptLedger({
            key: generateReceiptKey(),
            sessionId: label,
            persistPath: join(workDir, `${label}-receipts.jsonl`),
          }),
          audit: new AuditLog(join(workDir, `${label}-audit.jsonl`)),
          rules: RULES,
          defaults: { on_unmatched: 'pass', audit: 'all' },
        }),
      };
    },
  });
});

afterAll(async () => {
  await handle?.close();
  rmSync(workDir, { recursive: true, force: true });
});

describe('auth and exposure rules', () => {
  it('rejects requests without a bearer token (401)', async () => {
    const response = await fetch(handle.url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
      },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'initialize', params: {}, id: 1 }),
    });
    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toBe('Bearer');
  });

  it('rejects a wrong token and the MCP client surfaces it', async () => {
    await expect(connect('wrong-token-0123456789abcdef')).rejects.toThrow(/401|invalid/i);
  });

  it('404s on paths other than the MCP endpoint', async () => {
    const response = await fetch(new URL('/other', handle.url), {
      method: 'POST',
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    expect(response.status).toBe(404);
  });

  it('requires the first request of a session to be initialize', async () => {
    const response = await fetch(handle.url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        authorization: `Bearer ${TOKEN}`,
      },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', params: {}, id: 1 }),
    });
    expect(response.status).toBe(400);
  });

  it('refuses to configure a non-loopback bind without a token (fail-closed)', () => {
    expect(() => resolveHttpAuth(HttpTransportSchema.parse({ host: '0.0.0.0' }), {})).toThrow(
      /refusing to serve/,
    );
    // Loopback without a token is allowed; env token satisfies the rule too.
    expect(resolveHttpAuth(HttpTransportSchema.parse({}), {}).token).toBeUndefined();
    expect(
      resolveHttpAuth(HttpTransportSchema.parse({ host: '0.0.0.0' }), {
        TRIPWIRE_HTTP_TOKEN: 'env-token-0123456789',
      }).token,
    ).toBe('env-token-0123456789');
  });

  it('classifies loopback hosts correctly', () => {
    for (const host of ['127.0.0.1', 'localhost', '::1', '[::1]', '127.5.5.5']) {
      expect(isLoopbackHost(host), host).toBe(true);
    }
    for (const host of ['0.0.0.0', '192.168.1.10', 'example.com', '::']) {
      expect(isLoopbackHost(host), host).toBe(false);
    }
  });
});

describe('full pipeline over HTTP', () => {
  it('runs intent gate, Tier 1 block, self-correction, and pass — over HTTP', async () => {
    const client = await connect(TOKEN);

    const tools = (await client.listTools()).tools.map((t) => t.name);
    expect(tools).toContain('payments__send_payment');
    expect(tools).toContain('tripwire__declare_intent');

    // No intent yet → blocked.
    let payload = blockPayload(
      await call(client, 'payments__send_payment', {
        recipient: TRUSTED_WALLET,
        amount: 1,
        currency: 'USDC',
      }),
    );
    expect(payload.code).toBe('intent_required');

    await call(client, 'tripwire__declare_intent', {
      goal: 'Pay the outstanding Acme Corp invoice #7741',
    });
    await call(client, 'docs__read_document', { id: 'invoice-acme-7741' });

    // Poisoned recipient → structural block.
    payload = blockPayload(
      await call(client, 'payments__send_payment', {
        recipient: ATTACKER_WALLET,
        amount: 12_500,
        currency: 'USDC',
      }),
    );
    expect(payload.code).toBe('provenance_violation');

    // Self-correct and pass.
    await call(client, 'vendors__get_vendor', { vendor: 'acme-corp' });
    const ok = await call(client, 'payments__send_payment', {
      recipient: TRUSTED_WALLET,
      amount: 12_500,
      currency: 'USDC',
    });
    expect(ok.isError).toBeFalsy();
    await client.close();
  });

  it('isolates sessions: one agent’s provenance never vouches for another’s', async () => {
    const agentA = await connect(TOKEN);
    const agentB = await connect(TOKEN);

    // Agent A earns trusted provenance for the wallet.
    await call(agentA, 'tripwire__declare_intent', { goal: 'Pay the Acme Corp invoice' });
    await call(agentA, 'docs__read_document', { id: 'invoice-acme-7741' });
    await call(agentA, 'vendors__get_vendor', { vendor: 'acme-corp' });

    // Agent B declares intent but never fetched the vendor record. If state
    // bled between sessions, A's lookup would let B's payment through.
    await call(agentB, 'tripwire__declare_intent', { goal: 'Pay the Acme Corp invoice' });
    const blocked = blockPayload(
      await call(agentB, 'payments__send_payment', {
        recipient: TRUSTED_WALLET,
        amount: 12_500,
        currency: 'USDC',
      }),
    );
    expect(blocked.code).toBe('provenance_violation');
    expect(blocked.violations?.[0]?.reason).toBe('unknown_provenance');

    // And A still passes in the same breath.
    const ok = await call(agentA, 'payments__send_payment', {
      recipient: TRUSTED_WALLET,
      amount: 12_500,
      currency: 'USDC',
    });
    expect(ok.isError).toBeFalsy();

    await agentA.close();
    await agentB.close();
  });

  it('tears the session down on client close (upstreams reaped)', async () => {
    const before = sessionCounter;
    const client = await connect(TOKEN);
    await call(client, 'payments__get_balance', {});
    expect(sessionCounter).toBe(before + 1);
    await client.close();
    // Closing the transport DELETEs the session server-side; a fresh connect
    // must get a NEW session, not the old one.
    const client2 = await connect(TOKEN);
    await call(client2, 'payments__get_balance', {});
    expect(sessionCounter).toBe(before + 2);
    await client2.close();
  });
});
