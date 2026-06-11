#!/usr/bin/env node
/**
 * Toy upstream: the payments rail. The consequential sink Tripwire guards.
 * Deterministic on purpose (counter-based tx ids) so demo runs reproduce.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

let txCounter = 0;
let balance = 100_000;

const server = new McpServer({ name: 'payments', version: '0.1.0' });

server.registerTool(
  'get_balance',
  {
    title: 'Get treasury balance',
    description: 'Get the current treasury balance.',
    inputSchema: {},
  },
  async () => ({
    content: [{ type: 'text', text: JSON.stringify({ balance, currency: 'USDC' }) }],
  }),
);

server.registerTool(
  'send_payment',
  {
    title: 'Send payment',
    description: 'Send an on-chain payment from the treasury wallet. Irreversible.',
    inputSchema: {
      recipient: z.string().describe('Destination wallet address'),
      amount: z.number().positive().describe('Amount to send'),
      currency: z.string().describe('Currency symbol, e.g. USDC'),
      memo: z.string().optional().describe('Optional payment memo'),
    },
    annotations: { destructiveHint: true },
  },
  async ({ recipient, amount, currency, memo }) => {
    if (amount > balance) {
      return {
        content: [{ type: 'text', text: `Insufficient balance: ${balance} ${currency}.` }],
        isError: true,
      };
    }
    txCounter += 1;
    balance -= amount;
    const tx = {
      status: 'submitted',
      tx_id: `tx_${String(txCounter).padStart(4, '0')}`,
      recipient,
      amount,
      currency,
      ...(memo === undefined ? {} : { memo }),
    };
    return { content: [{ type: 'text', text: JSON.stringify(tx) }] };
  },
);

await server.connect(new StdioServerTransport());
