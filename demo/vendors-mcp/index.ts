#!/usr/bin/env node
/**
 * Toy upstream: the internal vendor database. Labeled `trusted` in policy —
 * this is where the real banking details live.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

interface Vendor {
  id: string;
  slug: string;
  name: string;
  wallet: string;
  currency: string;
  email: string;
  status: string;
}

const VENDORS: Vendor[] = [
  {
    id: 'V-1001',
    slug: 'acme-corp',
    name: 'Acme Corp',
    wallet: '0xAAAA00000000000000000000000000000000AAAA',
    currency: 'USDC',
    email: 'billing@acme.example',
    status: 'active',
  },
  {
    id: 'V-1002',
    slug: 'globex',
    name: 'Globex Industrial',
    wallet: '0xC0FFEE0000000000000000000000000000000001',
    currency: 'USDC',
    email: 'ap@globex.example',
    status: 'active',
  },
];

const server = new McpServer({ name: 'vendors', version: '0.1.0' });

server.registerTool(
  'list_vendors',
  {
    title: 'List vendors',
    description: 'List all vendors in the internal vendor database.',
    inputSchema: {},
  },
  async () => ({
    content: [{ type: 'text', text: JSON.stringify(VENDORS, null, 2) }],
  }),
);

server.registerTool(
  'get_vendor',
  {
    title: 'Get vendor record',
    description:
      'Fetch a single vendor record (including verified payment details) by id, slug, or name.',
    inputSchema: { vendor: z.string().describe('Vendor id, slug, or name') },
  },
  async ({ vendor }) => {
    const needle = vendor.trim().toLowerCase();
    const match = VENDORS.find(
      (v) => v.id.toLowerCase() === needle || v.slug === needle || v.name.toLowerCase() === needle,
    );
    if (match === undefined) {
      return {
        content: [{ type: 'text', text: `No vendor found matching "${vendor}".` }],
        isError: true,
      };
    }
    return { content: [{ type: 'text', text: JSON.stringify(match, null, 2) }] };
  },
);

await server.connect(new StdioServerTransport());
