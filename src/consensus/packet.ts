import type { Tool } from '@modelcontextprotocol/sdk/types.js';

import type { Origin } from '../provenance/index.js';
import { canonicalHash } from '../receipts/canonical.js';
import type { Receipt } from '../receipts/ledger.js';
import type { VerificationPacket } from './types.js';

/**
 * Build the verification packet a panel verifier receives: the declared
 * intent, the proposed call, Tier 1 provenance annotations, and excerpts of
 * the receipted evidence those annotations reference (plus a little recent
 * context). Verifiers see evidence excerpts, never the receipt HMACs or key.
 */

const MAX_EXCERPT_CHARS = 2_000;
const RECENT_RECEIPTS = 5;

export interface DeclaredIntent {
  goal: string;
  plan_summary?: string | undefined;
  receipt_seq: number;
  ts: string;
}

export function buildPacket(input: {
  tool: string;
  args: Record<string, unknown>;
  toolDef?: Tool | undefined;
  intent: DeclaredIntent | null;
  provenance: Record<string, Origin[]>;
  receipts: readonly Receipt[];
}): { packet: VerificationPacket; packetHash: string } {
  const referenced = new Set<number>();
  for (const origins of Object.values(input.provenance)) {
    for (const origin of origins) referenced.add(origin.receipt_seq);
  }
  // Recent context, excluding the intent declaration itself.
  for (const receipt of input.receipts.slice(-RECENT_RECEIPTS)) {
    if (receipt.seq !== input.intent?.receipt_seq) referenced.add(receipt.seq);
  }

  const evidence = [...referenced]
    .sort((a, b) => a - b)
    .flatMap((seq) => {
      const receipt = input.receipts.find((r) => r.seq === seq);
      if (receipt === undefined) return [];
      return [
        {
          receipt_seq: receipt.seq,
          tool: receipt.tool,
          upstream: receipt.upstream,
          excerpt: excerpt(receipt.result),
        },
      ];
    });

  const packet: VerificationPacket = {
    v: 1,
    tool: input.tool,
    args: input.args,
    tool_description: input.toolDef?.description,
    tool_input_schema: input.toolDef?.inputSchema,
    tool_annotations: input.toolDef?.annotations,
    declared_intent: input.intent,
    provenance: Object.fromEntries(
      Object.entries(input.provenance).map(([param, origins]) => [
        param,
        origins.map((o) => ({
          upstream: o.upstream,
          tool: o.tool,
          trust: o.trust,
          receipt_seq: o.receipt_seq,
        })),
      ]),
    ),
    evidence,
  };
  return { packet, packetHash: canonicalHash(JSON.parse(JSON.stringify(packet))) };
}

function excerpt(result: unknown): string {
  let text: string;
  try {
    text = JSON.stringify(result) ?? String(result);
  } catch {
    text = String(result);
  }
  if (text.length <= MAX_EXCERPT_CHARS) return text;
  return `${text.slice(0, MAX_EXCERPT_CHARS)}… [truncated ${text.length - MAX_EXCERPT_CHARS} chars]`;
}
