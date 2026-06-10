import type { CallToolResult, Tool } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

/**
 * Intent capture — the honest v1 mechanism (TRIPWIRE_PLAN.md §4.3).
 *
 * Tripwire injects one synthetic tool into the merged tool list. The agent
 * declares its goal before consequential actions; the declaration is
 * receipted like any other tool execution and becomes the `intent_match`
 * reference for Tier 2.
 *
 * Known limitation, by design: a fully compromised agent can declare a
 * malicious intent. But then the intent itself is on the unforgeable audit
 * record, Tier 1 still constrains where parameter values may come from, and
 * source_grounding still requires evidence. Defense in depth, not a silver
 * bullet.
 */

export const INTENT_TOOL_NAME = 'tripwire__declare_intent';

export const IntentArgsSchema = z.object({
  goal: z.string().min(1, 'goal must not be empty').max(2_000),
  plan_summary: z.string().max(4_000).optional(),
});

export type IntentArgs = z.infer<typeof IntentArgsSchema>;

export interface DeclaredIntentRecord {
  goal: string;
  plan_summary?: string | undefined;
  receipt_seq: number;
  ts: string;
}

export const INTENT_TOOL: Tool = {
  name: INTENT_TOOL_NAME,
  description:
    'Declare your current goal before taking consequential actions ' +
    '(payments, writes, sends, deletions). Call this with the goal exactly ' +
    'as the user stated it, plus a short plan summary. Verification policy ' +
    'may refuse consequential tool calls until an intent is on file, and ' +
    'your subsequent actions are checked for consistency against it.',
  inputSchema: {
    type: 'object',
    properties: {
      goal: {
        type: 'string',
        description: "The user's goal, as stated by the user",
      },
      plan_summary: {
        type: 'string',
        description: 'Short summary of the steps you plan to take',
      },
    },
    required: ['goal'],
  },
  annotations: { readOnlyHint: true, title: 'Declare intent (Tripwire)' },
};

export function intentAck(receiptSeq: number): CallToolResult {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify({
          status: 'intent_recorded',
          receipt_seq: receiptSeq,
          note: 'Subsequent consequential calls will be verified against this intent.',
        }),
      },
    ],
  };
}

export function invalidIntent(message: string): CallToolResult {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify({ status: 'invalid_intent', error: message }),
      },
    ],
    isError: true,
  };
}
