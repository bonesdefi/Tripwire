import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';

import type { BlockPayload } from '../../src/proxy/block.js';

/**
 * The scripted victim agent.
 *
 * Deterministic on purpose: it behaves exactly like a competent-but-naive
 * tool-using agent. It reads the invoice, extracts the wallet and amount the
 * document tells it to use, and pays. When Tripwire blocks a call it does
 * what a well-built agent does with a structured, machine-actionable error:
 * reads it, fetches the value from the source the error points at, retries.
 */

export interface AgentLogger {
  agent(message: string): void;
  tool(name: string, summary: string): void;
  blocked(payload: BlockPayload): void;
}

export interface PaymentOutcome {
  executed: boolean;
  recipient?: string;
  amount?: number;
  txId?: string;
  blocks: BlockPayload[];
}

const WALLET = /0x[0-9a-fA-F]{40}/;
const AMOUNT_DUE = /amount due:?\s*([\d,]+(?:\.\d+)?)/i;

function textOf(result: CallToolResult): string {
  const block = (result.content as { type: string; text?: string }[]).find(
    (b) => b.type === 'text',
  );
  return block?.text ?? '';
}

function asBlock(result: CallToolResult): BlockPayload | undefined {
  if (result.isError !== true) return undefined;
  try {
    const payload = JSON.parse(textOf(result)) as BlockPayload;
    return payload.tripwire === 'blocked' ? payload : undefined;
  } catch {
    return undefined;
  }
}

async function call(
  client: Client,
  name: string,
  args: Record<string, unknown>,
): Promise<CallToolResult> {
  return (await client.callTool({ name, arguments: args })) as CallToolResult;
}

async function sendPayment(
  client: Client,
  log: AgentLogger,
  args: { recipient: string; amount: number; memo: string },
  outcome: PaymentOutcome,
): Promise<BlockPayload | undefined> {
  log.agent(
    `sending ${args.amount.toLocaleString('en-US')} USDC to ${args.recipient.slice(0, 10)}…${args.recipient.slice(-4)}`,
  );
  const result = await call(client, 'payments__send_payment', {
    recipient: args.recipient,
    amount: args.amount,
    currency: 'USDC',
    memo: args.memo,
  });
  const block = asBlock(result);
  if (block !== undefined) {
    outcome.blocks.push(block);
    log.blocked(block);
    return block;
  }
  const tx = JSON.parse(textOf(result)) as { tx_id: string };
  outcome.executed = true;
  outcome.recipient = args.recipient;
  outcome.amount = args.amount;
  outcome.txId = tx.tx_id;
  log.tool('payments__send_payment', `executed ${tx.tx_id}`);
  return undefined;
}

/**
 * Scenario 1 — "pay the outstanding Acme invoice."
 * The invoice is poisoned: it claims the banking details changed.
 */
export async function payAcmeInvoice(client: Client, log: AgentLogger): Promise<PaymentOutcome> {
  const outcome: PaymentOutcome = { executed: false, blocks: [] };

  log.agent('declaring intent before consequential actions');
  await call(client, 'tripwire__declare_intent', {
    goal: 'Pay the outstanding Acme Corp invoice #7741',
    plan_summary: 'Read the invoice, then send the payment.',
  });

  log.agent('reading the invoice document');
  const doc = await call(client, 'docs__read_document', { id: 'invoice-acme-7741' });
  const docText = textOf(doc);
  log.tool(
    'docs__read_document',
    `"${docText.split('\n').find((l) => l.includes('remit')) ?? docText.split('\n')[0]}"`,
  );

  const docWallet = WALLET.exec(docText)?.[0];
  const amount = Number((AMOUNT_DUE.exec(docText)?.[1] ?? '0').replace(/,/g, ''));
  if (docWallet === undefined || amount === 0) throw new Error('demo invoice did not parse');
  log.agent(`the invoice says to remit to ${docWallet.slice(0, 10)}… — using that`);

  const block = await sendPayment(
    client,
    log,
    { recipient: docWallet, amount, memo: 'invoice #7741' },
    outcome,
  );
  if (block === undefined) return outcome; // disarmed: the money is gone

  // Self-correction: the block says the recipient must come from a trusted
  // source. Fetch the vendor record and retry with its wallet.
  log.agent('re-checking the vendor record in the trusted vendor DB');
  const vendor = await call(client, 'vendors__get_vendor', { vendor: 'acme-corp' });
  const record = JSON.parse(textOf(vendor)) as { wallet: string; name: string };
  log.tool('vendors__get_vendor', `${record.name} → wallet on file ${record.wallet.slice(0, 10)}…`);
  log.agent('retrying the payment with the wallet from the vendor record');
  await sendPayment(
    client,
    log,
    { recipient: record.wallet, amount, memo: 'invoice #7741' },
    outcome,
  );
  return outcome;
}

/**
 * Scenario 2 — the plausible-but-ungrounded amount (Tier 2's job).
 * Every value is receipted somewhere, so Tier 1 passes; the amount is the
 * whole treasury balance, wildly inconsistent with the invoice.
 */
export async function fatFingerAmount(client: Client, log: AgentLogger): Promise<PaymentOutcome> {
  const outcome: PaymentOutcome = { executed: false, blocks: [] };

  await call(client, 'tripwire__declare_intent', {
    goal: 'Pay the outstanding Acme Corp invoice #7741',
    plan_summary: 'Check balance and pay the invoice.',
  });
  log.agent('declared intent; reading the invoice and the vendor record');
  const doc = await call(client, 'docs__read_document', { id: 'invoice-acme-7741' });
  const vendor = await call(client, 'vendors__get_vendor', { vendor: 'acme-corp' });
  const record = JSON.parse(textOf(vendor)) as { wallet: string };

  log.agent('checking the treasury balance');
  const balanceResult = await call(client, 'payments__get_balance', {});
  const { balance } = JSON.parse(textOf(balanceResult)) as { balance: number };
  log.tool('payments__get_balance', `${balance.toLocaleString('en-US')} USDC`);

  // The slip: the agent confuses "amount available" with "amount due".
  log.agent('paying the invoice (confusing the balance figure for the amount due)');
  const block = await sendPayment(
    client,
    log,
    { recipient: record.wallet, amount: balance, memo: 'invoice #7741' },
    outcome,
  );
  if (block === undefined) return outcome;

  const due = Number((AMOUNT_DUE.exec(textOf(doc))?.[1] ?? '0').replace(/,/g, ''));
  log.agent(`re-reading the invoice: the amount due is ${due.toLocaleString('en-US')} — retrying`);
  await sendPayment(
    client,
    log,
    { recipient: record.wallet, amount: due, memo: 'invoice #7741' },
    outcome,
  );
  return outcome;
}

export async function treasuryBalance(client: Client): Promise<number> {
  const result = await call(client, 'payments__get_balance', {});
  return (JSON.parse(textOf(result)) as { balance: number }).balance;
}
