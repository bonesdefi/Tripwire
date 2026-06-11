import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { appendFileSync, readFileSync } from 'node:fs';

import { canonicalHash, canonicalize } from './canonical.js';

/**
 * Tier 0 — the receipt ledger.
 *
 * Every tool result that passes through the proxy is recorded here and signed
 * with HMAC-SHA256 over its canonical serialization. The key lives only in
 * the Tripwire process; the agent on the other side of the MCP boundary
 * cannot forge a receipt. The ledger is the ground truth of what actually
 * happened in a session.
 */

export interface Receipt {
  v: 1;
  session: string;
  seq: number;
  ts: string;
  tool: string;
  upstream: string;
  args: unknown;
  result: unknown;
  args_hash: string;
  result_hash: string;
  hmac: string;
}

export interface ReceiptVerification {
  ok: boolean;
  seq: number;
  error?: string;
}

const HMAC_ALGO = 'sha256';

/** The HMAC covers everything except the hmac field itself. */
function receiptMac(key: Buffer, receipt: Omit<Receipt, 'hmac'>): string {
  return createHmac(HMAC_ALGO, key).update(canonicalize(receipt), 'utf8').digest('hex');
}

function constantTimeEqualHex(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  if (ba.length !== bb.length || ba.length === 0) return false;
  return timingSafeEqual(ba, bb);
}

export function generateReceiptKey(): Buffer {
  return randomBytes(32);
}

export class ReceiptLedger {
  readonly sessionId: string;
  private readonly key: Buffer;
  private readonly persistPath: string | undefined;
  private readonly receipts: Receipt[] = [];
  private nextSeq = 1;

  constructor(options: { key: Buffer; sessionId: string; persistPath?: string }) {
    if (options.key.length < 16) {
      throw new Error('receipt HMAC key must be at least 16 bytes');
    }
    this.key = options.key;
    this.sessionId = options.sessionId;
    this.persistPath = options.persistPath;
  }

  /** Record and sign a tool execution. Called for every result the proxy forwards. */
  record(input: { tool: string; upstream: string; args: unknown; result: unknown }): Receipt {
    const unsigned: Omit<Receipt, 'hmac'> = {
      v: 1,
      session: this.sessionId,
      seq: this.nextSeq++,
      ts: new Date().toISOString(),
      tool: input.tool,
      upstream: input.upstream,
      args: input.args,
      result: input.result,
      args_hash: canonicalHash(input.args),
      result_hash: canonicalHash(input.result),
    };
    const receipt: Receipt = { ...unsigned, hmac: receiptMac(this.key, unsigned) };
    this.receipts.push(receipt);
    if (this.persistPath !== undefined) {
      appendFileSync(this.persistPath, JSON.stringify(receipt) + '\n', { mode: 0o600 });
    }
    return receipt;
  }

  list(): readonly Receipt[] {
    return this.receipts;
  }

  get(seq: number): Receipt | undefined {
    return this.receipts.find((r) => r.seq === seq);
  }

  verify(receipt: Receipt): ReceiptVerification {
    return verifyReceipt(this.key, receipt);
  }

  verifyAll(): { ok: boolean; count: number; failures: ReceiptVerification[] } {
    const failures = this.receipts.map((r) => this.verify(r)).filter((v) => !v.ok);
    return { ok: failures.length === 0, count: this.receipts.length, failures };
  }
}

/** Verify a single receipt against the session key. */
export function verifyReceipt(key: Buffer, receipt: Receipt): ReceiptVerification {
  const { hmac, ...unsigned } = receipt;
  try {
    if (canonicalHash(receipt.args) !== receipt.args_hash) {
      return { ok: false, seq: receipt.seq, error: 'args_hash mismatch (args tampered)' };
    }
    if (canonicalHash(receipt.result) !== receipt.result_hash) {
      return { ok: false, seq: receipt.seq, error: 'result_hash mismatch (result tampered)' };
    }
    if (!constantTimeEqualHex(receiptMac(key, unsigned), hmac)) {
      return { ok: false, seq: receipt.seq, error: 'HMAC mismatch' };
    }
    return { ok: true, seq: receipt.seq };
  } catch (err) {
    return { ok: false, seq: receipt.seq, error: `unverifiable receipt: ${String(err)}` };
  }
}

/** Load a persisted receipts.jsonl and verify every line against the key. */
export function verifyReceiptFile(
  key: Buffer,
  path: string,
): { ok: boolean; count: number; failures: ReceiptVerification[] } {
  const lines = readFileSync(path, 'utf8')
    .split('\n')
    .filter((l) => l.trim() !== '');
  const failures: ReceiptVerification[] = [];
  let expectedSeq = 1;
  for (const [index, line] of lines.entries()) {
    let receipt: Receipt;
    try {
      receipt = JSON.parse(line) as Receipt;
    } catch {
      failures.push({ ok: false, seq: -1, error: `line ${index + 1}: invalid JSON` });
      continue;
    }
    if (receipt.seq !== expectedSeq) {
      failures.push({
        ok: false,
        seq: receipt.seq,
        error: `line ${index + 1}: expected seq ${expectedSeq}, got ${receipt.seq}`,
      });
    }
    expectedSeq = receipt.seq + 1;
    const verdict = verifyReceipt(key, receipt);
    if (!verdict.ok) failures.push(verdict);
  }
  return { ok: failures.length === 0, count: lines.length, failures };
}
