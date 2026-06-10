import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  ReceiptLedger,
  generateReceiptKey,
  verifyReceipt,
  verifyReceiptFile,
  type Receipt,
} from '../src/receipts/ledger.js';

describe('ReceiptLedger', () => {
  let dir: string;
  let key: Buffer;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tripwire-ledger-'));
    key = generateReceiptKey();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const makeLedger = (persist = false) =>
    new ReceiptLedger({
      key,
      sessionId: 'test-session',
      ...(persist ? { persistPath: join(dir, 'receipts.jsonl') } : {}),
    });

  it('records receipts with monotonically increasing sequence numbers', () => {
    const ledger = makeLedger();
    const r1 = ledger.record({ tool: 'a__t', upstream: 'a', args: { x: 1 }, result: { ok: 1 } });
    const r2 = ledger.record({ tool: 'a__t', upstream: 'a', args: { x: 2 }, result: { ok: 2 } });
    expect(r1.seq).toBe(1);
    expect(r2.seq).toBe(2);
    expect(ledger.list()).toHaveLength(2);
    expect(ledger.get(2)).toBe(r2);
  });

  it('produces receipts that verify with the session key', () => {
    const ledger = makeLedger();
    const receipt = ledger.record({
      tool: 'payments__send_payment',
      upstream: 'payments',
      args: { recipient: '0xAAAA', amount: 12_500 },
      result: { content: [{ type: 'text', text: 'ok' }] },
    });
    expect(ledger.verify(receipt)).toEqual({ ok: true, seq: 1 });
    expect(ledger.verifyAll()).toEqual({ ok: true, count: 1, failures: [] });
  });

  it('detects tampered args, result, and metadata', () => {
    const ledger = makeLedger();
    const receipt = ledger.record({
      tool: 't__x',
      upstream: 't',
      args: { amount: 100 },
      result: { paid: 100 },
    });

    const tamperedArgs = { ...receipt, args: { amount: 100_000 } } as Receipt;
    expect(ledger.verify(tamperedArgs).ok).toBe(false);
    expect(ledger.verify(tamperedArgs).error).toMatch(/args_hash/);

    const tamperedResult = { ...receipt, result: { paid: 1 } } as Receipt;
    expect(ledger.verify(tamperedResult).ok).toBe(false);

    const tamperedSeq = { ...receipt, seq: 99 } as Receipt;
    expect(ledger.verify(tamperedSeq).ok).toBe(false);
    expect(ledger.verify(tamperedSeq).error).toMatch(/HMAC/);

    const tamperedTool = { ...receipt, tool: 't__other' } as Receipt;
    expect(ledger.verify(tamperedTool).ok).toBe(false);

    const tamperedTs = { ...receipt, ts: '2020-01-01T00:00:00.000Z' } as Receipt;
    expect(ledger.verify(tamperedTs).ok).toBe(false);
  });

  it('rejects receipts signed with a different key', () => {
    const ledger = makeLedger();
    const receipt = ledger.record({ tool: 't__x', upstream: 't', args: {}, result: {} });
    const wrongKey = generateReceiptKey();
    expect(verifyReceipt(wrongKey, receipt).ok).toBe(false);
  });

  it('rejects forged hmac values without throwing', () => {
    const ledger = makeLedger();
    const receipt = ledger.record({ tool: 't__x', upstream: 't', args: {}, result: {} });
    expect(verifyReceipt(key, { ...receipt, hmac: 'zz-not-hex' }).ok).toBe(false);
    expect(verifyReceipt(key, { ...receipt, hmac: '' }).ok).toBe(false);
    expect(verifyReceipt(key, { ...receipt, hmac: 'aa' }).ok).toBe(false);
  });

  it('refuses weak keys', () => {
    expect(() => new ReceiptLedger({ key: Buffer.from('short'), sessionId: 's' })).toThrow(
      /at least 16 bytes/,
    );
  });

  it('persists to JSONL and verifies from file', () => {
    const ledger = makeLedger(true);
    ledger.record({ tool: 'a__one', upstream: 'a', args: { q: 'x' }, result: { v: 1 } });
    ledger.record({ tool: 'b__two', upstream: 'b', args: {}, result: { v: 2 } });

    const path = join(dir, 'receipts.jsonl');
    const lines = readFileSync(path, 'utf8').trim().split('\n');
    expect(lines).toHaveLength(2);

    const verdict = verifyReceiptFile(key, path);
    expect(verdict).toEqual({ ok: true, count: 2, failures: [] });
  });

  it('fails file verification on tampering, reordering, or gaps', () => {
    const ledger = makeLedger(true);
    ledger.record({ tool: 'a__one', upstream: 'a', args: {}, result: { v: 1 } });
    ledger.record({ tool: 'a__one', upstream: 'a', args: {}, result: { v: 2 } });
    const path = join(dir, 'receipts.jsonl');
    const lines = readFileSync(path, 'utf8').trim().split('\n');

    // Tamper a value in line 1.
    writeFileSync(path, [lines[0]!.replace('"v":1', '"v":9'), lines[1]].join('\n') + '\n');
    expect(verifyReceiptFile(key, path).ok).toBe(false);

    // Reorder.
    writeFileSync(path, [lines[1], lines[0]].join('\n') + '\n');
    expect(verifyReceiptFile(key, path).ok).toBe(false);

    // Drop the first receipt (gap in seq).
    writeFileSync(path, lines[1] + '\n');
    expect(verifyReceiptFile(key, path).ok).toBe(false);

    // Untouched file still verifies.
    writeFileSync(path, lines.join('\n') + '\n');
    expect(verifyReceiptFile(key, path).ok).toBe(true);
  });
});
