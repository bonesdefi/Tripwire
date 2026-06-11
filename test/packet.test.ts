import { describe, expect, it } from 'vitest';

import { buildPacket } from '../src/consensus/packet.js';
import { ReceiptLedger, generateReceiptKey } from '../src/receipts/ledger.js';

function ledgerWithReceipts(): ReceiptLedger {
  const ledger = new ReceiptLedger({ key: generateReceiptKey(), sessionId: 's' });
  ledger.record({
    tool: 'tripwire__declare_intent',
    upstream: 'tripwire',
    args: { goal: 'pay the Acme invoice' },
    result: { status: 'intent_recorded' },
  }); // seq 1
  ledger.record({
    tool: 'docs__read_document',
    upstream: 'docs',
    args: { id: 'invoice-acme-7741' },
    result: { content: [{ type: 'text', text: 'Amount due: 12,500 USDC' }] },
  }); // seq 2
  ledger.record({
    tool: 'vendors__get_vendor',
    upstream: 'vendors',
    args: { vendor: 'acme-corp' },
    result: { content: [{ type: 'text', text: '{"wallet":"0xAAAA"}' }] },
  }); // seq 3
  return ledger;
}

describe('buildPacket', () => {
  it('assembles intent, provenance, and referenced evidence excerpts', () => {
    const ledger = ledgerWithReceipts();
    const { packet, packetHash } = buildPacket({
      tool: 'payments__send_payment',
      args: { recipient: '0xAAAA', amount: 12_500 },
      intent: { goal: 'pay the Acme invoice', receipt_seq: 1, ts: 'now' },
      provenance: {
        recipient: [
          { upstream: 'vendors', trust: 'trusted', tool: 'vendors__get_vendor', receipt_seq: 3 },
        ],
        amount: [
          { upstream: 'docs', trust: 'untrusted', tool: 'docs__read_document', receipt_seq: 2 },
        ],
      },
      receipts: ledger.list(),
    });

    expect(packet.declared_intent?.goal).toBe('pay the Acme invoice');
    expect(packet.provenance.recipient?.[0]).toMatchObject({ trust: 'trusted', receipt_seq: 3 });

    const seqs = packet.evidence.map((e) => e.receipt_seq);
    expect(seqs).toContain(2);
    expect(seqs).toContain(3);
    // The intent declaration itself is not evidence.
    expect(seqs).not.toContain(1);
    expect(packet.evidence.find((e) => e.receipt_seq === 2)?.excerpt).toContain('12,500');
    expect(packetHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('produces a stable hash for identical inputs', () => {
    const ledger = ledgerWithReceipts();
    const input = {
      tool: 'payments__send_payment',
      args: { recipient: '0xAAAA' },
      intent: null,
      provenance: {},
      receipts: ledger.list(),
    };
    expect(buildPacket(input).packetHash).toBe(buildPacket(input).packetHash);
  });

  it('truncates oversized evidence excerpts', () => {
    const ledger = new ReceiptLedger({ key: generateReceiptKey(), sessionId: 's' });
    ledger.record({
      tool: 'docs__read_document',
      upstream: 'docs',
      args: {},
      result: { text: 'x'.repeat(10_000) },
    });
    const { packet } = buildPacket({
      tool: 'payments__send_payment',
      args: {},
      intent: null,
      provenance: {},
      receipts: ledger.list(),
    });
    const excerpt = packet.evidence[0]?.excerpt ?? '';
    expect(excerpt.length).toBeLessThan(2_100);
    expect(excerpt).toContain('[truncated');
  });
});
