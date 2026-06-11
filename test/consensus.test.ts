import { describe, expect, it } from 'vitest';

import { runPanel } from '../src/consensus/panel.js';
import type { Verdict, VerificationPacket } from '../src/consensus/types.js';
import { VerdictParseError, parseVerdict, type VerifierClient } from '../src/consensus/verifier.js';

const PACKET: VerificationPacket = {
  v: 1,
  tool: 'payments__send_payment',
  args: { recipient: '0xAAAA', amount: 12_500 },
  declared_intent: { goal: 'pay the Acme invoice', receipt_seq: 1, ts: 'now' },
  provenance: {},
  evidence: [],
};

const passVerdict: Verdict = {
  verdict: 'pass',
  confidence: 0.9,
  reasons: [],
  evidence_refs: [],
  suspected_injection: false,
};
const failVerdict: Verdict = { ...passVerdict, verdict: 'fail', reasons: ['ungrounded amount'] };

function verifier(id: string, behavior: 'pass' | 'fail' | 'hang' | 'malformed'): VerifierClient {
  return {
    id,
    verify: () => {
      switch (behavior) {
        case 'pass':
          return Promise.resolve(passVerdict);
        case 'fail':
          return Promise.resolve(failVerdict);
        case 'hang':
          return new Promise<Verdict>(() => undefined); // never settles
        case 'malformed':
          return Promise.reject(new VerdictParseError('response is not a JSON object'));
      }
    },
  };
}

const options = {
  checks: ['intent_match' as const],
  quorum: 'unanimous' as const,
  failMode: 'closed' as const,
  timeoutMs: 200,
};

describe('parseVerdict', () => {
  it('parses a strict JSON verdict', () => {
    const v = parseVerdict(
      '{"verdict":"pass","confidence":0.8,"reasons":["ok"],"evidence_refs":["receipt:3"],"suspected_injection":false}',
    );
    expect(v.verdict).toBe('pass');
    expect(v.evidence_refs).toEqual(['receipt:3']);
  });

  it('applies schema defaults for optional arrays', () => {
    const v = parseVerdict('{"verdict":"fail","confidence":0.5}');
    expect(v.reasons).toEqual([]);
    expect(v.suspected_injection).toBe(false);
  });

  it('accepts a fenced JSON block (common provider tic)', () => {
    const v = parseVerdict('```json\n{"verdict":"pass","confidence":1}\n```');
    expect(v.verdict).toBe('pass');
  });

  it('rejects prose, malformed JSON, and schema violations', () => {
    expect(() => parseVerdict('I think this looks fine!')).toThrow(VerdictParseError);
    expect(() => parseVerdict('{"verdict":"pass"')).toThrow(VerdictParseError);
    expect(() => parseVerdict('{"verdict":"maybe","confidence":0.5}')).toThrow(VerdictParseError);
    expect(() => parseVerdict('{"verdict":"pass","confidence":1.5}')).toThrow(VerdictParseError);
    expect(() => parseVerdict('')).toThrow(VerdictParseError);
  });
});

describe('runPanel aggregation', () => {
  it('passes on unanimous pass', async () => {
    const result = await runPanel(
      [verifier('a/1', 'pass'), verifier('b/2', 'pass'), verifier('c/3', 'pass')],
      PACKET,
      'hash',
      options,
    );
    expect(result.decision).toBe('pass');
    expect(result.checks[0]?.passed).toBe(true);
    expect(result.checks[0]?.disagreement).toBe(false);
  });

  it('fails a unanimous quorum on a single dissent, and flags disagreement', async () => {
    const result = await runPanel(
      [verifier('a/1', 'pass'), verifier('b/2', 'pass'), verifier('c/3', 'fail')],
      PACKET,
      'hash',
      options,
    );
    expect(result.decision).toBe('fail');
    expect(result.checks[0]?.disagreement).toBe(true);
  });

  it('passes a split panel under majority quorum (disagreement still flagged)', async () => {
    const result = await runPanel(
      [verifier('a/1', 'pass'), verifier('b/2', 'pass'), verifier('c/3', 'fail')],
      PACKET,
      'hash',
      { ...options, quorum: 'majority' },
    );
    expect(result.decision).toBe('pass');
    expect(result.checks[0]?.disagreement).toBe(true);
  });

  it('fails majority when fails outnumber passes', async () => {
    const result = await runPanel(
      [verifier('a/1', 'pass'), verifier('b/2', 'fail'), verifier('c/3', 'fail')],
      PACKET,
      'hash',
      { ...options, quorum: 'majority' },
    );
    expect(result.decision).toBe('fail');
  });

  it('counts timeouts as failed verdicts under fail-closed', async () => {
    const result = await runPanel(
      [verifier('a/1', 'pass'), verifier('b/2', 'pass'), verifier('c/3', 'hang')],
      PACKET,
      'hash',
      { ...options, quorum: 'majority' },
    );
    // 2 pass vs 3 counted => 2*2 > 3, majority still passes...
    expect(result.checks[0]?.outcomes.find((o) => o.verifier === 'c/3')).toMatchObject({
      status: 'error',
      error: expect.stringContaining('timed out'),
    });
    expect(result.decision).toBe('pass');

    // ...but unanimous fails closed on the same timeout.
    const unanimous = await runPanel(
      [verifier('a/1', 'pass'), verifier('b/2', 'pass'), verifier('c/3', 'hang')],
      PACKET,
      'hash',
      options,
    );
    expect(unanimous.decision).toBe('fail');
  });

  it('counts malformed verdicts as failed under fail-closed', async () => {
    const result = await runPanel(
      [verifier('a/1', 'pass'), verifier('b/2', 'malformed')],
      PACKET,
      'hash',
      options,
    );
    expect(result.decision).toBe('fail');
    expect(result.checks[0]?.outcomes[1]?.error).toMatch(/verdict parse failed/);
  });

  it('fails closed when every verifier errors', async () => {
    const result = await runPanel(
      [verifier('a/1', 'hang'), verifier('b/2', 'malformed')],
      PACKET,
      'hash',
      { ...options, quorum: 'majority' },
    );
    expect(result.decision).toBe('fail');
  });

  it('under fail-open, errored verifiers abstain instead of blocking', async () => {
    const open = { ...options, failMode: 'open' as const };
    const result = await runPanel(
      [verifier('a/1', 'pass'), verifier('b/2', 'hang'), verifier('c/3', 'malformed')],
      PACKET,
      'hash',
      open,
    );
    expect(result.decision).toBe('pass');

    // Judgement still blocks under fail-open: a returned fail counts.
    const withDissent = await runPanel(
      [verifier('a/1', 'fail'), verifier('b/2', 'hang')],
      PACKET,
      'hash',
      open,
    );
    expect(withDissent.decision).toBe('fail');
  });

  it('runs every configured check and requires all to pass', async () => {
    const flaky: VerifierClient = {
      id: 'flaky/1',
      verify: ({ prompt }) =>
        Promise.resolve(prompt.check === 'bounds_and_sanity' ? failVerdict : passVerdict),
    };
    const result = await runPanel([flaky], PACKET, 'hash', {
      ...options,
      checks: ['intent_match', 'source_grounding', 'bounds_and_sanity'],
    });
    expect(result.decision).toBe('fail');
    expect(result.checks.map((c) => [c.check, c.passed])).toEqual([
      ['intent_match', true],
      ['source_grounding', true],
      ['bounds_and_sanity', false],
    ]);
    expect(result.checks.every((c) => c.prompt_version === 'v1')).toBe(true);
  });
});
