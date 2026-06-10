import { describe, expect, it } from 'vitest';

import { findRule, globToRegExp, matchesRule } from '../src/policy/match.js';

describe('globToRegExp', () => {
  const cases: [glob: string, value: string, expected: boolean][] = [
    // exact
    ['payments__send_payment', 'payments__send_payment', true],
    ['payments__send_payment', 'payments__send_payments', false],
    ['payments__send_payment', 'xpayments__send_payment', false],
    // star
    ['*', 'anything_at_all', true],
    ['*', '', true],
    ['payments__*', 'payments__send_payment', true],
    ['payments__*', 'payments__', true],
    ['payments__*', 'vendors__get_vendor', false],
    ['*__send_payment', 'payments__send_payment', true],
    ['*send*', 'payments__send_payment', true],
    ['*send*', 'payments__get_balance', false],
    ['a*b*c', 'abc', true],
    ['a*b*c', 'axxbyyc', true],
    ['a*b*c', 'acb', false],
    // question mark
    ['tx_000?', 'tx_0001', true],
    ['tx_000?', 'tx_00012', false],
    ['?', 'a', true],
    ['?', '', false],
    // regex metacharacters are literal
    ['a.b', 'a.b', true],
    ['a.b', 'axb', false],
    ['a+b', 'a+b', true],
    ['a+b', 'aab', false],
    ['(x)|(y)', '(x)|(y)', true],
    ['(x)|(y)', 'x', false],
    ['a[1]', 'a[1]', true],
    ['a[1]', 'a1', false],
    ['a{2}', 'a{2}', true],
    ['a$^b', 'a$^b', true],
    ['back\\slash', 'back\\slash', true],
  ];

  it.each(cases)('glob %s vs %s -> %s', (glob, value, expected) => {
    expect(globToRegExp(glob).test(value)).toBe(expected);
  });
});

describe('matchesRule', () => {
  const ctx = {
    tool: 'payments__send_payment',
    upstream: 'payments',
    annotations: { destructiveHint: true, title: 'Send payment' },
  };

  it('matches on tool glob, upstream, and annotation subset', () => {
    expect(matchesRule({ tool: 'payments__*' }, ctx)).toBe(true);
    expect(matchesRule({ upstream: 'payments' }, ctx)).toBe(true);
    expect(matchesRule({ annotation: { destructiveHint: true } }, ctx)).toBe(true);
    expect(
      matchesRule(
        { tool: '*__send_payment', upstream: 'payments', annotation: { destructiveHint: true } },
        ctx,
      ),
    ).toBe(true);
  });

  it('requires every provided clause to match (AND semantics)', () => {
    expect(matchesRule({ tool: 'payments__*', upstream: 'vendors' }, ctx)).toBe(false);
    expect(matchesRule({ tool: 'vendors__*', upstream: 'payments' }, ctx)).toBe(false);
    expect(matchesRule({ tool: 'payments__*', annotation: { destructiveHint: false } }, ctx)).toBe(
      false,
    );
  });

  it('annotation match is strict equality per key, no truthiness coercion', () => {
    expect(matchesRule({ annotation: { destructiveHint: 'true' } }, ctx)).toBe(false);
    expect(matchesRule({ annotation: { title: 'Send payment' } }, ctx)).toBe(true);
    expect(matchesRule({ annotation: { missingKey: true } }, ctx)).toBe(false);
  });

  it('treats missing annotations as an empty set', () => {
    const bare = { tool: 'docs__read_document', upstream: 'docs' };
    expect(matchesRule({ annotation: { destructiveHint: true } }, bare)).toBe(false);
    expect(matchesRule({ tool: 'docs__*' }, bare)).toBe(true);
  });
});

describe('findRule', () => {
  it('returns the first matching rule (declaration order wins)', () => {
    const rules = [
      { match: { tool: 'payments__send_payment' }, id: 'specific' },
      { match: { tool: 'payments__*' }, id: 'broad' },
      { match: { annotation: { destructiveHint: true } as Record<string, boolean> }, id: 'annot' },
    ];
    const ctx = {
      tool: 'payments__send_payment',
      upstream: 'payments',
      annotations: { destructiveHint: true },
    };
    expect(findRule(rules, ctx)?.id).toBe('specific');
    expect(findRule(rules.slice(1), ctx)?.id).toBe('broad');
    expect(findRule(rules.slice(2), ctx)?.id).toBe('annot');
    expect(findRule(rules, { tool: 'vendors__get_vendor', upstream: 'vendors' })).toBeUndefined();
  });
});
