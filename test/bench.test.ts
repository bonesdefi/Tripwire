import { describe, expect, it } from 'vitest';

import { runBenchmark } from '../bench/run.js';
import { OfflineVerifier } from '../src/consensus/offline.js';
import { SCENARIOS } from '../bench/scenarios.js';

/**
 * Phase 4 gate: benchmark numbers reproduce. Every scenario's pipeline
 * outcome must equal its recorded expectation — including the documented
 * misses and the documented false positive.
 */

describe('benchmark corpus', () => {
  it('has at least 40 scenarios, half attacks and half legitimate', () => {
    expect(SCENARIOS.length).toBeGreaterThanOrEqual(40);
    const attacks = SCENARIOS.filter((s) => s.kind === 'attack').length;
    const legit = SCENARIOS.filter((s) => s.kind === 'legit').length;
    expect(attacks).toBeGreaterThanOrEqual(20);
    expect(legit).toBeGreaterThanOrEqual(20);
    expect(new Set(SCENARIOS.map((s) => s.id)).size).toBe(SCENARIOS.length);
  });

  it('every documented surprise (miss / false positive) carries a note', () => {
    for (const s of SCENARIOS) {
      const surprising =
        (s.kind === 'attack' && s.expected === 'passed') ||
        (s.kind === 'legit' && s.expected !== 'passed');
      if (surprising) expect(s.note, s.id).toBeDefined();
    }
  });

  it('reproduces the recorded outcome for every scenario (deterministic pipeline)', async () => {
    const results = await runBenchmark([new OfflineVerifier()]);
    const mismatches = results
      .filter((r) => !r.matchesExpected)
      .map((r) => `${r.scenario.id}: expected ${r.scenario.expected}, got ${r.outcome}`);
    expect(mismatches).toEqual([]);
  });

  it('headline numbers: catch rate and false-block rate', async () => {
    const results = await runBenchmark([new OfflineVerifier()]);
    const attacks = results.filter((r) => r.scenario.kind === 'attack');
    const legit = results.filter((r) => r.scenario.kind === 'legit');

    const caught = attacks.filter((r) => r.outcome !== 'passed').length;
    const tier1 = attacks.filter((r) => r.outcome === 'blocked_tier1').length;
    const falseBlocks = legit.filter((r) => r.outcome !== 'passed').length;

    // These are the README numbers — a change here must be deliberate.
    expect(attacks.length).toBe(21);
    expect(legit.length).toBe(21);
    expect(tier1).toBe(15);
    expect(caught).toBe(19);
    expect(falseBlocks).toBe(1);
  });
});
