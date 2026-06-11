#!/usr/bin/env node
import { runPanel } from '../src/consensus/panel.js';
import { OfflineVerifier } from '../src/consensus/offline.js';
import { buildPacket } from '../src/consensus/packet.js';
import { defaultVerifierFactory } from '../src/consensus/providers.js';
import type { VerifierClient } from '../src/consensus/verifier.js';
import { ProvenanceIndex, indexExecution } from '../src/provenance/index.js';
import { evaluateTier1 } from '../src/provenance/tier1.js';
import { ReceiptLedger, generateReceiptKey } from '../src/receipts/ledger.js';
import { SCENARIOS, type BenchScenario, type ExpectedOutcome } from './scenarios.js';

/**
 * Benchmark harness: replays each scripted session through the verification
 * pipeline (Tier 1 provenance, then the Tier 2 panel) and reports catch
 * rate and false-block rate per tier.
 *
 * Deterministic by default: Tier 2 uses the offline reference verifier so
 * the numbers reproduce from a clean clone with zero API keys. Run with
 * `--live` (and provider keys in env) to use a real multi-provider panel.
 */

const DEFAULT_SENSITIVE = {
  recipient: { provenance: 'trusted' as const },
  amount: { provenance: 'any' as const },
};

export interface ScenarioResult {
  scenario: BenchScenario;
  outcome: ExpectedOutcome;
  matchesExpected: boolean;
}

export async function runScenario(
  scenario: BenchScenario,
  panel: VerifierClient[],
  timeoutMs = 30_000,
): Promise<ExpectedOutcome> {
  const ledger = new ReceiptLedger({ key: generateReceiptKey(), sessionId: scenario.id });
  const index = new ProvenanceIndex();

  let intent: { goal: string; receipt_seq: number; ts: string } | null = null;
  if (scenario.goal !== null) {
    const receipt = ledger.record({
      tool: 'tripwire__declare_intent',
      upstream: 'tripwire',
      args: { goal: scenario.goal },
      result: { status: 'intent_recorded' },
    });
    intent = { goal: scenario.goal, receipt_seq: receipt.seq, ts: receipt.ts };
  }

  for (const step of scenario.history) {
    const receipt = ledger.record({
      tool: step.tool,
      upstream: step.upstream,
      args: step.args,
      result: step.result,
    });
    indexExecution(
      index,
      { upstream: step.upstream, trust: step.trust, tool: step.tool, receipt_seq: receipt.seq },
      step.args,
      step.result,
    );
  }

  const tier1 = evaluateTier1(scenario.sensitive ?? DEFAULT_SENSITIVE, scenario.call.args, index);
  if (!tier1.ok) return 'blocked_tier1';

  const { packet, packetHash } = buildPacket({
    tool: scenario.call.tool,
    args: scenario.call.args,
    intent,
    provenance: tier1.annotations,
    receipts: ledger.list(),
  });
  const consensus = await runPanel(panel, packet, packetHash, {
    checks: ['intent_match', 'source_grounding', 'bounds_and_sanity'],
    quorum: panel.length > 1 ? 'majority' : 'unanimous',
    failMode: 'closed',
    timeoutMs,
  });
  return consensus.decision === 'fail' ? 'blocked_tier2' : 'passed';
}

export async function runBenchmark(panel: VerifierClient[]): Promise<ScenarioResult[]> {
  const results: ScenarioResult[] = [];
  for (const scenario of SCENARIOS) {
    const outcome = await runScenario(scenario, panel);
    results.push({ scenario, outcome, matchesExpected: outcome === scenario.expected });
  }
  return results;
}

function pct(n: number, d: number): string {
  return d === 0 ? 'n/a' : `${((100 * n) / d).toFixed(1)}%`;
}

async function main(): Promise<void> {
  const live = process.argv.includes('--live');
  const panel: VerifierClient[] = live
    ? ['anthropic/claude-sonnet-4-6', 'openai/gpt-5.1', 'google/gemini-2.5-pro'].map((id) =>
        defaultVerifierFactory(id),
      )
    : [new OfflineVerifier()];

  console.log(
    live
      ? 'mode: LIVE (real verifier panel — results may vary with model judgement)'
      : 'mode: offline deterministic (reference verifier; reproducible, zero API calls)',
  );
  const results = await runBenchmark(panel);

  const attacks = results.filter((r) => r.scenario.kind === 'attack');
  const legit = results.filter((r) => r.scenario.kind === 'legit');
  const caughtT1 = attacks.filter((r) => r.outcome === 'blocked_tier1');
  const caughtT2 = attacks.filter((r) => r.outcome === 'blocked_tier2');
  const missed = attacks.filter((r) => r.outcome === 'passed');
  const falseBlocks = legit.filter((r) => r.outcome !== 'passed');

  console.log('\n┌────────────────────────────────┬─────────┐');
  console.log(`│ attack scenarios               │ ${String(attacks.length).padStart(7)} │`);
  console.log(`│   caught by Tier 1 (structural)│ ${String(caughtT1.length).padStart(7)} │`);
  console.log(`│   caught by Tier 2 (consensus) │ ${String(caughtT2.length).padStart(7)} │`);
  console.log(`│   missed                       │ ${String(missed.length).padStart(7)} │`);
  console.log(
    `│   catch rate                   │ ${pct(caughtT1.length + caughtT2.length, attacks.length).padStart(7)} │`,
  );
  console.log('├────────────────────────────────┼─────────┤');
  console.log(`│ legitimate scenarios           │ ${String(legit.length).padStart(7)} │`);
  console.log(`│   false blocks                 │ ${String(falseBlocks.length).padStart(7)} │`);
  console.log(
    `│   false-block rate             │ ${pct(falseBlocks.length, legit.length).padStart(7)} │`,
  );
  console.log('└────────────────────────────────┴─────────┘');

  for (const r of missed) {
    console.log(`\nMISSED  ${r.scenario.id}: ${r.scenario.note ?? r.scenario.description}`);
  }
  for (const r of falseBlocks) {
    console.log(`\nFALSE BLOCK  ${r.scenario.id}: ${r.scenario.note ?? r.scenario.description}`);
  }

  const surprises = results.filter((r) => !r.matchesExpected);
  if (surprises.length > 0) {
    console.log('\nOutcomes differing from the recorded expectations:');
    for (const r of surprises) {
      console.log(`  ${r.scenario.id}: expected ${r.scenario.expected}, got ${r.outcome}`);
    }
    if (!live) process.exitCode = 1; // offline mode must reproduce exactly
  } else {
    console.log('\nAll outcomes match the recorded expectations.');
  }
}

const isMain = process.argv[1]?.endsWith('run.ts') || process.argv[1]?.endsWith('run.js');
if (isMain) {
  main().catch((err: unknown) => {
    console.error(err);
    process.exit(1);
  });
}
