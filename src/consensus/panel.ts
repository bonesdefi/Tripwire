import { CHECK_PROMPTS } from './prompts/index.js';
import type {
  CheckName,
  CheckOutcome,
  ConsensusResult,
  Verdict,
  VerificationPacket,
  VerifierOutcome,
} from './types.js';
import type { VerifierClient } from './verifier.js';

/**
 * Tier 2 — run the verifier panel and aggregate verdicts.
 *
 * Every verifier runs every check in parallel; verifiers never see each
 * other's outputs. Timeouts are enforced here, independent of client
 * behavior. Aggregation semantics:
 *
 * - fail_mode `closed` (mandatory for money paths): an errored, timed-out,
 *   or malformed verdict counts as FAIL.
 * - fail_mode `open`: errored verifiers are excluded; only returned
 *   verdicts vote. (Verifier *availability* stops being able to block,
 *   verifier *judgement* still can.)
 * - quorum `unanimous`: every counted verdict must pass.
 * - quorum `majority`: strictly more than half of counted verdicts pass.
 * - The call passes only if every check passes. Disagreement among returned
 *   verdicts is flagged per check — it is signal, not noise.
 */

export interface PanelOptions {
  checks: CheckName[];
  quorum: 'majority' | 'unanimous';
  failMode: 'closed' | 'open';
  timeoutMs: number;
}

const TIMEOUT = Symbol('timeout');

async function withTimeout(promise: Promise<Verdict>, ms: number): Promise<Verdict> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<typeof TIMEOUT>((resolve) => {
    timer = setTimeout(() => resolve(TIMEOUT), ms);
    timer.unref?.();
  });
  try {
    const result = await Promise.race([promise, timeout]);
    if (result === TIMEOUT) throw new Error(`verifier timed out after ${ms}ms`);
    return result;
  } finally {
    clearTimeout(timer);
  }
}

export async function runPanel(
  verifiers: VerifierClient[],
  packet: VerificationPacket,
  packetHash: string,
  options: PanelOptions,
): Promise<ConsensusResult> {
  const startedAt = Date.now();

  const checks = await Promise.all(
    options.checks.map(async (check): Promise<CheckOutcome> => {
      const prompt = CHECK_PROMPTS[check];
      const outcomes = await Promise.all(
        verifiers.map(async (verifier): Promise<VerifierOutcome> => {
          const verifierStart = Date.now();
          try {
            const verdict = await withTimeout(
              verifier.verify({ packet, prompt, timeoutMs: options.timeoutMs }),
              options.timeoutMs,
            );
            return {
              verifier: verifier.id,
              status: 'ok',
              verdict,
              latency_ms: Date.now() - verifierStart,
            };
          } catch (err) {
            return {
              verifier: verifier.id,
              status: 'error',
              error: err instanceof Error ? err.message : String(err),
              latency_ms: Date.now() - verifierStart,
            };
          }
        }),
      );
      return {
        check,
        prompt_version: prompt.version,
        ...aggregate(outcomes, options),
        outcomes,
      };
    }),
  );

  return {
    decision: checks.every((c) => c.passed) ? 'pass' : 'fail',
    checks,
    packet_hash: packetHash,
    latency_ms: Date.now() - startedAt,
  };
}

function aggregate(
  outcomes: VerifierOutcome[],
  options: Pick<PanelOptions, 'quorum' | 'failMode'>,
): { passed: boolean; disagreement: boolean } {
  const returned = outcomes.filter((o) => o.status === 'ok');
  const passes = returned.filter((o) => o.verdict?.verdict === 'pass').length;
  const fails = returned.length - passes;
  const disagreement = passes > 0 && fails > 0;

  // Counted votes: under fail-closed, errors vote fail; under fail-open,
  // errors abstain (and an all-error panel cannot block).
  const total = options.failMode === 'closed' ? outcomes.length : returned.length;
  if (total === 0) return { passed: options.failMode === 'open', disagreement };

  const passed = options.quorum === 'unanimous' ? passes === total : passes * 2 > total;
  return { passed, disagreement };
}
