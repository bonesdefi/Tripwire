import { z } from 'zod';

/**
 * Tier 2 — shared types.
 *
 * Verifiers must return strict JSON conforming to `VerdictSchema`; anything
 * else is treated as a failed verdict under fail-closed aggregation.
 */

export type CheckName = 'intent_match' | 'source_grounding' | 'bounds_and_sanity';

export const VerdictSchema = z.object({
  verdict: z.enum(['pass', 'fail']),
  confidence: z.number().min(0).max(1),
  reasons: z.array(z.string()).default([]),
  evidence_refs: z.array(z.string()).default([]),
  suspected_injection: z.boolean().default(false),
});

export type Verdict = z.infer<typeof VerdictSchema>;

/** A versioned verifier prompt template for one check. */
export interface CheckPrompt {
  check: CheckName;
  version: string;
  system: string;
}

export interface VerificationPacket {
  v: 1;
  /** Namespaced tool name of the proposed call. */
  tool: string;
  /** Full proposed parameters. */
  args: Record<string, unknown>;
  tool_description?: string | undefined;
  tool_input_schema?: unknown;
  tool_annotations?: unknown;
  /** The agent's declared intent, receipted, or null if none on file. */
  declared_intent: {
    goal: string;
    plan_summary?: string | undefined;
    receipt_seq: number;
    ts: string;
  } | null;
  /** Tier 1 provenance annotations: param -> origins. */
  provenance: Record<
    string,
    { upstream: string; tool: string; trust: string; receipt_seq: number }[]
  >;
  /** Receipted evidence excerpts relevant to the parameters. */
  evidence: {
    receipt_seq: number;
    tool: string;
    upstream: string;
    excerpt: string;
  }[];
}

export interface VerifierOutcome {
  verifier: string;
  status: 'ok' | 'error';
  verdict?: Verdict;
  error?: string;
  latency_ms: number;
}

export interface CheckOutcome {
  check: CheckName;
  prompt_version: string;
  passed: boolean;
  /** ok verdicts disagreed with each other — a signal in itself. */
  disagreement: boolean;
  outcomes: VerifierOutcome[];
}

export interface ConsensusResult {
  decision: 'pass' | 'fail';
  checks: CheckOutcome[];
  packet_hash: string;
  latency_ms: number;
}
