import type { Origin, ProvenanceIndex } from './index.js';

/**
 * Tier 1 enforcement: trace each sensitive parameter of a guarded call and
 * decide structurally whether it may proceed.
 *
 * - `provenance: trusted` — the value must have appeared in at least one
 *   trusted-tool result this session.
 * - `provenance: any` — the value must have appeared in *some* receipted
 *   tool result (blocks invented / carried-in values).
 *
 * No model is consulted. A violation here is a structural fact about the
 * session history, not a judgement call.
 */

export type ProvenanceRequirement = 'trusted' | 'any';

export type Tier1Reason =
  | 'untrusted_provenance' // value seen, but only in untrusted-tool results
  | 'unknown_provenance' // value never seen in any tool result this session
  | 'untraceable_param'; // param type cannot be traced (object/bool/null)

export interface Tier1Violation {
  param: string;
  reason: Tier1Reason;
  required: ProvenanceRequirement;
  value_preview: string;
  origins: Origin[];
}

export interface Tier1Result {
  ok: boolean;
  violations: Tier1Violation[];
  /** Origins for every traced param that passed — Tier 2 evidence later. */
  annotations: Record<string, Origin[]>;
}

/** Truncate a value for inclusion in errors/audit (never log full secrets). */
export function previewValue(value: unknown): string {
  const text = typeof value === 'string' ? value : (JSON.stringify(value) ?? String(value));
  if (text.length <= 24) return text;
  return `${text.slice(0, 12)}…${text.slice(-8)}`;
}

export function evaluateTier1(
  sensitiveParams: Record<string, { provenance: ProvenanceRequirement }>,
  args: Record<string, unknown>,
  index: ProvenanceIndex,
): Tier1Result {
  const violations: Tier1Violation[] = [];
  const annotations: Record<string, Origin[]> = {};

  for (const [param, requirement] of Object.entries(sensitiveParams)) {
    if (!(param in args)) continue; // not provided — nothing to trace
    const value = args[param];
    const elements: unknown[] = Array.isArray(value) ? value : [value];

    const paramOrigins: Origin[] = [];
    for (const element of elements) {
      if (typeof element !== 'string' && typeof element !== 'number') {
        violations.push({
          param,
          reason: 'untraceable_param',
          required: requirement.provenance,
          value_preview: previewValue(element),
          origins: [],
        });
        continue;
      }
      const origins = index.trace(element);
      const satisfied =
        requirement.provenance === 'trusted'
          ? origins.some((o) => o.trust === 'trusted')
          : origins.length > 0;
      if (satisfied) {
        paramOrigins.push(...origins);
      } else {
        violations.push({
          param,
          reason: origins.length === 0 ? 'unknown_provenance' : 'untrusted_provenance',
          required: requirement.provenance,
          value_preview: previewValue(element),
          origins,
        });
      }
    }
    if (paramOrigins.length > 0) annotations[param] = paramOrigins;
  }

  return { ok: violations.length === 0, violations, annotations };
}
