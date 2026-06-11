import { normalForms } from '../provenance/extract.js';
import type { Verdict, VerificationPacket } from './types.js';
import type { VerifierClient, VerifyInput } from './verifier.js';

/**
 * Deterministic offline reference verifier.
 *
 * This is NOT a substitute for independent models — it exists so the demo
 * and the benchmark are reproducible from a clean clone with zero API keys,
 * and so CI never makes a live call. It implements simple, auditable
 * heuristics for the three checks; the benchmark README documents exactly
 * where those heuristics miss (and false-block) relative to live panels.
 *
 * Heuristics (v1):
 * - intent_match: fail when no intent is on file, or when the declared
 *   goal shares no content words with the evidence the recipient's
 *   provenance points at (e.g. goal says "pay Acme", recipient traces to
 *   the Globex record).
 * - source_grounding: fail when a material parameter (recipient/amount,
 *   scalar or array) appears in none of the evidence excerpts.
 * - bounds_and_sanity: fail when the call's amount matches none of the
 *   "amount due" figures stated in evidence (when any are stated).
 */

const AMOUNT_DUE = /amount due:?\s*([\d][\d,_ ]*(?:\.\d+)?)/gi;

function words(text: string): Set<string> {
  return new Set(
    (text.toLowerCase().match(/[a-z][a-z0-9]{3,}/g) ?? []).filter((w) => !STOP_WORDS.has(w)),
  );
}

const STOP_WORDS = new Set([
  'invoice',
  'outstanding',
  'payment',
  'send',
  'wallet',
  'amount',
  'currency',
  'with',
  'from',
  'this',
  'that',
  'usdc',
]);

function verdict(pass: boolean, reasons: string[], extras: Partial<Verdict> = {}): Verdict {
  return {
    verdict: pass ? 'pass' : 'fail',
    confidence: pass ? 0.7 : 0.85,
    reasons,
    evidence_refs: [],
    suspected_injection: false,
    ...extras,
  };
}

function intentMatch(packet: VerificationPacket): Verdict {
  if (packet.declared_intent === null) {
    return verdict(false, ['no declared intent on file']);
  }
  const recipientOrigins = packet.provenance['recipient'] ?? packet.provenance['recipients'];
  if (recipientOrigins === undefined || recipientOrigins.length === 0) {
    return verdict(true, ['no recipient provenance to cross-check']);
  }
  const goalWords = words(
    `${packet.declared_intent.goal} ${packet.declared_intent.plan_summary ?? ''}`,
  );
  const originSeqs = new Set(recipientOrigins.map((o) => o.receipt_seq));
  const originText = packet.evidence
    .filter((e) => originSeqs.has(e.receipt_seq))
    .map((e) => e.excerpt.toLowerCase())
    .join(' ');
  for (const word of goalWords) {
    if (originText.includes(word)) {
      return verdict(true, [`recipient source mentions "${word}" from the declared goal`], {
        evidence_refs: [...originSeqs].map((s) => `receipt:${s}`),
      });
    }
  }
  return verdict(false, ['recipient does not trace to evidence related to the declared goal'], {
    suspected_injection: true,
  });
}

function sourceGrounding(packet: VerificationPacket): Verdict {
  const allEvidence = packet.evidence.map((e) => e.excerpt).join('\n');
  const evidenceForms = new Set<string>();
  for (const form of normalFormsOfText(allEvidence)) evidenceForms.add(form);

  const material: [string, unknown][] = [];
  for (const key of ['recipient', 'recipients', 'amount']) {
    if (key in packet.args) material.push([key, packet.args[key]]);
  }
  const failures: string[] = [];
  for (const [param, value] of material) {
    const elements: unknown[] = Array.isArray(value) ? value : [value];
    for (const element of elements) {
      if (typeof element !== 'string' && typeof element !== 'number') continue;
      const found = normalForms(element).some((f) => evidenceForms.has(f));
      if (!found) failures.push(`${param} is ungrounded: not found in any evidence excerpt`);
    }
  }
  return failures.length === 0
    ? verdict(true, ['material parameters directly evidenced'])
    : verdict(false, failures);
}

// Evidence excerpts are prose/JSON; reuse the Tier 1 extraction by walking
// the text through normalForms-compatible tokenization.
function normalFormsOfText(text: string): string[] {
  const forms: string[] = [];
  // Excerpts are JSON-encoded (sometimes doubly); backslashes from escaped
  // quotes must not stick to tokens.
  for (const token of text.split(/[\s"'{}[\],:\\()]+/)) {
    if (token === '') continue;
    forms.push(...normalForms(token));
  }
  // Comma-grouped amounts get split by the tokenizer above; recover them.
  for (const match of text.matchAll(/\d[\d,_ ]*(?:\.\d+)?/g)) {
    forms.push(...normalForms(match[0].trim()));
  }
  return forms;
}

function boundsAndSanity(packet: VerificationPacket): Verdict {
  const amount = packet.args['amount'];
  if (typeof amount !== 'number') return verdict(true, ['no numeric amount to check']);

  const due = new Set<string>();
  for (const e of packet.evidence) {
    for (const match of e.excerpt.matchAll(AMOUNT_DUE)) {
      const normalized = normalForms(match[1]!.trim());
      for (const f of normalized) due.add(f);
    }
  }
  if (due.size === 0) return verdict(true, ['no invoiced amounts in evidence to compare against']);

  const matches = normalForms(amount).some((f) => due.has(f));
  return matches
    ? verdict(true, ['amount matches an invoiced amount due'])
    : verdict(false, [`amount ${amount} does not match any invoiced amount due in evidence`]);
}

export class OfflineVerifier implements VerifierClient {
  readonly id: string;

  constructor(id = 'offline/deterministic-v1') {
    this.id = id;
  }

  verify({ packet, prompt }: VerifyInput): Promise<Verdict> {
    switch (prompt.check) {
      case 'intent_match':
        return Promise.resolve(intentMatch(packet));
      case 'source_grounding':
        return Promise.resolve(sourceGrounding(packet));
      case 'bounds_and_sanity':
        return Promise.resolve(boundsAndSanity(packet));
    }
  }
}

export const offlineVerifierFactory = (id: string): VerifierClient => new OfflineVerifier(id);
