import { MAX_FORMS_PER_RESULT, extractForms, normalForms } from './extract.js';

/**
 * Tier 1 — the session value-provenance index.
 *
 * Records where every distinct value observed in tool results first
 * appeared (which upstream, which tool, which receipt, which trust label),
 * and answers the structural question for guarded parameters: *where did
 * this value come from?*
 */

export type TrustLabel = 'trusted' | 'untrusted';

export interface Origin {
  upstream: string;
  trust: TrustLabel;
  tool: string;
  receipt_seq: number;
}

export class ProvenanceIndex {
  private readonly byForm = new Map<string, Origin[]>();

  /**
   * Index every value in a receipted tool result.
   *
   * `excludeForms` carries the forms present in the call's *arguments*: a
   * tool echoing an input back (search results, error messages, ...) must
   * not confer its own trust label on a value the agent supplied. Without
   * this, an agent could launder an attacker address into `trusted` by
   * querying a trusted tool with it.
   */
  indexResult(origin: Origin, result: unknown, excludeForms?: ReadonlySet<string>): void {
    const forms = extractForms(result);
    let budget = MAX_FORMS_PER_RESULT;
    for (const form of forms) {
      if (budget <= 0) break;
      budget -= 1;
      if (excludeForms?.has(form)) continue;
      const origins = this.byForm.get(form);
      if (origins === undefined) {
        this.byForm.set(form, [origin]);
      } else if (
        !origins.some((o) => o.receipt_seq === origin.receipt_seq && o.tool === origin.tool)
      ) {
        origins.push(origin);
      }
    }
  }

  /**
   * Trace a parameter value: every origin in which any normal form of the
   * value has been observed, in first-seen order. Empty array means the
   * value appeared nowhere in session history.
   */
  trace(value: string | number): Origin[] {
    const seen = new Set<Origin>();
    for (const form of normalForms(value)) {
      for (const origin of this.byForm.get(form) ?? []) {
        seen.add(origin);
      }
    }
    return [...seen].sort((a, b) => a.receipt_seq - b.receipt_seq);
  }

  /** Number of distinct indexed forms (diagnostics). */
  get size(): number {
    return this.byForm.size;
  }
}
