/**
 * Tier 1 value extraction and normalization.
 *
 * Every tool result is mined for the distinct values an agent might later
 * feed into a consequential call — addresses, amounts, emails, URLs, ids,
 * and short strings — and each value is reduced to one or more *normal
 * forms*. A guarded parameter is later normalized the same way and looked
 * up against the index, so "0xAAAA…", "0xaaaa…" and the un-prefixed hex all
 * resolve to the same origin, and "12,500" in an invoice matches the
 * numeric argument 12500.
 *
 * Forms are tagged (`s:`, `h:`, `n:`) so different value classes can never
 * collide. Extraction is deliberately generous: a missed extraction turns
 * into a false *block* downstream (the value would look unknown), and false
 * blocks are how security tools die.
 */

/** Strings longer than this are not indexed whole; their tokens still are. */
const MAX_WHOLE_STRING = 512;
/** Hard cap of forms extracted from a single result (DoS guard). */
export const MAX_FORMS_PER_RESULT = 20_000;

const HEX_VALUE = /^(0x)?[0-9a-fA-F]{6,}$/;
const NUMERIC_VALUE = /^[+-]?\d[\d,_ ]*(\.\d+)?$/;

const HEX_TOKEN = /0x[0-9a-fA-F]{6,}|\b[0-9a-fA-F]{16,}\b/g;
const EMAIL_TOKEN = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const URL_TOKEN = /https?:\/\/[^\s"'<>)\]]+/g;
const NUMBER_TOKEN = /\d[\d,_]*(?:\.\d+)?/g;
// id-like tokens: V-1001, invoice-acme-7741, tx_0001, ACC_12-9 ...
const ID_TOKEN = /[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)+/g;

function hexForm(value: string): string {
  return `h:${value.replace(/^0x/i, '').toLowerCase()}`;
}

function numericForm(value: string): string | undefined {
  const cleaned = value.replace(/[,_ ]/g, '');
  const num = Number(cleaned);
  if (!Number.isFinite(num)) return undefined;
  return `n:${String(num)}`;
}

/**
 * Normal forms of a *parameter value* being traced. Mirrors the forms that
 * indexing produces for equal values.
 */
export function normalForms(value: string | number): string[] {
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return [];
    return [`n:${String(Object.is(value, -0) ? 0 : value)}`];
  }
  const trimmed = value.trim();
  if (trimmed === '') return [];
  const forms = new Set<string>();
  forms.add(`s:${trimmed.toLowerCase()}`);
  if (HEX_VALUE.test(trimmed)) forms.add(hexForm(trimmed));
  if (NUMERIC_VALUE.test(trimmed)) {
    const n = numericForm(trimmed);
    if (n !== undefined) forms.add(n);
  }
  return [...forms];
}

function addStringForms(text: string, forms: Set<string>): void {
  const trimmed = text.trim();
  if (trimmed === '') return;

  if (trimmed.length <= MAX_WHOLE_STRING) {
    forms.add(`s:${trimmed.toLowerCase()}`);
    if (HEX_VALUE.test(trimmed)) forms.add(hexForm(trimmed));
    if (NUMERIC_VALUE.test(trimmed)) {
      const n = numericForm(trimmed);
      if (n !== undefined) forms.add(n);
    }
  }

  for (const match of trimmed.matchAll(HEX_TOKEN)) forms.add(hexForm(match[0]));
  for (const match of trimmed.matchAll(EMAIL_TOKEN)) forms.add(`s:${match[0].toLowerCase()}`);
  for (const match of trimmed.matchAll(URL_TOKEN)) forms.add(`s:${match[0].toLowerCase()}`);
  for (const match of trimmed.matchAll(ID_TOKEN)) forms.add(`s:${match[0].toLowerCase()}`);
  for (const match of trimmed.matchAll(NUMBER_TOKEN)) {
    const n = numericForm(match[0]);
    if (n !== undefined) forms.add(n);
  }
}

/**
 * Extract every indexable normal form from a tool result (or any JSON-ish
 * value). Object keys are not indexed; values are, recursively.
 */
export function extractForms(value: unknown): Set<string> {
  const forms = new Set<string>();
  walk(value, forms);
  return forms;
}

function walk(value: unknown, forms: Set<string>): void {
  if (forms.size >= MAX_FORMS_PER_RESULT) return;
  if (typeof value === 'string') {
    addStringForms(value, forms);
    return;
  }
  if (typeof value === 'number') {
    if (Number.isFinite(value)) forms.add(`n:${String(Object.is(value, -0) ? 0 : value)}`);
    return;
  }
  if (Array.isArray(value)) {
    for (const el of value) walk(el, forms);
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const v of Object.values(value)) walk(v, forms);
  }
}
