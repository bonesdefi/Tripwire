import { createHash } from 'node:crypto';

/**
 * Canonical JSON serialization.
 *
 * Receipts and the audit hash chain both sign canonical bytes; two
 * structurally-equal values MUST always serialize identically, and anything
 * that cannot be represented deterministically MUST throw rather than be
 * silently coerced. This module is a security boundary: it is intentionally
 * strict and intentionally dependency-free.
 *
 * Rules:
 * - Object keys are sorted by UTF-16 code unit (the default string sort).
 * - Strings/numbers are encoded exactly as `JSON.stringify` encodes them
 *   (shortest round-trip number form; standard string escaping).
 * - `-0` canonicalizes to `0`; `NaN`/`Infinity` throw.
 * - `undefined`-valued object properties are omitted (JSON semantics);
 *   `undefined` array elements become `null` (JSON semantics).
 * - Only null, boolean, number, string, arrays, and plain objects are
 *   accepted. Dates, Maps, class instances, bigints, functions throw.
 * - Circular references throw.
 */

export class CanonicalizationError extends TypeError {
  constructor(message: string) {
    super(`canonicalization failed: ${message}`);
    this.name = 'CanonicalizationError';
  }
}

export function canonicalize(value: unknown): string {
  if (value === undefined) {
    throw new CanonicalizationError('top-level value is undefined');
  }
  return c14n(value, new Set());
}

function c14n(value: unknown, seen: Set<object>): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) {
        throw new CanonicalizationError(`non-finite number: ${value}`);
      }
      return Object.is(value, -0) ? '0' : JSON.stringify(value);
    case 'object':
      break;
    default:
      throw new CanonicalizationError(`unsupported type: ${typeof value}`);
  }

  const obj = value as object;
  if (seen.has(obj)) {
    throw new CanonicalizationError('circular reference');
  }
  seen.add(obj);
  try {
    if (Array.isArray(obj)) {
      // Index-based loop: Array.prototype.map skips holes in sparse arrays,
      // which would emit invalid JSON. Holes and undefined become null.
      const parts: string[] = [];
      for (let i = 0; i < obj.length; i += 1) {
        const el: unknown = obj[i];
        parts.push(el === undefined ? 'null' : c14n(el, seen));
      }
      return `[${parts.join(',')}]`;
    }
    const proto: unknown = Object.getPrototypeOf(obj);
    if (proto !== Object.prototype && proto !== null) {
      throw new CanonicalizationError('non-plain object (class instance, Date, Map, ...)');
    }
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const key of keys) {
      const v = (obj as Record<string, unknown>)[key];
      if (v === undefined) continue;
      parts.push(`${JSON.stringify(key)}:${c14n(v, seen)}`);
    }
    return `{${parts.join(',')}}`;
  } finally {
    seen.delete(obj);
  }
}

/** SHA-256 of the canonical serialization, hex-encoded. */
export function canonicalHash(value: unknown): string {
  return sha256Hex(canonicalize(value));
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}
