import { appendFileSync, readFileSync } from 'node:fs';

import { canonicalize, sha256Hex } from '../receipts/canonical.js';

/**
 * Hash-chained, append-only JSONL audit log.
 *
 * Every entry embeds the hash of the previous entry; `verifyAuditFile`
 * re-derives the whole chain so any tampering, deletion, or reordering of
 * history fails loudly. Raw parameter values are NOT written here — entries
 * carry hashes and receipt sequence references; full values live in the
 * (mode-0600) receipt ledger, so the audit log stays safe to ship around.
 */

export const GENESIS_HASH = '0'.repeat(64);

export interface AuditEntry {
  seq: number;
  ts: string;
  type: string;
  data: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

export function entryHash(entry: Omit<AuditEntry, 'hash'>): string {
  return sha256Hex(canonicalize(entry));
}

export class AuditLog {
  private readonly path: string;
  private prevHash = GENESIS_HASH;
  private nextSeq = 1;

  constructor(path: string) {
    this.path = path;
  }

  append(type: string, data: Record<string, unknown>): AuditEntry {
    const unsigned: Omit<AuditEntry, 'hash'> = {
      seq: this.nextSeq,
      ts: new Date().toISOString(),
      type,
      data,
      prev_hash: this.prevHash,
    };
    const entry: AuditEntry = { ...unsigned, hash: entryHash(unsigned) };
    appendFileSync(this.path, JSON.stringify(entry) + '\n', { mode: 0o600 });
    this.nextSeq += 1;
    this.prevHash = entry.hash;
    return entry;
  }
}

export interface AuditVerification {
  ok: boolean;
  entries: number;
  errors: string[];
}

export function verifyAuditFile(path: string): AuditVerification {
  const lines = readFileSync(path, 'utf8')
    .split('\n')
    .filter((l) => l.trim() !== '');
  const errors: string[] = [];
  let prevHash = GENESIS_HASH;
  let expectedSeq = 1;

  for (const [index, line] of lines.entries()) {
    const lineNo = index + 1;
    let entry: AuditEntry;
    try {
      entry = JSON.parse(line) as AuditEntry;
    } catch {
      errors.push(`line ${lineNo}: invalid JSON`);
      break;
    }
    if (entry.seq !== expectedSeq) {
      errors.push(`line ${lineNo}: expected seq ${expectedSeq}, got ${entry.seq}`);
    }
    if (entry.prev_hash !== prevHash) {
      errors.push(`line ${lineNo}: broken chain (prev_hash does not match previous entry)`);
    }
    const { hash, ...unsigned } = entry;
    let recomputed: string;
    try {
      recomputed = entryHash(unsigned);
    } catch (err) {
      errors.push(`line ${lineNo}: unhashable entry: ${String(err)}`);
      break;
    }
    if (recomputed !== hash) {
      errors.push(`line ${lineNo}: entry hash mismatch (entry tampered)`);
    }
    prevHash = hash;
    expectedSeq = entry.seq + 1;
  }

  return { ok: errors.length === 0, entries: lines.length, errors };
}
