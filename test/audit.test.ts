import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { AuditLog, GENESIS_HASH, verifyAuditFile } from '../src/audit/log.js';

describe('AuditLog', () => {
  let dir: string;
  let path: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tripwire-audit-'));
    path = join(dir, 'audit.jsonl');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('chains entries from the genesis hash', () => {
    const log = new AuditLog(path);
    const e1 = log.append('proxy_started', { session: 's1' });
    const e2 = log.append('tool_call', { tool: 'a__t', decision: 'pass' });

    expect(e1.seq).toBe(1);
    expect(e1.prev_hash).toBe(GENESIS_HASH);
    expect(e2.seq).toBe(2);
    expect(e2.prev_hash).toBe(e1.hash);

    const verdict = verifyAuditFile(path);
    expect(verdict.ok).toBe(true);
    expect(verdict.entries).toBe(2);
  });

  it('verifies an empty log', () => {
    writeFileSync(path, '');
    expect(verifyAuditFile(path)).toEqual({ ok: true, entries: 0, errors: [] });
  });

  it('fails loudly when an entry is tampered', () => {
    const log = new AuditLog(path);
    log.append('tool_call', { tool: 'a__t', decision: 'pass' });
    log.append('tool_call', { tool: 'b__t', decision: 'pass' });

    const lines = readFileSync(path, 'utf8').trim().split('\n');
    writeFileSync(path, [lines[0]!.replace('"pass"', '"block"'), lines[1]].join('\n') + '\n');

    const verdict = verifyAuditFile(path);
    expect(verdict.ok).toBe(false);
    expect(verdict.errors.join('\n')).toMatch(/hash mismatch/);
  });

  it('fails when entries are deleted from the middle', () => {
    const log = new AuditLog(path);
    log.append('a', {});
    log.append('b', {});
    log.append('c', {});
    const lines = readFileSync(path, 'utf8').trim().split('\n');
    writeFileSync(path, [lines[0], lines[2]].join('\n') + '\n');

    const verdict = verifyAuditFile(path);
    expect(verdict.ok).toBe(false);
    expect(verdict.errors.join('\n')).toMatch(/broken chain|expected seq/);
  });

  it('fails when entries are reordered', () => {
    const log = new AuditLog(path);
    log.append('a', {});
    log.append('b', {});
    const lines = readFileSync(path, 'utf8').trim().split('\n');
    writeFileSync(path, [lines[1], lines[0]].join('\n') + '\n');

    expect(verifyAuditFile(path).ok).toBe(false);
  });

  it('fails when the head is truncated (history rewritten from genesis)', () => {
    const log = new AuditLog(path);
    log.append('a', {});
    log.append('b', {});
    const lines = readFileSync(path, 'utf8').trim().split('\n');
    writeFileSync(path, lines[1] + '\n');

    expect(verifyAuditFile(path).ok).toBe(false);
  });

  it('rejects garbage lines', () => {
    const log = new AuditLog(path);
    log.append('a', {});
    writeFileSync(path, readFileSync(path, 'utf8') + 'not json\n');
    const verdict = verifyAuditFile(path);
    expect(verdict.ok).toBe(false);
    expect(verdict.errors.join('\n')).toMatch(/invalid JSON/);
  });
});
