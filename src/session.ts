import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { AuditLog } from './audit/log.js';
import { ReceiptLedger, generateReceiptKey } from './receipts/ledger.js';

/**
 * A Tripwire session: one proxy run, one receipt ledger, one audit chain.
 *
 * Files live under `<state_dir>/sessions/<session-id>/`:
 *   - audit.jsonl    hash-chained audit log (no raw sensitive values)
 *   - receipts.jsonl full receipted tool traffic (created mode 0600)
 *   - hmac.key       session HMAC key (mode 0600), unless TRIPWIRE_HMAC_KEY
 *                    is provided via the environment
 *
 * The key never crosses the MCP boundary — that is the whole point: the
 * agent cannot forge receipts. It is persisted locally (or supplied via env)
 * so `tripwire verify-log` can re-validate a session after the fact.
 */

export interface Session {
  id: string;
  dir: string;
  ledger: ReceiptLedger;
  audit: AuditLog;
}

export const HMAC_KEY_ENV = 'TRIPWIRE_HMAC_KEY';

export function resolveSessionKey(env: NodeJS.ProcessEnv = process.env): Buffer | undefined {
  const hex = env[HMAC_KEY_ENV];
  if (hex === undefined || hex === '') return undefined;
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length < 32 || hex.length % 2 !== 0) {
    throw new Error(`${HMAC_KEY_ENV} must be a hex string of at least 16 bytes (32 hex chars)`);
  }
  return Buffer.from(hex, 'hex');
}

export function createSession(stateDir: string, env: NodeJS.ProcessEnv = process.env): Session {
  const id = `${new Date().toISOString().replace(/[:.]/g, '-')}-${randomBytes(4).toString('hex')}`;
  const dir = resolve(stateDir, 'sessions', id);
  mkdirSync(dir, { recursive: true });

  let key = resolveSessionKey(env);
  if (key === undefined) {
    key = generateReceiptKey();
    writeFileSync(join(dir, 'hmac.key'), key.toString('hex') + '\n', { mode: 0o600 });
  }

  return {
    id,
    dir,
    ledger: new ReceiptLedger({ key, sessionId: id, persistPath: join(dir, 'receipts.jsonl') }),
    audit: new AuditLog(join(dir, 'audit.jsonl')),
  };
}

/** Recover the HMAC key for a recorded session (env wins over the key file). */
export function loadSessionKey(
  sessionDir: string,
  env: NodeJS.ProcessEnv = process.env,
): Buffer | undefined {
  const fromEnv = resolveSessionKey(env);
  if (fromEnv !== undefined) return fromEnv;
  const keyPath = join(sessionDir, 'hmac.key');
  if (!existsSync(keyPath)) return undefined;
  return Buffer.from(readFileSync(keyPath, 'utf8').trim(), 'hex');
}
