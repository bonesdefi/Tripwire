import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import type { AuditEntry } from '../audit/log.js';

/**
 * `tripwire logs <session-dir>` — the audit log in plain English.
 * For the cryptographic verification of the same files, use
 * `tripwire verify-log`.
 */

export function describeEntry(entry: AuditEntry): string | undefined {
  const data = entry.data;
  const tool = typeof data.tool === 'string' ? data.tool : undefined;
  switch (entry.type) {
    case 'proxy_started':
      return `session started (servers: ${(data.upstreams as string[] | undefined)?.join(', ') ?? '?'})`;
    case 'proxy_stopped':
      return 'session ended';
    case 'upstream_connected':
      return `connected to server "${String(data.upstream)}" (${String(data.trust)})`;
    case 'upstream_connect_failed':
      return `could not connect to server "${String(data.upstream)}"`;
    case 'intent_declared':
      return 'agent declared its goal (recorded as a receipt)';
    case 'intent_rejected':
      return `agent sent an invalid goal declaration (${String(data.error)})`;
    case 'tools_listed':
      return `agent asked what tools exist (${String(data.count)} available)`;
    case 'tool_call': {
      const consensus = data.consensus as { decision?: string } | string | undefined;
      const aiNote =
        typeof consensus === 'object' && consensus?.decision === 'pass'
          ? ' — AI reviewers approved'
          : '';
      return `ALLOWED  ${tool}${aiNote}`;
    }
    case 'tool_call_blocked':
      return `BLOCKED  ${tool} — ${blockReason(String(data.code), data)}`;
    case 'tool_call_failed':
      return `FAILED   ${tool} — the server reported an error`;
    case 'tool_call_rejected':
      return `REFUSED  ${tool} — no such tool`;
    default:
      return undefined;
  }
}

function blockReason(code: string, data: Record<string, unknown>): string {
  switch (code) {
    case 'provenance_violation': {
      const violations = data.violations as { param: string; reason: string }[] | undefined;
      const detail = violations
        ?.map((v) =>
          v.reason === 'untrusted_provenance'
            ? `"${v.param}" came only from untrusted content`
            : v.reason === 'unknown_provenance'
              ? `"${v.param}" appeared in no tool result this session`
              : `"${v.param}" could not be traced`,
        )
        .join('; ');
      return detail ?? 'a protected value had no acceptable source';
    }
    case 'consensus_failed':
      return 'the AI reviewers did not approve it';
    case 'intent_required':
      return 'the agent had not declared its goal yet';
    case 'unmatched_tool':
      return 'no rule covers this tool and policy blocks unknowns';
    case 'hold_required':
      return 'policy requires human approval';
    default:
      return code;
  }
}

export function renderLogs(entries: AuditEntry[]): string[] {
  const lines: string[] = [];
  for (const entry of entries) {
    const description = describeEntry(entry);
    if (description === undefined) continue;
    const time = entry.ts.replace('T', ' ').replace(/\.\d+Z$/, '');
    lines.push(`${time}  ${description}`);
  }
  return lines;
}

export function runLogs(sessionDir: string): boolean {
  let raw: string;
  try {
    raw = readFileSync(join(sessionDir, 'audit.jsonl'), 'utf8');
  } catch {
    process.stdout.write(
      `No audit log found in ${sessionDir}.\n` +
        'Session folders live under .tripwire/sessions/ (newest last).\n',
    );
    return false;
  }
  const entries = raw
    .trim()
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => JSON.parse(l) as AuditEntry);
  for (const line of renderLogs(entries)) process.stdout.write(line + '\n');

  const blocked = entries.filter((e) => e.type === 'tool_call_blocked').length;
  const allowed = entries.filter((e) => e.type === 'tool_call').length;
  process.stdout.write(
    `\n${allowed} action${allowed === 1 ? '' : 's'} allowed, ${blocked} blocked. ` +
      'Run `tripwire verify-log` on this folder to cryptographically verify ' +
      'this record has not been altered.\n',
  );
  return true;
}
