import { describe, expect, it } from 'vitest';

import {
  agentSnippet,
  buildConfig,
  configToYaml,
  detectProviders,
  type WizardAnswers,
} from '../src/cli/init.js';
import { describeEntry, renderLogs } from '../src/cli/logs.js';
import { parseConfig } from '../src/policy/config.js';
import type { AuditEntry } from '../src/audit/log.js';

/**
 * The easy-mode surface: the wizard's generated config must always be a
 * VALID Tripwire config (it goes straight into the same Zod schema the
 * proxy loads), and the plain-English log rendering must cover every
 * decision type.
 */

const ANSWERS: WizardAnswers = {
  upstreams: [
    { name: 'payments', command: ['npx', 'payments-mcp'], carriesOutsideContent: false },
    { name: 'docs', command: ['npx', 'docs-mcp'], carriesOutsideContent: true },
  ],
  guardedTools: [{ tool: 'payments__send_payment', protectedParams: ['recipient', 'amount'] }],
  requireIntent: true,
  panel: ['anthropic/claude-sonnet-4-6', 'openai/gpt-5.1'],
};

describe('init wizard config generation', () => {
  it('produces YAML that passes the real config schema', () => {
    const config = parseConfig(configToYaml(ANSWERS), 'generated');
    expect(config.upstreams.map((u) => [u.name, u.trust])).toEqual([
      ['payments', 'trusted'],
      ['docs', 'untrusted'],
    ]);

    const rule = config.rules[0]!;
    expect(rule.match.tool).toBe('payments__send_payment');
    expect(rule.sensitive_params).toEqual({
      recipient: { provenance: 'trusted' },
      amount: { provenance: 'trusted' },
    });
    expect(rule.verify.tiers).toContain('consensus');
    expect(rule.verify.require_intent).toBe(true);
    expect(rule.verify.fail_mode).toBe('closed'); // money paths fail closed
    expect(rule.verify.quorum).toBe('majority'); // 2-model panel
  });

  it('always appends the destructiveHint safety-net rule', () => {
    const config = parseConfig(configToYaml(ANSWERS), 'generated');
    const last = config.rules.at(-1)!;
    expect(last.match.annotation).toEqual({ destructiveHint: true });
    expect(last.verify.tiers).toEqual(['receipts', 'provenance']);
  });

  it('omits the consensus tier when no AI panel was chosen', () => {
    const config = parseConfig(configToYaml({ ...ANSWERS, panel: [] }), 'generated');
    expect(config.rules[0]!.verify.tiers).toEqual(['receipts', 'provenance']);
    expect(config.rules[0]!.verify.panel).toEqual([]);
  });

  it('uses unanimous quorum for a single-model panel', () => {
    const single = buildConfig({ ...ANSWERS, panel: ['anthropic/claude-sonnet-4-6'] });
    const rule = (single.rules as { verify: { quorum: string } }[])[0]!;
    expect(rule.verify.quorum).toBe('unanimous');
  });

  it('emits a valid agent snippet with key placeholders for the chosen panel', () => {
    const snippet = JSON.parse(agentSnippet('tripwire.yaml', ANSWERS.panel)) as {
      mcpServers: { tripwire: { command: string; args: string[]; env: Record<string, string> } };
    };
    expect(snippet.mcpServers.tripwire.command).toBe('tripwire');
    expect(snippet.mcpServers.tripwire.args.some((a) => a.endsWith('tripwire.yaml'))).toBe(true);
    expect(Object.keys(snippet.mcpServers.tripwire.env)).toEqual([
      'ANTHROPIC_API_KEY',
      'OPENAI_API_KEY',
    ]);
  });

  it('detects available providers from the environment', () => {
    expect(detectProviders({}).length).toBe(0);
    const detected = detectProviders({ OPENAI_API_KEY: 'sk-x', GOOGLE_API_KEY: 'g-x' });
    expect(detected.map((p) => p.model)).toEqual(['openai/gpt-5.1', 'google/gemini-2.5-pro']);
  });
});

describe('plain-English log rendering', () => {
  const entry = (type: string, data: Record<string, unknown>): AuditEntry => ({
    seq: 1,
    ts: '2026-06-11T05:00:00.000Z',
    type,
    data,
    prev_hash: '0'.repeat(64),
    hash: 'f'.repeat(64),
  });

  it('describes every decision type without leaking raw values', () => {
    expect(describeEntry(entry('tool_call', { tool: 'payments__send_payment' }))).toContain(
      'ALLOWED',
    );
    expect(
      describeEntry(
        entry('tool_call', {
          tool: 'payments__send_payment',
          consensus: { decision: 'pass' },
        }),
      ),
    ).toContain('AI reviewers approved');

    const blocked = describeEntry(
      entry('tool_call_blocked', {
        tool: 'payments__send_payment',
        code: 'provenance_violation',
        violations: [{ param: 'recipient', reason: 'untrusted_provenance' }],
      }),
    );
    expect(blocked).toContain('BLOCKED');
    expect(blocked).toContain('untrusted content');

    expect(
      describeEntry(entry('tool_call_blocked', { tool: 't', code: 'consensus_failed' })),
    ).toContain('AI reviewers did not approve');
    expect(
      describeEntry(entry('tool_call_blocked', { tool: 't', code: 'intent_required' })),
    ).toContain('goal');
    expect(describeEntry(entry('intent_declared', {}))).toContain('goal');
  });

  it('renders a session timeline and skips internal entry types', () => {
    const lines = renderLogs([
      entry('proxy_started', { upstreams: ['payments'] }),
      entry('tools_listed', { count: 3 }),
      entry('tool_call', { tool: 'docs__read_document' }),
      entry('tool_call_blocked', { tool: 'payments__send_payment', code: 'intent_required' }),
    ]);
    expect(lines).toHaveLength(4);
    expect(lines[0]).toContain('session started');
    expect(lines.every((l) => l.startsWith('2026-06-11 05:00:00'))).toBe(true);
  });
});
