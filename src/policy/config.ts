import { readFileSync } from 'node:fs';

import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

/**
 * Tripwire configuration.
 *
 * Declarative YAML, Zod-validated with actionable errors. Defaults always
 * point in the safe direction: upstreams are `untrusted` until labeled,
 * verification is fail-closed, and a rule that lists a tier Tripwire cannot
 * run yet (consensus before Phase 3) blocks rather than silently passing.
 */

// No underscores allowed: tools are exposed as `<upstream>__<tool>` and the
// namespace is parsed back at the first `__`, so upstream names must never
// contain one.
const upstreamNamePattern = /^[A-Za-z0-9][A-Za-z0-9-]*$/;

export const UpstreamSchema = z.object({
  name: z
    .string()
    .regex(
      upstreamNamePattern,
      'upstream name must be alphanumeric/dashes (no underscores — they delimit the tool namespace)',
    )
    .refine(
      (name) => name !== 'tripwire',
      'upstream name "tripwire" is reserved for synthetic tools',
    ),
  command: z.array(z.string()).nonempty('command must have at least the executable'),
  trust: z.enum(['trusted', 'untrusted']).default('untrusted'),
  env: z.record(z.string()).default({}),
});

export const SensitiveParamSchema = z.object({
  provenance: z.enum(['trusted', 'any']),
});

export const RuleMatchSchema = z
  .object({
    tool: z.string().optional(),
    upstream: z.string().optional(),
    annotation: z.record(z.union([z.boolean(), z.string(), z.number()])).optional(),
  })
  .refine(
    (m) => m.tool !== undefined || m.upstream !== undefined || m.annotation !== undefined,
    'rule match must constrain at least one of: tool, upstream, annotation',
  );

export const VerifySchema = z
  .object({
    tiers: z
      .array(z.enum(['receipts', 'provenance', 'consensus']))
      .default(['receipts', 'provenance']),
    require_intent: z.boolean().default(false),
    panel: z.array(z.string()).default([]),
    quorum: z.enum(['majority', 'unanimous']).default('majority'),
    checks: z
      .array(z.enum(['intent_match', 'source_grounding', 'bounds_and_sanity']))
      .default(['intent_match', 'source_grounding', 'bounds_and_sanity']),
    on_fail: z.enum(['block', 'hold']).default('block'),
    fail_mode: z.enum(['closed', 'open']).default('closed'),
    timeout_ms: z.number().int().positive().default(8000),
  })
  .superRefine((verify, ctx) => {
    if (verify.tiers.includes('consensus') && verify.panel.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          'the consensus tier requires a non-empty panel (e.g. ["anthropic/claude-sonnet-latest", "openai/gpt-latest"])',
      });
    }
    if (verify.tiers.includes('consensus') && verify.checks.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'the consensus tier requires at least one check',
      });
    }
  });

export const RuleSchema = z.object({
  match: RuleMatchSchema,
  sensitive_params: z.record(SensitiveParamSchema).default({}),
  verify: VerifySchema.default({}),
});

export const DefaultsSchema = z.object({
  on_unmatched: z.enum(['pass', 'block']).default('pass'),
  audit: z.enum(['all', 'decisions']).default('all'),
});

export const HttpTransportSchema = z.object({
  host: z.string().default('127.0.0.1'),
  port: z.number().int().min(0).max(65535).default(8765), // 0 = ephemeral
  path: z.string().startsWith('/', 'path must start with "/"').default('/mcp'),
  /** Bearer token required on every request. Env TRIPWIRE_HTTP_TOKEN overrides. */
  auth_token: z.string().min(16, 'auth_token must be at least 16 characters').optional(),
  /** Host:port values accepted in the Host header (DNS-rebinding protection). */
  allowed_hosts: z.array(z.string()).optional(),
  /** Origins accepted in the Origin header (browser DNS-rebinding protection). */
  allowed_origins: z.array(z.string()).optional(),
  /** Reap a session whose last request was this many ms ago (0 = never). */
  idle_timeout_ms: z.number().int().min(0).default(600_000),
});

export const TransportSchema = z
  .object({
    type: z.enum(['stdio', 'http']).default('stdio'),
    http: HttpTransportSchema.default({}),
  })
  .default({});

export const ConfigSchema = z.object({
  upstreams: z
    .array(UpstreamSchema)
    .nonempty('at least one upstream is required')
    .superRefine((upstreams, ctx) => {
      const seen = new Set<string>();
      for (const u of upstreams) {
        if (seen.has(u.name)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `duplicate upstream name: ${u.name}`,
          });
        }
        seen.add(u.name);
      }
    }),
  defaults: DefaultsSchema.default({}),
  transport: TransportSchema,
  rules: z.array(RuleSchema).default([]),
  state_dir: z.string().default('.tripwire'),
});

export type UpstreamConfig = z.infer<typeof UpstreamSchema>;
export type SensitiveParamConfig = z.infer<typeof SensitiveParamSchema>;
export type RuleConfig = z.infer<typeof RuleSchema>;
export type VerifyConfig = z.infer<typeof VerifySchema>;
export type DefaultsConfig = z.infer<typeof DefaultsSchema>;
export type TransportConfig = z.infer<typeof TransportSchema>;
export type HttpTransportConfig = z.infer<typeof HttpTransportSchema>;
export type TripwireConfig = z.infer<typeof ConfigSchema>;

/** True for loopback hosts that are safe to serve without auth. */
export function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h.startsWith('127.');
}

/**
 * Resolve the effective bearer token (env wins over file) and enforce the
 * fail-closed exposure rule: a non-loopback bind MUST have a token, so a
 * security proxy can never be put on a network unauthenticated by accident.
 */
export function resolveHttpAuth(
  http: HttpTransportConfig,
  env: NodeJS.ProcessEnv = process.env,
): { token: string | undefined } {
  const envToken = env['TRIPWIRE_HTTP_TOKEN'];
  const token = envToken !== undefined && envToken !== '' ? envToken : http.auth_token;
  if (!isLoopbackHost(http.host) && (token === undefined || token === '')) {
    throw new ConfigError(
      `refusing to serve HTTP on non-loopback host "${http.host}" without an auth token. ` +
        'Set transport.http.auth_token (16+ chars) or the TRIPWIRE_HTTP_TOKEN environment ' +
        'variable, or bind to 127.0.0.1 for local-only use.',
    );
  }
  return { token };
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

export function parseConfig(yamlText: string, source = 'config'): TripwireConfig {
  let raw: unknown;
  try {
    raw = parseYaml(yamlText);
  } catch (err) {
    throw new ConfigError(`${source}: invalid YAML: ${err instanceof Error ? err.message : err}`);
  }
  const result = ConfigSchema.safeParse(raw);
  if (!result.success) {
    const details = result.error.issues
      .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new ConfigError(`${source}: invalid configuration:\n${details}`);
  }
  return result.data;
}

export function loadConfig(path: string): TripwireConfig {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (err) {
    throw new ConfigError(
      `cannot read config ${path}: ${err instanceof Error ? err.message : err}`,
    );
  }
  return parseConfig(text, path);
}
