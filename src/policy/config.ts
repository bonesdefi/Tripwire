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

export const VerifySchema = z.object({
  tiers: z
    .array(z.enum(['receipts', 'provenance', 'consensus']))
    .default(['receipts', 'provenance']),
  panel: z.array(z.string()).default([]),
  quorum: z.enum(['majority', 'unanimous']).default('majority'),
  checks: z
    .array(z.enum(['intent_match', 'source_grounding', 'bounds_and_sanity']))
    .default(['intent_match', 'source_grounding', 'bounds_and_sanity']),
  on_fail: z.enum(['block', 'hold']).default('block'),
  fail_mode: z.enum(['closed', 'open']).default('closed'),
  timeout_ms: z.number().int().positive().default(8000),
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
  rules: z.array(RuleSchema).default([]),
  state_dir: z.string().default('.tripwire'),
});

export type UpstreamConfig = z.infer<typeof UpstreamSchema>;
export type SensitiveParamConfig = z.infer<typeof SensitiveParamSchema>;
export type RuleConfig = z.infer<typeof RuleSchema>;
export type VerifyConfig = z.infer<typeof VerifySchema>;
export type DefaultsConfig = z.infer<typeof DefaultsSchema>;
export type TripwireConfig = z.infer<typeof ConfigSchema>;

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
