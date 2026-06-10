import { readFileSync } from 'node:fs';

import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

/**
 * Tripwire configuration (Phase 1 surface).
 *
 * Phase 1 needs upstream definitions and state location; the verification
 * `rules` section lands with the policy engine in Phase 2. Trust labels are
 * accepted (and defaulted to `untrusted` — the safe direction) so configs
 * written today keep working when Tier 1 starts consuming them.
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
  state_dir: z.string().default('.tripwire'),
});

export type UpstreamConfig = z.infer<typeof UpstreamSchema>;
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
