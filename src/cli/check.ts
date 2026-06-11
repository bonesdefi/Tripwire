import { PROVIDER_KEYS } from './init.js';
import {
  isLoopbackHost,
  loadConfig,
  resolveHttpAuth,
  type TripwireConfig,
} from '../policy/config.js';
import { globToRegExp } from '../policy/match.js';
import { Upstream } from '../proxy/upstream.js';
import { namespaceTool } from '../proxy/proxy.js';

/**
 * `tripwire check` — a plain-language health check. Validates the config,
 * actually starts each tool server, confirms guarded tools exist, and
 * verifies AI keys are present where rules need them. Designed so a
 * non-engineer can read the output and know what to do next.
 */

interface Finding {
  level: 'ok' | 'warn' | 'fail';
  message: string;
}

const ICONS = { ok: '✔', warn: '⚠', fail: '✘' } as const;

export async function runCheck(configPath: string): Promise<boolean> {
  const out = (s = ''): void => void process.stdout.write(s + '\n');
  const findings: Finding[] = [];
  const add = (level: Finding['level'], message: string): void => {
    findings.push({ level, message });
    out(`  ${ICONS[level]} ${message}`);
  };

  out(`\nChecking ${configPath} ...\n`);

  // 1. Config parses and validates.
  let config: TripwireConfig;
  try {
    config = loadConfig(configPath);
    add('ok', 'Config file is valid.');
  } catch (err) {
    add('fail', `Config problem: ${err instanceof Error ? err.message : String(err)}`);
    out('\nFix the config (or re-run `tripwire init`) and check again.');
    return false;
  }

  // 2. Transport exposure (HTTP mode only).
  if (config.transport.type === 'http') {
    const http = config.transport.http;
    try {
      const { token } = resolveHttpAuth(http);
      if (token !== undefined) {
        add('ok', `HTTP mode on ${http.host}:${http.port}${http.path} with bearer-token auth.`);
      } else {
        add(
          'ok',
          `HTTP mode on ${http.host}:${http.port}${http.path} — loopback only, no auth ` +
            '(fine for same-machine agents; add an auth token before exposing it).',
        );
      }
      if (!isLoopbackHost(http.host)) {
        add(
          'warn',
          `Tripwire will be reachable from the network on ${http.host}:${http.port}. ` +
            'Traffic is plain HTTP — put it behind a TLS reverse proxy and keep the ' +
            'bearer token secret.',
        );
      }
    } catch (err) {
      add('fail', err instanceof Error ? err.message : String(err));
    }
  }

  // 3. Each tool server actually starts and lists tools.
  const knownTools: string[] = [];
  for (const upstreamConfig of config.upstreams) {
    try {
      const upstream = await withTimeout(
        Upstream.connect(upstreamConfig),
        15_000,
        `"${upstreamConfig.name}" did not start within 15 seconds`,
      );
      const tools = await upstream.listTools();
      knownTools.push(...tools.map((t) => namespaceTool(upstreamConfig.name, t.name)));
      add(
        'ok',
        `Server "${upstreamConfig.name}" starts and offers ${tools.length} tool${tools.length === 1 ? '' : 's'} (${upstreamConfig.trust}).`,
      );
      await upstream.close();
    } catch (err) {
      add(
        'fail',
        `Server "${upstreamConfig.name}" could not be started: ` +
          `${err instanceof Error ? err.message : String(err)}. ` +
          `Double-check its command: ${upstreamConfig.command.join(' ')}`,
      );
    }
  }

  if (config.upstreams.every((u) => u.trust === 'untrusted')) {
    add(
      'warn',
      'No server is marked trusted. Protected values (like account numbers) ' +
        'have nowhere safe to come from, so guarded calls that require trusted ' +
        'provenance will always be blocked. Mark your internal system of record ' +
        'as trusted in the config.',
    );
  }

  // 3. Rules point at tools that exist, and AI panels have keys.
  config.rules.forEach((rule, index) => {
    const label = rule.match.tool ?? JSON.stringify(rule.match);
    if (rule.match.tool !== undefined && knownTools.length > 0) {
      const regex = globToRegExp(rule.match.tool);
      if (!knownTools.some((t) => regex.test(t))) {
        add(
          'warn',
          `Rule ${index + 1} guards "${rule.match.tool}", but none of your servers ` +
            'offer a tool with that name right now. (Names look like ' +
            `${knownTools[0] ?? 'server__tool'}.)`,
        );
      } else {
        add('ok', `Rule ${index + 1} ("${label}") matches at least one real tool.`);
      }
    }

    for (const panelEntry of rule.verify.panel) {
      const provider = PROVIDER_KEYS.find((p) =>
        panelEntry.startsWith(p.model.split('/')[0]! + '/'),
      );
      if (provider === undefined) {
        add(
          'warn',
          `Rule ${index + 1} uses "${panelEntry}" — unknown provider. ` +
            'Supported: anthropic/..., openai/..., google/...',
        );
      } else if (!provider.env.some((e) => (process.env[e] ?? '') !== '')) {
        add(
          'warn',
          `Rule ${index + 1} wants AI review from ${provider.label}, but ` +
            `${provider.env[0]} is not set in this terminal. With fail-closed ` +
            'policy, that verifier counts as a "no" vote — guarded calls may be ' +
            'blocked until the key is provided to the agent host.',
        );
      } else {
        add('ok', `AI reviewer ${panelEntry}: API key found.`);
      }
    }
  });

  if (config.rules.length === 0) {
    add(
      'warn',
      'No rules defined — Tripwire will record everything (receipts + audit) ' +
        'but block nothing. Run `tripwire init` to add protection.',
    );
  }

  const fails = findings.filter((f) => f.level === 'fail').length;
  const warns = findings.filter((f) => f.level === 'warn').length;
  out();
  if (fails > 0) {
    out(`Result: ${fails} problem${fails === 1 ? '' : 's'} to fix before using Tripwire.`);
  } else if (warns > 0) {
    out(`Result: working, with ${warns} warning${warns === 1 ? '' : 's'} worth reading above.`);
  } else {
    out('Result: everything looks good. Point your agent at Tripwire and go.');
  }
  return fails === 0;
}

async function withTimeout<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(message)), ms);
        timer.unref?.();
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
