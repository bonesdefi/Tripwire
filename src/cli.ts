#!/usr/bin/env node
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { verifyAuditFile } from './audit/log.js';
import { runCheck } from './cli/check.js';
import { runInitWizard } from './cli/init.js';
import { runLogs } from './cli/logs.js';
import { defaultVerifierFactory } from './consensus/providers.js';
import { ConfigError, loadConfig } from './policy/config.js';
import { TripwireProxy } from './proxy/proxy.js';
import { verifyReceiptFile } from './receipts/ledger.js';
import { createSession, loadSessionKey } from './session.js';

/**
 * tripwire run --config <path>      start the proxy on stdio
 * tripwire verify-log <session-dir> re-validate the audit chain and receipts
 *
 * In `run` mode stdout belongs to the MCP protocol; every human-facing
 * message goes to stderr.
 */

const VERSION = '0.2.0';

const USAGE = `tripwire ${VERSION} — the verification layer for AI agents

Getting started (no config knowledge needed):
  tripwire init                           Guided setup — answer a few plain-
                                          language questions, get a working config.
  tripwire check [--config <file>]        Health check: servers start, rules make
                                          sense, AI keys present. Plain English.

Everyday use:
  tripwire run --config <file>            Start the proxy (your agent launches this).
  tripwire logs <session-dir>             What happened, in plain English.
  tripwire verify-log <session-dir>       Cryptographically verify the record.

Session folders live under .tripwire/sessions/. Receipt verification needs the
session key: the hmac.key file written there, or TRIPWIRE_HMAC_KEY in the env.
Docs: docs/GETTING_STARTED.md · docs/POLICY.md · docs/THREAT_MODEL.md
`;

function fail(message: string): never {
  process.stderr.write(`tripwire: ${message}\n`);
  process.exit(1);
}

async function runProxy(args: string[]): Promise<void> {
  let configPath: string | undefined;
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === '--config' || args[i] === '-c') {
      configPath = args[i + 1];
      i += 1;
    } else {
      fail(`unknown argument: ${args[i]}\n\n${USAGE}`);
    }
  }
  if (configPath === undefined) fail(`run requires --config <path>\n\n${USAGE}`);

  const config = loadConfig(configPath);
  const session = createSession(config.state_dir);
  process.stderr.write(`tripwire: session ${session.id}\n`);
  process.stderr.write(`tripwire: recording to ${session.dir}\n`);

  const proxy = new TripwireProxy({
    upstreams: config.upstreams,
    ledger: session.ledger,
    audit: session.audit,
    rules: config.rules,
    defaults: config.defaults,
    verifierFactory: defaultVerifierFactory,
  });

  const shutdown = async (): Promise<never> => {
    await proxy.close().catch(() => undefined);
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown());
  process.on('SIGTERM', () => void shutdown());
  // When the agent disconnects (stdin closes), shut down cleanly.
  process.stdin.on('close', () => void shutdown());

  await proxy.start(new StdioServerTransport());
  process.stderr.write(
    `tripwire: proxying ${config.upstreams.map((u) => u.name).join(', ')} on stdio\n`,
  );
}

function verifyLog(args: string[]): void {
  const sessionDir = args[0];
  if (sessionDir === undefined) fail(`verify-log requires a session directory\n\n${USAGE}`);

  let failed = false;

  const auditPath = join(sessionDir, 'audit.jsonl');
  if (existsSync(auditPath)) {
    const audit = verifyAuditFile(auditPath);
    if (audit.ok) {
      process.stdout.write(`audit chain    OK   (${audit.entries} entries)\n`);
    } else {
      failed = true;
      process.stdout.write(`audit chain    FAIL (${audit.entries} entries)\n`);
      for (const error of audit.errors) process.stdout.write(`  ${error}\n`);
    }
  } else {
    failed = true;
    process.stdout.write(`audit chain    MISSING (${auditPath})\n`);
  }

  const receiptsPath = join(sessionDir, 'receipts.jsonl');
  if (existsSync(receiptsPath)) {
    const key = loadSessionKey(sessionDir);
    if (key === undefined) {
      failed = true;
      process.stdout.write(`receipts       NO KEY (set TRIPWIRE_HMAC_KEY or keep hmac.key)\n`);
    } else {
      const receipts = verifyReceiptFile(key, receiptsPath);
      if (receipts.ok) {
        process.stdout.write(`receipts       OK   (${receipts.count} receipts)\n`);
      } else {
        failed = true;
        process.stdout.write(`receipts       FAIL (${receipts.count} receipts)\n`);
        for (const failure of receipts.failures) {
          process.stdout.write(`  seq ${failure.seq}: ${failure.error}\n`);
        }
      }
    }
  } else {
    process.stdout.write(`receipts       none recorded\n`);
  }

  process.exit(failed ? 1 : 0);
}

function configFlag(args: string[], fallback = 'tripwire.yaml'): string {
  const index = args.findIndex((a) => a === '--config' || a === '-c');
  return index === -1 ? fallback : (args[index + 1] ?? fallback);
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  switch (command) {
    case 'init':
      await runInitWizard(rest[0]?.startsWith('-') === false ? rest[0] : 'tripwire.yaml');
      break;
    case 'check':
      process.exit((await runCheck(configFlag(rest))) ? 0 : 1);
      break;
    case 'run':
      await runProxy(rest);
      break;
    case 'logs': {
      const dir = rest[0];
      if (dir === undefined) fail(`logs requires a session directory\n\n${USAGE}`);
      process.exit(runLogs(dir) ? 0 : 1);
      break;
    }
    case 'verify-log':
      verifyLog(rest);
      break;
    case '--version':
    case '-v':
      process.stdout.write(`${VERSION}\n`);
      break;
    case undefined:
    case '--help':
    case '-h':
      process.stderr.write(USAGE);
      process.exit(command === undefined ? 1 : 0);
      break;
    default:
      fail(`unknown command: ${command}\n\n${USAGE}`);
  }
}

main().catch((err: unknown) => {
  if (err instanceof ConfigError) fail(err.message);
  fail(err instanceof Error ? (err.stack ?? err.message) : String(err));
});
