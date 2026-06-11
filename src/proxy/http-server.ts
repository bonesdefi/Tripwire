import { randomUUID, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';

import type { HttpTransportConfig } from '../policy/config.js';
import type { TripwireProxy } from './proxy.js';

/**
 * Multi-session Streamable HTTP front door for Tripwire.
 *
 * One process serves many agents. Each MCP session gets its OWN TripwireProxy
 * — its own receipt ledger, provenance index, audit chain, declared intent,
 * and upstream connections — so verification state never bleeds between
 * agents. This is the same per-session isolation the stdio path gets for free
 * by being one-process-per-agent.
 *
 * Safe by default: bind to loopback, bearer-token auth (required on any
 * non-loopback bind — enforced in config.resolveHttpAuth), and DNS-rebinding
 * protection on every session transport.
 */

const MAX_BODY_BYTES = 4 * 1024 * 1024;

export interface SessionProxy {
  proxy: TripwireProxy;
  /** Human label for logs (the Tripwire session id). */
  label: string;
}

export interface ServeHttpOptions {
  http: HttpTransportConfig;
  /** Effective bearer token (already resolved from env/config), or undefined. */
  token: string | undefined;
  /** Builds a fresh session+proxy for each new MCP session. */
  createSessionProxy: () => SessionProxy;
  log?: (message: string) => void;
}

export interface HttpServerHandle {
  readonly url: string;
  readonly port: number;
  close(): Promise<void>;
}

interface LiveSession {
  transport: StreamableHTTPServerTransport;
  proxy: TripwireProxy;
  label: string;
  lastSeen: number;
  closing: boolean;
}

function bearerOk(token: string, header: string | undefined): boolean {
  if (header === undefined) return false;
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  if (match === null) return false;
  const provided = Buffer.from(match[1]!);
  const expected = Buffer.from(token);
  return provided.length === expected.length && timingSafeEqual(provided, expected);
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) throw new Error('request body too large');
    chunks.push(chunk as Buffer);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  if (raw.trim() === '') return undefined;
  return JSON.parse(raw);
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(payload);
}

function rpcError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, {
    jsonrpc: '2.0',
    error: { code: -32_000, message },
    id: null,
  });
}

export async function serveHttp(options: ServeHttpOptions): Promise<HttpServerHandle> {
  const { http, token, createSessionProxy } = options;
  const log = options.log ?? (() => undefined);
  const sessions = new Map<string, LiveSession>();

  // Resolved after listen() so an ephemeral port (0) yields the real one.
  let boundPort = http.port;
  const allowedHosts = (): string[] =>
    http.allowed_hosts ?? [
      `${http.host}:${boundPort}`,
      `localhost:${boundPort}`,
      `127.0.0.1:${boundPort}`,
    ];

  const teardown = async (sessionId: string): Promise<void> => {
    const live = sessions.get(sessionId);
    if (live === undefined || live.closing) return;
    live.closing = true;
    sessions.delete(sessionId);
    await live.proxy.close().catch(() => undefined);
    log(`session closed: ${live.label}`);
  };

  const newSessionTransport = (register: (id: string) => void): StreamableHTTPServerTransport =>
    new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      enableJsonResponse: true,
      enableDnsRebindingProtection: true,
      allowedHosts: allowedHosts(),
      ...(http.allowed_origins !== undefined ? { allowedOrigins: http.allowed_origins } : {}),
      // Fires while the initialize request is being handled — the only
      // moment the transport knows its own session id.
      onsessioninitialized: register,
      onsessionclosed: (sessionId) => {
        void teardown(sessionId);
      },
    });

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    if (url.pathname !== http.path) {
      rpcError(res, 404, `not found (MCP endpoint is ${http.path})`);
      return;
    }
    if (token !== undefined && !bearerOk(token, req.headers.authorization)) {
      res.setHeader('www-authenticate', 'Bearer');
      rpcError(res, 401, 'missing or invalid bearer token');
      return;
    }

    const sessionId = req.headers['mcp-session-id'];
    const existing = typeof sessionId === 'string' ? sessions.get(sessionId) : undefined;

    if (existing !== undefined) {
      existing.lastSeen = Date.now();
      await existing.transport.handleRequest(req, res);
      return;
    }

    if (req.method !== 'POST') {
      rpcError(res, 400, 'missing or unknown Mcp-Session-Id');
      return;
    }

    let body: unknown;
    try {
      body = await readBody(req);
    } catch (err) {
      rpcError(
        res,
        400,
        `invalid request body: ${err instanceof Error ? err.message : String(err)}`,
      );
      return;
    }

    if (sessionId !== undefined) {
      rpcError(res, 404, 'unknown session (it may have expired — re-initialize)');
      return;
    }
    if (!isInitializeRequest(body)) {
      rpcError(res, 400, 'first request must be an MCP "initialize"');
      return;
    }

    // New agent: spin up an isolated session + proxy. The session id is
    // assigned (and registered) while the initialize request is handled.
    const { proxy, label } = createSessionProxy();
    let live: LiveSession | undefined;
    const transport = newSessionTransport((id) => {
      live = { transport, proxy, label, lastSeen: Date.now(), closing: false };
      sessions.set(id, live);
      transport.onclose = () => {
        void teardown(id);
      };
      log(`session opened: ${label}`);
    });
    try {
      // Cast: the SDK's accessor-based optional properties don't satisfy our
      // exactOptionalPropertyTypes; the runtime shape conforms to Transport.
      await proxy.start(transport as unknown as Parameters<TripwireProxy['start']>[0]);
      await transport.handleRequest(req, res, body);
    } catch (err) {
      await proxy.close().catch(() => undefined);
      if (!res.headersSent) {
        rpcError(
          res,
          500,
          `failed to start session: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
      return;
    }
    if (live === undefined) {
      // Initialization didn't complete (transport rejected the request);
      // don't leak the per-session upstream processes.
      await proxy.close().catch(() => undefined);
    }
  };

  const server: Server = createServer((req, res) => {
    handle(req, res).catch((err: unknown) => {
      if (!res.headersSent) {
        rpcError(res, 500, `internal error: ${err instanceof Error ? err.message : String(err)}`);
      } else {
        res.end();
      }
    });
  });

  // Reap idle sessions so per-session upstream subprocesses don't accumulate.
  const reaper =
    http.idle_timeout_ms > 0
      ? setInterval(
          () => {
            const cutoff = Date.now() - http.idle_timeout_ms;
            for (const [id, live] of sessions) {
              if (live.lastSeen < cutoff) {
                log(`session idle-expired: ${live.label}`);
                void teardown(id);
              }
            }
          },
          Math.min(http.idle_timeout_ms, 30_000),
        )
      : undefined;
  reaper?.unref?.();

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(http.port, http.host, () => {
      server.off('error', reject);
      resolve();
    });
  });

  const address = server.address();
  boundPort = typeof address === 'object' && address !== null ? address.port : http.port;

  return {
    url: `http://${http.host}:${boundPort}${http.path}`,
    port: boundPort,
    close: async () => {
      if (reaper !== undefined) clearInterval(reaper);
      await Promise.allSettled([...sessions.keys()].map((id) => teardown(id)));
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
