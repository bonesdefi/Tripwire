import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
  type CallToolResult,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';

import { AuditLog } from '../audit/log.js';
import type { UpstreamConfig } from '../policy/config.js';
import { canonicalHash } from '../receipts/canonical.js';
import { ReceiptLedger } from '../receipts/ledger.js';
import { Upstream } from './upstream.js';

/**
 * The Tripwire proxy core: an MCP server facing the agent, an MCP client to
 * each upstream. Tools are merged and re-exposed as
 * `<upstream>__<tool>`; descriptions, schemas and annotations pass through
 * verbatim, and call results are forwarded byte-for-byte. Every result is
 * receipted (Tier 0) and audited before it returns to the agent.
 */

export const NAMESPACE_SEPARATOR = '__';

export interface ProxyOptions {
  upstreams: UpstreamConfig[];
  ledger: ReceiptLedger;
  audit: AuditLog;
  version?: string;
}

export function namespaceTool(upstream: string, tool: string): string {
  return `${upstream}${NAMESPACE_SEPARATOR}${tool}`;
}

export function parseNamespacedTool(name: string): { upstream: string; tool: string } | undefined {
  const idx = name.indexOf(NAMESPACE_SEPARATOR);
  if (idx <= 0 || idx + NAMESPACE_SEPARATOR.length >= name.length) return undefined;
  return {
    upstream: name.slice(0, idx),
    tool: name.slice(idx + NAMESPACE_SEPARATOR.length),
  };
}

export class TripwireProxy {
  private readonly server: Server;
  private readonly upstreamConfigs: UpstreamConfig[];
  private readonly upstreams = new Map<string, Upstream>();
  private readonly ledger: ReceiptLedger;
  private readonly audit: AuditLog;

  constructor(options: ProxyOptions) {
    this.upstreamConfigs = options.upstreams;
    this.ledger = options.ledger;
    this.audit = options.audit;
    this.server = new Server(
      { name: 'tripwire', version: options.version ?? '0.1.0' },
      { capabilities: { tools: {} } },
    );
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: await this.mergedTools(),
    }));
    this.server.setRequestHandler(CallToolRequestSchema, async (request) =>
      this.forwardToolCall(request.params.name, request.params.arguments ?? {}),
    );
  }

  /** Connect all upstreams, then start serving the agent on `transport`. */
  async start(transport: Transport): Promise<void> {
    for (const config of this.upstreamConfigs) {
      try {
        const upstream = await Upstream.connect(config);
        this.upstreams.set(config.name, upstream);
        this.audit.append('upstream_connected', { upstream: config.name, trust: config.trust });
      } catch (err) {
        this.audit.append('upstream_connect_failed', {
          upstream: config.name,
          error: err instanceof Error ? err.message : String(err),
        });
        await this.closeUpstreams();
        throw new Error(`failed to connect upstream "${config.name}": ${String(err)}`);
      }
    }
    await this.server.connect(transport);
    this.audit.append('proxy_started', {
      session: this.ledger.sessionId,
      upstreams: this.upstreamConfigs.map((u) => u.name),
    });
  }

  async close(): Promise<void> {
    await this.server.close().catch(() => undefined);
    await this.closeUpstreams();
    this.audit.append('proxy_stopped', {});
  }

  private async closeUpstreams(): Promise<void> {
    await Promise.allSettled([...this.upstreams.values()].map((u) => u.close()));
    this.upstreams.clear();
  }

  private async mergedTools(): Promise<Tool[]> {
    const perUpstream = await Promise.all(
      [...this.upstreams.values()].map(async (upstream) => {
        const tools = await upstream.listTools();
        // Everything except the name passes through verbatim.
        return tools.map((tool) => ({ ...tool, name: namespaceTool(upstream.name, tool.name) }));
      }),
    );
    const tools = perUpstream.flat();
    this.audit.append('tools_listed', {
      count: tools.length,
      tools: tools.map((t) => t.name),
    });
    return tools;
  }

  private async forwardToolCall(
    name: string,
    args: Record<string, unknown>,
  ): Promise<CallToolResult> {
    const parsed = parseNamespacedTool(name);
    const upstream = parsed === undefined ? undefined : this.upstreams.get(parsed.upstream);
    if (parsed === undefined || upstream === undefined) {
      this.audit.append('tool_call_rejected', { tool: name, reason: 'unknown_tool' });
      throw new McpError(ErrorCode.InvalidParams, `Unknown tool: ${name}`);
    }

    const startedAt = Date.now();
    let result: CallToolResult;
    try {
      result = await upstream.callTool(parsed.tool, args);
    } catch (err) {
      this.audit.append('tool_call_failed', {
        tool: name,
        upstream: upstream.name,
        args_hash: canonicalHash(args),
        error: err instanceof Error ? err.message : String(err),
        latency_ms: Date.now() - startedAt,
      });
      if (err instanceof McpError) throw err;
      throw new McpError(
        ErrorCode.InternalError,
        `Upstream "${upstream.name}" failed: ${String(err)}`,
      );
    }

    // Tier 0: receipt the real execution before the agent ever sees it.
    const receipt = this.ledger.record({
      tool: name,
      upstream: upstream.name,
      args,
      result,
    });
    this.audit.append('tool_call', {
      tool: name,
      upstream: upstream.name,
      receipt_seq: receipt.seq,
      args_hash: receipt.args_hash,
      result_hash: receipt.result_hash,
      is_error: result.isError === true,
      decision: 'pass',
      latency_ms: Date.now() - startedAt,
    });
    return result;
  }
}
