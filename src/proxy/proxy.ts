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
import type { DefaultsConfig, RuleConfig, UpstreamConfig } from '../policy/config.js';
import { findRule } from '../policy/match.js';
import { extractForms } from '../provenance/extract.js';
import { ProvenanceIndex } from '../provenance/index.js';
import { evaluateTier1 } from '../provenance/tier1.js';
import { canonicalHash } from '../receipts/canonical.js';
import { ReceiptLedger } from '../receipts/ledger.js';
import { blockResult, holdBlock, provenanceBlock, unmatchedToolBlock } from './block.js';
import { Upstream } from './upstream.js';

/**
 * The Tripwire proxy core: an MCP server facing the agent, an MCP client to
 * each upstream. Tools are merged and re-exposed as
 * `<upstream>__<tool>`; descriptions, schemas and annotations pass through
 * verbatim, and call results are forwarded byte-for-byte.
 *
 * Verification pipeline on each call:
 *  - policy match (first rule wins; unmatched calls follow defaults)
 *  - Tier 1 provenance enforcement of sensitive parameters (structural)
 *  - forward to the upstream
 *  - Tier 0 receipt + provenance indexing of the result, then audit
 */

export const NAMESPACE_SEPARATOR = '__';

export interface ProxyOptions {
  upstreams: UpstreamConfig[];
  ledger: ReceiptLedger;
  audit: AuditLog;
  rules?: RuleConfig[];
  defaults?: DefaultsConfig;
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
  private readonly rules: RuleConfig[];
  private readonly defaults: DefaultsConfig;
  private readonly provenance = new ProvenanceIndex();

  constructor(options: ProxyOptions) {
    this.upstreamConfigs = options.upstreams;
    this.ledger = options.ledger;
    this.audit = options.audit;
    this.rules = options.rules ?? [];
    this.defaults = options.defaults ?? { on_unmatched: 'pass', audit: 'all' };
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

    // --- Policy match (first rule wins) ---------------------------------
    const rule = findRule(this.rules, {
      tool: name,
      upstream: upstream.name,
      annotations: upstream.getCachedTool(parsed.tool)?.annotations,
    });
    if (rule === undefined && this.defaults.on_unmatched === 'block') {
      this.audit.append('tool_call_blocked', {
        tool: name,
        upstream: upstream.name,
        code: 'unmatched_tool',
        args_hash: canonicalHash(args),
        latency_ms: Date.now() - startedAt,
      });
      return blockResult(unmatchedToolBlock(name));
    }

    // --- Tier 1: provenance enforcement (structural, no models) ---------
    let tier1Annotations: Record<string, unknown> = {};
    if (rule !== undefined && rule.verify.tiers.includes('provenance')) {
      const tier1 = evaluateTier1(rule.sensitive_params, args, this.provenance);
      if (!tier1.ok) {
        this.audit.append('tool_call_blocked', {
          tool: name,
          upstream: upstream.name,
          code: 'provenance_violation',
          tier: 'provenance',
          on_fail: rule.verify.on_fail,
          args_hash: canonicalHash(args),
          violations: tier1.violations.map((v) => ({
            param: v.param,
            reason: v.reason,
            required: v.required,
            origins: v.origins.map((o) => ({
              upstream: o.upstream,
              tool: o.tool,
              trust: o.trust,
              receipt_seq: o.receipt_seq,
            })),
          })),
          latency_ms: Date.now() - startedAt,
        });
        return blockResult(
          rule.verify.on_fail === 'hold'
            ? holdBlock(name)
            : provenanceBlock(name, tier1.violations),
        );
      }
      tier1Annotations = Object.fromEntries(
        Object.entries(tier1.annotations).map(([param, origins]) => [
          param,
          origins.map((o) => ({
            upstream: o.upstream,
            trust: o.trust,
            receipt_seq: o.receipt_seq,
          })),
        ]),
      );
    }

    // Tier 2 (consensus) arrives in Phase 3. A rule listing it today means
    // the tier is *not configured*, which is different from a verifier
    // failing at runtime — so the call proceeds, loudly flagged in audit.
    const consensusSkipped =
      rule !== undefined && rule.verify.tiers.includes('consensus') ? true : undefined;
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

    // Tier 0: receipt the real execution before the agent ever sees it,
    // then index its values for Tier 1 provenance tracing.
    const receipt = this.ledger.record({
      tool: name,
      upstream: upstream.name,
      args,
      result,
    });
    // Failed executions are not evidence, and echoed inputs must not gain
    // the tool's trust label (see ProvenanceIndex.indexResult).
    if (result.isError !== true) {
      this.provenance.indexResult(
        { upstream: upstream.name, trust: upstream.trust, tool: name, receipt_seq: receipt.seq },
        result,
        extractForms(args),
      );
    }
    this.audit.append('tool_call', {
      tool: name,
      upstream: upstream.name,
      receipt_seq: receipt.seq,
      args_hash: receipt.args_hash,
      result_hash: receipt.result_hash,
      is_error: result.isError === true,
      decision: 'pass',
      ...(rule !== undefined ? { rule: this.rules.indexOf(rule) } : {}),
      ...(Object.keys(tier1Annotations).length > 0 ? { tier1_provenance: tier1Annotations } : {}),
      ...(consensusSkipped === true ? { consensus: 'skipped_not_configured' } : {}),
      latency_ms: Date.now() - startedAt,
    });
    return result;
  }
}
