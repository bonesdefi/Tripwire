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
import { buildPacket } from '../consensus/packet.js';
import { runPanel } from '../consensus/panel.js';
import type { ConsensusResult } from '../consensus/types.js';
import type { VerifierClient, VerifierFactory } from '../consensus/verifier.js';
import {
  INTENT_TOOL,
  INTENT_TOOL_NAME,
  IntentArgsSchema,
  intentAck,
  invalidIntent,
  type DeclaredIntentRecord,
} from '../intent/declare.js';
import type { DefaultsConfig, RuleConfig, UpstreamConfig } from '../policy/config.js';
import { findRule } from '../policy/match.js';
import { ProvenanceIndex, indexExecution, type Origin } from '../provenance/index.js';
import { evaluateTier1 } from '../provenance/tier1.js';
import { canonicalHash } from '../receipts/canonical.js';
import { ReceiptLedger } from '../receipts/ledger.js';
import {
  blockResult,
  consensusFailedBlock,
  holdBlock,
  intentRequiredBlock,
  provenanceBlock,
  summarizeChecks,
  unmatchedToolBlock,
} from './block.js';
import { Upstream } from './upstream.js';

/**
 * The Tripwire proxy core: an MCP server facing the agent, an MCP client to
 * each upstream. Tools are merged and re-exposed as
 * `<upstream>__<tool>`; descriptions, schemas and annotations pass through
 * verbatim, and call results are forwarded byte-for-byte.
 *
 * Verification pipeline on each call:
 *  - policy match (first rule wins; unmatched calls follow defaults)
 *  - intent requirement (block until tripwire__declare_intent is on file)
 *  - Tier 1 provenance enforcement of sensitive parameters (structural)
 *  - Tier 2 multi-model consensus when the rule demands it
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
  /** Builds Tier 2 verifier clients from `provider/model` panel entries. */
  verifierFactory?: VerifierFactory;
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
  private readonly verifierFactory: VerifierFactory | undefined;
  private readonly provenance = new ProvenanceIndex();
  private declaredIntent: DeclaredIntentRecord | null = null;

  constructor(options: ProxyOptions) {
    this.upstreamConfigs = options.upstreams;
    this.ledger = options.ledger;
    this.audit = options.audit;
    this.rules = options.rules ?? [];
    this.defaults = options.defaults ?? { on_unmatched: 'pass', audit: 'all' };
    this.verifierFactory = options.verifierFactory;
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
    const tools = [...perUpstream.flat(), INTENT_TOOL];
    this.audit.append('tools_listed', {
      count: tools.length,
      tools: tools.map((t) => t.name),
    });
    return tools;
  }

  /** Handle the synthetic intent tool: validate, receipt, remember. */
  private handleDeclareIntent(args: Record<string, unknown>): CallToolResult {
    const parsed = IntentArgsSchema.safeParse(args);
    if (!parsed.success) {
      const message = parsed.error.issues.map((i) => i.message).join('; ');
      this.audit.append('intent_rejected', { error: message });
      return invalidIntent(message);
    }
    // The declaration is receipted like any other tool execution; only the
    // goal's hash reaches the audit log (the full text lives in receipts).
    const receipt = this.ledger.record({
      tool: INTENT_TOOL_NAME,
      upstream: 'tripwire',
      args: parsed.data,
      result: { status: 'intent_recorded' },
    });
    this.declaredIntent = {
      goal: parsed.data.goal,
      plan_summary: parsed.data.plan_summary,
      receipt_seq: receipt.seq,
      ts: receipt.ts,
    };
    this.audit.append('intent_declared', {
      goal_hash: canonicalHash(parsed.data.goal),
      receipt_seq: receipt.seq,
    });
    return intentAck(receipt.seq);
  }

  /**
   * Panel entries become clients via the factory; an entry that cannot be
   * constructed (unknown provider, no factory) becomes a client that always
   * errors, which fail-closed aggregation counts as a failed verdict.
   */
  private buildVerifiers(panel: string[]): VerifierClient[] {
    return panel.map((id) => {
      try {
        if (this.verifierFactory === undefined) {
          throw new Error('no verifier factory configured');
        }
        return this.verifierFactory(id);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return { id, verify: () => Promise.reject(new Error(message)) };
      }
    });
  }

  private async forwardToolCall(
    name: string,
    args: Record<string, unknown>,
  ): Promise<CallToolResult> {
    if (name === INTENT_TOOL_NAME) return this.handleDeclareIntent(args);

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

    // --- Intent requirement ----------------------------------------------
    if (rule !== undefined && rule.verify.require_intent && this.declaredIntent === null) {
      this.audit.append('tool_call_blocked', {
        tool: name,
        upstream: upstream.name,
        code: 'intent_required',
        args_hash: canonicalHash(args),
        latency_ms: Date.now() - startedAt,
      });
      return blockResult(intentRequiredBlock(name));
    }

    // --- Tier 1: provenance enforcement (structural, no models) ---------
    let tier1Annotations: Record<string, unknown> = {};
    let tier1Origins: Record<string, Origin[]> = {};
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
      tier1Origins = tier1.annotations;
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

    // --- Tier 2: multi-model consensus (high-stakes only) ----------------
    let consensus: ConsensusResult | undefined;
    if (rule !== undefined && rule.verify.tiers.includes('consensus')) {
      const { packet, packetHash } = buildPacket({
        tool: name,
        args,
        toolDef: upstream.getCachedTool(parsed.tool),
        intent: this.declaredIntent,
        provenance: tier1Origins,
        receipts: this.ledger.list(),
      });
      consensus = await runPanel(this.buildVerifiers(rule.verify.panel), packet, packetHash, {
        checks: rule.verify.checks,
        quorum: rule.verify.quorum,
        failMode: rule.verify.fail_mode,
        timeoutMs: rule.verify.timeout_ms,
      });
      if (consensus.decision === 'fail') {
        this.audit.append('tool_call_blocked', {
          tool: name,
          upstream: upstream.name,
          code: 'consensus_failed',
          tier: 'consensus',
          on_fail: rule.verify.on_fail,
          args_hash: canonicalHash(args),
          packet_hash: consensus.packet_hash,
          checks: summarizeChecks(consensus),
          consensus_latency_ms: consensus.latency_ms,
          latency_ms: Date.now() - startedAt,
        });
        return blockResult(
          rule.verify.on_fail === 'hold' ? holdBlock(name) : consensusFailedBlock(name, consensus),
        );
      }
    }

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
    // the tool's trust label (see indexExecution).
    indexExecution(
      this.provenance,
      { upstream: upstream.name, trust: upstream.trust, tool: name, receipt_seq: receipt.seq },
      args,
      result,
    );
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
      ...(consensus === undefined
        ? {}
        : {
            consensus: {
              decision: consensus.decision,
              packet_hash: consensus.packet_hash,
              latency_ms: consensus.latency_ms,
              checks: consensus.checks.map((c) => ({
                check: c.check,
                prompt_version: c.prompt_version,
                passed: c.passed,
                disagreement: c.disagreement,
              })),
            },
          }),
      latency_ms: Date.now() - startedAt,
    });
    return result;
  }
}
