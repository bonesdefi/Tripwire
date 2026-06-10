import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import {
  StdioClientTransport,
  getDefaultEnvironment,
} from '@modelcontextprotocol/sdk/client/stdio.js';
import type { CallToolResult, Tool } from '@modelcontextprotocol/sdk/types.js';

import type { UpstreamConfig } from '../policy/config.js';

/**
 * One connected upstream MCP server. Tripwire is an MCP client to each of
 * these and re-exposes their tools to the agent under
 * `<upstream-name>__<tool-name>`.
 */
export class Upstream {
  readonly name: string;
  readonly trust: 'trusted' | 'untrusted';
  private readonly client: Client;
  // Cache of upstream tool definitions, refreshed on every listTools(); the
  // policy engine matches on annotations (e.g. destructiveHint) at call time.
  private readonly toolCache = new Map<string, Tool>();

  private constructor(config: UpstreamConfig, client: Client) {
    this.name = config.name;
    this.trust = config.trust;
    this.client = client;
  }

  static async connect(config: UpstreamConfig): Promise<Upstream> {
    const [command, ...args] = config.command;
    const transport = new StdioClientTransport({
      command,
      args,
      env: { ...getDefaultEnvironment(), ...config.env },
      // Upstream diagnostics surface on the proxy's stderr; stdout stays
      // reserved for the MCP protocol.
      stderr: 'inherit',
    });
    const client = new Client({ name: 'tripwire-proxy', version: '0.1.0' });
    await client.connect(transport);
    const upstream = new Upstream(config, client);
    await upstream.listTools(); // warm the tool cache; also validates the upstream
    return upstream;
  }

  async listTools(): Promise<Tool[]> {
    const result = await this.client.listTools();
    this.toolCache.clear();
    for (const tool of result.tools) this.toolCache.set(tool.name, tool);
    return result.tools;
  }

  /** Last-known definition of an upstream tool (bare, un-namespaced name). */
  getCachedTool(name: string): Tool | undefined {
    return this.toolCache.get(name);
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
    const result = await this.client.callTool({ name, arguments: args });
    return result as CallToolResult;
  }

  async close(): Promise<void> {
    await this.client.close();
  }
}
