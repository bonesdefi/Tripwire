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
    return new Upstream(config, client);
  }

  async listTools(): Promise<Tool[]> {
    const result = await this.client.listTools();
    return result.tools;
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
    const result = await this.client.callTool({ name, arguments: args });
    return result as CallToolResult;
  }

  async close(): Promise<void> {
    await this.client.close();
  }
}
