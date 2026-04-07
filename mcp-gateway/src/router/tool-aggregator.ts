import { BackendPool } from "./backend-pool.js";
import type { GatewayConfig } from "../config.js";

interface PrefixedTool {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
}

interface ToolRoute {
  backendKey: string;
  originalToolName: string;
}

export class ToolAggregator {
  private pool: BackendPool;
  private config: GatewayConfig;

  constructor(pool: BackendPool, config: GatewayConfig) {
    this.pool = pool;
    this.config = config;
  }

  /**
   * Get all tools the user is authorized to see, prefixed by client
   */
  async getToolsForUser(projectIds: string[]): Promise<PrefixedTool[]> {
    const backendKeys = this.pool.getAuthorizedBackendKeys(projectIds);
    const allTools: PrefixedTool[] = [];

    for (const key of backendKeys) {
      const [prefix, serviceName] = key.split(":");

      // Find client name for description
      let clientName = prefix;
      for (const client of Object.values(this.config.clients)) {
        if (client.prefix === prefix) {
          clientName = client.name;
          break;
        }
      }

      const tools = await this.pool.listTools(key);
      for (const tool of tools) {
        allTools.push({
          name: `${prefix}_${tool.name}`,
          description: `[${clientName}] ${tool.description || tool.name}`,
          inputSchema: tool.inputSchema,
        });
      }
    }

    return allTools;
  }

  /**
   * Parse a prefixed tool name back to backend key + original name
   */
  parseToolName(prefixedName: string): ToolRoute | null {
    for (const client of Object.values(this.config.clients)) {
      const prefix = client.prefix + "_";
      if (prefixedName.startsWith(prefix)) {
        const remainder = prefixedName.slice(prefix.length);

        // Find which service owns this tool
        for (const service of client.services) {
          const backendKey = `${client.prefix}:${service.name}`;
          // We need to check if the backend has this tool
          // For now, try each service in order
          return { backendKey, originalToolName: remainder };
        }
      }
    }
    return null;
  }

  /**
   * Route and call a prefixed tool
   */
  async callTool(
    prefixedName: string,
    args: Record<string, unknown>,
    projectIds: string[]
  ): Promise<{ content: Array<{ type: string; text: string }> }> {
    // Verify the user has access to this tool's client
    const authorizedKeys = this.pool.getAuthorizedBackendKeys(projectIds);

    // Try each authorized backend to find the one that owns this tool
    for (const client of Object.values(this.config.clients)) {
      const prefix = client.prefix + "_";
      if (!prefixedName.startsWith(prefix)) continue;

      const originalToolName = prefixedName.slice(prefix.length);

      // Try each service in this client
      for (const service of client.services) {
        const backendKey = `${client.prefix}:${service.name}`;

        // Check authorization
        if (!authorizedKeys.includes(backendKey)) continue;

        // Check if this backend has the tool
        const tools = await this.pool.listTools(backendKey);
        if (tools.some((t) => t.name === originalToolName)) {
          return this.pool.callTool(backendKey, originalToolName, args);
        }
      }
    }

    throw new Error(`Tool not found or unauthorized: ${prefixedName}`);
  }
}
