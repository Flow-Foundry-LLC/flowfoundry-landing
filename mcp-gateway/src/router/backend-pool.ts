import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { TTLCache } from "../cache.js";
import type { GatewayConfig, ClientConfig } from "../config.js";

interface BackendConnection {
  client: Client;
  transport: StreamableHTTPClientTransport;
  apiKey: string;
  available: boolean;
}

interface ToolInfo {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
}

export class BackendPool {
  private backends = new Map<string, BackendConnection>(); // "prefix:serviceName" → connection
  private config: GatewayConfig;
  private toolCache = new TTLCache<ToolInfo[]>();

  constructor(config: GatewayConfig) {
    this.config = config;
  }

  async initialize(): Promise<void> {
    for (const [projectId, client] of Object.entries(this.config.clients)) {
      for (const service of client.services) {
        const key = `${client.prefix}:${service.name}`;
        const apiKey = process.env[service.api_key_env];

        if (!apiKey) {
          console.warn(`[pool] Missing env var ${service.api_key_env} for ${key}, skipping`);
          continue;
        }

        try {
          await this.connectBackend(key, service.url, apiKey);
          console.log(`[pool] Connected: ${key} → ${service.url}`);
        } catch (err) {
          console.warn(`[pool] Failed to connect ${key}: ${err}. Will retry.`);
          this.backends.set(key, {
            client: null!,
            transport: null!,
            apiKey,
            available: false,
          });
        }
      }
    }

    // Background reconnection for failed backends
    setInterval(() => this.reconnectFailed(), 30_000).unref();
  }

  private async connectBackend(key: string, url: string, apiKey: string): Promise<void> {
    const transport = new StreamableHTTPClientTransport(new URL(`${url}/mcp`), {
      requestInit: {
        headers: {
          Authorization: `Bearer ${apiKey}`,
        },
      },
    });

    const client = new Client({ name: "mcp-gateway", version: "1.0.0" });
    await client.connect(transport);

    this.backends.set(key, { client, transport, apiKey, available: true });
  }

  private async reconnectFailed(): Promise<void> {
    for (const [key, backend] of this.backends) {
      if (backend.available) continue;

      // Find the service URL from config
      const [prefix, serviceName] = key.split(":");
      let serviceUrl = "";
      for (const client of Object.values(this.config.clients)) {
        if (client.prefix === prefix) {
          const svc = client.services.find((s) => s.name === serviceName);
          if (svc) serviceUrl = svc.url;
        }
      }

      if (!serviceUrl) continue;

      try {
        await this.connectBackend(key, serviceUrl, backend.apiKey);
        console.log(`[pool] Reconnected: ${key}`);
      } catch {
        // Still failing, will retry next cycle
      }
    }
  }

  /**
   * Get all backend keys that the user is authorized for based on project IDs
   */
  getAuthorizedBackendKeys(projectIds: string[]): string[] {
    const keys: string[] = [];
    for (const projectId of projectIds) {
      const client = this.config.clients[projectId];
      if (!client) continue;
      for (const service of client.services) {
        const key = `${client.prefix}:${service.name}`;
        const backend = this.backends.get(key);
        if (backend?.available) keys.push(key);
      }
    }
    return keys;
  }

  /**
   * List tools from a specific backend, with caching
   */
  async listTools(backendKey: string): Promise<ToolInfo[]> {
    const cached = this.toolCache.get(backendKey);
    if (cached) return cached;

    const backend = this.backends.get(backendKey);
    if (!backend?.available) return [];

    try {
      const result = await backend.client.listTools();
      const tools = (result.tools || []).map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema as Record<string, unknown>,
      }));
      this.toolCache.set(backendKey, tools, 60_000); // cache 60s
      return tools;
    } catch (err) {
      console.error(`[pool] Failed to list tools from ${backendKey}:`, err);
      backend.available = false;
      return [];
    }
  }

  /**
   * Call a tool on a specific backend
   */
  async callTool(
    backendKey: string,
    toolName: string,
    args: Record<string, unknown>
  ): Promise<{ content: Array<{ type: string; text: string }> }> {
    const backend = this.backends.get(backendKey);
    if (!backend?.available) {
      throw new Error(`Backend ${backendKey} is unavailable`);
    }

    const result = await backend.client.callTool({ name: toolName, arguments: args });
    return result as { content: Array<{ type: string; text: string }> };
  }
}
