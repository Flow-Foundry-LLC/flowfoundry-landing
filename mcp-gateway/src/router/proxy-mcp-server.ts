import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { ToolAggregator } from "./tool-aggregator.js";

/**
 * Creates a per-request MCP Server that proxies tools based on user authorization
 */
export function createProxyMcpServer(
  aggregator: ToolAggregator,
  projectIds: string[]
): Server {
  const server = new Server(
    { name: "mcp-gateway", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const tools = await aggregator.getToolsForUser(projectIds);
    return {
      tools: tools.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
      })),
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    return aggregator.callTool(name, (args || {}) as Record<string, unknown>, projectIds);
  });

  return server;
}
