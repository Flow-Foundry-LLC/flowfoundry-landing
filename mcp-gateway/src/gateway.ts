import express from "express";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
// bearerAuth handled manually in /mcp handler
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { loadConfig } from "./config.js";
import { InMemoryClientsStore } from "./auth/clients-store.js";
import { ZohoOAuthProvider } from "./auth/zoho-oauth-provider.js";
import { BackendPool } from "./router/backend-pool.js";
import { ToolAggregator } from "./router/tool-aggregator.js";
import { createProxyMcpServer } from "./router/proxy-mcp-server.js";

// ── Validate required env vars ──────────────────────────────────────────────

const required = ["ZOHO_CLIENT_ID", "ZOHO_CLIENT_SECRET", "ZOHO_REDIRECT_URI", "JWT_SECRET"];
for (const key of required) {
  if (!process.env[key]) {
    console.error(`Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

// ── Load config and initialize ──────────────────────────────────────────────

const config = loadConfig();
const PORT = parseInt(process.env.PORT || "3000", 10);

console.log(`[gateway] Loading config: ${Object.keys(config.clients).length} clients configured`);
console.log(`[gateway] Portal: ${config.portal_name}`);
console.log(`[gateway] Gateway URL: ${config.gateway_url}`);

// ── Initialize backend pool ─────────────────────────────────────────────────

const pool = new BackendPool(config);
await pool.initialize();

// ── Initialize auth ─────────────────────────────────────────────────────────

const clientsStore = new InMemoryClientsStore();
const oauthProvider = new ZohoOAuthProvider(clientsStore, config);
const aggregator = new ToolAggregator(pool, config);

// ── Express app ─────────────────────────────────────────────────────────────

const app = express();

// Trust nginx proxy
app.set("trust proxy", 1);

// CORS
app.use((_req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, MCP-Protocol-Version, Accept"
  );
  if (_req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  next();
});

// Request logging (before everything else)
app.use((req, _res, next) => {
  console.log(`[http] ${req.method} ${req.url}`);
  next();
});

// ── OAuth routes (installed at root by SDK) ─────────────────────────────────

app.use(
  mcpAuthRouter({
    provider: oauthProvider,
    issuerUrl: new URL(config.gateway_url),
    serviceDocumentationUrl: new URL("https://www.flowfoundry.com"),
    scopesSupported: ["mcp:tools"],
  })
);

// ── Zoho OAuth callback (our custom route) ──────────────────────────────────

app.get("/zoho/callback", async (req, res) => {
  const { code, state, error } = req.query as Record<string, string>;

  if (error) {
    console.error(`[auth] Zoho returned error: ${error}`);
    res.status(400).send(`Zoho authentication error: ${error}`);
    return;
  }

  if (!code || !state) {
    res.status(400).send("Missing code or state parameter");
    return;
  }

  await oauthProvider.handleZohoCallback(code, state, res);
});

// ── Health check ────────────────────────────────────────────────────────────

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    server: "mcp-gateway",
    clients: Object.values(config.clients).map((c) => c.name),
  });
});

// ── MCP endpoint (protected by bearer auth) ─────────────────────────────────

app.post("/mcp", async (req, res) => {
  // Manual bearer auth check (bypass middleware to avoid body issues)
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Missing bearer token" });
    return;
  }

  let authInfo;
  try {
    authInfo = await oauthProvider.verifyAccessToken(authHeader.slice(7));
  } catch (err) {
    console.error("[mcp] Token verification failed:", err);
    res.status(401).json({ error: "Invalid token" });
    return;
  }

  const projectIds = (authInfo.extra?.projects as string[]) || [];

  // Read body manually
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  const bodyStr = Buffer.concat(chunks).toString("utf-8");

  let parsedBody;
  try {
    parsedBody = JSON.parse(bodyStr);
  } catch {
    res.status(400).json({ jsonrpc: "2.0", error: { code: -32700, message: "Parse error" }, id: null });
    return;
  }

  const method = parsedBody?.method || (Array.isArray(parsedBody) ? "batch" : "unknown");
  console.log(`[mcp] ${authInfo.extra?.email} | ${method} | ${projectIds.length} projects`);

  try {
    const proxyServer = createProxyMcpServer(aggregator, projectIds);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });
    await proxyServer.connect(transport);
    await transport.handleRequest(req, res, parsedBody);
  } catch (err) {
    console.error("[mcp] Handler error:", err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: String(err) },
        id: null,
      });
    }
  }
});

// ── Handle DELETE /mcp for session cleanup ──────────────────────────────────

app.delete("/mcp", async (_req, res) => {
  res.status(200).json({ ok: true });
});

// ── Error handler ───────────────────────────────────────────────────────────

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error("[error]", err);
  if (!res.headersSent) {
    res.status(500).json({ error: err.message });
  }
});

// ── Start ───────────────────────────────────────────────────────────────────

app.listen(PORT, "127.0.0.1", () => {
  console.log(`[gateway] MCP Gateway running on http://127.0.0.1:${PORT}`);
  console.log(`[gateway] OAuth: ${config.gateway_url}/.well-known/oauth-authorization-server`);
  console.log(`[gateway] MCP endpoint: ${config.gateway_url}/mcp`);
  console.log(`[gateway] Zoho callback: ${config.gateway_url}/zoho/callback`);
});
