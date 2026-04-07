import express from "express";
import cookieParser from "cookie-parser";
import { createServer } from "node:http";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { loadConfig } from "./config.js";
import { InMemoryClientsStore } from "./auth/clients-store.js";
import { ZohoOAuthProvider } from "./auth/zoho-oauth-provider.js";
import { BackendPool } from "./router/backend-pool.js";
import { ToolAggregator } from "./router/tool-aggregator.js";
import { createProxyMcpServer } from "./router/proxy-mcp-server.js";
import { sessionAuth } from "./middleware/auth.js";
import apiRoutes from "./routes/api.js";
import setupUi from "./routes/setup-ui.js";
import { buildGatewayConfig, getAuthorizedServices, upsertUser, listClients } from "./db.js";
import { verifyGatewayToken, signGatewayToken } from "./auth/jwt.js";
import { exchangeZohoCode, getZohoUserProfile, getUserProjectIds } from "./auth/zoho-api.js";
import { getLoginUrl as getSamlLoginUrl, validateResponse as validateSamlResponse } from "./auth/saml.js";

// ── Validate env vars ───────────────────────────────────────────────────────

for (const key of ["ZOHO_CLIENT_ID", "ZOHO_CLIENT_SECRET", "ZOHO_REDIRECT_URI", "JWT_SECRET"]) {
  if (!process.env[key]) { console.error(`Missing: ${key}`); process.exit(1); }
}

// ── Config ──────────────────────────────────────────────────────────────────

const fileConfig = loadConfig();
const PORT = parseInt(process.env.PORT || "3000", 10);

function getRuntimeConfig() {
  const dbClients = buildGatewayConfig();
  return { ...fileConfig, clients: Object.keys(dbClients).length > 0 ? dbClients : fileConfig.clients };
}

const runtimeConfig = getRuntimeConfig();
console.log(`[gateway] Portal: ${runtimeConfig.portal_name}, URL: ${runtimeConfig.gateway_url}`);

// ── Backend pool ────────────────────────────────────────────────────────────

const pool = new BackendPool(runtimeConfig);
await pool.initialize();

// ── Auth ────────────────────────────────────────────────────────────────────

const clientsStore = new InMemoryClientsStore();
const oauthProvider = new ZohoOAuthProvider(clientsStore, runtimeConfig);

// ══════════════════════════════════════════════════════════════════════════════
// TWO EXPRESS APPS sharing one HTTP server to avoid mcpAuthRouter conflicts
// ══════════════════════════════════════════════════════════════════════════════

// App 1: Setup UI + health (regular Express)
const setupApp = express();
setupApp.set("trust proxy", 1);

// SAML login — redirects to Zoho Directory SSO
setupApp.get("/setup/login", async (_req, res) => {
  try {
    const url = await getSamlLoginUrl();
    res.redirect(url);
  } catch (err) {
    console.error("[setup] SAML login error:", err);
    res.status(500).send("Failed to initiate SAML login");
  }
});

// SAML callback — Zoho POSTs the assertion here after login
setupApp.post("/setup/saml/callback", express.urlencoded({ extended: false }), async (req, res) => {
  try {
    const samlUser = await validateSamlResponse(req.body);
    console.log(`[setup] SAML login: ${samlUser.email}`);

    // Use email hash as user ID (SAML doesn't give us ZUID)
    const userId = samlUser.email.replace(/[^a-zA-Z0-9]/g, "_");
    upsertUser(userId, samlUser.email, samlUser.email.split("@")[0]);

    // Sign a session JWT
    const { access_token } = await signGatewayToken(
      { zuid: userId, email: samlUser.email, projects: [] },
      runtimeConfig.gateway_url, "24h"
    );

    res.setHeader("Set-Cookie", `gateway_session=${access_token}; HttpOnly; Secure; SameSite=Lax; Max-Age=86400; Path=/`);
    res.redirect("/setup");
  } catch (err) {
    console.error("[setup] SAML callback error:", err);
    res.status(400).send("SAML authentication failed. Make sure you have access to the MCP Gateway app in Zoho Directory.");
  }
});

setupApp.get("/health", (_req, res) => {
  res.json({ status: "ok", server: "mcp-gateway", clients: listClients().map((c) => c.name) });
});

setupApp.get("/zoho/callback", async (req, res) => {
  const { code, state, error } = req.query as Record<string, string>;
  if (error) { res.status(400).send(`Zoho error: ${error}`); return; }
  if (!code || !state) { res.status(400).send("Missing code or state"); return; }
  await oauthProvider.handleZohoCallback(code, state, res);
});

// Protected setup routes
const ss = sessionAuth(runtimeConfig.gateway_url);
setupApp.use("/setup/api", cookieParser(), ss, express.json(), apiRoutes);
setupApp.use("/setup", cookieParser(), ss, setupUi);

// App 2: MCP OAuth + endpoint (uses mcpAuthRouter)
const mcpApp = express();
mcpApp.set("trust proxy", 1);

mcpApp.use(
  mcpAuthRouter({
    provider: oauthProvider,
    issuerUrl: new URL(runtimeConfig.gateway_url),
    serviceDocumentationUrl: new URL("https://www.flowfoundry.com"),
    scopesSupported: ["mcp:tools"],
  })
);

mcpApp.post("/mcp", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) { res.status(401).json({ error: "Missing bearer token" }); return; }

  let tokenPayload;
  try { tokenPayload = await verifyGatewayToken(authHeader.slice(7), runtimeConfig.gateway_url); }
  catch { res.status(401).json({ error: "Invalid token" }); return; }

  const authorizedServices = getAuthorizedServices(tokenPayload.zuid, tokenPayload.projects);
  const projectIds = [...new Set(authorizedServices.map((s) => s.client_project_id))];

  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);

  let parsedBody;
  try { parsedBody = JSON.parse(Buffer.concat(chunks).toString("utf-8")); }
  catch { res.status(400).json({ jsonrpc: "2.0", error: { code: -32700, message: "Parse error" }, id: null }); return; }

  console.log(`[mcp] ${tokenPayload.email} | ${parsedBody?.method || "unknown"} | ${authorizedServices.length} services`);

  try {
    const currentConfig = getRuntimeConfig();
    const currentPool = new BackendPool(currentConfig);
    await currentPool.initialize();
    const agg = new ToolAggregator(currentPool, currentConfig);
    const proxyServer = createProxyMcpServer(agg, projectIds);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    await proxyServer.connect(transport);
    await transport.handleRequest(req, res, parsedBody);
  } catch (err) {
    console.error("[mcp] Error:", err);
    if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: String(err) }, id: null });
  }
});

mcpApp.delete("/mcp", (_req, res) => { res.json({ ok: true }); });

// ── HTTP server that routes to the right app ────────────────────────────────

const server = createServer((req, res) => {
  const url = req.url || "/";

  // Routes handled by setupApp
  if (url.startsWith("/setup") || url === "/health" || url.startsWith("/zoho/callback")) {
    setupApp(req, res);
    return;
  }

  // Everything else (/.well-known/*, /authorize, /token, /register, /mcp, etc.)
  mcpApp(req, res);
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`[gateway] MCP Gateway running on http://127.0.0.1:${PORT}`);
  console.log(`[gateway] Setup: ${runtimeConfig.gateway_url}/setup/login`);
  console.log(`[gateway] MCP: ${runtimeConfig.gateway_url}/mcp`);
});

// ── Auto-sync projects every 15 minutes ─────────────────────────────────────

async function autoSyncProjects() {
  const { getZohoToken, listClients, upsertClient } = await import("./db.js");
  const { refreshZohoToken, getUserProjectIds } = await import("./auth/zoho-api.js");

  const storedToken = getZohoToken("zoho_refresh_token");
  if (!storedToken) return; // No token yet — skip silently

  try {
    const zohoTokens = await refreshZohoToken(storedToken);
    if (zohoTokens.refresh_token) {
      const { setZohoToken } = await import("./db.js");
      setZohoToken("zoho_refresh_token", zohoTokens.refresh_token);
    }

    const ZOHO_DOMAIN = process.env.ZOHO_DOMAIN || "zoho.com";
    const portalName = runtimeConfig.portal_name;
    const projectsRes = await fetch(
      `https://projectsapi.${ZOHO_DOMAIN}/restapi/portal/${portalName}/projects/?range=100&index=1`,
      { headers: { Authorization: `Zoho-oauthtoken ${zohoTokens.access_token}` } }
    );
    const projectsData = (await projectsRes.json()) as {
      projects?: Array<{ id: number; id_string?: string; name: string }>
    };

    const existing = new Set(listClients().map((c) => c.project_id));
    let added = 0;

    for (const p of projectsData.projects || []) {
      const id = p.id_string || String(p.id);
      if (!existing.has(id)) {
        const prefix = p.name.toLowerCase().replace(/[^a-z0-9]+/g, "").slice(0, 20);
        upsertClient(id, p.name, prefix);
        console.log(`[sync] Auto-added client: ${p.name} (${id})`);
        added++;
      }
    }

    if (added > 0) console.log(`[sync] Added ${added} new client(s)`);
  } catch (err) {
    console.error("[sync] Auto-sync error:", err);
  }
}

// Run immediately on startup, then every 15 minutes
setTimeout(autoSyncProjects, 10_000);
setInterval(autoSyncProjects, 15 * 60 * 1000);
