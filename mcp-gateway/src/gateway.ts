import express from "express";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { loadConfig } from "./config.js";
import { InMemoryClientsStore } from "./auth/clients-store.js";
import { ZohoOAuthProvider } from "./auth/zoho-oauth-provider.js";
import { BackendPool } from "./router/backend-pool.js";
import { ToolAggregator } from "./router/tool-aggregator.js";
import { createProxyMcpServer } from "./router/proxy-mcp-server.js";
import { sessionAuth } from "./middleware/auth.js";
import apiRoutes, { setGatewayUrl } from "./routes/api.js";
import setupUi from "./routes/setup-ui.js";
import { handleOAuthCallback } from "./routes/oauth-service.js";
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

// ── Rate limiters ──────────────────────────────────────────────────────────

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30, // 30 attempts per window for auth endpoints
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later" },
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute for API
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later" },
});

const mcpLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200, // 200 MCP calls per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
});

// App 1: Setup UI + health (regular Express)
const setupApp = express();
setupApp.set("trust proxy", 1);

// SAML login — redirects to Zoho Directory SSO
setupApp.get("/setup/login", authLimiter, async (_req, res) => {
  try {
    const url = await getSamlLoginUrl();
    res.redirect(url);
  } catch (err) {
    console.error("[setup] SAML login error:", err);
    res.status(500).send("Failed to initiate SAML login");
  }
});

// SAML callback — Zoho POSTs the assertion here after login
setupApp.post("/setup/saml/callback", authLimiter, express.urlencoded({ extended: false }), async (req, res) => {
  try {
    const samlUser = await validateSamlResponse(req.body);
    console.log(`[setup] SAML login: ${samlUser.email}`);

    // Use email hash as user ID (SAML doesn't give us ZUID)
    const userId = samlUser.email.replace(/[^a-zA-Z0-9]/g, "_");
    upsertUser(userId, samlUser.email, samlUser.email.split("@")[0]);

    // Sign a session JWT
    const { access_token } = await signGatewayToken(
      { zuid: userId, email: samlUser.email, projects: [] },
      runtimeConfig.gateway_url, "4h"
    );

    res.setHeader("Set-Cookie", `gateway_session=${access_token}; HttpOnly; Secure; SameSite=Lax; Max-Age=14400; Path=/`);
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

// OAuth callback for per-service auth (before session middleware — external redirect)
setupApp.get("/setup/oauth/callback", (req, res) => {
  handleOAuthCallback(req, res, runtimeConfig.gateway_url);
});

// Set gateway URL for API routes
setGatewayUrl(runtimeConfig.gateway_url);

// Protected setup routes
const ss = sessionAuth(runtimeConfig.gateway_url);
setupApp.use("/setup/api", apiLimiter, cookieParser(), ss, express.json(), apiRoutes);
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

mcpApp.post("/mcp", mcpLimiter, async (req, res) => {
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
    if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
  }
});

mcpApp.delete("/mcp", (_req, res) => { res.json({ ok: true }); });

// ── HTTP server that routes to the right app ────────────────────────────────

const server = createServer((req, res) => {
  const url = req.url || "/";

  // Redirect root to setup login
  if (url === "/" || url === "") {
    res.writeHead(302, { Location: "/setup/login" });
    res.end();
    return;
  }

  // Serve static assets
  if (url === "/logo.png") {
    try {
      const __dirname = dirname(fileURLToPath(import.meta.url));
      const buf = readFileSync(join(__dirname, "..", "logo.png"));
      res.writeHead(200, { "Content-Type": "image/png", "Cache-Control": "public, max-age=86400" });
      res.end(buf);
    } catch { res.writeHead(404); res.end(); }
    return;
  }

  if (url === "/favicon.png" || url === "/favicon.ico") {
    const buf = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAACgAAAAoCAYAAACM/rhtAAAAtGVYSWZJSSoACAAAAAYAEgEDAAEAAAABAAAAGgEFAAEAAABWAAAAGwEFAAEAAABeAAAAKAEDAAEAAAACAAAAEwIDAAEAAAABAAAAaYcEAAEAAABmAAAAAAAAAGAAAAABAAAAYAAAAAEAAAAGAACQBwAEAAAAMDIxMAGRBwAEAAAAAQIDAACgBwAEAAAAMDEwMAGgAwABAAAA//8AAAKgBAABAAAAKAAAAAOgBAABAAAAKAAAAAAAAABNP10PAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAFR2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSfvu78nIGlkPSdXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQnPz4KPHg6eG1wbWV0YSB4bWxuczp4PSdhZG9iZTpuczptZXRhLyc+CjxyZGY6UkRGIHhtbG5zOnJkZj0naHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyc+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczpBdHRyaWI9J2h0dHA6Ly9ucy5hdHRyaWJ1dGlvbi5jb20vYWRzLzEuMC8nPgogIDxBdHRyaWI6QWRzPgogICA8cmRmOlNlcT4KICAgIDxyZGY6bGkgcmRmOnBhcnNlVHlwZT0nUmVzb3VyY2UnPgogICAgIDxBdHRyaWI6Q3JlYXRlZD4yMDI2LTA0LTA2PC9BdHRyaWI6Q3JlYXRlZD4KICAgICA8QXR0cmliOkRhdGE+eyZxdW90O2RvYyZxdW90OzomcXVvdDtEQUhHRjF6R1laTSZxdW90OywmcXVvdDt1c2VyJnF1b3Q7OiZxdW90O1VBRElVdjRzbWQ4JnF1b3Q7LCZxdW90O2JyYW5kJnF1b3Q7OiZxdW90O0JBRElVdVk4bW13JnF1b3Q7fTwvQXR0cmliOkRhdGE+CiAgICAgPEF0dHJpYjpFeHRJZD42YmIwYzBkMS05ZDhlLTQxNWQtOGI1ZS1iZDFhODMyMjQ1YTU8L0F0dHJpYjpFeHRJZD4KICAgICA8QXR0cmliOkZiSWQ+NTI1MjY1OTE0MTc5NTgwPC9BdHRyaWI6RmJJZD4KICAgICA8QXR0cmliOlRvdWNoVHlwZT4yPC9BdHRyaWI6VG91Y2hUeXBlPgogICAgPC9yZGY6bGk+CiAgIDwvcmRmOlNlcT4KICA8L0F0dHJpYjpBZHM+CiA8L3JkZjpEZXNjcmlwdGlvbj4KCiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0nJwogIHhtbG5zOmRjPSdodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyc+CiAgPGRjOnRpdGxlPgogICA8cmRmOkFsdD4KICAgIDxyZGY6bGkgeG1sOmxhbmc9J3gtZGVmYXVsdCc+VW50aXRsZWQgZGVzaWduIC0gMTwvcmRmOmxpPgogICA8L3JkZjpBbHQ+CiAgPC9kYzp0aXRsZT4KIDwvcmRmOkRlc2NyaXB0aW9uPgoKIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PScnCiAgeG1sbnM6cGRmPSdodHRwOi8vbnMuYWRvYmUuY29tL3BkZi8xLjMvJz4KICA8cGRmOkF1dGhvcj5CcmF5ZGVuIEJlbmd0emVuPC9wZGY6QXV0aG9yPgogPC9yZGY6RGVzY3JpcHRpb24+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczp4bXA9J2h0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8nPgogIDx4bXA6Q3JlYXRvclRvb2w+Q2FudmEgZG9jPURBSEdGMXpHWVpNIHVzZXI9VUFESVV2NHNtZDggYnJhbmQ9QkFESVV1WThtbXc8L3htcDpDcmVhdG9yVG9vbD4KIDwvcmRmOkRlc2NyaXB0aW9uPgo8L3JkZjpSREY+CjwveDp4bXBtZXRhPgo8P3hwYWNrZXQgZW5kPSdyJz8+BjNn7gAACURJREFUWIXNmAtQVecZx885e869oFWTOo7N2CRtajKdTtupk75SJ8102mk7fcx0YlAUBZGIlUQ7xmgTsTLGSUUFBVFARK6iqMUHEEDACAYfKBHx/Y5tnTRtjKYao3jP7p7z9b/n3nOlr2koqLkzO3vvOfv47f/7vt1vr6b14YdI0/tyvD79XD8XfMw9Pzx4vzn+7QPVDFXzs4E1zoX47O7PPlUffi7QQO8HyT4dl6h+fyogfZ+jM4MHiOOBS3TeInkq8MdbR+KHdX9/PwE9lboOxY2UhwDXYUq6YJFzwlrovyciXZX7A1ipMVWH24x5dMwkcZAJ6mTkdLK/0HFtqHqXlaUgNf2eq0la1LyVWkC06B3UzkjsMx3ZZrl0EN/3a79S7/m+Ud+k1qSHvLb3EtJXz27SUqjVINFiOLKVuXKv6VAHI7k/8Ip6L1pG/0Q2jtr+p9AzcfcM0p/kZkO/h5yd7AI1A6iJOfJNKLcLfngQfrgvuES1ubrj2wOd2h/fdKp+mBfte/ejm7Iik4hqtoqa4Hu1ppS1gKyDkjsA2ArQJuYBKqVF5Xfb6I2nKVwx8peRZwns7sFFTXu71JhIfzBIboFZtwGuCqUagLWWQztN4tVmpt+Hl3+jhmqeImfDd9rc/Mhpc1dM7cN9VGZ+T65jH1EF1KsA4GbAVZokt1kkqhAk1YzCW9moGGDoK29Q+deJNowguXbEi5Gx+lhF33du52rDZRF7h0KAK7McuRZw67G1bMLvjaZLmwG6yfgbFjPM72uXDG+hsieI1nyZnLVf66TQo30bMP5A1wsHPSjyrDYqBEwB/K4YMKqsNskpg1lXw/+gqrOO5cf6ZmkBXjDsLJV8kcTKxySVfIlE9pDnvHdRi/QODvudV7I0U2Yb22kZI57NpMyFcsvgg8tRrwRcPnPdFVCymF2mssDjfv+uBQ88aucMvukuH0pi+TBJhZ8nMTuwp/v4vQOMRizP1ObS64Cbz6RYgCj9PUo24HKg4FKL+CImaSV+F5pzov0Cqraz+yfS0gEkcgc6ctlnXZ4z2KUZaJeujfHaJfRCxVhQ5Go/47MNKWYzl88xXDEXcFkoChTQ9uswba5B9kKtKpZARCcWSwLFtDxAIideyrzPkFg8QNIMKD9N36Xd8cGeq+hPdAWZisw1O2mmSfYM5gCSxG9RXoUfZkLRTObQa1BkgX6+K0t75J8WVqANlkvNc7QMbZcgoPLjyZ4X58qp2I4yjDCfqn0rqnbPN29/Er7enEIwpZ1uSP4bAME8fCbKy/C7lw1XzoIas/Xw7UztR34/v29XrpFIKwCXi4UtxSKWBsieqsaCO0wH5BR9YXe1e67eLG2AXG2cIZjUnqg7HCvnLwBOgU7HsxehHhTlL2m/8yeK9V2EviuMY1TMVMQ7shhwr6BtGsAmox9AnanGRUrXBnl9e2LmWCKQbyTRGqUWc/h43RucT8YESoVfIynIgHoZ+gmY6AF/klgKVqhNpzVQrxCmLUUQvWZhkUYUEOqnY8+calL4BfaLHqsYi9wCFqJ1WPksJu0EACYjEJIBPBGAaREV7CnG2Jh60X4flASekCXGX2kdTpa1QZdnAmiC4fUTaYB+Hv6cCjNPgYoZ+vweAfpSn5+mBUWe0U6hAIXnmU44QSM+zqBwEo6xCYCbZKrJTlyZpA3w+kWTUlV4hVlH1YjcsqDkKrieA9w4LGY86hRATjTVQiVBTSfT3NJ93v8NGPWhyyv6fU4UIDPGqcGXmS5PgYJQ0R6rJjMkpQIw2cpVbSsT7gSGXW1MpqYA8ZWWA5XIfhbtx0D1sabflwQWaY/DItMQOItYO63SrE8MGdvHyuIexpn7IeF04IWWK+DgIgGDYwI+nrkEk9njtASvbXpkgvAemLbFes/FKRNO1FwPTLUfG1UwEXVi9PcYAM7A4nPYRVp0xwqfGLBrpfawKNKvUjGgik0XkUgiVQ2MrWUCJksy+Mfjta96fXAMqto5HBeikEXhZ3XJk6A42nm+pxYD89pjIxawR8NVxmGRCzFmjv6um68N7DEg5WtDRIlxicowQRFzRSkUzAHYBMMl5UvJxrUbqdoQv9/ty8HhfK35oZMCgAm6y5N1LyiUz3m1Ci61EyThfSJTW45D+Xi2WL94pUcK+peh3Zopyo29tAmDhLDRhgBYge0iD/kenNseo39wLSWyvXiAu4Jp9KoKAmzoz+N9KmBSVW14tUhRfqfg1ekD0+Zhm0KSIfOMNt9/exIokZS+Qs+nbZhgA87hjdjzkOuJLQFX7W98hn7tRsIdBfmq+A00zfBOCZ4OGEAqUD6JeduTZ+YM9Fus9kYVeIjiEqRmRYFy1T+rJ8ddbEVb2Q/crTqJSi+1R8aMwbcig65GRG5BgrBOG6HaufTTIJ8TPEmT4GOToHZa5MRQkDZOHjEH/RQYgKRaXBEWUGA4VArwVUZG9zl7/OHVeiM1YpIaJKg1qHHv4FUYvB7AtVayN3jT0P5ivfkOlWAhBbjd5anjDaUEbcrxrAIFGbcstwCI56uRO67GJl2iX6aQ9gVvjJ4mDLF/req1kU6jYTsNOBXqoJ66udVhH9yNCd4MhLy2u58xxQ52iHbhXQMUrAdMLQqUllvUFYBFADcCcAPGKbeEuhrwUmNur9SLXS93skW0n6nJhVBqNiCS1V24mb1Pb0WyZ96kr6K9AKw3hagDTB9galBXoWxXBXdlXKr4ZriG+r4ZKVzlg4OiYvQyq8YAYq+5Xv1jIJoRMLsMRzTDyduRvOy3ClUbu9kYTXsAuBMmxrXTK40oO6Jq1pguYAUp+Cp2lVdqT3a3VK/gVP1eh9ZPHDBL6ShMewCZ9R7cS/aZjvs2oA9r3hXTeds4TocQDLvhr28BZLel/mkg0Yjf9VCuBVFbz96l7dpTfQLXHdIH5YfNl5yj1nU6AzN1YC87BFN3sr/zU3FP83bz+4C8Re2m+iNJin2W47QGiA4ArBU+12g2hXdqnkv0yY3uP0B6Kw6fGvC4fcLKl0fYDTprEl0KEv05nsSxfst5pznTOWx+TKfx7GjAlQdM195jNItW9nM6GblI3bX/Z3xIf8fvOhn3iH3GmmifC6yQp+Mb5Nl+J8XZ/iH7VHC+OBJXxDvMmbcOak9W+vsqedfXe/DnESAr/4uJ6KjW31fqXxb2f5n0HxmFtSSmC4aWAAAAAElFTkSuQmCC", "base64");
    res.writeHead(200, { "Content-Type": "image/png", "Cache-Control": "public, max-age=86400" });
    res.end(buf);
    return;
  }

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
