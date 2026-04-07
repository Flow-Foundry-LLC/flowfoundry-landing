import { Router } from "express";
import { requireRole } from "../middleware/auth.js";
import * as db from "../db.js";
import { refreshZohoToken, getUserProjectIds } from "../auth/zoho-api.js";
import { discoverOAuthEndpoints, initiateOAuthConnect, registerOAuthClient } from "./oauth-service.js";

const api = Router();

// ── Clients ─────────────────────────────────────────────────────────────────

api.get("/clients", requireRole("super_admin", "admin"), (_req, res) => {
  res.json(db.listClients());
});

api.post("/clients", requireRole("super_admin"), (req, res) => {
  const { project_id, name, prefix } = req.body;
  if (!project_id || !name || !prefix) {
    res.status(400).json({ error: "project_id, name, and prefix are required" });
    return;
  }
  const client = db.upsertClient(project_id, name, prefix);
  res.json(client);
});

api.delete("/clients/:projectId", requireRole("super_admin"), (req, res) => {
  db.deleteClient(req.params.projectId);
  res.json({ ok: true });
});

// ── Services ────────────────────────────────────────────────────────────────

api.get("/clients/:projectId/services", requireRole("super_admin", "admin"), (req, res) => {
  const services = db.listServicesForClient(req.params.projectId).map((s) => ({
    ...s,
    oauth_client_secret: s.oauth_client_secret ? "***" : "",
    oauth_access_token: s.oauth_access_token ? "***" : "",
    oauth_refresh_token: s.oauth_refresh_token ? "***" : "",
  }));
  res.json(services);
});

api.get("/services/next-port", requireRole("super_admin", "admin"), (_req, res) => {
  const clients = db.listClients();
  let maxPort = 3099;
  for (const client of clients) {
    const services = db.listServicesForClient(client.project_id);
    for (const s of services) {
      const match = s.url.match(/:(\d+)/);
      if (match) {
        const port = parseInt(match[1]);
        if (port > maxPort) maxPort = port;
      }
    }
  }
  res.json({ port: maxPort + 1 });
});

api.post("/clients/:projectId/services", requireRole("super_admin", "admin"), (req, res) => {
  const { name, url, api_key_env, auth_type,
    oauth_client_id, oauth_client_secret, oauth_authorize_url, oauth_token_url, oauth_scope } = req.body;
  if (!name || !url) {
    res.status(400).json({ error: "name and url are required" });
    return;
  }
  const service = db.createService(req.params.projectId, name, url, api_key_env || "", auth_type || "api_key", {
    client_id: oauth_client_id, client_secret: oauth_client_secret,
    authorize_url: oauth_authorize_url, token_url: oauth_token_url, scope: oauth_scope,
  });
  res.json(service);
});

api.put("/services/:id", requireRole("super_admin", "admin"), (req, res) => {
  const id = parseInt(req.params.id);
  const service = db.updateService(id, req.body);
  if (!service) {
    res.status(404).json({ error: "Service not found" });
    return;
  }
  res.json(service);
});

api.delete("/services/:id", requireRole("super_admin"), (req, res) => {
  db.deleteService(parseInt(req.params.id));
  res.json({ ok: true });
});

// ── Service OAuth ──────────────────────────────────────────────────────────

api.post("/oauth-discover", requireRole("super_admin", "admin"), async (req, res) => {
  const { url } = req.body;
  if (!url) { res.status(400).json({ error: "url is required" }); return; }
  const result = await discoverOAuthEndpoints(url);
  res.json(result);
});

let _gatewayUrl = "";
export function setGatewayUrl(url: string) { _gatewayUrl = url; }

api.get("/services/:id/oauth-connect", requireRole("super_admin", "admin"), async (req, res) => {
  let service = db.getService(parseInt(req.params.id));
  if (!service) { res.status(404).json({ error: "Service not found" }); return; }
  if (service.auth_type !== "oauth") { res.status(400).json({ error: "Service is not OAuth type" }); return; }

  let authorizeUrl = service.oauth_authorize_url;
  let tokenUrl = service.oauth_token_url;
  let clientId = service.oauth_client_id;
  let usePkce = false;
  let registrationEndpoint = "";

  // Always try discovery to detect PKCE requirements
  const discovered = await discoverOAuthEndpoints(service.url);
  if (discovered.discovered) {
    usePkce = (discovered.code_challenge_methods_supported || []).includes("S256");
    registrationEndpoint = discovered.registration_endpoint || "";

    if (!authorizeUrl) {
      authorizeUrl = discovered.authorization_endpoint!;
      tokenUrl = discovered.token_endpoint!;
      db.updateService(service.id, {
        oauth_authorize_url: authorizeUrl,
        oauth_token_url: tokenUrl,
        oauth_scope: discovered.scopes_supported?.join(" ") || service.oauth_scope,
      });
      console.log(`[oauth] Auto-discovered endpoints for ${service.name}: ${authorizeUrl}`);
    }
  } else if (!authorizeUrl) {
    // No discovery and no saved endpoints — can't proceed
    res.status(400).json({
      error: "Could not auto-discover OAuth endpoints. Please configure them in Advanced settings.",
      needs_config: true,
    });
    return;
  }

  // If discovery didn't detect PKCE but the authorize URL looks like Zoho, force PKCE
  if (!usePkce && authorizeUrl.includes("zoho")) {
    usePkce = true;
  }

  // Step 2: Dynamic client registration if no client_id
  if (!clientId) {
    if (registrationEndpoint) {
      try {
        const reg = await registerOAuthClient(registrationEndpoint, _gatewayUrl, service.name);
        clientId = reg.client_id;
        db.updateService(service.id, {
          oauth_client_id: clientId,
          oauth_client_secret: reg.client_secret || "",
        });
        console.log(`[oauth] Dynamically registered client for ${service.name}: ${clientId}`);
      } catch (err) {
        console.error(`[oauth] Dynamic registration failed for ${service.name}:`, err);
        res.status(400).json({
          error: "Dynamic client registration failed. Please enter Client ID manually in Advanced settings.",
          needs_config: true,
        });
        return;
      }
    } else {
      res.status(400).json({
        error: "No registration endpoint available. Please enter Client ID in Advanced settings.",
        needs_config: true,
      });
      return;
    }
  }

  // Reload service to get any updates
  service = db.getService(service.id)!;

  const redirectUrl = initiateOAuthConnect(
    service.id, authorizeUrl, clientId,
    service.oauth_scope, _gatewayUrl, usePkce
  );
  res.json({ redirect_url: redirectUrl });
});

// ── Users ───────────────────────────────────────────────────────────────────

api.get("/users", requireRole("super_admin"), (_req, res) => {
  res.json(db.listUsers());
});

api.put("/users/:zuid/role", requireRole("super_admin"), (req, res) => {
  const { role } = req.body;
  if (!["super_admin", "admin", "dev"].includes(role)) {
    res.status(400).json({ error: "Invalid role" });
    return;
  }
  db.setUserRole(req.params.zuid, role);
  res.json(db.getUser(req.params.zuid));
});

api.delete("/users/:zuid", requireRole("super_admin"), (req, res) => {
  db.deleteUser(req.params.zuid);
  res.json({ ok: true });
});

// ── User Access Overrides ───────────────────────────────────────────────────

api.get("/users/:zuid/access", requireRole("super_admin"), (req, res) => {
  const overrides = db.getUserAccessOverrides(req.params.zuid);
  res.json(overrides);
});

api.put("/users/:zuid/access/:serviceId", requireRole("super_admin"), (req, res) => {
  const { enabled } = req.body;
  if (typeof enabled !== "boolean") {
    res.status(400).json({ error: "enabled must be a boolean" });
    return;
  }
  db.setUserAccess(req.params.zuid, parseInt(req.params.serviceId), enabled);
  res.json({ ok: true });
});

api.delete("/users/:zuid/access/:serviceId", requireRole("super_admin"), (req, res) => {
  db.deleteUserAccess(req.params.zuid, parseInt(req.params.serviceId));
  res.json({ ok: true });
});

// ── Sync Projects from Zoho ─────────────────────────────────────────────────

api.post("/sync-projects", requireRole("super_admin", "admin"), async (_req, res) => {
  const storedToken = db.getZohoToken("zoho_refresh_token");
  if (!storedToken) {
    res.status(400).json({
      error: "No Zoho refresh token stored. Connect to the MCP gateway from Claude.ai first to authorize Zoho access."
    });
    return;
  }

  try {
    // Refresh the Zoho token
    const zohoTokens = await refreshZohoToken(storedToken);

    // Store updated refresh token if provided
    if (zohoTokens.refresh_token) {
      db.setZohoToken("zoho_refresh_token", zohoTokens.refresh_token);
    }

    // Fetch all projects from Zoho
    const portalName = process.env.ZOHO_PORTAL_NAME || "flowfoundry";
    const projectIds = await getUserProjectIds(zohoTokens.access_token, portalName);

    // Check which are already in the DB
    const existingClients = db.listClients();
    const existingIds = new Set(existingClients.map((c) => c.project_id));

    // We need project names — fetch them from the API
    const ZOHO_DOMAIN = process.env.ZOHO_DOMAIN || "zoho.com";
    const projectsRes = await fetch(
      `https://projectsapi.${ZOHO_DOMAIN}/restapi/portal/${portalName}/projects/?range=100&index=1`,
      { headers: { Authorization: `Zoho-oauthtoken ${zohoTokens.access_token}` } }
    );
    const projectsData = (await projectsRes.json()) as {
      projects?: Array<{ id: number; id_string?: string; name: string }>
    };

    const added: string[] = [];
    for (const p of projectsData.projects || []) {
      const id = p.id_string || String(p.id);
      if (!existingIds.has(id)) {
        // Auto-generate prefix from name
        const prefix = p.name.toLowerCase().replace(/[^a-z0-9]+/g, "").slice(0, 20);
        db.upsertClient(id, p.name, prefix);
        added.push(p.name);
      }
    }

    res.json({
      total_projects: projectsData.projects?.length || 0,
      already_existed: existingClients.length,
      newly_added: added.length,
      added_clients: added,
    });
  } catch (err) {
    console.error("[sync] Error:", err);
    res.status(500).json({ error: "Failed to sync: " + String(err) });
  }
});

// ── Current user info ───────────────────────────────────────────────────────

api.get("/me", (req, res) => {
  res.json(req.user);
});

export default api;
