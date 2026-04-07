import { Router } from "express";
import { requireRole } from "../middleware/auth.js";
import * as db from "../db.js";
import { refreshZohoToken, getUserProjectIds } from "../auth/zoho-api.js";

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
  res.json(db.listServicesForClient(req.params.projectId));
});

api.post("/clients/:projectId/services", requireRole("super_admin", "admin"), (req, res) => {
  const { name, url, api_key_env, auth_type } = req.body;
  if (!name || !url) {
    res.status(400).json({ error: "name and url are required" });
    return;
  }
  const service = db.createService(req.params.projectId, name, url, api_key_env || "", auth_type || "api_key");
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
