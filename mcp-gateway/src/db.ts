import Database from "better-sqlite3";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";

// ── Encryption helpers (AES-256-GCM) ───────────────────────────────────────

const ENC_KEY_RAW = process.env.DB_ENCRYPTION_KEY || process.env.JWT_SECRET || "";
const ENC_KEY = scryptSync(ENC_KEY_RAW, "mcp-gateway-db-enc", 32);

function encrypt(plaintext: string): string {
  if (!plaintext) return "";
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `enc:${iv.toString("base64url")}:${tag.toString("base64url")}:${encrypted.toString("base64url")}`;
}

function decrypt(ciphertext: string): string {
  if (!ciphertext) return "";
  if (!ciphertext.startsWith("enc:")) return ciphertext; // plaintext fallback for migration
  const [, ivB64, tagB64, dataB64] = ciphertext.split(":");
  const iv = Buffer.from(ivB64, "base64url");
  const tag = Buffer.from(tagB64, "base64url");
  const data = Buffer.from(dataB64, "base64url");
  const decipher = createDecipheriv("aes-256-gcm", ENC_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const DB_PATH = join(__dirname, "..", "gateway.db");

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

// ── Schema ──────────────────────────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    zuid TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'dev' CHECK (role IN ('super_admin', 'admin', 'dev')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS clients (
    project_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    prefix TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_project_id TEXT NOT NULL REFERENCES clients(project_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    api_key_env TEXT NOT NULL DEFAULT '',
    auth_type TEXT NOT NULL DEFAULT 'api_key' CHECK (auth_type IN ('api_key', 'oauth', 'none')),
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(client_project_id, name)
  );

  CREATE TABLE IF NOT EXISTS zoho_tokens (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS user_access (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_zuid TEXT NOT NULL REFERENCES users(zuid) ON DELETE CASCADE,
    service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_zuid, service_id)
  );
`);

// ── Seed super admin ────────────────────────────────────────────────────────

// Seed super admin (both ZUID and SAML email-based ID)
for (const [id, email, name] of [
  ["24042349", "brayden.b@flowfoundry.com", "Brayden Bengtzen"],
  ["brayden_b_flowfoundry_com", "brayden.b@flowfoundry.com", "Brayden Bengtzen"],  // SAML login ID
] as const) {
  const existing = db.prepare("SELECT zuid FROM users WHERE zuid = ?").get(id);
  if (!existing) {
    db.prepare("INSERT INTO users (zuid, email, name, role) VALUES (?, ?, ?, ?)").run(
      id, email, name, "super_admin"
    );
  }
}

// ── User Queries ────────────────────────────────────────────────────────────

export interface User {
  zuid: string;
  email: string;
  name: string;
  role: "super_admin" | "admin" | "dev";
}

export function getUser(zuid: string): User | undefined {
  return db.prepare("SELECT zuid, email, name, role FROM users WHERE zuid = ?").get(zuid) as User | undefined;
}

export function upsertUser(zuid: string, email: string, name: string, role?: string): User {
  // Check if user exists by ID or by email (handles SAML vs OAuth ID mismatch)
  const existing = getUser(zuid);
  const existingByEmail = db.prepare("SELECT zuid, email, name, role FROM users WHERE email = ?").get(email) as User | undefined;

  if (existing) {
    if (role) {
      db.prepare("UPDATE users SET email = ?, name = ?, role = ?, updated_at = datetime('now') WHERE zuid = ?")
        .run(email, name, role, zuid);
    } else {
      db.prepare("UPDATE users SET email = ?, name = ?, updated_at = datetime('now') WHERE zuid = ?")
        .run(email, name, zuid);
    }
  } else if (existingByEmail && existingByEmail.zuid !== zuid) {
    // Same email, different ID — update the existing record's ID to match
    // This happens when SAML login creates a different ID than OAuth login
    db.prepare("UPDATE users SET zuid = ?, name = ?, updated_at = datetime('now') WHERE email = ?")
      .run(zuid, name, email);
  } else {
    db.prepare("INSERT INTO users (zuid, email, name, role) VALUES (?, ?, ?, ?)")
      .run(zuid, email, name, role || "dev");
  }
  return getUser(zuid)!;
}

export function listUsers(): User[] {
  return db.prepare("SELECT zuid, email, name, role FROM users ORDER BY role, name").all() as User[];
}

export function setUserRole(zuid: string, role: string): void {
  db.prepare("UPDATE users SET role = ?, updated_at = datetime('now') WHERE zuid = ?").run(role, zuid);
}

export function deleteUser(zuid: string): void {
  db.prepare("DELETE FROM users WHERE zuid = ?").run(zuid);
}

// ── Client Queries ──────────────────────────────────────────────────────────

export interface ClientRow {
  project_id: string;
  name: string;
  prefix: string;
}

export function getClient(projectId: string): ClientRow | undefined {
  return db.prepare("SELECT project_id, name, prefix FROM clients WHERE project_id = ?").get(projectId) as ClientRow | undefined;
}

export function listClients(): ClientRow[] {
  return db.prepare("SELECT project_id, name, prefix FROM clients ORDER BY name").all() as ClientRow[];
}

export function upsertClient(projectId: string, name: string, prefix: string): ClientRow {
  const existing = getClient(projectId);
  if (existing) {
    db.prepare("UPDATE clients SET name = ?, prefix = ?, updated_at = datetime('now') WHERE project_id = ?")
      .run(name, prefix, projectId);
  } else {
    db.prepare("INSERT INTO clients (project_id, name, prefix) VALUES (?, ?, ?)")
      .run(projectId, name, prefix);
  }
  return getClient(projectId)!;
}

export function deleteClient(projectId: string): void {
  db.prepare("DELETE FROM clients WHERE project_id = ?").run(projectId);
}

// ── Service Queries ─────────────────────────────────────────────────────────

// ── OAuth column migration ─────────────────────────────────────────────────

const oauthColumns = [
  "oauth_client_id TEXT NOT NULL DEFAULT ''",
  "oauth_client_secret TEXT NOT NULL DEFAULT ''",
  "oauth_authorize_url TEXT NOT NULL DEFAULT ''",
  "oauth_token_url TEXT NOT NULL DEFAULT ''",
  "oauth_scope TEXT NOT NULL DEFAULT ''",
  "oauth_access_token TEXT NOT NULL DEFAULT ''",
  "oauth_refresh_token TEXT NOT NULL DEFAULT ''",
  "oauth_token_expires_at TEXT NOT NULL DEFAULT ''",
];

const existingCols = new Set(
  (db.prepare("PRAGMA table_info(services)").all() as { name: string }[]).map((c) => c.name)
);
for (const col of oauthColumns) {
  const colName = col.split(" ")[0];
  if (!existingCols.has(colName)) {
    db.exec(`ALTER TABLE services ADD COLUMN ${col}`);
  }
}

export interface ServiceRow {
  id: number;
  client_project_id: string;
  name: string;
  url: string;
  api_key_env: string;
  auth_type: string;
  enabled: number;
  oauth_client_id: string;
  oauth_client_secret: string;
  oauth_authorize_url: string;
  oauth_token_url: string;
  oauth_scope: string;
  oauth_access_token: string;
  oauth_refresh_token: string;
  oauth_token_expires_at: string;
}

function decryptServiceRow(row: ServiceRow | undefined): ServiceRow | undefined {
  if (!row) return undefined;
  return {
    ...row,
    oauth_access_token: decrypt(row.oauth_access_token),
    oauth_refresh_token: decrypt(row.oauth_refresh_token),
    oauth_client_secret: decrypt(row.oauth_client_secret),
  };
}

function decryptServiceRows(rows: ServiceRow[]): ServiceRow[] {
  return rows.map((r) => decryptServiceRow(r)!);
}

export function getService(id: number): ServiceRow | undefined {
  return decryptServiceRow(db.prepare("SELECT * FROM services WHERE id = ?").get(id) as ServiceRow | undefined);
}

export function listServicesForClient(projectId: string): ServiceRow[] {
  return decryptServiceRows(db.prepare("SELECT * FROM services WHERE client_project_id = ? ORDER BY name").all(projectId) as ServiceRow[]);
}

export function listAllServices(): ServiceRow[] {
  return decryptServiceRows(db.prepare("SELECT * FROM services ORDER BY client_project_id, name").all() as ServiceRow[]);
}

export function createService(
  clientProjectId: string, name: string, url: string, apiKeyEnv: string, authType: string = "api_key",
  oauth?: { client_id?: string; client_secret?: string; authorize_url?: string; token_url?: string; scope?: string }
): ServiceRow {
  const result = db.prepare(
    `INSERT INTO services (client_project_id, name, url, api_key_env, auth_type,
      oauth_client_id, oauth_client_secret, oauth_authorize_url, oauth_token_url, oauth_scope)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    clientProjectId, name, url, apiKeyEnv, authType,
    oauth?.client_id || "", encrypt(oauth?.client_secret || ""),
    oauth?.authorize_url || "", oauth?.token_url || "", oauth?.scope || ""
  );
  return getService(result.lastInsertRowid as number)!;
}

export function updateService(id: number, updates: Partial<{
  name: string; url: string; api_key_env: string; auth_type: string; enabled: number;
  oauth_client_id: string; oauth_client_secret: string; oauth_authorize_url: string;
  oauth_token_url: string; oauth_scope: string;
}>): ServiceRow | undefined {
  const encryptedKeys = new Set(["oauth_client_secret", "oauth_access_token", "oauth_refresh_token"]);
  const fields: string[] = [];
  const values: unknown[] = [];
  for (const [key, val] of Object.entries(updates)) {
    if (val !== undefined) {
      fields.push(`${key} = ?`);
      values.push(encryptedKeys.has(key) && typeof val === "string" ? encrypt(val) : val);
    }
  }
  if (fields.length === 0) return getService(id);
  fields.push("updated_at = datetime('now')");
  values.push(id);
  db.prepare(`UPDATE services SET ${fields.join(", ")} WHERE id = ?`).run(...values);
  return getService(id);
}

export function updateServiceOAuthTokens(
  id: number, accessToken: string, refreshToken: string, expiresAt: string
): void {
  db.prepare(
    "UPDATE services SET oauth_access_token = ?, oauth_refresh_token = ?, oauth_token_expires_at = ?, updated_at = datetime('now') WHERE id = ?"
  ).run(encrypt(accessToken), encrypt(refreshToken), expiresAt, id);
}

export function deleteService(id: number): void {
  db.prepare("DELETE FROM services WHERE id = ?").run(id);
}

// ── User Access Queries ─────────────────────────────────────────────────────

export interface UserAccessRow {
  id: number;
  user_zuid: string;
  service_id: number;
  enabled: number;
}

export function getUserAccessOverrides(zuid: string): UserAccessRow[] {
  return db.prepare("SELECT * FROM user_access WHERE user_zuid = ?").all(zuid) as UserAccessRow[];
}

export function setUserAccess(zuid: string, serviceId: number, enabled: boolean): void {
  db.prepare(
    "INSERT INTO user_access (user_zuid, service_id, enabled) VALUES (?, ?, ?) ON CONFLICT(user_zuid, service_id) DO UPDATE SET enabled = ?, updated_at = datetime('now')"
  ).run(zuid, serviceId, enabled ? 1 : 0, enabled ? 1 : 0);
}

export function deleteUserAccess(zuid: string, serviceId: number): void {
  db.prepare("DELETE FROM user_access WHERE user_zuid = ? AND service_id = ?").run(zuid, serviceId);
}

export function getUserAccessForService(serviceId: number): (UserAccessRow & { email: string; name: string })[] {
  return db.prepare(`
    SELECT ua.*, u.email, u.name FROM user_access ua
    JOIN users u ON ua.user_zuid = u.zuid
    WHERE ua.service_id = ?
  `).all(serviceId) as (UserAccessRow & { email: string; name: string })[];
}

// ── Resolved Access (combines Zoho projects + overrides) ────────────────────

export function getAuthorizedServices(zuid: string, zohoProjectIds: string[]): ServiceRow[] {
  const user = getUser(zuid);
  if (!user) return [];

  // Super admin gets everything
  if (user.role === "super_admin") {
    return listAllServices().filter((s) => s.enabled);
  }

  // Get services for user's assigned projects
  const allServices: ServiceRow[] = [];
  for (const projectId of zohoProjectIds) {
    const services = listServicesForClient(projectId);
    allServices.push(...services);
  }

  // Apply overrides
  const overrides = getUserAccessOverrides(zuid);
  const overrideMap = new Map(overrides.map((o) => [o.service_id, o.enabled]));

  return allServices.filter((s) => {
    if (!s.enabled) return false; // globally disabled
    const override = overrideMap.get(s.id);
    if (override !== undefined) return override === 1; // per-user override
    return true; // default: enabled if assigned to project
  });
}

// ── Build gateway config from DB ────────────────────────────────────────────

export interface RuntimeServiceConfig {
  name: string;
  url: string;
  api_key_env: string;
  auth_type: string;
  oauth_access_token: string;
  oauth_refresh_token: string;
  oauth_token_expires_at: string;
  oauth_token_url: string;
  oauth_client_id: string;
  oauth_client_secret: string;
}

export function buildGatewayConfig(): Record<string, { name: string; prefix: string; services: RuntimeServiceConfig[] }> {
  const clients = listClients();
  const config: Record<string, { name: string; prefix: string; services: RuntimeServiceConfig[] }> = {};

  for (const client of clients) {
    const services = listServicesForClient(client.project_id).filter((s) => s.enabled);
    if (services.length > 0) {
      config[client.project_id] = {
        name: client.name,
        prefix: client.prefix,
        services: services.map((s) => ({
          name: s.name, url: s.url, api_key_env: s.api_key_env,
          auth_type: s.auth_type,
          oauth_access_token: s.oauth_access_token,
          oauth_refresh_token: s.oauth_refresh_token,
          oauth_token_expires_at: s.oauth_token_expires_at,
          oauth_token_url: s.oauth_token_url,
          oauth_client_id: s.oauth_client_id,
          oauth_client_secret: s.oauth_client_secret,
        })),
      };
    }
  }

  return config;
}

// ── Zoho Token Storage ──────────────────────────────────────────────────────

export function setZohoToken(key: string, value: string): void {
  const encVal = encrypt(value);
  db.prepare(
    "INSERT INTO zoho_tokens (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = datetime('now')"
  ).run(key, encVal, encVal);
}

export function getZohoToken(key: string): string | undefined {
  const row = db.prepare("SELECT value FROM zoho_tokens WHERE key = ?").get(key) as { value: string } | undefined;
  return row?.value ? decrypt(row.value) : undefined;
}

export default db;
