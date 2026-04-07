import { readFileSync } from "node:fs";
import { z } from "zod";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ServiceSchema = z.object({
  name: z.string(),
  url: z.string().url(),
  api_key_env: z.string(),
});

const ClientSchema = z.object({
  name: z.string(),
  prefix: z.string().regex(/^[a-z0-9]+$/),
  services: z.array(ServiceSchema).min(1),
});

const ConfigSchema = z.object({
  portal_name: z.string(),
  gateway_url: z.string().url(),
  project_cache_ttl_ms: z.number().default(300000),
  jwt_expiry: z.string().default("8h"),
  clients: z.record(z.string(), ClientSchema),
});

export type GatewayConfig = z.infer<typeof ConfigSchema>;
export type ServiceConfig = z.infer<typeof ServiceSchema>;
export type ClientConfig = z.infer<typeof ClientSchema>;

export function loadConfig(): GatewayConfig {
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const configPath = join(__dirname, "..", "config.json");
  const raw = JSON.parse(readFileSync(configPath, "utf-8"));
  return ConfigSchema.parse(raw);
}
