import { randomUUID, randomBytes, createHash } from "node:crypto";
import type { Request, Response } from "express";
import { getService, updateService, updateServiceOAuthTokens } from "../db.js";

// ── Pending OAuth state (in-memory, 10-min TTL) ────────────────────────────

interface PendingState {
  serviceId: number;
  createdAt: number;
  codeVerifier?: string;
}

const pendingStates = new Map<string, PendingState>();

// Cleanup expired states every 60s
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of pendingStates) {
    if (now - val.createdAt > 10 * 60 * 1000) pendingStates.delete(key);
  }
}, 60_000).unref();

// ── OAuth Discovery ────────────────────────────────────────────────────────

export async function discoverOAuthEndpoints(baseUrl: string): Promise<{
  discovered: boolean;
  authorization_endpoint?: string;
  token_endpoint?: string;
  registration_endpoint?: string;
  scopes_supported?: string[];
  code_challenge_methods_supported?: string[];
}> {
  // Extract origin (scheme + host) from URL — well-known is always at root
  let origin: string;
  try {
    const parsed = new URL(baseUrl);
    origin = parsed.origin;
  } catch {
    origin = baseUrl.replace(/\/[^/]*$/, "");
  }

  // Try RFC 8414 and OIDC discovery at the origin root
  for (const path of [
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
  ]) {
    try {
      const url = `${origin}${path}`;
      console.log(`[oauth] Trying discovery: ${url}`);
      const res = await fetch(url, {
        signal: AbortSignal.timeout(5000),
      });
      if (res.ok) {
        const data = await res.json() as Record<string, unknown>;
        if (data.authorization_endpoint && data.token_endpoint) {
          return {
            discovered: true,
            authorization_endpoint: data.authorization_endpoint as string,
            token_endpoint: data.token_endpoint as string,
            registration_endpoint: (data.registration_endpoint as string) || undefined,
            scopes_supported: (data.scopes_supported as string[]) || [],
            code_challenge_methods_supported: (data.code_challenge_methods_supported as string[]) || [],
          };
        }
      }
    } catch {
      // Try next
    }
  }
  return { discovered: false };
}

// ── Dynamic Client Registration (RFC 7591) ─────────────────────────────────

export async function registerOAuthClient(
  registrationEndpoint: string,
  gatewayUrl: string,
  clientName: string
): Promise<{ client_id: string; client_secret?: string }> {
  const res = await fetch(registrationEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: `MCP Gateway - ${clientName}`,
      redirect_uris: [`${gatewayUrl}/setup/oauth/callback`],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_post",
    }),
    signal: AbortSignal.timeout(10000),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Registration failed (${res.status}): ${body}`);
  }

  const data = await res.json() as { client_id: string; client_secret?: string };
  return { client_id: data.client_id, client_secret: data.client_secret };
}

// ── PKCE Helpers ───────────────────────────────────────────────────────────

function generateCodeVerifier(): string {
  return randomBytes(32).toString("base64url");
}

function generateCodeChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

// ── Initiate OAuth Connect ─────────────────────────────────────────────────

export function initiateOAuthConnect(
  serviceId: number,
  authorizeUrl: string,
  clientId: string,
  scope: string,
  gatewayUrl: string,
  usePkce: boolean = false
): string {
  const state = randomUUID();
  let codeVerifier: string | undefined;

  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: `${gatewayUrl}/setup/oauth/callback`,
    state,
  });

  if (usePkce) {
    codeVerifier = generateCodeVerifier();
    params.set("code_challenge", generateCodeChallenge(codeVerifier));
    params.set("code_challenge_method", "S256");
  }

  if (scope) params.set("scope", scope);

  pendingStates.set(state, { serviceId, createdAt: Date.now(), codeVerifier });

  return `${authorizeUrl}?${params.toString()}`;
}

// ── OAuth Callback Handler ─────────────────────────────────────────────────

export async function handleOAuthCallback(
  req: Request,
  res: Response,
  gatewayUrl: string
): Promise<void> {
  const { code, state, error } = req.query as Record<string, string>;

  if (error) {
    res.redirect(`/setup?oauth=error&message=${encodeURIComponent(error)}`);
    return;
  }

  if (!code || !state) {
    res.redirect("/setup?oauth=error&message=Missing+code+or+state");
    return;
  }

  const pending = pendingStates.get(state);
  if (!pending) {
    res.redirect("/setup?oauth=error&message=Invalid+or+expired+state");
    return;
  }
  pendingStates.delete(state);

  const service = getService(pending.serviceId);
  if (!service) {
    res.redirect("/setup?oauth=error&message=Service+not+found");
    return;
  }

  try {
    // Exchange authorization code for tokens
    const tokenParams: Record<string, string> = {
      grant_type: "authorization_code",
      code,
      redirect_uri: `${gatewayUrl}/setup/oauth/callback`,
      client_id: service.oauth_client_id,
    };
    if (service.oauth_client_secret) {
      tokenParams.client_secret = service.oauth_client_secret;
    }
    if (pending.codeVerifier) {
      tokenParams.code_verifier = pending.codeVerifier;
    }

    const tokenRes = await fetch(service.oauth_token_url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(tokenParams).toString(),
    });

    if (!tokenRes.ok) {
      const errBody = await tokenRes.text();
      console.error(`[oauth] Token exchange failed for service ${service.id}:`, errBody);
      res.redirect(`/setup?oauth=error&message=${encodeURIComponent("Token exchange failed")}`);
      return;
    }

    const tokens = (await tokenRes.json()) as {
      access_token: string;
      refresh_token?: string;
      expires_in?: number;
    };

    const expiresAt = tokens.expires_in
      ? new Date(Date.now() + tokens.expires_in * 1000).toISOString()
      : "";

    updateServiceOAuthTokens(
      service.id,
      tokens.access_token,
      tokens.refresh_token || "",
      expiresAt
    );

    console.log(`[oauth] Service ${service.name} (${service.id}) connected successfully`);
    res.redirect(`/setup?oauth=success&service=${encodeURIComponent(service.name)}`);
  } catch (err) {
    console.error(`[oauth] Callback error for service ${service.id}:`, err);
    res.redirect(`/setup?oauth=error&message=${encodeURIComponent(String(err))}`);
  }
}

// ── Token Refresh ──────────────────────────────────────────────────────────

export async function refreshServiceOAuthToken(service: {
  id: number;
  oauth_token_url: string;
  oauth_client_id: string;
  oauth_client_secret: string;
  oauth_refresh_token: string;
}): Promise<string> {
  const res = await fetch(service.oauth_token_url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: service.oauth_refresh_token,
      client_id: service.oauth_client_id,
      client_secret: service.oauth_client_secret,
    }).toString(),
  });

  if (!res.ok) {
    throw new Error(`Token refresh failed: ${res.status} ${await res.text()}`);
  }

  const tokens = (await res.json()) as {
    access_token: string;
    refresh_token?: string;
    expires_in?: number;
  };

  const expiresAt = tokens.expires_in
    ? new Date(Date.now() + tokens.expires_in * 1000).toISOString()
    : "";

  updateServiceOAuthTokens(
    service.id,
    tokens.access_token,
    tokens.refresh_token || service.oauth_refresh_token,
    expiresAt
  );

  return tokens.access_token;
}
