import { randomUUID } from "node:crypto";
import type { Response } from "express";
import type { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { OAuthClientInformationFull, OAuthTokens, OAuthTokenRevocationRequest } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import {
  exchangeZohoCode,
  refreshZohoToken,
  getZohoUserProfile,
  getUserProjectIds,
  getZohoAuthUrl,
} from "./zoho-api.js";
import { signGatewayToken, verifyGatewayToken } from "./jwt.js";
import type { GatewayConfig } from "../config.js";
import { TTLCache } from "../cache.js";
import { setZohoToken } from "../db.js";

interface PendingAuth {
  codeChallenge: string;
  redirectUri: string;
  state?: string;
  clientId: string;
}

interface CompletedAuth {
  zuid: string;
  email: string;
  projects: string[];
  codeChallenge: string;
  zohoRefreshToken: string;
}

interface RefreshTokenData {
  zuid: string;
  email: string;
  zohoRefreshToken: string;
}

export class ZohoOAuthProvider implements OAuthServerProvider {
  private _clientsStore: OAuthRegisteredClientsStore;
  private config: GatewayConfig;

  // Caches
  private projectCache = new TTLCache<string[]>();

  // In-memory state for OAuth flows
  private pendingAuths = new Map<string, PendingAuth>(); // zohoState → pending auth
  private gatewayCodes = new Map<string, string>(); // gatewayCode → zohoState
  private completedAuths = new Map<string, CompletedAuth>(); // gatewayCode → completed auth
  private refreshTokens = new Map<string, RefreshTokenData>(); // refreshToken → data

  constructor(clientsStore: OAuthRegisteredClientsStore, config: GatewayConfig) {
    this._clientsStore = clientsStore;
    this.config = config;
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    return this._clientsStore;
  }

  /**
   * Step 1: Claude.ai calls /authorize
   * We redirect to Zoho's OAuth consent page
   */
  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response
  ): Promise<void> {
    const gatewayCode = randomUUID();
    const zohoState = randomUUID();

    // Store the MCP client's PKCE challenge and redirect info
    this.pendingAuths.set(zohoState, {
      codeChallenge: params.codeChallenge,
      redirectUri: params.redirectUri,
      state: params.state,
      clientId: client.client_id,
    });

    // Map gateway code to zoho state for callback correlation
    this.gatewayCodes.set(gatewayCode, zohoState);

    // Store reverse mapping: zohoState → gatewayCode
    this.pendingAuths.get(zohoState)!.clientId = client.client_id;
    // We need zohoState → gatewayCode mapping too
    (this.pendingAuths.get(zohoState)! as unknown as Record<string, string>)._gatewayCode = gatewayCode;

    // Redirect user to Zoho consent page
    const zohoAuthUrl = getZohoAuthUrl(zohoState);
    console.log(`[auth] Redirecting to Zoho OAuth for client ${client.client_id}`);
    res.redirect(zohoAuthUrl);
  }

  /**
   * Step 2: Zoho redirects back to /zoho/callback
   * This is called from the Express route handler, not from the SDK
   */
  async handleZohoCallback(code: string, state: string, res: Response): Promise<void> {
    const pending = this.pendingAuths.get(state);
    if (!pending) {
      res.status(400).send("Invalid OAuth state");
      return;
    }

    const gatewayCode = (pending as unknown as Record<string, string>)._gatewayCode;

    try {
      // Exchange Zoho auth code for tokens
      const zohoTokens = await exchangeZohoCode(code);
      console.log(`[auth] Got Zoho tokens for state ${state}`);

      // Get user profile
      const profile = await getZohoUserProfile(zohoTokens.access_token);
      console.log(`[auth] User: ${profile.email} (ZUID: ${profile.zuid})`);

      // Get user's project assignments
      const projectIds = await getUserProjectIds(
        zohoTokens.access_token,
        this.config.portal_name
      );
      console.log(`[auth] User ${profile.email} has ${projectIds.length} projects`);

      // Filter to only configured projects
      const configuredProjects = projectIds.filter((id) => id in this.config.clients);
      console.log(`[auth] ${configuredProjects.length} projects have MCP services configured`);

      // Cache projects
      this.projectCache.set(profile.zuid, configuredProjects, this.config.project_cache_ttl_ms);

      // Persist refresh token for project syncing
      if (zohoTokens.refresh_token) {
        setZohoToken("zoho_refresh_token", zohoTokens.refresh_token);
        console.log(`[auth] Stored Zoho refresh token for project syncing`);
      }

      // Store completed auth data
      this.completedAuths.set(gatewayCode, {
        zuid: profile.zuid,
        email: profile.email,
        projects: configuredProjects,
        codeChallenge: pending.codeChallenge,
        zohoRefreshToken: zohoTokens.refresh_token || "",
      });

      // Redirect back to Claude.ai with the gateway auth code
      const redirectUrl = new URL(pending.redirectUri);
      redirectUrl.searchParams.set("code", gatewayCode);
      if (pending.state) redirectUrl.searchParams.set("state", pending.state);

      // Clean up pending state
      this.pendingAuths.delete(state);

      console.log(`[auth] Redirecting back to client with gateway code`);
      res.redirect(redirectUrl.toString());
    } catch (err) {
      console.error(`[auth] Zoho callback error:`, err);
      const redirectUrl = new URL(pending.redirectUri);
      redirectUrl.searchParams.set("error", "server_error");
      redirectUrl.searchParams.set("error_description", "Failed to authenticate with Zoho");
      if (pending.state) redirectUrl.searchParams.set("state", pending.state);
      this.pendingAuths.delete(state);
      res.redirect(redirectUrl.toString());
    }
  }

  /**
   * Step 3: SDK calls this to get the PKCE challenge for the auth code
   */
  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<string> {
    const completed = this.completedAuths.get(authorizationCode);
    if (!completed) throw new Error("Invalid authorization code");
    return completed.codeChallenge;
  }

  /**
   * Step 4: Claude.ai exchanges the gateway code for tokens
   */
  async exchangeAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<OAuthTokens> {
    const completed = this.completedAuths.get(authorizationCode);
    if (!completed) throw new Error("Invalid authorization code");

    // Sign a gateway JWT
    const { access_token, expires_in } = await signGatewayToken(
      { zuid: completed.zuid, email: completed.email, projects: completed.projects },
      this.config.gateway_url,
      this.config.jwt_expiry
    );

    // Generate a refresh token
    const refreshToken = randomUUID();
    this.refreshTokens.set(refreshToken, {
      zuid: completed.zuid,
      email: completed.email,
      zohoRefreshToken: completed.zohoRefreshToken,
    });

    // Clean up one-time auth code
    this.completedAuths.delete(authorizationCode);

    console.log(`[auth] Issued JWT for ${completed.email} with ${completed.projects.length} projects`);

    return {
      access_token,
      token_type: "bearer",
      expires_in,
      refresh_token: refreshToken,
    };
  }

  /**
   * Step 5: Claude.ai refreshes the token
   * Re-checks Zoho project membership
   */
  async exchangeRefreshToken(
    _client: OAuthClientInformationFull,
    refreshToken: string
  ): Promise<OAuthTokens> {
    const data = this.refreshTokens.get(refreshToken);
    if (!data) throw new Error("Invalid refresh token");

    // Use cached projects if available, otherwise re-fetch from Zoho
    let projects: string[] = this.projectCache.get(data.zuid) || [];

    if (projects.length === 0) {
      try {
        const zohoTokens = await refreshZohoToken(data.zohoRefreshToken);
        const projectIds = await getUserProjectIds(
          zohoTokens.access_token,
          this.config.portal_name
        );
        projects = projectIds.filter((id) => id in this.config.clients);
        this.projectCache.set(data.zuid, projects, this.config.project_cache_ttl_ms);
        console.log(`[auth] Refreshed token for ${data.email}, ${projects.length} projects (from Zoho)`);
      } catch (err) {
        console.error(`[auth] Zoho refresh failed for ${data.email}:`, err);
        this.refreshTokens.delete(refreshToken);
        throw new Error("Zoho authentication failed — account may be deactivated");
      }
    } else {
      console.log(`[auth] Refreshed token for ${data.email}, ${projects.length} projects (cached)`);
    }

    const { access_token, expires_in } = await signGatewayToken(
      { zuid: data.zuid, email: data.email, projects },
      this.config.gateway_url,
      this.config.jwt_expiry
    );

    // Keep same refresh token (don't rotate — Claude.ai doesn't handle rotation well)
    return {
      access_token,
      token_type: "bearer",
      expires_in,
      refresh_token: refreshToken,
    };
  }

  /**
   * Validates a gateway JWT on every /mcp request
   */
  async verifyAccessToken(token: string): Promise<AuthInfo> {
    try {
      const payload = await verifyGatewayToken(token, this.config.gateway_url);
      console.log(`[auth] Token verified for ${payload.email}`);
      return {
        token,
        clientId: payload.zuid,
        scopes: [],
        extra: {
          zuid: payload.zuid,
          email: payload.email,
          projects: payload.projects,
        },
      };
    } catch (err) {
      console.error(`[auth] Token verification failed:`, err);
      throw err;
    }
  }

  async revokeToken(
    _client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest
  ): Promise<void> {
    if (request.token_type_hint === "refresh_token") {
      this.refreshTokens.delete(request.token);
    }
  }
}
