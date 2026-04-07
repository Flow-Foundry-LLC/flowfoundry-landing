const ZOHO_DOMAIN = process.env.ZOHO_DOMAIN || "zoho.com";
const ACCOUNTS_URL = `https://accounts.${ZOHO_DOMAIN}`;
const PROJECTS_API_URL = `https://projectsapi.${ZOHO_DOMAIN}`;

interface ZohoTokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
  error?: string;
}

interface ZohoUserProfile {
  zuid: string;
  email: string;
  display_name: string;
}

export async function exchangeZohoCode(code: string): Promise<ZohoTokenResponse> {
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: process.env.ZOHO_CLIENT_ID!,
    client_secret: process.env.ZOHO_CLIENT_SECRET!,
    redirect_uri: process.env.ZOHO_REDIRECT_URI!,
    code,
  });

  const res = await fetch(`${ACCOUNTS_URL}/oauth/v2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });

  const data = (await res.json()) as ZohoTokenResponse;
  if (data.error) throw new Error(`Zoho token error: ${data.error}`);
  return data;
}

export async function refreshZohoToken(refreshToken: string): Promise<ZohoTokenResponse> {
  const params = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: process.env.ZOHO_CLIENT_ID!,
    client_secret: process.env.ZOHO_CLIENT_SECRET!,
    refresh_token: refreshToken,
  });

  const res = await fetch(`${ACCOUNTS_URL}/oauth/v2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });

  const data = (await res.json()) as ZohoTokenResponse;
  if (data.error) throw new Error(`Zoho refresh error: ${data.error}`);
  return data;
}

export async function getZohoUserProfile(accessToken: string): Promise<ZohoUserProfile> {
  const res = await fetch(`${ACCOUNTS_URL}/oauth/user/info`, {
    headers: { Authorization: `Zoho-oauthtoken ${accessToken}` },
  });

  const data = (await res.json()) as Record<string, unknown>;
  if (data.error) throw new Error(`Zoho user info error: ${data.error}`);

  return {
    zuid: String(data.ZUID || data.zuid),
    email: String(data.Email || data.email),
    display_name: String(data.Display_Name || data.display_name || data.First_Name || ""),
  };
}

export async function getUserProjectIds(
  accessToken: string,
  portalName: string
): Promise<string[]> {
  const projectIds: string[] = [];

  // First, try to get the portal ID from the portals list
  let portalId = portalName;
  try {
    const portalsUrl = `${PROJECTS_API_URL}/restapi/portals/`;
    console.log(`[zoho-api] Fetching portals from: ${portalsUrl}`);
    const portalsRes = await fetch(portalsUrl, {
      headers: { Authorization: `Zoho-oauthtoken ${accessToken}` },
    });
    if (portalsRes.ok) {
      const portalsData = (await portalsRes.json()) as { portals?: Array<{ id: number; id_string?: string; name: string }> };
      console.log(`[zoho-api] Found ${portalsData.portals?.length || 0} portals`);
      const portal = portalsData.portals?.find(
        (p) => p.name.toLowerCase() === portalName.toLowerCase() || String(p.id) === portalName || p.id_string === portalName
      );
      if (portal) {
        portalId = portal.id_string || String(portal.id);
        console.log(`[zoho-api] Resolved portal "${portalName}" → ID ${portalId}`);
      } else {
        console.log(`[zoho-api] Portals found:`, portalsData.portals?.map((p) => `${p.name} (${p.id})`));
      }
    } else {
      const errText = await portalsRes.text();
      console.error(`[zoho-api] Portals API ${portalsRes.status}: ${errText}`);
    }
  } catch (err) {
    console.error(`[zoho-api] Failed to fetch portals:`, err);
  }

  // Now fetch projects using the resolved portal ID
  let page = 1;
  const perPage = 100;

  while (true) {
    // Try v3 API first, fall back to REST API
    const url = `${PROJECTS_API_URL}/restapi/portal/${portalId}/projects/?range=${perPage}&index=${(page - 1) * perPage + 1}`;
    console.log(`[zoho-api] Fetching projects: ${url}`);
    const res = await fetch(url, {
      headers: { Authorization: `Zoho-oauthtoken ${accessToken}` },
    });

    if (!res.ok) {
      const errText = await res.text();
      console.error(`[zoho-api] Projects API ${res.status}: ${errText}`);
      break;
    }

    const data = (await res.json()) as { projects?: Array<{ id: number; id_string?: string; name: string }> };
    const projects = data.projects || [];
    console.log(`[zoho-api] Got ${projects.length} projects on page ${page}`);
    if (projects.length === 0) break;

    for (const p of projects) {
      const id = p.id_string || String(p.id);
      console.log(`[zoho-api]   Project: ${p.name} (${id})`);
      projectIds.push(id);
    }

    if (projects.length < perPage) break;
    page++;
  }

  return projectIds;
}

export function getZohoAuthUrl(state: string): string {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: process.env.ZOHO_CLIENT_ID!,
    scope: "ZohoProjects.projects.READ,AaaServer.profile.READ",
    redirect_uri: process.env.ZOHO_REDIRECT_URI!,
    access_type: "offline",
    prompt: "consent",
    state,
  });

  return `${ACCOUNTS_URL}/oauth/v2/auth?${params.toString()}`;
}
