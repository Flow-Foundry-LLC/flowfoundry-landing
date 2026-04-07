import { SignJWT, jwtVerify } from "jose";

const getSecret = () => new TextEncoder().encode(process.env.JWT_SECRET!);

export interface GatewayTokenPayload {
  zuid: string;
  email: string;
  projects: string[];
}

export async function signGatewayToken(
  payload: GatewayTokenPayload,
  issuer: string,
  expiry: string = "8h"
): Promise<{ access_token: string; expires_in: number }> {
  const expirySeconds = parseExpiry(expiry);

  const token = await new SignJWT({
    email: payload.email,
    projects: payload.projects,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(issuer)
    .setSubject(payload.zuid)
    .setIssuedAt()
    .setExpirationTime(expiry)
    .sign(getSecret());

  return { access_token: token, expires_in: expirySeconds };
}

export async function verifyGatewayToken(
  token: string,
  issuer: string
): Promise<GatewayTokenPayload> {
  const { payload } = await jwtVerify(token, getSecret(), { issuer });

  return {
    zuid: payload.sub!,
    email: payload.email as string,
    projects: payload.projects as string[],
  };
}

function parseExpiry(expiry: string): number {
  const match = expiry.match(/^(\d+)([smhd])$/);
  if (!match) return 28800; // default 8h
  const [, num, unit] = match;
  const multipliers: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 };
  return parseInt(num) * (multipliers[unit] || 3600);
}
