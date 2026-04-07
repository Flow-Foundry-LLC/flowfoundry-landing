import type { Request, Response, NextFunction } from "express";
import { verifyGatewayToken } from "../auth/jwt.js";
import { getUser, upsertUser, type User } from "../db.js";

// Extend Express Request
declare global {
  namespace Express {
    interface Request {
      user?: User & { projects: string[] };
    }
  }
}

/**
 * Middleware that extracts and verifies the session cookie or bearer token,
 * then attaches the user to req.user
 */
export function sessionAuth(issuer: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Check cookie first, then bearer token
    const token = req.cookies?.gateway_session || req.headers.authorization?.replace("Bearer ", "");

    if (!token) {
      res.status(401).json({ error: "Not authenticated" });
      return;
    }

    try {
      const payload = await verifyGatewayToken(token, issuer);
      const user = getUser(payload.zuid);
      if (!user) {
        // Auto-create as dev on first login
        upsertUser(payload.zuid, payload.email, payload.email.split("@")[0]);
        req.user = { ...getUser(payload.zuid)!, projects: payload.projects };
      } else {
        req.user = { ...user, projects: payload.projects };
      }
      next();
    } catch {
      res.status(401).json({ error: "Invalid or expired session" });
    }
  };
}

/**
 * Require a minimum role level
 */
export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      res.status(401).json({ error: "Not authenticated" });
      return;
    }
    if (!roles.includes(req.user.role)) {
      res.status(403).json({ error: "Insufficient permissions" });
      return;
    }
    next();
  };
}
