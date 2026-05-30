import { type Request, type Response, type NextFunction } from "express";
import type { AuthUser } from "@workspace/api-zod";
import { db, usersTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { getSession } from "../lib/auth";

declare global {
  namespace Express {
    interface User extends AuthUser {}

    interface Request {
      isAuthenticated(): this is AuthedRequest;
      user?: User | undefined;
    }

    export interface AuthedRequest {
      user: User;
    }
  }
}

// Only accept UUID v4 tokens (used as anonymous user IDs)
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export async function authMiddleware(
  req: Request,
  _res: Response,
  next: NextFunction,
) {
  req.isAuthenticated = function (this: Request) {
    return this.user != null;
  } as Request["isAuthenticated"];

  // ── 1. Cookie-based OIDC session (highest priority) ──────────────────────
  const sid = req.cookies?.["sid"] as string | undefined;
  if (sid) {
    try {
      const session = await getSession(sid);
      if (session?.user) {
        req.user = session.user;
        next();
        return;
      }
    } catch {
      // non-fatal — fall through to Bearer token check
    }
  }

  // ── 2. Bearer UUID token (anonymous / localStorage-based auth) ───────────
  const authHeader = req.headers["authorization"];
  if (!authHeader?.startsWith("Bearer ")) {
    next();
    return;
  }

  const token = authHeader.slice(7).trim();
  if (!UUID_V4.test(token)) {
    next();
    return;
  }

  try {
    // Auto-create user on first request — the UUID IS the user ID
    await db
      .insert(usersTable)
      .values({
        id: token,
        email: null,
        firstName: null,
        lastName: null,
        profileImageUrl: null,
      })
      .onConflictDoNothing();

    const [dbUser] = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.id, token));

    if (dbUser) {
      req.user = {
        id: dbUser.id,
        email: dbUser.email,
        firstName: dbUser.firstName,
        lastName: dbUser.lastName,
        profileImageUrl: dbUser.profileImageUrl,
      };
    }
  } catch {
    // non-fatal — proceed unauthenticated
  }

  next();
}
