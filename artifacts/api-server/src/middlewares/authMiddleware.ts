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

  // Legacy anonymous identities are read-only-compatible: an existing row is
  // still honoured, a NEW one is never minted.
  //
  // This is what makes signing in mandatory. Until now any browser could invent
  // a UUID, send it as a bearer token, and be handed a brand-new account with
  // no email, no password and nothing tying it to a person — so "log in" was
  // effectively optional, and an account was a string in localStorage that died
  // with the browser profile.
  //
  // Existing anonymous rows keep working during the changeover rather than
  // being cut off, because their scans, credits and monitors hang off that id
  // and registering PROMOTES the same row in place (see routes/account.ts) —
  // so those users can claim their history instead of losing it. Set
  // ALLOW_LEGACY_ANONYMOUS_BEARER=false to close the path completely once
  // they have had the chance.
  if (process.env["ALLOW_LEGACY_ANONYMOUS_BEARER"] === "false") {
    next();
    return;
  }

  try {
    const [dbUser] = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.id, token));

    // No row for this UUID: an unrecognised token is now simply not
    // authenticated, where it used to CREATE the account it named.
    if (!dbUser) {
      next();
      return;
    }

    // Registering converts an anonymous row into an account in place, keeping
    // the same id. Without this check the original UUID would keep working as a
    // bearer token for that account forever — a password-equivalent credential
    // that survives every password change and cannot be revoked. Once a row is
    // a real account, the only way in is a session cookie.
    //
    // The test is "has an email", not "has a password". A Google account has no
    // password, so keying on passwordHash alone would leave every
    // Google-only account reachable through its original UUID — reopening
    // exactly the hole this check exists to close. Anonymous rows are created
    // with a null email and never gain one except by registering.
    if (dbUser?.passwordHash || dbUser?.email) {
      next();
      return;
    }

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
