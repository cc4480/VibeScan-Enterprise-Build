import * as client from "openid-client";
import crypto from "crypto";
import { type Request, type Response } from "express";
import { db, sessionsTable, sessionUserIdExpr } from "@workspace/db";
import { eq, lt, sql } from "drizzle-orm";
import type { AuthUser } from "@workspace/api-zod";

export const ISSUER_URL = process.env.ISSUER_URL ?? "https://replit.com/oidc";
export const SESSION_COOKIE = "sid";
export const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;

/**
 * What a session holds. Only the user: the upstream OIDC access and refresh
 * tokens used to be stored here in plaintext, and nothing ever read them back.
 * They are no longer written, and migration 0032 strips them from existing rows.
 */
export interface SessionData {
  user: AuthUser;
}

/**
 * Accepted by createSession/updateSession so that callers which still pass the
 * old token fields (googleAuth.ts, accountShared.ts) keep type-checking. The
 * fields are dropped before anything is written: persistedSession() keeps
 * `user` and nothing else.
 */
export type SessionInput = SessionData & {
  access_token?: unknown;
  refresh_token?: unknown;
  expires_at?: unknown;
};

/**
 * The value stored in sessions.sid. The cookie carries the raw id; the table
 * only ever holds its SHA-256, so a leaked table cannot be replayed as cookies.
 * Same scheme as api_tokens and auth_tokens. Must match the SQL in migration
 * 0031, which hashes pre-existing rows with sha256 over the UTF-8 bytes.
 */
export function hashSessionId(sid: string): string {
  return crypto.createHash("sha256").update(sid).digest("hex");
}

function persistedSession(data: SessionInput): Record<string, unknown> {
  return { user: data.user };
}

let oidcConfig: client.Configuration | null = null;

export async function getOidcConfig(): Promise<client.Configuration> {
  if (!oidcConfig) {
    oidcConfig = await client.discovery(
      new URL(ISSUER_URL),
      process.env.REPL_ID!,
    );
  }
  return oidcConfig;
}

/** Creates a session and returns the RAW id, which only the cookie ever holds. */
export async function createSession(data: SessionInput): Promise<string> {
  const sid = crypto.randomBytes(32).toString("hex");
  await db.insert(sessionsTable).values({
    sid: hashSessionId(sid),
    sess: persistedSession(data),
    expire: new Date(Date.now() + SESSION_TTL),
  });
  return sid;
}

/** Takes the raw cookie value; it is hashed before the lookup. */
export async function getSession(sid: string): Promise<SessionData | null> {
  const key = hashSessionId(sid);
  const [row] = await db
    .select()
    .from(sessionsTable)
    .where(eq(sessionsTable.sid, key));

  if (!row || row.expire < new Date()) {
    if (row) await db.delete(sessionsTable).where(eq(sessionsTable.sid, key));
    return null;
  }

  return row.sess as unknown as SessionData;
}

export async function updateSession(
  sid: string,
  data: SessionInput,
): Promise<void> {
  await db
    .update(sessionsTable)
    .set({
      sess: persistedSession(data),
      expire: new Date(Date.now() + SESSION_TTL),
    })
    .where(eq(sessionsTable.sid, hashSessionId(sid)));
}

/** Housekeeping: an expired session is otherwise deleted only if someone presents it again. */
export async function purgeExpiredSessions(): Promise<void> {
  await db.delete(sessionsTable).where(lt(sessionsTable.expire, new Date()));
}

export async function deleteSession(sid: string): Promise<void> {
  await db.delete(sessionsTable).where(eq(sessionsTable.sid, hashSessionId(sid)));
}

/**
 * Revoke every session belonging to a user.
 *
 * Called after a password reset. Without it, resetting a password does not
 * actually evict whoever prompted the reset: their existing session cookie
 * keeps working until it expires, which defeats the point of resetting.
 *
 * Sessions store the user inside the `sess` JSON blob, so this filters on that
 * rather than on a column. `sessionUserIdExpr` is the exact expression the
 * `IDX_session_user_id` expression index is built on; Postgres only uses an
 * expression index when the query repeats the expression verbatim, so do not
 * inline a differently-written copy here.
 */
export async function deleteSessionsForUser(userId: string): Promise<void> {
  await db.delete(sessionsTable).where(sql`${sessionUserIdExpr} = ${userId}`);
}

export async function clearSession(
  res: Response,
  sid?: string,
): Promise<void> {
  if (sid) await deleteSession(sid);
  res.clearCookie(SESSION_COOKIE, { path: "/" });
}

export function getSessionId(req: Request): string | undefined {
  const authHeader = req.headers["authorization"];
  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.slice(7);
  }
  return req.cookies?.[SESSION_COOKIE];
}
